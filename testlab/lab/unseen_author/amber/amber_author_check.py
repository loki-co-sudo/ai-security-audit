"""Author-only contract matrix; no research, grading, or model execution."""
import hashlib
import importlib
import itertools
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[4]
IDS = ('unseen-amber-23', 'unseen-amber-51', 'unseen-amber-86')


def main():
    counts = {'assertions': 0, 'http_requests': 0, 'app_configurations': 0}
    def check(condition, label):
        counts['assertions'] += 1
        if not condition:
            raise AssertionError(label)

    for cid in IDS:
        case = json.loads((ROOT / 'testlab/lab/blind_cases' / (cid + '.json')).read_text())
        truth = json.loads((ROOT / 'testlab/lab/truth' / (cid + '.json')).read_text())
        cls = getattr(importlib.import_module(truth['app']['module']), 'App')
        all_flags = tuple(truth['env_flaws'])
        variants = [set(f for i, f in enumerate(all_flags) if mask & (1 << i)) for mask in range(1 << len(all_flags))]
        seed_ids = []
        witnesses = set()
        for seed, flags in itertools.product((7, 19, 43), variants):
            app = cls(seed=seed, flaws=flags)
            counts['app_configurations'] += 1
            stores = {'submission': app.submissions, 'review': app.reviews} if hasattr(app, 'submissions') else {'application': app.applications, 'placement': app.placements}
            before = json.dumps([app.people, stores, app.notes], sort_keys=True)
            try:
                for role in [None] + list(app.roles):
                    uid = app.people[role]['id'] if role else None
                    active = role not in (None, 'user_expired')
                    for op in case['spec']['operations']:
                        if op['method'] != 'GET':
                            continue
                        acc, ret = op['access'], op.get('returns', {})
                        param = next(iter(op.get('params', {})), None)
                        otype = op['params'][param]['object'] if param else ret.get('object')
                        store = stores[otype] if otype else None
                        items = list(store.values()) + [{'id': 'absent-object'}] if param else [None]
                        for item in items:
                            path = op['path'].replace('{' + param + '}', item['id']) if param else op['path']
                            expected_status, expected_body = 200, None
                            kind = acc['kind']
                            allowed = True
                            if kind != 'public' and not active:
                                expected_status = 401
                            elif param:
                                if item['id'] not in store:
                                    expected_status = 404
                                else:
                                    schema = case['spec']['objects'][otype]
                                    allowed = item[schema['owner_field']] == uid
                                    if kind == 'owner_or_shared':
                                        allowed |= uid in item[schema['shared_field']]
                                    expected_status = 200 if allowed else 403
                                    expected_body = item if kind != 'unspecified' else {'id': item['id'], 'assessment' if otype == 'submission' else 'household': app.notes[item['id']]}
                            elif kind == 'role':
                                expected_status = 200 if case['accounts'][role]['privilege'] in acc['roles'] else 403
                            elif kind == 'own_list':
                                schema = case['spec']['objects'][otype]
                                expected_body = [x for x in store.values() if x[schema['owner_field']] == uid or (acc['visible_to'] == 'owner_or_shared' and uid in x[schema['shared_field']])]
                            oid = op['op_id']
                            valid_item = param and item['id'] in store
                            if active and valid_item and oid == 'review_read' and 'review_owner' in flags:
                                if expected_status == 403:
                                    witnesses.add('review_owner')
                                expected_status = 200
                            if active and valid_item and oid in ('assessment_preview', 'household_view'):
                                flag = 'assessment_access' if oid == 'assessment_preview' else 'household_access'
                                if flag in flags:
                                    if expected_status == 403:
                                        witnesses.add(flag)
                                    expected_status = 200
                            if active and oid == 'submission_mine' and 'shared_in_mine' in flags:
                                expected_body = [x for x in store.values() if x['author'] == uid or uid in x['shared']]
                                if any(x['author'] != uid for x in expected_body):
                                    witnesses.add('shared_in_mine')
                            if active and valid_item and oid == 'submission_read' and expected_status == 200 and 'extra_note' in flags:
                                expected_body = dict(expected_body, moderation_note=app.notes[item['id']])
                                witnesses.add('extra_note')
                            if role is None and oid == 'capacity_summary' and 'capacity_anonymous' in flags:
                                expected_status = 200
                                witnesses.add('capacity_anonymous')
                            if active and oid == 'management_totals' and 'totals_role' in flags:
                                if expected_status == 403:
                                    witnesses.add('totals_role')
                                expected_status = 200
                            if role == 'coordinator' and oid == 'application_list' and 'coordinator_list' in flags:
                                expected_body = list(store.values())
                                witnesses.add('coordinator_list')
                            status, headers, raw = app.route(path, {}, role, 0)
                            body = json.loads(raw)
                            label = (cid, seed, sorted(flags), role, oid, item and item['id'])
                            check(status == expected_status, label)
                            check(headers.get('Content-Type') == 'application/json', label)
                            if status == 200:
                                if expected_body is not None:
                                    check(body == expected_body, label)
                                allowed_fields = set(ret.get('fields', []))
                                if oid == 'submission_read' and 'extra_note' in flags:
                                    allowed_fields.add('moderation_note')
                                for row in body if isinstance(body, list) else [body]:
                                    check(set(row) == allowed_fields, label)
                check(before == json.dumps([app.people, stores, app.notes], sort_keys=True), 'GET must not mutate fixtures')
                check(not app.requests, 'direct author checks must not execute research')
                ids = {p['id'] for p in app.people.values()} | {i for store in stores.values() for i in store}
                check(len(ids) == len(app.people) + sum(map(len, stores.values())), 'IDs unique across object types')
                if not flags:
                    check(all(ids.isdisjoint(prior) for prior in seed_ids), 'IDs change across seeds')
                    seed_ids.append(ids)
                for otype, store in stores.items():
                    list_ops = [o for o in case['spec']['operations'] if o['access']['kind'] == 'own_list' and o['returns']['object'] == otype]
                    observed = set()
                    for op, role in itertools.product(list_ops, app.roles[:-1]):
                        observed.update(x['id'] for x in json.loads(app.route(op['path'], {}, role, 0)[2]))
                    check(set(store) <= observed, 'all object IDs observable without guessing')
            finally:
                app._srv.server_close()
        check(witnesses == set(all_flags), 'each truth flaw has an author-side witness')
        for flags in (set(), set(all_flags)):
            with cls(seed=7, flaws=flags) as app:
                stores = {'submission': app.submissions, 'review': app.reviews} if hasattr(app, 'submissions') else {'application': app.applications, 'placement': app.placements}
                for role, op in itertools.product([None] + list(app.roles), case['spec']['operations']):
                    param = next(iter(op.get('params', {})), None)
                    path = op['path']
                    if param:
                        otype = op['params'][param]['object']
                        path = path.replace('{' + param + '}', next(iter(stores[otype])))
                    headers = {} if role is None else {'Authorization': 'Bearer ' + app.credentials()['cred:' + role]}
                    req = Request(app.base_url + path, headers=headers, method=op['method'])
                    try:
                        with urlopen(req, timeout=3) as response:
                            status, body = response.status, response.read().decode()
                    except HTTPError as error:
                        status, body = error.code, error.read().decode()
                        error.close()
                    counts['http_requests'] += 1
                    if op['method'] != 'GET':
                        check(status == 405, 'non-GET refused')
                    elif role == 'user_expired':
                        check(status == 401, 'expired token refused even on public endpoints')
                    else:
                        reference = app.route(path, {}, role, 0)
                        check((status, body) == (reference[0], reference[2]), 'HTTP matches fixture contract')
                check(len(app.requests) == 6 * len(case['spec']['operations']), 'HTTP audit count')
    normal = json.loads((ROOT / 'testlab/lab/blind_cases/unseen-amber-51.json').read_text())
    paired = json.loads((ROOT / 'testlab/lab/blind_cases/unseen-amber-86.json').read_text())
    normal.pop('case_id'); paired.pop('case_id')
    check(normal == paired, 'paired public contracts are identical except case ID')
    print(json.dumps(counts, sort_keys=True))


if __name__ == '__main__':
    main()
