"""Private fixture checks only; never invokes a research workflow or grader."""
import importlib
import itertools
import json
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[3]
IDS = ('unseen-cobalt-17', 'unseen-cobalt-42', 'unseen-cobalt-68')


def main():
    assertions = 0
    def check(value):
        nonlocal assertions
        assert value
        assertions += 1

    for cid in IDS:
        case = json.loads((ROOT / 'testlab/lab/blind_cases' / (cid + '.json')).read_text())
        truth = json.loads((ROOT / 'testlab/lab/truth' / (cid + '.json')).read_text())
        cls = getattr(importlib.import_module(truth['app']['module']), 'App')
        flags = truth['env_flaws']
        configurations = [set(flags[i] for i in range(len(flags)) if mask & (1 << i)) for mask in range(1 << len(flags))]
        previous_ids = None
        for seed, enabled in itertools.product((0, 1, 2), configurations):
            app = cls(seed=seed, flaws=enabled)
            try:
                base = '/' + case['target_ref'].split(':')[1]
                objects = case['spec']['objects']
                main_type = next(iter(objects))
                owner_field = objects[main_type]['owner_field']
                admin = next(r for r, a in case['accounts'].items() if a['privilege'] == 'admin')
                for role in [None] + list(app.roles):
                    uid = app.people[role]['id'] if role else None
                    for op in case['spec']['operations']:
                        if op['method'] != 'GET':
                            continue
                        param = next(iter(op.get('params', {})), None)
                        records = app.invoices if param == 'invoice_id' or op['op_id'] == 'billing_invoices' else app.records
                        items = list(records.values()) if param else [None]
                        for item in items:
                            path = op['path'].replace('{' + param + '}', item['id']) if param else op['path']
                            status, headers, raw = app.route(path, {}, role, 0)
                            body = json.loads(raw)
                            kind = op['access']['kind']
                            expected = 200
                            if kind != 'public' and role in (None, 'user_expired'):
                                expected = 401
                            elif kind == 'role':
                                allowed = role == admin or (op['op_id'] == 'operations_summary' and 'role_summary' in enabled)
                                expected = 200 if allowed else 403
                            elif param:
                                field = 'payer' if param == 'invoice_id' else owner_field
                                allowed = item[field] == uid
                                if op['op_id'] == 'record_detail':
                                    allowed |= uid in item.get('shared', []) or 'object_read' in enabled
                                if op['op_id'] == 'record_preview':
                                    allowed |= 'preview_access' in enabled
                                expected = 200 if allowed else 403
                            check(status == expected)
                            check(headers.get('Content-Type') == 'application/json')
                            if status == 200 and kind == 'own_list':
                                field = objects[op['returns']['object']]['owner_field']
                                list_is_fault = op['op_id'] == ('billing_invoices' if hasattr(app, 'invoices') else 'owned_records')
                                expected_items = list(records.values()) if list_is_fault and 'list_scope' in enabled else [x for x in records.values() if x[field] == uid]
                                if op['op_id'] == 'billing_invoices':
                                    expected_items = list(app.invoices.values()) if 'list_scope' in enabled else [x for x in app.invoices.values() if x[field] == uid]
                                check(body == expected_items)
                            if status == 200 and param and op['op_id'] in ('record_detail', 'billing_invoice'):
                                check(body == item)
                ids = set(app.records) | {p['id'] for p in app.people.values()}
                check(len(ids) == len(app.records) + len(app.people))
                if not enabled:
                    if previous_ids is not None:
                        check(ids.isdisjoint(previous_ids))
                    previous_ids = ids
                check(app.requests == [])
            finally:
                app._srv.server_close()
        with cls(seed=0, flaws=flags) as app:
            for method, role, path, expected in [('GET', None, '/__check__', 401), ('GET', 'user_expired', base + '/identity', 401), ('POST', admin, base + '/records/unused/cancel', 405)]:
                headers = {} if role is None else {'Authorization': 'Bearer ' + app.credentials()['cred:' + role]}
                request = Request(app.base_url + path, headers=headers, method=method)
                try:
                    with urlopen(request, timeout=3) as response:
                        status = response.status
                except HTTPError as error:
                    status = error.code
                    error.close()
                check(status == expected)
    print(f'Author-only fixture checks: {assertions} assertions passed; no research or grading executed.')


if __name__ == '__main__':
    main()
