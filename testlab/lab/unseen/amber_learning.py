"""Isolated peer-assessment service with synthetic identities."""
import json
import random
import secrets
from testlab.lab.apps import LabApp


class App(LabApp):
    roles = ('learner_a', 'learner_b', 'learner_c', 'instructor', 'user_expired')

    def __init__(self, canary=None, flaws=frozenset(), seed=None):
        super().__init__(canary)
        self.flaws = frozenset(flaws)
        rng = random.Random(seed) if seed is not None else secrets.SystemRandom()
        fresh = lambda prefix: prefix + format(rng.getrandbits(96), '024x')
        self.people = {r: {'id': fresh('p_'), 'name': r} for r in self.roles}
        self.submissions, self.reviews = {}, {}
        for i, role in enumerate(self.roles[:3]):
            reviewer = self.roles[(i + 1) % 3]
            for number in range(2):
                sid, rid = fresh('s_'), fresh('r_')
                self.submissions[sid] = {'id': sid, 'author': self.people[role]['id'], 'shared': [self.people[reviewer]['id']] if number == 0 else [], 'exercise': 'exercise-' + str(number), 'state': 'submitted'}
                self.reviews[rid] = {'id': rid, 'reviewer': self.people[reviewer]['id'], 'submission_id': sid, 'score': 3 + number}
        self.notes = {key: 'synthetic-assessment-' + fresh('n_') for key in self.submissions}

    def route(self, path, q, role, n_prev):
        def out(status, body):
            return status, {'Content-Type': 'application/json'}, json.dumps(body)
        if path == '/learning/exercises':
            return out(200, [{'title': 'Practice', 'level': 'introductory'}])
        if role is None or role == 'user_expired':
            return out(401, {'error': 'authentication required'})
        uid = self.people[role]['id']
        if path == '/learning/profile':
            return out(200, self.people[role])
        if path == '/learning/submissions/mine':
            return out(200, [s for s in self.submissions.values() if s['author'] == uid or ('shared_in_mine' in self.flaws and uid in s['shared'])])
        if path == '/learning/submissions/accessible':
            return out(200, [s for s in self.submissions.values() if s['author'] == uid or uid in s['shared']])
        if path == '/learning/reviews/assigned':
            return out(200, [r for r in self.reviews.values() if r['reviewer'] == uid])
        if path == '/learning/instructor/counts':
            return out(200, {'submitted': len(self.submissions)}) if role == 'instructor' else out(403, {'error': 'forbidden'})
        if path == '/learning/preferences':
            return out(200, {'language': 'en'})
        bits = path.split('/')
        if len(bits) == 4 and bits[1:3] == ['learning', 'reviews']:
            item = self.reviews.get(bits[3])
            if item is None:
                return out(404, {'error': 'not found'})
            if item['reviewer'] != uid and 'review_owner' not in self.flaws:
                return out(403, {'error': 'forbidden'})
            return out(200, item)
        if len(bits) in (4, 5) and bits[1:3] == ['learning', 'submissions']:
            item = self.submissions.get(bits[3])
            suffix = bits[4] if len(bits) == 5 else ''
            if item is None or suffix not in ('', 'assessment'):
                return out(404, {'error': 'not found'})
            allowed = item['author'] == uid or (not suffix and uid in item['shared'])
            if suffix == 'assessment' and 'assessment_access' in self.flaws:
                allowed = True
            if not allowed:
                return out(403, {'error': 'forbidden'})
            if suffix:
                return out(200, {'id': item['id'], 'assessment': self.notes[item['id']]})
            value = dict(item)
            if 'extra_note' in self.flaws:
                value['moderation_note'] = self.notes[item['id']]
            return out(200, value)
        return out(404, {'error': 'not found'})
