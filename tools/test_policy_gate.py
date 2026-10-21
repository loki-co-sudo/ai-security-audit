"""core/autonomy の型・Gate・予算・タスク状態の固定試験(実LLM・外部通信なし)。"""
import os
import tempfile
import unittest
from unittest.mock import patch

from core.autonomy import journal as jr
from core.autonomy.actions import (
    ActionResult, ApprovalGrant, CapabilityRegistry, CapabilitySpec, SideEffect,
    args_hash, make_action, new_grant, validate_args,
)
from core.autonomy.budget import BudgetLedger
from core.autonomy.policy_gate import AuditUnavailable, EngagementPolicy, PolicyGate
from core.autonomy.task_graph import TaskState, can_transition, derive_task_states

BASE = "http://127.0.0.1:8000"
T0, T1, T3 = SideEffect.T0_LOCAL, SideEffect.T1_OBSERVE, SideEffect.T3_NEEDS_APPROVAL


def _registry():
    r = CapabilityRegistry()
    r.register(CapabilitySpec("web.crawl", T1, args_schema={"url": {"type": "str", "required": True}},
                              target_arg="url", max_requests=50))
    r.register(CapabilitySpec("llm.triage", T0, args_schema={"n": {"type": "int"}},
                              uses_llm="strong", llm_calls=2))
    r.register(CapabilitySpec("web.authenticate", T3, mutating=True,
                              args_schema={"url": {"type": "str", "required": True},
                                           "role": {"type": "str", "required": True},
                                           "auth_ref": {"type": "str", "required": True}},
                              target_arg="url", max_requests=3))
    r.register(CapabilitySpec("web.fuzz_post_points", T3, mutating=True, enabled=False,
                              args_schema={"url": {"type": "str", "required": True}},
                              target_arg="url", max_requests=100))
    return r


class _Env:
    def __init__(self, tc, *, used=0, max_req=10, allowed=("127.0.0.1",), excluded=(),
                 effects=(T0, T1), grants=None, clock=None, deadline=None, max_llm=None):
        self.tmp = tempfile.TemporaryDirectory()
        tc.addCleanup(self.tmp.cleanup)
        self.used = used
        self.journal = jr.RunJournal(jr.new_run_id(), self.tmp.name)
        tc.addCleanup(self.journal.close)
        self.now = [1000.0]
        self.mono = [0.0]
        self.budget = BudgetLedger(max_requests=max_req, request_counter=lambda: self.used,
                                   deadline_seconds=deadline, max_llm_calls=max_llm,
                                   clock=lambda: self.mono[0])
        self.budget.start()
        self.registry = _registry()
        self.policy = EngagementPolicy(base_origin=BASE, allowed_targets=list(allowed),
                                       excluded_targets=list(excluded),
                                       allowed_side_effects=frozenset(effects))
        self.gate = PolicyGate(self.registry, self.policy, self.budget, self.journal,
                               grants=grants, clock=(clock or (lambda: self.now[0])))

    def action(self, cap="web.crawl", args=None, task="t1", auth="anonymous"):
        spec = self.registry.get(cap)
        args = args if args is not None else {"url": BASE + "/"}
        return make_action(spec, task, args, auth_context=auth)

    def events(self, type_=None):
        evs = jr.replay(self.journal.run_id, self.tmp.name).events
        return [e for e in evs if type_ is None or e["type"] == type_]


class SpecTest(unittest.TestCase):
    def test_mutating_must_be_t3_and_t0_cannot_send(self):
        with self.assertRaises(ValueError):
            CapabilitySpec("web.x", SideEffect.T1_OBSERVE, mutating=True,
                           args_schema={"url": {"type": "str"}}, target_arg="url", max_requests=1)
        with self.assertRaises(ValueError):
            CapabilitySpec("local.x", T0, max_requests=1)
        with self.assertRaises(ValueError):
            CapabilitySpec("web.y", T1, max_requests=1)          # target_arg が無い
        with self.assertRaises(ValueError):
            CapabilitySpec("Bad Name", T0)
        with self.assertRaises(ValueError):                       # 秘密値を直接受ける引数名
            CapabilitySpec("web.z", T3, mutating=True, target_arg="url", max_requests=1,
                           args_schema={"url": {"type": "str"}, "password": {"type": "str"}})

    def test_duplicate_registration_rejected(self):
        r = _registry()
        with self.assertRaises(ValueError):
            r.register(r.get("web.crawl"))

    def test_validate_args(self):
        spec = _registry().get("web.crawl")
        self.assertEqual(validate_args(spec, {"url": BASE}), [])
        self.assertTrue(validate_args(spec, {}))
        self.assertTrue(validate_args(spec, {"url": 5}))
        self.assertTrue(validate_args(spec, {"url": BASE, "extra": 1}))
        self.assertTrue(validate_args(spec, {"url": BASE, "password": "x"}))


class GateTest(unittest.TestCase):
    def test_allow_and_decision_journaled_before_return(self):
        env = _Env(self)
        d = env.gate.decide(env.action())
        self.assertEqual((d.verdict, d.reason_codes), ("allow", ()))
        ev = env.events("gate_decision")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["verdict"], "allow")
        self.assertEqual(ev[0]["args_hash"], args_hash("web.crawl", {"url": BASE + "/"}))

    def test_unknown_and_disabled_capability(self):
        env = _Env(self)
        bad = env.action()
        bad = type(bad)(bad.action_id, bad.task_id, "web.nope", bad.args, bad.auth_context, bad.dedupe_key)
        self.assertEqual(env.gate.decide(bad).reason_codes, ("capability.unknown",))
        self.assertEqual(env.gate.decide(env.action("web.fuzz_post_points", {"url": BASE + "/"})).reason_codes,
                         ("capability.disabled",))

    def test_invalid_args_denied(self):
        env = _Env(self)
        self.assertEqual(env.gate.decide(env.action(args={"url": 5})).reason_codes, ("args.invalid",))

    def test_scope_rules(self):
        self.assertEqual(_Env(self, allowed=()).gate.decide(_Env(self, allowed=()).action()).reason_codes[0:1],
                         ("scope.empty_allowlist",))
        env = _Env(self)
        self.assertEqual(env.gate.decide(env.action(args={"url": "http://127.0.0.1:9999/"})).reason_codes,
                         ("scope.cross_origin",))
        self.assertEqual(env.gate.decide(env.action(args={"url": "https://127.0.0.1:8000/"})).reason_codes,
                         ("scope.cross_origin",))
        self.assertEqual(env.gate.decide(env.action(args={"url": "http://evil.example/"})).reason_codes,
                         ("scope.cross_origin",))
        self.assertEqual(env.gate.decide(env.action(args={"url": "ftp://127.0.0.1:8000/"})).reason_codes,
                         ("scope.invalid_target",))
        self.assertEqual(env.gate.decide(env.action(args={"url": "http://u:p@127.0.0.1:8000/"})).reason_codes,
                         ("scope.invalid_target",))
        ex = _Env(self, excluded=("127.0.0.1",))                  # 除外は許可より優先
        self.assertEqual(ex.gate.decide(ex.action()).reason_codes, ("scope.excluded",))
        out = _Env(self, allowed=("10.0.0.0/8",))                  # 基準origin内だが許可リスト外
        self.assertEqual(out.gate.decide(out.action()).reason_codes, ("scope.out_of_scope",))

    def test_side_effect_class_requires_explicit_permission(self):
        env = _Env(self, effects=(T0,))
        self.assertEqual(env.gate.decide(env.action()).reason_codes, ("side_effect.not_permitted",))
        local = env.gate.decide(env.action("llm.triage", {"n": 1}))
        self.assertTrue(local.allowed)

    def test_budget_rules(self):
        env = _Env(self, used=10, max_req=10)
        self.assertEqual(env.gate.decide(env.action()).reason_codes, ("budget.requests_exhausted",))
        self.assertTrue(env.gate.decide(env.action("llm.triage", {"n": 1})).allowed)   # ローカルは可
        env = _Env(self, used=9, max_req=10)   # 残予算が1でもActionの上限(50)で丸ごと拒否しない
        self.assertTrue(env.gate.decide(env.action()).allowed)
        env = _Env(self, deadline=60.0)
        env.mono[0] = 61.0
        self.assertEqual(env.gate.decide(env.action()).reason_codes, ("budget.time_exhausted",))
        self.assertTrue(env.gate.decide(env.action("llm.triage", {"n": 1})).reason_codes
                        == ("budget.time_exhausted",))          # LLMも止まる
        env = _Env(self, max_llm=1)
        self.assertEqual(env.gate.decide(env.action("llm.triage", {"n": 1})).reason_codes,
                         ("budget.llm_calls_exhausted",))        # 必要2回 > 残1回

    def test_dedupe_and_retry_and_unknown_outcome(self):
        env = _Env(self)
        a = env.action()
        self.assertTrue(env.gate.decide(a).allowed)
        env.gate.start_action(a)
        again = env.action(task="t2")
        self.assertEqual(env.gate.decide(again).reason_codes, ("dedupe.already_done",))   # running
        env.gate.finish_action(a, ActionResult("done"))
        self.assertEqual(env.gate.decide(again).reason_codes, ("dedupe.already_done",))   # done
        # 失敗は max_failed_retries(1)回まで再試行可、超えたら拒否
        f = env.action(args={"url": BASE + "/f"})
        for expect_allowed in (True, True, False):
            d = env.gate.decide(f)
            self.assertEqual(d.allowed, expect_allowed, d)
            if d.allowed:
                env.gate.start_action(f)
                env.gate.finish_action(f, ActionResult("failed"))
        # exhausted は done と同様に再実行しない
        x = env.action(args={"url": BASE + "/x"})
        env.gate.decide(x); env.gate.start_action(x)
        env.gate.finish_action(x, ActionResult("exhausted"))
        self.assertEqual(env.gate.decide(x).reason_codes, ("dedupe.already_done",))


class ApprovalTest(unittest.TestCase):
    ARGS = {"url": BASE + "/login", "role": "a", "auth_ref": "cred_a"}

    def test_missing_grant_needs_approval_and_is_not_executable(self):
        env = _Env(self)
        d = env.gate.decide(env.action("web.authenticate", dict(self.ARGS)))
        self.assertEqual((d.verdict, d.reason_codes), ("needs_approval", ("approval.missing",)))
        self.assertFalse(d.allowed)

    def test_valid_grant_allows_once_and_records_consumption(self):
        g = new_grant("web.authenticate", self.ARGS, expires_at=2000.0)
        env = _Env(self, grants=[g])
        a = env.action("web.authenticate", dict(self.ARGS))
        self.assertEqual(env.gate.decide(a).reason_codes, ("approval.granted",))
        used = env.events("approval_consumed")
        self.assertEqual([u["grant_id"] for u in used], [g.grant_id])
        # 消費の記録は gate_decision より前
        types = [e["type"] for e in env.events()]
        self.assertLess(types.index("approval_consumed"), types.index("gate_decision"))
        # 再利用は拒否
        again = env.action("web.authenticate", dict(self.ARGS), task="t2")
        self.assertEqual(env.gate.decide(again).reason_codes, ("approval.reused",))

    def test_expired_grant_is_denied_never_allowed(self):
        g = new_grant("web.authenticate", self.ARGS, expires_at=1500.0)
        env = _Env(self, grants=[g])
        env.now[0] = 1500.0                                # 期限ちょうども失効
        d = env.gate.decide(env.action("web.authenticate", dict(self.ARGS)))
        self.assertEqual((d.verdict, d.reason_codes), ("deny", ("approval.expired",)))
        self.assertEqual(env.events("approval_consumed"), [])

    def test_changed_args_and_role_swap_are_denied(self):
        g = new_grant("web.authenticate", self.ARGS, expires_at=2000.0)
        env = _Env(self, grants=[g])
        changed = dict(self.ARGS, url=BASE + "/other")
        self.assertEqual(env.gate.decide(env.action("web.authenticate", changed)).reason_codes,
                         ("approval.args_mismatch",))
        role_b = dict(self.ARGS, role="b", auth_ref="cred_b")   # Aの承認でBは実行できない
        self.assertEqual(env.gate.decide(env.action("web.authenticate", role_b, task="t2")).reason_codes,
                         ("approval.args_mismatch",))
        self.assertEqual(env.events("approval_consumed"), [])

    def test_grant_for_other_capability_does_not_apply(self):
        g = new_grant("web.fuzz_post_points", {"url": BASE + "/"}, expires_at=2000.0)
        env = _Env(self, grants=[g])
        d = env.gate.decide(env.action("web.authenticate", dict(self.ARGS)))
        self.assertEqual(d.reason_codes, ("approval.missing",))

    def test_grant_not_consumed_when_other_checks_deny(self):
        g = new_grant("web.authenticate", self.ARGS, expires_at=2000.0)
        env = _Env(self, grants=[g], used=10, max_req=10)   # 予算切れ
        d = env.gate.decide(env.action("web.authenticate", dict(self.ARGS)))
        self.assertEqual(d.reason_codes, ("budget.requests_exhausted",))
        self.assertEqual(env.events("approval_consumed"), [])

    def test_t3_not_runnable_by_permission_flags_alone(self):
        env = _Env(self, effects=(T0, T1, SideEffect.T2_DIFFERENTIAL, T3))
        d = env.gate.decide(env.action("web.authenticate", dict(self.ARGS)))
        self.assertEqual(d.reason_codes, ("approval.missing",))


class FailClosedTest(unittest.TestCase):
    def test_decision_not_recorded_means_deny(self):
        env = _Env(self)
        with patch("core.autonomy.journal.os.fsync", side_effect=OSError("disk full")):
            d = env.gate.decide(env.action())
        self.assertEqual((d.verdict, d.reason_codes), ("deny", ("audit.unavailable",)))
        self.assertTrue(env.gate.audit_failed)
        # 以後はジャーナルに触れずに拒否し続ける
        self.assertEqual(env.gate.decide(env.action(args={"url": BASE + "/b"})).reason_codes,
                         ("audit.unavailable",))
        with self.assertRaises(AuditUnavailable):
            env.gate.start_action(env.action())

    def test_start_record_failure_blocks_send(self):
        env = _Env(self)
        a = env.action()
        self.assertTrue(env.gate.decide(a).allowed)
        with patch("core.autonomy.journal.os.fsync", side_effect=OSError("io")):
            with self.assertRaises(AuditUnavailable):
                env.gate.start_action(a)

    def test_finish_record_failure_marks_unknown_outcome(self):
        env = _Env(self)
        a = env.action()
        env.gate.decide(a); env.gate.start_action(a)
        with patch("core.autonomy.journal.os.fsync", side_effect=OSError("io")):
            with self.assertRaises(AuditUnavailable):
                env.gate.finish_action(a, ActionResult("done"))
        self.assertTrue(env.gate.audit_failed)
        self.assertEqual(env.gate._key_state[a.dedupe_key], "unknown_outcome")


class TaskStateTest(unittest.TestCase):
    def test_transitions(self):
        self.assertTrue(can_transition(TaskState.NEEDS_APPROVAL, TaskState.READY))
        self.assertTrue(can_transition(TaskState.RUNNING, TaskState.EXHAUSTED))
        self.assertFalse(can_transition(TaskState.DONE, TaskState.READY))
        self.assertFalse(can_transition(TaskState.UNKNOWN_OUTCOME, TaskState.READY))  # 自動では動かさない
        self.assertFalse(can_transition(TaskState.EXHAUSTED, TaskState.DONE))

    def test_replay_derives_states_and_unknown_outcome(self):
        env = _Env(self)
        ok, interrupted, denied, waiting, ex = [env.action(task=t, args={"url": BASE + "/" + t})
                                                for t in ("ok", "intr", "den", "wait", "ex")]
        auth = env.action("web.authenticate", {"url": BASE + "/l", "role": "a", "auth_ref": "c"}, task="wait")
        for t in ("ok", "intr", "den", "wait", "ex"):
            env.journal.append("task_added", task_id=t)
        env.gate.decide(ok); env.gate.start_action(ok); env.gate.finish_action(ok, ActionResult("done"))
        env.gate.decide(interrupted); env.gate.start_action(interrupted)       # 完了を書く前に停止
        env.gate.decide(env.action(args={"url": "http://other.example/"}, task="den"))
        env.gate.decide(auth)
        env.gate.decide(ex); env.gate.start_action(ex); env.gate.finish_action(ex, ActionResult("exhausted"))
        states = derive_task_states(env.events())
        self.assertEqual(states["ok"], TaskState.DONE)
        self.assertEqual(states["intr"], TaskState.UNKNOWN_OUTCOME)
        self.assertEqual(states["den"], TaskState.SKIPPED)
        self.assertEqual(states["wait"], TaskState.NEEDS_APPROVAL)
        self.assertEqual(states["ex"], TaskState.EXHAUSTED)

    def test_explicit_task_state_event(self):
        events = [{"type": "task_added", "task_id": "a"},
                  {"type": "task_state", "task_id": "a", "state": "skipped"},
                  {"type": "task_state", "task_id": "a", "state": "bogus"}]
        self.assertEqual(derive_task_states(events)["a"], TaskState.SKIPPED)


class BudgetTest(unittest.TestCase):
    def test_llm_reservation_is_before_the_call(self):
        t = [0.0]
        b = BudgetLedger(max_requests=1, request_counter=lambda: 0, max_llm_calls=2,
                         max_llm_input_chars=100, clock=lambda: t[0], deadline_seconds=10)
        b.start()
        self.assertTrue(b.reserve_llm_call(50).ok)
        self.assertEqual(b.reserve_llm_call(500).reason, "budget.llm_input_too_large")
        self.assertEqual(b.llm_calls_used, 1)                    # 拒否は回数を消費しない
        self.assertTrue(b.reserve_llm_call(1).ok)
        self.assertEqual(b.reserve_llm_call(1).reason, "budget.llm_calls_exhausted")
        t[0] = 11.0
        self.assertEqual(b.reserve_llm_call(1).reason, "budget.time_exhausted")

    def test_requests_follow_the_transport_counter(self):
        n = [3]
        b = BudgetLedger(max_requests=5, request_counter=lambda: n[0])
        self.assertEqual(b.requests_remaining(), 2)
        n[0] = 9
        self.assertEqual(b.requests_remaining(), 0)
        self.assertEqual(b.snapshot()["requests_used"], 9)


if __name__ == "__main__":
    unittest.main()
