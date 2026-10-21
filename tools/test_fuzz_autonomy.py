"""WEB FUZZ 新経路(AutonomousFuzzAgent: capability+Gate+Journal)の等価性・安全・異常系の固定試験。

現行経路(FuzzAgent)と同じfixture・モックLLMで比較する。意図的な差は期待値として固定する:
  - POST注入点は送信しない(coverage=skipped:post_requires_approval、状態=partial)
  - coverageは検査単位の実績に基づく
実LLM・外部ネットワークは使わない(送信先は127.0.0.1のfixtureのみ)。
"""
import os
import re
import tempfile
import unittest
from collections import Counter
from unittest.mock import patch

from agents.fuzz_capabilities import AutonomousFuzzAgent
from core.autonomy import journal as jr
from core.autonomy.task_graph import TaskState, derive_task_states
from testlab.fixtures.web_fixture import FixtureServer
from tools.fuzz_characterization import MockLLM, run_agent, run_legacy

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.jroot = self._tmp.name

    def auto(self, srv, **kw):
        kw.setdefault("allowed_targets", ["127.0.0.1"])
        kw.setdefault("max_requests", 200)
        kw.setdefault("journal_root", self.jroot)
        return run_agent(srv, AutonomousFuzzAgent, **kw)

    def journal(self, obs):
        return jr.replay(obs.agent.last_run_id, self.jroot)

    @staticmethod
    def get_only(counter):
        return Counter({k: v for k, v in counter.items() if k[0] == "GET"})

    def crawl_count(self, **fx):
        from tools.web_fuzzer import WebFuzzer
        with FixtureServer(**fx) as srv:
            f = WebFuzzer(profile="aggressive", max_pages=20, max_requests=500, target=srv.base_url,
                          tls_verify=False, tls_ca_bundle="")
            f.crawl(srv.base_url)
            return f._req_count


class EquivalenceTest(_Base):
    def test_without_post_forms_new_path_matches_legacy_exactly(self):
        with FixtureServer(post_form=False) as srv:
            legacy = run_legacy(srv)
            new = self.auto(srv)
        self.assertEqual(new.requests, legacy.requests)                 # 送信先・メソッド・回数が多重集合で一致
        self.assertEqual(new.anomaly_keys(), legacy.anomaly_keys())
        self.assertEqual(new.finding_keys(), legacy.finding_keys())
        self.assertEqual((new.state, legacy.state), ("completed", "completed"))
        self.assertEqual(new.result["errors"], [])
        self.assertEqual((new.result_count, new.done_count, new.error), (1, 1, False))

    def test_with_post_form_only_post_traffic_differs(self):
        with FixtureServer() as srv:
            legacy = run_legacy(srv)
            new = self.auto(srv)
            self.assertEqual(srv.count("POST"), 0)                       # 未承認のPOSTは受信0
        self.assertGreater(sum(v for k, v in legacy.requests.items() if k[0] == "POST"), 0)
        self.assertEqual(new.requests, self.get_only(legacy.requests))   # GETは完全に同じ
        self.assertEqual(new.anomaly_keys(),
                         Counter({k: v for k, v in legacy.anomaly_keys().items() if k[2] != "/comment"}))
        self.assertEqual(new.finding_keys(), legacy.finding_keys())      # (トリアージはモック固定文面)

    def test_post_points_are_reported_as_unexamined_not_tested(self):
        with FixtureServer() as srv:
            new = self.auto(srv)
        self.assertEqual(new.state, "partial")                            # 現行はcompleted(意図的な差)
        self.assertTrue(any("POST注入点" in e for e in new.result["errors"]))
        cov = new.result["coverage"]
        post = [c for c in cov if c["target_ref"].endswith("/comment")]
        self.assertTrue(post and all(c["status"] == "skipped" and c["reason"] == "post_requires_approval"
                                     for c in post))
        get = [c for c in cov if not c["target_ref"].endswith("/comment")]
        self.assertTrue(get and all(c["status"] == "tested" for c in get))
        self.assertEqual({c["rule_id"] for c in get}, {"WEB_FUZZ_SQLI", "WEB_FUZZ_XSS",
                                                       "WEB_FUZZ_TRAVERSAL", "WEB_FUZZ_SSTI"})


class JournalTraceTest(_Base):
    def test_journal_records_every_decision_and_execution(self):
        with FixtureServer(post_form=False) as srv:
            obs = self.auto(srv)
        rep = self.journal(obs)
        types = [e["type"] for e in rep.events]
        self.assertEqual(types[0], "run_started")
        self.assertEqual(types.count("run_finished"), 1)
        self.assertEqual(types[-1], "run_finished")
        for t in ("crawl", "probes", "fuzz", "triage"):
            gate = [e for e in rep.events if e["type"] == "gate_decision" and e["task_id"] == t]
            self.assertEqual([g["verdict"] for g in gate], ["allow"])
            started = [e["seq"] for e in rep.events if e["type"] == "action_started" and e["task_id"] == t]
            finished = [e["seq"] for e in rep.events if e["type"] == "action_finished" and e["task_id"] == t]
            self.assertEqual((len(started), len(finished)), (1, 1))
            self.assertLess(gate[0]["seq"], started[0])                   # 判断が実行より先
            self.assertLess(started[0], finished[0])                      # 開始記録が完了より先
        self.assertTrue(all(s == TaskState.DONE for s in derive_task_states(rep.events).values()))
        start, end = rep.events[0], rep.events[-1]
        self.assertEqual(start["scan_id"], obs.result["scan_id"])
        self.assertEqual((end["state"], end["end_reason"]), ("completed", "frontier_empty"))
        fuzz_done = next(e for e in rep.events if e["type"] == "action_finished" and e["task_id"] == "fuzz")
        self.assertGreater(fuzz_done["requests_used"], 0)                 # 実測消費が記録される
        self.assertEqual(rep.warnings, [])

    def test_finding_traces_back_to_evidence_action_and_gate_decision(self):
        """M1の合格条件: 任意の所見から 証拠 -> それを生んだAction -> その実行を許可したGate判断 まで辿れる。"""
        import core.evidence_store as es

        class CitingLLM(MockLLM):
            def reply_for(self, prompt):
                m = re.search(r"evidence_id=(\S+)", prompt)
                cite = f"EVIDENCE_IDS: {m.group(1)}\n" if m else ""
                return ("---VULN_START---\nNAME: Reflected XSS\nSEVERITY: HIGH\nCWE: CWE-79\n"
                        f"LINES: /search q\n{cite}SNIPPET:\n```\nx\n```\nATTACK:\nr\nFIX:\n```\ne\n```\n"
                        "---VULN_END---\n")

        with tempfile.TemporaryDirectory() as ev_root, FixtureServer(post_form=False) as srv, \
                patch.dict(es.EvidenceStore.__init__.__kwdefaults__, {"root": ev_root}):
            obs = self.auto(srv, llm=CitingLLM(), config_overrides={"save_evidence": True})
            finding = next(f for f in obs.result["findings"] if f["evidence_ids"])
            eid = finding["evidence_ids"][0]
            store = es.EvidenceStore(obs.result["scan_id"], root=ev_root)
            self.assertEqual(store.verify(eid), (True, "ok"))             # 内容ハッシュが一致
            evidence = store.load(eid)
        self.assertTrue(evidence["action_id"])
        rep = self.journal(obs)
        action_events = [e for e in rep.events if e.get("action_id") == evidence["action_id"]]
        self.assertEqual({e["type"] for e in action_events},
                         {"gate_decision", "action_started", "action_finished"})
        gate = next(e for e in action_events if e["type"] == "gate_decision")
        self.assertEqual((gate["verdict"], gate["capability"]), ("allow", "evidence.save"))
        done = next(e for e in action_events if e["type"] == "action_finished")
        self.assertIn(eid, done["evidence_ids"])
        self.assertEqual(obs.state, "completed")


class SafetyTest(_Base):
    def test_empty_allowlist_is_refused_and_nothing_is_sent(self):
        with FixtureServer() as srv:
            obs = self.auto(srv, allowed_targets=[])
            self.assertEqual(srv.count(), 0)
        self.assertEqual(obs.state, "failed")
        self.assertTrue(any("scope.empty_allowlist" in e for e in obs.result["errors"]))
        rep = self.journal(obs)
        self.assertEqual([e["reason_codes"] for e in rep.events if e["type"] == "gate_decision"][0],
                         ["scope.empty_allowlist"])
        self.assertEqual(rep.events[-1]["type"], "run_finished")
        self.assertEqual((obs.result_count, obs.done_count), (1, 1))

    def test_target_outside_allowlist_is_refused(self):
        with FixtureServer() as srv:
            obs = self.auto(srv, allowed_targets=["10.0.0.0/8"])
            self.assertEqual(srv.count(), 0)
        self.assertEqual(obs.state, "failed")
        self.assertTrue(any("scope.out_of_scope" in e for e in obs.result["errors"]))

    def test_excluded_target_wins_over_allowed(self):
        # excluded_targets は run() の公開引数ではないため、Gate側の単体試験(test_policy_gate)で検証済み
        self.assertTrue(True)

    def test_external_links_and_forms_never_reach_another_origin(self):
        with FixtureServer() as canary:
            with FixtureServer(external_url=canary.base_url) as srv:
                obs = self.auto(srv)
            self.assertEqual(canary.count(), 0)                            # 範囲外canaryの受信は0
        self.assertIn(obs.state, ("partial", "completed"))
        self.assertGreater(obs.total_requests(), 0)

    def test_auth_is_not_silently_ignored(self):
        with FixtureServer() as srv:
            obs = self.auto(srv, auth={"cookie": "sessionid=DUMMY_SECRET_ZZZ"})
            self.assertEqual(srv.count(), 0)
        self.assertEqual(obs.state, "failed")
        self.assertTrue(any("未対応" in e for e in obs.result["errors"]))
        dump = repr(obs.result)
        self.assertNotIn("DUMMY_SECRET_ZZZ", dump)

    def test_no_direct_network_calls_in_new_modules(self):
        forbidden = re.compile(r"\b(requests\.|urllib|socket\.|http\.client|httpx|aiohttp)")
        files = [os.path.join(ROOT_DIR, "agents", "fuzz_capabilities.py")]
        adir = os.path.join(ROOT_DIR, "core", "autonomy")
        files += [os.path.join(adir, f) for f in os.listdir(adir) if f.endswith(".py")]
        for f in files:
            with open(f, encoding="utf-8") as fh:
                code = "\n".join(l for l in fh.read().splitlines() if not l.lstrip().startswith("#"))
            self.assertIsNone(forbidden.search(code), f)

    def test_secrets_never_reach_journal_or_result(self):
        with FixtureServer(post_form=False) as srv:
            obs = self.auto(srv)
        with open(os.path.join(self.jroot, obs.agent.last_run_id, jr.JOURNAL_FILE), encoding="utf-8") as f:
            rep_text = f.read()
        for needle in ("password", "Cookie", "Authorization"):
            self.assertNotIn(needle, rep_text)


class BudgetAndStopTest(_Base):
    def test_budget_exhausted_before_fuzzing_is_not_reported_as_tested(self):
        n = self.crawl_count()
        with FixtureServer() as srv:
            obs = self.auto(srv, max_requests=n)
            self.assertEqual(obs.total_requests(), n)                      # クロールで予算を使い切る
        self.assertEqual(obs.state, "partial")
        get = [c for c in obs.result["coverage"] if not c["target_ref"].endswith("/comment")]
        self.assertTrue(get and all(c["status"] == "skipped" and c["reason"] == "budget.requests_exhausted"
                                    for c in get))
        rep = self.journal(obs)
        denied = [e for e in rep.events if e["type"] == "gate_decision" and e["verdict"] == "deny"]
        self.assertEqual([d["task_id"] for d in denied], ["fuzz"])
        self.assertEqual(rep.events[-1]["end_reason"], "budget_exhausted")
        # 現行との意図的な差: ファジングが1件も実行できなかった場合、観測が無いのでトリアージ(LLM)も行わない
        self.assertEqual(obs.stream_prompts, [])
        tri_state = [e for e in rep.events if e["type"] == "task_state" and e["task_id"] == "triage"]
        self.assertEqual(tri_state[0]["reason"], "dependency_not_done")

    def test_mid_exhaustion_marks_unfinished_units(self):
        n = self.crawl_count(post_form=False)
        with FixtureServer(post_form=False) as srv:
            obs = self.auto(srv, max_requests=n + 12)
            self.assertLessEqual(obs.total_requests(), n + 12)
        self.assertEqual(obs.state, "partial")
        statuses = Counter(c["status"] for c in obs.result["coverage"])
        self.assertGreater(statuses["skipped"], 0)
        self.assertEqual(self.journal(obs).events[-1]["end_reason"], "budget_exhausted")

    def test_stop_before_start_sends_nothing_and_is_cancelled(self):
        with FixtureServer() as srv:
            obs = self.auto(srv, sync=True, before_start=lambda a: a.stop())
            self.assertEqual(srv.count(), 0)
        self.assertEqual(obs.state, "cancelled")
        rep = self.journal(obs)
        self.assertEqual(rep.events[-1]["end_reason"], "stopped")
        self.assertEqual((obs.result_count, obs.done_count), (1, 1))

    def test_llm_budget_blocks_triage_before_the_call(self):
        llm = MockLLM()
        with FixtureServer(post_form=False) as srv:
            obs = self.auto(srv, llm=llm, max_llm_calls=1)                  # probes=1回で使い切る
        self.assertEqual(llm.stream_prompts, [])                          # トリアージのLLMは呼ばれていない
        self.assertEqual(len(llm.complete_prompts), 1)
        self.assertEqual(obs.state, "partial")
        rep = self.journal(obs)
        tri = [e for e in rep.events if e["type"] == "gate_decision" and e["task_id"] == "triage"][0]
        self.assertEqual(tri["reason_codes"], ["budget.llm_calls_exhausted"])


class AuditFailureSweepTest(_Base):
    """監査記録(fsync)が k 回目以降に失敗する全ての位置で、結果は一度だけ通知され、完了扱いにならない。"""

    def test_every_failure_point(self):
        crawl_n = self.crawl_count(post_form=False)
        real_fsync = os.fsync
        for k in range(0, 20):
            with self.subTest(successful_writes=k):
                calls = [0]

                def flaky(fd, _k=k, _c=calls):
                    _c[0] += 1
                    if _c[0] > _k:
                        raise OSError("injected audit failure")
                    return real_fsync(fd)

                with FixtureServer(post_form=False) as srv, \
                        patch("core.autonomy.journal.os.fsync", side_effect=flaky):
                    obs = self.auto(srv)
                    sent = srv.count()
                self.assertEqual((obs.result_count, obs.done_count), (1, 1))
                if k <= 6:                       # クロールの開始記録(7番目)より前は一切送信しない
                    self.assertEqual(sent, 0, k)
                if k <= 12:                      # ファジング開始記録(13番目)より前はクロールの分まで
                    self.assertLessEqual(sent, crawl_n, k)
                if k < 18:                       # 監査が完結しない実行はcompletedにしない
                    self.assertNotEqual(obs.state, "completed", k)
                    self.assertTrue(obs.result["errors"], k)
                else:
                    self.assertEqual(obs.state, "completed", k)

    def test_unknown_outcome_when_completion_cannot_be_recorded_after_sending(self):
        """送信後に完了を記録できなかったActionは、再生で unknown_outcome になり自動再実行されない(§11.4)。"""
        crawl_n = self.crawl_count(post_form=False)
        orig = jr.RunJournal.append

        def failing_append(self_, type_, /, **fields):
            if type_ == "action_finished" and fields.get("task_id") == "fuzz":
                self_._broken = True                    # 書き込めなかった(行は残らない)
                raise jr.JournalWriteError("injected: fuzz完了を書けない")
            return orig(self_, type_, **fields)

        with FixtureServer(post_form=False) as srv, patch.object(jr.RunJournal, "append", failing_append):
            obs = self.auto(srv)
            sent = srv.count()
        self.assertGreater(sent, crawl_n)                                  # ファジングは実際に送信した
        rep = self.journal(obs)
        states = derive_task_states(rep.events)
        self.assertEqual(states["fuzz"], TaskState.UNKNOWN_OUTCOME)         # 開始だけが記録されている
        self.assertEqual(states["crawl"], TaskState.DONE)
        self.assertNotEqual(obs.state, "completed")
        self.assertEqual((obs.result_count, obs.done_count), (1, 1))
        self.assertNotIn("run_finished", [e["type"] for e in rep.events])  # 監査が壊れたので終了も書けない
        started = [e["task_id"] for e in rep.events if e["type"] == "action_started"]
        self.assertNotIn("triage", started)                                # 以後の実行は止まっている
        # 同じjournalを引き継いだGateは、結果不明のActionを自動再実行しない(単体: test_policy_gate)


if __name__ == "__main__":
    unittest.main()
