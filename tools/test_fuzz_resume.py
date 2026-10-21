"""WEB FUZZ 新経路の中断・再開(Phase B)の固定試験。実際にプロセスを強制終了(os._exit)して再開する。

不変条件(二重実行なし・Findingの二重作成なし・予算の巻き戻しなし・完了済みタスクの再実行なし)を、
全タスク × 5つの強制終了位置で確認する。実LLM・外部ネットワークは使わない(送信先は127.0.0.1のfixtureのみ)。
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from collections import Counter

from agents.fuzz_capabilities import AutonomousFuzzAgent, auth_action_args
from core.autonomy import journal as jr
from core.autonomy.actions import new_grant
from core.autonomy.run_store import RunStore
from core.autonomy.task_graph import TaskState, derive_task_states
from testlab.fixtures.web_fixture import FixtureServer
from tools.fuzz_characterization import run_agent

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHILD = os.path.join(ROOT, "tools", "autonomy_crash_child.py")
TOK_A, TOK_B = "TOK_ALICE_9f3a71", "TOK_BOB_c42e08"
CRASH_POINTS = [
    "journal:gate_decision:{t}:after",     # 判断を書いた直後(開始前)
    "journal:action_started:{t}:after",     # 開始を書いた直後(送信前)
    "store:finish_task:{t}:before",         # 実行後・状態ストアへcommitする直前
    "store:finish_task:{t}:after",          # commit直後・journalの完了記録の前
    "journal:action_finished:{t}:after",    # 完了記録の直後
]
TASKS = ["crawl", "probes", "fuzz", "triage"]


def _cov(counter):
    """coverageのキーからfixtureのポート番号(実行ごとに違う)を除く。"""
    return Counter({(re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:PORT", k[0]),) + k[1:]: v
                    for k, v in counter.items()})


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name

    def child(self, srv, crash, run=None, grants=None, config=None):
        run = dict(run or {})
        run.setdefault("allowed_targets", ["127.0.0.1"])
        run.setdefault("max_requests", 200)
        run.setdefault("profile", "aggressive")
        cfg = {"target": srv.base_url, "journal_root": self.root, "crash": crash, "run": run,
               "grants": grants or [], "config": config or {}}
        before = set(os.listdir(self.root))
        p = subprocess.run([sys.executable, CHILD, json.dumps(cfg)], cwd=ROOT, capture_output=True,
                           text=True, timeout=120)
        new = sorted(set(os.listdir(self.root)) - before)
        return p, (new[0] if new else None)

    def resume(self, srv, run_id, **kw):
        kw.setdefault("allowed_targets", ["127.0.0.1"])
        kw.setdefault("max_requests", 200)
        return run_agent(srv, AutonomousFuzzAgent, journal_root=self.root, resume_run_id=run_id,
                         keep_requests=True, sync=True, **kw)

    def baseline(self, **fx):
        with FixtureServer(**fx) as srv:
            obs = run_agent(srv, AutonomousFuzzAgent, allowed_targets=["127.0.0.1"], max_requests=200,
                            journal_root=self.root)
            return obs.requests, obs.finding_keys(), _cov(obs.coverage_keys()), obs.state

    def events(self, run_id):
        return jr.replay(run_id, self.root).events


class ResumeSweepTest(_Base):
    def test_every_task_and_crash_point(self):
        base_req, base_find, base_cov, base_state = self.baseline(post_form=False)
        self.assertEqual(base_state, "completed")
        for task in TASKS:
            for tmpl in CRASH_POINTS:
                crash = tmpl.format(t=task)
                with self.subTest(crash=crash):
                    with FixtureServer(post_form=False) as srv:
                        p, rid = self.child(srv, crash)
                        self.assertEqual(p.returncode, 137, p.stderr[-500:])
                        child_sent = srv.request_counter()
                        child_total = sum(child_sent.values())
                        obs = self.resume(srv, rid)
                        final = srv.request_counter()
                    self.assertEqual((obs.result_count, obs.done_count), (1, 1))
                    # 二重実行なし: どのリクエストも、中断なしの実行より多く送られない
                    self.assertEqual(final - base_req, Counter(), crash)
                    ev = self.events(rid)
                    resumed = [e for e in ev if e["type"] == "run_resumed"]
                    self.assertEqual(len(resumed), 1)
                    # 予算の巻き戻しなし: 前回の消費(不明分は上限)が、実際に送った数を下回らない
                    self.assertGreaterEqual(resumed[0]["prior_requests"], child_total, crash)
                    # 完了済みタスクの再実行なし: 再開後に action_started が増えるのは未完了のタスクだけ
                    after = ev[ev.index(resumed[0]):]
                    done_before = {t for t, st in derive_task_states(ev[:ev.index(resumed[0])]).items()
                                   if st == TaskState.DONE}
                    restarted = [e["task_id"] for e in after if e["type"] == "action_started"]
                    self.assertFalse(set(restarted) & done_before, (crash, restarted, done_before))
                    # Findingの二重作成なし
                    self.assertLessEqual(obs.finding_keys() - base_find, Counter())
                    if obs.state == "completed":
                        self.assertEqual(final, base_req, crash)
                        self.assertEqual(obs.finding_keys(), base_find)
                        self.assertEqual(_cov(obs.coverage_keys()), base_cov)
                    else:
                        # 結果不明のタスクが残る: 何も得られていなければfailed、一部あればpartial。必ず理由を示す
                        self.assertIn(obs.state, ("partial", "failed"))
                        self.assertTrue(any("不明" in e for e in obs.result["errors"]), obs.result["errors"])
                    self.assertEqual(ev[-1]["type"], "run_finished")


class UnknownOutcomeTest(_Base):
    def test_unknown_is_not_retried_automatically_and_retry_is_explicit(self):
        base_req, base_find, _cov, _st = self.baseline(post_form=False)
        with FixtureServer(post_form=False) as srv:
            p, rid = self.child(srv, "store:finish_task:fuzz:before")        # 送信済み・commit前
            self.assertEqual(p.returncode, 137)
            child_total = srv.request_counter()
            obs = self.resume(srv, rid)
            self.assertEqual(srv.request_counter(), child_total)             # 自動では再送されない
            self.assertEqual(obs.state, "partial")
            with RunStore(rid, self.root) as store:
                st = store.tasks()
            self.assertEqual(st["fuzz"]["state"], "unknown_outcome")
            self.assertEqual(st["triage"]["state"], "skipped")                # 依存先は動かない
        with FixtureServer(post_form=False) as srv2:
            p, rid2 = self.child(srv2, "store:finish_task:fuzz:before")
            obs2 = self.resume(srv2, rid2, retry_unknown=["fuzz"], additional_requests=300)
            ev = self.events(rid2)
            self.assertEqual(obs2.state, "completed")
            self.assertEqual(obs2.finding_keys(), base_find)
            auth_ev = [e for e in ev if e["type"] == "reexecution_authorized"]
            self.assertEqual([(e["task_id"], e["reason"]) for e in auth_ev], [("fuzz", "retry_unknown")])
            # 明示した再実行のぶんだけ、ファジングの送信が重複する(クロールは重複しない)
            fin = srv2.request_counter()
            dup = fin - base_req
            self.assertGreater(sum(dup.values()), 0)
            self.assertTrue(all(k[1] != "/" for k in dup))

    def test_unknown_consumption_is_not_refunded(self):
        with FixtureServer(post_form=False) as srv:
            p, rid = self.child(srv, "journal:action_started:fuzz:after")
            self.assertEqual(p.returncode, 137)
            obs = self.resume(srv, rid)                                       # 追加予算なしでは再実行できない
            prior = [e for e in self.events(rid) if e["type"] == "run_resumed"][0]["prior_requests"]
        self.assertGreaterEqual(prior, 200)                                   # 不明分は宣言上限で計上
        obs2 = None
        with FixtureServer(post_form=False) as srv2:
            p, rid2 = self.child(srv2, "journal:action_started:fuzz:after")
            obs2 = self.resume(srv2, rid2, retry_unknown=["fuzz"])            # 追加予算なし
            denied = [e for e in self.events(rid2) if e["type"] == "gate_decision" and e["task_id"] == "fuzz"]
        self.assertEqual(denied[-1]["reason_codes"], ["budget.requests_exhausted"])
        self.assertEqual(obs2.state, "partial")


class AuthResumeTest(_Base):
    def kw(self, srv):
        return {"auth": {"cookie": f"sid={TOK_A}", "confirm_url": srv.base_url + "me",
                         "expect_text": "Hello alice"}}

    def grant_specs(self, srv):
        return [{"capability": "web.authenticate", "args": auth_action_args(srv.base_url, "a")}]

    def grants(self, srv):
        return [new_grant("web.authenticate", auth_action_args(srv.base_url, "a"),
                          expires_at=time.time() + 600)]

    def run_kwargs(self, srv):
        return dict(self.kw(srv))

    def test_reapplying_auth_needs_a_fresh_approval(self):
        with FixtureServer(post_form=False, auth=True) as srv:
            p, rid = self.child(srv, "journal:action_finished:fuzz:after",
                                run=self.run_kwargs(srv), grants=self.grant_specs(srv))
            self.assertEqual(p.returncode, 137, p.stderr[-400:])
            cookies_before = len(srv.cookies_seen)
            # 承認なし: 認証を再適用せず、認証前提の送信もしない
            obs = self.resume(srv, rid, **self.kw(srv))
            self.assertEqual(len(srv.cookies_seen), cookies_before)
            self.assertEqual(obs.state, "partial")
        self.assertTrue(any("approval.missing" in e or "セッション" in e or "approval" in e
                            for e in obs.result["errors"]))

    def test_fresh_approval_completes_the_resumed_run(self):
        with FixtureServer(post_form=False, auth=True) as srv:
            p, rid = self.child(srv, "journal:action_finished:fuzz:after",
                                run=self.run_kwargs(srv), grants=self.grant_specs(srv))
            self.assertEqual(p.returncode, 137)
            fresh = self.grants(srv)
            obs = self.resume(srv, rid, approvals=fresh, **self.kw(srv))
            used = [e for e in self.events(rid) if e["type"] == "approval_consumed"]
            self.assertEqual(len(used), 2)                                    # 当初 + 再適用
            self.assertEqual(obs.state, "completed")
            reuse = [e for e in self.events(rid) if e["type"] == "reexecution_authorized"]
            self.assertEqual([e["reason"] for e in reuse], ["session_reapply"])


    def test_a_consumed_grant_stays_consumed_across_crashes(self):
        """再開で消費した承認は、再度クラッシュして再開しても使えない(状態ストアとジャーナルが消費を記憶する)。"""
        with FixtureServer(post_form=False, auth=True) as srv:
            args = auth_action_args(srv.base_url, "a")
            g1 = {"capability": "web.authenticate", "args": args, "grant_id": "grant_first00001"}
            g2 = {"capability": "web.authenticate", "args": args, "grant_id": "grant_second0002"}
            p, rid = self.child(srv, "journal:action_finished:fuzz:after", run=self.run_kwargs(srv), grants=[g1])
            self.assertEqual(p.returncode, 137)
            # 1回目の再開(g2を消費)も、トリアージ中に再びクラッシュさせる
            run = dict(self.run_kwargs(srv), resume_run_id=rid, allowed_targets=["127.0.0.1"], max_requests=200,
                       profile="aggressive")
            cfg = {"target": srv.base_url, "journal_root": self.root, "crash": "store:finish_task:triage:before",
                   "run": run, "grants": [g2], "config": {}}
            p2 = subprocess.run([sys.executable, CHILD, json.dumps(cfg)], cwd=ROOT, capture_output=True,
                                text=True, timeout=120)
            self.assertEqual(p2.returncode, 137, p2.stderr[-400:])
            cookies = len(srv.cookies_seen)
            # 2回目の再開で同じg2を使っても拒否される
            reused = new_grant("web.authenticate", args, expires_at=time.time() + 600, grant_id="grant_second0002")
            obs = self.resume(srv, rid, approvals=[reused], **self.kw(srv))
            self.assertEqual(len(srv.cookies_seen), cookies)                   # 認証は再適用されない
            gate = [e for e in self.events(rid) if e["type"] == "gate_decision" and e["task_id"] == "auth_a"]
            self.assertEqual(gate[-1]["reason_codes"], ["approval.reused"])
            self.assertEqual(obs.state, "partial")
            self.assertEqual(len([e for e in self.events(rid) if e["type"] == "approval_consumed"]), 2)


class RefusalTest(_Base):
    def test_changed_profile_is_refused_without_side_effects(self):
        with FixtureServer(post_form=False) as srv:
            p, rid = self.child(srv, "journal:action_finished:crawl:after")
            self.assertEqual(p.returncode, 137)
            before_events = len(self.events(rid))
            before_req = srv.request_counter()
            for change in (dict(max_requests=500), dict(allowed_targets=["127.0.0.1", "10.0.0.0/8"]),
                           dict(max_pages=5)):
                with self.subTest(change):
                    obs = self.resume(srv, rid, **change)
                    self.assertEqual(obs.state, "failed")
                    self.assertTrue(any("プロファイル" in e for e in obs.result["errors"]))
            self.assertEqual(len(self.events(rid)), before_events)            # 一切書き込まない
            self.assertEqual(srv.request_counter(), before_req)               # 一切送信しない
            ok = self.resume(srv, rid)                                         # 変更なしなら再開できる
            self.assertEqual(ok.state, "completed")

    def test_finished_run_cannot_be_resumed(self):
        with FixtureServer(post_form=False) as srv:
            obs = run_agent(srv, AutonomousFuzzAgent, allowed_targets=["127.0.0.1"], max_requests=200,
                            journal_root=self.root)
            rid = obs.agent.last_run_id
            again = self.resume(srv, rid)
        self.assertEqual(again.state, "failed")
        self.assertTrue(any("終了済み" in e for e in again.result["errors"]))

    def test_unknown_retry_task_and_missing_run_are_refused(self):
        with FixtureServer(post_form=False) as srv:
            p, rid = self.child(srv, "journal:action_finished:crawl:after")
            bad = self.resume(srv, rid, retry_unknown=["nope"])
            self.assertEqual(bad.state, "failed")
            missing = self.resume(srv, jr.new_run_id())
            self.assertEqual(missing.state, "failed")

    def test_state_store_holds_no_raw_credentials(self):
        with FixtureServer(post_form=False, auth=True) as srv:
            kw = {"auth": {"cookie": f"sid={TOK_A}", "confirm_url": srv.base_url + "me",
                           "expect_text": "Hello alice"}}
            g = [{"capability": "web.authenticate", "args": auth_action_args(srv.base_url, "a")}]
            p, rid = self.child(srv, "journal:action_finished:fuzz:after", run=kw, grants=g)
            self.assertEqual(p.returncode, 137)
        for name in ("state.sqlite3", "state.sqlite3-wal", jr.JOURNAL_FILE):
            path = os.path.join(self.root, rid, name)
            if os.path.exists(path):
                with open(path, "rb") as f:
                    self.assertNotIn(TOK_A.encode(), f.read(), name)


if __name__ == "__main__":
    unittest.main()
