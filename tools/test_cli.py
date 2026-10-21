"""CLIのプロセス境界試験。LLMはMockLLM、HTTPは127.0.0.1のFixtureServerのみ。"""
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from cli import exit_code
from core.autonomy.journal import replay
from testlab.fixtures.web_fixture import FixtureServer

ROOT = str(Path(__file__).resolve().parents[1])
CHILD = r'''
import os, sys, time
from pathlib import Path
from unittest.mock import patch
import cli
from core import config
from tools.fuzz_characterization import MockLLM
from agents.fuzz_agent import FuzzAgent
from tools.autonomy_crash_child import install_crash
if os.environ.get("CLI_TEST_CRASH"):
    install_crash(os.environ["CLI_TEST_CRASH"])
original = cli.AutonomousFuzzAgent._cap_crawl
def crawl(self, *a, **kw):
    result = original(self, *a, **kw)
    ready = os.environ.get("CLI_TEST_READY")
    if ready:
        Path(ready).touch()
        while not self.is_stopped():
            time.sleep(0.01)
    return result
with patch.dict(config._cfg, {**config._DEFAULTS, "effort": "speed"}, clear=True), \
     patch.object(config, "load", lambda: None), \
     patch.object(cli, "LLMClient", lambda **kw: MockLLM()), \
     patch.object(FuzzAgent, "_save_investigation", lambda *a, **kw: None), \
     patch.object(FuzzAgent, "_record_telemetry", lambda *a, **kw: None), \
     patch.object(cli.AutonomousFuzzAgent, "_cap_crawl", crawl):
    sys.exit(cli.main(sys.argv[1:]))
'''


class CLITest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.runs = self.base / "runs"

    def command(self, args):
        return [sys.executable, "-c", CHILD, *args]

    def env(self, **extra):
        return {**os.environ, "PYTHONPATH": ROOT, **extra}

    def call(self, args):
        p = subprocess.run(self.command(args), cwd=self.base, env=self.env(), capture_output=True,
                           text=True, timeout=45)
        data = json.loads(p.stdout)
        self.assertIsInstance(data, dict)
        return p, data

    def crash(self, args):
        before = set(self.runs.glob("run_*"))
        p = subprocess.run(self.command(args), cwd=self.base,
                           env=self.env(CLI_TEST_CRASH="journal:gate_decision:triage:after"),
                           capture_output=True, text=True, timeout=45)
        self.assertEqual(p.returncode, 137, p.stderr)
        created = set(self.runs.glob("run_*")) - before
        self.assertEqual(len(created), 1)
        return created.pop().name

    def common(self):
        return ["--allow", "127.0.0.1", "--journal-root", str(self.runs)]

    def scan(self, srv, *extra):
        return ["scan", "fuzz", "--target", srv.base_url, "--profile", "aggressive",
                *self.common(), *extra]

    def auth_file(self, srv, mode=0o600):
        path = self.base / "auth.json"
        path.write_text(json.dumps({r: {"cookie": f"sid={token}", "confirm_url": srv.base_url + "me",
                                       "expect_text": f"Hello {name}"}
                                    for r, token, name in (("a", "TOK_ALICE_cli_12345", "alice"),
                                                            ("b", "TOK_BOB_cli_98765", "bob"))}))
        path.chmod(mode)
        return str(path)

    def test_json_progress_and_thresholds(self):
        with FixtureServer(post_form=False) as srv:
            p, data = self.call(self.scan(srv, "--fail-on", "high", "--out", str(self.base / "result.json")))
            self.assertEqual(p.returncode, 1, p.stderr)
            self.assertEqual(data["state"], "completed")
            self.assertTrue(p.stderr)
            self.assertEqual(json.loads((self.base / "result.json").read_text()), data)
            self.assertEqual(json.loads((self.runs / data["run_id"] / "cli_result.json").read_text()), data)
            self.assertTrue(srv.count())
            p, data = self.call(self.scan(srv, "--fail-on", "critical"))
            self.assertEqual(p.returncode, 0, data)

    def test_exit_priority(self):
        for state, expected in (("completed", 1), ("partial", 2), ("failed", 2), ("cancelled", 130)):
            with self.subTest(state=state):
                self.assertEqual(exit_code({"state": state, "findings": [{"severity": "CRITICAL"}]}, "low"), expected)
        self.assertEqual(exit_code({"state": "completed", "findings": [{"severity": "HIGH"}]}), 0)

    def test_budget_and_scope_failure(self):
        with FixtureServer(post_form=False) as srv:
            p, data = self.call(self.scan(srv, "--max-requests", "3"))
            self.assertEqual((p.returncode, data["state"]), (2, "partial"))
            self.assertLessEqual(srv.count(), 3)
            count = srv.count()
            args = self.scan(srv)
            args[args.index("127.0.0.1")] = "192.0.2.1"
            p, data = self.call(args)
            self.assertEqual((p.returncode, data["state"]), (2, "failed"))
            self.assertEqual(srv.count(), count)

    def test_invalid_args_are_json_and_do_not_echo_secrets(self):
        for args in (["scan", "fuzz", "--target", "http://127.0.0.1"],
                     ["status", "run_123456789abc", "--allow", ""],
                     ["scan", "fuzz", "--target", "http://127.0.0.1", "--allow", "127.0.0.1",
                      "--password", "CLI_SECRET_23456"]):
            p, data = self.call(args)
            self.assertEqual(p.returncode, 2)
            self.assertEqual(data["state"], "failed")
            self.assertNotIn("CLI_SECRET_23456", p.stdout + p.stderr)

    def test_loose_permissions_rejected(self):
        with FixtureServer(auth=True) as srv:
            path = self.auth_file(srv, 0o644)
            p, data = self.call(self.scan(srv, "--auth-file", path, "--approve-auth", "a,b"))
            self.assertEqual(p.returncode, 2)
            self.assertIn("0600", str(data))
            self.assertEqual(srv.count(), 0)

    def test_unapproved_auth_sends_nothing(self):
        with FixtureServer(auth=True) as srv:
            path = self.auth_file(srv)
            for extra in ([], ["--approve-auth", "a"]):
                p, data = self.call(self.scan(srv, "--auth-file", path, *extra))
                self.assertEqual(p.returncode, 2)
                self.assertEqual(srv.count(), 0)
                self.assertEqual(srv.cookies_seen, [])

    def test_approved_auth_is_masked_and_single_use(self):
        with FixtureServer(post_form=False, auth=True) as srv:
            path = self.auth_file(srv)
            p, data = self.call(self.scan(srv, "--auth-file", path, "--approve-auth", "a,b", "--permit-t2"))
            self.assertEqual(p.returncode, 0, (data, p.stderr))
            self.assertTrue(any("TOK_ALICE_cli_12345" in c for c in srv.cookies_seen))
            self.assertTrue(any("TOK_BOB_cli_98765" in c for c in srv.cookies_seen))
            rid = data["run_id"]
            events = replay(rid, str(self.runs)).events
            consumed = [e for e in events if e["type"] == "approval_consumed"]
            self.assertEqual(len(consumed), 2)
            self.assertEqual(len({e["grant_id"] for e in consumed}), 2)
            for token in (b"TOK_ALICE_cli_12345", b"TOK_BOB_cli_98765"):
                self.assertNotIn(token, (p.stdout + p.stderr).encode())
                for file in self.runs.rglob("*"):
                    if file.is_file():
                        self.assertNotIn(token, file.read_bytes(), str(file))
            rid = self.crash(self.scan(srv, "--auth-file", path, "--approve-auth", "a,b", "--permit-t2"))
            before = srv.count()
            p, denied = self.call(["resume", rid, *self.common(), "--auth-file", path])
            self.assertEqual(p.returncode, 2)
            self.assertEqual(srv.count(), before)
            p, resumed = self.call(["resume", rid, *self.common(), "--auth-file", path,
                                    "--approve-auth", "a,b"])
            self.assertEqual(p.returncode, 0, resumed)
            consumed = [e for e in replay(rid, str(self.runs)).events if e["type"] == "approval_consumed"]
            self.assertEqual(len({e["grant_id"] for e in consumed}), 4)

    def test_resume_and_read_only_status(self):
        with FixtureServer(post_form=False) as srv:
            p, data = self.call(self.scan(srv))
            self.assertEqual(p.returncode, 0, data)
            rid, count = data["run_id"], srv.count()
            journal = self.runs / rid / "journal.jsonl"
            before = journal.read_bytes()
            p, state = self.call(["status", rid, *self.common()])
            self.assertEqual(p.returncode, 0, state)
            self.assertEqual(state["state"], "completed")
            self.assertTrue(state["tasks"])
            self.assertEqual(journal.read_bytes(), before)
            p, rejected = self.call(["resume", rid, *self.common()])
            self.assertEqual(p.returncode, 2, rejected)
            self.assertEqual(srv.count(), count)
            rid = self.crash(self.scan(srv))
            count = srv.count()
            p, resumed = self.call(["resume", rid, *self.common()])
            self.assertEqual(p.returncode, 0, resumed)
            self.assertEqual(resumed["run_id"], rid)
            self.assertEqual(srv.count(), count)
            self.assertEqual(len(resumed["findings"]), len(data["findings"]))
            for actual, baseline in zip(resumed["findings"], data["findings"]):
                self.assertRegex(actual["finding_id"], r"^finding_[0-9a-f]{12}$")
                self.assertEqual(actual, {**baseline, "finding_id": actual["finding_id"]})

    def engagement_file(self, doc, name="engagement.json"):
        path = self.base / name
        path.write_text(json.dumps(doc))
        return str(path)

    def test_engagement_validation_fails_closed_before_any_request(self):
        row = {"path": "/account", "param": "id", "a": "allow", "b": "deny"}
        bad = [{"cookie": "sid=ENG_SECRET_123456"},                                        # 認証値などの未知キー
               {"idor_expectations": [{**row, "path": "http://evil/account"}]},            # origin付きpath
               {"idor_expectations": [row, row]},                                          # 重複
               {"engagement_id": "bad id!"}]
        with FixtureServer(post_form=False) as srv:
            for doc in bad:
                p, data = self.call(self.scan(srv, "--engagement", self.engagement_file(doc)))
                self.assertEqual((p.returncode, data["state"]), (2, "failed"), doc)
                self.assertNotIn("ENG_SECRET_123456", p.stdout + p.stderr)
            p, data = self.call(self.scan(srv, "--engagement", str(self.base / "missing.json")))
            self.assertEqual(p.returncode, 2)
            self.assertEqual(srv.count(), 0)

    def test_engagement_expectations_are_recorded_and_restored_on_resume(self):
        row = {"path": "/account", "param": "id", "a": "allow", "b": "deny"}
        eng = self.engagement_file({"engagement_id": "lab-1", "idor_expectations": [row]})
        with FixtureServer(post_form=False) as srv:
            rid = self.crash(self.scan(srv, "--engagement", eng))
            db = sqlite3.connect(self.runs / rid / "state.sqlite3")
            try:
                profile = json.loads(db.execute("SELECT value FROM meta WHERE key='profile_json'").fetchone()[0])
            finally:
                db.close()
            self.assertEqual([(e["path"], e["a"], e["b"]) for e in profile["idor_expectations"]],
                             [("/account", "allow", "deny")])
            self.assertNotIn("cookie", json.dumps(profile))
            p, resumed = self.call(["resume", rid, *self.common()])     # 表は開始時のプロファイルから復元される
            self.assertEqual((p.returncode, resumed["state"]), (0, "completed"), resumed)
            p, data = self.call(self.scan(srv, "--engagement", eng))
            self.assertEqual(data["engagement_id"], "lab-1")

    def test_exclude_wins_over_allow_and_sends_nothing(self):
        with FixtureServer(post_form=False) as srv:
            p, data = self.call(self.scan(srv, "--exclude", "127.0.0.1"))
            self.assertEqual((p.returncode, data["state"]), (2, "failed"))
            self.assertIn("除外", data["errors"][0])
            eng = self.engagement_file({"exclude": ["127.0.0.0/8"]}, "ex.json")
            p, data = self.call(self.scan(srv, "--engagement", eng))
            self.assertEqual((p.returncode, data["state"]), (2, "failed"))
            self.assertEqual(srv.count(), 0)
            p, data = self.call(self.scan(srv, "--exclude", "http://x/y"))      # URL/pathは不可
            self.assertEqual(p.returncode, 2)

    def test_targets_file_runs_sequentially_with_isolated_results(self):
        with FixtureServer(post_form=False) as a, FixtureServer(post_form=False) as b:
            tf = self.base / "targets.txt"
            tf.write_text(f"# lab\n{a.base_url}\n{b.base_url}\n{a.base_url}\n")        # 重複は1回だけ
            args = ["scan", "fuzz", "--targets-file", str(tf), "--profile", "aggressive", *self.common()]
            p, data = self.call(args)
            self.assertEqual((p.returncode, data["state"], data["batch"]), (0, "completed", True), data)
            self.assertEqual([r["target"] for r in data["results"]], [a.base_url, b.base_url])
            self.assertEqual(len({r["run_id"] for r in data["results"]}), 2)         # Runは対象ごとに別
            self.assertTrue(a.count() and b.count())
            self.assertTrue(all(f["target"] in (a.base_url, b.base_url) for f in data["findings"]))
            p, data = self.call(args + ["--exclude", "127.0.0.1"])
            self.assertEqual((p.returncode, data["state"]), (2, "failed"))
            tf.write_text(f"{a.base_url}\nhttp://u:p@127.0.0.1/\n")                  # 1件でも不正なら全体を実行しない
            before = a.count()
            p, data = self.call(["scan", "fuzz", "--targets-file", str(tf), *self.common()])
            self.assertEqual(p.returncode, 2)
            self.assertEqual(a.count(), before)

    def test_targets_file_rejects_auth_and_target_conflict(self):
        with FixtureServer(auth=True) as srv:
            tf = self.base / "t.txt"
            tf.write_text(srv.base_url + "\n")
            p, data = self.call(["scan", "fuzz", "--targets-file", str(tf), "--auth-file", self.auth_file(srv),
                                 "--approve-auth", "a,b", *self.common()])
            self.assertEqual(p.returncode, 2)
            self.assertIn("併用", data["errors"][0])
            self.assertEqual(srv.count(), 0)
            p, data = self.call(["scan", "fuzz", "--target", srv.base_url, "--targets-file", str(tf), *self.common()])
            self.assertEqual(p.returncode, 2)

    def test_scan_audit_local_file_json_and_thresholds(self):
        src = self.base / "app.py"
        src.write_text("import os\nPASSWORD = 'AUDIT_SECRET_123456'\ndef run(x):\n    os.system(x)\n")
        out = self.base / "audit.json"
        p, data = self.call(["scan", "audit", "--target", str(src), "--fail-on", "high", "--out", str(out)])
        self.assertEqual(data["state"], "completed", data)
        self.assertEqual(p.returncode, 1, p.stderr)                  # MockLLMの固定所見はHIGH
        self.assertEqual(json.loads(out.read_text()), data)
        self.assertNotIn("AUDIT_SECRET_123456", p.stdout)             # 入力マスキングは常に有効
        p, data = self.call(["scan", "audit", "--target", str(src), "--fail-on", "critical"])
        self.assertEqual(p.returncode, 0, data)
        p, data = self.call(["scan", "audit", "--target", str(self.base / "missing.py")])
        self.assertEqual((p.returncode, data["state"]), (2, "failed"))

    def test_unknown_retry_and_extra_budget(self):
        with FixtureServer(post_form=False) as srv:
            p = subprocess.run(self.command(self.scan(srv)), cwd=self.base,
                               env=self.env(CLI_TEST_CRASH="journal:action_started:fuzz:after"),
                               capture_output=True, text=True, timeout=45)
            self.assertEqual(p.returncode, 137, p.stderr)
            rid = next(self.runs.glob("run_*")).name
            p, result = self.call(["resume", rid, *self.common(), "--retry-unknown", "fuzz",
                                   "--additional-requests", "200"])
            self.assertEqual(p.returncode, 0, result)
            events = replay(rid, str(self.runs)).events
            self.assertTrue(any(e["type"] == "reexecution_authorized" and e["reason"] == "retry_unknown"
                                and e["task_id"] == "fuzz" for e in events))
            resumed = next(e for e in events if e["type"] == "run_resumed")
            self.assertEqual(resumed["additional_requests"], 200)
            self.assertGreaterEqual(resumed["prior_requests"], 200)

    def test_out_failure_returns_failed_and_retains_result(self):
        with FixtureServer(post_form=False) as srv:
            p, result = self.call(self.scan(srv, "--out", str(self.base)))
            self.assertEqual(p.returncode, 2, result)
            self.assertEqual(result["state"], "failed")
            self.assertEqual(json.loads((self.runs / result["run_id"] / "cli_result.json").read_text()), result)

    def test_sigint_saves_result_and_terminal_run_is_not_replayed(self):
        with FixtureServer(post_form=False) as srv:
            ready, output = self.base / "ready", self.base / "cancelled.json"
            child = subprocess.Popen(self.command(self.scan(srv, "--out", str(output))), cwd=self.base,
                                     env=self.env(CLI_TEST_READY=str(ready)), stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 20
                while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(ready.exists(), "crawlが完了しませんでした")
                child.send_signal(signal.SIGINT)
                stdout, stderr = child.communicate(timeout=20)
                data = json.loads(stdout)
                self.assertEqual(child.returncode, 130, stderr)
                self.assertEqual(data["state"], "cancelled")
                self.assertEqual(json.loads(output.read_text()), data)
                self.assertEqual(json.loads((self.runs / data["run_id"] / "cli_result.json").read_text()), data)
                before = srv.count(path="/")
                p, resumed = self.call(["resume", data["run_id"], *self.common()])
                self.assertEqual(p.returncode, 2, resumed)
                self.assertEqual(srv.count(path="/"), before)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate()


if __name__ == "__main__":
    unittest.main()
