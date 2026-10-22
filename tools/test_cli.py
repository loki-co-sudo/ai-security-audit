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
import cli

from cli import exit_code
from core.autonomy.journal import replay
from testlab.fixtures.web_fixture import FixtureServer

ROOT = str(Path(__file__).resolve().parents[1])
CHILD = r'''
import json, os, sys, time
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
    if os.environ.get("CLI_TEST_PROFILES"):
        config._cfg["profiles"] = json.loads(os.environ["CLI_TEST_PROFILES"])
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

    def test_format_md_prints_markdown_and_effort_auto_resolves(self):
        src = self.base / "app.py"
        src.write_text("import os\ndef run(x):\n    os.system(x)\n")
        p = subprocess.run(self.command(["scan", "audit", "--target", str(src), "--format", "md", "--effort", "auto"]),
                           cwd=self.base, env=self.env(), capture_output=True, text=True, timeout=45)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(p.stdout.startswith("# "), p.stdout[:80])        # JSONではなくMarkdown
        self.assertIn("## [", p.stdout)
        self.assertRegex(p.stderr, r"effort auto -> (speed|balanced|quality)")
        p, data = self.call(["scan", "audit", "--target", str(src), "--effort", "auto"])
        self.assertEqual(data["state"], "completed", data)               # 既定のjsonは従来どおり
        p, data = self.call(["scan", "audit", "--target", str(src), "--effort", "bogus"])
        self.assertEqual(p.returncode, 2)

    def test_scan_audit_accepts_a_project_directory(self):
        proj = self.base / "proj"
        (proj / "app").mkdir(parents=True)
        (proj / "app" / "views.py").write_text("@app.route('/u')\ndef u(uid):\n    return db.get(uid)\n")
        (proj / "app" / "db.py").write_text("def get(uid):\n    return cur.execute('SELECT ' + uid)\n")
        p, data = self.call(["scan", "audit", "--target", str(proj), "--fail-on", "high"])
        self.assertIn(data["state"], ("completed", "partial"), data)
        self.assertEqual(p.returncode, 1, data)
        self.assertTrue(any(c["target_ref"] == "app/views.py" and c["status"] == "tested" for c in data["coverage"]))
        p, data = self.call(["scan", "audit", "--target", str(self.base / "missing_dir")])
        self.assertEqual((p.returncode, data["state"]), (2, "failed"))

    def test_scan_defense_single_pass_over_a_local_log(self):
        attack = self.base / "attack.log"
        attack.write_text('10.0.0.5 - - [22/Oct/2026:01:00:00 +0900] "GET /?q=1 UNION SELECT 1,2 HTTP/1.1" 200 12 "-" "x"\n')
        benign = self.base / "benign.log"
        benign.write_text('10.0.0.6 - - [22/Oct/2026:01:00:01 +0900] "GET /index.html HTTP/1.1" 200 5 "-" "x"\n')
        p, data = self.call(["scan", "defense", "--target", str(attack)])      # watchせず終了すること(timeout=45で検証)
        self.assertEqual((p.returncode, data["state"]), (0, "completed"), data)
        self.assertIn("1 alerts", p.stderr)                                    # シグネチャ検知はLLMに依存せず動く
        p, data = self.call(["scan", "defense", "--target", str(benign)])
        self.assertEqual(data["state"], "completed", data)
        self.assertIn("0 alerts", p.stderr)
        p, data = self.call(["scan", "defense", "--target", str(self.base / "none.log")])
        self.assertEqual((p.returncode, data["state"]), (2, "failed"))

    def test_use_profile_expands_defaults_and_explicit_args_win(self):
        prof = {"lab": {"engagement_id": "lab1", "target": "X", "effort": "speed", "allow": ["a.example", "b.example"],
                        "scan_profile": "aggressive", "max_requests": 50, "tls_verify": True}}
        a = cli.expand_profile(["scan", "fuzz", "--use-profile", "lab", "--max-requests", "7"], prof)
        self.assertEqual(a[:2], ["scan", "fuzz"])
        self.assertEqual(a.count("--allow"), 2)
        self.assertIn("--tls-verify", a)
        self.assertEqual(a[a.index("--max-requests") + 1], "7")           # 明示引数が優先
        self.assertEqual(a.count("--max-requests"), 1)
        b = cli.expand_profile(["scan", "audit", "--use-profile", "lab"], prof)
        self.assertNotIn("--allow", b)                                     # モード非対応のキーは無視
        self.assertNotIn("--max-requests", b)
        for bad in ({"lab": {"api_key": "SECRET_X"}}, {"lab": {"tls_verify": "yes"}}, {}):
            with self.assertRaises(cli.CLIError) as cm:
                cli.expand_profile(["scan", "fuzz", "--use-profile", "lab"], bad)
            self.assertNotIn("SECRET_X", str(cm.exception))

    def test_profile_scope_mode_only_accepts_block_and_rate_limit_is_fuzz_only(self):
        ok = cli.expand_profile(["scan", "fuzz", "--use-profile", "p"],
                                {"p": {"scope_mode": "block", "rate_limit_rps": 2.5, "target": "X"}})
        self.assertEqual(ok[ok.index("--rate-limit-rps") + 1], "2.5")
        self.assertNotIn("block", ok)                                       # フラグにはならない(検証のみ)
        for mode in ("warn", "", None, True):
            with self.assertRaises(cli.CLIError, msg=mode):
                cli.expand_profile(["scan", "fuzz", "--use-profile", "p"], {"p": {"scope_mode": mode}})
        with self.assertRaises(cli.CLIError):                               # 他モードでもwarnは受け付けない
            cli.expand_profile(["scan", "attack", "--use-profile", "p"], {"p": {"scope_mode": "warn"}})
        a = cli.expand_profile(["scan", "audit", "--use-profile", "p"], {"p": {"rate_limit_rps": 2, "target": "X"}})
        self.assertNotIn("--rate-limit-rps", a)                             # fuzz以外には渡さない

    def test_rate_limit_rps_is_validated_and_persisted_for_resume(self):
        with FixtureServer(post_form=False) as srv:
            for bad in ("0", "-1", "abc", "1001", "nan"):
                p, data = self.call(self.scan(srv, "--rate-limit-rps", bad))
                self.assertEqual(p.returncode, 2, (bad, data))
            self.assertEqual(srv.count(), 0)
            p, data = self.call(self.scan(srv, "--rate-limit-rps", "50"))
            self.assertEqual(data["state"], "completed", data)
            from agents.fuzz_capabilities import load_profile
            self.assertEqual(load_profile(data["run_id"], str(self.runs))["rate_limit_rps"], 50.0)

    def test_webfuzzer_rate_limit_only_tightens_the_profile_rate(self):
        from tools.web_fuzzer import WebFuzzer
        rate = lambda profile, cap: WebFuzzer(profile=profile, rate_limit_rps=cap).transport.policy.rate_per_sec  # noqa: E731
        self.assertEqual(rate("stealth", 2), 2)               # プロファイル5/秒より厳しく
        self.assertEqual(rate("stealth", 50), 5)              # 緩める方向には働かない
        self.assertEqual(rate("aggressive", 3), 3)            # 無制限のプロファイルには上限を足せる
        self.assertIsNone(rate("aggressive", None))
        self.assertEqual(rate("stealth", None), 5)

    def test_use_profile_end_to_end_and_unknown_profile_fails(self):
        src = self.base / "app.py"
        src.write_text("def f():\n    return 1\n")
        profiles = json.dumps({"p": {"target": str(src), "effort": "speed"}})
        p = subprocess.run(self.command(["scan", "audit", "--use-profile", "p"]), cwd=self.base,
                           env=self.env(CLI_TEST_PROFILES=profiles), capture_output=True, text=True, timeout=45)
        self.assertEqual(json.loads(p.stdout)["state"], "completed", p.stdout)
        p, data = self.call(["scan", "audit", "--use-profile", "missing"])
        self.assertEqual((p.returncode, data["state"]), (2, "failed"))

    def test_scan_defense_duration_watches_appended_lines_then_ends(self):
        log = self.base / "live.log"
        log.write_text('10.0.0.6 - - [22/Oct/2026:01:00:01 +0900] "GET /index.html HTTP/1.1" 200 5 "-" "x"\n')
        proc = subprocess.Popen(self.command(["scan", "defense", "--target", str(log), "--duration", "4"]),
                                cwd=self.base, env=self.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(1.5)
        with open(log, "a") as fh:
            fh.write('10.0.0.5 - - [22/Oct/2026:01:00:02 +0900] "GET /?q=1 UNION SELECT 1,2 HTTP/1.1" 200 12 "-" "x"\n')
        out, err = proc.communicate(timeout=40)
        data = json.loads(out)
        self.assertEqual(data["state"], "completed", data)           # 期限終了はcancelledではない
        self.assertIn("1 alerts", err)                                # 開始後に追記された行も検知する
        self.assertTrue(any("指定時間" in e for e in data["errors"]), data["errors"])
        p, data = self.call(["scan", "defense", "--target", str(log), "--duration", "0"])
        self.assertEqual((p.returncode, data["state"]), (2, "failed"))

    def test_scan_runner_does_not_import_the_gui(self):
        code = ("import sys, core.scan_runner as r, cli; "
                "bad=[m for m in ('tkinter','customtkinter','gui') if m in sys.modules]; "
                "assert not bad, bad; assert r.CLIError is cli.CLIError")
        p = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=self.env(), capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_targets_file_for_audit_defense_and_attack(self):
        a, b = self.base / "a.py", self.base / "b.py"
        a.write_text("import os\ndef run(x):\n    os.system(x)\n")
        b.write_text("def f():\n    return 1\n")
        tf = self.base / "targets.txt"
        tf.write_text(f"# comment\n{a}\n{b}\n{self.base / 'missing.py'}\n")
        p, data = self.call(["scan", "audit", "--targets-file", str(tf), "--fail-on", "high"])
        self.assertTrue(data["batch"], data)
        self.assertEqual([r["target"] for r in data["results"]], [str(a), str(b), str(self.base / "missing.py")])
        self.assertEqual([r["state"] for r in data["results"]][2], "failed")       # 失敗は他対象の結果を消さない
        self.assertEqual(data["state"], "partial")
        self.assertEqual(p.returncode, 2, data)                                   # completedでなければ所見より優先して2
        two = self.base / "two.txt"
        two.write_text(f"{a}\n{b}\n")
        p, data = self.call(["scan", "audit", "--targets-file", str(two), "--fail-on", "high"])
        self.assertEqual((data["state"], p.returncode, len(data["findings"])), ("completed", 1, 2), data)
        log = self.base / "x.log"
        log.write_text('10.0.0.6 - - [22/Oct/2026:01:00:01 +0900] "GET /index.html HTTP/1.1" 200 5 "-" "x"\n')
        tf2 = self.base / "logs.txt"
        tf2.write_text(f"{log}\n{log}\n")                                          # 重複は1件
        p, data = self.call(["scan", "defense", "--targets-file", str(tf2)])
        self.assertEqual((len(data["results"]), data["state"]), (1, "completed"), data)
        p, data = self.call(["scan", "audit", "--target", str(a), "--targets-file", str(tf)])
        self.assertEqual(p.returncode, 2)                                           # 排他
        empty = self.base / "empty.txt"
        empty.write_text("# nothing\n")
        p, data = self.call(["scan", "audit", "--targets-file", str(empty)])
        self.assertEqual((p.returncode, data["state"]), (2, "failed"))
        with FixtureServer(post_form=False) as srv:
            host = srv.base_url.split("//")[1].split("/")[0]
            tf3 = self.base / "hosts.txt"
            tf3.write_text(f"{host}\n192.0.2.1\n")
            p, data = self.call(["scan", "attack", "--targets-file", str(tf3), "--allow", "127.0.0.1", "--no-web",
                                 "--profile", "aggressive"])
            states = {r["target"]: r["state"] for r in data["results"]}
            self.assertEqual(states["192.0.2.1"], "failed", data)                   # 許可外は送らず失敗
            self.assertIn(states[host], ("completed", "partial"), data)

    def test_scan_attack_is_scoped_and_exclude_wins(self):
        with FixtureServer(post_form=False) as srv:
            host = srv.base_url.split("//")[1].split("/")[0]
            base = ["scan", "attack", "--target", host, "--profile", "aggressive"]
            p, data = self.call([*base, "--allow", "192.0.2.1"])                    # 範囲外=scope_mode=blockで送信しない
            self.assertEqual((p.returncode, data["state"]), (2, "failed"), data)
            self.assertEqual(srv.count(), 0)
            p, data = self.call([*base, "--allow", "127.0.0.1", "--exclude", "127.0.0.0/8"])
            self.assertEqual((p.returncode, data["state"]), (2, "failed"))
            self.assertEqual(srv.count(), 0)
            p, data = self.call(["scan", "attack", "--target", host])               # --allow必須
            self.assertEqual(p.returncode, 2)
            p, data = self.call([*base, "--allow", "127.0.0.1", "--no-web"])
            self.assertIn(data["state"], ("completed", "partial"), data)
            self.assertIn("errors", data)

    def ledger_args(self, *a):
        return [*a, "--engagement-id", "lab", "--ledger-root", str(self.base / "ledger")]

    def test_ledger_records_scans_and_diff_status_suppress_flow(self):
        with FixtureServer(post_form=False) as srv:
            p, first = self.call(self.scan(srv, "--engagement-id", "lab", "--ledger-root", str(self.base / "ledger")))
            self.assertEqual((p.returncode, first["engagement_id"]), (0, "lab"), first)
            self.assertNotIn("ledger_error", first)
            self.assertTrue(first["target"].startswith("http://127.0.0.1"))        # ScanResult本来のtargetを消さない
            events = [json.loads(x) for x in (self.base / "ledger" / "lab" / "events.jsonl").read_text().splitlines()]
            self.assertEqual({e["target"] for e in events if e["type"] == "scan_recorded"}, {first["target"]})
            p, second = self.call(self.scan(srv, "--engagement-id", "lab", "--ledger-root", str(self.base / "ledger")))
            a, b = first["scan_id"], second["scan_id"]
            p, d = self.call(["diff", "--before", a, "--after", b, "--engagement-id", "lab",
                              "--ledger-root", str(self.base / "ledger"), "--fail-on", "high"])
            self.assertEqual(d["state"], "completed", d)
            self.assertTrue(d["items"])
            self.assertEqual(p.returncode, 0 if not d["findings"] else 1)
            fid = d["items"][0]["finding_id"]
            p, m = self.call(["mark", fid, "fixed", "--reason", "修正済み", *self.ledger_args()])
            self.assertEqual((p.returncode, m["status"]), (0, "fixed"), m)
            p, bad = self.call(["mark", fid, "fixed", "--reason", " ", *self.ledger_args()])
            self.assertEqual(p.returncode, 2)
            p, bad = self.call(["mark", "f_0123456789abcdef", "fixed", "--reason", "x", *self.ledger_args()])
            self.assertEqual(p.returncode, 2)
            p, s_ = self.call(["suppress", fid, "--reason", "調整中", "--until", "2999-01-01T00:00:00+00:00",
                               *self.ledger_args()])
            self.assertEqual(p.returncode, 0, s_)
            p, f = self.call(["findings", *self.ledger_args()])
            self.assertTrue(all(x["finding_id"] != fid for x in f["findings"]))
            self.assertEqual(f["suppressed_count"], 1)
            p, f = self.call(["findings", "--include-suppressed", *self.ledger_args()])
            self.assertTrue(any(x["finding_id"] == fid and x["suppressed"] for x in f["findings"]))
            p, bad = self.call(["diff", "--before", a, "--after", "nope", *self.ledger_args()])
            self.assertEqual((p.returncode, bad["state"]), (2, "failed"))
            p, bad = self.call(["findings", "--engagement-id", "../x", "--ledger-root", str(self.base / "ledger")])
            self.assertEqual(p.returncode, 2)
            p, bad = self.call(self.scan(srv, "--engagement-id", "a", "--engagement",
                                         self.engagement_file({"engagement_id": "b"}, "mismatch.json")))
            self.assertEqual(p.returncode, 2)

    def test_scan_output_carries_ledger_view_and_fail_on_ignores_only_active_suppressions(self):
        files = [self.base / "a.py", self.base / "b.py"]
        for f in files:
            f.write_text("import os\ndef run(x):\n    os.system(x)\n")
        tf = self.base / "two.txt"
        tf.write_text("\n".join(map(str, files)) + "\n")
        led = ["--engagement-id", "lab2", "--ledger-root", str(self.base / "ledger2")]
        scan = ["scan", "audit", "--targets-file", str(tf), *led, "--fail-on", "high"]
        until = ["--until", "2999-01-01T00:00:00+00:00"]
        p, first = self.call(scan)
        self.assertEqual((p.returncode, first["state"]), (1, "completed"), first)
        ids = [r["ledger"]["findings"][0]["finding_id"] for r in first["results"]]
        self.assertEqual([len(r["ledger"]["findings"]) for r in first["results"]], [1, 1])
        self.assertEqual(len(set(ids)), 2, ids)
        self.assertFalse(any(r["ledger"]["findings"][0]["suppressed"] for r in first["results"]))
        _, s_ = self.call(["suppress", ids[0], "--reason", "調整中", *until, *led])
        self.assertEqual(s_["state"], "completed", s_)
        p, second = self.call(scan)
        self.assertEqual(p.returncode, 1, second)                          # 一部だけ抑制 → 残りの所見で失敗する
        self.assertEqual(len(second["findings"]), 2)                       # JSONの所見は落とさない
        self.assertEqual([r["ledger"]["findings"][0]["suppressed"] for r in second["results"]], [True, False])
        self.call(["suppress", ids[1], "--reason", "調整中", *until, *led])
        p, third = self.call(scan)
        self.assertEqual((p.returncode, third["state"]), (0, "completed"), third)   # 全件が期限内の抑制
        self.assertEqual(len(third["findings"]), 2)
        p = subprocess.run(self.command([*scan[:-2], "--format", "md"]), cwd=self.base, env=self.env(),
                           capture_output=True, text=True, timeout=45)
        self.assertEqual(p.stdout.count("Suppressed: 1 "), 2, p.stdout)
        self.assertIn("Ledger: engagement=lab2", p.stdout)
        p, plain = self.call(["scan", "audit", "--targets-file", str(tf), "--fail-on", "high"])
        self.assertEqual(p.returncode, 1)                                  # engagement無しは従来どおり全所見で判定
        self.assertTrue(all("ledger" not in r for r in plain["results"]))

    def test_openapi_adds_unlinked_get_endpoints_to_coverage_without_trusting_servers(self):
        import http.server
        import threading

        class Srv:
            def __init__(self):
                self.paths = []
                outer = self

                class H(http.server.BaseHTTPRequestHandler):
                    def log_message(self, *a):
                        pass

                    def do_GET(self):
                        outer.paths.append(self.path)
                        body = b"<html><body>no links</body></html>"
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
                threading.Thread(target=self.srv.serve_forever, daemon=True).start()
                self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/"

            def close(self):
                self.srv.shutdown()
                self.srv.server_close()

        main, other = Srv(), Srv()
        self.addCleanup(main.close)
        self.addCleanup(other.close)
        spec = self.base / "api.json"
        spec.write_text(json.dumps({"openapi": "3.0.3", "paths": {
            "/hidden": {"get": {"operationId": "hidden", "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]}},
            "/other": {"get": {"operationId": "other", "parameters": [{"name": "z", "in": "query"}]}},
            "/danger": {"post": {"operationId": "danger", "parameters": [{"name": "w", "in": "query"}]}}},
            "servers": [{"url": other.url}]}))
        args = self.scan(type("S", (), {"base_url": main.url}))
        p, base = self.call(args)                                    # --openapiなし: 隠しAPIは検査されない
        self.assertFalse([x for x in main.paths if x.startswith("/hidden")])
        p, data = self.call([*args, "--openapi", str(spec), "--openapi-op", "hidden"])
        self.assertTrue([x for x in main.paths if x.startswith("/hidden?q=")])
        self.assertFalse([x for x in main.paths if x.startswith("/other")])      # 選択していないoperation
        self.assertEqual(other.paths, [])                                         # serversのURLへは送らない
        hidden = {c["rule_id"]: c["status"] for c in data["coverage"]
                  if c["target_ref"].endswith("/hidden") and c["parameter"] == "q"}
        self.assertEqual(hidden, {f"WEB_FUZZ_{c}": "tested" for c in ("SQLI", "XSS", "TRAVERSAL", "SSTI")})
        for bad in (["--openapi", str(spec)], ["--openapi", str(spec), "--openapi-op", "danger"],
                    ["--openapi", str(spec), "--openapi-op", "nope"], ["--openapi-op", "hidden"],
                    ["--openapi", str(self.base / "missing.json"), "--openapi-op", "hidden"]):
            n = len(main.paths)
            p, bad_r = self.call([*args, *bad])
            self.assertEqual((p.returncode, bad_r["state"]), (2, "failed"), bad)
            self.assertEqual(len(main.paths), n)
        p, listing = self.call(["openapi", str(spec)])
        self.assertEqual(sorted(o["operation_id"] for o in listing["operations"]), ["danger", "hidden", "other"])
        self.assertEqual([o["selectable"] for o in listing["operations"] if o["operation_id"] == "danger"], [False])

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
