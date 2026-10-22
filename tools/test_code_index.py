"""tools/code_index.py(P4.2)の固定試験。対象コードの実行・root外参照・上限・循環を一時ディレクトリで検証する。"""
import os
import re
import shutil
import tempfile
import textwrap
import unittest

from tools import code_index as ci


def w(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(text))
    return p


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.root = os.path.join(self.d, "proj")
        self.outside = os.path.join(self.d, "outside")
        os.makedirs(self.root)
        os.makedirs(self.outside)

    def fn(self, idx, qual):
        (f,) = [x for x in idx.functions if x.qualname == qual]
        return f


class SplitProjectTest(Base):
    def setUp(self):
        super().setUp()
        w(self.root, "app/__init__.py", "")
        w(self.root, "app/views.py", """
            from flask import Flask
            from app import db, auth
            app = Flask(__name__)

            @app.route("/user/<uid>")
            def show_user(uid):
                return db.get_user(uid)          # 認可なし(脆弱)

            @app.route("/me")
            @auth.require_login
            def show_me():
                return db.get_user(auth.current_user())

            def helper_unrelated():
                return 1
        """)
        w(self.root, "app/db.py", """
            def get_user(uid):
                cur = conn.cursor()
                cur.execute("SELECT * FROM users WHERE id = " + str(uid))
                return cur.fetchone()
        """)
        w(self.root, "app/auth.py", """
            def require_login(f):
                return f
            def current_user():
                return session["uid"]
        """)

    def test_entry_auth_and_db_functions_are_prioritized_over_unrelated_ones(self):
        idx = ci.build_index(self.root)
        self.assertEqual(sorted(idx.files), ["app/__init__.py", "app/auth.py", "app/db.py", "app/views.py"])
        show_user, show_me = self.fn(idx, "show_user"), self.fn(idx, "show_me")
        self.assertTrue(show_user.is_entry and not show_user.auth)       # 認可なしの入口
        self.assertTrue(show_me.is_entry and show_me.auth)
        self.assertTrue(self.fn(idx, "get_user").db)
        self.assertGreater(self.fn(idx, "get_user").score, self.fn(idx, "helper_unrelated").score)
        self.assertEqual(self.fn(idx, "helper_unrelated").score, 0)
        self.assertTrue({"app/db.py", "app/auth.py"} <= idx.imports["app/views.py"])

    def test_context_has_file_names_real_line_numbers_and_flags_omissions(self):
        ctx = ci.render_context(ci.build_index(self.root))
        self.assertIn("### app/views.py:", ctx.text)
        self.assertIn("### app/db.py:", ctx.text)
        self.assertRegex(ctx.text, r"\n?\d+\| +cur\.execute\(")                # 実際の行番号つき
        self.assertNotIn("helper_unrelated", ctx.text)                          # 無関係な関数は入らない
        small = ci.render_context(ci.build_index(self.root), budget_chars=250)
        self.assertTrue(small.omitted)
        self.assertIn("Omitted (context budget)", small.text)                   # 入らなかった物は黙って消さない
        self.assertIn("do not assume omitted code is safe", small.text)

    def test_line_movement_does_not_change_function_identity(self):
        before = {(f.file, f.qualname): f for f in ci.build_index(self.root).functions}
        path = os.path.join(self.root, "app/views.py")
        with open(path, encoding="utf-8") as f:
            src = f.read()
        with open(path, "w", encoding="utf-8") as f:
            f.write("# moved\n# moved\n" + src)
        after = {(f.file, f.qualname): f for f in ci.build_index(self.root).functions}
        self.assertEqual(set(before), set(after))                                # 行が動いても同じ関数
        self.assertEqual(after[("app/views.py", "show_user")].start, before[("app/views.py", "show_user")].start + 2)


class SafetyTest(Base):
    def test_target_code_is_never_executed_or_imported(self):
        marker = os.path.join(self.d, "executed.marker")
        w(self.root, "evil.py", f"open({marker!r}, 'w').write('x')\nimport os\nos.system('touch {marker}')\n")
        ci.render_context(ci.build_index(self.root))
        self.assertFalse(os.path.exists(marker))

    def test_excluded_directories_and_secret_files(self):
        w(self.root, ".venv/lib/x.py", "def venv_fn(): pass\n")
        w(self.root, "node_modules/y.py", "def nm(): pass\n")
        w(self.root, "reports/z.py", "def rp(): pass\n")
        w(self.root, ".env", "TOKEN=SECRET_ENV_123\n")
        w(self.root, "keys/server.pem", "-----BEGIN-----\n")
        w(self.root, "secrets.py", "KEY = 'SECRET_PY_456'\n")
        w(self.root, "ok.py", "def fine(): pass\n")
        idx = ci.build_index(self.root)
        self.assertEqual(idx.files, ["ok.py"])
        reasons = dict(idx.skipped)
        self.assertIn("秘密ファイル", reasons["secrets.py"])
        ctx = ci.render_context(idx)
        self.assertNotIn("SECRET_PY_456", ctx.text)
        self.assertNotIn("SECRET_ENV_123", ctx.text)

    def test_symlinks_cannot_escape_the_root(self):
        w(self.outside, "leak.py", "def leaked(): pass\nSECRET = 'OUTSIDE_SECRET_789'\n")
        os.symlink(self.outside, os.path.join(self.root, "linkdir"))
        os.symlink(os.path.join(self.outside, "leak.py"), os.path.join(self.root, "linkfile.py"))
        w(self.root, "inside.py", "def inside(): pass\n")
        idx = ci.build_index(self.root)
        self.assertEqual(idx.files, ["inside.py"])
        self.assertTrue(all("symlink" in r for p, r in idx.skipped if p in ("linkdir", "linkfile.py")))
        self.assertEqual(len([1 for p, _ in idx.skipped if p in ("linkdir", "linkfile.py")]), 2)
        self.assertNotIn("OUTSIDE_SECRET_789", ci.render_context(idx).text)
        # rootそのものがsymlinkでも解決した実体を基準にする
        link_root = os.path.join(self.d, "rootlink")
        os.symlink(self.root, link_root)
        self.assertEqual(ci.build_index(link_root).files, ["inside.py"])

    def test_not_a_directory_is_an_error(self):
        with self.assertRaises(NotADirectoryError):
            ci.build_index(os.path.join(self.d, "missing"))


class LimitsAndGapsTest(Base):
    def test_file_count_size_and_total_limits_are_reported_not_hidden(self):
        for i in range(5):
            w(self.root, f"m{i}.py", f"def f{i}(): pass\n")
        idx = ci.build_index(self.root, max_files=3)
        self.assertEqual(len(idx.files), 3)
        self.assertTrue(idx.limit_hit)
        self.assertEqual(sum("ファイル数上限" in r for _, r in idx.skipped), 2)
        w(self.root, "big.py", "x = 1\n" + "# pad\n" * 5000)
        idx = ci.build_index(self.root, max_file_bytes=1000)
        self.assertTrue(any(p == "big.py" and "サイズ上限" in r for p, r in idx.skipped))
        idx = ci.build_index(self.root, max_total_bytes=40)
        self.assertTrue(any("合計サイズ上限" in r for _, r in idx.skipped))

    def test_syntax_errors_are_skipped_with_reason_and_do_not_stop_the_index(self):
        w(self.root, "broken.py", "def (:\n")
        w(self.root, "good.py", "def ok(): pass\n")
        idx = ci.build_index(self.root)
        self.assertEqual(idx.files, ["good.py"])
        self.assertTrue(any(p == "broken.py" and "SyntaxError" in r for p, r in idx.skipped))
        self.assertIn("broken.py", ci.render_context(idx).text)               # 解析できなかったことを文脈に明記

    def test_dynamic_imports_and_unresolvable_calls_are_not_marked_analyzed(self):
        w(self.root, "dyn.py", """
            import importlib
            def load(name):
                mod = importlib.import_module(name)
                return getattr(mod, "run")()
            def chained(x):
                return x.a()[0]()
        """)
        w(self.root, "plain.py", "def plain(): return 1\n")
        idx = ci.build_index(self.root)
        self.assertEqual(idx.dynamic_files, ["dyn.py"])
        self.assertGreater(self.fn(idx, "load").unresolved, 0)
        self.assertGreater(self.fn(idx, "chained").unresolved, 0)
        self.assertEqual(self.fn(idx, "plain").unresolved, 0)
        self.assertIn("Dynamic import", ci.render_context(idx).text)

    def test_circular_imports_are_detected_without_recursion(self):
        w(self.root, "a.py", "import b\ndef fa(): return b.fb()\n")
        w(self.root, "b.py", "import c\ndef fb(): return c.fc()\n")
        w(self.root, "c.py", "import a\ndef fc(): return a.fa()\n")
        w(self.root, "solo.py", "def s(): pass\n")
        idx = ci.build_index(self.root)
        self.assertEqual(idx.cycles, [["a.py", "b.py", "c.py"]])
        self.assertIn("Circular imports", ci.render_context(idx).text)

    def test_relative_imports_resolve_inside_packages(self):
        w(self.root, "pkg/__init__.py", "")
        w(self.root, "pkg/a.py", "from . import b\nfrom .c import fc\n")
        w(self.root, "pkg/b.py", "def fb(): pass\n")
        w(self.root, "pkg/c.py", "def fc(): pass\n")
        idx = ci.build_index(self.root)
        self.assertEqual(idx.imports["pkg/a.py"], {"pkg/__init__.py", "pkg/b.py", "pkg/c.py"})   # パッケージ本体にも依存

    def test_deep_nesting_does_not_crash(self):
        w(self.root, "deep.py", "x = " + "(" * 150 + "1" + ")" * 150 + "\ndef ok(): pass\n")
        idx = ci.build_index(self.root)
        self.assertTrue(idx.files or idx.skipped)                              # 例外で止まらない


class AuditProjectTest(Base):
    def run_audit(self):
        from unittest import mock
        from agents.audit_agent import AuditAgent
        from core.event_bus import EventBus
        from tools.fuzz_characterization import MockLLM
        llm = MockLLM()
        agent = AuditAgent(EventBus(), llm)
        with mock.patch.object(AuditAgent, "_save_investigation", lambda *a, **k: None), \
             mock.patch.object(AuditAgent, "_record_telemetry", lambda *a, **k: None), \
             mock.patch.dict("core.config._cfg", {**__import__("core.config", fromlist=["x"])._DEFAULTS, "effort": "speed"}, clear=True):
            agent._safe_run(path=self.root)
        return agent._last_scan_result, llm

    def setUp(self):
        super().setUp()
        w(self.root, "app/views.py", """
            from app import db
            API_KEY = "sk-PROJECT_SECRET_VALUE_123456"
            @app.route("/user/<uid>")
            def show_user(uid):
                return db.get_user(uid)
        """)
        w(self.root, "app/db.py", """
            def get_user(uid):
                return cur.execute("SELECT * FROM users WHERE id = " + uid)
        """)
        w(self.root, "app/util.py", "def unrelated(): return 1\n")
        w(self.root, "broken.py", "def (:\n")
        self.marker = os.path.join(self.d, "ran.marker")
        w(self.root, "evil.py", f"open({self.marker!r}, 'w').close()\n")

    def test_multi_file_prompt_result_and_honest_coverage(self):
        res, llm = self.run_audit()
        prompt = llm.stream_prompts[0]
        self.assertIn("app/views.py:", prompt)
        self.assertIn("app/db.py:", prompt)
        self.assertNotIn("PROJECT_SECRET_VALUE", prompt)                  # 入力マスキング
        self.assertNotIn("unrelated", prompt)
        self.assertFalse(os.path.exists(self.marker))                     # 対象コードは実行されない
        cov = {c["target_ref"]: c for c in res.to_dict()["coverage"]}
        self.assertEqual(cov["app/views.py"]["status"], "tested")
        self.assertEqual(cov["app/util.py"]["status"], "skipped")         # 送っていないファイルをtestedにしない
        self.assertEqual(cov["broken.py"]["status"], "skipped")
        self.assertIn("SyntaxError", cov["broken.py"]["reason"])
        self.assertEqual(res.state, "partial")                            # 解析できなかったファイルがあるためcompletedにしない
        self.assertEqual(res.mode, "AUDIT")
        self.assertTrue(res.findings)

    def test_single_file_path_is_unchanged(self):
        from unittest import mock
        from agents.audit_agent import AuditAgent
        from core.event_bus import EventBus
        from tools.fuzz_characterization import MockLLM
        llm = MockLLM()
        agent = AuditAgent(EventBus(), llm)
        one = os.path.join(self.root, "app", "db.py")
        with mock.patch.object(AuditAgent, "_save_investigation", lambda *a, **k: None), \
             mock.patch.object(AuditAgent, "_record_telemetry", lambda *a, **k: None):
            agent._safe_run(path=one)
        self.assertIn("```python", llm.stream_prompts[0])
        self.assertNotIn("multi-file", llm.stream_prompts[0])
        self.assertEqual(agent._last_scan_result.target, one)

    def test_empty_project_fails_instead_of_reporting_success(self):
        for name in os.listdir(self.root):
            full = os.path.join(self.root, name)
            shutil.rmtree(full, ignore_errors=True) if os.path.isdir(full) else os.unlink(full)
        w(self.root, "readme.txt", "x")
        res, _ = self.run_audit()
        self.assertEqual(res.state, "failed")

@unittest.skipUnless(__import__("core.orchestrator", fromlist=["x"]).LANGGRAPH_AVAILABLE, "langgraph未導入")
class AuditProjectEvidenceTest(Base):
    """標準エンジンのプロジェクト監査: save_evidence有効時、LLMへ送った関数内のAST観測だけを相対パスの証拠として保存する。"""

    def audit(self, save_evidence: bool, cite: bool = True):
        import glob
        import json
        from unittest import mock
        from agents.audit_agent import AuditAgent
        from core import config
        from core.event_bus import EventBus
        from tools.fuzz_characterization import MockLLM

        class CitingLLM(MockLLM):
            def reply_for(self, prompt):
                ids = re.findall(r"evidence_id=(\S+) app/db\.py:(\d+)", prompt)
                if not (cite and ids):
                    return super().reply_for(prompt)
                return ("---VULN_START---\nNAME: SQL built by concatenation\nSEVERITY: HIGH\nCWE: CWE-89\nLINES: app/db.py:" + ids[0][1]
                        + "\nEVIDENCE_IDS: " + ids[0][0] + ", evidence_bogus_0000\nSNIPPET:\n```\nx\n```\nATTACK:\ny\nFIX:\n```\nz\n```\n---VULN_END---")

        llm = CitingLLM()
        agent = AuditAgent(EventBus(), llm)
        cwd = os.getcwd()
        os.chdir(self.d)                                       # reports/evidence/ を一時ディレクトリ内へ
        self.addCleanup(os.chdir, cwd)
        with mock.patch.object(AuditAgent, "_save_investigation", lambda *a, **k: None), \
             mock.patch.object(AuditAgent, "_record_telemetry", lambda *a, **k: None), \
             mock.patch.dict(config._cfg, {**config._DEFAULTS, "effort": "speed", "save_evidence": save_evidence}, clear=True):
            agent._safe_run(path=self.root)
        saved = []
        for f in glob.glob(os.path.join(self.d, "reports", "evidence", "*", "*.json")):
            with open(f, encoding="utf-8") as fh:
                saved.append(json.load(fh))
        return agent._last_scan_result, llm, saved

    def setUp(self):
        super().setUp()
        w(self.root, "app/views.py", """
            from app import db
            @app.route("/user/<uid>")
            def show_user(uid):
                return db.get_user(uid)
        """)
        w(self.root, "app/db.py", """
            def get_user(uid):
                return cur.execute("SELECT * FROM users WHERE id = " + uid)
            exec("1")
        """)
        w(self.root, "app/util.py", "def unrelated():\n    return 1\n")

    def test_evidence_is_saved_with_project_relative_paths_only_for_sent_functions(self):
        res, llm, saved = self.audit(True)
        prompt = llm.stream_prompts[0]
        self.assertIn("## AST evidence IDs", prompt)
        self.assertIn("EVIDENCE_IDS", prompt)                                  # 引用指示はIDがある時だけ付く
        self.assertNotIn("app/util.py", prompt.split("## AST evidence IDs", 1)[1])   # 送っていないファイルの観測は証拠にしない
        # app/db.pyのget_user内(L3)だけ。同じファイルでも送っていない範囲(モジュール直下のexec)は証拠にしない
        self.assertEqual({(e["path"], e["line_start"], e["source"]) for e in saved}, {("app/db.py", 3, "ast_prescan")})
        self.assertNotIn("..", saved[0]["path"])
        self.assertEqual(len(res.findings), 1)
        cited = res.findings[0].evidence_ids
        self.assertEqual(cited, [saved[0]["evidence_id"]])                      # 実在IDだけ採用する
        self.assertTrue(any("未知の証拠IDを除外" in e for e in res.errors), res.errors)
        self.assertFalse(any("証拠保存は未対応" in e for e in res.errors))

    def test_nothing_is_saved_or_asked_when_save_evidence_is_off(self):
        res, llm, saved = self.audit(False)
        self.assertNotIn("AST evidence IDs", llm.stream_prompts[0])
        self.assertNotIn("EVIDENCE_IDS", llm.stream_prompts[0])
        self.assertEqual(saved, [])
        self.assertFalse(os.path.exists(os.path.join(self.d, "reports", "evidence")))

    def test_save_code_evidence_keeps_only_safe_project_relative_paths(self):
        from core.evidence_store import EvidenceStore
        self.addCleanup(os.chdir, os.getcwd())          # 先に現在地を控える(chdirの後では一時ディレクトリを控えてしまう)
        os.chdir(self.d)
        st = EvidenceStore("scan_unit")
        for given, shown in (("app/db.py", "app/db.py"), ("../etc/passwd", "passwd"), ("/etc/passwd", "passwd")):
            st.save_code_evidence(path=given, line_start=1, line_end=1, excerpt="x", source="ast_prescan", project_relative=True)
        import glob, json

        def _load(f):
            with open(f, encoding="utf-8") as fh:
                return json.load(fh)
        paths = sorted(_load(f)["path"] for f in glob.glob(os.path.join(st.dir, "*.json")))
        self.assertEqual(paths, ["app/db.py", "passwd", "passwd"])              # 絶対パス/..は従来どおり相対化(ファイル名のみ)


class LangGraphProjectTest(AuditProjectTest):
    """LangGraph版も標準エンジンと同じ索引・マスク・非実行・正直なcoverageでディレクトリを扱う(モックLLM)。"""

    def run_audit(self):
        from unittest import mock
        from agents.langgraph_audit_agent import LangGraphAuditAgent
        from core.event_bus import EventBus
        from tools.fuzz_characterization import MockLLM
        llm = MockLLM()
        agent = LangGraphAuditAgent(EventBus(), llm)
        with mock.patch.object(LangGraphAuditAgent, "_save_investigation", lambda *a, **k: None), \
             mock.patch.object(LangGraphAuditAgent, "_record_telemetry", lambda *a, **k: None), \
             mock.patch.dict("core.config._cfg", {**__import__("core.config", fromlist=["x"])._DEFAULTS, "effort": "speed"}, clear=True):
            agent._safe_run(path=self.root)
        return agent._last_scan_result, llm

    def test_prompt_is_multi_file_and_deep_pass_sees_the_same_text(self):
        res, llm = self.run_audit()
        self.assertIn("Multi-file Python project excerpt", llm.stream_prompts[0])
        self.assertIn("app/db.py:", llm.stream_prompts[0])
        self.assertNotIn("PROJECT_SECRET_VALUE", llm.stream_prompts[0])

    def test_empty_project_fails_instead_of_reporting_success(self):
        super().test_empty_project_fails_instead_of_reporting_success()


if __name__ == "__main__":
    unittest.main()
