"""AUDIT MODEの証拠保存・入力マスキング(P1.2)を、モックLLMで実際にAuditAgentを走らせて検証する。"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents.audit_agent import AuditAgent
from core import redaction
from core.event_bus import EventBus
from tools import report_generator as reports

SECRET = "AUDIT_DUMMY_SECRET_q7Zk41"
SOURCE = (
    "import pickle\n"
    f'DB_PASSWORD = "{SECRET}"\n'
    "def load(data):\n"
    "    return pickle.loads(data)\n"
)


class _FakeLLM:
    model = "fake-model"

    def __init__(self, cite_ids=()):
        self.received = []
        self.cite_ids = list(cite_ids)

    @staticmethod
    def system(content):
        return {"role": "system", "content": content}

    @staticmethod
    def user(content):
        return {"role": "user", "content": content}

    def stream(self, messages, on_chunk=None, on_error=None):
        self.received.append(messages)
        text = (
            "---VULN_START---\nNAME: Unsafe deserialization\nSEVERITY: HIGH\n"
            "CWE: Novel — No CVE/CWE Match\nLINES: 4\n"
            + (f"EVIDENCE_IDS: {', '.join(self.cite_ids)}\n" if self.cite_ids else "")
            + "SNIPPET:\n```\npickle.loads(data)\n```\nATTACK:\nCrafted pickle.\n"
            "FIX:\n```\nuse json\n```\n---VULN_END---\n"
        )
        if on_chunk:
            on_chunk(text)
        return text

    def complete(self, messages):
        return ""


def _run(tmp, llm, *, save_evidence, store_kwargs=None):
    src = Path(tmp) / "target.py"
    src.write_text(SOURCE, encoding="utf-8")
    real_get = __import__("core.config", fromlist=["get"]).get

    def fake_get(key, default=None):
        return save_evidence if key == "save_evidence" else real_get(key, default)

    cwd = os.getcwd()
    os.chdir(tmp)
    try:
        agent = AuditAgent(EventBus(), llm)
        with patch("agents.audit_agent.config.get", side_effect=fake_get), \
                patch("agents.audit_agent.time.sleep"):
            if store_kwargs:
                from core import evidence_store as es
                orig = es.EvidenceStore

                class _Capped(orig):
                    def __init__(self, scan_id, **kw):
                        super().__init__(scan_id, **{**kw, **store_kwargs})

                with patch("agents.audit_agent.EvidenceStore", _Capped):
                    agent.run(str(src))
            else:
                agent.run(str(src))
        return agent._last_scan_result
    finally:
        os.chdir(cwd)


def _all_text(root):
    """生成物すべての連結（テストが用意した入力ファイル target.py 自体は除く）。"""
    return "".join(p.read_text(encoding="utf-8", errors="replace")
                   for p in Path(root).rglob("*") if p.is_file() and p.name != "target.py")


class AuditEvidenceTest(unittest.TestCase):
    def test_on_saves_masks_and_validates_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            llm = _FakeLLM(cite_ids=["evidence_000000000000"])  # 存在しないID
            first = _run(tmp, llm, save_evidence=True)
            ev_dir = Path(tmp) / "reports" / "evidence" / first.scan_id
            files = sorted(ev_dir.glob("*.json"))
            self.assertGreaterEqual(len(files), 2)  # import pickle / pickle.loads
            data = [json.loads(p.read_text(encoding="utf-8")) for p in files]
            self.assertTrue(all(d["kind"] == "code" and d["source"] == "ast_prescan" for d in data))
            self.assertTrue(all(d["path"] == "target.py" for d in data))  # 絶対パスを残さない
            self.assertNotIn(SECRET, _all_text(tmp))
            self.assertNotIn(SECRET, json.dumps(llm.received, ensure_ascii=False))
            self.assertIn("evidence_id=", json.dumps(llm.received))
            self.assertIn("EVIDENCE_IDS", json.dumps(llm.received))
            self.assertEqual(first.findings[0].evidence_ids, [])
            self.assertTrue(any("未知の証拠IDを除外" in e for e in first.errors))

            real = [d["evidence_id"] for d in data][0]
            second = _run(tmp, _FakeLLM(cite_ids=[real]), save_evidence=True)
            # 2回目は別scan_idで保存されるため、1回目のIDは未知として除外される（スキャン間の流用不可）
            self.assertEqual(second.findings[0].evidence_ids, [])

    def test_cited_real_id_is_adopted_and_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            llm = _FakeLLM()
            # 先にIDを知るため、モックが送信プロンプトから実在IDを拾って引用する
            def stream(messages, on_chunk=None, on_error=None):
                llm.received.append(messages)
                joined = json.dumps(messages)
                import re
                m = re.search(r"evidence_id=(evidence_[a-f0-9]+)", joined)
                if not m:  # 検証パス等、証拠一覧を含まない呼び出し
                    return state["text"]
                eid = m.group(1)
                text = ("---VULN_START---\nNAME: Unsafe deserialization\nSEVERITY: HIGH\n"
                        f"CWE: Novel — No CVE/CWE Match\nLINES: 4\nEVIDENCE_IDS: {eid}\n"
                        "SNIPPET:\n```\npickle.loads(data)\n```\nATTACK:\nx\nFIX:\n```\ny\n```\n"
                        "---VULN_END---\n")
                state["text"] = text
                if on_chunk:
                    on_chunk(text)
                return text
            state = {"text": ""}
            llm.stream = stream
            result = _run(tmp, llm, save_evidence=True)
            ids = result.findings[0].evidence_ids
            self.assertEqual(len(ids), 1)
            self.assertTrue((Path(tmp) / "reports" / "evidence" / result.scan_id / f"{ids[0]}.json").is_file())
            html = reports.generate("AUDIT", "t", "", scan_result=result)
            self.assertIn(f"evidence/{result.scan_id}/{ids[0]}.json", html)

    def test_off_writes_nothing_but_reports_not_saved(self):
        with tempfile.TemporaryDirectory() as tmp:
            llm = _FakeLLM()
            result = _run(tmp, llm, save_evidence=False)
            self.assertFalse((Path(tmp) / "reports" / "evidence").exists())
            self.assertNotIn(SECRET, json.dumps(llm.received, ensure_ascii=False))  # マスクはOFFでも有効
            self.assertNotIn("EVIDENCE_IDS", json.dumps(llm.received))
            html = reports.generate("AUDIT", "t", "", scan_result=result)
            self.assertIn("not saved / unavailable", html)

    def test_cap_overflow_records_omission(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run(tmp, _FakeLLM(), save_evidence=True, store_kwargs={"max_items": 1})
            self.assertEqual(len(list((Path(tmp) / "reports" / "evidence" / result.scan_id).glob("*.json"))), 1)
            self.assertTrue(any("証拠保存を省略" in e and "件数上限" in e for e in result.errors))

    def test_save_failure_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("core.evidence_store.os.makedirs", side_effect=OSError("disk full")):
                result = _run(tmp, _FakeLLM(), save_evidence=True)
            self.assertEqual(result.state, "completed")
            self.assertEqual(len(result.findings), 1)  # 所見は破棄しない
            self.assertTrue(any("証拠保存エラー" in e for e in result.errors))


class LangGraphMaskTest(unittest.TestCase):
    """LangGraph版: orchestrator.load_codeがマスクし、以降のLLM送信に値が渡らない。"""

    @unittest.skipUnless(__import__("core.orchestrator", fromlist=["x"]).LANGGRAPH_AVAILABLE,
                         "langgraph未導入")
    def test_graph_sends_masked_source(self):
        from core.orchestrator import build_audit_graph
        llm = _FakeLLM()
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "target.py"
            src.write_text(SOURCE, encoding="utf-8")
            graph = build_audit_graph(llm, EventBus(), lambda: False)
            graph.invoke({"source_path": str(src), "source_code": "", "outputs": [],
                          "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                          "iteration": 0, "phase": "init"})
        self.assertTrue(llm.received, "LLMが呼ばれていない（検証が空振り）")
        sent = json.dumps(llm.received, ensure_ascii=False)
        self.assertNotIn(SECRET, sent)
        self.assertIn("REDACTED", sent)


class MaskSourceTest(unittest.TestCase):
    def test_masks_values_keeps_names_lines_and_is_idempotent(self):
        t = 'DB_PASSWORD = "hunter2"\ncfg = {"api_key": "abc123", "name": "x"}\ntoken=\'zzz\'\nok = 1\n'
        o = redaction.mask_source(t)
        for v in ("hunter2", "abc123", "zzz"):
            self.assertNotIn(v, o)
        self.assertIn("DB_PASSWORD", o)
        self.assertIn('"name": "x"', o)
        self.assertEqual(o.count("\n"), t.count("\n"))
        self.assertEqual(redaction.mask_source(o), o)

    def test_comparison_literals_masked(self):
        o = redaction.mask_source('if password == "admin":\n    pass\nif token != "t0k":\n    pass\n')
        self.assertNotIn("admin", o)
        self.assertNotIn("t0k", o)
        self.assertIn("password ==", o)

    def test_known_secrets_masked_anywhere(self):
        self.assertNotIn("Zq9", redaction.mask_source("x = connect('host', 'Zq9')", {"Zq9"}))


if __name__ == "__main__":
    unittest.main()
