"""DEFENSE MODEの証拠保存・ログ入力マスキング(P1.2)を、モックLLMで実際にMonitorAgentを走らせて検証する。"""
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents.monitor_agent import MonitorAgent
from core import redaction
from core.event_bus import EventBus
from tools import report_generator as reports

SECRET = "DEFENSE_DUMMY_SECRET_x81Pq"
LOG = (
    f'10.0.0.5 - - [11/Oct/2026:10:00:00] "GET /item?id=1 UNION SELECT pw&token={SECRET} HTTP/1.1" 200 "Authorization: Bearer {SECRET}"\n'
    '10.0.0.6 - - [11/Oct/2026:10:00:01] "GET /index.html HTTP/1.1" 200 "-"\n'
    '10.0.0.7 - - [11/Oct/2026:10:00:02] "GET /../../etc/passwd HTTP/1.1" 404 "-"\n'
)


class _FakeLLM:
    model = "fake-model"

    def __init__(self, cite=None):
        self.received = []
        self.cite = cite  # "real" | list[str] | None

    @staticmethod
    def system(content):
        return {"role": "system", "content": content}

    @staticmethod
    def user(content):
        return {"role": "user", "content": content}

    def stream(self, messages, on_chunk=None, on_error=None):
        self.received.append(messages)
        joined = json.dumps(messages)
        ids = re.findall(r"evidence_id=(evidence_[a-f0-9]+)", joined)
        cited = ([ids[0]] if ids else []) if self.cite == "real" else list(self.cite or [])
        text = (
            "---THREAT_START---\nSEVERITY: HIGH\nTHREAT_TYPE: SQL Injection\nMITRE_TTP: T1190\n"
            "ATTACKER_IP: 10.0.0.5\n"
            + (f"EVIDENCE_IDS: {', '.join(cited)}\n" if cited else "")
            + "TIMELINE: isolated\nANALYSIS:\nUNION based probe.\nIMMEDIATE_ACTIONS:\nBlock IP.\n"
            "---THREAT_END---\n"
        )
        if on_chunk:
            on_chunk(text)
        return text

    def complete(self, messages):
        return ""


def _run(tmp, llm, *, save_evidence, store_kwargs=None):
    log = Path(tmp) / "access.log"
    log.write_text(LOG, encoding="utf-8")
    real_get = __import__("core.config", fromlist=["get"]).get

    def fake_get(key, default=None):
        return save_evidence if key == "save_evidence" else real_get(key, default)

    cwd = os.getcwd()
    os.chdir(tmp)
    try:
        agent = MonitorAgent(EventBus(), llm)
        patches = [patch("agents.monitor_agent.config.get", side_effect=fake_get)]
        if store_kwargs:
            from core import evidence_store as es
            orig = es.EvidenceStore

            class _Capped(orig):
                def __init__(self, scan_id, **kw):
                    super().__init__(scan_id, **{**kw, **store_kwargs})
            patches.append(patch("agents.monitor_agent.EvidenceStore", _Capped))
        for p in patches:
            p.start()
        try:
            agent.run(str(log), watch_mode=False)
        finally:
            for p in patches:
                p.stop()
        return agent._last_scan_result, agent
    finally:
        os.chdir(cwd)


def _all_text(root):
    return "".join(p.read_text(encoding="utf-8", errors="replace")
                   for p in Path(root).rglob("*") if p.is_file() and p.name != "access.log")


def _bus_text(agent):
    return json.dumps([e.payload for e in agent.bus.drain()] if hasattr(agent.bus, "drain") else [],
                      ensure_ascii=False, default=str)


class DefenseEvidenceTest(unittest.TestCase):
    def test_on_saves_masks_and_adopts_real_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            llm = _FakeLLM(cite="real")
            result, _ = _run(tmp, llm, save_evidence=True)
            ev_dir = Path(tmp) / "reports" / "evidence" / result.scan_id
            files = list(ev_dir.glob("*.json"))
            self.assertGreaterEqual(len(files), 2)  # UNION SELECT / path traversal
            data = [json.loads(p.read_text(encoding="utf-8")) for p in files]
            self.assertTrue(all(d["kind"] == "log" and d["source"] == "access.log" for d in data))
            self.assertTrue(all(d["patterns"] for d in data))
            self.assertNotIn(SECRET, _all_text(tmp))
            self.assertNotIn(SECRET, json.dumps(llm.received, ensure_ascii=False))
            self.assertIn("EVIDENCE_IDS", json.dumps(llm.received))
            ids = result.findings[0].evidence_ids
            self.assertEqual(len(ids), 1)
            self.assertTrue((ev_dir / f"{ids[0]}.json").is_file())
            html = reports.generate("DEFENSE MODE", "t", "", scan_result=result)
            self.assertIn(f"evidence/{result.scan_id}/{ids[0]}.json", html)

    def test_alerts_use_masked_line_but_detection_uses_raw(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, agent = _run(tmp, _FakeLLM(), save_evidence=False)
            events = []
            while True:  # drain()は1回50件までのため、空になるまで取り出す
                batch = agent.bus.drain()
                if not batch:
                    break
                events.extend(batch)
            alerts = [e.payload for e in events if e.kind == "alert"]
            self.assertTrue(alerts, "検知(生の行)でALERTが出ていない")
            # SECRETを含むSQLi行は生の行で検知され、そのALERT/OUTPUT表示はマスク済み
            self.assertTrue(any("SQL_INJECTION" in a["message"] for a in alerts))
            blob = json.dumps([e.payload for e in events], ensure_ascii=False, default=str)
            self.assertNotIn(SECRET, blob)
            # 表示はマスク後に80文字へ切り詰めるため、タグが途中で切れることがある（値は残らない）
            self.assertIn("token=***RED", blob)
            self.assertNotIn(SECRET, _all_text(tmp))

    def test_unknown_id_rejected_as_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = _run(tmp, _FakeLLM(cite=["evidence_000000000000"]), save_evidence=True)
            self.assertEqual(result.findings[0].evidence_ids, [])
            self.assertTrue(any("未知の証拠IDを除外" in e for e in result.errors))

    def test_off_writes_nothing_but_reports_not_saved(self):
        with tempfile.TemporaryDirectory() as tmp:
            llm = _FakeLLM()
            result, _ = _run(tmp, llm, save_evidence=False)
            self.assertFalse((Path(tmp) / "reports" / "evidence").exists())
            self.assertNotIn(SECRET, json.dumps(llm.received, ensure_ascii=False))
            self.assertNotIn("EVIDENCE_IDS", json.dumps(llm.received))
            html = reports.generate("DEFENSE MODE", "t", "", scan_result=result)
            self.assertIn("not saved / unavailable", html)

    def test_cap_overflow_records_omission(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = _run(tmp, _FakeLLM(), save_evidence=True, store_kwargs={"max_items": 1})
            self.assertEqual(len(list((Path(tmp) / "reports" / "evidence" / result.scan_id).glob("*.json"))), 1)
            self.assertTrue(any("証拠保存を省略" in e and "件数上限" in e for e in result.errors))

    def test_save_failure_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("core.evidence_store.os.makedirs", side_effect=OSError("disk full")):
                result, _ = _run(tmp, _FakeLLM(), save_evidence=True)
            self.assertGreaterEqual(len(result.findings), 1)  # 所見は破棄しない
            self.assertTrue(any("証拠保存エラー" in e for e in result.errors))


class MaskLogLineTest(unittest.TestCase):
    def test_masks_query_header_json_and_is_idempotent(self):
        for text, secret in [
            ('GET /a?token=abc123&x=1 "Authorization: Bearer sk-9"', "abc123"),
            ('GET /a "Authorization: Bearer sk-9"', "sk-9"),
            ("Cookie: sid=zzz; a=b", "zzz"),
            ('{"password": "pw1", "u": "x"}', "pw1"),
            ("POST /login password=hunter2&user=bob", "hunter2"),
        ]:
            out = redaction.mask_log_line(text)
            self.assertNotIn(secret, out)
            self.assertEqual(redaction.mask_log_line(out), out)

    def test_non_secret_content_preserved(self):
        t = '10.0.0.5 "GET /index.html?id=1&x=2 HTTP/1.1" 200'
        self.assertEqual(redaction.mask_log_line(t), t)


if __name__ == "__main__":
    unittest.main()
