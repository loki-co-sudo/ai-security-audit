"""CTFフラグの中身と取得経路がScanResult→HTML/MD/PDFに残ることを検証する(P1.2 ATTACK)。"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents.recon_agent import ReconAgent
from core.ctf_safety import CtfSafetyGuard
from core.event_bus import EventBus
from core.findings import new_scan_result
from tools import report_generator as reports

FLAG = "flag{route_test_0001}"


class _Resp:
    def __init__(self, status, text, headers=None):
        self.status_code, self.text, self.headers = status, text, headers or {"Content-Type": "text/plain"}


class _Session:
    """notes.txtだけ200でフラグを返す。それ以外は404。"""
    def request(self, method, url, **kw):
        if url.endswith("/notes.txt"):
            return _Resp(200, f"memo\n{FLAG}\nend")
        return _Resp(404, "nope")


def _result_with(findings, errors=()):
    r = new_scan_result("ATTACK", "http://t.local")
    r.findings, r.errors = findings, list(errors)
    return r


def _agent():
    return ReconAgent(EventBus(), None)


def _guard():
    g = CtfSafetyGuard(max_requests=30)
    g.jitter = (0, 0)
    return g


class FlagRoutesTest(unittest.TestCase):
    def test_active_route_recorded_and_reported(self):
        a = _agent()
        hits = a._ctf_tier1("http://t.local", _Session(), _guard())
        self.assertEqual(hits, [FLAG])  # 既存の戻り値の契約は不変
        recon = {"flags": hits}
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                findings, errs = a._flag_findings(recon, "scan_aaaaaaaaaaaa")
            finally:
                os.chdir(cwd)
        self.assertEqual(errs, [])
        f = findings[0]
        self.assertEqual((f.rule_id, f.severity), ("CTF_FLAG", "INFO"))
        self.assertIn(FLAG, f.description)
        self.assertIn("GET http://t.local/notes.txt", f.location)
        self.assertIn("Tier1", f.analysis)
        self.assertIn("wordlist:notes.txt", f.analysis)
        self.assertIn(FLAG, f.snippet)  # 応答中の位置が分かる抜粋
        self.assertEqual(f.evidence_ids, [])  # save_evidence既定OFFでも経路は残る
        result = _result_with(findings)
        for out in (reports.generate("ATTACK MODE", "x", "", scan_result=result),
                    reports.generate_markdown("ATTACK MODE", "x", "", scan_result=result)):
            self.assertIn(FLAG, out)  # 抜粋(コードブロック/pre)に生のまま残る
            self.assertTrue("notes.txt" in out or r"notes\.txt" in out)  # MDは構文エスケープされる
            self.assertIn("Tier1", out)
        self.assertTrue(reports.generate_pdf("ATTACK MODE", "x", "", scan_result=result).startswith(b"%PDF"))

    def test_passive_route_lists_recon_fields(self):
        a = _agent()
        recon = {"ports": [{"port": 21, "banner": f"220 {FLAG}"}],
                 "web": {"headers": {"X-Note": FLAG}}}
        a._detect_and_report_flags(recon)
        self.assertEqual(recon["flags"], [FLAG])
        f = a._flag_findings(recon, "scan_aaaaaaaaaaaa")[0][0]
        self.assertIn("ports[0].banner", f.analysis)
        self.assertIn("web.headers.X-Note", f.analysis)
        self.assertIn("追加送信なし", f.analysis)

    def test_save_evidence_on_stores_response(self):
        a = _agent()
        hits = a._ctf_tier1("http://t.local", _Session(), _guard())
        real_get = __import__("core.config", fromlist=["get"]).get
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                with patch("agents.recon_agent.config.get",
                           side_effect=lambda k, d=None: True if k == "save_evidence" else real_get(k, d)):
                    findings, errs = a._flag_findings({"flags": hits}, "scan_bbbbbbbbbbbb")
                ids = findings[0].evidence_ids
                self.assertEqual(len(ids), 1)
                self.assertTrue((Path(tmp) / "reports" / "evidence" / "scan_bbbbbbbbbbbb" / f"{ids[0]}.json").is_file())
            finally:
                os.chdir(cwd)

    def test_request_url_secret_is_masked(self):
        a = _agent()
        a._record_active_route([FLAG], _Resp(200, FLAG), _guard(), tier=2, method="GET",
                               url="http://t.local/x?token=SECRETVAL&p=1", rationale="r",
                               params={"password": "hunter2"})
        f = a._flag_findings({"flags": [FLAG]}, "scan_cccccccccccc")[0][0]
        for leak in ("SECRETVAL", "hunter2"):
            self.assertNotIn(leak, f.location + f.analysis + f.snippet)

    def test_no_flags_no_findings(self):
        self.assertEqual(_agent()._flag_findings({"flags": []}, "scan_dddddddddddd"), ([], []))


if __name__ == "__main__":
    unittest.main()
