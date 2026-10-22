"""P3.2: 台帳ビューをHTML/MD/PDF/JSONレポートへ反映する固定試験。LLM・ネットワーク不使用。"""
import json
import tempfile
import unittest
from datetime import timedelta

from core import findings_ledger as fl
from tools import report_generator as rg
from tools.test_findings_ledger import T0, TARGET, finding, scan, unit_cov


def full(sid, findings, cov):
    r = scan(sid, findings, cov)
    for f in r["findings"]:
        f.setdefault("description", f"desc {f['location']}")
    return r


class LedgerReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = [T0]
        self.led = fl.Ledger("lab", self.tmp.name, now=lambda: self.now[0])
        self.cov = unit_cov("/a", "q") + unit_cov("/b", "id")
        self.s1 = full("s1", [finding("/a q"), finding("/b id", "SQLI")], self.cov)
        self.s2 = full("s2", [finding("/a q"), finding("/c x")], self.cov + unit_cov("/c", "x"))
        self.led.record_scan(self.s1)
        self.led.record_scan(self.s2)

    def attach(self, result):
        return {**result, "ledger": self.led.report_view(result)}

    def fid(self, scan_, loc):
        return fl.finding_id("lab", TARGET, "CWE-79" if loc != "/b id" else "SQLI", loc, "authenticated")

    def outputs(self, result):
        return {"html": rg.generate("WEB FUZZ", TARGET, "", scan_result=result),
                "md": rg.generate_markdown("WEB FUZZ", TARGET, "", scan_result=result),
                "json": rg.generate_json("WEB FUZZ", TARGET, "", scan_result=result)}

    def test_diff_is_shown_in_every_format(self):
        out = self.outputs(self.attach(self.s2))
        for fmt, text in out.items():
            text = text.replace("\\", "")
            self.assertIn("NOT_OBSERVED", text, fmt)
            self.assertIn(self.fid(self.s1, "/b id"), text, fmt)
        doc = json.loads(out["json"])
        self.assertEqual(doc["ledger"]["baseline_scan"], "s1")
        self.assertEqual({f["ledger_diff"] for f in doc["findings"]}, {"PERSISTING", "NEW"})

    def test_suppression_removes_finding_and_counts_but_keeps_reason(self):
        fid = self.fid(self.s2, "/c x")
        self.led.suppress(fid, "受容済みの既知事項", (T0 + timedelta(days=3)).isoformat())
        out = self.outputs(self.attach(self.s2))
        doc = json.loads(out["json"])
        self.assertEqual(doc["suppressed"], 1)
        self.assertEqual(doc["suppressed_findings"][0]["reason"], "受容済みの既知事項")
        self.assertEqual([f["location"] for f in doc["findings"]], ["/a q"])
        self.assertEqual(sum(doc["counts"].values()), 1)
        for fmt in ("html", "md"):
            self.assertIn("Suppressed: 1", out[fmt])
            self.assertIn("受容済みの既知事項", out[fmt] if fmt == "html" else out[fmt].replace("\\", ""))
            self.assertNotIn("desc /c x", out[fmt].replace("\\", ""))

    def test_expired_suppression_returns_to_the_report(self):
        fid = self.fid(self.s2, "/c x")
        self.led.suppress(fid, "短期", (T0 + timedelta(days=1)).isoformat())
        self.now[0] = T0 + timedelta(days=2)
        doc = json.loads(self.outputs(self.attach(self.s2))["json"])
        self.assertEqual(doc["suppressed"], 0)
        self.assertEqual(len(doc["findings"]), 2)

    def test_unrecorded_scan_has_no_diff_and_says_so(self):
        s3 = full("s3", [finding("/a q")], self.cov)
        doc = json.loads(self.outputs(self.attach(s3))["json"])
        self.assertIsNone(doc["ledger"]["diff"])
        self.assertIn("未記録", doc["ledger"]["note"])

    def test_no_ledger_keeps_previous_behaviour(self):
        doc = json.loads(self.outputs(self.s2)["json"])
        self.assertIsNone(doc["ledger"])
        self.assertEqual(doc["suppressed"], 0)
        self.assertEqual(len(doc["findings"]), 2)
        self.assertIn("no ledger applied", rg.generate("WEB FUZZ", TARGET, "", scan_result=self.s2))

    def test_report_does_not_write_to_the_ledger(self):
        def raw():
            with open(self.led.path, "rb") as fh:
                return fh.read()
        before = raw()
        self.outputs(self.attach(self.s2))
        self.assertEqual(raw(), before)

    def test_pdf_renders_with_ledger(self):
        pdf = rg.generate_pdf("WEB FUZZ", TARGET, "", scan_result=self.attach(self.s2))
        if pdf is not None:
            self.assertTrue(pdf.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
