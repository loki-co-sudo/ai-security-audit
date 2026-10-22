"""P3.2: GUIの案件ID(config.engagement_id)→所見台帳への記録・レポートビュー付与の固定試験(Tk不要)。"""
import json
import os
import tempfile
import unittest
from unittest import mock

from core import config
from gui.ledger_util import attach_ledger
from tools import report_generator as rg
from tools.test_findings_ledger import TARGET, finding, scan, unit_cov


class AttachLedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cwd = os.getcwd()
        os.chdir(self.tmp.name)                          # reports/engagements/ を一時ディレクトリ内へ
        self.addCleanup(os.chdir, cwd)
        self.cov = unit_cov("/a", "q")

    def cfg(self, eid):
        return mock.patch.dict(config._cfg, {**config._DEFAULTS, "engagement_id": eid}, clear=True)

    def result(self, sid, findings):
        r = scan(sid, findings, self.cov)
        for f in r["findings"]:
            f.setdefault("description", "desc")
        return r

    def test_unset_id_changes_nothing_and_writes_nothing(self):
        r = self.result("s1", [finding("/a q")])
        with self.cfg(""):
            self.assertIs(attach_ledger(r), r)
            self.assertIsNone(attach_ledger(None))
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "reports")))

    def test_records_once_and_shows_diff_and_suppression_in_reports(self):
        r1, r2 = self.result("s1", [finding("/a q")]), self.result("s2", [])
        with self.cfg("lab-1"):
            a = attach_ledger(r1)
            self.assertEqual(a["engagement_id"], "lab-1")
            self.assertNotIn("ledger", r1)                                           # 入力は書き換えない
            self.assertEqual(len(a["ledger"]["findings"]), 1)
            self.assertIn("過去scanがない", a["ledger"]["note"])                       # 初回は差分なし
            b = attach_ledger(r2)
            self.assertEqual(b["ledger"]["baseline_scan"], "s1")
            self.assertEqual(b["ledger"]["diff"]["counts"].get("NOT_OBSERVED"), 1)    # 検査済みで不在=NOT_OBSERVED
            md = rg.generate_markdown("WEB FUZZ", TARGET, "", scan_result=b)
            self.assertIn("Ledger: engagement=lab-1", md.replace("\\", ""))
            self.assertIn("NOT_OBSERVED", md.replace("\\", ""))                          # Markdownの`_`エスケープを除いて比較
            from core.findings_ledger import Ledger
            led = Ledger("lab-1")
            fid = a["ledger"]["findings"][0]["finding_id"]
            led.suppress(fid, "調整中", "2999-01-01T00:00:00+00:00")                  # 期限内の抑制
            c = attach_ledger(self.result("s3", [finding("/a q")]))
            self.assertTrue(c["ledger"]["findings"][0]["suppressed"])
            md = rg.generate_markdown("WEB FUZZ", TARGET, "", scan_result=c)
            self.assertIn("Suppressed: 1", md.replace("\\", ""))
        path = os.path.join(self.tmp.name, "reports", "engagements", "lab-1", "events.jsonl")
        with open(path, encoding="utf-8") as fh:
            events = [json.loads(x) for x in fh.read().splitlines()]
        self.assertEqual([e["scan_id"] for e in events if e["type"] == "scan_recorded"], ["s1", "s2", "s3"])

    def test_ledger_failure_is_noted_and_never_hides_the_result(self):
        r = self.result("s1", [finding("/a q")])
        with self.cfg("bad/id"):                                                      # 設定ファイルを手で壊した場合
            out = attach_ledger(r)
        self.assertEqual(len(out["findings"]), 1)
        self.assertTrue(any("所見台帳への記録に失敗しました" in e for e in out["errors"]), out["errors"])
        self.assertNotIn("ledger", out)

    def test_config_validator_accepts_empty_and_rejects_unsafe_ids(self):
        for ok in ("", "lab", "client-2026.q1_a"):
            self.assertEqual(config.validate_config({"engagement_id": ok}), [], ok)
        for bad in ("../x", "a/b", "a b", " lead", "x" * 65, "..", "a..b", 5):
            self.assertTrue(config.validate_config({"engagement_id": bad}), bad)


if __name__ == "__main__":
    unittest.main()
