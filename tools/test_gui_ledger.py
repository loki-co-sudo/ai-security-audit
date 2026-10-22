"""P3.2: GUIの案件ID(config.engagement_id)→所見台帳への記録・レポートビュー付与の固定試験(Tk不要)。"""
import json
import os
import tempfile
import unittest
from unittest import mock

from core import config
from core.findings_ledger import Ledger, LedgerError
from gui import ledger_util
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



class LedgerOperationsTest(unittest.TestCase):
    """GUIの台帳操作(一覧・状態変更・期限付き抑制)のロジック。ダイアログは薄く、検証と記録はここと台帳側が担う。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, cwd)
        p = mock.patch.dict(config._cfg, {**config._DEFAULTS, "engagement_id": "lab-ops"}, clear=True)
        p.start()
        self.addCleanup(p.stop)
        r = scan("s1", [finding("/a q"), finding("/b id", "SQLI")], unit_cov("/a", "q") + unit_cov("/b", "id"))
        for f in r["findings"]:
            f.setdefault("description", "d")
        self.fids = [x["finding_id"] for x in attach_ledger(r)["ledger"]["findings"]]

    def test_list_shows_status_and_suppression_and_requires_an_id(self):
        res = ledger_util.list_findings()
        self.assertEqual((res["engagement_id"], len(res["findings"])), ("lab-ops", 2))
        self.assertTrue(all(f["status"] == "open" and not f["suppressed"] for f in res["findings"]))
        with mock.patch.dict(config._cfg, {"engagement_id": ""}):
            with self.assertRaises(LedgerError):
                ledger_util.list_findings()

    def test_status_requires_a_reason_and_a_known_status_and_finding(self):
        fid = self.fids[0]
        ledger_util.apply_status(fid, "fixed", "修正を確認")
        self.assertEqual({f["finding_id"]: f["status"] for f in ledger_util.list_findings()["findings"]}[fid], "fixed")
        for args in ((fid, "fixed", "  "), (fid, "wontfix", "x"), ("f_0123456789abcdef", "fixed", "x"), ("bogus", "fixed", "x")):
            with self.assertRaises(LedgerError, msg=str(args)):
                ledger_util.apply_status(*args)

    def test_suppression_is_time_limited_and_visible_with_reason_and_expiry(self):
        fid = self.fids[1]
        until = ledger_util.apply_suppress(fid, "調整中", "30")
        row = {f["finding_id"]: f for f in ledger_util.list_findings()["findings"]}[fid]
        self.assertTrue(row["suppressed"])
        self.assertEqual((row["suppression_reason"], row["suppression_expires_at"]), ("調整中", until))
        for days in ("0", "-1", "366", "abc", "", None, "1.5"):
            with self.assertRaises(LedgerError, msg=str(days)):
                ledger_util.apply_suppress(self.fids[0], "x", days)                  # 無期限・極端な長期・不正値は作れない
        with self.assertRaises(LedgerError):
            ledger_util.apply_suppress(self.fids[0], " ", "7")                       # 理由必須
        # 抑制はCLI(同じ台帳)の出力にも反映される
        self.assertEqual(Ledger("lab-ops").findings()["suppressed_count"], 1)

if __name__ == "__main__":
    unittest.main()
