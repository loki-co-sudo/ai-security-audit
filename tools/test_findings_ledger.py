"""core/findings_ledger.py(P3.2)の固定試験。LLM・ネットワーク不使用。"""
import fcntl
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from core import findings_ledger as fl

def rd(path, mode="r"):
    with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as f:
        return f.read()


def wr(path, data, mode="w"):
    with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as f:
        f.write(data)


T0 = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
TARGET = "http://127.0.0.1:8080/"


def unit_cov(path, param, status="tested", auth="authenticated", cats=("XSS", "SQLI")):
    return [{"target_ref": TARGET.rstrip("/") + path, "parameter": param, "rule_id": f"WEB_FUZZ_{c}",
             "status": status, "auth_context": auth, "reason": ""} for c in cats]


def finding(loc, rule="CWE-79", sev="HIGH"):
    return {"rule_id": rule, "location": loc, "severity": sev, "verification_state": "observed"}


def scan(sid, findings, coverage, mode="WEB FUZZ", state="completed", dv="webfuzz-2", target=TARGET):
    return {"scan_id": sid, "mode": mode, "target": target, "state": state, "detector_version": dv,
            "findings": findings, "coverage": coverage, "errors": []}


class LedgerBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.clock = [T0]
        self.led = fl.Ledger("lab", self.tmp.name, now=lambda: self.clock[0])

    def ids(self, diff):
        return {i["location"]: i["state"] for i in diff["items"]}


class IdentityTest(unittest.TestCase):
    def test_location_noise_does_not_change_the_id(self):
        base = fl.finding_id("e", TARGET, "cwe-79", "/search q", "authenticated")
        for loc in ("GET /search q", "get  /search   q", "http://127.0.0.1:8080/search?q=1 q", "/search q:120"):
            self.assertEqual(fl.finding_id("e", TARGET, "CWE-79", loc, "authenticated"), base, loc)
        self.assertNotEqual(base, fl.finding_id("e", TARGET, "CWE-79", "/search q", "anonymous"))      # 認証役割
        self.assertNotEqual(base, fl.finding_id("e", TARGET, "CWE-79", "/search other", "authenticated"))
        self.assertNotEqual(base, fl.finding_id("other", TARGET, "CWE-79", "/search q", "authenticated"))  # 案件分離
        self.assertNotIn("TOKEN", base)

    def test_code_line_move_keeps_the_same_finding(self):
        a = fl.finding_id("e", "app.py", "SQLI", "app.py:10", "unknown")
        self.assertEqual(a, fl.finding_id("e", "app.py", "SQLI", "app.py:99-120", "unknown"))

    def test_engagement_id_rejects_traversal(self):
        for bad in ("../x", "a/b", "", "..", "a..b", "x" * 65, "-x"):
            with self.assertRaises(fl.LedgerError, msg=bad):
                fl.validate_engagement_id(bad)


class DiffTest(LedgerBase):
    def record(self, *a, **kw):
        self.clock[0] += timedelta(minutes=1)
        return self.led.record_scan(scan(*a, **kw))

    def test_new_persisting_and_not_observed_need_proof(self):
        cov = unit_cov("/a", "q") + unit_cov("/b", "id") + unit_cov("/c", "x")
        self.record("s1", [finding("/a q"), finding("/b id", "SQLI")], cov)
        self.record("s2", [finding("/a q"), finding("/c x")], cov)
        d = self.led.diff("s1", "s2")
        self.assertEqual(self.ids(d), {"/a q": "PERSISTING", "/c x": "NEW", "/b id": "NOT_OBSERVED"})
        self.assertEqual(d["counts"]["NOT_OBSERVED"], 1)

    def test_absence_is_unverified_when_the_recheck_was_not_sound(self):
        full = unit_cov("/b", "id")
        cases = {
            "budget/skipped": dict(coverage=unit_cov("/b", "id", status="skipped")),
            "failed": dict(coverage=unit_cov("/b", "id", status="failed")),
            "one category skipped": dict(coverage=unit_cov("/b", "id", cats=("XSS",)) + unit_cov("/b", "id", status="skipped", cats=("SQLI",))),
            "auth expired": dict(coverage=unit_cov("/b", "id", auth="expired")),
            "auth unknown": dict(coverage=unit_cov("/b", "id", auth="unknown")),
            "other unit only": dict(coverage=unit_cov("/zzz", "q")),
            "legacy coverage": dict(coverage=[{"target_ref": TARGET + "b", "parameter": "id",
                                                "rule_id": "WEB_FUZZ_PROBE", "status": "tested", "auth_context": "authenticated"}]),
            "no coverage": dict(coverage=[]),
            "detector changed": dict(coverage=full, dv="webfuzz-3"),
            "detector unknown": dict(coverage=full, dv=""),
        }
        for name, kw in cases.items():
            with self.subTest(name):
                led = fl.Ledger("e-" + str(abs(hash(name))), self.tmp.name, now=lambda: self.clock[0])
                led.record_scan(scan("s1", [finding("/b id")], full))
                self.clock[0] += timedelta(minutes=1)
                led.record_scan(scan("s2", [], **kw))
                d = led.diff("s1", "s2")
                self.assertEqual(self.ids(d), {"/b id": "UNVERIFIED"})
                self.assertTrue(d["items"][0]["reason"])

    def test_llm_modes_never_prove_absence(self):
        self.record("s1", [finding("app.py:10", "SQLI")], [], mode="AUDIT", dv="audit-1", target="app.py")
        self.record("s2", [], [{"target_ref": "app.py", "rule_id": "LLM_CODE_REVIEW", "status": "tested"}],
                    mode="AUDIT", dv="audit-1", target="app.py")
        self.assertEqual(self.ids(self.led.diff("s1", "s2")), {"app.py:10": "UNVERIFIED"})

    def test_regression_after_a_sound_recheck_or_a_human_fix(self):
        cov = unit_cov("/b", "id")
        self.record("s1", [finding("/b id")], cov)
        self.record("s2", [], cov)                       # 比較可能な再検査で未観測
        self.record("s3", [finding("/b id")], cov)
        self.assertEqual(self.ids(self.led.diff("s2", "s3")), {"/b id": "REGRESSED"})
        # 不在だけでは人のstatusを変えない
        fid = self.led.findings()["findings"][0]["finding_id"]
        self.assertEqual(self.led.findings()["findings"][0]["status"], "open")
        self.led.set_status(fid, "fixed", "修正をデプロイ")
        self.record("s4", [finding("/b id")], cov)
        self.assertEqual(self.ids(self.led.diff("s3", "s4")), {"/b id": "REGRESSED"})

    def test_unsound_gap_does_not_make_a_regression(self):
        cov = unit_cov("/b", "id")
        self.record("s1", [finding("/b id")], cov)
        self.record("s2", [], unit_cov("/b", "id", status="skipped"))      # 未検査の空白
        self.record("s3", [finding("/b id")], cov)
        self.assertEqual(self.ids(self.led.diff("s2", "s3")), {"/b id": "NEW"})       # 空白の後は確定状態を持たない
        d13 = self.led.diff("s1", "s3")
        self.assertEqual(self.ids(d13), {"/b id": "PERSISTING"})

    def test_diff_argument_validation(self):
        self.record("s1", [], [])
        self.record("s2", [], [], target="http://other/")
        self.record("s3", [], [])
        with self.assertRaises(fl.LedgerError):
            self.led.diff("s1", "nope")
        with self.assertRaises(fl.LedgerError):
            self.led.diff("s1", "s2")                       # 対象が違う
        with self.assertRaises(fl.LedgerError):
            self.led.diff("s3", "s1")                       # 順序が逆


class StatusSuppressionTest(LedgerBase):
    def setUp(self):
        super().setUp()
        self.led.record_scan(scan("s1", [finding("/a q")], unit_cov("/a", "q")))
        self.fid = self.led.findings()["findings"][0]["finding_id"]

    def test_status_requires_reason_known_id_and_valid_value(self):
        for args in ((self.fid, "fixed", " "), (self.fid, "closed", "x"), ("f_0123456789abcdef", "fixed", "x"), ("bad", "fixed", "x")):
            with self.assertRaises(fl.LedgerError, msg=args):
                self.led.set_status(*args)
        self.led.set_status(self.fid, "accepted-risk", "業務上許容")
        self.assertEqual(self.led.findings()["findings"][0]["status"], "accepted-risk")

    def test_suppression_needs_reason_and_future_expiry_and_expires_without_deleting(self):
        soon = (T0 + timedelta(days=1)).isoformat()
        for args in ((self.fid, "", soon), (self.fid, "x", ""), (self.fid, "x", "not-a-date"),
                     (self.fid, "x", (T0 - timedelta(days=1)).isoformat())):
            with self.assertRaises(fl.LedgerError, msg=args):
                self.led.suppress(*args)
        self.led.suppress(self.fid, "調整中", soon)
        shown = self.led.findings()
        self.assertEqual((shown["findings"], shown["suppressed_count"]), ([], 1))
        full = self.led.findings(include_suppressed=True)["findings"][0]
        self.assertEqual((full["suppressed"], full["suppression_reason"]), (True, "調整中"))
        self.clock[0] = T0 + timedelta(days=2)               # 期限切れ: 表示に復帰、台帳からは消えない
        back = self.led.findings()
        self.assertEqual((len(back["findings"]), back["suppressed_count"]), (1, 0))
        self.assertEqual(sum(e["type"] == "suppressed" for e in self.led.read()[0]), 1)

    def test_diff_hides_suppressed_but_counts_them(self):
        self.led.suppress(self.fid, "調整中", (T0 + timedelta(days=9)).isoformat())
        self.clock[0] += timedelta(minutes=1)
        self.led.record_scan(scan("s2", [finding("/a q")], unit_cov("/a", "q")))
        d = self.led.diff("s1", "s2")
        self.assertEqual((d["items"], d["suppressed_count"]), ([], 1))
        self.assertEqual(len(self.led.diff("s1", "s2", include_suppressed=True)["items"]), 1)


class FileIntegrityTest(LedgerBase):
    def test_engagements_are_isolated(self):
        other = fl.Ledger("other", self.tmp.name, now=lambda: self.clock[0])
        r1 = self.led.record_scan(scan("s1", [finding("/a q")], []))
        r2 = other.record_scan(scan("s1", [finding("/a q")], []))
        self.assertNotEqual(r1["finding_ids"], r2["finding_ids"])
        self.assertEqual(len(self.led.read()[0]), 2)
        with self.assertRaises(fl.LedgerError):
            other.set_status(r1["finding_ids"][0], "fixed", "別案件のid")

    def test_recording_the_same_scan_twice_is_idempotent(self):
        self.led.record_scan(scan("s1", [finding("/a q")], []))
        n = len(self.led.read()[0])
        self.led.record_scan(scan("s1", [finding("/a q")], []))
        self.assertEqual(len(self.led.read()[0]), n)

    def test_duplicate_event_lines_are_ignored_with_a_warning(self):
        self.led.record_scan(scan("s1", [finding("/a q")], []))
        wr(self.led.path, rd(self.led.path).splitlines()[0] + "\n", "a")
        events, warnings = self.led.read()
        self.assertEqual(len(events), 2)
        self.assertTrue(any("重複" in w for w in warnings))

    def test_corrupt_middle_line_is_never_skipped_silently(self):
        self.led.record_scan(scan("s1", [finding("/a q")], []))
        lines = rd(self.led.path).splitlines()
        wr(self.led.path, lines[0] + "\n{broken\n" + lines[1] + "\n")
        with self.assertRaises(fl.LedgerCorrupt):
            self.led.read()
        with self.assertRaises(fl.LedgerCorrupt):
            self.led.record_scan(scan("s2", [], []))

    def test_unsupported_schema_and_foreign_engagement_lines_are_rejected(self):
        self.led.record_scan(scan("s1", [], []))
        ev = json.loads(rd(self.led.path).splitlines()[0])
        for patch in ({"schema_version": "99"}, {"engagement_id": "other"}):
            wr(self.led.path, json.dumps({**ev, "event_id": "x" + str(patch), **patch}) + "\n", "a")
            with self.assertRaises(fl.LedgerCorrupt):
                self.led.read()
            wr(self.led.path, json.dumps(ev) + "\n")

    def test_partial_last_line_warns_then_is_repaired_on_next_append(self):
        self.led.record_scan(scan("s1", [finding("/a q")], []))
        good = rd(self.led.path, "rb")
        wr(self.led.path, b'{"schema_version": "1", "event_id": "part', "ab")
        events, warnings = self.led.read()
        self.assertEqual(len(events), 2)
        self.assertTrue(any("不完全" in w for w in warnings))
        self.led.record_scan(scan("s2", [], []))
        self.assertTrue(rd(self.led.path, "rb").startswith(good))
        events, warnings = self.led.read()
        self.assertEqual((len(events), warnings), (3, []))

    def test_concurrent_writer_is_refused_not_interleaved(self):
        self.led.record_scan(scan("s1", [], []))
        fd = os.open(os.path.join(self.led.dir, "events.lock"), os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            before = rd(self.led.path, "rb")
            with self.assertRaises(fl.LedgerBusy):
                self.led.record_scan(scan("s2", [], []))
            self.assertEqual(rd(self.led.path, "rb"), before)
        finally:
            os.close(fd)
        self.led.record_scan(scan("s2", [], []))

    def test_no_secret_or_response_body_is_stored(self):
        r = scan("s1", [{**finding("/a q"), "snippet": "SECRET_BODY_123", "description": "desc SECRET_BODY_123"}], [])
        r["coverage"] = [{**c, "reason": "SECRET_REASON_456"} for c in unit_cov("/a", "q")]
        self.led.record_scan(r)
        raw = rd(self.led.path)
        self.assertNotIn("SECRET_BODY_123", raw)
        self.assertNotIn("SECRET_REASON_456", raw)
        self.assertEqual(oct(os.stat(self.led.path).st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
