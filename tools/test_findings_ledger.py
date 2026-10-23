"""core/findings_ledger.py(P3.2)の固定試験。LLM・ネットワーク不使用。"""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from core import file_lock, findings_ledger as fl

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
        fd = file_lock.acquire(os.path.join(self.led.dir, "events.lock"))
        try:
            before = rd(self.led.path, "rb")
            with self.assertRaises(fl.LedgerBusy):
                self.led.record_scan(scan("s2", [], []))
            self.assertEqual(rd(self.led.path, "rb"), before)
        finally:
            file_lock.release(fd)
        self.led.record_scan(scan("s2", [], []))

    def test_lock_is_released_when_the_holder_process_dies(self):
        import subprocess
        import sys
        self.led.record_scan(scan("s1", [], []))
        lock_path = os.path.join(self.led.dir, "events.lock")
        code = ("import sys,os;from core import file_lock;file_lock.acquire(sys.argv[1]);"
                "print('held',flush=True);os._exit(9)")
        p = subprocess.run([sys.executable, "-c", code, lock_path], capture_output=True, text=True, timeout=30)
        self.assertIn("held", p.stdout)
        self.led.record_scan(scan("s2", [], []))                                # 異常終了後はロックが残らない

    def test_no_secret_or_response_body_is_stored(self):
        r = scan("s1", [{**finding("/a q"), "snippet": "SECRET_BODY_123", "description": "desc SECRET_BODY_123"}], [])
        r["coverage"] = [{**c, "reason": "SECRET_REASON_456"} for c in unit_cov("/a", "q")]
        self.led.record_scan(r)
        raw = rd(self.led.path)
        self.assertNotIn("SECRET_BODY_123", raw)
        self.assertNotIn("SECRET_REASON_456", raw)
        self.assertEqual(oct(os.stat(self.led.path).st_mode & 0o777), "0o600")


class ReviewR1R5Test(LedgerBase):
    """実装レビュー(2026-10-23) R1/R5: カテゴリ欠落を不在証明にしない・改行なし末尾も同じ検証を通す。"""

    def record(self, *a, **kw):
        self.clock[0] += timedelta(minutes=1)
        return self.led.record_scan(scan(*a, **kw))

    def test_missing_category_rows_are_unverified_not_absent(self):
        self.record("s1", [finding("/b id", "SQLI")], unit_cov("/b", "id"))
        self.record("s2", [], unit_cov("/b", "id", cats=("XSS",)))              # SQLIの行そのものが無い
        self.assertEqual(self.ids(self.led.diff("s1", "s2")), {"/b id": "UNVERIFIED"})

    def test_extra_categories_in_recheck_still_prove_absence(self):
        self.record("s1", [finding("/b id", "SQLI")], unit_cov("/b", "id", cats=("XSS",)))
        self.record("s2", [], unit_cov("/b", "id", cats=("XSS", "SQLI")))
        self.assertEqual(self.ids(self.led.diff("s1", "s2")), {"/b id": "NOT_OBSERVED"})

    def test_empty_coverage_and_old_format_are_unverified(self):
        self.record("s1", [finding("/b id", "SQLI")], unit_cov("/b", "id"))
        self.record("s2", [], [])
        self.assertEqual(self.ids(self.led.diff("s1", "s2")), {"/b id": "UNVERIFIED"})
        # 過去形式(unit_categories/tested_categoriesが無いイベント)は安全側に読む
        lines = [json.loads(x) for x in rd(self.led.path).splitlines()]
        for ev in lines:
            ev.pop("unit_categories", None)
            ev.pop("tested_categories", None)
        with open(self.led.path, "w", encoding="utf-8") as f:
            f.write("".join(json.dumps(e, sort_keys=True) + "\n" for e in lines))
        self.record("s3", [], unit_cov("/b", "id"))
        self.assertEqual(self.ids(self.led.diff("s1", "s3")), {"/b id": "UNVERIFIED"})

    def _bad_events(self):
        base = {"schema_version": "1", "engagement_id": "lab", "event_id": "x", "type": "scan_recorded"}
        return [{**base, "schema_version": "999"}, {**base, "engagement_id": "other"},
                {k: v for k, v in base.items() if k != "event_id"}, {k: v for k, v in base.items() if k != "type"}]

    def test_unterminated_last_line_is_validated_like_other_lines(self):
        self.record("s1", [], [])
        for bad in self._bad_events():
            n = len(self.led.read()[0])
            with open(self.led.path, "ab") as f:
                f.write(json.dumps(bad).encode())
            events, warnings = self.led.read()
            self.assertEqual(len(events), n, bad)
            self.assertTrue(any("最終行を採用しませんでした" in w for w in warnings), bad)
            self.record(f"next-{n}", [], [])                      # 追記時に取り除かれる
            self.assertTrue(all(json.loads(x)["event_id"] != "x" for x in rd(self.led.path).splitlines()))

    def test_terminated_bad_line_is_corrupt_and_valid_unterminated_tail_is_recovered(self):
        self.record("s1", [], [])
        ok = self.led._event("status_changed", event_id="ok-tail", finding_id="f_" + "0" * 16, status="open", reason="r")
        with open(self.led.path, "ab") as f:
            f.write(json.dumps(ok).encode())
        self.assertEqual(len(self.led.read()[0]), 2)                          # 有効な改行なし末尾は採用
        self.record("s2", [], [])
        self.assertEqual(len(self.led.read()[0]), 3)                          # 追記後も破損しない
        with open(self.led.path, "ab") as f:
            f.write(json.dumps(self._bad_events()[0]).encode() + b"\n")
        with self.assertRaises(fl.LedgerCorrupt):
            self.led.read()


class ReviewR6Test(LedgerBase):
    """実装レビュー R6: 所見ID v2は正規化origin(scheme/host/実効port)を含む。旧IDは上書きも自動継承もしない。"""

    def fid(self, target, loc="/a q"):
        return fl.finding_id("lab", target, "SQLI", loc, "authenticated")

    def test_origin_distinguishes_scheme_and_port_but_not_default_port_or_case(self):
        self.assertNotEqual(self.fid("http://example.test"), self.fid("https://example.test"))
        self.assertNotEqual(self.fid("http://example.test:8080"), self.fid("http://example.test:8081"))
        self.assertEqual(self.fid("http://Example.TEST"), self.fid("http://example.test:80"))
        self.assertEqual(self.fid("https://example.test"), self.fid("https://example.test:443/path?x=1"))
        self.assertTrue(self.fid("http://[::1]:8080").startswith("f2_"))
        self.assertEqual(fl.finding_id("e", "app.py", "R", "app.py:3", "unknown"),
                         fl.finding_id("e", "APP.py", "R", "app.py:90-99", "unknown"))      # コード監査は従来どおり

    def test_suppression_is_not_shared_between_http_and_https(self):
        for sid, tgt in (("h", "http://example.test"), ("s", "https://example.test")):
            self.led.record_scan(scan(sid, [finding("/a q", "SQLI")], unit_cov("/a", "q"), target=tgt))
        a, b = self.fid("http://example.test"), self.fid("https://example.test")
        self.clock[0] += timedelta(minutes=1)
        self.led.suppress(a, "accepted for http", (self.clock[0] + timedelta(days=3)).isoformat())
        listed = {f["finding_id"]: f["suppressed"] for f in self.led.findings(include_suppressed=True)["findings"]}
        self.assertEqual(listed, {a: True, b: False})

    def _legacy_ledger(self):
        """v2導入前に作られた台帳(finding_idがf_、id_versionなし)を再現する。"""
        old = fl.legacy_finding_id(self.led.engagement_id, "http://example.test", "SQLI", "/a q", "authenticated")
        self.led.record_scan(scan("old", [finding("/a q", "SQLI")], unit_cov("/a", "q"), target="http://example.test"))
        new = self.fid_of_engagement("http://example.test")
        lines = [json.loads(x) for x in rd(self.led.path).splitlines()]
        for ev in lines:
            if ev.get("finding_id") == new:
                ev["finding_id"] = old
                ev["event_id"] = f"obs:old:{old}"
                ev.pop("id_version", None)
        with open(self.led.path, "w", encoding="utf-8") as f:
            f.write("".join(json.dumps(e, sort_keys=True) + "\n" for e in lines))
        return old

    def fid_of_engagement(self, target):
        return fl.finding_id(self.led.engagement_id, target, "SQLI", "/a q", "authenticated")

    def test_legacy_events_are_kept_warned_and_not_inherited(self):
        old = self._legacy_ledger()
        self.clock[0] += timedelta(minutes=1)
        self.led.suppress(old, "legacy accept", (self.clock[0] + timedelta(days=3)).isoformat())
        events, warnings = self.led.read()
        self.assertTrue(any("旧形式(v1)" in w for w in warnings))
        self.led.record_scan(scan("new", [finding("/a q", "SQLI")], unit_cov("/a", "q"), target="http://example.test"))
        view = self.led.report_view(scan("new", [finding("/a q", "SQLI")], unit_cov("/a", "q"), target="http://example.test"))
        row = view["findings"][0]
        self.assertTrue(row["finding_id"].startswith("f2_"))
        self.assertFalse(row["suppressed"])                       # 旧IDの抑制は新IDへ自動継承しない
        self.assertEqual(row["status"], "open")
        self.assertIn(old, {f["finding_id"] for f in self.led.findings(include_suppressed=True)["findings"]})   # 旧記録は残る

    def test_diff_refuses_across_id_versions_instead_of_guessing(self):
        self._legacy_ledger()
        self.led.record_scan(scan("new", [finding("/a q", "SQLI")], unit_cov("/a", "q"), target="http://example.test"))
        with self.assertRaises(fl.LedgerError):
            self.led.diff("old", "new")

    def test_v2_to_v2_diff_unchanged(self):
        self.led.record_scan(scan("x1", [finding("/a q", "SQLI")], unit_cov("/a", "q")))
        self.led.record_scan(scan("x2", [finding("/a q", "SQLI")], unit_cov("/a", "q")))
        self.assertEqual(self.ids(self.led.diff("x1", "x2")), {"/a q": "PERSISTING"})


if __name__ == "__main__":
    unittest.main()
