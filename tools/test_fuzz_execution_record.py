"""WebFuzzer.fuzz_log(検査単位の実行記録)の固定試験。fuzz()の返り値・挙動は変えない追加情報。"""
import threading
import unittest

from testlab.fixtures.web_fixture import FixtureServer
from tools.web_fuzzer import DEFAULT_PROBES, WebFuzzer

STATUSES = {"completed", "exhausted", "stopped", "not_started", "transport_error", "partial"}


def _fuzzer(srv, max_requests, stop_event=None):
    return WebFuzzer(profile="aggressive", max_pages=20, max_requests=max_requests,
                     target=srv.base_url, stop_event=stop_event, tls_verify=False, tls_ca_bundle="")


def _points(f, srv):
    return f.crawl(srv.base_url)["injection_points"]


class FuzzExecutionRecordTest(unittest.TestCase):
    def _assert_every_unit_recorded_once(self, f, points):
        log = f.fuzz_log
        keys = [(r["url"], r["method"], r["param"], r["category"]) for r in log]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(len(keys), len(points) * len(DEFAULT_PROBES))
        for r in log:
            self.assertIn(r["status"], STATUSES)
            self.assertLessEqual(r["attempted"], r["planned"])
        return log

    def _measure(self):
        with FixtureServer() as srv:
            f = _fuzzer(srv, 500)
            pts = _points(f, srv)
            crawl_used = f._req_count
            f.fuzz(pts, DEFAULT_PROBES)
            return crawl_used, f._req_count

    def test_full_run_records_completed_and_first_signal(self):
        with FixtureServer() as srv:
            f = _fuzzer(srv, 500)
            pts = _points(f, srv)
            anomalies = f.fuzz(pts, DEFAULT_PROBES)
            log = self._assert_every_unit_recorded_once(f, pts)
        self.assertEqual({r["status"] for r in log}, {"completed"})
        self.assertEqual({(a["category"], a["param"]) for a in anomalies},
                         {("SQLI", "id"), ("XSS", "q"), ("XSS", "text")})   # 返り値は従来どおり
        sqli = next(r for r in log if r["param"] == "id" and r["category"] == "SQLI")
        self.assertEqual((sqli["reason"], sqli["attempted"]), ("first_signal", 1))
        self.assertLess(sqli["attempted"], sqli["planned"])
        safe = [r for r in log if r["param"] == "page"]
        self.assertTrue(all(r["attempted"] == r["planned"] and r["reason"] == "" for r in safe))

    def test_budget_zero_for_fuzz_phase_marks_all_not_started(self):
        crawl_used, _total = self._measure()
        with FixtureServer() as srv:
            f = _fuzzer(srv, crawl_used)            # クロールで予算を使い切る
            pts = _points(f, srv)
            self.assertEqual(f._req_count, crawl_used)
            before = srv.count()
            self.assertEqual(f.fuzz(pts, DEFAULT_PROBES), [])
            log = self._assert_every_unit_recorded_once(f, pts)
            self.assertEqual(srv.count(), before)   # ファジングの送信は0
        self.assertEqual({(r["status"], r["reason"], r["attempted"]) for r in log},
                         {("not_started", "budget_exhausted", 0)})

    def test_mid_exhaustion_distinguishes_done_from_unfinished(self):
        crawl_used, _total = self._measure()
        extra = 15
        with FixtureServer() as srv:
            f = _fuzzer(srv, crawl_used + extra)
            pts = _points(f, srv)
            f.fuzz(pts, DEFAULT_PROBES)
            log = self._assert_every_unit_recorded_once(f, pts)
            self.assertLessEqual(f._req_count, crawl_used + extra)
        self.assertLessEqual(sum(r["attempted"] for r in log), extra)
        self.assertTrue(any(r["status"] in ("exhausted", "not_started") for r in log))
        for r in log:
            if r["status"] == "completed" and r["reason"] != "first_signal":
                self.assertEqual(r["attempted"], r["planned"])       # completedは全て試行済み
            if r["status"] == "not_started":
                self.assertEqual(r["attempted"], 0)
            if r["status"] == "exhausted":
                self.assertTrue(0 < r["attempted"] < r["planned"])
            if r["status"] in ("exhausted", "not_started"):
                self.assertEqual(r["reason"], "budget_exhausted")

    def test_exactly_enough_budget_completes_everything(self):
        _crawl_used, total = self._measure()
        with FixtureServer() as srv:
            f = _fuzzer(srv, total)
            pts = _points(f, srv)
            f.fuzz(pts, DEFAULT_PROBES)
            log = self._assert_every_unit_recorded_once(f, pts)
            self.assertEqual(f._req_count, total)
        self.assertEqual({r["status"] for r in log}, {"completed"})
        # 1件でも足りなければ未実施が現れる(ちょうど完遂との境界)
        with FixtureServer() as srv:
            f = _fuzzer(srv, total - 1)
            pts = _points(f, srv)
            f.fuzz(pts, DEFAULT_PROBES)
            log = self._assert_every_unit_recorded_once(f, pts)
        self.assertTrue(any(r["status"] != "completed" for r in log))

    def test_stop_marks_not_started_with_reason(self):
        stop = threading.Event()
        with FixtureServer() as srv:
            f = _fuzzer(srv, 500, stop_event=stop)
            pts = _points(f, srv)
            stop.set()
            before = srv.count()
            self.assertEqual(f.fuzz(pts, DEFAULT_PROBES), [])
            log = self._assert_every_unit_recorded_once(f, pts)
            self.assertEqual(srv.count(), before)
        self.assertEqual({(r["status"], r["reason"]) for r in log}, {("not_started", "stopped")})

    def test_transport_error_when_no_response_is_obtained(self):
        with FixtureServer() as srv:
            f = _fuzzer(srv, 500)
            _points(f, srv)
            bad = {"url": "http://127.0.0.1:1/x", "method": "GET", "param": "q", "where": "query", "fields": {}}
            before = srv.count()
            f.fuzz([bad], DEFAULT_PROBES)         # 別originは送信前に拒否される(応答なし)
            self.assertEqual(srv.count(), before)
        log = f.fuzz_log
        self.assertEqual(len(log), len(DEFAULT_PROBES))
        self.assertEqual({r["status"] for r in log}, {"transport_error"})
        self.assertTrue(all(r["errors"] == r["attempted"] == r["planned"] for r in log))

    def test_log_is_reset_per_fuzz_call_and_returns_copies(self):
        with FixtureServer() as srv:
            f = _fuzzer(srv, 500)
            pts = _points(f, srv)
            f.fuzz(pts[:1], DEFAULT_PROBES)
            n1 = len(f.fuzz_log)
            f.fuzz(pts[:1], DEFAULT_PROBES)
            self.assertEqual(len(f.fuzz_log), n1)
            f.fuzz_log[0]["status"] = "tampered"
            self.assertNotEqual(f.fuzz_log[0]["status"], "tampered")



class _Marking(WebFuzzer):
    """送信結果を加工して不完全な観測を作る試験用サブクラス(通信はFixtureServerへ実際に行う)。"""
    mode = ""
    only_param = "page"

    def _send(self, url, method, fields):
        resp = super()._send(url, method, fields)
        probing = self.only_param in fields and fields.get(self.only_param) not in (None, "1", "")
        self.calls = getattr(self, "calls", 0) + 1
        if resp is None or not probing and self.mode != "baseline_fail":
            return resp
        if self.mode == "incomplete" and probing:
            resp.fz_truncated, resp.fz_incomplete_reason = True, "read_error"
        elif self.mode == "one_fails" and probing and not getattr(self, "_failed", False):
            self._failed = True
            return None
        elif self.mode == "baseline_fail" and not probing and self.only_param in fields and not getattr(self, "_b", False):
            self._b = True
            return None
        return resp


class IncompleteObservationTest(unittest.TestCase):
    """実装レビュー(2026-10-23) R2/R3: 不完全な観測を『検査済み・兆候なし』にしない。"""

    def _run(self, mode):
        with FixtureServer() as srv:
            f = _Marking(profile="aggressive", max_pages=20, max_requests=500, target=srv.base_url,
                         tls_verify=False, tls_ca_bundle="")
            f.mode = mode
            pts = _points(f, srv)
            anomalies = f.fuzz(pts, DEFAULT_PROBES)
            return f.fuzz_log, anomalies

    def _page(self, log):
        return [r for r in log if r["param"] == "page"]

    def test_clean_run_still_completed(self):
        log, _ = self._run("")
        self.assertEqual({r["status"] for r in self._page(log)}, {"completed"})

    def test_incomplete_bodies_without_signal_are_partial(self):
        log, anomalies = self._run("incomplete")
        page = self._page(log)
        self.assertTrue(page)
        self.assertEqual({r["status"] for r in page}, {"partial"})
        self.assertTrue(all("incomplete_bodies=" in r["reason"] for r in page))
        self.assertEqual({(a["category"], a["param"]) for a in anomalies},
                         {("SQLI", "id"), ("XSS", "q"), ("XSS", "text")})   # 他の検査単位の検出は従来どおり

    def test_partial_probe_failure_without_signal_is_partial_not_completed(self):
        log, _ = self._run("one_fails")
        failed = [r for r in self._page(log) if r["errors"] == 1]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["status"], "partial")
        self.assertIn("probes_failed=1/", failed[0]["reason"])
        self.assertEqual({r["status"] for r in self._page(log) if r["errors"] == 0}, {"completed"})

    def test_baseline_failure_without_signal_is_partial(self):
        log, _ = self._run("baseline_fail")
        self.assertTrue(any(r["status"] == "partial" and "baseline_failed" in r["reason"] for r in self._page(log)))

    def test_ssti_confirmation_failure_is_unconfirmed_not_negative(self):
        from tools import web_fuzzer as wf

        class F(WebFuzzer):
            def _send(self, *a, **k):
                return None
        f = F(profile="aggressive", max_pages=1, max_requests=5, target="http://127.0.0.1:1", tls_verify=False, tls_ca_bundle="")
        out = f._confirm_ssti("http://127.0.0.1:1/x", "GET", {"q": "1"}, "q", "{{7*7}}", "body", ("HIGH", "49"))
        self.assertIs(out, wf.UNCONFIRMED)

    def test_first_signal_early_exit_is_kept(self):
        log, _ = self._run("incomplete")
        sqli = next(r for r in log if r["param"] == "id" and r["category"] == "SQLI")
        self.assertEqual((sqli["status"], sqli["reason"]), ("completed", "first_signal"))


class TransportIncompleteTest(unittest.TestCase):
    def _cap(self, chunks, exc=None, policy=None):
        import requests
        from core.http_transport import HttpTransport

        class Body:
            def iter_content(self, chunk_size):
                for c in chunks:
                    yield c
                if exc:
                    raise requests.exceptions.ChunkedEncodingError("synthetic")

            def close(self):
                pass
        r = Body()
        HttpTransport(1)._cap_response_body(r)
        return r

    def test_interrupted_read_marks_incomplete_and_keeps_partial_body(self):
        r = self._cap([b"partial"], exc=True)
        self.assertEqual((r._content, r.fz_truncated, r.fz_incomplete_reason, r.fz_bytes_read),
                         (b"partial", True, "read_error", 7))

    def test_complete_body_is_not_marked(self):
        r = self._cap([b"abc", b"def"])
        self.assertEqual((r._content, r.fz_truncated, r.fz_incomplete_reason), (b"abcdef", False, None))

    def test_empty_body_is_complete_and_distinct_from_error(self):
        self.assertFalse(self._cap([]).fz_truncated)
        self.assertTrue(self._cap([], exc=True).fz_truncated)

    def test_size_cap_is_reported(self):
        from core.http_transport import HttpTransport
        t = HttpTransport(1)
        cap = t.policy.max_response_bytes
        r = self._cap([b"x" * (cap + 10)])
        self.assertEqual((r.fz_truncated, r.fz_incomplete_reason, r.fz_bytes_read), (True, "size_cap", cap))

    def test_upstream_incompleteness_reaches_stored_evidence_and_reported_notes(self):
        import tempfile
        from agents.fuzz_agent import FuzzAgent
        from core.evidence_store import EvidenceStore
        with tempfile.TemporaryDirectory() as d:
            store = EvidenceStore("scan_x", root=d)
            a = {"method": "GET", "url": "http://x.test/a?q=1", "status": 200, "response_headers": {},
                 "response_body": "p", "baseline_body": "", "response_incomplete": "response:read_error"}
            known, errors = FuzzAgent._save_evidence(store, [a], [], set())
            self.assertEqual(len(known), 1)
            ev = store.load(next(iter(known)))
            self.assertTrue(ev["truncated"])
            self.assertIn("read_error", ev["omitted_reason"])
            notes = FuzzAgent.incomplete_notes([a], [], set())       # 証拠保存のON/OFFと無関係に報告する
            self.assertTrue(any("根拠応答が不完全" in n and "read_error" in n for n in notes))


class IncompleteEvidencePathsTest(unittest.TestCase):
    """レビュー再検査 F1/F2: baseline・追加確認・IDORの不完全性を保持し、報告文字列に秘密値を出さない。"""

    def test_baseline_incomplete_with_clean_signal_is_reported_without_evidence_saving(self):
        class F(WebFuzzer):
            def _send(self, url, method, fields):
                resp = super()._send(url, method, fields)
                val = str(fields.get("id", "x"))
                if resp is not None and "id" in fields and val.isalnum():       # 兆候の無い通常値=baseline
                    resp.fz_truncated, resp.fz_incomplete_reason = True, "read_error"
                return resp
        with FixtureServer() as srv:
            f = F(profile="aggressive", max_pages=20, max_requests=500, target=srv.base_url, tls_verify=False,
                  tls_ca_bundle="")
            anomalies = f.fuzz(_points(f, srv), DEFAULT_PROBES)
        sqli = next(a for a in anomalies if a["category"] == "SQLI")
        self.assertIn("baseline:read_error", sqli["response_incomplete"])
        self.assertNotIn("response:", sqli["response_incomplete"])             # 主応答は完全

    def test_ssti_confirmation_truncated_but_positive_keeps_the_limitation(self):
        f = WebFuzzer(profile="aggressive", max_pages=1, max_requests=5, target="http://127.0.0.1:1", tls_verify=False,
                      tls_ca_bundle="")
        f._rng.seed(1)
        a, b = f._rng.sample(range(11, 98), 2)
        f._rng.seed(1)
        f._send = lambda *x, **k: type("R", (), {"text": f"x {a * b}", "fz_truncated": True,
                                                 "fz_incomplete_reason": "read_error"})()
        out = f._confirm_ssti("http://127.0.0.1:1/x", "GET", {"q": "1"}, "q", "{{7*7}}", "body", ("HIGH", "49"))
        self.assertEqual((len(out), out[2]), (3, "read_error"))

    def test_idor_both_directions_carry_incompleteness(self):
        class R:
            def __init__(self, text, status=200, cut=False):
                self.text, self.status_code, self.headers = text, status, {}
                self.fz_truncated, self.fz_incomplete_reason = cut, "read_error" if cut else None
        f = WebFuzzer(profile="aggressive", max_pages=1, max_requests=50, target="http://127.0.0.1:1",
                      auth={"cookie": "a=1"}, auth_b={"cookie": "b=1"}, tls_verify=False, tls_ca_bundle="")
        body = "invoice 1001 for customer " + "x" * 200

        def send_as(session, url):
            if session is f.session_b:
                return R(body, cut=True)
            if session is f.session:
                return R(body)
            return R("forbidden", 403)
        f._send_as = send_as
        f.idor_expectations = [{"path": "/inv", "param": "id", "a": "allow", "b": "deny", "value": None}]
        pts = [{"url": "http://127.0.0.1:1/inv", "method": "GET", "param": "id", "fields": {"id": "1001"}}]
        found = f._detect_idor(pts)
        self.assertEqual(len(found), 1)
        self.assertIn("session_b:read_error", found[0]["response_incomplete"])

    def test_notes_and_store_errors_never_contain_known_secrets(self):
        import tempfile
        from agents.fuzz_agent import FuzzAgent
        from core.evidence_store import EvidenceStore
        secret = "DUMMY_REVIEW_SECRET"
        a = {"method": "GET", "url": f"http://x.test/a?token={secret}&q=1", "status": 200, "response_headers": {},
             "response_body": "p", "baseline_body": "", "response_incomplete": "response:read_error"}
        notes = FuzzAgent.incomplete_notes([a], [dict(a, response_incomplete="session_b:read_error")], {secret})
        self.assertEqual(len(notes), 2)
        self.assertNotIn(secret, "\n".join(notes))
        with tempfile.TemporaryDirectory() as d:
            store = EvidenceStore("scan_y", root=d)
            known, errors = FuzzAgent._save_evidence(store, [a], [dict(a)], {secret})
            self.assertNotIn(secret, "\n".join(errors))
            for eid in known:
                ev = store.load(eid)
                self.assertTrue(ev["truncated"])
                self.assertNotIn(secret, str(ev))


if __name__ == "__main__":
    unittest.main()
