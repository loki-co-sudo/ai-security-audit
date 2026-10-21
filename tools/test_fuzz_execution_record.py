"""WebFuzzer.fuzz_log(検査単位の実行記録)の固定試験。fuzz()の返り値・挙動は変えない追加情報。"""
import threading
import unittest

from testlab.fixtures.web_fixture import FixtureServer
from tools.web_fuzzer import DEFAULT_PROBES, WebFuzzer

STATUSES = {"completed", "exhausted", "stopped", "not_started", "transport_error"}


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


if __name__ == "__main__":
    unittest.main()
