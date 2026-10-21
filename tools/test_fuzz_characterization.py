"""現行WEB FUZZ経路の特性化試験。後続のcapability化の比較基準になる(実LLM・外部通信なし)。

ここで固定するのは「現行の挙動」であり、望ましい挙動とは限らない。望ましくない現行の挙動
(POSTの送信、予算切れでも全注入点がtested)には「現行の限界」と明記し、新経路での意図的な差は
docs/AUTONOMOUS_PHASE_A_DESIGN.md §11 に従って別の試験で固定する。
"""
import json
import os
import re
import unittest
from collections import Counter

from testlab.fixtures.web_fixture import FixtureServer
from tools.fuzz_characterization import run_legacy

_GT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "testlab", "ground_truth.json")


def _strip_port(s: str) -> str:
    return re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:PORT", s)


def _load_ground_truth() -> list[dict]:
    with open(_GT_PATH, encoding="utf-8") as f:
        return json.load(f)["cases"]


def _classify(observation) -> tuple[set, set, set, int]:
    """ground truthに対する (TP, FP, FN) のcase_id集合と、対象外の異常数を返す。"""
    methods = {(p, path): m for (m, p, path) in observation.injection_points()}
    detected = set()
    for (cat, param, path) in observation.anomaly_keys():
        method = methods.get((param, path), "GET")
        detected.add((cat, f"{method} {path} {param}"))
    tp, fp, fn, known = set(), set(), set(), set()
    for case in _load_ground_truth():
        key = (case["rule_id"], case["location"])
        known.add(key)
        hit = key in detected
        if case["expected"] == "vulnerable":
            (tp if hit else fn).add(case["case_id"])
        elif hit:
            fp.add(case["case_id"])
    return tp, fp, fn, len(detected - known)


class FuzzCharacterizationTest(unittest.TestCase):
    def test_ground_truth_file_is_well_formed(self):
        cases = _load_ground_truth()
        ids = [c["case_id"] for c in cases]
        self.assertEqual(len(ids), len(set(ids)))
        for c in cases:
            self.assertIn(c["expected"], ("vulnerable", "not_vulnerable"))
            self.assertTrue(c["rule_id"] and c["location"])

    def test_baseline_matches_ground_truth(self):
        with FixtureServer() as srv:
            obs = run_legacy(srv)
        tp, fp, fn, unknown = _classify(obs)
        self.assertEqual(tp, {"sqli-item-id", "xss-search-q", "xss-comment-text"})
        self.assertEqual((fp, fn, unknown), (set(), set(), 0))
        self.assertEqual(obs.state, "completed")
        self.assertEqual(obs.result["errors"], [])

    def test_lifecycle_result_and_done_exactly_once(self):
        with FixtureServer() as srv:
            obs = run_legacy(srv)
        self.assertEqual((obs.result_count, obs.done_count, obs.error), (1, 1, False))

    def test_requests_stay_on_fixture_and_expected_paths(self):
        with FixtureServer() as srv:
            obs = run_legacy(srv)
        paths = {(m, p) for (m, p, _q, _b) in obs.requests}
        self.assertEqual(paths, {("GET", "/"), ("GET", "/search"), ("GET", "/item"), ("GET", "/safe"),
                                 ("GET", "/escaped"), ("GET", "/guestbook"), ("POST", "/comment")})

    def test_current_limit_legacy_path_sends_post(self):
        """現行の限界: POSTフォームの注入点にも送信する。新経路(web.fuzz_get_points)は送らない(§11.1)。"""
        with FixtureServer() as srv:
            obs = run_legacy(srv)
            self.assertGreater(srv.count("POST", "/comment"), 0)
        self.assertEqual(obs.injection_points()[("POST", "text", "/comment")], 1)

    def test_deterministic_across_runs(self):
        """予算が拘束しない場合、リクエスト・異常・所見・coverage・状態は多重集合として揺れない。"""
        snaps = []
        for _ in range(3):
            with FixtureServer() as srv:
                obs = run_legacy(srv)
            snaps.append((obs.requests, obs.anomaly_keys(), obs.injection_points(), obs.finding_keys(),
                          Counter(( _strip_port(k[0]),) + k[1:] for k in obs.coverage_keys().elements()),
                          obs.state))
        self.assertTrue(all(s == snaps[0] for s in snaps[1:]))
        self.assertEqual(sum(snaps[0][0].values()), 78)

    def test_budget_binding_only_bounds_total_and_state(self):
        """予算が拘束するときは、どの注入点が先に消費するかが競合で変わり得るため、総数と状態だけを固定する。"""
        for limit in (12, 30):
            with FixtureServer() as srv:
                obs = run_legacy(srv, max_requests=limit)
            self.assertLessEqual(obs.total_requests(), limit)
            self.assertEqual(obs.state, "partial")
            self.assertTrue(any("予算" in e for e in obs.result["errors"]))

    def test_current_limit_unfinished_points_still_reported_tested(self):
        """現行の限界: 予算切れで未実施でも全注入点がtestedになる(§11.3で新経路は区別する)。"""
        with FixtureServer() as srv:
            obs = run_legacy(srv, max_requests=12)
        self.assertLess(sum(obs.anomaly_keys().values()), 3)       # 全ては検出できていない(どれが残るかは競合で変わる)
        statuses = {k[3] for k in obs.coverage_keys()}
        self.assertEqual(statuses, {"tested"})                      # しかし全てtested
        self.assertGreater(len(obs.coverage_keys()), 0)


if __name__ == "__main__":
    unittest.main()
