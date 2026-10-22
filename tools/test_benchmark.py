"""tools/benchmark.py(P2.1)の固定試験。集計器は手計算できる予測集合で検証する。"""
import copy
import json
import os
import tempfile
import unittest
from unittest import mock

from tools import benchmark as bm


def case(cid, rule, loc, expected):
    return {"case_id": cid, "rule_id": rule, "location": loc, "expected": expected}


class EvaluateTest(unittest.TestCase):
    def test_hand_computed_counts(self):
        cases = [
            case("a", "X", "GET /a q", "vulnerable"),        # 検出・実施済み -> TP
            case("b", "X", "GET /b q", "vulnerable"),        # 未検出・実施済み -> FN
            case("c", "X", "GET /c q", "vulnerable"),        # 未検出・未実施 -> FN(かつ未実施)
            case("d", "X", "GET /d q", "not_vulnerable"),    # 検出 -> FP
            case("e", "X", "GET /e q", "not_vulnerable"),    # 未検出・実施済み -> TN
            case("f", "X", "GET /f q", "not_vulnerable"),    # 未検出・未実施 -> TNに数えない
            case("g", "Y", "GET /g q", "not_vulnerable"),    # Yには脆弱ケースが無い
        ]
        det = {("X", "GET /a q"), ("X", "GET /d q"), ("X", "GET /zzz q")}          # 最後は正解データに無い検出
        exam = {("X", "GET /a q"), ("X", "GET /b q"), ("X", "GET /d q"), ("X", "GET /e q"), ("Y", "GET /g q")}
        r = bm.evaluate(cases, det, exam)
        x, y, t = r["per_rule"]["X"], r["per_rule"]["Y"], r["total"]
        self.assertEqual((x["tp"], x["fp"], x["fn"], x["fn_unexamined"], x["tn"], x["unexamined_negative"]),
                         (1, 2, 2, 1, 1, 1))
        self.assertEqual(x["unlisted"], ["GET /zzz q"])
        self.assertEqual((x["cases"], x["unexamined"]), (6, 2))
        self.assertEqual((x["precision"], x["recall"], x["unexamined_rate"]), (0.3333, 0.3333, 0.3333))
        self.assertEqual((y["tp"], y["fp"], y["fn"], y["tn"]), (0, 0, 0, 1))
        self.assertEqual((y["precision"], y["recall"]), ("N/A", "N/A"))          # 分母0はN/A
        self.assertEqual((t["tp"], t["fp"], t["fn"], t["tn"], t["cases"]), (1, 2, 2, 2, 7))
        self.assertEqual((t["precision"], t["recall"]), (0.3333, 0.3333))

    def test_unexamined_negative_is_never_counted_as_correct(self):
        cases = [case("n", "X", "GET /n q", "not_vulnerable")]
        r = bm.evaluate(cases, set(), set())
        self.assertEqual((r["total"]["tn"], r["total"]["unexamined_negative"]), (0, 1))
        r2 = bm.evaluate(cases, set(), {("X", "GET /n q")})
        self.assertEqual((r2["total"]["tn"], r2["total"]["unexamined_negative"]), (1, 0))

    def test_detections_are_a_set_so_duplicates_do_not_inflate(self):
        cases = [case("a", "X", "GET /a q", "vulnerable")]
        det = {("X", "GET /a q"), ("X", "GET /a q")}                              # 同一ケースの重複所見
        self.assertEqual(bm.evaluate(cases, det, {("X", "GET /a q")})["total"]["tp"], 1)

    def test_empty_everything_is_all_na(self):
        r = bm.evaluate([], set(), set())
        self.assertEqual((r["total"]["precision"], r["total"]["recall"], r["total"]["unexamined_rate"]),
                         ("N/A", "N/A", "N/A"))

    def test_location_normalization(self):
        self.assertEqual(bm.location_of("get", "http://127.0.0.1:1234/item?id=1&x=2#f", "id"), "GET /item id")


class TruthTest(unittest.TestCase):
    def test_shipped_truth_is_well_formed(self):
        doc = bm.load_truth()
        cases = doc["cases"]
        self.assertGreaterEqual(len(cases), 20)
        for rule in ("SQLI", "XSS", "SSTI", "TRAVERSAL", "IDOR"):
            rows = [c for c in cases if c["rule_id"] == rule]
            self.assertTrue(any(c["expected"] == "vulnerable" for c in rows), rule)
            self.assertTrue(any(c["expected"] == "not_vulnerable" for c in rows), rule)   # 正常例を含む
        for c in cases:
            if c["rule_id"] == "IDOR":
                self.assertIn("expected_access", c)                                # 期待権限を持つ

    def test_invalid_truth_is_rejected(self):
        base = {"cases": [case("a", "X", "GET /a q", "vulnerable")]}
        for mutate in (lambda d: d["cases"].append(case("a", "X", "GET /b q", "vulnerable")),      # id重複
                       lambda d: d["cases"].append(case("b", "X", "GET /a q", "vulnerable")),      # キー重複
                       lambda d: d["cases"].append(case("c", "X", "GET /c q", "maybe"))):          # expected不正
            doc = copy.deepcopy(base)
            mutate(doc)
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
                json.dump(doc, f)
            self.addCleanup(os.unlink, f.name)
            with self.assertRaises(ValueError):
                bm.load_truth(f.name)


class RealRunTest(unittest.TestCase):
    def test_baseline_is_stable_and_matches_the_saved_baseline(self):
        with open(bm.BASELINE_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        cur = bm.benchmark_web_fuzz(runs=2)
        self.assertTrue(cur["stable"], "同じ固定入力なのに検出集合が回ごとに変わった")
        delta = bm.compare(saved, cur)
        self.assertEqual(delta, {"per_rule": {}, "added_detections": [], "removed_detections": []},
                         "検出品質が基準値から変わりました。P2.2等の意図した改善なら、差(TP/FP/FNと理由)を記載して"
                         "`python tools/benchmark.py web-fuzz --runs 3 --save-baseline testlab/baselines/web_fuzz_detector.json`で更新")
        self.assertEqual(saved["llm_usage"], "n/a (detector mode)")

    def test_baseline_records_remaining_weakness_and_kept_true_positives(self):
        """P2.2後の基準値: 脆弱例の検出(TP)は維持され、残る誤検出は期待権限が要る閲覧者別ページのみ。"""
        with open(bm.BASELINE_PATH, encoding="utf-8") as f:
            doc = json.load(f)
        m = doc["metrics"]["per_rule"]
        self.assertEqual(m["IDOR"]["fp"], 1)            # /order(期待権限表が未実装のため区別できない)
        self.assertIn(["IDOR", "GET /order id"], doc["detections"])
        for rule in ("SQLI", "XSS", "SSTI", "TRAVERSAL", "IDOR"):
            self.assertGreaterEqual(m[rule]["tp"], 1, rule)
            self.assertEqual(m[rule]["fn"], 0, rule)    # 取りこぼしが増えていない
        self.assertEqual(m["SSTI"]["fp"] + m["XSS"]["fp"] + m["SQLI"]["fp"] + m["TRAVERSAL"]["fp"], 0)

    def test_tiny_budget_surfaces_unexamined_cases_as_misses(self):
        truth = bm.load_truth()
        out = bm.run_web_fuzz_detector(max_requests=45)
        r = bm.evaluate(truth["cases"], out["detections"], out["examined"])
        t = r["total"]
        self.assertLessEqual(out["requests"], 45)
        self.assertGreater(t["unexamined"], 0)
        self.assertEqual(t["tp"] + t["fn"], sum(1 for c in truth["cases"] if c["expected"] == "vulnerable"))
        self.assertGreater(t["fn_unexamined"], 0)                                 # 未検査の脆弱ケースは見逃しに計上
        listed_fp = t["fp"] - sum(len(v["unlisted"]) for v in r["per_rule"].values())
        self.assertEqual(t["tn"] + t["unexamined_negative"] + listed_fp,    # 正常例は必ずどれか1つに分類される
                         sum(1 for c in truth["cases"] if c["expected"] == "not_vulnerable"))


class ExpectationTest(unittest.TestCase):
    PATH = os.path.join(os.path.dirname(bm.BASELINE_PATH), "web_fuzz_detector_expectations.json")

    def test_parser_accepts_valid_and_rejects_ambiguous_or_unsafe_rows(self):
        from core.engagement import EngagementError, parse_idor_expectations as parse
        ok = parse([{"path": "/account", "param": "id", "a": "allow", "b": "deny"},
                    {"path": "/account", "param": "id", "value": "2", "a": "deny", "b": "allow"}])
        self.assertEqual((ok[0]["value"], ok[1]["value"]), (None, "2"))
        self.assertEqual(parse(None), [])
        bad = [[{"path": "/a", "param": "id", "a": "allow"}],                                  # b欠落
               [{"path": "/a?x=1", "param": "id", "a": "allow", "b": "deny"}],                 # クエリ付きパス
               [{"path": "http://h/a", "param": "id", "a": "allow", "b": "deny"}],             # origin付き
               [{"path": "/a/*", "param": "id", "a": "allow", "b": "deny"}],                   # ワイルドカード
               [{"path": "/a", "param": "id", "a": "maybe", "b": "deny"}],                     # 値が不正
               [{"path": "/a", "param": "id", "a": "allow", "b": "deny", "x": 1}],             # 未知キー
               [{"path": "/a", "param": "id", "a": "allow", "b": "deny"}] * 2,                  # 重複
               "x"]
        for rows in bad:
            with self.assertRaises(EngagementError, msg=str(rows)):
                parse(rows)

    def test_with_expectations_matches_saved_baseline_and_keeps_true_positives(self):
        with open(self.PATH, encoding="utf-8") as f:
            saved = json.load(f)
        cur = bm.benchmark_web_fuzz(runs=2, with_expectations=True)
        self.assertTrue(cur["stable"])
        self.assertEqual(bm.compare(saved, cur), {"per_rule": {}, "added_detections": [], "removed_detections": []})
        without = bm.benchmark_web_fuzz(runs=1)["metrics"]["per_rule"]["IDOR"]
        with_exp = cur["metrics"]["per_rule"]["IDOR"]
        self.assertEqual(with_exp["tp"], without["tp"])        # 期待権限表で脆弱例を取りこぼさない
        self.assertEqual(with_exp["fn"], 0)
        self.assertLess(with_exp["fp"], without["fp"])         # 閲覧者別ページの誤検出が減る
        self.assertEqual(saved["kind"], "web_fuzz_detector_with_expectations")

    def test_line_format_round_trips_and_reports_the_offending_line(self):
        from core.engagement import (EngagementError, format_expectation_lines as fmt,
                                     parse_expectation_lines as parse, parse_idor_expectations)
        rows = parse("# comment\n/account id 1 a=allow b=deny\n\n/public id a=allow b=allow\n")
        self.assertEqual([(r["path"], r["param"], r["value"], r["a"], r["b"]) for r in rows],
                         [("/account", "id", "1", "allow", "deny"), ("/public", "id", None, "allow", "allow")])
        self.assertEqual(parse(fmt(rows)), rows)                                   # 表示用の形式から元に戻せる
        self.assertEqual(rows, parse_idor_expectations(rows))                      # 辞書形式と同じ検証を通る
        self.assertEqual(parse(""), [])
        for text, line in (("/a id a=allow", 1), ("# ok\n/a id a=maybe b=deny", 2), ("/a?x=1 id a=allow b=deny", 1),
                           ("/a id a=allow b=deny\n/a id a=allow b=deny", 2), ("/a id a=allow a=deny b=deny", 1),
                           ("http://h/a id a=allow b=deny", 1), ("/a id 1 2 a=allow b=deny", 1)):
            with self.assertRaises(EngagementError, msg=text) as cm:
                parse(text)
            self.assertTrue(str(cm.exception).startswith(f"{line}行目"), (text, str(cm.exception)))

    def test_legacy_fuzz_agent_applies_the_table_and_rejects_an_invalid_one(self):
        """GUI経路の旧FuzzAgentが期待表を使う: 表なしで除外される公開ページが、b=denyの表では違反の根拠になる。"""
        from agents.fuzz_agent import FuzzAgent
        from core import config
        from core.event_bus import EventBus
        from testlab.fixtures.web_benchmark import BenchmarkServer, TOKENS
        from tools.fuzz_characterization import MockLLM
        with BenchmarkServer() as srv:
            def run(exp):
                bus, agent = EventBus(), FuzzAgent(EventBus(), MockLLM())
                agent.bus = bus
                with mock.patch.dict(config._cfg, {**config._DEFAULTS, "allowed_targets": [], "scope_mode": "warn",
                                                   "save_evidence": False, "effort": "speed"}, clear=True), \
                     mock.patch.object(FuzzAgent, "_save_investigation", lambda *a, **k: None), \
                     mock.patch.object(FuzzAgent, "_record_telemetry", lambda *a, **k: None):
                    agent._safe_run(target=srv.base_url, profile="aggressive", max_requests=1500,
                                    auth={"cookie": "sid=" + TOKENS["alice"]}, auth_b={"cookie": "sid=" + TOKENS["bob"]},
                                    idor_expectations=exp)
                text = "".join(e.payload["text"] for e in bus.drain(100000) if e.kind == "output")
                return agent._last_scan_result, text
            res, text = run(None)
            self.assertNotIn("/public?id", "".join(l for l in text.splitlines() if "[IDOR?]" in l))   # 表なし: 公開として除外
            self.assertNotIn("IDOR期待権限", text)
            res, text = run([{"path": "/public", "param": "id", "a": "allow", "b": "deny"}])
            self.assertIn("/public?id", "".join(l for l in text.splitlines() if "[IDOR?]" in l))       # 表あり: 期待上deny
            self.assertIn("IDOR期待権限 : 1行", text)
            res, text = run([{"path": "/public", "param": "id", "a": "allow"}])     # 不正な表は送信せず失敗する
            self.assertEqual(res.state, "failed")
            self.assertTrue(any("期待権限表が不正です" in e for e in res.errors), res.errors)

    def test_expectation_overrides_public_check_and_marks_basis(self):
        """期待上denyのBが読めれば、認証なしでも読める公開ページでも違反(期待表が公開判定より優先)。"""
        from testlab.fixtures.web_benchmark import BenchmarkServer, TOKENS
        from tools.web_fuzzer import WebFuzzer
        with BenchmarkServer() as srv:
            def run(exp):
                f = WebFuzzer(profile="aggressive", max_pages=40, max_requests=3000, target=srv.base_url,
                              auth={"cookie": "sid=" + TOKENS["alice"]}, auth_b={"cookie": "sid=" + TOKENS["bob"]},
                              tls_verify=False, tls_ca_bundle="")
                f.idor_expectations = exp
                f.authenticate(); f.authenticate_b()
                pts = [p for p in f.crawl(srv.base_url)["injection_points"] if p["url"].endswith("/public")]
                return f._detect_idor(pts)
            self.assertEqual(run([]), [])                                           # 表なし: 公開として除外
            hit = run([{"path": "/public", "param": "id", "value": None, "a": "allow", "b": "deny"}])
            self.assertEqual([h["basis"] for h in hit], ["expectation"])


class DefenseBenchmarkTest(unittest.TestCase):
    def test_truth_is_well_formed_and_labelled_by_meaning(self):
        doc = bm.load_truth(bm.DEFENSE_TRUTH_PATH)
        from core.settings import ATTACK_PATTERNS
        rules = {c["rule_id"] for c in doc["cases"]}
        self.assertEqual(rules, set(ATTACK_PATTERNS))                              # 全シグネチャに脆弱例/正常例がある
        for rule in rules:
            exp = {c["expected"] for c in doc["cases"] if c["rule_id"] == rule}
            self.assertEqual(exp, {"vulnerable", "not_vulnerable"}, rule)
        self.assertTrue(all(c["line"] for c in doc["cases"]))

    def test_run_matches_the_saved_baseline_and_is_deterministic(self):
        with open(bm.DEFENSE_BASELINE_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        cur = bm.benchmark_defense(runs=3)
        self.assertTrue(cur["stable"])
        self.assertEqual(bm.compare(saved, cur), {"per_rule": {}, "added_detections": [], "removed_detections": []},
                         "シグネチャ検知の品質が基準値から変わりました。意図した変更なら差(TP/FP/FN)を記載して"
                         "`python tools/benchmark.py defense --runs 3 --save-baseline testlab/baselines/defense_signatures.json`で更新")
        self.assertEqual(cur["metrics"]["total"]["unexamined"], 0)

    def test_baseline_fixes_defense2_blind_spots_and_new_heldout_cases_pass(self):
        """defense-2で残った4件の見逃しを直した。その後に追加した未見ケース(heldout3-*)も基準値で検出/非検出が正しい。"""
        with open(bm.DEFENSE_BASELINE_PATH, encoding="utf-8") as f:
            doc = json.load(f)
        det = {tuple(d) for d in doc["detections"]}
        for rule, lid in (("SQL_INJECTION", "heldout-sqli-union-all"), ("CMD_INJECTION", "heldout-cmd-pipe-nc"),
                          ("BRUTE_FORCE", "heldout-bf-sshd-failed-password"), ("SSRF", "heldout-ssrf-ipv6-loopback"),
                          ("SQL_INJECTION", "heldout3-sqli-union-all-mixedcase"), ("CMD_INJECTION", "heldout3-cmd-pipe-bash"),
                          ("BRUTE_FORCE", "heldout3-bf-sshd-root"), ("SSRF", "heldout3-ssrf-ipv6-long")):
            self.assertIn((rule, lid), det)
        for rule, lid in (("SQL_INJECTION", "heldout3-sqli-benign-union-word"), ("CMD_INJECTION", "heldout3-cmd-benign-pipe"),
                          ("BRUTE_FORCE", "heldout3-bf-benign-accepted"), ("SSRF", "heldout3-ssrf-benign-ipv6-public")):
            self.assertNotIn((rule, lid), det)
        self.assertEqual((doc["metrics"]["total"]["fn"], doc["metrics"]["total"]["fp"]), (0, 0))
        self.assertEqual(doc["llm_usage"], "n/a (signature mode)")

    def test_defense2_baseline_is_kept_as_history(self):
        """defense-2時点: 58判定でFN4(後続の修正前)。同じ検出器版では見逃していた。"""
        path = os.path.join(os.path.dirname(bm.DEFENSE_BASELINE_PATH), "defense_signatures.before-defense-3.json")
        with open(path, encoding="utf-8") as f:
            old = json.load(f)
        self.assertEqual((old["metrics"]["total"]["fp"], old["metrics"]["total"]["fn"]), (0, 4))
        self.assertNotIn(("SSRF", "heldout-ssrf-ipv6-loopback"), {tuple(d) for d in old["detections"]})

    def test_pre_change_baseline_is_kept_as_history(self):
        """defense-2(URLデコード照合・文脈限定)の前の基準値: 同じ検出器で エンコード回避を見逃し、部分一致の誤検知があった。"""
        path = os.path.join(os.path.dirname(bm.DEFENSE_BASELINE_PATH), "defense_signatures.before-defense-2.json")
        with open(path, encoding="utf-8") as f:
            old = json.load(f)
        det = {tuple(d) for d in old["detections"]}
        self.assertNotIn(("SQL_INJECTION", "sqli-union-urlencoded"), det)
        self.assertIn(("SCANNER", "scanner-benign-zapier"), det)
        self.assertEqual((old["metrics"]["total"]["fp"], old["metrics"]["total"]["fn"]), (5, 5))


class AttackBenchmarkTest(unittest.TestCase):
    def test_truth_covers_every_sensitive_path_header_and_labels_traps(self):
        from core.settings import SECURITY_HEADERS, SENSITIVE_PATHS
        doc = bm.load_truth(bm.ATTACK_TRUTH_PATH)
        loc = {(c["rule_id"], c["location"]): c["expected"] for c in doc["cases"]}
        for label in ("main", "catchall", "held"):
            for path in SENSITIVE_PATHS:
                self.assertIn(("SENSITIVE_PATH", f"{label} {path}"), loc)
        for label in ("main", "held"):
            for h in SECURITY_HEADERS:
                self.assertIn(("MISSING_HEADER", f"{label} {h}"), loc)
        self.assertTrue(all(v == "not_vulnerable" for (r, l), v in loc.items() if l.startswith("catchall ")))
        self.assertEqual({r for r, _ in loc}, {"OPEN_PORT", "SENSITIVE_PATH", "MISSING_HEADER", "COOKIE_FLAG", "TECH"})

    def test_run_matches_the_saved_baseline_and_is_deterministic(self):
        with open(bm.ATTACK_BASELINE_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        cur = bm.benchmark_attack(runs=2)
        self.assertTrue(cur["stable"])
        self.assertEqual(bm.compare(saved, cur), {"per_rule": {}, "added_detections": [], "removed_detections": []},
                         "ATTACK偵察の検出品質が基準値から変わりました。意図した変更なら差を記載して"
                         "`python tools/benchmark.py attack --runs 3 --save-baseline testlab/baselines/attack_recon.json`で更新")
        self.assertEqual(cur["metrics"]["total"]["unexamined"], 0)

    def test_fixes_hold_on_heldout_cases_and_known_weakness_is_recorded(self):
        with open(bm.ATTACK_BASELINE_PATH, encoding="utf-8") as f:
            doc = json.load(f)
        det = {tuple(d) for d in doc["detections"]}
        for key in (("SENSITIVE_PATH", "held /.env"), ("TECH", "held Apache"), ("TECH", "held Express.js"),
                    ("TECH", "main Nginx"), ("COOKIE_FLAG", "held b Missing Secure flag"),
                    ("COOKIE_FLAG", "held b Missing HttpOnly flag"), ("COOKIE_FLAG", "main sid Missing Secure flag")):
            self.assertIn(key, det)
        for key in (("SENSITIVE_PATH", "held /admin"), ("SENSITIVE_PATH", "held /robots.txt"),
                    ("SENSITIVE_PATH", "catchall /.env"), ("SENSITIVE_PATH", "main /api"),
                    ("COOKIE_FLAG", "held a Missing HttpOnly flag"), ("COOKIE_FLAG", "held a Missing Secure flag"),
                    ("COOKIE_FLAG", "main pref Missing HttpOnly flag"), ("OPEN_PORT", "tcp:closed_a")):
            self.assertNotIn(key, det)
        total = doc["metrics"]["total"]
        self.assertEqual((total["fn"], total["fp"]), (0, 2))
        # 残した弱点: 本文に「WordPress/Drupalは使っていない」とあるだけでも技術名の言及として拾う(キーワード照合)
        self.assertIn(("TECH", "main WordPress"), det)
        self.assertIn(("TECH", "main Drupal"), det)

    def test_pre_fix_baseline_is_kept_as_history(self):
        path = os.path.join(os.path.dirname(bm.ATTACK_BASELINE_PATH), "attack_recon.before-fixes.json")
        with open(path, encoding="utf-8") as f:
            old = json.load(f)
        det = {tuple(d) for d in old["detections"]}
        self.assertNotIn(("TECH", "main Nginx"), det)                  # ヘッダーをdict reprで照合していたため見逃し
        self.assertIn(("SENSITIVE_PATH", "catchall /.env"), det)       # soft-404を実在として報告
        self.assertIn(("COOKIE_FLAG", "main pref Missing HttpOnly flag"), det)   # HttpOnlyの大文字小文字
        self.assertGreater(old["metrics"]["total"]["fp"], 50)

    def test_prober_marks_exposure_by_status_and_reports_soft_404(self):
        from testlab.fixtures.attack_benchmark import AttackLab
        from tools.web_prober import WebProber
        with AttackLab() as lab:
            res = WebProber(profile="aggressive").probe(lab.main.base_url)
            by = {f["path"]: f for f in res["found_paths"]}
            self.assertTrue(by["/.env"]["exposed"])
            self.assertEqual((by["/api"]["status"], by["/api"]["exposed"]), (301, False))
            self.assertIsNone(res["soft_404"])
            res = WebProber(profile="aggressive").probe(lab.catchall.base_url)
            self.assertEqual(res["found_paths"], [])
            self.assertEqual(res["soft_404"]["status"], 200)


class CompareTest(unittest.TestCase):
    def test_compare_reports_changes_without_judging(self):
        with open(bm.BASELINE_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        cur = copy.deepcopy(saved)
        cur["detections"].remove(["IDOR", "GET /order id"])
        cur["metrics"]["per_rule"]["IDOR"].update(fp=0, tn=8, precision=1.0)
        d = bm.compare(saved, cur)
        self.assertEqual(d["removed_detections"], [["IDOR", "GET /order id"]])
        self.assertEqual(d["per_rule"]["IDOR"]["fp"], [1, 0])
        self.assertEqual(d["added_detections"], [])


if __name__ == "__main__":
    unittest.main()
