"""tools/benchmark.py(P2.1)の固定試験。集計器は手計算できる予測集合で検証する。"""
import copy
import json
import os
import tempfile
import unittest

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

    def test_known_weaknesses_are_visible_in_the_baseline(self):
        """基準値は「現行の検出が誤りやすい罠」でFPが出ることを示している(改善の余地の根拠)。"""
        with open(bm.BASELINE_PATH, encoding="utf-8") as f:
            m = json.load(f)["metrics"]["per_rule"]
        self.assertGreater(m["IDOR"]["fp"], 0)          # 公開/閲覧者別ページを長さ類似だけでIDOR候補にする
        self.assertGreater(m["SSTI"]["fp"], 0)          # 偶然の"49"
        self.assertGreater(m["XSS"]["fp"], 0)           # text/plainの反射
        self.assertEqual(m["SQLI"]["fp"] + m["TRAVERSAL"]["fp"], 0)   # 静的な罠は正しく無視される

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


class CompareTest(unittest.TestCase):
    def test_compare_reports_changes_without_judging(self):
        with open(bm.BASELINE_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        cur = copy.deepcopy(saved)
        cur["detections"].remove(["SSTI", "GET /results q"])
        cur["metrics"]["per_rule"]["SSTI"].update(fp=0, tn=2, precision=1.0)
        d = bm.compare(saved, cur)
        self.assertEqual(d["removed_detections"], [["SSTI", "GET /results q"]])
        self.assertEqual(d["per_rule"]["SSTI"]["fp"], [1, 0])
        self.assertEqual(d["added_detections"], [])


if __name__ == "__main__":
    unittest.main()
