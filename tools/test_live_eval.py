"""tools/live_eval.py(実LLM評価ハーネス)の非LLM部分の固定試験: ヒント除去・行照合・呼出し上限。"""
import ast
import json
import unittest

from tools import live_eval as le


class StripHintsTest(unittest.TestCase):
    def setUp(self):
        with open(le.os.path.join(le.ROOT, "samples", "target_code.py"), encoding="utf-8") as f:
            self.src = f.read()
        self.out = le.strip_hints(self.src)

    def test_all_comments_and_docstrings_are_removed_but_lines_do_not_move(self):
        self.assertEqual(self.src.count("\n"), self.out.count("\n"))
        self.assertNotIn("#", self.out)
        self.assertNotIn("BUG", self.out)
        self.assertNotIn("INTENTIONALLY", self.out)
        tree = ast.parse(self.out)                          # 構文は保たれる
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.Module)):
                self.assertIsNone(ast.get_docstring(node))

    def test_function_definitions_stay_on_the_labelled_lines(self):
        names = {n.name: n.lineno for n in ast.parse(self.out).body if isinstance(n, ast.FunctionDef)}
        with open(le.TRUTH, encoding="utf-8") as f:
            truth = json.load(f)
        self.assertEqual(names["authenticate"], 54)
        self.assertEqual(names["process_payment_request"], 251)
        for v in truth["vulnerabilities"]:
            self.assertLess(v["lines"][0], v["lines"][1])


class MatchTest(unittest.TestCase):
    TRUTH = {"match_margin_lines": 1, "vulnerabilities": [
        {"id": "A", "lines": [10, 20]}, {"id": "B", "lines": [30, 40]}]}

    def test_line_formats_and_margin(self):
        self.assertEqual(le.line_numbers("12"), [12])
        self.assertEqual(le.line_numbers("12-14"), [12, 13, 14])
        self.assertEqual(le.line_numbers("app.py:5, 7"), [5, 7])
        self.assertEqual(le.line_numbers(""), [])

    def test_hits_extras_and_no_overclaim_for_missing_lines(self):
        findings = [{"location": "15", "description": "x"}, {"location": "21", "description": "y"},
                    {"location": "99", "description": "z"}, {"location": "", "description": "no lines"}]
        hit, extra = le.match(findings, self.TRUTH)
        self.assertEqual(sorted(hit), ["A"])                # 21はA(10-20)の余白1行内
        self.assertEqual(len(hit["A"]), 2)
        self.assertEqual([e["description"] for e in extra], ["z", "no lines"])   # 位置不明は的中に数えない


class DecoyTest(unittest.TestCase):
    TRUTH = {"match_margin_lines": 1,
             "vulnerabilities": [{"id": "A", "lines": [10, 20]}],
             "decoys": [{"id": "D1", "lines": [30, 40]}, {"id": "D2", "lines": [50, 60]}]}

    def test_decoy_hits_are_counted_only_when_no_vulnerability_overlaps(self):
        findings = [{"location": "35", "description": "x"},            # D1
                    {"location": "21", "description": "y"},            # Aの余白内(欠陥の指摘)。decoyに数えない
                    {"location": "29", "description": "z"},            # D1の余白内
                    {"location": "99", "description": "w"},            # どちらでもない
                    {"location": "", "description": "no lines"}]
        self.assertEqual(le.match_decoys(findings, self.TRUTH), {"D1": ["x", "z"]})
        self.assertEqual(le.match_decoys([], self.TRUTH), {})
        self.assertEqual(le.match_decoys([{"location": "35"}], {"vulnerabilities": [], "decoys": []}), {})   # decoy無しの正解データ(v1)


class DecoySameClassTest(unittest.TestCase):
    TRUTH = {"match_margin_lines": 0, "vulnerabilities": [],
             "decoys": [{"id": "D2", "lines": [10, 20], "class_cwes": ["CWE-78"], "class_keywords": ["command injection", "コマンドインジェクション"]}]}

    def test_only_the_lookalike_class_counts_as_a_same_class_false_positive(self):
        f = lambda desc, rule="": {"location": "15", "description": desc, "rule_id": rule}      # noqa: E731
        same = [f("OSコマンドインジェクション"), f("x", "CWE-78"), f("Command Injection via shell")]
        other = [f("所有権の検証がない(IDOR)", "CWE-639"), f("競合状態")]
        self.assertEqual(len(le.match_decoys(same + other, self.TRUTH)["D2"]), 5)                  # 行範囲だけなら全て
        self.assertEqual(len(le.match_decoys(same + other, self.TRUTH, same_class_only=True)["D2"]), 3)   # 同種だけ
        self.assertEqual(le.match_decoys(other, self.TRUTH, same_class_only=True), {})

    def test_criteria_do_not_match_function_names_negations_or_word_fragments(self):
        """過去の不具合: `literal_eval`にeval、`Resource`にrce、本文の否定文にキーワードが一致した。判定はCWEとタイトルの単語一致だけ。"""
        d = {"id": "D5", "lines": [1, 9], "class_cwes": ["CWE-95"],
             "class_keywords": ["eval()", "rce", "code execution", "コード実行"]}
        no = [{"description": "ast.literal_eval のリソース爆増による枯渇", "rule_id": "CWE-400"},
              {"description": "Resource Exhaustion in parse_filter", "rule_id": "CWE-400"},
              {"description": "DoS", "rule_id": "CWE-400", "analysis": "これは code execution ではない(コード実行は不可)"},
              {"description": "x", "rule_id": "CWE-950"}]                                  # CWE-95 の前方一致で CWE-950 を拾わない
        yes = [{"description": "RCE via eval()", "rule_id": ""}, {"description": "x", "rule_id": "CWE-95"},
               {"description": "任意のコード実行", "rule_id": ""}]
        for f in no:
            self.assertFalse(le._is_same_class(f, d), f)
        for f in yes:
            self.assertTrue(le._is_same_class(f, d), f)


class SampleV2Test(unittest.TestCase):
    def setUp(self):
        with open(le.TRUTHS["v2"], encoding="utf-8") as f:
            self.truth = json.load(f)
        with open(le.os.path.join(le.ROOT, self.truth["source"]), encoding="utf-8") as f:
            self.src = f.read()

    def test_truth_matches_the_markers_and_sections_do_not_overlap(self):
        import re
        marks = {}
        for i, line in enumerate(self.src.splitlines(), 1):
            m = re.match(r"# \[([VD]\d) (start|end)\]", line)
            if m:
                marks.setdefault(m.group(1), {})[m.group(2)] = i
        listed = {e["id"]: e["lines"] for e in self.truth["vulnerabilities"] + self.truth["decoys"]}
        self.assertEqual(listed, {k: [v["start"], v["end"]] for k, v in marks.items()})    # マーカーと正解が一致
        spans = sorted(listed.values())
        margin = self.truth["match_margin_lines"]
        for (a0, a1), (b0, b1) in zip(spans, spans[1:]):
            self.assertLess(a1 + margin, b0 - margin, (a1, b0))                              # 余白を足しても隣の区画に届かない
        self.assertEqual(len(self.truth["vulnerabilities"]), 8)
        self.assertEqual(len(self.truth["decoys"]), 6)
        for d in self.truth["decoys"]:
            self.assertTrue(d["class_cwes"] and d["class_keywords"], d["id"])                   # 同種の判定基準がある

    def test_stripped_version_keeps_lines_and_hides_every_hint(self):
        out = le.strip_hints(self.src)
        self.assertEqual(self.src.count("\n"), out.count("\n"))
        for hint in ("decoy", "[V1", "[D1", "安全(", "欠陥", "SSRF", "オープンリダイレクト", "競合:"):
            self.assertNotIn(hint, out)
        ast.parse(out)
        names = {n.name: n.lineno for n in ast.parse(out).body if isinstance(n, ast.FunctionDef)}
        for v in self.truth["vulnerabilities"]:
            self.assertTrue(any(v["lines"][0] <= ln <= v["lines"][1] for ln in names.values()), v["id"])   # 各欠陥の区画に関数がある


class InvalidRunTest(unittest.TestCase):
    def test_empty_llm_output_is_invalid_not_a_zero_recall(self):
        """レート制限(429)などで応答が空の回を再現率0.0として記録すると、『見つけられなかった』と誤読される。"""
        from unittest import mock
        fake = {"state": "partial", "errors": ["AI推論が空応答でした"], "n_findings": 0, "hit": {}, "unlabeled": [],
                "decoy_hits": {}, "decoy_same_class_hits": {}, "decoy_findings": [], "llm_calls": 1,
                "chars_in": 100, "chars_out": 0, "elapsed_s": 1.0}
        good = dict(fake, state="completed", n_findings=2, chars_out=500, errors=[], hit={"V1": ["x"]})
        with mock.patch.object(le, "run_audit_once", side_effect=[fake, good]):
            out = le.evaluate("m", 2, "speed", 5, sample="v2")
        self.assertEqual(out["recall_per_run"], [None, round(1 / 8, 3)])
        self.assertEqual((out["runs_invalid"], out["runs_with_findings"]), (1, 1))
        self.assertEqual(out["per_vuln_hits"]["V1"], 1)


class CallLimitTest(unittest.TestCase):
    def test_limit_stops_before_the_call_is_sent(self):
        llm = le.CountingLLM(base_url="http://127.0.0.1:9", api_key="x", model="m", timeout=1)
        llm.limit = 0
        llm.calls = 3
        llm.limit = 3
        with self.assertRaises(le.CallLimit):
            llm.complete([{"role": "user", "content": "hi"}])
        self.assertEqual(llm.calls, 3)                      # 上限到達後は送信前に止まり、数は増えない


if __name__ == "__main__":
    unittest.main()
