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
