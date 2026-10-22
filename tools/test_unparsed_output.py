"""LLMが形式(所見マーカー)を守らず、実質のある分析を出したのに所見0件・成功に見える問題の固定試験。

背景: 小型モデル(ministral-8b)の出力が1.2万文字あるのに、---VULN_START--- が無く「0 vulnerabilities detected」・completedになった(2026-10-23)。
"""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from agents.base_agent import unparsed_output_note
from core import config
from core.event_bus import EventBus
from tools.fuzz_characterization import MockLLM

PROSE = "このコードには複数の問題があります。" * 40            # 長い説明文(マーカー無し)
BLOCK = ("---VULN_START---\nNAME: SQL injection\nSEVERITY: HIGH\nCWE: CWE-89\nLINES: 3\nSNIPPET:\n```\nx\n```\n"
         "ATTACK:\ny\nFIX:\n```\nz\n```\n---VULN_END---")


class ProseLLM(MockLLM):
    text = PROSE

    def reply_for(self, prompt):
        return self.text


class HelperTest(unittest.TestCase):
    def test_only_long_marker_free_output_is_flagged(self):
        self.assertEqual(unparsed_output_note(""), "")
        self.assertEqual(unparsed_output_note("脆弱性は見つかりませんでした。"), "")           # 短い「問題なし」は対象外
        self.assertEqual(unparsed_output_note(PROSE + BLOCK), "")                           # マーカーがあれば対象外
        broken = PROSE + "---VULN_START---\nNAME: x\nSEVERITY: HIGH\n(ENDが無い)"                  # STARTだけの壊れたブロック
        self.assertNotEqual(unparsed_output_note(broken), "")                                # 取り込めていないので注記する
        self.assertEqual(unparsed_output_note(PROSE + "---THREAT_START---x---THREAT_END---"), "")
        self.assertNotEqual(unparsed_output_note(PROSE + "---VULN_START---x---THREAT_END---"), "")   # 種類が食い違うブロックは完全ではない
        self.assertIn("所見マーカー", unparsed_output_note(PROSE))
        self.assertEqual(unparsed_output_note("a" * 399), "")
        self.assertNotEqual(unparsed_output_note("a" * 400), "")


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.src = os.path.join(self.d, "app.py")
        with open(self.src, "w", encoding="utf-8") as f:
            f.write("import os\ndef run(x):\n    os.system(x)\n")

    def run_agent(self, cls, llm):
        agent = cls(EventBus(), llm)
        with mock.patch.object(cls, "_save_investigation", lambda *a, **k: None), \
             mock.patch.object(cls, "_record_telemetry", lambda *a, **k: None), \
             mock.patch.dict(config._cfg, {**config._DEFAULTS, "effort": "speed", "save_evidence": False}, clear=True):
            agent._safe_run(path=self.src)
        return agent._last_scan_result

    def engines(self):
        from agents.audit_agent import AuditAgent
        from agents.langgraph_audit_agent import LangGraphAuditAgent
        return (AuditAgent, LangGraphAuditAgent)

    def test_long_output_without_markers_is_partial_in_both_engines(self):
        for cls in self.engines():
            res = self.run_agent(cls, ProseLLM())
            self.assertEqual(res.state, "partial", cls.__name__)
            self.assertEqual(res.findings, [])
            self.assertTrue(any("所見マーカー" in e for e in res.errors), res.errors)

    def test_marker_output_and_a_short_no_issue_answer_stay_completed(self):
        for cls in self.engines():
            ok = ProseLLM()
            ok.text = BLOCK
            res = self.run_agent(cls, ok)
            self.assertEqual((res.state, len(res.findings) >= 1), ("completed", True), cls.__name__)
            short = ProseLLM()
            short.text = "脆弱性は見つかりませんでした。"
            self.assertEqual(self.run_agent(cls, short).state, "completed", cls.__name__)


class OtherAgentsTest(unittest.TestCase):
    def test_fuzz_flags_it_only_when_signals_exist(self):
        from agents.fuzz_agent import FuzzAgent
        fuzzer = mock.Mock()
        fuzzer.transport.req_count, fuzzer.max_requests = 1, 100
        agent = FuzzAgent(EventBus(), MockLLM())
        st, errs = agent._determine_state(fuzzer, triage_ran=True, triage_text=PROSE, had_signals=True)
        self.assertEqual(st, "partial")
        self.assertTrue(any("所見マーカー" in e for e in errs))
        st, errs = agent._determine_state(fuzzer, triage_ran=True, triage_text=PROSE, had_signals=False)
        self.assertEqual((st, errs), ("completed", []))                                     # 兆候が無ければ「問題なし」の説明で良い

    def test_recon_flags_it(self):
        from agents.recon_agent import ReconAgent
        agent = ReconAgent(EventBus(), MockLLM())
        self.assertEqual(agent._determine_state(triage_text=PROSE, host_resolved=True)[0], "partial")
        self.assertEqual(agent._determine_state(triage_text=BLOCK, host_resolved=True)[0], "completed")

    def test_defense_only_adds_a_note_because_signature_alerts_are_the_primary_detection(self):
        from agents.monitor_agent import MonitorAgent
        agent = MonitorAgent(EventBus(), MockLLM())
        st, errs = agent._determine_state(watch_error=None, analyses=[PROSE])
        self.assertEqual(st, "completed")                                                   # 状態は変えない
        self.assertTrue(any("脅威マーカー" in e for e in errs), errs)
        self.assertEqual(agent._determine_state(watch_error=None, analyses=["---THREAT_START---x---THREAT_END---" + PROSE])[1], [])


if __name__ == "__main__":
    unittest.main()
