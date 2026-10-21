"""LLM呼出前の予算ゲート(BaseAgent._llm_gate / LLMClient.max_tokens)の固定試験。実LLM・外部通信なし。"""
import types
import unittest
from unittest.mock import patch

from agents.base_agent import BaseAgent
from core.autonomy.budget import BudgetLedger, LLMGate
from core import config as _config
from core.event_bus import EventBus
from core.llm_client import LLMClient

VERIFIED = "---VULN_START---\nNAME: x\nSEVERITY: LOW\n---VULN_END---\n"


class RecordingLLM:
    """呼出を記録する duck-typed クライアント。max_tokens/usage_out の受け渡しも記録する。"""
    model = "m"
    base_url = ""
    api_key = ""
    timeout = 1

    def __init__(self, usage=None):
        self.calls: list[dict] = []
        self.usage = usage

    @staticmethod
    def system(c): return {"role": "system", "content": c}
    @staticmethod
    def user(c): return {"role": "user", "content": c}

    def complete(self, messages, max_tokens=None, usage_out=None):
        self.calls.append({"kind": "complete", "max_tokens": max_tokens, "chars": sum(len(m["content"]) for m in messages)})
        if usage_out is not None and self.usage:
            usage_out.update(self.usage)
        return "reply"

    def stream(self, messages, on_chunk, on_done=None, on_error=None, max_tokens=None):
        self.calls.append({"kind": "stream", "max_tokens": max_tokens, "chars": sum(len(m["content"]) for m in messages)})
        on_chunk(VERIFIED)
        return VERIFIED


class _Agent(BaseAgent):
    def run(self, **kw):
        pass


def _agent(llm, **ledger_kw):
    a = _Agent(EventBus(), llm)
    ledger = BudgetLedger(max_requests=1, request_counter=lambda: 0, **ledger_kw)
    ledger.start()
    return a, ledger


class AgentGateTest(unittest.TestCase):
    def setUp(self):
        # 利用者のconfig.json(FASTモデル等)に左右されないよう既定値に固定する
        p = patch.dict(_config._cfg, dict(_config._DEFAULTS), clear=True)
        p.start()
        self.addCleanup(p.stop)

    def test_without_gate_behavior_is_unchanged(self):
        llm = RecordingLLM()
        a = _Agent(EventBus(), llm)
        self.assertEqual(a._complete_llm([llm.user("hi")]), "reply")
        self.assertEqual(a._stream_llm([llm.user("hi")]), VERIFIED)
        # 従来どおり max_tokens/usage_out を渡さない
        self.assertEqual([c["max_tokens"] for c in llm.calls], [None, None])
        self.assertEqual(a._llm_denials, [])

    def test_calls_are_refused_before_reaching_the_llm(self):
        llm = RecordingLLM()
        a, ledger = _agent(llm, max_llm_calls=2)
        a._llm_gate = LLMGate(ledger)
        self.assertEqual(a._complete_llm([llm.user("1")]), "reply")
        self.assertEqual(a._stream_llm([llm.user("2")]), VERIFIED)
        self.assertEqual(a._complete_llm([llm.user("3")]), "")          # 拒否: 空応答
        self.assertEqual(a._stream_llm([llm.user("4")]), "")
        self.assertEqual(len(llm.calls), 2)                              # LLMには届いていない
        self.assertEqual(a._llm_denials, ["budget.llm_calls_exhausted"] * 2)
        self.assertEqual(ledger.llm_calls_used, 2)

    def test_oversized_input_and_deadline_are_refused(self):
        llm = RecordingLLM()
        t = [0.0]
        ledger = BudgetLedger(max_requests=1, request_counter=lambda: 0, max_llm_input_chars=50,
                              deadline_seconds=5, clock=lambda: t[0])
        ledger.start()
        a = _Agent(EventBus(), llm)
        a._llm_gate = LLMGate(ledger)
        self.assertEqual(a._complete_llm([llm.user("x" * 500)]), "")
        self.assertEqual(a._llm_denials, ["budget.llm_input_too_large"])
        self.assertEqual(llm.calls, [])
        self.assertEqual(ledger.llm_calls_used, 0)                       # 拒否は回数を消費しない
        t[0] = 6.0
        self.assertEqual(a._complete_llm([llm.user("ok")]), "")
        self.assertEqual(a._llm_denials[-1], "budget.time_exhausted")

    def test_verification_samples_count_against_the_same_budget(self):
        llm = RecordingLLM()
        a, ledger = _agent(llm, max_llm_calls=2)
        a._llm_gate = LLMGate(ledger)
        out = a._verify_findings("evidence", "DRAFT", samples=5)         # 5回走らせようとする
        self.assertEqual(len(llm.calls), 2)                              # 予算の2回で止まる
        self.assertEqual(a._llm_denials.count("budget.llm_calls_exhausted"), 3)
        self.assertIn("_START---", out)                                  # 得られた検証結果は使う

    def test_verification_all_refused_keeps_the_draft(self):
        llm = RecordingLLM()
        a, ledger = _agent(llm, max_llm_calls=0)
        a._llm_gate = LLMGate(ledger)
        self.assertEqual(a._verify_findings("e", "DRAFT", samples=2), "DRAFT")
        self.assertEqual(llm.calls, [])

    def test_max_output_tokens_passed_only_when_configured(self):
        llm = RecordingLLM()
        a, ledger = _agent(llm)
        a._llm_gate = LLMGate(ledger, max_output_tokens=321)
        a._complete_llm([llm.user("a")])
        a._stream_llm([llm.user("b")])
        self.assertEqual([c["max_tokens"] for c in llm.calls], [321, 321])

    def test_unknown_usage_is_not_counted_as_zero(self):
        llm = RecordingLLM(usage=None)
        a, ledger = _agent(llm)
        a._llm_gate = LLMGate(ledger)
        a._complete_llm([llm.user("a")])
        a._stream_llm([llm.user("b")])                                   # ストリーミングは不明
        s = ledger.llm_usage_summary()
        self.assertEqual((s["calls"], s["calls_with_unknown_usage"], s["estimated_cost"]),
                         (2, 2, "unknown"))
        llm2 = RecordingLLM(usage={"input_tokens": 10, "output_tokens": 4})
        a2, l2 = _agent(llm2)
        a2._llm_gate = LLMGate(l2)
        a2._complete_llm([llm2.user("a")])
        s2 = l2.llm_usage_summary()
        self.assertEqual((s2["input_tokens_known"], s2["output_tokens_known"],
                          s2["calls_with_unknown_usage"]), (10, 4, 0))

    def test_llm_exception_does_not_leak_a_reservation_as_known_usage(self):
        class Boom(RecordingLLM):
            def complete(self, messages, max_tokens=None, usage_out=None):
                raise RuntimeError("down")
        llm = Boom()
        a, ledger = _agent(llm)
        a._llm_gate = LLMGate(ledger)
        self.assertEqual(a._complete_llm([llm.user("a")]), "")
        s = ledger.llm_usage_summary()
        self.assertEqual((s["calls"], s["calls_with_unknown_usage"], s["input_tokens_known"]), (1, 1, 0))


class _FakeCompletions:
    def __init__(self, response):
        self.kwargs = None
        self.response = response

    def create(self, **kw):
        self.kwargs = kw
        return self.response


def _client_with(response):
    c = LLMClient("http://127.0.0.1:1/v1", "dummy-key", "m", 1)
    fake = _FakeCompletions(response)
    c._client = types.SimpleNamespace(chat=types.SimpleNamespace(completions=fake))
    return c, fake


class ClientTest(unittest.TestCase):
    def _resp(self, usage=None):
        msg = types.SimpleNamespace(content="hello")
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)], usage=usage)

    def test_complete_sends_no_max_tokens_by_default(self):
        c, fake = _client_with(self._resp())
        self.assertEqual(c.complete([{"role": "user", "content": "x"}]), "hello")
        self.assertNotIn("max_tokens", fake.kwargs)
        c.complete([{"role": "user", "content": "x"}], max_tokens=77)
        self.assertEqual(fake.kwargs["max_tokens"], 77)

    def test_complete_reports_usage_only_when_present(self):
        c, _ = _client_with(self._resp(types.SimpleNamespace(prompt_tokens=12, completion_tokens=3)))
        out = {}
        c.complete([{"role": "user", "content": "x"}], usage_out=out)
        self.assertEqual(out, {"input_tokens": 12, "output_tokens": 3})
        c2, _ = _client_with(self._resp(None))
        out2 = {}
        c2.complete([{"role": "user", "content": "x"}], usage_out=out2)
        self.assertEqual(out2, {})                                       # 取得不能は空(0にしない)

    def test_stream_max_tokens_passthrough(self):
        chunk = types.SimpleNamespace(choices=[types.SimpleNamespace(delta=types.SimpleNamespace(content="a"))])
        c, fake = _client_with([chunk])
        got = []
        c.stream([{"role": "user", "content": "x"}], on_chunk=got.append)
        self.assertNotIn("max_tokens", fake.kwargs)
        c.stream([{"role": "user", "content": "x"}], on_chunk=got.append, max_tokens=9)
        self.assertEqual(fake.kwargs["max_tokens"], 9)
        self.assertTrue(fake.kwargs["stream"])


if __name__ == "__main__":
    unittest.main()
