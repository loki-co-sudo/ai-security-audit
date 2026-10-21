"""現行WEB FUZZ経路(FuzzAgent)の特性化装置。

固定fixture・モックLLMで現行経路を実行し、後続のcapability化(docs/AUTONOMOUS_PHASE_A_DESIGN.md §11.5)
と比較できる観測結果を返す。FuzzAgent/WebFuzzerは変更しない。比較は結果の多重集合(Counter)で行う。
"""
from __future__ import annotations
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from unittest.mock import patch
from urllib.parse import urlparse

from agents.fuzz_agent import FuzzAgent
from core import config as _config
from core import event_bus as ev
from core.event_bus import EventBus

# FAST/STRONG共通のモック応答。プローブ生成は空JSON(=組込みプローブのみ)、トリアージは固定文面。
CANNED_TRIAGE = (
    "---VULN_START---\nNAME: Reflected XSS\nSEVERITY: HIGH\nCWE: CWE-79\nLINES: /search q\n"
    "SNIPPET:\n```\nx\n```\nATTACK:\nreflected\nFIX:\n```\nescape\n```\n---VULN_END---\n"
)


class MockLLM:
    """duck-typed LLMClient。受信したプロンプトを記録する。"""
    model = "mock-model"
    base_url = "http://mock.invalid"
    api_key = ""
    timeout = 1

    def __init__(self):
        self.stream_prompts: list[str] = []
        self.complete_prompts: list[str] = []

    @staticmethod
    def system(c): return {"role": "system", "content": c}
    @staticmethod
    def user(c): return {"role": "user", "content": c}
    @staticmethod
    def assistant(c): return {"role": "assistant", "content": c}

    def complete(self, messages):
        self.complete_prompts.append("\n".join(m["content"] for m in messages))
        return "{}"

    def stream(self, messages, on_chunk, on_done=None, on_error=None):
        self.stream_prompts.append("\n".join(m["content"] for m in messages))
        on_chunk(CANNED_TRIAGE)
        if on_done:
            on_done()
        return CANNED_TRIAGE


@dataclass
class Observation:
    result: dict
    requests: Counter
    stream_prompts: list = field(default_factory=list)
    done_count: int = 0
    result_count: int = 0
    error: bool = False

    @property
    def state(self) -> str:
        return self.result.get("state", "")

    def finding_keys(self) -> Counter:
        return Counter((f["rule_id"], f["location"], f["severity"], f["verification_state"])
                       for f in self.result.get("findings", []))

    def coverage_keys(self) -> Counter:
        return Counter((c["target_ref"], c["parameter"], c["rule_id"], c["status"], c["auth_context"])
                       for c in self.result.get("coverage", []))

    def _summary(self) -> str:
        return self.stream_prompts[0] if self.stream_prompts else ""

    def injection_points(self) -> Counter:
        """トリアージ入力のサマリーから (METHOD, param, パス) を取り出す。"""
        pts = re.findall(r"^  (GET|POST) (\S+) \(\w+\) (\S+)$", self._summary(), re.M)
        return Counter((m, p, urlparse(u).path) for m, p, u in pts)

    def anomaly_keys(self) -> Counter:
        """トリアージ入力のサマリーから観測された異常の (category, param, パス) を取り出す。"""
        found = re.findall(r"- category=(\S+) param=(\S+) url=(\S+) ", self._summary())
        return Counter((c, p, urlparse(u).path) for c, p, u in found)

    def total_requests(self) -> int:
        return sum(self.requests.values())


def run_legacy(server, *, max_requests: int = 200, max_pages: int = 20,
               profile: str = "aggressive", timeout: float = 60) -> Observation:
    """現行のFuzzAgentを実行して観測結果を返す(送信先はserverのみ)。"""
    server.requests.clear()
    bus, llm = EventBus(), MockLLM()
    agent = FuzzAgent(bus, llm)
    agent.set_effort_override("speed")   # 検証パスなし(LLM呼出を決定論的に保つ)
    out = Observation(result={}, requests=Counter())
    # 利用者のconfig.json(FASTモデル・allowed_targets等)に結果が左右されないよう既定値に固定する。
    with patch.dict(_config._cfg, dict(_config._DEFAULTS), clear=True), \
         patch.object(FuzzAgent, "_save_investigation", lambda *a, **k: None), \
         patch.object(FuzzAgent, "_record_telemetry", lambda *a, **k: None):
        agent.start(target=server.base_url, profile=profile,
                    max_requests=max_requests, max_pages=max_pages)
        t0, done = time.time(), False
        while time.time() - t0 < timeout and not done:
            for e in bus.drain(limit=200):
                if e.kind == ev.RESULT:
                    out.result = e.payload
                    out.result_count += 1
                elif e.kind == ev.DONE:
                    out.done_count += 1
                    out.error = bool(e.payload and e.payload.get("error"))
                    done = True
            time.sleep(0.02)
        agent._thread.join(timeout=5)
    out.requests = server.request_counter()
    out.stream_prompts = list(llm.stream_prompts)
    if not done:
        raise TimeoutError("FuzzAgentがDONEを送らなかった")
    return out
