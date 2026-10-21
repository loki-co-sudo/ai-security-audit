"""
core/autonomy/budget.py — Run予算(リクエスト・時間・LLM)

設計: docs/AUTONOMOUS_PHASE_A_DESIGN.md §11.3 の三層。
  1. Run予算(リクエスト): 送信の唯一の真実は HttpTransport の計数。本クラスは二重計数せず、
     計数関数を受け取って残量を見る。
  2. Action上限(CapabilitySpec.max_requests)は情報用で、ここでは拒否に使わない。
  3. 実測消費: Action前後の計数の差を呼び出し側が記録する(snapshot)。
時間は壁時計(注入可能)、LLMは呼出前に予約して制限する(応答後の加算だけでは超過を防げない)。
"""

from __future__ import annotations
import threading
import time
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class BudgetDecision:
    ok: bool
    reason: str = ""


class BudgetLedger:
    def __init__(self, *, max_requests: int, request_counter: Callable[[], int],
                 deadline_seconds: float | None = None,
                 max_llm_calls: int | None = None,
                 max_llm_input_chars: int | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.max_requests = max_requests
        self._counter = request_counter
        self.deadline_seconds = deadline_seconds
        self.max_llm_calls = max_llm_calls
        self.max_llm_input_chars = max_llm_input_chars   # 1回あたりの入力文字数の上限
        self._clock = clock
        self._t0: float | None = None
        self._lock = threading.Lock()
        self._llm_calls = 0

    # ── リクエスト ──
    def requests_used(self) -> int:
        return int(self._counter())

    def requests_remaining(self) -> int:
        return max(0, self.max_requests - self.requests_used())

    # ── 時間 ──
    def start(self) -> None:
        if self._t0 is None:
            self._t0 = self._clock()

    def time_exhausted(self) -> bool:
        if self.deadline_seconds is None or self._t0 is None:
            return False
        return self._clock() - self._t0 >= self.deadline_seconds

    # ── LLM(呼出前に予約) ──
    @property
    def llm_calls_used(self) -> int:
        return self._llm_calls

    def llm_calls_remaining(self) -> int | None:
        if self.max_llm_calls is None:
            return None
        return max(0, self.max_llm_calls - self._llm_calls)

    def reserve_llm_call(self, input_chars: int = 0) -> BudgetDecision:
        """LLMを呼ぶ**前**に予約する。拒否された場合は呼んではならない(回数は消費しない)。"""
        with self._lock:
            if self.time_exhausted():
                return BudgetDecision(False, "budget.time_exhausted")
            if self.max_llm_calls is not None and self._llm_calls >= self.max_llm_calls:
                return BudgetDecision(False, "budget.llm_calls_exhausted")
            if self.max_llm_input_chars is not None and input_chars > self.max_llm_input_chars:
                return BudgetDecision(False, "budget.llm_input_too_large")
            self._llm_calls += 1
            return BudgetDecision(True)

    def snapshot(self) -> dict:
        return {"requests_used": self.requests_used(), "requests_max": self.max_requests,
                "llm_calls_used": self._llm_calls, "llm_calls_max": self.max_llm_calls}
