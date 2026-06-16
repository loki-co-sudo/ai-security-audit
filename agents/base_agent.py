"""
agents/base_agent.py — エージェント抽象基底クラス
"""

from __future__ import annotations
import threading
from abc import ABC, abstractmethod
from datetime import datetime
from core.event_bus import EventBus
import core.event_bus as ev
from core.llm_client import LLMClient


class BaseAgent(ABC):
    """全エージェントが継承する基底クラス。"""

    def __init__(self, bus: EventBus, llm: LLMClient):
        self.bus  = bus
        self.llm  = llm
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ── ライフサイクル ─────────────────────────────────────
    def start(self, **kwargs) -> None:
        """バックグラウンドスレッドで run() を起動する。"""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._safe_run,
            kwargs=kwargs,
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """停止シグナルを送信する。run() 内で is_stopped() を確認して終了する。"""
        self._stop_event.set()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def _safe_run(self, **kwargs) -> None:
        try:
            self.run(**kwargs)
        except Exception as e:
            self._log(f"[AGENT ERROR] {e}")
            self.bus.done(error=True)

    @abstractmethod
    def run(self, **kwargs) -> None:
        """サブクラスが実装するメイン処理。バックグラウンドスレッドで実行される。"""

    # ── Event Bus ヘルパー ─────────────────────────────────
    def _log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.bus.log(f"[{ts}] {msg}")

    def _out(self, text: str, tag: str = "") -> None:
        self.bus.output(text, tag)

    def _step(self, idx: int, state: str) -> None:
        self.bus.step(idx, state)

    def _status(self, msg: str) -> None:
        self.bus.status(msg)

    def _alert(self, severity: str, message: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.bus.alert(severity, message, ts)

    def _stats(self, counts: dict) -> None:
        self.bus.stats(counts)

    def _done(self, error: bool = False) -> None:
        self.bus.done(error)

    # ── LLM ヘルパー ──────────────────────────────────────
    def _stream_llm(self, messages: list[dict]) -> str:
        """LLMをストリーミングし、各チャンクを OUTPUT イベントで流す。"""
        return self.llm.stream(
            messages=messages,
            on_chunk=lambda chunk: self._out(chunk),
            on_error=lambda e: self._out(f"\n[ LLM ERROR ] {e}\n", "critical"),
        )

    def _complete_llm(self, messages: list[dict]) -> str:
        """LLMを非ストリーミングで呼び出す（短い補助的な推論に使用）。"""
        try:
            return self.llm.complete(messages)
        except Exception as e:
            self._log(f"LLM error: {e}")
            return ""
