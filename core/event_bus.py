"""
core/event_bus.py — スレッドセーフなUI更新キュー

バックグラウンドスレッドからGUIスレッドへイベントを安全に渡す。
"""

import queue
from dataclasses import dataclass, field
from typing import Any


# ─── イベント種別定数 ──────────────────────────────────────
LOG    = "log"      # システムログ（左下ログペイン）
OUTPUT = "output"   # AI出力テキスト（右ペイン、tag付き）
STEP   = "step"     # ステップ進捗更新 {idx, state}
ALERT  = "alert"    # 防御アラート {severity, message, time}
STATS  = "stats"    # 検出統計更新 {CRITICAL:n, HIGH:n, ...}
STATUS = "status"   # ステータスバーテキスト更新
DONE   = "done"     # 処理完了 {error: bool}
CLEAR  = "clear"    # 出力エリアをクリア


@dataclass
class Event:
    kind: str
    payload: Any = field(default=None)


class EventBus:
    """単一のqueueを持つシンプルなイベントバス。"""

    def __init__(self):
        self._q: queue.Queue[Event] = queue.Queue()

    # ── Publisher API ──────────────────────────────────────
    def emit(self, kind: str, payload: Any = None) -> None:
        self._q.put(Event(kind=kind, payload=payload))

    def log(self, msg: str) -> None:
        self.emit(LOG, msg)

    def output(self, text: str, tag: str = "") -> None:
        self.emit(OUTPUT, {"text": text, "tag": tag})

    def step(self, idx: int, state: str) -> None:
        self.emit(STEP, {"idx": idx, "state": state})

    def alert(self, severity: str, message: str, timestamp: str = "") -> None:
        self.emit(ALERT, {"severity": severity, "message": message, "time": timestamp})

    def stats(self, counts: dict) -> None:
        self.emit(STATS, counts)

    def status(self, msg: str) -> None:
        self.emit(STATUS, msg)

    def done(self, error: bool = False) -> None:
        self.emit(DONE, {"error": error})

    def clear(self) -> None:
        self.emit(CLEAR)

    # ── Consumer API ──────────────────────────────────────
    def drain(self, limit: int = 50) -> list[Event]:
        """最大 limit 件のイベントを非ブロッキングで取り出す。"""
        events = []
        for _ in range(limit):
            try:
                events.append(self._q.get_nowait())
            except queue.Empty:
                break
        return events

    def flush(self) -> None:
        """キューを空にする。"""
        while not self._q.empty():
            try:
                self._q.get_nowait()
            except queue.Empty:
                break
