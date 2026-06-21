"""
agents/base_agent.py — エージェント抽象基底クラス
"""

from __future__ import annotations
import re
import threading
from abc import ABC, abstractmethod
from datetime import datetime
from core.event_bus import EventBus
import core.event_bus as ev
import core.config as config
from core.llm_client import LLMClient

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _count_severities(text: str) -> dict:
    """ストリーミング中テキストから深刻度を集計する。"""
    return {s: len(re.findall(rf"SEVERITY:\s*{s}\b", text, re.I)) for s in _SEVERITIES}

# レポート/分析の出力言語をLLMに指示するディレクティブ。
# 設定 (report_lang) に応じて全エージェントの system プロンプトへ自動付与する。
_LANG_DIRECTIVE = {
    "ja": "\n\n# 出力言語\nすべての分析・説明・レポート本文は日本語で記述してください。"
          "コード・識別子・技術用語・固有名詞は原語のままで構いません。",
    "en": "\n\n# Output language\nWrite all analysis, explanations and report content in English. "
          "Keep code, identifiers, technical terms and proper nouns in their original form.",
}


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
    @staticmethod
    def _apply_language(messages: list[dict]) -> list[dict]:
        """設定の report_lang に応じて system プロンプトへ言語指示を付与する。"""
        directive = _LANG_DIRECTIVE.get(config.get("report_lang", "ja"))
        if not directive:
            return messages
        out = [dict(m) for m in messages]
        for m in out:
            if m.get("role") == "system":
                m["content"] = (m.get("content", "") or "") + directive
                return out
        out.insert(0, {"role": "system", "content": directive.strip()})
        return out

    def _stream_llm(self, messages: list[dict], live_stats: bool = False) -> str:
        """LLMをストリーミングし、各チャンクを OUTPUT イベントで流す。

        live_stats=True のとき、累積テキストから深刻度を逐次集計し、変化したら
        STATS イベントを送る（DETECTION SUMMARY のリアルタイム更新）。
        """
        acc = {"text": "", "last": None}

        def _chunk(chunk: str) -> None:
            self._out(chunk)
            if live_stats:
                acc["text"] += chunk
                counts = _count_severities(acc["text"])
                if counts != acc["last"]:
                    acc["last"] = counts
                    self._stats(counts)

        return self.llm.stream(
            messages=self._apply_language(messages),
            on_chunk=_chunk,
            on_error=lambda e: self._out(f"\n[ LLM ERROR ] {e}\n", "critical"),
        )

    def _complete_llm(self, messages: list[dict]) -> str:
        """LLMを非ストリーミングで呼び出す（短い補助的な推論に使用）。"""
        try:
            return self.llm.complete(self._apply_language(messages))
        except Exception as e:
            self._log(f"LLM error: {e}")
            return ""

    # ── 成果物の保存 ──────────────────────────────────────
    def _save_investigation(self, mode_title: str, target: str, body: str) -> str | None:
        """調査レポートを reports/investigation/ に Markdown 保存する。"""
        from tools import report_generator  # noqa: PLC0415
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            doc = (
                f"# AI Security Audit — {mode_title} Investigation Report\n"
                f"- Target: {target}\n- Date: {ts}\n- Engine: {self.llm.model}\n\n{body}"
            )
            path = report_generator.save_artifact(doc, "investigation", ext="md")
            self._out(f"\n  💾 調査レポートを保存しました: {path}\n", "green")
            self._log(f"Investigation report saved: {path}")
            return path
        except Exception as e:
            self._out(f"\n  [ 保存エラー ] {e}\n", "high")
            self._log(f"Artifact save error: {e}")
            return None

    def _save_poc(self, target: str, exploit_text: str) -> str | None:
        """生成した PoC を reports/poc/ に Markdown 保存する（送信はしない）。"""
        if not exploit_text.strip():
            return None
        from tools import report_generator  # noqa: PLC0415
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            doc = (
                f"# Generated PoC — {target}\n"
                f"- Date: {ts}\n- Engine: {self.llm.model}\n"
                f"- NOTE: これらの PoC はローカル生成のみ。対象へ送信・実行されていません。\n\n"
                f"{exploit_text}\n"
            )
            path = report_generator.save_artifact(doc, "poc", ext="md")
            self._out(f"\n  💾 PoC を保存しました: {path}\n", "green")
            self._log(f"PoC saved: {path}")
            return path
        except Exception as e:
            self._out(f"\n  [ 保存エラー ] {e}\n", "high")
            self._log(f"Artifact save error: {e}")
            return None
