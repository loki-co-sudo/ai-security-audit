"""
core/llm_client.py — LLM通信抽象層

OpenAI互換API（Ollama / OpenAI / vLLM 等）のストリーミング・非ストリーミングを統一。
"""

from __future__ import annotations
from typing import Callable, Iterator
from core.settings import LLM_BASE_URL, LLM_API_KEY, LLM_MODEL, LLM_TIMEOUT

_OR_REFERER = "https://github.com/loki-co-sudo/ai-security-audit"
_OR_TITLE   = "AI Security Audit System"


def _or_headers(base_url: str) -> dict:
    """OpenRouter 使用時のみ推奨ヘッダーを返す。他エンドポイントでは空。"""
    if "openrouter.ai" in base_url:
        return {"HTTP-Referer": _OR_REFERER, "X-Title": _OR_TITLE}
    return {}


class LLMClient:
    def __init__(
        self,
        base_url: str = LLM_BASE_URL,
        api_key:  str = LLM_API_KEY,
        model:    str = LLM_MODEL,
        timeout:  int = LLM_TIMEOUT,
    ):
        from openai import OpenAI  # 遅延インポート — 起動時間への影響ゼロ
        self.model    = model
        self.timeout  = timeout
        self.base_url = base_url
        self.api_key  = api_key
        self._client  = OpenAI(
            base_url=base_url, api_key=api_key,
            default_headers=_or_headers(base_url),
        )

    def update(
        self,
        base_url: str,
        api_key:  str,
        model:    str,
        timeout:  int,
    ) -> None:
        """設定変更時にクライアントを再生成する。エージェントは参照を共有するため即時反映される。"""
        from openai import OpenAI  # noqa: PLC0415
        self.model    = model
        self.timeout  = timeout
        self.base_url = base_url
        self.api_key  = api_key
        self._client  = OpenAI(
            base_url=base_url, api_key=api_key,
            default_headers=_or_headers(base_url),
        )

    # ── ストリーミング API ─────────────────────────────────
    def stream(
        self,
        messages:   list[dict],
        on_chunk:   Callable[[str], None],
        on_done:    Callable[[], None] | None = None,
        on_error:   Callable[[Exception], None] | None = None,
    ) -> str:
        """
        LLMをストリーミング呼び出しし、各チャンクを on_chunk に渡す。
        完全なレスポンス文字列を返す。
        """
        full = ""
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                stream=True,
                timeout=self.timeout,
            )
            for chunk in response:
                delta = chunk.choices[0].delta.content or ""
                if delta:
                    full += delta
                    on_chunk(delta)
        except Exception as e:
            if on_error:
                on_error(e)
            else:
                raise
        finally:
            if on_done:
                on_done()
        return full

    # ── 非ストリーミング API ───────────────────────────────
    def complete(self, messages: list[dict]) -> str:
        """LLMを一括呼び出しし、完全なレスポンス文字列を返す。"""
        response = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            stream=False,
            timeout=self.timeout,
        )
        return response.choices[0].message.content or ""

    # ── モデル一覧の自動取得 ───────────────────────────────
    @staticmethod
    def fetch_models(base_url: str, api_key: str = "", timeout: int = 15) -> list[str]:
        """接続先の /v1/models から利用可能なモデル ID 一覧を取得する。

        OpenAI 互換エンドポイント（OpenRouter / OpenAI / Ollama / LM Studio 等）が
        対応する標準のモデル一覧 API を叩く。取得失敗時は例外を送出する。
        """
        from openai import OpenAI  # noqa: PLC0415
        client = OpenAI(
            base_url=base_url,
            api_key=api_key or "ollama",
            default_headers=_or_headers(base_url),
            timeout=timeout,
        )
        resp = client.models.list()
        ids = [m.id for m in getattr(resp, "data", []) if getattr(m, "id", None)]
        return sorted(set(ids))

    # ── ユーティリティ ─────────────────────────────────────
    @staticmethod
    def system(content: str) -> dict:
        return {"role": "system", "content": content}

    @staticmethod
    def user(content: str) -> dict:
        return {"role": "user", "content": content}

    @staticmethod
    def assistant(content: str) -> dict:
        return {"role": "assistant", "content": content}
