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


def _parse_models_response(raw: dict) -> list[dict]:
    """/models の生JSONを [{id, price_out, context, intelligence, coding}, ...]
    （id昇順）へ変換する純粋関数。

    price_out は「100万トークンあたりのUSD（出力/completion側）」。OpenRouterの
    pricing.completion は1トークンあたりのUSD文字列のため *1_000_000 して格納する
    （lokicode の ModelPicker.tsx の costTier() と同じ単位に揃える）。
    intelligence/coding は data[].benchmarks.artificial_analysis.{intelligence_index,
    coding_index}（Artificial Analysis社のベンチマークスコア。OpenRouterが一部モデルにのみ
    付与、多くのローカル/マイナーモデルは未収録）。lokicodeのModelPicker.tsxには無い、
    本ツール独自の追加項目（知能指数ソート機能・後述のsort_models()のため）。
    いずれもフィールドが無い・パース不能なバックエンド（Ollama等）では None とし、
    例外は投げない（cve_client.py と同じサイレント失敗の方針）。
    """
    def _to_float(v):
        if v is None:
            return None
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    out: list[dict] = []
    seen: set[str] = set()
    for m in raw.get("data", []) or []:
        model_id = m.get("id")
        if not model_id or model_id in seen:
            continue
        seen.add(model_id)

        price_out = None
        pricing = m.get("pricing") or {}
        raw_price = pricing.get("completion")
        if raw_price is not None:
            try:
                price_out = float(raw_price) * 1_000_000
            except (TypeError, ValueError):
                price_out = None

        context = None
        raw_ctx = m.get("context_length")
        if raw_ctx is not None:
            try:
                context = int(raw_ctx)
            except (TypeError, ValueError):
                context = None

        aa = ((m.get("benchmarks") or {}).get("artificial_analysis") or {})
        intelligence = _to_float(aa.get("intelligence_index"))
        coding       = _to_float(aa.get("coding_index"))

        out.append({
            "id": model_id, "price_out": price_out, "context": context,
            "intelligence": intelligence, "coding": coding,
        })
    out.sort(key=lambda d: d["id"])
    return out


def sort_models(models: list[dict], by: str = "id") -> list[dict]:
    """モデル一覧を並べ替える純粋関数（元のリストは変更しない）。

    by="id"（既定）: id昇順（従来通り）。
    by="intelligence": intelligence（知能指数）降順。値が None のモデルは
    「不明」として末尾へ送る（存在するモデルを優先表示する・未収録=低評価と
    誤読させないため最後尾固定であって0点扱いにはしない）。
    lokicodeのModelPicker.tsxにはソート機能自体が無く、本ツール独自の追加。
    """
    if by == "intelligence":
        return sorted(
            models,
            key=lambda d: (d["intelligence"] is None, -(d["intelligence"] or 0), d["id"]),
        )
    return sorted(models, key=lambda d: d["id"])


def cost_tier(price_out: float | None) -> str:
    """100万トークンあたりのUSD（出力側）からコスト階級を返す（4段階）。

    lokicode の ModelPicker.tsx costTier() と同じ閾値: 0/不明→無料、$1未満→低、
    $10未満→中、それ以上→高。負値（変動/ルーターモデルの目印）は「高」扱いにせず
    lokicode同様に別枠が必要だが、本ツールが繋ぐ先（OpenRouter/Ollama/OpenAI等）では
    負のpricingは現状想定しないため簡略化し、0以下は「無料」に含める。
    """
    if price_out is None or price_out <= 0:
        return "無料"
    if price_out < 1:
        return "低"
    if price_out < 10:
        return "中"
    return "高"


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
    def fetch_models(base_url: str, api_key: str = "", timeout: int = 15) -> list[dict]:
        """接続先の /models から利用可能なモデル一覧（価格・コンテキスト長付き）を取得する。

        OpenAI 互換エンドポイント（OpenRouter / OpenAI / Ollama / LM Studio 等）が
        対応する標準のモデル一覧 API を叩く。openai SDK の型付きレスポンスには
        pricing/context_length が乗らないため、requests で生JSONを取得しパースする。
        取得失敗時は例外を送出する（呼び出し側の try/except で「取得失敗」表示に使う）。
        戻り値は _parse_models_response() 参照（id昇順ソート）。
        """
        import requests  # noqa: PLC0415
        headers = {"Authorization": f"Bearer {api_key or 'ollama'}", **_or_headers(base_url)}
        resp = requests.get(f"{base_url.rstrip('/')}/models", headers=headers, timeout=timeout)
        resp.raise_for_status()
        return _parse_models_response(resp.json())

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
