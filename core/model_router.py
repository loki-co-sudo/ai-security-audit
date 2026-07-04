"""
core/model_router.py — ロール別モデルルーティング & 推論エフォート

lokicode のエージェント設計（コスト効率ルーティング + エフォートプリセット）を
本ツールへ移植したもの。単一モデルを全処理に使う代わりに、役割で使い分ける:

  STRONG（合成）モデル … 最終的な専門推論。脆弱性トリアージ・攻撃仮説・監査・
      検証パス。BaseAgent の `_stream_llm()`（ストリーミング）が使う。= config の llm_model。
  FAST（思考）モデル   … 量が出る機械的な生成。検出プローブ生成・要約・分類など。
      BaseAgent の `_complete_llm(role="fast")` が使う。= config の llm_fast_model。

FAST が未設定（空文字）のときは STRONG を共用するため、単一モデル時と完全に同一の
挙動になる（後方互換）。別エンドポイント（例: ローカル Ollama=FAST + クラウド=STRONG）
を使う場合は llm_fast_base_url / llm_fast_api_key を設定する。空なら STRONG の接続を共用。
"""

from __future__ import annotations
import core.config as config
from core.settings import EFFORT_PRESETS, DEFAULT_EFFORT
from core.llm_client import LLMClient


def current_effort() -> dict:
    """現在の推論エフォートのプリセット dict を返す。"""
    level = config.get("effort", DEFAULT_EFFORT)
    return EFFORT_PRESETS.get(level, EFFORT_PRESETS[DEFAULT_EFFORT])


def fast_model_configured() -> bool:
    """FAST モデルが設定されており、ルーティングが有効か。"""
    return bool((config.get("llm_fast_model", "") or "").strip())


def build_fast_client(strong: LLMClient | None) -> LLMClient | None:
    """FAST 用 LLMClient を生成して返す。

    FAST 未設定、または strong が None のときは strong をそのまま返す（＝単一モデル動作）。
    FAST の base_url / api_key が空なら strong の接続情報を共用する。
    """
    fast_model = (config.get("llm_fast_model", "") or "").strip()
    if not fast_model or strong is None:
        return strong
    base = (config.get("llm_fast_base_url", "") or "").strip() or strong.base_url
    key  = (config.get("llm_fast_api_key", "") or "").strip() or strong.api_key
    return LLMClient(base, key, fast_model, strong.timeout)


def fast_signature(strong: LLMClient | None) -> tuple:
    """FAST クライアントの再生成要否を判定するための設定シグネチャ。"""
    return (
        (config.get("llm_fast_model", "") or "").strip(),
        (config.get("llm_fast_base_url", "") or "").strip(),
        (config.get("llm_fast_api_key", "") or "").strip(),
        getattr(strong, "base_url", None),
        getattr(strong, "api_key", None),
        getattr(strong, "timeout", None),
    )
