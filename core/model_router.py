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


# 既知モデルslugの相対的な「重さ」ヒューリスティック（厳密なコスト表ではなく、
# STRONG/FAST の取り違え検知が目的の目安）。値が大きいほど高性能・高コストとみなす。
# パターンは小文字部分一致。より具体的なパターンを先に置く（"qwen3-30b" は "qwen3" 系より先）。
_MODEL_WEIGHT_HINTS: list[tuple[str, int]] = [
    ("opus", 5), ("gpt-5.5", 5), ("gpt-5", 5), ("o1", 5), ("o3", 5),
    ("qwen3-max", 4), ("llama-4-scout", 4), ("llama4:scout", 4),
    ("sonnet", 3), ("mistral-large", 3),
    ("qwen3-30b", 2), ("qwen2.5-coder:14b", 2), ("mistral-medium", 2),
    ("fable", 1), ("haiku", 1), ("-mini", 1), (":mini", 1), ("mistral-small", 1),
    ("-8b", 1), ("-3b", 1), (":8b", 1), (":3b", 1),
]


def _model_weight(model_id: str) -> int | None:
    """モデルslugから既知パターンで大まかな「重さ」を推定する。未知なら None（判定対象外）。"""
    low = (model_id or "").strip().lower()
    for pat, weight in _MODEL_WEIGHT_HINTS:
        if pat in low:
            return weight
    return None


def assess_readiness(strong_id: str, fast_id: str) -> list[str]:
    """STRONG/FAST モデル構成のヒューリスティック警告を返す（空リスト＝問題なし）。

    設定画面での注意喚起のみが目的でブロックはしない（`docs/AGENT_ARCHITECTURE.md` §5.2）。
    既知slugパターンに基づく目安に過ぎないため、未知のモデルは警告対象外とし
    誤検知より見逃しを優先する。
    """
    warnings: list[str] = []
    strong_id = (strong_id or "").strip()
    fast_id = (fast_id or "").strip()
    if not fast_id:
        return warnings  # FAST未設定＝ルーティング無効（STRONG共用）。警告対象外。
    if strong_id and strong_id == fast_id:
        warnings.append("STRONGとFASTが同一モデルです。コスト分離の効果がありません。")
        return warnings
    strong_weight = _model_weight(strong_id)
    fast_weight = _model_weight(fast_id)
    if strong_weight is not None and fast_weight is not None and fast_weight > strong_weight:
        warnings.append(
            f"FAST（{fast_id}）がSTRONG（{strong_id}）より高性能/高コストに見えます。"
            "取り違えていないか確認してください。"
        )
    return warnings
