"""
core/config.py — 実行時設定の読み書き

settings.py の定数をデフォルト値として使い、config.json に上書き保存する。
APIキー等を含むため config.json は .gitignore で除外すること。
"""

from __future__ import annotations
import json
import os
from core.settings import (
    LLM_BASE_URL, LLM_API_KEY, LLM_MODEL, LLM_TIMEOUT,
    LLM_FAST_MODEL, LLM_FAST_BASE_URL, LLM_FAST_API_KEY, DEFAULT_EFFORT,
)

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")

_DEFAULTS: dict = {
    "llm_base_url": LLM_BASE_URL,
    "llm_api_key":  LLM_API_KEY,
    "llm_model":    LLM_MODEL,
    "llm_timeout":  LLM_TIMEOUT,
    # FAST（廉価）モデル — 補助的・機械的なLLM呼び出しに使う。空=ルーティング無効。
    # base_url / api_key が空なら主モデル（STRONG）の接続情報を共用する。
    "llm_fast_model":    LLM_FAST_MODEL,
    "llm_fast_base_url": LLM_FAST_BASE_URL,
    "llm_fast_api_key":  LLM_FAST_API_KEY,
    # 推論エフォート: "speed" / "balanced" / "quality"。
    "effort": DEFAULT_EFFORT,
    # 接続先から取得したモデル一覧のキャッシュ（「↻ 取得」で更新）。
    "available_models": [],
    # レポート生成言語: "ja"（日本語）または "en"（英語）。
    "report_lang": "ja",
}

_cfg: dict = {}


def load() -> dict:
    global _cfg
    _cfg = dict(_DEFAULTS)
    if os.path.isfile(_CONFIG_PATH):
        try:
            with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
                _cfg.update(json.load(f))
        except Exception:
            pass
    return _cfg


def save(data: dict) -> None:
    _cfg.update(data)
    with open(_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(_cfg, f, indent=2, ensure_ascii=False)


def get(key: str, default=None):
    if not _cfg:
        load()
    return _cfg.get(key, _DEFAULTS.get(key, default))
