"""
core/config.py — 実行時設定の読み書き

settings.py の定数をデフォルト値として使い、config.json に上書き保存する。
APIキー等を含むため config.json は .gitignore で除外すること。
"""

from __future__ import annotations
import json
import os
import logging
from core.settings import (
    LLM_BASE_URL, LLM_API_KEY, LLM_MODEL, LLM_TIMEOUT,
    LLM_FAST_MODEL, LLM_FAST_BASE_URL, LLM_FAST_API_KEY, DEFAULT_EFFORT,
    EFFORT_LEVELS, PORT_SCOPES,
)

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
_logger = logging.getLogger(__name__)

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

# 設定キーの許容リスト（未知キー警告のため）
_VALID_KEYS = frozenset(_DEFAULTS.keys())

# 値バリデーションルール: キー → 検査関数（失敗時にメッセージを返す、OKなら None）
def _validate_timeout(v) -> str | None:
    try:
        n = float(v)
    except (TypeError, ValueError):
        return "llm_timeout は数値である必要があります"
    if n <= 0:
        return "llm_timeout は 0 より大きい値が必要です"
    return None

def _validate_effort(v) -> str | None:
    if v not in EFFORT_LEVELS:
        return f"effort は {EFFORT_LEVELS} のいずれかである必要があります"
    return None

def _validate_report_lang(v) -> str | None:
    if v not in ("ja", "en"):
        return "report_lang は 'ja' または 'en' である必要があります"
    return None

def _validate_port_range(v) -> str | None:
    if not isinstance(v, list) or not all(isinstance(p, int) and 1 <= p <= 65535 for p in v):
        return "port_range は 1-65535 の整数リストである必要があります"
    return None

_VALIDATORS = {
    "llm_timeout": _validate_timeout,
    "effort":      _validate_effort,
    "report_lang": _validate_report_lang,
    "port_range":  _validate_port_range,
}


def validate_config(data: dict) -> list[str]:
    """設定データをバリデーションし、警告/エラーメッセージのリストを返す。"""
    warnings: list[str] = []
    for key in data:
        if key not in _VALID_KEYS:
            warnings.append(f"未知の設定キー '{key}' が含まれています（無視されます）")
    for key, validator in _VALIDATORS.items():
        if key in data:
            err = validator(data[key])
            if err:
                warnings.append(f"[{key}] {err}")
    return warnings


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
    msgs = validate_config(data)
    for m in msgs:
        _logger.warning("config validation: %s", m)
    _cfg.update(data)
    with open(_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(_cfg, f, indent=2, ensure_ascii=False)


def get(key: str, default=None):
    if not _cfg:
        load()
    return _cfg.get(key, _DEFAULTS.get(key, default))