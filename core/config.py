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
    EFFORT_LEVELS, PORT_SCOPES, TLS_VERIFY_DEFAULT, TLS_CA_BUNDLE_DEFAULT,
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
    # バグバウンティ対応: 対象範囲（Scope）ガード（BOUNTY_ROADMAP.md Phase A）。
    # 空 = 制限なし（既存インストールとの後方互換）。
    "allowed_targets": [],
    # 範囲外を検出したときの挙動: "warn"（警告のみ続行）| "block"（実行ブロック）。
    "scope_mode": "warn",
    # WEB FUZZ TLS検証（P0.2）。既定はFalse（既存動作の維持・自己署名ラボ環境が多いため）。
    # 新しい案件ではtrueにし、必要ならtls_ca_bundleで自己署名CAを個別指定する。
    "tls_verify": TLS_VERIFY_DEFAULT,
    "tls_ca_bundle": TLS_CA_BUNDLE_DEFAULT,
    # 証拠保存（P1.2）。既定OFF（既存設定との後方互換）。ONでもマスキング後のみ保存し、
    # 生の認証情報は保存しない（core/redaction.py・core/evidence_store.py）。
    "save_evidence": False,
    # CLIの案件プロファイル(cli.py --use-profile NAME)。{名前: {engagement_id,target,allow,exclude,scan_profile,effort,...}}。秘密値は置かない。
    "profiles": {},
    # GUIの所見台帳(P3.2): 空=記録しない(既定・従来どおり)。設定するとGUIのスキャン結果を
    # reports/engagements/<id>/ へ記録し、レポートに差分・抑制を反映する(CLIの--engagement-idと同じ台帳)。
    "engagement_id": "",
    # ローカルOllama向けの構造化出力(JSONスキーマ制約)。既定OFF=従来どおり(core/structured_output.py)。
    # 小型モデルが所見マーカーを守れず所見0件になるのを避ける。形式が保証されるだけで内容の正しさは保証されない。
    "llm_structured": False,
    "llm_structured_num_ctx": 12288,
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

def _validate_scope_mode(v) -> str | None:
    if v not in ("warn", "block"):
        return "scope_mode は 'warn' または 'block' である必要があります"
    return None

def _validate_tls_verify(v) -> str | None:
    if not isinstance(v, bool):
        return "tls_verify は true/false である必要があります"
    return None

def _validate_tls_ca_bundle(v) -> str | None:
    if not isinstance(v, str):
        return "tls_ca_bundle は文字列（ファイルパス）である必要があります"
    if v and not os.path.isfile(v):
        return f"tls_ca_bundle のファイルが見つかりません: {v}"
    return None

def _validate_save_evidence(v) -> str | None:
    if not isinstance(v, bool):
        return "save_evidence は true/false である必要があります"
    return None

def _validate_engagement_id(v) -> str | None:
    if v == "":
        return None
    from core.findings_ledger import validate_engagement_id, LedgerError
    try:
        validate_engagement_id(v)
    except LedgerError as e:
        return str(e)
    return None

def _validate_llm_structured(v) -> str | None:
    return None if isinstance(v, bool) else "llm_structured は true/false である必要があります"

def _validate_llm_structured_num_ctx(v) -> str | None:
    if isinstance(v, bool) or not isinstance(v, int) or not 2048 <= v <= 262144:
        return "llm_structured_num_ctx は 2048〜262144 の整数である必要があります"
    return None

_VALIDATORS = {
    "llm_structured": _validate_llm_structured,
    "llm_structured_num_ctx": _validate_llm_structured_num_ctx,
    "engagement_id": _validate_engagement_id,
    "llm_timeout": _validate_timeout,
    "effort":      _validate_effort,
    "report_lang": _validate_report_lang,
    "port_range":  _validate_port_range,
    "scope_mode":  _validate_scope_mode,
    "tls_verify":  _validate_tls_verify,
    "tls_ca_bundle": _validate_tls_ca_bundle,
    "save_evidence": _validate_save_evidence,
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


_runtime: dict = {}     # このプロセス内だけの上書き(CLIのフラグ等)。load()で消えず、config.jsonへは保存しない


def set_runtime_override(key: str, value) -> None:
    """このプロセス内だけ設定値を上書きする(保存しない・load()の再読込でも維持する)。未知のキーは拒否する。"""
    if key not in _VALID_KEYS:
        raise KeyError(f"未知の設定キー: {key}")
    _runtime[key] = value


def get(key: str, default=None):
    if key in _runtime:
        return _runtime[key]
    if not _cfg:
        load()
    return _cfg.get(key, _DEFAULTS.get(key, default))