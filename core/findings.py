"""
core/findings.py — 構造化所見・実行ライフサイクルのデータ契約 (P1.1)

docs/PRACTICAL_ROADMAP.md §5 P1.1 の設計契約を実装する。標準ライブラリの
dataclass/Enumのみを使い、特定LLMプロバイダーのJSON出力機能を必須にしない。

設計方針:
  - `ScanState`（completed/partial/failed/cancelled）は「指定した検査範囲について
    完了したか」を表す実行状態であり、対象に脆弱性が無いことの保証ではない。
  - `VerificationState`（observed/corroborated/manually_confirmed）は所見の裏付けの
    強さであり、severity・対応status・アンサンブル支持率とは別の軸として扱う。
    LLMが同意しただけでmanually_confirmedへ昇格させてはならない（呼び出し側の責務）。
  - `CoverageItem`は「何を検査したか／しなかったか」を表す。ページ数等の代用指標ではない。
"""

from __future__ import annotations
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

SCHEMA_VERSION = "1"


class ScanState(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VerificationState(str, Enum):
    OBSERVED = "observed"                    # 機械的観測のみ
    CORROBORATED = "corroborated"             # 複数根拠・検証パスによる裏付けあり
    MANUALLY_CONFIRMED = "manually_confirmed"  # 人間が確認済み（LLM同意では昇格しない）


class CoverageStatus(str, Enum):
    TESTED = "tested"
    SKIPPED = "skipped"
    FAILED = "failed"


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


@dataclass
class CoverageItem:
    """対象endpoint/コード位置・parameter・rule・認証contextの検査状況。

    単なるページ数・リクエスト数の代用ではなく、「何を検査対象にしたか」を表す。
    """
    target_ref: str                  # endpoint URL / "file.py:120" 等の識別子
    status: str                      # CoverageStatus値（tested/skipped/failed）
    rule_id: str = ""
    parameter: str = ""
    auth_context: str = ""           # 例: "anonymous" / "authenticated" / "session_b"
    reason: str = ""                 # skipped/failed時は必須相当。testedでも補足情報を許容

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    location: str                    # URL+parameter / "file.py:120" 等
    severity: str                    # CRITICAL/HIGH/MEDIUM/LOW
    verification_state: str = VerificationState.OBSERVED.value
    evidence_ids: list[str] = field(default_factory=list)
    description: str = ""
    remediation: str = ""
    verifier_support: dict = field(default_factory=dict)  # 例: {"votes": 2, "total": 3}
    raw_block: str = ""              # 旧マーカー形式の原文（互換保持。証拠管理はP1.2で分離）

    snippet: str = ""
    analysis: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    scan_id: str
    engagement_id: str
    mode: str                        # "AUDIT" | "ATTACK" | "WEB FUZZ" | "DEFENSE"
    target: str
    started_at: str
    schema_version: str = SCHEMA_VERSION
    ended_at: str = ""
    state: str = ScanState.FAILED.value
    errors: list[str] = field(default_factory=list)
    coverage: list[CoverageItem] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    config_version: str = ""
    detector_version: str = ""
    model: str = ""
    prompt_version: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def new_scan_result(mode: str, target: str, engagement_id: str = "default") -> ScanResult:
    return ScanResult(
        scan_id=new_id("scan"),
        engagement_id=engagement_id,
        mode=mode,
        target=target,
        started_at=_now_iso(),
    )
