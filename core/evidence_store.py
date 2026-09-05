"""
core/evidence_store.py — 所見に紐づく証拠の保存 (P1.2)

`reports/evidence/<scan_id>/` へ所見に必要な証拠のみJSON形式で保存する。
件数・1件あたりのサイズ・総容量に上限を設け、全通信の無制限保存は行わない。
マスキング（core/redaction.py）はディスク書き込み前に必ず適用する。

保存は既定OFF（core.config.get("save_evidence", False)）。呼び出し側が明示的に
有効化した場合のみ実際にファイルを書く。OFFでも「保存未実施」を示す構造化データ
（omitted_reason等）は呼び出し側が残せるようにする（本モジュールはそこまで強制しない）。

保存失敗は例外にせず`save_errors`へ記録して呼び出し側に委ねる（所見自体を破棄しない）。
"""

from __future__ import annotations
import json
import os
import re
import time
from dataclasses import dataclass, asdict

from core.findings import new_id
from core import redaction

EVIDENCE_ROOT = os.path.join("reports", "evidence")

DEFAULT_MAX_ITEMS_PER_SCAN = 200
DEFAULT_MAX_ITEM_BYTES = 20_000
DEFAULT_MAX_TOTAL_BYTES = 5_000_000


@dataclass
class HttpEvidence:
    evidence_id: str
    method: str
    url: str                 # マスク済み
    status: int | None
    headers: dict             # マスク済み
    body_excerpt: str         # マスク済み・切り詰め済み
    baseline_excerpt: str     # 比較用の通常応答（マスク済み・切り詰め済み・任意）
    timestamp: str
    omitted_reason: str = ""  # 保存を省略した場合の理由（サイズ超過等）

    def to_dict(self) -> dict:
        return asdict(self)


class EvidenceStore:
    """1スキャン分の証拠保存を管理する。scan_idごとにディレクトリを分ける。"""

    def __init__(self, scan_id: str, *,
                max_items: int = DEFAULT_MAX_ITEMS_PER_SCAN,
                max_item_bytes: int = DEFAULT_MAX_ITEM_BYTES,
                max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
                root: str = EVIDENCE_ROOT):
        self.scan_id = scan_id
        self.max_items = max_items
        self.max_item_bytes = max_item_bytes
        self.max_total_bytes = max_total_bytes
        self.dir = os.path.join(root, scan_id)
        self._count = 0
        self._total_bytes = 0
        self._save_errors: list[str] = []

    @property
    def count(self) -> int:
        return self._count

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    @property
    def save_errors(self) -> list[str]:
        return list(self._save_errors)

    def save_http_evidence(self, *, method: str, url: str, status: int | None,
                           headers: dict | None = None, body: str = "",
                           baseline_body: str = "",
                           known_secrets: set[str] | None = None) -> str | None:
        """HTTP証拠をマスクした上で保存し evidence_id を返す。

        件数上限・総容量上限に達している場合はNoneを返す（呼び出し側は
        「証拠保存を省略した」ことをcoverage/errorsへ反映すること）。
        1件あたりのサイズ上限を超える場合は本文を省略して保存する
        （証拠そのものを完全に捨てるのではなく、省略理由を明示して保持する）。
        """
        if self._count >= self.max_items:
            return None
        eid = new_id("evidence")
        masked_url = redaction.mask_url(url, known_secrets)
        masked_headers = redaction.mask_headers(headers or {}, known_secrets=known_secrets)
        masked_body = redaction.mask_body(body, known_secrets, max_len=self.max_item_bytes)
        masked_baseline = redaction.mask_body(baseline_body, known_secrets, max_len=self.max_item_bytes)
        ev = HttpEvidence(
            evidence_id=eid, method=method, url=masked_url, status=status,
            headers=masked_headers, body_excerpt=masked_body,
            baseline_excerpt=masked_baseline,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
        )
        payload = json.dumps(ev.to_dict(), ensure_ascii=False)
        size = len(payload.encode("utf-8"))
        if size > self.max_item_bytes:
            ev.body_excerpt = ""
            ev.baseline_excerpt = ""
            ev.omitted_reason = f"1件あたりの上限({self.max_item_bytes}bytes)超過のため本文を省略"
            payload = json.dumps(ev.to_dict(), ensure_ascii=False)
            size = len(payload.encode("utf-8"))
        if self._total_bytes + size > self.max_total_bytes:
            return None
        try:
            os.makedirs(self.dir, exist_ok=True)
            path = os.path.join(self.dir, f"{eid}.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write(payload)
        except OSError as e:
            self._save_errors.append(f"{eid}: {e}")
            return None
        self._count += 1
        self._total_bytes += size
        return eid

    def load(self, evidence_id: str) -> dict | None:
        """保存済み証拠を読み込む。存在しない・壊れている場合はNone。"""
        # evidence_idをそのままパスへ使わない（new_id()の既知フォーマットのみ許容）。
        if not re.fullmatch(r"[A-Za-z0-9_\-]+", evidence_id):
            return None
        path = os.path.join(self.dir, f"{evidence_id}.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None
