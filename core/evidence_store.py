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


@dataclass
class CodeEvidence:
    evidence_id: str
    path: str                # 相対化済み（絶対パスのホームディレクトリ等を残さない）
    line_start: int
    line_end: int
    excerpt: str             # マスク済み・切り詰め済み
    source: str              # 由来（例: "ast_prescan"）。LLMの主張ではなく決定的観測であることを示す
    timestamp: str
    omitted_reason: str = ""
    kind: str = "code"

    def to_dict(self) -> dict:
        return asdict(self)


def relativize_path(path: str, base: str | None = None) -> str:
    """証拠に残すパスを相対形へ変換する。baseがcwd配下でない場合はファイル名のみ。

    GUIのファイルダイアログは絶対パスを返すため、そのまま保存するとホームディレクトリ名が
    レポートに残る。相対化できない場合はファイル名のみを残す（情報量より漏えい抑止を優先）。
    """
    try:
        ap = os.path.abspath(path)
        root = os.path.abspath(base or os.getcwd())
        if os.path.commonpath([ap, root]) == root:
            return os.path.relpath(ap, root)
    except ValueError:
        pass
    return os.path.basename(path)


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
        self._omissions: list[str] = []

    @property
    def omissions(self) -> list[str]:
        """上限到達により保存を省略した理由（保存失敗とは別。呼び出し側がerrors/表示へ反映する）。"""
        return list(self._omissions)

    def _omit(self, reason: str) -> None:
        if reason not in self._omissions:  # 上限到達後は毎回同じ理由になるため重複を畳む
            self._omissions.append(reason)

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
            self._omit(f"件数上限({self.max_items}件)に達したため証拠を保存しなかった")
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
        return self._persist(ev, shrink_fields=("body_excerpt", "baseline_excerpt"))

    def save_code_evidence(self, *, path: str, line_start: int, line_end: int,
                           excerpt: str, source: str,
                           known_secrets: set[str] | None = None) -> str | None:
        """コード証拠（相対パス・行範囲・マスク済み抜粋）を保存し evidence_id を返す。

        `source`には証拠の由来（"ast_prescan"等の決定的観測）を渡す。LLMが報告した
        行番号から後付けで作った抜粋は、所見の裏付けにならない（LLMの主張の言い換えに
        過ぎない）ため、この関数の呼び出し元は決定的観測のみを渡すこと。
        """
        if self._count >= self.max_items:
            self._omit(f"件数上限({self.max_items}件)に達したため証拠を保存しなかった")
            return None
        eid = new_id("evidence")
        ev = CodeEvidence(
            evidence_id=eid, path=relativize_path(path),
            line_start=line_start, line_end=line_end,
            excerpt=redaction.mask_source(excerpt, known_secrets, max_len=self.max_item_bytes),
            source=source, timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
        )
        return self._persist(ev, shrink_fields=("excerpt",))

    def _persist(self, ev, *, shrink_fields: tuple[str, ...]) -> str | None:
        """サイズ検査→総容量検査→書き込みの共通処理。成功時evidence_id、省略/失敗時None。"""
        payload = json.dumps(ev.to_dict(), ensure_ascii=False)
        size = len(payload.encode("utf-8"))
        if size > self.max_item_bytes:
            for fld in shrink_fields:
                setattr(ev, fld, "")
            ev.omitted_reason = f"1件あたりの上限({self.max_item_bytes}bytes)超過のため本文を省略"
            payload = json.dumps(ev.to_dict(), ensure_ascii=False)
            size = len(payload.encode("utf-8"))
        if self._total_bytes + size > self.max_total_bytes:
            self._omit(f"総容量上限({self.max_total_bytes}bytes)に達したため証拠を保存しなかった")
            return None
        eid = ev.evidence_id
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
