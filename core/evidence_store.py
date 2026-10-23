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
import hashlib
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
    # 由来情報(自律化 設計 §3.7)。全種別共通。保存時に埋まる。
    action_id: str = ""        # この証拠を生んだAction(自律経路)。無ければ空
    masking_version: str = ""  # 保存時のマスキング規則の版(core.redaction.MASKING_VERSION)
    truncated: bool = False    # 本文/抜粋を切り詰めた・省略したか
    content_sha256: str = ""   # 保存するマスク済みデータ(本項目を除く)のsha256。改ざん検出の補助

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
    action_id: str = ""
    masking_version: str = ""
    truncated: bool = False
    content_sha256: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LogEvidence:
    evidence_id: str
    source: str              # ログファイル（相対化済み）
    line: str                # マスク済み・切り詰め済みのログ1行
    patterns: list           # 一致した攻撃パターン名（決定的観測）
    observed_at: str         # エージェントがこの行を観測した時刻
    timestamp: str
    omitted_reason: str = ""
    kind: str = "log"
    action_id: str = ""
    masking_version: str = ""
    truncated: bool = False
    content_sha256: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ObservationEvidence:
    evidence_id: str
    category: str            # "port" / "web_path" / "web_headers" / "subdomain" 等（決定的観測の種類）
    target_ref: str          # 観測対象（host:port/tcp、URL等）
    detail: str              # マスク済み・切り詰め済みの観測内容（バナー、ヘッダー一覧等）
    timestamp: str
    omitted_reason: str = ""
    kind: str = "observation"
    action_id: str = ""
    masking_version: str = ""
    truncated: bool = False
    content_sha256: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


_HASH_PLACEHOLDER = "0" * 64


def content_digest(data: dict) -> str:
    """証拠の保存内容(content_sha256自身を除く)の正規化JSONのsha256。

    保存するのは**マスク済み**データなので、ハッシュ対象も常にマスク済み。改ざん・差し替えの
    検出の補助であり、匿名化でも、証拠が正しいことの保証でもない(書換え側がハッシュも
    作り直せる)。
    """
    body = {k: v for k, v in data.items() if k != "content_sha256"}
    canon = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


_SCAN_REF_RE = re.compile(r"scan_[a-f0-9]{12}")
_EVID_REF_RE = re.compile(r"evidence_[a-f0-9]{12}")


def inspect_evidence(root: str | None, scan_id: str, evidence_id: str) -> dict:
    """保存済み証拠を**読み取り専用**で検査する。作成・修復・書換えはしない。

    戻り値: {"integrity", "completeness", "reason"}。2軸は別物:
      integrity    … 保存物の整合性。ok(記録時のハッシュと一致) / missing / hash_mismatch(保存後に内容が変わった) /
                      no_hash(由来情報導入前の旧形式) / invalid_reference(IDの形式が不正・保存先の外を指す) /
                      unreadable(読めない・壊れている) / unchecked(保存先が指定されていない=検査不能)
      completeness … 取得内容の完全性。complete(保存時に切り詰め・省略の記録なし) / truncated(切り詰め・省略・上流で不完全と記録) /
                      unknown(整合性が確認できない、または旧形式)
    ハッシュ一致(ok)は保存物が記録後に変わっていないことだけを示す。所見の意味的な正しさ・元の全文があることは意味しない。
    保存先は呼び出し側が明示する(cwdから推測しない)。"""
    if not root:
        return {"integrity": "unchecked", "completeness": "unknown", "reason": "evidence_root_not_specified"}
    if not (_SCAN_REF_RE.fullmatch(str(scan_id or "")) and _EVID_REF_RE.fullmatch(str(evidence_id or ""))):
        return {"integrity": "invalid_reference", "completeness": "unknown", "reason": "bad_id_format"}
    path = os.path.join(root, scan_id, f"{evidence_id}.json")
    try:
        if os.path.islink(path) or os.path.realpath(path) != os.path.join(os.path.realpath(root), scan_id, f"{evidence_id}.json"):
            return {"integrity": "invalid_reference", "completeness": "unknown", "reason": "outside_root_or_symlink"}
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"integrity": "missing", "completeness": "unknown", "reason": "file_not_found"}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {"integrity": "unreadable", "completeness": "unknown", "reason": "read_or_parse_failed"}
    if not isinstance(data, dict):
        return {"integrity": "unreadable", "completeness": "unknown", "reason": "not_an_object"}
    recorded = data.get("content_sha256", "")
    if not recorded:
        return {"integrity": "no_hash", "completeness": "unknown", "reason": "legacy_evidence_without_hash"}
    if content_digest(data) != recorded:
        return {"integrity": "hash_mismatch", "completeness": "unknown", "reason": "content_changed_after_save"}
    cut = bool(data.get("truncated")) or bool(data.get("omitted_reason"))
    return {"integrity": "ok", "completeness": "truncated" if cut else "complete",
            "reason": str(data.get("omitted_reason") or ("truncated" if cut else ""))[:120]}


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
                           known_secrets: set[str] | None = None,
                           action_id: str = "", source_incomplete: str | None = None) -> str | None:
        """HTTP証拠をマスクした上で保存し evidence_id を返す。

        `source_incomplete`は上流で既に本文が不完全だった理由(途中切断・サイズ上限・呼び出し側の切り詰め等)。
        この層では渡された文字列の長さしか分からないため、指定時は truncated=True にして理由を残す。

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
            action_id=action_id,
            truncated=bool(source_incomplete) or len(body or "") > self.max_item_bytes
            or len(baseline_body or "") > self.max_item_bytes,
            omitted_reason=f"上流で本文が不完全: {source_incomplete}" if source_incomplete else "",
        )
        return self._persist(ev, shrink_fields=("body_excerpt", "baseline_excerpt"))

    def save_code_evidence(self, *, path: str, line_start: int, line_end: int,
                           excerpt: str, source: str,
                           known_secrets: set[str] | None = None,
                           action_id: str = "", project_relative: bool = False) -> str | None:
        """コード証拠（相対パス・行範囲・マスク済み抜粋）を保存し evidence_id を返す。

        `source`には証拠の由来（"ast_prescan"等の決定的観測）を渡す。LLMが報告した
        行番号から後付けで作った抜粋は、所見の裏付けにならない（LLMの主張の言い換えに
        過ぎない）ため、この関数の呼び出し元は決定的観測のみを渡すこと。
        `project_relative=True`はプロジェクト監査用: `path`がプロジェクト直下からの相対パス(絶対パス・`..`なし)なら
        そのまま残す(cwd基準の相対化では同名ファイルが区別できなくなるため)。条件を満たさなければ従来どおり相対化する。
        """
        if project_relative and (os.path.isabs(path) or ".." in path.replace("\\", "/").split("/") or "\x00" in path):
            project_relative = False
        if self._count >= self.max_items:
            self._omit(f"件数上限({self.max_items}件)に達したため証拠を保存しなかった")
            return None
        eid = new_id("evidence")
        ev = CodeEvidence(
            evidence_id=eid, path=path.replace("\\", "/") if project_relative else relativize_path(path),
            line_start=line_start, line_end=line_end,
            excerpt=redaction.mask_source(excerpt, known_secrets, max_len=self.max_item_bytes),
            source=source, timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            action_id=action_id, truncated=len(excerpt or "") > self.max_item_bytes,
        )
        return self._persist(ev, shrink_fields=("excerpt",))

    def save_log_evidence(self, *, source: str, line: str, patterns: list[str],
                          known_secrets: set[str] | None = None,
                          action_id: str = "") -> str | None:
        """ログ証拠（入力元・マスク済み行・一致パターン・観測時刻）を保存し evidence_id を返す。"""
        if self._count >= self.max_items:
            self._omit(f"件数上限({self.max_items}件)に達したため証拠を保存しなかった")
            return None
        eid = new_id("evidence")
        ev = LogEvidence(
            evidence_id=eid, source=relativize_path(source),
            line=redaction.mask_log_line(line, known_secrets, max_len=self.max_item_bytes),
            patterns=list(patterns), observed_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            action_id=action_id, truncated=len(line or "") > self.max_item_bytes,
        )
        return self._persist(ev, shrink_fields=("line",))

    def save_observation_evidence(self, *, category: str, target_ref: str, detail: str,
                                  known_secrets: set[str] | None = None,
                                  action_id: str = "") -> str | None:
        """偵察で得た決定的観測（ポート/バナー、検出パス、応答ヘッダー等）を保存し evidence_id を返す。"""
        if self._count >= self.max_items:
            self._omit(f"件数上限({self.max_items}件)に達したため証拠を保存しなかった")
            return None
        eid = new_id("evidence")
        ev = ObservationEvidence(
            evidence_id=eid, category=category,
            target_ref=redaction.mask_log_line(target_ref, known_secrets, max_len=1000),
            detail=redaction.mask_log_line(detail, known_secrets, max_len=self.max_item_bytes),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            action_id=action_id,
            truncated=len(detail or "") > self.max_item_bytes or len(target_ref or "") > 1000,
        )
        return self._persist(ev, shrink_fields=("detail",))

    def _persist(self, ev, *, shrink_fields: tuple[str, ...]) -> str | None:
        """サイズ検査→総容量検査→書き込みの共通処理。成功時evidence_id、省略/失敗時None。"""
        ev.masking_version = redaction.MASKING_VERSION
        ev.content_sha256 = _HASH_PLACEHOLDER   # 固定長。サイズ判定を最終形と一致させる
        payload = json.dumps(ev.to_dict(), ensure_ascii=False)
        size = len(payload.encode("utf-8"))
        if size > self.max_item_bytes:
            for fld in shrink_fields:
                setattr(ev, fld, "")
            ev.omitted_reason = f"1件あたりの上限({self.max_item_bytes}bytes)超過のため本文を省略"
            ev.truncated = True
        ev.content_sha256 = content_digest(ev.to_dict())
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

    def verify(self, evidence_id: str) -> tuple[bool, str]:
        """保存済み証拠が記録時のハッシュと一致するか検査する。(ok, 理由コード)を返す。

        理由: ok / missing(存在しない・読めない・不正ID) / no_hash(由来情報導入前の旧証拠) /
        hash_mismatch(保存後に内容が変わった)。切り詰め済み(truncated)の証拠は、ハッシュが
        一致しても「元の全文」ではないため、同じ根拠での再検証には使えないことに注意。
        """
        data = self.load(evidence_id)
        if data is None:
            return False, "missing"
        recorded = data.get("content_sha256", "")
        if not recorded:
            return False, "no_hash"
        if content_digest(data) != recorded:
            return False, "hash_mismatch"
        return True, "ok"

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
