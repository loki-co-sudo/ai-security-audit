"""
core/autonomy/journal.py — Run Journal（追記式JSONLの判断・実行記録）

設計: docs/AUTONOMOUS_PHASE_A_DESIGN.md §3.2。P3.2 の events.jsonl が同じ「追記・再生・
破損末尾の回復」を再利用できるよう、イベントの共通形式をここで固定する。

契約:
  - 1行1イベント。共通フィールド: event_id / schema_version / run_id / seq(1始まり連続) /
    ts / type / prev_hash。prev_hash は直前の行（改行を除く）のsha256で、先頭は全ゼロ。
    これは破損・欠落の検出補助であり、改ざん防止ではない（書換え側が連鎖を作り直せる）。
  - 書込みはfail closed: 記録できなかった判断を実行してはならないため、容量超過・書込み失敗は
    例外にし、呼び出し側（Policy Gate）は実行を拒否する。書込み失敗後はこのwriterを使えない。
  - 末尾の改行なしの部分行は書込み途中の残骸として警告付きで破棄し、sidecar(.partial)に退避する。
    途中行の破損・seq欠落・hash不整合は黙殺せず JournalCorrupt にする。
  - 単一writer。プロセス終了で解放されるOSロックを使い、古いロックファイルが残っても詰まらない。
  - 機密値は書込み前に core.redaction でマスクする（呼び出し側のマスク漏れに対する多層防御）。
    秘密値そのものをfieldsに渡さないのが原則。
"""

from __future__ import annotations
import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime

from core import redaction
from core.findings import new_id

SCHEMA_VERSION = "1"
JOURNAL_ROOT = os.path.join("reports", "runs")
JOURNAL_FILE = "journal.jsonl"
LOCK_FILE = "journal.lock"
PARTIAL_FILE = "journal.jsonl.partial"

GENESIS_HASH = "0" * 64
DEFAULT_MAX_EVENTS = 20_000
DEFAULT_MAX_BYTES = 10_000_000

# 容量上限の対象外。上限に達してもRunの終了を記録できるようにする。
UNCAPPED_TYPES = frozenset({"run_finished"})

_RUN_ID_RE = re.compile(r"^run_[0-9a-f]{12}$")
_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_RESERVED = frozenset({"event_id", "schema_version", "run_id", "seq", "ts", "type", "prev_hash"})

try:  # POSIX
    import fcntl as _fcntl
    _msvcrt = None
except ImportError:  # Windows
    _fcntl = None
    import msvcrt as _msvcrt


class JournalError(Exception):
    pass


class JournalCorrupt(JournalError):
    """途中行の破損・seq欠落・hash不整合。黙殺せず呼び出し側が止める。"""


class JournalFull(JournalError):
    """件数またはサイズの上限。記録できないため実行してはならない。"""


class JournalLocked(JournalError):
    """別のwriterが同じRunを開いている。"""


class JournalWriteError(JournalError):
    """書込み失敗。以後このwriterは使えない（fail closed）。"""


def new_run_id() -> str:
    return new_id("run")


def validate_run_id(run_id: str) -> str:
    """run_idはパスに使うため生成形式のみ受理する（pathトラバーサル対策）。"""
    if not isinstance(run_id, str) or not _RUN_ID_RE.match(run_id):
        raise ValueError(f"不正なrun_idです: {run_id!r}")
    return run_id


def _line_hash(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


@dataclass
class Replay:
    events: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    good_bytes: int = 0       # 検証済みの完全な行が占めるバイト数（改行込み）
    last_hash: str = GENESIS_HASH
    partial_tail: bytes = b""


def _parse(data: bytes, run_id: str) -> Replay:
    rep = Replay()
    if not data:
        return rep
    segments = data.split(b"\n")
    tail = segments.pop()  # 改行で終わっていれば空
    if tail:
        rep.partial_tail = tail
        rep.warnings.append(f"末尾の未完了行({len(tail)}バイト)を破棄しました")
    prev = GENESIS_HASH
    for n, raw in enumerate(segments, start=1):
        try:
            ev = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise JournalCorrupt(f"{n}行目がJSONとして読めません: {e}") from e
        if not isinstance(ev, dict):
            raise JournalCorrupt(f"{n}行目がオブジェクトではありません")
        if ev.get("schema_version") != SCHEMA_VERSION:
            raise JournalCorrupt(f"{n}行目のschema_versionが未対応です: {ev.get('schema_version')!r}")
        if ev.get("run_id") != run_id:
            raise JournalCorrupt(f"{n}行目のrun_idが一致しません")
        if ev.get("seq") != n:
            raise JournalCorrupt(f"{n}行目のseqが連続していません: {ev.get('seq')!r}")
        if ev.get("prev_hash") != prev:
            raise JournalCorrupt(f"{n}行目のprev_hashが直前の行と一致しません")
        rep.events.append(ev)
        prev = _line_hash(raw)
        rep.good_bytes += len(raw) + 1
    rep.last_hash = prev
    return rep


def _journal_dir(run_id: str, root: str) -> str:
    return os.path.join(root, validate_run_id(run_id))


def replay(run_id: str, root: str = JOURNAL_ROOT) -> Replay:
    """読み取り専用の再生。ファイルを変更せず、ロックも取らない。"""
    path = os.path.join(_journal_dir(run_id, root), JOURNAL_FILE)
    with open(path, "rb") as f:
        return _parse(f.read(), run_id)


def _mask(obj, known: set[str]):
    if isinstance(obj, str):
        return redaction.mask_log_line(obj, known)
    if isinstance(obj, dict):
        return {k: _mask(v, known) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_mask(v, known) for v in obj]
    return obj


class RunJournal:
    """1 Run分の追記writer。with文での利用を推奨する。"""

    def __init__(self, run_id: str, root: str = JOURNAL_ROOT, *,
                 known_secrets: set[str] | None = None,
                 max_events: int = DEFAULT_MAX_EVENTS,
                 max_bytes: int = DEFAULT_MAX_BYTES):
        self.run_id = validate_run_id(run_id)
        self.dir = os.path.join(root, self.run_id)
        self.path = os.path.join(self.dir, JOURNAL_FILE)
        self.max_events = max_events
        self.max_bytes = max_bytes
        self._known = {s for s in (known_secrets or ()) if s}
        self._mutex = threading.Lock()
        self._closed = False
        self._broken = False
        self.warnings: list[str] = []

        os.makedirs(self.dir, exist_ok=True)
        self._lock_fd = self._acquire_lock(os.path.join(self.dir, LOCK_FILE))
        try:
            rep = self._recover()
            self._seq = len(rep.events)
            self._prev_hash = rep.last_hash
            self._bytes = rep.good_bytes
            self._file = open(self.path, "ab")
        except BaseException:
            self._release_lock()
            raise

    # ── ロック ────────────────────────────────────────
    @staticmethod
    def _acquire_lock(path: str):
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if _fcntl is not None:
                _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
            else:
                _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
        except OSError as e:
            os.close(fd)
            raise JournalLocked(f"別のwriterがこのRunを使用中です: {path}") from e
        return fd

    def _release_lock(self) -> None:
        fd, self._lock_fd = self._lock_fd, None
        if fd is None:
            return
        try:
            if _fcntl is not None:
                _fcntl.flock(fd, _fcntl.LOCK_UN)
            else:
                os.lseek(fd, 0, os.SEEK_SET)
                _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        os.close(fd)

    # ── 回復 ──────────────────────────────────────────
    def _recover(self) -> Replay:
        try:
            with open(self.path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return Replay()
        rep = _parse(data, self.run_id)   # 途中破損はここで JournalCorrupt
        if rep.partial_tail:
            with open(os.path.join(self.dir, PARTIAL_FILE), "ab") as f:
                f.write(rep.partial_tail + b"\n")
            with open(self.path, "r+b") as f:
                f.truncate(rep.good_bytes)
                f.flush()
                os.fsync(f.fileno())
            self.warnings.extend(rep.warnings)
        return rep

    # ── 追記 ──────────────────────────────────────────
    def append(self, type: str, /, **fields) -> dict:
        if not isinstance(type, str) or not _TYPE_RE.match(type):
            raise ValueError(f"不正なイベント種別です: {type!r}")
        clash = _RESERVED.intersection(fields)
        if clash:
            raise ValueError(f"予約済みフィールドは指定できません: {sorted(clash)}")
        with self._mutex:
            if self._closed:
                raise JournalError("closeされたjournalには書き込めません")
            if self._broken:
                raise JournalWriteError("以前の書込み失敗により、このjournalは使用できません")
            event = {
                "event_id": new_id("evt"),
                "schema_version": SCHEMA_VERSION,
                "run_id": self.run_id,
                "seq": self._seq + 1,
                "ts": datetime.now().isoformat(timespec="milliseconds"),
                "type": type,
                "prev_hash": self._prev_hash,
            }
            event.update(_mask(fields, self._known))
            raw = json.dumps(event, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
            size = len(raw) + 1
            if type not in UNCAPPED_TYPES and (
                    self._seq >= self.max_events or self._bytes + size > self.max_bytes):
                raise JournalFull(
                    f"journalの上限に達しました(events={self._seq}, bytes={self._bytes})")
            try:
                self._file.write(raw + b"\n")
                self._file.flush()
                os.fsync(self._file.fileno())
            except OSError as e:
                self._broken = True
                raise JournalWriteError(f"journalへの書込みに失敗しました: {e}") from e
            self._seq += 1
            self._prev_hash = _line_hash(raw)
            self._bytes += size
            return event

    @property
    def event_count(self) -> int:
        return self._seq

    def close(self) -> None:
        with self._mutex:
            if self._closed:
                return
            self._closed = True
            try:
                self._file.close()
            finally:
                self._release_lock()

    def __enter__(self) -> "RunJournal":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
