"""
tools/log_watcher.py — ログファイル監視・行ストリーム

ファイル末尾をポーリング（tailf相当）で追跡し、新着行をジェネレータで生成する。
外部依存なし（標準ライブラリのみ）。
"""

from __future__ import annotations
import gzip
import json
import os
import re
import select
import shutil
import subprocess
import tempfile
import time
import zlib
from typing import Callable, Generator

_IP_KEYS = ("remote_addr", "remote_ip", "client_ip", "clientip", "src_ip", "ip", "host")
_MAX_TEXT = 4000
_MAX_DEPTH = 3
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024    # gzip展開後の読み取り上限(圧縮爆弾対策)
_MAX_LINE_BYTES = 1024 * 1024            # 1行の上限(改行の無い巨大データでメモリを使い切らない)
JOURNAL_PASS_LINES = 10000               # journaldの1回通しで読む直近の件数
_JOURNAL_UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_@.\-]{0,99}")


def parse_journal_target(target: str) -> str | None:
    """`journald` / `journald:UNIT` ならunit(全体は空文字)を返し、それ以外のパスはNone。unit不正はValueError。

    unitは`journalctl -u`の引数になるため、先頭が英数字で長さ・文字種を限定する(`-`始まりのオプション注入を防ぐ)。
    """
    if target == "journald":
        return ""
    if target.startswith("journald:"):
        unit = target[len("journald:"):]
        if not _JOURNAL_UNIT.fullmatch(unit):
            raise ValueError("journaldのunit名が不正です(英数字・: _ @ . -、100文字以内)")
        return unit
    return None


def _flatten(obj, prefix: str, out: list[str], depth: int = 0) -> None:
    items = obj.items() if isinstance(obj, dict) else enumerate(obj[:20])
    for k, v in items:
        if len(out) > 200:
            return
        if isinstance(v, (dict, list)) and depth < _MAX_DEPTH:
            _flatten(v, f"{prefix}{k}.", out, depth + 1)
        else:
            out.append(f"{prefix}{k}={v}")


def normalize_log_line(line: str) -> tuple[str, str]:
    """(分類に使うテキスト, 問題の種別)。問題が無ければ種別は空文字。

    '{'で始まる行はJSONLとして解釈し、全スカラー値を 'key=value' に平坦化する(攻撃ペイロードがどのフィールドにあっても
    既存のシグネチャ検知に掛かる)。IPらしいキーがあれば先頭へ置く。JSONとして不正、またはオブジェクトでない行は
    **捨てずに生テキストのまま**検知へ回し、種別 'invalid_json' を返す(不正な行に紛れた攻撃を見逃さないため)。
    """
    s = line.strip()
    if not s.startswith("{"):
        return s, ""
    try:
        obj = json.loads(s)
    except ValueError:
        return s, "invalid_json"
    if not isinstance(obj, dict):
        return s, "invalid_json"
    parts: list[str] = []
    msg = obj.get("MESSAGE")
    if isinstance(msg, list) and msg and all(isinstance(b, int) and 0 <= b < 256 for b in msg[:_MAX_TEXT]):
        obj = {**obj, "MESSAGE": bytes(msg[:_MAX_TEXT]).decode("utf-8", errors="replace")}   # journaldの非UTF-8メッセージ
    if isinstance(obj.get("MESSAGE"), str):
        parts.append(f"MESSAGE={obj['MESSAGE']}")      # 本文を先頭へ(IP抽出・表示で他フィールドより優先)
        obj = {k: v for k, v in obj.items() if k != "MESSAGE"}
    _flatten(obj, "", parts)
    ip = next((str(obj[k]) for k in _IP_KEYS if isinstance(obj.get(k), (str, int))), "")
    text = " ".join(([ip] if ip else []) + parts)
    return text[:_MAX_TEXT], ""


class LogWatcher:
    """
    ログファイルを末尾から継続的に読み込むジェネレータ。

    - watch_mode=True : ファイル末尾を追跡し続ける（tailf相当）
    - single_pass=True: ファイルを1回通して全行を返す

    実ログ対応(P4.3): ファイル識別子(dev, inode)とサイズを追跡する。
    - 完結していない最終行(改行なし)は次回まで保持し、書き込み途中の行を分割して返さない。
    - rename-create(ローテーション): 旧ファイルを開いたまま残りを読み切ってから、新ファイルを先頭から読む。
    - copytruncate / 縮小: サイズが読み取り位置を下回ったら先頭から読み直す。
    - ファイルが一時的に無い間は待機して継続する。

    取りこぼし得る条件(exactly-onceは保証しない): 旧ファイルを最後に読んでからrename/truncateまでに書かれ、かつ
    copytruncateでコピー前に消えた行、ポーリング間隔内に複数回ローテーションされた中間ファイル、
    縮小後に元と同じサイズまで書き戻された場合(縮小を検知できない)。
    `stats` に件数を残す(ローテーション/縮小/一時不在/不完全行の破棄・フラッシュ)。

    gzip(回転済みアーカイブ): 拡張子が`.gz`のパスは追跡できないため、watch_modeでも1回通しで全行を読む
    (`archive=True`)。展開後256MiB・1行1MiBを上限とし、超過・破損・途中切れは`stats`へ記録して読めた分で終了する
    (`archive_truncated`/`archive_error`)。呼び出し側はこれをpartial扱いにする。
    """

    def __init__(self, path: str):
        self.path = path
        self.journal = parse_journal_target(path)          # None=通常ファイル / ""=全体 / unit名
        self.archive = self.journal is None and path.lower().endswith(".gz")
        self.stats = {"lines": 0, "rotations": 0, "truncations": 0, "missing_polls": 0,
                      "partial_flushed": 0, "partial_discarded": 0, "archive_truncated": 0, "archive_error": "", "journal_error": ""}

    def watch(
        self,
        interval: float = 1.0,
        stop_fn:  Callable[[], bool] | None = None,
        single_pass: bool = False,
    ) -> Generator[str, None, None]:
        """
        新着行をyieldするジェネレータ。
        stop_fn() が True を返すと終了する。
        """
        if self.journal is not None:
            yield from self._read_journal(follow=not single_pass, interval=interval, stop_fn=stop_fn)
            return
        if not os.path.isfile(self.path):
            raise FileNotFoundError(f"Log file not found: {self.path}")

        if single_pass or self.archive:
            yield from (self._read_gzip() if self.archive else self._read_all())
            return

        fh = open(self.path, "rb")
        try:
            fh.seek(0, os.SEEK_END)         # 既存行はスキップ
            ident = self._ident(os.fstat(fh.fileno()))
            carry = b""
            while True:
                if stop_fn and stop_fn():
                    return
                try:
                    st = os.stat(self.path)
                except OSError:
                    st = None
                    self.stats["missing_polls"] += 1
                if st is not None and self._ident(st) != ident:
                    # rename-create: 新ファイルを開けてから、旧ファイルの残りを読み切る。
                    # 不完全な最終行は旧ファイルがもう伸びないので確定して返す
                    try:
                        new_fh = open(self.path, "rb")
                    except OSError:
                        self.stats["missing_polls"] += 1
                        time.sleep(interval)
                        continue
                    data, carry = self._drain(fh, carry)
                    for line in data:
                        yield from self._emit(line, stop_fn)
                    if carry:
                        self.stats["partial_flushed"] += 1
                        yield from self._emit(carry + b"\n", stop_fn)
                    carry = b""
                    fh.close()
                    fh = new_fh
                    ident = self._ident(os.fstat(fh.fileno()))
                    self.stats["rotations"] += 1
                elif st is not None and st.st_size < fh.tell():
                    # copytruncate / 縮小: 先頭から読み直す。保持していた不完全行は元データが消えたため破棄
                    if carry:
                        self.stats["partial_discarded"] += 1
                    carry = b""
                    fh.seek(0)
                    self.stats["truncations"] += 1
                data, carry = self._drain(fh, carry)       # 一時不在の間も、開いたままの旧ファイルの残りは読める
                for line in data:
                    yield from self._emit(line, stop_fn)
                if stop_fn and stop_fn():
                    return
                time.sleep(interval)
        finally:
            fh.close()

    @staticmethod
    def _ident(st) -> tuple[int, int]:
        return (st.st_dev, st.st_ino)

    @staticmethod
    def _drain(fh, carry: bytes) -> tuple[list[bytes], bytes]:
        """現在位置から読めるだけ読み、完結した行(改行付き)と、未完の末尾を返す。"""
        chunk = fh.read()
        if not chunk:
            return [], carry
        buf = carry + chunk
        parts = buf.split(b"\n")
        return [p + b"\n" for p in parts[:-1]], parts[-1]

    def _emit(self, raw: bytes, stop_fn):
        if stop_fn and stop_fn():
            return
        self.stats["lines"] += 1
        yield raw.decode("utf-8", errors="replace")

    def _read_all(self) -> Generator[str, None, None]:
        """ファイル全体を1行ずつyieldする（single_pass用）。"""
        with open(self.path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                self.stats["lines"] += 1
                yield line

    def _read_journal(self, follow: bool, interval: float, stop_fn) -> Generator[str, None, None]:
        """`journalctl -o json`の出力を行として返す。固定引数のsubprocess(shell無し)で、読み取り専用。

        1回通しは直近JOURNAL_PASS_LINES件、追跡(follow)は開始後の新着のみ。journalctlが無い/権限不足/異常終了は
        statsのjournal_errorに残して終了する(エラーを検出0件の成功にしない)。
        """
        exe = shutil.which("journalctl")
        if not exe:
            self.stats["journal_error"] = "journalctlが見つかりません"
            return
        cmd = [exe, "--no-pager", "-o", "json"] + (["-u", self.journal] if self.journal else [])
        cmd += ["-f", "-n", "0"] if follow else ["-n", str(JOURNAL_PASS_LINES)]
        with tempfile.TemporaryFile() as err:
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err, stdin=subprocess.DEVNULL)
            except OSError as e:
                self.stats["journal_error"] = f"journalctlを起動できません({type(e).__name__})"
                return
            buf = b""
            try:
                fd = proc.stdout.fileno()
                while True:
                    if stop_fn and stop_fn():
                        return
                    ready, _, _ = select.select([fd], [], [], interval if follow else 1.0)
                    if not ready:
                        if proc.poll() is not None:
                            break
                        continue
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    buf += chunk
                    *lines, buf = buf.split(b"\n")
                    for raw in lines:
                        if len(raw) > _MAX_LINE_BYTES:
                            self.stats["archive_truncated"] += 1
                            continue
                        yield from self._emit(raw + b"\n", stop_fn)
                    if len(buf) > _MAX_LINE_BYTES:
                        self.stats["archive_truncated"] += 1
                        buf = b""
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                proc.stdout.close()
            if buf.strip():
                yield from self._emit(buf + b"\n", stop_fn)
            rc = proc.returncode
            err.seek(0)
            msg = err.read(400).decode("utf-8", errors="replace").strip().replace("\n", " ")
            if (rc not in (0, None, -15)) or "insufficient permissions" in msg.lower():
                self.stats["journal_error"] = (msg or f"終了コード{rc}")[:200]

    def _read_gzip(self) -> Generator[str, None, None]:
        """gzipアーカイブを1行ずつyieldする。上限超過・破損・途中切れは例外にせずstatsへ記録して終了する。"""
        total = 0
        try:
            with gzip.open(self.path, "rb") as f:
                while True:
                    raw = f.readline(_MAX_LINE_BYTES + 1)
                    if not raw:
                        return
                    total += len(raw)
                    if len(raw) > _MAX_LINE_BYTES or total > MAX_ARCHIVE_BYTES:
                        self.stats["archive_truncated"] += 1
                        return
                    self.stats["lines"] += 1
                    yield raw.decode("utf-8", errors="replace")
        except (OSError, EOFError, zlib.error) as e:      # BadGzipFile(OSError)・途中切れ(EOFError)・破損(zlib.error)
            self.stats["archive_error"] = type(e).__name__

    @staticmethod
    def generate_sample_log(path: str, entries: int = 200) -> None:
        """
        テスト用サンプルログを生成する。
        攻撃パターンを含む Apache-like ログ。
        """
        import random
        from datetime import datetime, timedelta

        ips     = ["192.168.1.10", "10.0.0.5", "203.0.113.42", "198.51.100.77"]
        methods = ["GET", "POST", "PUT"]
        normal_paths = ["/", "/index.html", "/about", "/contact", "/login",
                        "/static/app.js", "/api/users", "/api/products"]
        attack_lines = [
            "GET /index.php?id=1 UNION SELECT 1,2,3,username,password FROM users-- HTTP/1.1",
            "POST /login.php HTTP/1.1 | username=admin&password=' OR '1'='1",
            "GET /../../../etc/passwd HTTP/1.1",
            "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1",
            "GET /admin/config.php HTTP/1.1",
            "GET /.env HTTP/1.1",
            "GET /.git/HEAD HTTP/1.1",
            "POST /api/exec?cmd=cat%20/etc/passwd HTTP/1.1",
            "GET /wp-admin/admin.php HTTP/1.1",
            "User-Agent: sqlmap/1.7.8",
            "GET /xmlrpc.php HTTP/1.1",
        ]

        now = datetime.now()
        lines = []
        for i in range(entries):
            ts  = (now - timedelta(seconds=(entries - i) * 3)).strftime("%d/%b/%Y:%H:%M:%S +0000")
            ip  = random.choice(ips)
            method = random.choice(methods)
            status = random.choice([200, 200, 200, 301, 404, 500])

            if i % 20 == 0 and attack_lines:
                req    = random.choice(attack_lines)
                status = 200
            else:
                req = f"{random.choice(methods)} {random.choice(normal_paths)} HTTP/1.1"

            lines.append(f'{ip} - - [{ts}] "{req}" {status} {random.randint(100,5000)}')

        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
