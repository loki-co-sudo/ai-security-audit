"""プロセス間の排他ロック(非ブロッキング)。POSIXは flock、Windowsは msvcrt.locking の先頭1バイト。"""
from __future__ import annotations
import os

try:  # POSIX
    import fcntl as _fcntl
    _msvcrt = None
except ImportError:  # Windows
    _fcntl = None
    import msvcrt as _msvcrt


class LockBusy(OSError):
    """別のプロセス(またはfd)が既にロックを保持している。"""


def acquire(path: str) -> int:
    """ロック用ファイルを開いて排他ロックを取る。取れなければ LockBusy(fdは閉じる)。"""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if _fcntl is not None:
            _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        else:
            os.lseek(fd, 0, os.SEEK_SET)
            _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
    except OSError as e:
        os.close(fd)
        raise LockBusy(str(e)) from e
    return fd


def release(fd: int) -> None:
    """ロックを解放してfdを閉じる(異常終了時はOSがfdを閉じて解放する)。"""
    try:
        if _fcntl is not None:
            _fcntl.flock(fd, _fcntl.LOCK_UN)
        else:
            os.lseek(fd, 0, os.SEEK_SET)
            _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
    except OSError:
        pass
    os.close(fd)
