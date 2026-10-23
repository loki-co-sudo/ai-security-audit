"""評価ハーネスの隔離補助(docs/LOCAL_LAB_EVAL.md §9 ステップ3)。bubblewrap(bwrap)を使う。

  ネットワーク: `--unshare-net` の新しいネットワーク名前空間ではloopbackだけが存在し、外部へ到達できない。
               ハーネス全体をその中で再実行する(`reexec_without_network`)。実LLMはネットワークが要るため併用できない。
  正解データ: 診断ワークフローだけを別プロセス(`tools/lab_worker.py`)で実行し、そのプロセスの見える範囲で
               正解ディレクトリを空のtmpfsで覆う(マウント名前空間)。親(採点側)は正解を読める。
どちらも利用者権限のまま(root・特権不要)。bwrapが無い・使えない環境では明示的に失敗し、黙って隔離なしで続けない。
隔離できているかは、実行時に観測した値(ネットワークIF一覧・正解ディレクトリの見える件数)で記録する。
"""
from __future__ import annotations
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FLAG = "LAB_NET_ISOLATED"


class IsolationError(RuntimeError):
    pass


def bwrap_path() -> str:
    p = shutil.which("bwrap")
    if not p:
        raise IsolationError("bwrap(bubblewrap)が見つかりません。隔離なしでは続行しません。")
    return p


def _base(*extra: str) -> list[str]:
    return [bwrap_path(), "--bind", "/", "/", "--dev", "/dev", "--proc", "/proc", *extra]


def network_state() -> dict:
    """読み取りだけで、現在のネットワーク名前空間のIF一覧を返す(通信はしない)。"""
    try:
        with open("/proc/net/dev", encoding="utf-8") as f:
            ifaces = sorted(line.split(":")[0].strip() for line in f.read().splitlines()[2:] if ":" in line)
    except OSError:
        ifaces = []
    return {"interfaces": ifaces, "loopback_only": bool(ifaces) and set(ifaces) <= {"lo"},
            "wrapper_flag": os.environ.get(ENV_FLAG) == "1"}


def reexec_without_network(argv: list[str]) -> None:
    """この実行を、外部へ到達できないネットワーク名前空間の中で再実行する(戻らない)。"""
    if os.environ.get(ENV_FLAG) == "1":
        return
    cmd = _base("--unshare-net", "--setenv", ENV_FLAG, "1", sys.executable, *argv)
    os.chdir(ROOT)
    os.execv(cmd[0], cmd)


def run_worker(payload: dict, hide_dir: str, timeout: int = 300) -> dict:
    """ワークフローを別プロセスで実行する。hide_dirは子から見て空のtmpfsで覆う。戻り値: 結果dict(+worker_checks)。"""
    cmd = _base("--tmpfs", hide_dir, sys.executable, os.path.join(ROOT, "tools", "lab_worker.py"))
    p = subprocess.run(cmd, input=json.dumps(payload), capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    if p.returncode != 0:
        raise IsolationError(f"隔離ワーカーが失敗しました(code={p.returncode}): {p.stderr[-400:]}")
    try:
        return json.loads(p.stdout)
    except ValueError as e:
        raise IsolationError(f"隔離ワーカーの出力が不正です: {e}") from e
