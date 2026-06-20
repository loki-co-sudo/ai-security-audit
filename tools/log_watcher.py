"""
tools/log_watcher.py — ログファイル監視・行ストリーム

watchdog でファイル変更を検知し、新着行をジェネレータで生成する。
"""

from __future__ import annotations
import os
import time
from typing import Callable, Generator


class LogWatcher:
    """
    ログファイルを末尾から継続的に読み込むジェネレータ。

    - watch_mode=True : ファイル末尾を追跡し続ける（tailf相当）
    - single_pass=True: ファイルを1回通して全行を返す
    """

    def __init__(self, path: str):
        self.path = path

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
        if not os.path.isfile(self.path):
            raise FileNotFoundError(f"Log file not found: {self.path}")

        if single_pass:
            yield from self._read_all()
            return

        # シーク位置をファイル末尾に初期化（既存行はスキップ）
        with open(self.path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)  # EOF
            position = f.tell()

        while True:
            if stop_fn and stop_fn():
                return
            try:
                with open(self.path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(position)
                    new_lines = f.readlines()
                    position  = f.tell()
                for line in new_lines:
                    if stop_fn and stop_fn():
                        return
                    yield line
            except (FileNotFoundError, OSError):
                pass  # ローテーション対応: ファイルが一時的に消えても継続
            time.sleep(interval)

    def _read_all(self) -> Generator[str, None, None]:
        """ファイル全体を1行ずつyieldする（single_pass用）。"""
        with open(self.path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                yield line

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
