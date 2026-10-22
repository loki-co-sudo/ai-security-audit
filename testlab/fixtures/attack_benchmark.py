"""ATTACK MODE(偵察)の検出品質評価用fixture(P2.1)。ポート・センシティブパス・ヘッダー・Cookie・技術検出の正解と罠を持つ。

127.0.0.1のみ・標準ライブラリのみ・決定論的。正解は testlab/benchmark/ground_truth_attack.json。
実在サービスには使わない。HTTPは3台: "main"(既知の応答)、"catchall"(どのpathにも同じ200を返すsoft-404の罠)、
"held"(改修後に追加した未見のケース: pathをエコーするsoft-404・小文字のCookie属性・Server/X-Powered-Byによる技術検出)。
"""
from __future__ import annotations
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# main: path → (status, body, extra headers)。ここに無いpathは404
MAIN_ROUTES = {
    "/": (200, "<html><body>lab home. We do not use WordPress or Drupal here.</body></html>", {}),
    "/.env": (200, "APP_ENV=lab\nDEBUG=true\n", {}),
    "/.git/HEAD": (200, "ref: refs/heads/main\n", {}),
    "/admin": (200, "<html><form>login</form></html>", {}),
    "/robots.txt": (200, "User-agent: *\nDisallow: /admin\n", {}),
    "/actuator/health": (200, '{"status":"UP"}', {"Content-Type": "application/json"}),
    "/backup.zip": (403, "forbidden", {}),                       # 存在はするが内容は返さない
    "/api": (301, "", {"Location": "/api/"}),                    # 内容ではなく転送
    "/swagger": (500, "internal error", {}),                     # サーバーエラー(内容ではない)
}
MAIN_HEADERS = {"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"}
MAIN_COOKIES = ["sid=abc123; Path=/; HttpOnly", "pref=dark; Path=/; Secure; HttpOnly"]
CATCHALL_BODY = "<html><body>Sorry, nothing here. Try the search box.</body></html>"

# ポートの役割 → 起動時の挙動。bannerがNoneなら接続を受けるだけで何も送らない
PORT_ROLES = {"ssh_banner": b"SSH-2.0-OpenSSH_8.4\r\n", "ftp_banner": b"220 lab FTP ready\r\n", "silent": None}
CLOSED_ROLES = ("closed_a", "closed_b")


HELD_ROUTES = {
    "/.env": (200, "SECRET=1\n", {}),                          # catch-allの中の実在
    "/admin": (302, "", {"Location": "/login"}),
}
HELD_HEADERS = {"X-Powered-By": "Express"}      # Serverは version_string で1回だけ出す
HELD_COOKIES = ["a=1; Path=/; httponly; secure", "b=2; Path=/"]


class _Http:
    """fallback: "404"=未登録pathは404 / "same"=全pathに同じ200 / "echo"=全pathに要求pathを含む200。"""

    def __init__(self, routes, fallback: str, headers=None, cookies=None, server: str = "nginx/1.18.0"):
        self.requests: list[str] = []
        outer = self

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def version_string(self):        # 標準のServer値(BaseHTTP/…)を連結させない
                return server

            def do_GET(self):
                path = self.path.split("?")[0]
                outer.requests.append(path)
                if path in routes:
                    status, body, extra = routes[path]
                elif fallback == "same":
                    status, body, extra = 200, CATCHALL_BODY, {}
                elif fallback == "echo":
                    status, body, extra = 200, f"<html><body>Not found: {path}</body></html>", {}
                else:
                    status, body, extra = 404, "not found", {}
                data = body.encode()
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                if path == "/":
                    for c in cookies or []:
                        self.send_header("Set-Cookie", c)
                for k, v in extra.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"


class AttackLab:
    """context managerとして使う。main/catchallのHTTP、バナー付きTCP、閉じたポートを用意する。"""

    def __enter__(self):
        self.main = _Http(MAIN_ROUTES, "404", MAIN_HEADERS, MAIN_COOKIES)
        self.catchall = _Http({}, "same", server="lab")
        self.held = _Http(HELD_ROUTES, "echo", HELD_HEADERS, HELD_COOKIES, server="Apache/2.4.41")     # 改修後に追加した未見のケース
        self.servers = {"main": self.main, "catchall": self.catchall, "held": self.held}
        self.listeners: dict[str, socket.socket] = {}
        self._stop = threading.Event()
        self._threads = [srv.thread for srv in self.servers.values()]
        for role, banner in PORT_ROLES.items():
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            s.listen(16)
            s.settimeout(0.2)
            self.listeners[role] = s
            self._threads.append(threading.Thread(target=self._serve, args=(s, banner), daemon=True))
        self.closed_ports = {}
        for role in CLOSED_ROLES:                       # 確保して閉じる(他プロセスが使う競合は理論上あり得る)
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            self.closed_ports[role] = s.getsockname()[1]
            s.close()
        for t in self._threads:
            t.start()
        return self

    def _serve(self, s, banner):
        while not self._stop.is_set():
            try:
                c, _ = s.accept()
            except (socket.timeout, OSError):
                continue
            try:
                if banner:
                    c.sendall(banner)
                c.settimeout(0.3)
                try:
                    c.recv(64)
                except OSError:
                    pass
            finally:
                c.close()

    def __exit__(self, *a):
        self._stop.set()
        for srv in self.servers.values():
            srv.server.shutdown()
        for s in self.listeners.values():
            s.close()
        for t in self._threads:
            t.join(2)

    @property
    def request_count(self) -> int:
        return sum(len(srv.requests) for srv in self.servers.values())

    @property
    def ports(self) -> dict[str, int]:
        return {**{r: s.getsockname()[1] for r, s in self.listeners.items()}, **self.closed_ports}
