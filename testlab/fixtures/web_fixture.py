"""WEB FUZZ 評価用の決定論的なローカルfixtureサーバー（127.0.0.1のみ・標準ライブラリのみ）。

全リクエストを記録する（メソッド・パス・クエリ・本文）。実在サービスには使わない。
ground truth は testlab/ground_truth.json（P2.1と共用）。
"""
from __future__ import annotations
import html
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class FixtureServer:
    def __init__(self):
        self.requests: list[tuple[str, str, str, str]] = []  # (method, path, query, body)
        self._lock = threading.Lock()
        outer = self

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _record(self, body: str = ""):
                u = urlparse(self.path)
                with outer._lock:
                    outer.requests.append((self.command, u.path, u.query, body))
                return u

            def _reply(self, text: str, ctype: str = "text/html"):
                data = text.encode()
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                u = self._record()
                qs = parse_qs(u.query)
                q = qs.get("q", [""])[0]
                pid = qs.get("id", [""])[0]
                body = "<html><body>"
                if u.path == "/":
                    body += ('<a href="/search?q=hi">search</a> <a href="/item?id=1">item</a> '
                             '<a href="/safe?page=1">safe</a> <a href="/escaped?q=hi">escaped</a> '
                             '<a href="/guestbook">guestbook</a>')
                elif u.path == "/search":
                    body += "Results for: " + q                        # 未エスケープ反射 -> XSS
                elif u.path == "/item":
                    if "'" in pid:
                        body += "You have an error in your SQL syntax near '"  # -> SQLI
                    else:
                        body += "Item " + html.escape(pid)
                elif u.path == "/safe":
                    body += "Static page"                               # 入力を使わない正常例
                elif u.path == "/escaped":
                    body += "Results for: " + html.escape(q)            # エスケープ済みの正常例
                elif u.path == "/guestbook":
                    body += ('<form method="POST" action="/comment">'
                             '<input name="text" value="hello"><input type="submit"></form>')
                body += "</body></html>"
                self._reply(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode() if length else ""
                u = self._record(raw)
                text = parse_qs(raw).get("text", [""])[0]
                if u.path == "/comment":
                    self._reply("<html><body>Saved: " + text + "</body></html>")  # POST反射 -> XSS
                else:
                    self._reply("<html><body>ok</body></html>")

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._srv.server_address[1]}/"

    def start(self) -> "FixtureServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()

    def request_counter(self) -> Counter:
        with self._lock:
            return Counter(self.requests)

    def count(self, method: str | None = None, path: str | None = None) -> int:
        with self._lock:
            return sum(1 for m, p, _q, _b in self.requests
                       if (method is None or m == method) and (path is None or p == path))

    def __enter__(self) -> "FixtureServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
