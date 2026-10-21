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
    """post_form=False でPOSTフォームを持たない版、external_url で外部originへのリンク/フォームを
    含む版(範囲外送信の検査用canaryと組み合わせる)を作れる。既定は特性化試験の基準構成。"""

    def __init__(self, *, post_form: bool = True, external_url: str | None = None, auth: bool = False):
        self.post_form = post_form
        self.external_url = external_url
        self.auth = auth
        self.cookies_seen: list[str] = []      # 受信したCookieヘッダー(認証情報が送られたかの検査用)
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
                    if self.headers.get("Cookie"):
                        outer.cookies_seen.append(self.headers.get("Cookie"))
                return u

            def _user(self):
                """Cookie 'sid=TOK_<NAME>_...' から利用者名を返す(認証fixture用)。無ければ None。"""
                for part in (self.headers.get("Cookie") or "").split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == "sid" and v.startswith("TOK_"):
                        return v.split("_")[1].lower()
                return None

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
                             '<a href="/safe?page=1">safe</a> <a href="/escaped?q=hi">escaped</a> ')
                    if outer.auth:
                        body += '<a href="/account?id=1">account</a>'
                    if outer.post_form:
                        body += '<a href="/guestbook">guestbook</a>'
                    if outer.external_url:
                        ext = outer.external_url.rstrip("/")
                        body += (f'<a href="{ext}/x?q=1">external</a>'
                                 f'<form method="POST" action="{ext}/post"><input name="z" value="1"></form>')
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
                elif outer.auth and u.path == "/me":
                    user = self._user()
                    body += (f"Hello {user}" if user else
                             '<form method="POST" action="/login"><input name="u">'
                             '<input type="password" name="p"></form>')
                elif outer.auth and u.path == "/account":
                    user = self._user()
                    owners = {"1": "alice", "2": "bob"}
                    if not user:
                        body += ('<form method="POST" action="/login"><input name="u">'
                                 '<input type="password" name="p"></form>')
                    else:   # 意図的なIDOR: 所有者を検査しない(誰でも任意のidを取得できる)
                        body += (f"Account {pid or '1'} owner={owners.get(pid or '1', '?')} "
                                 + "private-note " * 20)
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
