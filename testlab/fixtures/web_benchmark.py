"""WEB FUZZ 検出品質の評価用fixture(P2.1)。脆弱な例と、現行の検出が誤りやすい「正常例・罠」を含む。

127.0.0.1のみ・標準ライブラリのみ・決定論的。正解は testlab/benchmark/ground_truth_web_fuzz.json。
認証はCookie `sid=TOK_<NAME>_...` で、利用者は alice / bob の2人。実在サービスには使わない。
各ページは "/" からリンクされ、クロールで注入点が見つかる。全リクエストを記録する。
"""
from __future__ import annotations
import html
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

TOKENS = {"alice": "TOK_ALICE_bench01", "bob": "TOK_BOB_bench02"}

_LINKS = ["/search?q=hi", "/raw?q=hi", "/item?id=1", "/doc-sqlerr?id=1", "/greet?name=guest",
          "/results?q=ab", "/download?file=readme.txt", "/docs?file=a.txt",
          "/account?id=1", "/profile?id=1", "/public?id=5", "/ticket?id=7", "/order?id=9",
          "/escaped?q=hi", "/safe?page=1"]


class BenchmarkServer:
    def __init__(self):
        self.requests: list[tuple[str, str, str, str]] = []
        self._lock = threading.Lock()
        outer = self

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _user(self):
                for part in (self.headers.get("Cookie") or "").split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == "sid" and v.startswith("TOK_"):
                        return v.split("_")[1].lower()
                return None

            def _reply(self, text, ctype="text/html", code=200):
                data = text.encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                u = urlparse(self.path)
                with outer._lock:
                    outer.requests.append(("GET", u.path, u.query, ""))
                qs = {k: v[0] for k, v in parse_qs(u.query).items()}
                q, pid, name = qs.get("q", ""), qs.get("id", ""), qs.get("name", "")
                user = self._user()
                p = u.path
                if p == "/":
                    return self._reply("<html><body>" + " ".join(f'<a href="{l}">{l}</a>' for l in _LINKS)
                                       + "</body></html>")
                # ── XSS ──
                if p == "/search":            # 脆弱: 未エスケープ反射(text/html)
                    return self._reply("<html><body>Results for: " + q + "</body></html>")
                if p == "/escaped":           # 正常: エスケープ済み
                    return self._reply("<html><body>Results for: " + html.escape(q) + "</body></html>")
                if p == "/raw":               # 罠: 反射するがtext/plain(ブラウザで実行されない)
                    return self._reply("Echo: " + q, ctype="text/plain")
                # ── SQLi ──
                if p == "/item":              # 脆弱: 単一引用符でDBエラー署名
                    if "'" in pid:
                        return self._reply("<html><body>You have an error in your SQL syntax near '"
                                           "</body></html>")
                    return self._reply("<html><body>Item " + html.escape(pid) + "</body></html>")
                if p == "/doc-sqlerr":        # 罠: 常にエラー文言を含む静的な解説ページ(入力と無関係)
                    return self._reply("<html><body>Doc: a common message is 'You have an error in your "
                                       "SQL syntax'. Item " + html.escape(pid) + "</body></html>")
                # ── SSTI ──
                if p == "/greet":             # 脆弱: {{7*7}} を評価
                    shown = name.replace("{{7*7}}", "49").replace("${7*7}", "49") \
                                .replace("#{7*7}", "49").replace("<%= 7*7 %>", "49")
                    return self._reply("<html><body>Hello " + html.escape(shown) + "</body></html>")
                if p == "/results":           # 罠: 入力長×7件と表示するだけ。"{{7*7}}"(7文字)で偶然"49"になる
                    return self._reply(f"<html><body>{len(q) * 7} results</body></html>")
                # ── パストラバーサル ──
                if p == "/download":          # 脆弱: ../ で /etc/passwd 風の内容
                    f = qs.get("file", "")
                    if "../" in f or "..%2f" in f.lower() or "....//" in f:
                        return self._reply("root:x:0:0:root:/root:/bin/bash\n", ctype="text/plain")
                    return self._reply("README", ctype="text/plain")
                if p == "/docs":              # 罠: 常にroot:x:0:0:を含む解説(入力と無関係)
                    return self._reply("<html><body>Example: root:x:0:0:root:/root:/bin/bash</body></html>")
                # ── アクセス制御(IDOR)。要ログイン ──
                if p in ("/account", "/profile", "/public", "/ticket", "/order"):
                    if not user and p != "/public":
                        return self._reply('<html><body><form method="POST" action="/login"><input name="u">'
                                           '<input type="password" name="p"></form></body></html>')
                    owners = {"1": "alice", "2": "bob", "7": "alice", "9": None}
                    if p == "/account":       # 脆弱: 所有者を検査しない
                        return self._reply(f"<html><body>Account {html.escape(pid)} owner={owners.get(pid)} "
                                           + "private-note " * 20 + "</body></html>")
                    if p == "/profile":       # 正常: 所有者以外は403
                        if owners.get(pid) != user:
                            return self._reply("Forbidden", code=403)
                        return self._reply(f"<html><body>Profile {html.escape(pid)} of {user} " + "note " * 30 + "</body></html>")
                    if p == "/public":        # 罠: 公開オブジェクト(誰が読んでも同じ。期待上は許可)
                        return self._reply("<html><body>Public notice " + "lorem " * 30 + "</body></html>")
                    if p == "/ticket":        # 脆弱: 他人のチケットが読める(内容は別人でも長さが近い)
                        return self._reply(f"<html><body>Ticket {html.escape(pid)} owner=alice " + "detail " * 25
                                           + "</body></html>")
                    if p == "/order":         # 罠: 閲覧者ごとの注文を返す(別内容・同じ長さ。正常な動作)
                        return self._reply(f"<html><body>Orders of {user}: " + "item " * 30 + "</body></html>")
                if p == "/safe":
                    return self._reply("<html><body>Static page</body></html>")
                return self._reply("Not found", code=404)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode() if length else ""
                u = urlparse(self.path)
                with outer._lock:
                    outer.requests.append(("POST", u.path, u.query, raw))
                self._reply("ok")

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._srv.server_address[1]}/"

    def start(self) -> "BenchmarkServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()

    def request_counter(self) -> Counter:
        with self._lock:
            return Counter(self.requests)

    def __enter__(self) -> "BenchmarkServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
