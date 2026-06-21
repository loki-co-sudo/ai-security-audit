"""
testlab/vuln_server.py — ローカル検証用の「意図的に脆弱な」ダミーWebサイト

このプロジェクトのツール（WEB FUZZ / web_prober）が検出する脆弱性を、
わざと再現するための練習用ターゲット。見た目は普通のショップサイト風だが、
各所に脆弱性を仕込んである。標準ライブラリのみで動作し、127.0.0.1 のみに
バインドするため外部には公開されない（安全）。

⚠️ あくまで自分のPC内での学習・動作確認専用。実在サービスには使わないこと。

起動:
    python testlab/vuln_server.py            # http://127.0.0.1:8000
    python testlab/vuln_server.py 8081       # ポート指定

ツールでの使い方:
    WEB FUZZ の TARGET 欄に  http://127.0.0.1:8000  を入力して「FUZZ ▶」。
    ブラウザで  http://127.0.0.1:8000  を開けばサイトの見た目も確認できる。

再現する脆弱性:
    - SQLインジェクション兆候 / 反射型XSS / パストラバーサル / SSTI
    - セキュリティヘッダ欠如 / 機微パス露出 / 安全でないCookie / 技術スタック露出
"""
from __future__ import annotations
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# 200 を返す（＝露出している）機微パス
_EXPOSED_PATHS = {
    "/robots.txt":    "User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n",
    "/.env":          "DB_PASSWORD=supersecret\nAPI_KEY=sk-test-leaked-1234\n",
    "/.git/HEAD":     "ref: refs/heads/main\n",
    "/.htaccess":     "AuthType Basic\nRequire valid-user\n",
    "/admin":         "<html><body><h1>Admin Panel</h1></body></html>",
    "/backup.zip":    "PK\x03\x04 (dummy backup archive)",
    "/api":           '{"status":"ok","version":"1.0"}',
    "/phpinfo.php":   "<html><body><h1>PHP Version 7.4.3</h1></body></html>",
    "/server-status": "<html><body>Apache Server Status</body></html>",
}

_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Meiryo,sans-serif;background:#f4f6f9;color:#222;line-height:1.6}
.nav{display:flex;align-items:center;gap:20px;background:#1f2a44;color:#fff;padding:12px 28px;flex-wrap:wrap}
.brand{font-size:20px;font-weight:bold;color:#5cc8ff}
.nav nav{display:flex;gap:16px}
.nav a{color:#dfe7f2;text-decoration:none;font-size:14px}
.nav a:hover{color:#5cc8ff}
.nav form.search{margin-left:auto;display:flex;gap:6px}
.nav input{padding:6px 10px;border:0;border-radius:4px;width:200px}
.nav button{padding:6px 14px;border:0;border-radius:4px;background:#5cc8ff;color:#06263a;font-weight:bold;cursor:pointer}
main{max-width:960px;margin:28px auto;padding:0 20px}
.hero{background:linear-gradient(135deg,#1f2a44,#2e4a7a);color:#fff;padding:40px;border-radius:12px;margin-bottom:24px}
.hero h1{font-size:28px;margin-bottom:8px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:18px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.card h3{font-size:16px;margin-bottom:6px}
.card a{color:#2563eb;text-decoration:none}
.price{color:#e85d04;font-weight:bold;margin-top:8px}
.panel{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:22px;margin-top:16px}
.result{background:#0f1623;color:#cfe;padding:14px;border-radius:8px;font-family:Consolas,monospace;font-size:13px;white-space:pre-wrap;margin-top:10px}
.form-row{margin:10px 0}
.form-row label{display:block;font-size:13px;color:#555;margin-bottom:4px}
.form-row input{width:100%;padding:8px 10px;border:1px solid #cbd5e1;border-radius:4px}
.btn{margin-top:10px;padding:9px 18px;border:0;border-radius:5px;background:#2563eb;color:#fff;font-weight:bold;cursor:pointer}
footer{max-width:960px;margin:30px auto;padding:18px 20px;color:#888;font-size:12px;border-top:1px solid #e2e8f0}
"""

_NAV = """
<header class="nav">
  <div class="brand">🛒 DemoShop</div>
  <nav>
    <a href="/">ホーム</a>
    <a href="/products">商品一覧</a>
    <a href="/blog?topic=news">ブログ</a>
    <a href="/greet?name=guest">マイページ</a>
    <a href="/login">ログイン</a>
  </nav>
  <form class="search" action="/search" method="GET">
    <input type="text" name="q" placeholder="商品を検索...">
    <button type="submit">検索</button>
  </form>
</header>
"""


def _page(title: str, body: str) -> str:
    return (
        "<!DOCTYPE html><html lang=\"ja\"><head><meta charset=\"utf-8\">"
        f"<title>{title} - DemoShop</title>"
        "<script src=\"/static/jquery.min.js\"></script>"
        "<link rel=\"stylesheet\" href=\"/wp-content/themes/demoshop/style.css\">"
        f"<style>{_CSS}</style></head><body>"
        f"{_NAV}<main>{body}</main>"
        "<footer>© 2026 DemoShop — これは学習・動作確認用のダミーサイトです（実在しません）。</footer>"
        "</body></html>"
    )


_PRODUCTS = [
    (1, "ワイヤレスイヤホン", "¥4,980"),
    (2, "メカニカルキーボード", "¥8,200"),
    (3, "USB-C ハブ 7in1", "¥3,480"),
    (4, "ノートPCスタンド", "¥2,980"),
]


def _home() -> str:
    cards = "".join(
        f'<div class="card"><h3><a href="/product?id={pid}">{name}</a></h3>'
        f'<div class="price">{price}</div></div>'
        for pid, name, price in _PRODUCTS[:3]
    )
    return _page("ホーム",
        '<div class="hero"><h1>DemoShop へようこそ</h1>'
        '<p>テスト用のダミー通販サイトです。商品検索・記事・ログインを試せます。</p></div>'
        '<h2 style="margin-bottom:12px">おすすめ商品</h2>'
        f'<div class="grid">{cards}</div>')


def _products() -> str:
    cards = "".join(
        f'<div class="card"><h3><a href="/product?id={pid}">{name}</a></h3>'
        f'<div class="price">{price}</div></div>'
        for pid, name, price in _PRODUCTS
    )
    return _page("商品一覧", f'<h2 style="margin-bottom:12px">商品一覧</h2><div class="grid">{cards}</div>')


def _vuln_panel(value: str) -> str:
    """入力値に応じて脆弱性の"兆候"を含むパネルHTMLを返す（検出専用の再現）。"""
    sig = []
    # SQLインジェクション: 引用符を含むとDBエラー署名を出す
    if "'" in value or '"' in value:
        sig.append(
            "SQL error: You have an error in your SQL syntax; check the manual "
            f"that corresponds to your MySQL server version near '{value}'"
        )
    # パストラバーサル: ../etc/passwd 風の入力で passwd 風の内容
    if re.search(r"(\.\.[\\/]|etc[\\/]passwd|%2e%2e)", value, re.I):
        sig.append("root:x:0:0:root:/root:/bin/bash\n"
                   "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
    # SSTI: テンプレート式を評価したように 49 を返す
    if re.search(r"(7\s*\*\s*7|\{\{.*?\}\}|\$\{.*?\}|<%=.*?%>|#\{.*?\})", value):
        sig.append("Result: 49")
    out = ""
    if sig:
        out += '<div class="result">' + "\n".join(sig) + "</div>"
    # 反射型XSS: 入力を未エスケープでそのまま反射
    out += f'<div class="result">入力された値: {value}</div>'
    return out


def _detail(title: str, lead: str, value: str) -> str:
    return _page(title,
        f'<div class="panel"><h2>{title}</h2><p>{lead}</p>{_vuln_panel(value)}</div>')


def _login_form(msg: str = "") -> str:
    note = f'<div class="result">{msg}</div>' if msg else ""
    return _page("ログイン",
        '<div class="panel"><h2>ログイン</h2>'
        '<form action="/login" method="POST">'
        '<div class="form-row"><label>ユーザー名</label>'
        '<input type="text" name="username" value=""></div>'
        '<div class="form-row"><label>パスワード</label>'
        '<input type="password" name="password" value=""></div>'
        '<button class="btn" type="submit">ログイン</button>'
        f'</form>{note}</div>')


class VulnHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41"   # 技術スタック露出（Server ヘッダ）
    sys_version = "(Ubuntu)"

    def log_message(self, fmt, *args):
        sys.stdout.write("  %s - %s\n" % (self.address_string(), fmt % args))

    def _respond(self, code: int, body: str, ctype: str = "text/html; charset=utf-8",
                 set_cookie: bool = False) -> None:
        data = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "PHP/7.4.3")   # 技術スタック露出
        if set_cookie:
            # Secure / HttpOnly を付けない安全でない Cookie
            self.send_header("Set-Cookie", "SESSIONID=8f3a2b1c9d; Path=/")
        # ※ Content-Security-Policy / Strict-Transport-Security 等は意図的に未設定
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if path in ("/", ""):
            self._respond(200, _home(), set_cookie=True); return
        if path == "/products":
            self._respond(200, _products()); return
        if path in _EXPOSED_PATHS:
            self._respond(200, _EXPOSED_PATHS[path]); return

        if path == "/search":
            self._respond(200, _detail("検索結果",
                f'「{qs.get("q","")}」の検索結果:', qs.get("q", ""))); return
        if path == "/product":
            self._respond(200, _detail("商品詳細",
                "商品ID の詳細情報:", qs.get("id", ""))); return
        if path == "/blog":
            self._respond(200, _detail("ブログ",
                "トピックの記事一覧:", qs.get("topic", ""))); return
        if path == "/greet":
            self._respond(200, _detail("マイページ",
                "ようこそ:", qs.get("name", ""))); return
        if path == "/login":
            self._respond(200, _login_form()); return

        self._respond(404, _page("404", '<div class="panel"><h2>404 Not Found</h2></div>'))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        fields = {k: v[0] for k, v in parse_qs(raw).items()}
        if urlparse(self.path).path == "/login":
            user = fields.get("username", "")
            self._respond(200, _login_form(f"ログイン失敗: ユーザー {user} は存在しません" + _vuln_panel(user)))
            return
        val = next(iter(fields.values()), "")
        self._respond(200, _detail("結果", "送信内容:", val))


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    httpd = ThreadingHTTPServer(("127.0.0.1", port), VulnHandler)
    print(f"[vuln-lab] http://127.0.0.1:{port}  (Ctrl+C で停止 / 127.0.0.1 のみ)")
    print("[vuln-lab] ブラウザで上記を開けばサイトを確認できます。")
    print("[vuln-lab] ツールの WEB FUZZ の TARGET 欄に上記URLを入力してください。")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[vuln-lab] 停止しました。")
        httpd.shutdown()


if __name__ == "__main__":
    main()
