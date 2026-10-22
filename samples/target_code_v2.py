"""
samples/target_code_v2.py — 難しめの評価用サンプル(実行しない・ライブラリ呼び出しはスタブ)。

`# [Vn start]`〜`# [Vn end]` は欠陥(vulnerable)、`# [Dn start]`〜`# [Dn end]` は「危なそうに見えるが安全」(decoy)。
正解行範囲はこのマーカーから機械的に作る(testlab/benchmark/ground_truth_audit_v2.json)。評価時はコメントとdocstringを
全て除いた版をLLMへ渡す(行番号は不変)。実在のサービスや秘密値は含まない。
"""
import ast
import hashlib
import hmac
import json
import os
import random
import secrets
import subprocess
import time
import yaml
from urllib.parse import urlparse

import db  # スタブ: db.query(sql, params) / db.get_order(order_id) / db.coupon(code) など

ALLOWED_WEBHOOK_PREFIX = "https://hooks.example.com"
ALLOWED_TABLES = {"orders", "invoices", "shipments"}
REPORT_FORMATS = {"pdf": "--format=pdf", "csv": "--format=csv"}
UPLOAD_DIR = "/srv/uploads"
SECRET_KEY = os.environ["APP_SECRET_KEY"]


# [V1 start] SSRF: 接頭辞の文字列比較は https://hooks.example.com.attacker.net を通す
def register_webhook(user, url):
    if not url.startswith(ALLOWED_WEBHOOK_PREFIX):
        raise ValueError("webhook host not allowed")
    db.query("INSERT INTO webhooks(user_id, url) VALUES (%s, %s)", (user["id"], url))
    return fetch_url(url)


def fetch_url(url):
    import urllib.request
    return urllib.request.urlopen(url, timeout=5).read()
# [V1 end]


# [V2 start] 一括代入: リクエストのJSONを全てそのままDBへ反映する(is_admin / balance も書ける)
def update_profile(user, payload):
    fields = json.loads(payload)
    sets = ", ".join(f"{k} = %s" for k in fields)
    db.query(f"UPDATE users SET {sets} WHERE id = %s", (*fields.values(), user["id"]))
    return {"ok": True}
# [V2 end]


# [V3 start] 関数をまたぐ認可漏れ: 取得ヘルパーが所有者を確認せず、呼び出し側も確認しない
def _load_order(order_id):
    return db.get_order(order_id)


def order_detail(user, order_id):
    order = _load_order(order_id)
    return {"id": order["id"], "items": order["items"], "address": order["address"], "viewer": user["id"]}
# [V3 end]


# [V4 start] 競合: クーポンの利用回数を「確認→加算」の2段階で行い、同時リクエストで上限を超えて使える
def redeem_coupon(user, code):
    coupon = db.coupon(code)
    if coupon["used"] >= coupon["limit"]:
        raise ValueError("coupon exhausted")
    time.sleep(0)
    db.query("UPDATE coupons SET used = used + 1 WHERE code = %s", (code,))
    db.query("INSERT INTO redemptions(user_id, code) VALUES (%s, %s)", (user["id"], code))
    return coupon["discount"]
# [V4 end]


# [V5 start] オープンリダイレクト: "/" 始まりの確認は //attacker.net も通す
def login_redirect(next_url):
    if next_url.startswith("/"):
        return {"status": 302, "location": next_url}
    return {"status": 302, "location": "/home"}
# [V5 end]


# [V6 start] 安全でないデシリアライズ: アップロードされた設定をyaml.Loader(任意のPythonオブジェクトを生成できる)で読む
def import_settings(user, uploaded_text):
    settings = yaml.load(uploaded_text, Loader=yaml.Loader)
    db.query("UPDATE users SET settings = %s WHERE id = %s", (json.dumps(settings, default=str), user["id"]))
    return settings
# [V6 end]


# [V7 start] 推測可能な確認コード: 4桁の乱数を回数制限なしで検証する
def send_phone_code(user):
    code = str(random.randint(1000, 9999))
    db.query("UPDATE users SET phone_code = %s WHERE id = %s", (code, user["id"]))
    return code


def verify_phone_code(user, submitted):
    row = db.query("SELECT phone_code FROM users WHERE id = %s", (user["id"],))
    return bool(row) and row[0]["phone_code"] == submitted
# [V7 end]


# [V8 start] 署名の比較に == を使い、さらに署名対象にタイムスタンプ(有効期限)が含まれていない
def make_download_token(user_id, path):
    sig = hmac.new(SECRET_KEY.encode(), f"{user_id}:{path}".encode(), hashlib.sha256).hexdigest()
    return f"{user_id}:{path}:{sig}"


def check_download_token(token):
    user_id, path, sig = token.split(":", 2)
    expected = hmac.new(SECRET_KEY.encode(), f"{user_id}:{path}".encode(), hashlib.sha256).hexdigest()
    if sig == expected:
        return user_id, path
    raise PermissionError("bad token")
# [V8 end]


# [D1 start] 安全(decoy): f文字列でSQLを組むが、テーブル名は固定の許可集合からのみ、値は全てバインド変数
def list_records(user, table, status):
    if table not in ALLOWED_TABLES:
        raise ValueError("unknown table")
    return db.query(f"SELECT * FROM {table} WHERE owner_id = %s AND status = %s", (user["id"], status))
# [D1 end]


# [D2 start] 安全(decoy): subprocessだがshell=False・引数は固定辞書のみ・ユーザー入力は選択キーとして使うだけ
def render_report(user, fmt, report_id):
    flag = REPORT_FORMATS.get(fmt)
    if flag is None:
        raise ValueError("unsupported format")
    out = os.path.join(UPLOAD_DIR, f"report-{int(report_id)}.{fmt}")
    subprocess.run(["/usr/local/bin/render", flag, "--id", str(int(report_id)), "--out", out], check=True, shell=False)
    return out
# [D2 end]


# [D3 start] 安全(decoy): md5は認証ではなくキャッシュキー(内容の同一性)にだけ使う
def cache_key(payload):
    return hashlib.md5(json.dumps(payload, sort_keys=True).encode()).hexdigest()
# [D3 end]


# [D4 start] 安全(decoy): 保存先を絶対パスへ解決し、UPLOAD_DIR配下であることを確認してから書く
def save_upload(user, filename, data):
    safe_name = os.path.basename(filename)
    target = os.path.realpath(os.path.join(UPLOAD_DIR, str(user["id"]), safe_name))
    root = os.path.realpath(os.path.join(UPLOAD_DIR, str(user["id"])))
    if os.path.commonpath([root, target]) != root:
        raise PermissionError("path escapes upload dir")
    with open(target, "wb") as f:
        f.write(data)
    return target
# [D4 end]


# [D5 start] 安全(decoy): ast.literal_eval はリテラルのみ評価し、任意コードを実行しない
def parse_filter(expr):
    value = ast.literal_eval(expr)
    if not isinstance(value, (int, str, list, tuple)):
        raise ValueError("unsupported filter")
    return value
# [D5 end]


# [D6 start] 安全(decoy): セキュリティ用途の乱数は secrets、定数時間比較は compare_digest
def new_session_token():
    return secrets.token_urlsafe(32)


def tokens_equal(a, b):
    return hmac.compare_digest(a.encode(), b.encode())
# [D6 end]


def safe_host(url):
    return urlparse(url).hostname
