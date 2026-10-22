"""
samples/target_code_v3.py — 評価用サンプル(v3: 強いモデル同士を見分けるための難しめ版。実行しない・外部ライブラリはスタブ)。

`# [Vn start]`〜`# [Vn end]` は欠陥、`# [Dn start]`〜`# [Dn end]` は対応する欠陥の「安全版」(decoy)。各decoyは、Vnと同じ種類の
欠陥が**ない**ことだけを意図している(他の観点の指摘は別問題)。正解行範囲はマーカーから機械的に作る
(testlab/benchmark/ground_truth_audit_v3.json)。評価時はコメントとdocstringを全て除いた版をLLMへ渡す(行番号は不変)。
実在のサービスや秘密値は含まない。
"""
import hashlib
import hmac
import json
import os
import stat
import time

import jwt  # スタブ: jwt.decode(token, key, algorithms=[...], options={...})
import db   # スタブ: db.query(sql, params) / db.one(sql, params) / db.order(order_id) など

JWT_SECRET = os.environ["JWT_SECRET"]
ROLE_RANK = {"viewer": 1, "member": 2, "manager": 3, "admin": 4}
INVITABLE_BY = {"manager": {"viewer", "member"}, "admin": {"viewer", "member", "manager", "admin"}}
SORT_COLUMNS = {"date": "created_at", "total": "total_cents", "status": "status"}
RATE_LIMIT_PER_MINUTE = 20
_hits = {}


# [V1 start] 二次インジェクション: 登録時はHTMLエスケープだけして保存し、後で管理レポートがその値をSQLへ連結する
def register(username):
    safe = username.replace("<", "&lt;").replace(">", "&gt;")
    db.query("INSERT INTO users(username) VALUES (%s)", (safe,))


def admin_report(day):
    rows = db.query("SELECT username FROM users WHERE signup_day = %s", (day,))
    out = []
    for row in rows:
        out.append(db.query(f"SELECT COUNT(*) AS n FROM logins WHERE username = '{row['username']}'"))
    return out
# [V1 end]


# [D1 start] 安全(V1の安全版): 保存値も条件値も常にバインド変数。並び順は固定の列名対応表から選ぶ
def my_orders(user, sort):
    column = SORT_COLUMNS.get(sort, "created_at")
    return db.query(f"SELECT * FROM orders WHERE user_id = %s ORDER BY {column}", (user["id"],))
# [D1 end]


# [V2 start] 署名を検証しないJWTの内容を権限判断に使う(「内部用」の読み取り関数が、そのまま削除の認可に使われる)
def peek_claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def delete_user(token, target_id):
    claims = peek_claims(token)
    if claims.get("role") != "admin":
        raise PermissionError("admin only")
    db.query("DELETE FROM users WHERE id = %s", (target_id,))
# [V2 end]


# [D2 start] 安全(V2の安全版): 署名とexpを検証し、アルゴリズムを固定して、検証済みの内容だけを使う
def verified_claims(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"require": ["exp", "sub"]})


def delete_user_verified(token, target_id):
    claims = verified_claims(token)
    if claims.get("role") != "admin":
        raise PermissionError("admin only")
    db.query("DELETE FROM users WHERE id = %s", (target_id,))
# [D2 end]


# [V3 start] レート制限のキーに X-Forwarded-For の値(クライアントが自由に付けられる)をそのまま使う
def allow_request(headers, remote_addr):
    ip = headers.get("X-Forwarded-For", remote_addr).split(",")[0].strip()
    now = time.time()
    window = [t for t in _hits.get(ip, []) if now - t < 60]
    if len(window) >= RATE_LIMIT_PER_MINUTE:
        return False
    window.append(now)
    _hits[ip] = window
    return True
# [V3 end]


# [D3 start] 安全(V3の安全版): 接続元アドレス(信頼できる値)だけをキーにする
def allow_request_by_peer(remote_addr):
    now = time.time()
    window = [t for t in _hits.get(remote_addr, []) if now - t < 60]
    if len(window) >= RATE_LIMIT_PER_MINUTE:
        return False
    window.append(now)
    _hits[remote_addr] = window
    return True
# [D3 end]


# [V4 start] 払い戻しの上限確認が「今回の額 <= 注文総額」だけで、これまでの払い戻し累計を見ていない
def refund(user, order_id, amount_cents):
    order = db.order(order_id)
    if order["user_id"] != user["id"]:
        raise PermissionError("not your order")
    if amount_cents <= 0 or amount_cents > order["total_cents"]:
        raise ValueError("invalid amount")
    db.query("UPDATE orders SET refunded_cents = refunded_cents + %s WHERE id = %s", (amount_cents, order_id))
    return amount_cents
# [V4 end]


# [D4 start] 安全(V4の安全版): 累計の払い戻し額を含めて上限を確認し、更新も条件つきで一度に行う
def refund_checked(user, order_id, amount_cents):
    order = db.order(order_id)
    if order["user_id"] != user["id"]:
        raise PermissionError("not your order")
    if amount_cents <= 0 or order["refunded_cents"] + amount_cents > order["total_cents"]:
        raise ValueError("invalid amount")
    updated = db.query("UPDATE orders SET refunded_cents = refunded_cents + %s "
                       "WHERE id = %s AND refunded_cents + %s <= total_cents", (amount_cents, order_id, amount_cents))
    if not updated:
        raise ValueError("refund limit reached")
    return amount_cents
# [D4 end]


# [V5 start] ルート表で、GETの一覧だけ管理者チェックで包み、同じパスのPOST(作成)は包み忘れている
def require_admin(handler):
    def wrapped(user, *args):
        if user.get("role") != "admin":
            raise PermissionError("admin only")
        return handler(user, *args)
    return wrapped


def list_accounts(user):
    return db.query("SELECT id, username, role FROM users")


def create_account(user, payload):
    data = json.loads(payload)
    db.query("INSERT INTO users(username, role) VALUES (%s, %s)", (data["username"], data.get("role", "member")))


ROUTES = {
    ("GET", "/admin/accounts"): require_admin(list_accounts),
    ("POST", "/admin/accounts"): create_account,
}
# [V5 end]


# [D5 start] 安全(V5の安全版): 全ての管理ルートを同じ方法で包み、包み忘れを起動時に検査する
SAFE_ROUTES = {
    ("GET", "/admin/accounts"): require_admin(list_accounts),
    ("POST", "/admin/accounts"): require_admin(create_account),
}
assert all(getattr(h, "__name__", "") == "wrapped" for h in SAFE_ROUTES.values())
# [D5 end]


# [V6 start] 割引の重ね掛け: 同じクーポンコードを複数回指定でき、割引率の合計に上限がない(合計が負になる)
def apply_coupons(total_cents, codes):
    for code in codes:
        coupon = db.one("SELECT percent FROM coupons WHERE code = %s AND active = 1", (code,))
        if coupon:
            total_cents = total_cents - total_cents * coupon["percent"] // 100
            total_cents -= coupon["percent"]
    return total_cents
# [V6 end]


# [D6 start] 安全(V6の安全版): 重複コードを除き、上限件数・上限割引を決め、合計が負にならないようにする
def apply_coupons_capped(total_cents, codes):
    unique = list(dict.fromkeys(codes))[:2]
    percent = 0
    for code in unique:
        coupon = db.one("SELECT percent FROM coupons WHERE code = %s AND active = 1", (code,))
        if coupon:
            percent += coupon["percent"]
    percent = min(percent, 30)
    return max(total_cents - total_cents * percent // 100, 0)
# [D6 end]


# [V7 start] 招待時の権限確認が「招待者がmanager以上」だけで、付与できるroleの上限を確認していない
def invite(inviter, email, role):
    if ROLE_RANK.get(inviter["role"], 0) < ROLE_RANK["manager"]:
        raise PermissionError("managers only")
    if role not in ROLE_RANK:
        raise ValueError("unknown role")
    db.query("INSERT INTO invites(email, role, invited_by) VALUES (%s, %s, %s)", (email, role, inviter["id"]))
# [V7 end]


# [D7 start] 安全(V7の安全版): 招待者のroleごとに付与できるroleの集合を決めて確認する
def invite_checked(inviter, email, role):
    allowed = INVITABLE_BY.get(inviter["role"], set())
    if role not in allowed:
        raise PermissionError("cannot grant this role")
    db.query("INSERT INTO invites(email, role, invited_by) VALUES (%s, %s, %s)", (email, role, inviter["id"]))
# [D7 end]


# [V8 start] 確認→使用の間にシンボリックリンクを差し替えられる(os.accessで確認してからopenする)
def read_export(user, name):
    path = os.path.join("/srv/exports", str(user["id"]), os.path.basename(name))
    if not os.access(path, os.R_OK):
        raise FileNotFoundError(name)
    with open(path, "rb") as f:
        return f.read()
# [V8 end]


# [D8 start] 安全(V8の安全版): O_NOFOLLOWで開いてから、開いたファイル記述子で種類を確認する
def read_export_nofollow(user, name):
    path = os.path.join("/srv/exports", str(user["id"]), os.path.basename(name))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise FileNotFoundError(name)
        return os.read(fd, 1 << 20)
    finally:
        os.close(fd)
# [D8 end]


def sign(payload):
    return hmac.new(JWT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
