"""
target_code.py — テスト用のバグ入りコード
Sample Web Application Backend

INTENTIONALLY VULNERABLE — For Security Audit Tool Testing ONLY
Do NOT deploy to production.
"""

import hashlib
import hmac
import time
import sqlite3
import os
import json
from functools import wraps

# ── データベース初期化 ───────────────────────────────────────
DB_PATH = "users.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT UNIQUE NOT NULL,
            password     TEXT NOT NULL,
            role         TEXT DEFAULT 'user',
            balance      REAL DEFAULT 0.0,
            session_token TEXT,
            reset_token  TEXT,
            token_expiry INTEGER
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER,
            action    TEXT,
            timestamp INTEGER
        );
        INSERT OR IGNORE INTO users (username, password, role, balance)
        VALUES ('admin', 'admin123', 'admin', 99999.0);
        INSERT OR IGNORE INTO users (username, password, role, balance)
        VALUES ('alice', 'alice123', 'user', 500.0);
        INSERT OR IGNORE INTO users (username, password, role, balance)
        VALUES ('bob',   'bob456',  'user', 200.0);
    """)
    conn.commit()
    conn.close()


# ══════════════════════════════════════════════════════════════
#  VULNERABILITY 1: SQL インジェクション + 予測可能なトークン
# ══════════════════════════════════════════════════════════════
def authenticate(username: str, password: str) -> dict | None:
    """
    ユーザー認証。成功したらセッション情報を返す。

    BUG 1: username/password を直接文字列結合 → SQLインジェクション可能
           例: username = "' OR '1'='1' --"
    BUG 2: セッショントークンが MD5(username + 現在秒) で生成 → 予測可能
           同一秒内に複数リクエストを送れば同一トークンが発行される
    """
    conn = sqlite3.connect(DB_PATH)
    # ↓ 脆弱: パラメータ化クエリを使っていない
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor = conn.execute(query)
    row = cursor.fetchone()
    conn.close()

    if row:
        # ↓ 脆弱: 時刻ベースの MD5 トークン（秒単位で衝突する）
        token = hashlib.md5(f"{username}{int(time.time())}".encode()).hexdigest()
        return {
            "id": row[0], "username": row[1],
            "role": row[3], "balance": row[4],
            "token": token,
        }
    return None


# ══════════════════════════════════════════════════════════════
#  VULNERABILITY 2: TOCTOU 競合状態（セッション二重作成）
# ══════════════════════════════════════════════════════════════
active_sessions: dict[int, dict] = {}


def create_session(user_id: int, token: str) -> bool:
    """
    セッションを作成する。

    BUG: 「存在チェック」と「書き込み」の間にスリープがあり、
         マルチスレッド環境で同一ユーザーのセッションが二重発行される。
         攻撃者は並列リクエストで複数のアクティブセッションを取得できる。
    """
    if user_id not in active_sessions:          # ← check
        time.sleep(0.002)                        # ← gap (競合ウィンドウ)
        active_sessions[user_id] = {             # ← use
            "token": token,
            "created_at": time.time(),
            "request_count": 0,
        }
        return True
    return False


def validate_session(token: str) -> dict | None:
    """
    BUG: タイミング攻撃に脆弱な == 比較を使用。
         hmac.compare_digest() を使うべき。
    """
    for user_id, session in active_sessions.items():
        if session["token"] == token:   # ← タイミングサイドチャネル
            return {"user_id": user_id, **session}
    return None


# ══════════════════════════════════════════════════════════════
#  VULNERABILITY 3: IDOR（安全でない直接オブジェクト参照）
# ══════════════════════════════════════════════════════════════
def get_user_profile(requesting_user_id: int, target_user_id: int) -> dict | None:
    """
    BUG: requesting_user_id が target_user_id にアクセスする権限を
         一切検証していない。任意のユーザー情報を閲覧できる（IDOR）。
         例: 一般ユーザーが admin(id=1) のプロフィールを取得可能。
    """
    conn = sqlite3.connect(DB_PATH)
    # 権限チェックなし ↓
    row = conn.execute(
        "SELECT id, username, role, balance FROM users WHERE id = ?",
        (target_user_id,),
    ).fetchone()
    conn.close()
    return {"id": row[0], "username": row[1], "role": row[2], "balance": row[3]} if row else None


# ══════════════════════════════════════════════════════════════
#  VULNERABILITY 4: 負の金額チェック欠如（ビジネスロジック欠陥）
# ══════════════════════════════════════════════════════════════
def transfer_funds(from_id: int, to_id: int, amount: float) -> bool:
    """
    BUG 1: amount がマイナスでも処理を通過 → 逆送金攻撃
           例: amount=-500 とすると、受取人から送金者に資金が移る。
    BUG 2: 残高チェックと UPDATE の間でアトミック性がなく、
           並列リクエストで残高以上の金額を送金できる（二重支払い）。
    BUG 3: ゼロ金額の送金も許可される（DoS 的なログ汚染）。
    """
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT balance FROM users WHERE id = ?", (from_id,)).fetchone()

    if row and row[0] >= amount:    # ← amount < 0 の場合も True になる
        # ↓ 非アトミックな二段階 UPDATE（競合状態の温床）
        conn.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, from_id))
        conn.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_id))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False


# ══════════════════════════════════════════════════════════════
#  VULNERABILITY 5: パストラバーサル
# ══════════════════════════════════════════════════════════════
UPLOAD_DIR = "/tmp/uploads"


def read_user_file(username: str, filename: str) -> str:
    """
    BUG: filename を os.path.join に直接渡している。
         filename = "../../etc/passwd" のようなパスで任意ファイルを読める。
         os.path.basename() や os.path.realpath() による正規化が必要。
    """
    filepath = os.path.join(UPLOAD_DIR, username, filename)   # ← 脆弱
    with open(filepath, "r") as f:
        return f.read()


# ══════════════════════════════════════════════════════════════
#  VULNERABILITY 6: パスワードリセットの論理欠陥
# ══════════════════════════════════════════════════════════════
_reset_tokens: dict[str, dict] = {}


def request_password_reset(username: str) -> str:
    """
    BUG 1: トークンが MD5(username) の固定値 → ユーザー名が分かれば
           トークンを事前計算できる（オフライン攻撃可能）。
    BUG 2: 既存のリセットトークンを無効化しないため、
           古いリンクが永続的に有効になる可能性がある。
    """
    token = hashlib.md5(username.encode()).hexdigest()  # ← 決定論的・予測可能
    _reset_tokens[token] = {"username": username, "expires": time.time() + 3600}
    return token


def reset_password(token: str, new_password: str) -> bool:
    """
    BUG: 有効期限チェックが実装されていない！
         expires フィールドは保存しているが、比較していない。
         発行から何時間後でもパスワードリセットが可能。
    """
    if token in _reset_tokens:
        data = _reset_tokens[token]
        # ↓ expires の検証なし
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (new_password, data["username"]),
        )
        conn.commit()
        conn.close()
        del _reset_tokens[token]
        return True
    return False


# ══════════════════════════════════════════════════════════════
#  VULNERABILITY 7: 信頼されていない入力による権限昇格
# ══════════════════════════════════════════════════════════════
def is_admin(user_data: dict) -> bool:
    """
    BUG: クライアントが渡した dict をそのまま信頼している。
         攻撃者が {"role": "admin"} を含む dict を構築してデコレータを通過できる。
         ロール検証はデータベースから直接行うべき。
    """
    return user_data.get("role") == "admin"


def admin_required(func):
    @wraps(func)
    def wrapper(user_data: dict, *args, **kwargs):
        if not is_admin(user_data):   # ← 信頼されていない入力を検査
            raise PermissionError("Admin access required")
        return func(user_data, *args, **kwargs)
    return wrapper


@admin_required
def delete_user(admin_data: dict, target_id: int) -> bool:
    """管理者のみがユーザーを削除できる（はず）"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM users WHERE id = ?", (target_id,))
    conn.commit()
    conn.close()
    return True


# ══════════════════════════════════════════════════════════════
#  VULNERABILITY 8: JSON デシリアライズ後の型検証なし
# ══════════════════════════════════════════════════════════════
def process_payment_request(json_payload: str) -> dict:
    """
    BUG: JSON をパースした後、各フィールドの型を検証していない。
         "amount": "999999999" (文字列) や "amount": true (bool) を渡すと
         比較演算が意図しない結果になる可能性がある。
         また、amount に非常に大きな浮動小数点数を渡すと inf になり
         残高チェックを突破される（float('inf') >= any_float は True）。
    """
    data = json.loads(json_payload)
    from_id = data["from_id"]
    to_id   = data["to_id"]
    amount  = data["amount"]   # ← 型・範囲チェックなし

    return {
        "status": "queued",
        "from_id": from_id,
        "to_id": to_id,
        "amount": amount,
    }


# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("[*] 脆弱テストアプリケーション起動完了")
    print("[*] gui_audit_app.py でスキャンしてください")
    print(f"[*] DB: {os.path.abspath(DB_PATH)}")
