"""
core/redaction.py — 証拠のマスキング (P1.2)

ディスク保存・GUI/ログ表示・LLM送信より前に、機密値をマスクする。
Cookie/Set-Cookie/Authorization等のヘッダー、設定した認証ヘッダー、URL中や
JSON/form中の機密値を対象とする。マスク済み証拠にはハッシュを付けるが、これは
改ざん検出の補助であり匿名化ではない（同じ値は常に同じハッシュになる）。

設計方針:
  - 呼び出し側が把握している「既知の機密値」（configured cookie/token/password等の
    実際の文字列）の完全一致マスクを主とする。これが最も確実に漏えいを防げる。
  - キー名（password/token/api_key等）に基づくヒューリスティックマスクを補助とする。
    値そのものを知らない場合の保険であり、万能ではない。
  - 完全な構文解析（HTTPヘッダー/JSON/form）はしない。証拠は参考情報であり、
    軽量な正規表現ベースの近似で十分とする（過剰実装を避ける）。
"""

from __future__ import annotations
import hashlib
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

_MASK_TAG = "***REDACTED***"

# 常にマスクするヘッダー名（大文字小文字を無視）
SENSITIVE_HEADER_NAMES = frozenset({
    "cookie", "set-cookie", "authorization", "proxy-authorization",
    "x-api-key", "x-auth-token",
})

# URL/JSON/formの機密パラメータ名（キー名ベースのヒューリスティック）
SENSITIVE_PARAM_NAMES = frozenset({
    "password", "passwd", "pwd", "token", "access_token", "refresh_token",
    "api_key", "apikey", "secret", "authorization", "auth", "session",
    "sessionid", "csrf", "csrftoken",
})


def short_hash(value: str) -> str:
    """改ざん検出の補助用ハッシュ（匿名化ではない。同じ値は同じハッシュになる）。"""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def mask_value(value: str) -> str:
    if not value:
        return value
    return f"{_MASK_TAG}(sha256:{short_hash(value)})"


def _mask_known_secrets(text: str, known_secrets: set[str]) -> str:
    """既知の機密値（設定済みcookie/token/password等）が本文中に現れたら置換する。

    長い値から先にマスクする（短い値が長い値の部分文字列である場合の重複置換ずれを防ぐ）。
    """
    if not text or not known_secrets:
        return text
    for secret in sorted((s for s in known_secrets if s), key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, mask_value(secret))
    return text


def mask_headers(headers: dict | None, *,
                 extra_sensitive_names: set[str] | None = None,
                 known_secrets: set[str] | None = None) -> dict:
    """ヘッダー値をマスクする。ヘッダー名は保持し値だけ置き換える。"""
    sensitive = SENSITIVE_HEADER_NAMES | {n.lower() for n in (extra_sensitive_names or ())}
    known = {s for s in (known_secrets or ()) if s}
    out = {}
    for k, v in (headers or {}).items():
        v = str(v)
        if k.lower() in sensitive:
            out[k] = mask_value(v)
        else:
            out[k] = _mask_known_secrets(v, known) if known else v
    return out


def mask_url(url: str, known_secrets: set[str] | None = None) -> str:
    """URLのクエリ文字列を機密パラメータ名・既知の機密値でマスクする。パス自体は変更しない。"""
    known = {s for s in (known_secrets or ()) if s}
    try:
        parts = urlsplit(url)
    except ValueError:
        return mask_value(url)
    masked_q = []
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        if k.lower() in SENSITIVE_PARAM_NAMES:
            masked_q.append((k, mask_value(v)))
        elif known:
            masked_q.append((k, _mask_known_secrets(v, known)))
        else:
            masked_q.append((k, v))
    new_query = urlencode(masked_q)
    path = _mask_known_secrets(parts.path, known) if known else parts.path
    return urlunsplit((parts.scheme, parts.netloc, path, new_query, parts.fragment))


_FORM_KV_RE = re.compile(r'(^|&)([A-Za-z0-9_\-]+)=([^&]*)')
_JSON_KV_RE = re.compile(r'"([A-Za-z0-9_\-]+)"\s*:\s*"([^"]*)"')


def mask_body(body: str, known_secrets: set[str] | None = None, max_len: int = 2000) -> str:
    """本文（JSON/form/プレーンテキスト）をマスクする。

    まず既知の機密値（呼び出し側が把握している実際の文字列）を完全一致でマスクし、
    次にキー名ヒューリスティックでform形式(key=value)・JSON形式("key":"value")を
    追加マスクする。厳密な構文解析はしない（証拠は参考情報のため）。
    """
    known = {s for s in (known_secrets or ()) if s}
    text = (body or "")[:max_len]
    if known:
        text = _mask_known_secrets(text, known)

    def _form_sub(m: re.Match) -> str:
        sep, key, val = m.group(1), m.group(2), m.group(3)
        if key.lower() in SENSITIVE_PARAM_NAMES:
            return f"{sep}{key}={mask_value(val)}"
        return m.group(0)

    def _json_sub(m: re.Match) -> str:
        key, val = m.group(1), m.group(2)
        if key.lower() in SENSITIVE_PARAM_NAMES:
            return f'"{key}": "{mask_value(val)}"'
        return m.group(0)

    text = _FORM_KV_RE.sub(_form_sub, text)
    text = _JSON_KV_RE.sub(_json_sub, text)
    return text
