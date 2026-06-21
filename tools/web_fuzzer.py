"""
tools/web_fuzzer.py — Webスマートファジング（クロール＋注入点検出＋異常検知）

設計方針（重要）:
  本モジュールは「認可された対象」への脆弱性"発見"を目的とする検出指向ファザーである。
  - 検出のみ: ペイロードに対するレスポンスの異常（リフレクション／DBエラー署名／
    サーバエラー化／既知ファイル署名）を観測して脆弱性の"兆候"を報告する。
    データ窃取・RCE実行・認証回避などのエクスプロイトは行わない。
  - 非DoS: 総リクエスト数に上限を設け、ステルスプロファイルのジッター／低並列を流用する。
  - 同一オリジン限定: クロールはターゲットと同じホストのみを辿る。

外部依存は requests のみ（HTML解析は軽量な正規表現ベース）。
"""

from __future__ import annotations
import re
import time
import random
import html as _html
import concurrent.futures
from typing import Callable
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, urlsplit

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from core.settings import (
    SCAN_PROFILES, DEFAULT_SCAN_PROFILE, STEALTH_USER_AGENTS,
)

# ── 検出シグネチャ ─────────────────────────────────────────
# SQLインジェクションを示唆するDBエラーメッセージ断片
_SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql", r"mysql_fetch", r"mysqli?_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)", r"postgresql.*error", r"syntax error at or near",
    r"sqlite3?\.(operational|programming)error", r"sqlite_error",
    r"ora-\d{5}", r"oracle.*driver",
    r"microsoft sql server", r"odbc.*sql server", r"unclosed quotation",
    r"sql syntax.*near", r"native client.*error",
]
# /etc/passwd 等のパストラバーサル成功署名
_TRAVERSAL_SIG = re.compile(r"root:.*:0:0:", re.I)
# テンプレートインジェクション（SSTI）算術評価署名: 7*7 -> 49
_SSTI_PROBE_RESULT = "49"

_SQL_ERR_RE = re.compile("|".join(_SQL_ERRORS), re.I)


# ── 既定の検出プローブ（AI生成ペイロードが無い場合のフォールバック） ──
# いずれも標準的な脆弱性"検出"用テストベクタ（兆候観測が目的）。
DEFAULT_PROBES = {
    "SQLI":      ["'", "''", "' OR '1'='1", "1' AND '1'='2", "1\" OR \"1\"=\"1"],
    "XSS":       ["<svg/onload=__FZ__>", "\"'><__FZ__>", "javascript:__FZ__"],
    "TRAVERSAL": ["../../../../etc/passwd", "....//....//etc/passwd",
                  "..%2f..%2f..%2fetc%2fpasswd"],
    "SSTI":      ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"],
}
# XSSリフレクション判定に使うユニークマーカー
_XSS_MARKER = "fzx9q7"


class WebFuzzer:
    def __init__(
        self,
        profile: str = DEFAULT_SCAN_PROFILE,
        max_pages: int = 20,
        max_requests: int = 200,
        timeout: int = 8,
        log: Callable[[str], None] | None = None,
        auth: dict | None = None,
    ):
        prof = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_SCAN_PROFILE])
        self.threads      = prof["path_threads"]
        self.jitter       = prof["path_jitter"]
        self.max_pages    = max_pages
        self.max_requests = max_requests        # DoS防止のための総リクエスト上限
        self.timeout      = timeout
        self.log          = log or (lambda m: None)
        self.auth         = auth or {}          # 認証設定（cookie/header/login）
        self._req_count   = 0
        self._user_agents = list(STEALTH_USER_AGENTS)
        self.session = requests.Session()
        self.session.verify = False

    # ── 認証 ───────────────────────────────────────────────
    def authenticate(self) -> tuple[bool, str]:
        """Cookie / ヘッダー / ログインフォーム認証をセッションへ適用する。

        ログインフォームは CSRF を含む hidden 入力を自動抽出して送信する。
        以後のクロール／ファジングはこの認証済みセッションで行われる。
        """
        a = self.auth or {}
        applied: list[str] = []

        # 1) 生Cookie（例: "sessionid=abc; csrftoken=xyz"）
        #    ドメイン依存を避けるため Cookie ヘッダーとして全リクエストに付与する。
        raw = (a.get("cookie") or "").strip()
        if raw:
            self.session.headers["Cookie"] = raw
            applied.append("cookie")

        # 2) 任意ヘッダー（例: Authorization: Bearer ...）
        hn = (a.get("header_name") or "").strip()
        hv = (a.get("header_value") or "").strip()
        if hn and hv:
            self.session.headers[hn] = hv
            applied.append("header")

        # 3) ログインフォーム（CSRF自動対応）
        login_url = (a.get("login_url") or "").strip()
        if login_url:
            ok, msg = self._form_login(a, login_url)
            applied.append(f"login({'ok' if ok else 'uncertain'})")
            if not ok:
                return False, msg

        if not applied:
            return True, "認証設定なし"
        return True, "認証適用: " + ", ".join(applied)

    def _form_login(self, a: dict, login_url: str) -> tuple[bool, str]:
        try:
            r = self.session.get(login_url, timeout=self.timeout, verify=False)
        except requests.RequestException as e:
            return False, f"ログインページ取得失敗: {e}"

        # ログインフォーム（password入力を含むform）の hidden 入力を収集（CSRF等）
        fields = self._login_form_fields(r.text)
        uf = (a.get("user_field") or "").strip()
        pf = (a.get("pass_field") or "").strip()
        if uf:
            fields[uf] = a.get("user_val", "")
        if pf:
            fields[pf] = a.get("pass_val", "")

        action = (a.get("post_url") or "").strip() or login_url
        try:
            rp = self.session.post(action, data=fields, timeout=self.timeout,
                                   allow_redirects=True, verify=False)
        except requests.RequestException as e:
            return False, f"ログインPOST失敗: {e}"

        if self._login_ok(rp):
            return True, "ログイン成功"
        return False, ("ログイン失敗の可能性（認証フォームが残存／"
                       "セッションCookie未設定）。認証なしで継続します。")

    @staticmethod
    def _login_form_fields(html_text: str) -> dict:
        """password入力を含むformの hidden/text 入力を name:value で返す。"""
        for m in re.finditer(r"<form\b[^>]*>(.*?)</form>", html_text, re.I | re.S):
            inner = m.group(1)
            if "type=\"password\"" not in inner.lower() and "type='password'" not in inner.lower():
                continue
            fields = {}
            for im in re.finditer(r"<input\b([^>]*)>", inner, re.I):
                attrs = im.group(1)
                name = _attr(attrs, "name")
                itype = (_attr(attrs, "type") or "text").lower()
                if not name or itype in ("submit", "button", "image", "reset"):
                    continue
                fields[name] = _attr(attrs, "value") or ""
            return fields
        return {}

    def _login_ok(self, resp) -> bool:
        """ログイン成否のヒューリスティック判定。"""
        body = resp.text.lower()
        still_login = "type=\"password\"" in body or "type='password'" in body
        has_cookie  = len(self.session.cookies) > 0
        return (not still_login) and (has_cookie or resp.status_code in (301, 302, 303))

    # ── 内部ヘルパー ───────────────────────────────────────
    def _budget_left(self) -> bool:
        return self._req_count < self.max_requests

    def _get(self, url, params=None, data=None, method="GET"):
        """予算・ジッターを考慮してHTTPリクエストを送る。失敗時 None。"""
        if not self._budget_left():
            return None
        lo, hi = self.jitter
        if hi > 0:
            time.sleep(random.uniform(lo, hi))
        self._req_count += 1
        headers = {"User-Agent": random.choice(self._user_agents)}
        try:
            if method == "POST":
                return self.session.post(url, data=data, headers=headers,
                                         timeout=self.timeout, allow_redirects=False)
            return self.session.get(url, params=params, headers=headers,
                                    timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return None

    # ── 1. クロール ────────────────────────────────────────
    def crawl(self, base_url: str) -> dict:
        """同一オリジンを浅くクロールし、注入点（クエリ／フォーム）を抽出する。"""
        base = base_url if base_url.startswith("http") else "http://" + base_url
        host = urlparse(base).netloc
        seen: set[str] = set()
        queue = [base]
        injection_points: list[dict] = []
        pages_fetched = 0

        while queue and pages_fetched < self.max_pages and self._budget_left():
            url = queue.pop(0)
            norm = url.split("#")[0]
            if norm in seen:
                continue
            seen.add(norm)
            resp = self._get(norm)
            if resp is None or "text/html" not in resp.headers.get("Content-Type", "text/html"):
                continue
            pages_fetched += 1
            body = resp.text
            self.log(f"crawl [{pages_fetched}] {norm} ({resp.status_code})")

            # URLに含まれるクエリパラメータを注入点として登録
            for pname, pval in parse_qsl(urlsplit(norm).query):
                injection_points.append({
                    "url": norm.split("?")[0], "method": "GET", "where": "query",
                    "param": pname, "fields": dict(parse_qsl(urlsplit(norm).query)),
                })

            # フォームを抽出
            injection_points += self._extract_forms(norm, body)

            # 同一オリジンのリンクを辿る
            for href in re.findall(r'href=["\']([^"\']+)["\']', body, re.I):
                nxt = urljoin(norm, href).split("#")[0]
                if urlparse(nxt).netloc == host and nxt not in seen and nxt.startswith("http"):
                    if not re.search(r"\.(png|jpe?g|gif|svg|css|js|ico|woff2?|pdf|zip)$", nxt, re.I):
                        queue.append(nxt)

        # 重複注入点を除去（url+param+method）
        uniq = {}
        for ip in injection_points:
            key = (ip["url"], ip["param"], ip["method"])
            uniq.setdefault(key, ip)
        return {"injection_points": list(uniq.values()), "pages": pages_fetched}

    def _extract_forms(self, page_url: str, body: str) -> list[dict]:
        points = []
        for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body, re.I | re.S):
            attrs, inner = m.group(1), m.group(2)
            action = _attr(attrs, "action") or page_url
            method = (_attr(attrs, "method") or "GET").upper()
            action_url = urljoin(page_url, action).split("#")[0]
            fields = {}
            for im in re.finditer(r"<(?:input|textarea|select)\b([^>]*)>", inner, re.I):
                iattr = im.group(1)
                name = _attr(iattr, "name")
                if not name:
                    continue
                itype = (_attr(iattr, "type") or "text").lower()
                if itype in ("submit", "button", "image", "reset", "file"):
                    continue
                fields[name] = _attr(iattr, "value") or "1"
            for name in fields:
                points.append({
                    "url": action_url, "method": method, "where": "form",
                    "param": name, "fields": dict(fields),
                })
        return points

    # ── 2. ファジング（検出のみ） ──────────────────────────
    def fuzz(self, points: list[dict], probes: dict[str, list[str]] | None = None) -> list[dict]:
        """各注入点へ検出プローブを送り、レスポンス異常を観測して兆候を返す。"""
        probes = probes or DEFAULT_PROBES
        findings: list[dict] = []

        def _work(point):
            return self._fuzz_point(point, probes)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for res in ex.map(_work, points):
                findings.extend(res)
        return findings

    def _fuzz_point(self, point: dict, probes: dict[str, list[str]]) -> list[dict]:
        if not self._budget_left():
            return []
        url, method, param = point["url"], point["method"], point["param"]
        base_fields = dict(point.get("fields", {}))

        # ベースライン取得
        base_resp = self._send(url, method, base_fields)
        base_len  = len(base_resp.text) if base_resp is not None else 0
        base_body = base_resp.text if base_resp is not None else ""

        out = []
        for category, payload_list in probes.items():
            for payload in payload_list:
                if not self._budget_left():
                    return out
                # XSSマーカー埋め込み
                send_payload = payload.replace("__FZ__", f"alert('{_XSS_MARKER}')")
                fields = dict(base_fields)
                fields[param] = send_payload
                resp = self._send(url, method, fields)
                if resp is None:
                    continue
                ev = self._detect(category, send_payload, resp, base_body, base_len)
                if ev:
                    out.append({
                        "url": url, "method": method, "param": param,
                        "category": category, "payload": send_payload,
                        "severity": ev[0], "evidence": ev[1],
                        "status": resp.status_code,
                    })
                    self.log(f"  [!] {category} 兆候: {param}@{url}")
                    break  # 同カテゴリは最初の兆候で十分
        return out

    def _send(self, url, method, fields):
        if method == "POST":
            return self._get(url, data=fields, method="POST")
        return self._get(url, params=fields, method="GET")

    def _detect(self, category, payload, resp, base_body, base_len):
        """(severity, evidence) を返す。兆候なしなら None。検出のみ。"""
        body = resp.text

        if category == "SQLI":
            m = _SQL_ERR_RE.search(body)
            if m and not _SQL_ERR_RE.search(base_body):
                return ("HIGH", f"DBエラー署名がレスポンスに出現: {m.group(0)[:60]!r}")
            if resp.status_code >= 500 and base_len and abs(len(body) - base_len) > 50:
                return ("MEDIUM", f"単一引用符でHTTP {resp.status_code}化（注入の可能性）")

        elif category == "XSS":
            # マーカーがエスケープされず原文のまま反射しているか
            if _XSS_MARKER in body:
                snippet = _context(body, _XSS_MARKER)
                if _html.escape(f"alert('{_XSS_MARKER}')") not in body or "<svg" in snippet.lower():
                    return ("HIGH", f"ペイロードが未エスケープで反射: …{snippet}…")

        elif category == "TRAVERSAL":
            if _TRAVERSAL_SIG.search(body) and not _TRAVERSAL_SIG.search(base_body):
                return ("CRITICAL", "/etc/passwd 形式の内容がレスポンスに出現")

        elif category == "SSTI":
            if _SSTI_PROBE_RESULT in body and _SSTI_PROBE_RESULT not in base_body:
                snippet = _context(body, _SSTI_PROBE_RESULT)
                return ("HIGH", f"テンプレート式が評価された痕跡(7*7=49): …{snippet}…")

        return None


# ── モジュール関数 ─────────────────────────────────────────
def _attr(attr_str: str, name: str) -> str | None:
    m = re.search(rf'{name}\s*=\s*["\']([^"\']*)["\']', attr_str, re.I)
    if m:
        return m.group(1)
    m = re.search(rf"{name}\s*=\s*([^\s>]+)", attr_str, re.I)
    return m.group(1) if m else None


def _context(body: str, needle: str, width: int = 40) -> str:
    i = body.find(needle)
    if i < 0:
        return ""
    s = max(0, i - width)
    e = min(len(body), i + len(needle) + width)
    return body[s:e].replace("\n", " ").replace("\r", "")
