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
import random
import threading
import html as _html
import concurrent.futures
from typing import Callable
from urllib.parse import urljoin, urlencode, parse_qsl, urlsplit

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import core.config as config
from core.settings import (
    SCAN_PROFILES, DEFAULT_SCAN_PROFILE, STEALTH_USER_AGENTS,
)
from core.http_transport import HttpTransport, OriginRejected, RequestPolicy

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

# オブジェクトID風パラメータの判定（数値ID or UUID）。IDOR比較の候補選定に使う。
_OBJ_ID_RE = re.compile(
    r"^\d+$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I,
)


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
        auth_b: dict | None = None,
        target: str | None = None,
        stop_event: threading.Event | None = None,
        tls_verify: bool | None = None,
        tls_ca_bundle: str | None = None,
    ):
        prof = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_SCAN_PROFILE])
        self.threads      = prof["path_threads"]
        self.jitter       = prof["path_jitter"]
        self.max_pages    = max_pages
        self.max_requests = max_requests        # DoS防止のための総リクエスト上限
        self.timeout      = timeout
        self.log          = log or (lambda m: None)
        self.auth         = auth or {}          # 認証設定（cookie/header/login）
        self.auth_b       = auth_b or {}        # 第2アカウント設定（IDOR比較用・任意）
        self._user_agents = list(STEALTH_USER_AGENTS)
        # 全送信経路の唯一の送信口（同一origin検査・共有予算・レート/429/STOP制御・
        # 手動リダイレクト制御）。A/Bセッションはこのインスタンスを共有する
        # （P0.1/P0.2: PRACTICAL_ROADMAP.md §4）。レート上限はプロファイル値を使う
        # （settings.pyに集約。aggressiveはNone=無制限で既存の速度を維持）。
        policy = RequestPolicy(max_requests=max_requests, timeout=timeout,
                               rate_per_sec=prof.get("path_rate_per_sec"))
        self.transport = HttpTransport(policy=policy, stop_event=stop_event)
        if target:
            self.bind_target(target)

        # TLS検証（P0.2）。未指定ならconfig.jsonの設定を使う（既定はFalse=既存動作維持）。
        # tls_ca_bundleは tls_verify=True の場合のみ独自CAとして使う。
        if tls_verify is None:
            tls_verify = bool(config.get("tls_verify", False))
        if tls_ca_bundle is None:
            tls_ca_bundle = config.get("tls_ca_bundle", "") or None
        verify_value = tls_ca_bundle if (tls_verify and tls_ca_bundle) else bool(tls_verify)
        if not tls_verify:
            self.log("[TLS] 証明書検証は無効です（既定・既存インストールとの後方互換）。"
                     "新しい案件では有効化を推奨します。")
        self.tls_verify = tls_verify

        self.session = requests.Session()
        self.session.verify = verify_value
        # 第2セッション（IDOR比較用）。auth_b 未設定なら None のまま
        # （_detect_idor は None なら即座に空リストを返す＝既存挙動への影響なし）。
        self.session_b = None
        if self.auth_b:
            self.session_b = requests.Session()
            self.session_b.verify = verify_value
        # 認証状態: authenticated / anonymous / expired / unknown（P0.2）。
        # Cookie/ヘッダー設定だけでは"authenticated"と断定しない。auth未設定は"anonymous"、
        # confirm_url未設定でログインフォームも使わない場合は"unknown"（判定不能）とする。
        self.auth_state, self.auth_state_reason = ("anonymous", "認証設定なし") if not self.auth \
            else ("unknown", "未認証（authenticate()未実行）")
        self.auth_state_b, self.auth_state_reason_b = ("anonymous", "認証設定なし") if not self.auth_b \
            else ("unknown", "未認証（authenticate_b()未実行）")

    @property
    def _req_count(self) -> int:
        """既存呼び出し元（GUI/セルフテスト）互換のための読み取り専用プロパティ。"""
        return self.transport.req_count

    def _transport_error_reason(self) -> str:
        """直近の送信失敗理由を日本語メッセージへ変換する（origin範囲外/予算切れ/通信エラーを区別）。"""
        reason = self.transport.last_error
        return {
            "origin_rejected": "送信不可: 基準origin範囲外",
            "budget_exhausted": "送信不可: リクエスト予算切れ",
            "stopped": "送信不可: STOPにより中断",
            "network_error": "通信エラー",
            "retry_after_exceeded": "429のRetry-Afterが待機上限を超えたため再送せず終了",
            "rate_limited": "429が連続し再送上限に達した",
            "tls_error": "TLS証明書検証エラー（自己署名証明書等。tls_ca_bundleの設定を確認）",
            "tls_config_error": "TLS設定エラー（tls_ca_bundleのパスが不正）",
        }.get(reason, "送信不可: 原因不明")

    def bind_target(self, base_url: str) -> None:
        """基準originを確定する。認証（authenticate）より前に呼ぶこと。

        crawl() 側でも同じ base_url で bind_origin を呼ぶため、こちらを呼ばずに
        crawl() から先に呼ばれた場合はそちらで確定する（idempotent）。ここで先に
        確定しておくのは、ログインフォーム送信を認証前にorigin確定させるため。
        """
        url = base_url if base_url.startswith("http") else "http://" + base_url
        self.transport.bind_origin(url)

    # ── 認証 ───────────────────────────────────────────────
    def authenticate(self) -> tuple[bool, str]:
        """主セッション（session）へ Cookie / ヘッダー / ログインフォーム認証を適用する。

        戻り値は従来どおり(bool, str)。認証状態(authenticated/anonymous/expired/unknown)は
        `self.auth_state`/`self.auth_state_reason`に副作用として保存する（P0.2）。
        """
        ok, msg, login_outcome = self._authenticate_session(self.session, self.auth)
        self.auth_state, self.auth_state_reason = self._resolve_auth_state(
            self.session, self.auth, login_outcome)
        return ok, msg

    def authenticate_b(self) -> tuple[bool, str]:
        """第2セッション（session_b・IDOR比較用）へ認証を適用する。session_b 未設定なら何もしない。"""
        if self.session_b is None:
            return True, "第2セッション未設定"
        ok, msg, login_outcome = self._authenticate_session(self.session_b, self.auth_b)
        self.auth_state_b, self.auth_state_reason_b = self._resolve_auth_state(
            self.session_b, self.auth_b, login_outcome)
        return ok, msg

    def _resolve_auth_state(self, session, auth: dict, login_outcome: str) -> tuple[str, str]:
        """認証状態を判定する（P0.2）。

        Cookie/ヘッダー設定だけでは"authenticated"と断定しない。`confirm_url`が
        設定されていれば同一origin確認URLの内容で判定し（最も信頼できる）、
        未設定の場合はログインフォームの`login_outcome`（_form_login参照）で判定する。
        "expired"は'failed'（パスワードフォーム残存等の実証拠）のときだけ断定し、
        'unconfirmed'（送信不可・リダイレクト未追跡等）は"unknown"に留める
        （P0.1のPOSTリダイレクト未追跡により、ただの成功ログインまで
        "失敗"と誤認しないようにするため）。
        """
        confirm_url = (auth.get("confirm_url") or "").strip()
        if confirm_url:
            return self.check_auth_state(auth, session)
        if not auth:
            return "anonymous", "認証設定なし"
        if login_outcome == "ok":
            return "authenticated", "ログイン成功のヒューリスティック判定(confirm_url未設定)"
        if login_outcome == "failed":
            return "expired", "ログインフォームが残存する等、失敗の実証拠あり"
        if login_outcome == "unconfirmed":
            return "unknown", ("ログイン結果を確認できず(送信不可、または別origin転送/POST"
                               "リダイレクト未追跡のため)。confirm_urlの設定で判定可能")
        return "unknown", "Cookie/ヘッダーのみ設定・確認手段なし（confirm_urlの設定を推奨）"

    def check_auth_state(self, auth: dict, session=None) -> tuple[str, str]:
        """confirm_url（同一origin限定）へGETし、expect_textの有無で認証状態を判定する。

        confirm_urlが別originの場合はHttpTransportが送信を拒否しNoneが返る
        （＝確認用URLとして外部originを指定しても到達しない）。
        """
        session = session or self.session
        confirm_url = (auth.get("confirm_url") or "").strip()
        expect_text = auth.get("expect_text", "")
        if not confirm_url:
            return "unknown", "confirm_url未設定のため判定不能"
        resp = self.transport.request(session, "GET", confirm_url, allow_redirects=True)
        if resp is None:
            return "unknown", f"confirm_url取得失敗（{self._transport_error_reason()}）"
        body = resp.text.lower()
        still_login = "type=\"password\"" in body or "type='password'" in body
        if still_login:
            return "expired", "confirm_urlの内容にログインフォームが残存"
        if not expect_text:
            return "unknown", "confirm_urlは取得できたがexpect_text未設定のため判定不能"
        if expect_text in resp.text:
            return "authenticated", "confirm_urlにexpect_textを確認"
        return "expired", "confirm_urlの内容にexpect_textが見当たらない"

    def _authenticate_session(self, session, auth: dict) -> tuple[bool, str, str]:
        """Cookie / ヘッダー / ログインフォーム認証を指定セッションへ適用する。

        ログインフォームは CSRF を含む hidden 入力を自動抽出して送信する。
        以後のクロール／ファジングはこの認証済みセッションで行われる。
        戻り値3つ目はlogin_outcome（_form_login参照。login_url未設定なら"not_attempted"）。
        """
        a = auth or {}
        applied: list[str] = []

        # 1) 生Cookie（例: "sessionid=abc; csrftoken=xyz"）
        #    ドメイン依存を避けるため Cookie ヘッダーとして全リクエストに付与する。
        raw = (a.get("cookie") or "").strip()
        if raw:
            session.headers["Cookie"] = raw
            applied.append("cookie")

        # 2) 任意ヘッダー（例: Authorization: Bearer ...）
        hn = (a.get("header_name") or "").strip()
        hv = (a.get("header_value") or "").strip()
        if hn and hv:
            session.headers[hn] = hv
            applied.append("header")

        # 3) ログインフォーム（CSRF自動対応）
        login_url = (a.get("login_url") or "").strip()
        login_outcome = "not_attempted"
        if login_url:
            ok, msg, login_outcome = self._form_login(session, a, login_url)
            applied.append(f"login({'ok' if ok else 'uncertain'})")
            if not ok:
                return False, msg, login_outcome

        if not applied:
            return True, "認証設定なし", login_outcome
        return True, "認証適用: " + ", ".join(applied), login_outcome

    def _form_login(self, session, a: dict, login_url: str) -> tuple[bool, str, str]:
        """戻り値3つ目はlogin_outcome: 'ok'（成功と判定）/ 'failed'（失敗の実証拠あり）/
        'unconfirmed'（送信不可・リダイレクト未追跡等で真偽不明）。
        認証状態(_resolve_auth_state)は'failed'のときだけ"expired"と断定する。
        """
        # 基準originが未確定ならここで確定する（bind_target未使用の直接呼び出し互換）。
        if self.transport.base_origin is None:
            try:
                self.transport.bind_origin(
                    login_url if login_url.startswith("http") else "http://" + login_url
                )
            except OriginRejected as e:
                return False, f"ログインURLのorigin確定に失敗: {e}", "unconfirmed"
        r = self.transport.request(session, "GET", login_url, allow_redirects=True)
        if r is None:
            return False, f"ログインページ取得失敗（{self._transport_error_reason()}）", "unconfirmed"

        # ログインフォーム（password入力を含むform）の hidden 入力を収集（CSRF等）
        fields = self._login_form_fields(r.text)
        uf = (a.get("user_field") or "").strip()
        pf = (a.get("pass_field") or "").strip()
        if uf:
            fields[uf] = a.get("user_val", "")
        if pf:
            fields[pf] = a.get("pass_val", "")

        action = (a.get("post_url") or "").strip() or login_url
        rp = self.transport.request(session, "POST", action, data=fields, allow_redirects=True)
        if rp is None:
            return False, f"ログインPOST失敗（{self._transport_error_reason()}）", "unconfirmed"

        if rp.status_code in (301, 302, 303, 307, 308):
            return False, (
                f"ログインPOSTがリダイレクト(HTTP {rp.status_code})のまま完了しました。"
                "別originへの転送、またはPOSTの301/302/307/308は初期版では自動追跡しない"
                "ため（認証転送は同一origin限定）、認証未確認として継続します。"
            ), "unconfirmed"
        if self._login_ok(session, rp):
            return True, "ログイン成功", "ok"
        return False, ("ログイン失敗の可能性（認証フォームが残存／"
                       "セッションCookie未設定）。認証なしで継続します。"), "failed"

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

    def _login_ok(self, session, resp) -> bool:
        """ログイン成否のヒューリスティック判定。"""
        body = resp.text.lower()
        still_login = "type=\"password\"" in body or "type='password'" in body
        has_cookie  = len(session.cookies) > 0
        return (not still_login) and (has_cookie or resp.status_code in (301, 302, 303))

    # ── 内部ヘルパー ───────────────────────────────────────
    def _budget_left(self) -> bool:
        return self.transport.budget_left()

    def _stopped(self) -> bool:
        return self.transport.is_stopped()

    def _get(self, url, params=None, data=None, method="GET"):
        """origin検査・予算・ジッターを考慮してHTTPリクエストを送る。失敗時 None。"""
        if self.transport.is_stopped() or not self.transport.budget_left():
            return None
        lo, hi = self.jitter
        if hi > 0:
            # ジッター待機もSTOPで中断可能にする（transport.request()内の待機と同様）。
            if not self.transport.interruptible_sleep(random.uniform(lo, hi)):
                return None
        headers = {"User-Agent": random.choice(self._user_agents)}
        return self.transport.request(self.session, method, url,
                                      params=params, data=data, headers=headers,
                                      allow_redirects=False)

    # ── 1. クロール ────────────────────────────────────────
    def crawl(self, base_url: str) -> dict:
        """同一オリジンを浅くクロールし、注入点（クエリ／フォーム）を抽出する。"""
        base = base_url if base_url.startswith("http") else "http://" + base_url
        self.transport.bind_origin(base)  # 未確定なら基準originをここで確定（idempotent）
        seen: set[str] = set()
        queue = [base]
        injection_points: list[dict] = []
        pages_fetched = 0

        while queue and pages_fetched < self.max_pages and self._budget_left() and not self._stopped():
            url = queue.pop(0)
            norm = url.split("#")[0]
            if norm in seen:
                continue
            seen.add(norm)
            resp = self._get(norm)
            if resp is None:
                continue

            # URLに含まれるクエリパラメータは、レスポンスのContent-Typeに関わらず
            # 注入点として登録する（JSON API・ファイル配信系エンドポイント等、
            # text/html以外を返すページのパラメータも対象に含める）。
            # 以前はこの登録処理がtext/html限定のブロックの中にあったため、
            # 非HTMLレスポンスを返すエンドポイント（例: /api/profile?id=、
            # /files?name= のような JSON/plain-text 応答）のパラメータが
            # 構造的に検出漏れになっていた（試運転で発覚・IDOR/パストラバーサル
            # の検出漏れの原因）。
            for pname, pval in parse_qsl(urlsplit(norm).query):
                injection_points.append({
                    "url": norm.split("?")[0], "method": "GET", "where": "query",
                    "param": pname, "fields": dict(parse_qsl(urlsplit(norm).query)),
                })

            if "text/html" not in resp.headers.get("Content-Type", "text/html"):
                continue
            pages_fetched += 1
            body = resp.text
            self.log(f"crawl [{pages_fetched}] {norm} ({resp.status_code})")

            # フォームを抽出（HTML必須のためtext/html限定のまま）
            injection_points += self._extract_forms(norm, body)

            # 同一オリジン（scheme+host+port一致）のリンクのみ辿る。
            # ここでの除外は補助（クロール範囲を絞る最適化）であり、送信口
            # （HttpTransport.request）の検査を省略する根拠にはしない。
            for href in re.findall(r'href=["\']([^"\']+)["\']', body, re.I):
                nxt = urljoin(norm, href).split("#")[0]
                if nxt not in seen and self.transport.is_same_origin(nxt):
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
            # 別originへ送信するフォームは候補から除外する（補助的な最適化。
            # 実際の安全境界は送信口 HttpTransport.request() 側の検査）。
            if not self.transport.is_same_origin(action_url):
                continue
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
        if not self._budget_left() or self._stopped():
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
                if not self._budget_left() or self._stopped():
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

    # ── 3. アクセス制御不備(IDOR)チェック — 第2セッション比較（GET限定・検出のみ） ──
    def _detect_idor(self, points: list[dict]) -> list[dict]:
        """第2セッション（session_b）で、セッションAのみアクセス可能なはずの
        オブジェクトID風パラメータへ、同一URLへのGETのみで再取得し比較する。

        安全境界: GET等の非破壊メソッドに限定する（BOUNTY_ROADMAP.md Phase C）。
        POST/PUT/DELETE等の書き込み系メソッドは対象外（データ改変のリスクを避けるため）。
        GET限定は原則であり、サーバ側の実装次第（副作用のあるGETエンドポイント等）では
        100%の安全性を保証するものではない（advisorレビュー指摘・2026-08-16）。
        session_b が未設定（auth_b未設定）なら常に空リストを返す（後方互換）。
        """
        if self.session_b is None:
            return []
        findings: list[dict] = []
        seen_urls: set[str] = set()
        for p in points:
            if not self._budget_left():
                break
            if p["method"] != "GET":
                continue
            value = str(p.get("fields", {}).get(p["param"], ""))
            if not _OBJ_ID_RE.match(value):
                continue
            if p["url"] in seen_urls:
                continue
            seen_urls.add(p["url"])

            full_url = p["url"]
            if p.get("fields"):
                full_url = full_url + "?" + urlencode(p["fields"])

            resp_a = self._send_as(self.session, full_url)
            if resp_a is None or resp_a.status_code >= 400:
                continue
            resp_b = self._send_as(self.session_b, full_url)
            if resp_b is None:
                continue
            if resp_b.status_code == 200 and self._bodies_similar(resp_a.text, resp_b.text):
                findings.append({
                    "url": full_url, "param": p["param"], "method": p["method"],
                    "status_a": resp_a.status_code, "status_b": resp_b.status_code,
                    "evidence": (
                        "第2セッションが同一URLへのGETで200・類似コンテンツを取得"
                        "（本来アクセス権が無いはずの可能性 — 要人手確認）"
                    ),
                })
                self.log(f"  [!] IDOR? 兆候: {p['param']}@{full_url}")
        return findings

    def _send_as(self, session, url: str):
        """指定セッションでorigin検査・予算・ジッターを考慮してGETリクエストを送る。失敗時 None。"""
        if self.transport.is_stopped() or not self.transport.budget_left():
            return None
        lo, hi = self.jitter
        if hi > 0:
            if not self.transport.interruptible_sleep(random.uniform(lo, hi)):
                return None
        headers = {"User-Agent": random.choice(self._user_agents)}
        return self.transport.request(session, "GET", url, headers=headers,
                                      allow_redirects=False)

    @staticmethod
    def _bodies_similar(a: str, b: str, threshold: float = 0.6) -> bool:
        """簡易類似度判定（同一オブジェクトのレスポンスかどうかの粗い近似）。

        最終判定ではなく、AIトリアージに渡す追加エビデンスの選別に使うだけなので、
        厳密な差分アルゴリズムではなく長さ比という粗い近似で十分とする。
        """
        if not a or not b:
            return False
        la, lb = len(a), len(b)
        return min(la, lb) / max(la, lb) >= threshold

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
