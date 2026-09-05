"""
core/http_transport.py — WEB FUZZ全送信経路の同一origin検査・共有予算・手動リダイレクト制御 (P0.1)

設計方針（docs/PRACTICAL_ROADMAP.md §4 P0.1 の設計契約）:
  - 唯一の送信口: `HttpTransport.request()` を通さない送信経路を作らない。
  - 送信直前にorigin検査: フォーム抽出時の除外等は補助であり、ここでの検査を省略しない。
  - 予約は原子的: 予算はスキャン単位でA/Bセッションが共有し、並列実行しても超過しない。
  - 自動リダイレクト無効: hopごとに再検査・再予約しながら手動追跡する。POSTの
    301/302/307/308は初期版では自動再送しない（認証未確認として扱う）。
  - 外部SSO/IdPのログイン追跡は非対応: base originと異なるURLへの送信は
    常に拒否されるため、認証情報・Cookieが別originへ渡ることは構造的にない。

このモジュールは検出のみ・非DoSという既存の安全設計を変更しない。TLS検証・レート制御・
停止イベントはP0.2で扱う（ここでは既存の `session.verify` をそのまま利用する）。
"""

from __future__ import annotations
import threading
from dataclasses import dataclass
from urllib.parse import urlsplit, urljoin

import requests

_DEFAULT_PORTS = {"http": 80, "https": 443}
_REDIRECT_CODES = (301, 302, 303, 307, 308)
_DEFAULT_MAX_REDIRECT_HOPS = 5


@dataclass(frozen=True)
class Origin:
    scheme: str
    host: str
    port: int

    def __str__(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


def normalize_origin(url: str) -> Origin | None:
    """HTTP/HTTPSのみ受理し、scheme・正規化host・実効portを返す。不正なら None。

    - userinfo付きURL（user:pass@host）は拒否する。
    - schemeはhttp/httpsのみ。両者は別originとして扱う。
    - IPv6リテラルは urlsplit().hostname が括弧なしで返す表現をそのまま比較に使う。
    - portは省略時にscheme既定値（http=80, https=443）を補う。不正port（範囲外・非数値）は拒否。
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    if scheme not in _DEFAULT_PORTS:
        return None
    if parts.username or parts.password:
        return None
    host = parts.hostname
    if not host:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    return Origin(scheme=scheme, host=host.lower(), port=port)


class OriginRejected(Exception):
    """送信先originが基準origin範囲外、または基準origin未確定のまま送信しようとした。"""

    def __init__(self, url: str, reason: str):
        super().__init__(f"{reason}: {url}")
        self.url = url
        self.reason = reason


class HttpTransport:
    """WEB FUZZの全送信を一元化する送信口。

    A/Bセッション（IDOR比較用の第2アカウント含む）はこのインスタンスを共有することで、
    予算・基準originを1スキャン単位で共有する（docs/PRACTICAL_ROADMAP.md §4 P0.1 契約5）。
    """

    def __init__(self, max_requests: int, timeout: int = 8,
                 max_redirect_hops: int = _DEFAULT_MAX_REDIRECT_HOPS):
        self.max_requests = max_requests
        self.timeout = timeout
        self.max_redirect_hops = max_redirect_hops
        self._base_origin: Origin | None = None
        self._req_count = 0
        self._lock = threading.Lock()
        # request()がNoneを返した直近の理由（呼び出し側が原因を区別したい場合の補助情報。
        # "origin_rejected" / "budget_exhausted" / "network_error" のいずれか）。
        self._last_error: str | None = None

    # ── 基準origin ──────────────────────────────────────
    def bind_origin(self, url: str) -> None:
        """基準originを確定する。認証・クロールより前に呼ぶ。二重呼び出しは最初の値を維持する。"""
        if self._base_origin is not None:
            return
        origin = normalize_origin(url)
        if origin is None:
            raise OriginRejected(url, "対象URLのorigin確定に失敗（http/https以外、または不正URL）")
        self._base_origin = origin

    @property
    def base_origin(self) -> Origin | None:
        return self._base_origin

    def is_same_origin(self, url: str) -> bool:
        """基準origin未確定、または解析不能なurlの場合は False。"""
        if self._base_origin is None:
            return False
        origin = normalize_origin(url)
        return origin is not None and origin == self._base_origin

    def _check_origin(self, url: str) -> None:
        if self._base_origin is None:
            raise OriginRejected(url, "基準origin未確定のまま送信しようとした")
        origin = normalize_origin(url)
        if origin is None or origin != self._base_origin:
            raise OriginRejected(url, f"送信先originが基準origin範囲外(base={self._base_origin})")

    # ── 予算 ────────────────────────────────────────────
    def reserve(self) -> bool:
        """1件分の送信予算を原子的に予約する。取得できれば True。"""
        with self._lock:
            if self._req_count >= self.max_requests:
                return False
            self._req_count += 1
            return True

    @property
    def req_count(self) -> int:
        return self._req_count

    def budget_left(self) -> bool:
        return self._req_count < self.max_requests

    @property
    def last_error(self) -> str | None:
        """直近の request() がNoneを返した理由。呼び出し元がメッセージを組み立てる補助。"""
        return self._last_error

    # ── 唯一の送信口 ────────────────────────────────────
    def request(self, session: requests.Session, method: str, url: str, *,
                params=None, data=None, headers=None,
                allow_redirects: bool = False) -> requests.Response | None:
        """origin検査→予算予約→送信を1件ずつ行う唯一の送信経路。

        戻り値: origin範囲外・予算切れ・通信例外は None（呼び出し側は従来どおり
        None チェックのみで済む）。allow_redirects=True の場合のみ、hopごとに
        再検査・再予約しながら手動でリダイレクトを追跡する
        （GETの301/302/303/307/308、POSTの303→GETのみ）。
        POSTの301/302/307/308は初期版では追跡せず、その時点の応答をそのまま返す
        （呼び出し側で認証未確認として扱うことを想定）。
        """
        self._last_error = None
        try:
            self._check_origin(url)
        except OriginRejected:
            self._last_error = "origin_rejected"
            return None
        resp = self._send_one(session, method, url, params=params, data=data, headers=headers)
        if resp is None or not allow_redirects:
            return resp

        hops = 0
        cur_method, cur_data = method, data
        while resp is not None and resp.status_code in _REDIRECT_CODES and hops < self.max_redirect_hops:
            loc = resp.headers.get("Location")
            if not loc:
                break
            next_url = urljoin(resp.url, loc)
            try:
                self._check_origin(next_url)
            except OriginRejected:
                break  # 別originへの転送は追跡しない（認証情報・Cookieを渡さない）
            if resp.status_code == 303 and cur_method == "POST":
                cur_method, cur_data = "GET", None
            elif cur_method == "POST":
                # POSTの301/302/307/308は初期版では自動再送しない（認証未確認）
                break
            hops += 1
            # Locationは絶対URLへ解決済み（next_url）なので、hop以降はparamsを
            # 引き継がない（元のparamsを再付与すると二重・不整合になるため）。
            nxt = self._send_one(session, cur_method, next_url, data=cur_data, headers=headers)
            if nxt is None:
                return None
            resp = nxt
        return resp

    def _send_one(self, session: requests.Session, method: str, url: str, *,
                  params=None, data=None, headers=None) -> requests.Response | None:
        """予算を1件予約してから送信する（失敗した通信も予算を消費する）。"""
        if not self.reserve():
            self._last_error = "budget_exhausted"
            return None
        try:
            resp = session.request(method, url, params=params, data=data,
                                   headers=headers, timeout=self.timeout,
                                   allow_redirects=False)
            self._last_error = None
            return resp
        except requests.RequestException:
            self._last_error = "network_error"
            return None
