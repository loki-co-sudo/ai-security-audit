"""
core/http_transport.py — WEB FUZZ全送信経路の同一origin検査・共有予算・
手動リダイレクト制御・レート/429/STOP制御 (P0.1 + P0.2)

設計方針（docs/PRACTICAL_ROADMAP.md §4 の設計契約）:
  - 唯一の送信口: `HttpTransport.request()` を通さない送信経路を作らない。
  - 送信直前にorigin検査: フォーム抽出時の除外等は補助であり、ここでの検査を省略しない。
  - 予約は原子的: 予算はスキャン単位でA/Bセッションが共有し、並列実行しても超過しない。
  - 自動リダイレクト無効: hopごとに再検査・再予約しながら手動追跡する。POSTの
    301/302/307/308は初期版では自動再送しない（認証未確認として扱う）。
  - 外部SSO/IdPのログイン追跡は非対応: base originと異なるURLへの送信は
    常に拒否されるため、認証情報・Cookieが別originへ渡ることは構造的にない。
  - レート上限・429バックオフ・STOPによる待機中断・応答サイズ上限を`RequestPolicy`に集約する（P0.2）。
    プローブ・認証POSTは自動再試行しない。GETの429リトライのみ有限回・予算内で行う。

このモジュールは検出のみ・非DoSという既存の安全設計を変更しない。TLS検証はP0.2で
`core/settings.py`/`core/config.py`側の設定として扱い、ここでは呼び出し側が設定した
`session.verify`をそのまま利用する（このモジュール自身はTLS設定を持たない）。
"""

from __future__ import annotations
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit, urljoin

import requests

_DEFAULT_PORTS = {"http": 80, "https": 443}
_REDIRECT_CODES = (301, 302, 303, 307, 308)
_DEFAULT_MAX_REDIRECT_HOPS = 5
_DEFAULT_MAX_CONSECUTIVE_429 = 3
_DEFAULT_MAX_BACKOFF_SECONDS = 30.0
_DEFAULT_MAX_RESPONSE_BYTES = 5_000_000  # 1レスポンスあたりの読取上限（メモリ膨張防止）


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


@dataclass
class RequestPolicy:
    """送信ポリシー（P0.2）。設定値をエージェント/GUIへ直書きせずここに集約する。"""

    max_requests: int
    timeout: int = 8
    max_redirect_hops: int = _DEFAULT_MAX_REDIRECT_HOPS
    rate_per_sec: float | None = None       # 秒あたり送信数の上限。None/0以下は無制限
    max_consecutive_429: int = _DEFAULT_MAX_CONSECUTIVE_429  # GET限定・429の連続リトライ上限
    max_backoff_seconds: float = _DEFAULT_MAX_BACKOFF_SECONDS  # Retry-After不正値時の上限。
    # 有効なRetry-Afterでもこれを超える待機は「実行期限超過」とみなし再送しない。
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES  # 1レスポンスの読取上限


class HttpTransport:
    """WEB FUZZの全送信を一元化する送信口。

    A/Bセッション（IDOR比較用の第2アカウント含む）はこのインスタンスを共有することで、
    予算・レート・基準originを1スキャン単位で共有する（PRACTICAL_ROADMAP.md §4 P0.1 契約5）。
    """

    def __init__(self, max_requests: int | None = None, timeout: int = 8,
                 max_redirect_hops: int = _DEFAULT_MAX_REDIRECT_HOPS, *,
                 policy: RequestPolicy | None = None,
                 stop_event: threading.Event | None = None,
                 clock=time.monotonic, sleeper=time.sleep):
        """policy未指定時は max_requests/timeout/max_redirect_hops から既定値付きで組み立てる
        （既存呼び出し元との後方互換）。clock/sleeper はテストで仮想時計に差し替えるためのフック。
        """
        if policy is None:
            if max_requests is None:
                raise ValueError("max_requests または policy のいずれかが必要です")
            policy = RequestPolicy(max_requests=max_requests, timeout=timeout,
                                   max_redirect_hops=max_redirect_hops)
        self.policy = policy
        self._base_origin: Origin | None = None
        self._req_count = 0
        self._lock = threading.Lock()
        self._next_allowed_at = 0.0  # レート制御: 次に送信可能な時刻（self._clock()と同じ時間軸）
        # request()がNoneを返した直近の理由（呼び出し側が原因を区別したい場合の補助情報。
        # "origin_rejected" / "budget_exhausted" / "stopped" / "network_error" のいずれか）。
        self._last_error: str | None = None
        self._stop_event = stop_event
        self._clock = clock
        self._sleeper = sleeper

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
            if self._req_count >= self.policy.max_requests:
                return False
            self._req_count += 1
            return True

    @property
    def req_count(self) -> int:
        return self._req_count

    @property
    def max_requests(self) -> int:
        return self.policy.max_requests

    def budget_left(self) -> bool:
        return self._req_count < self.policy.max_requests

    @property
    def last_error(self) -> str | None:
        """直近の request() がNoneを返した理由。呼び出し元がメッセージを組み立てる補助。

        単一のインスタンス属性であり、並列送信（fuzz()のThreadPoolExecutor経由の
        呼び出し）では別スレッドの結果で上書きされうる。並列パスでは信頼しないこと
        （現状は単一スレッドで呼ぶ_form_login/認証系の呼び出しのみがこれを参照する）。
        """
        return self._last_error

    # ── STOP ────────────────────────────────────────────
    def is_stopped(self) -> bool:
        return self._stop_event is not None and self._stop_event.is_set()

    def _sleep_interruptible(self, seconds: float) -> bool:
        """指定秒数待機する。STOPがセットされたら早期終了しFalse（待機未完了）を返す。"""
        if seconds <= 0:
            return True
        if self._stop_event is None:
            self._sleeper(seconds)
            return True
        end = self._clock() + seconds
        while self._clock() < end:
            if self._stop_event.is_set():
                return False
            self._sleeper(min(0.1, end - self._clock()))
        return True

    def interruptible_sleep(self, seconds: float) -> bool:
        """呼び出し側（WebFuzzerのジッター待機等）向けの公開ラッパー。

        送信の待機に限らず、STOPで中断すべき任意の待機はこれを経由させ、
        `time.sleep()`を直接呼んで停止不能な待機を作らないようにする。
        """
        return self._sleep_interruptible(seconds)

    # ── レート制御（秒あたり送信数の上限。全セッション共有） ──
    def _throttle(self) -> bool:
        """rate_per_sec設定に従い、必要なら次の送信可能時刻まで待つ。STOPで中断されたらFalse。"""
        rate = self.policy.rate_per_sec
        if not rate or rate <= 0:
            return True
        min_interval = 1.0 / rate
        with self._lock:
            now = self._clock()
            wait = self._next_allowed_at - now
            self._next_allowed_at = (self._next_allowed_at if wait > 0 else now) + min_interval
        return self._sleep_interruptible(max(0.0, wait))

    # ── 429 Retry-After ─────────────────────────────────
    def _retry_after_seconds(self, resp: requests.Response) -> float:
        """Retry-Afterを秒数へ変換する。秒表記・HTTP-date双方に対応。

        欠落・不正値は上限付きの既定バックオフ（1秒）とする。有効な値はそのまま返す
        （max_backoff_secondsを超えるかどうかは呼び出し側で判定し、超える場合は
        ここで丸めて再送するのではなく「早く再送せず未完了として終了する」）。
        """
        raw = (resp.headers.get("Retry-After") or "").strip()
        cap = self.policy.max_backoff_seconds
        if not raw:
            return min(1.0, cap)
        if raw.isdigit():
            return max(0.0, float(raw))
        try:
            dt = parsedate_to_datetime(raw)
        except (TypeError, ValueError, OverflowError):
            return min(1.0, cap)
        if dt is None:
            return min(1.0, cap)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.fromtimestamp(time.time(), tz=timezone.utc)
        delta = (dt - now).total_seconds()
        return max(0.0, delta)

    # ── 唯一の送信口 ────────────────────────────────────
    def request(self, session: requests.Session, method: str, url: str, *,
                params=None, data=None, headers=None,
                allow_redirects: bool = False) -> requests.Response | None:
        """origin検査→予算予約→レート制御→送信を1件ずつ行う唯一の送信経路。

        戻り値: origin範囲外・予算切れ・STOP前・通信例外は None（呼び出し側は従来どおり
        None チェックのみで済む）。429はGETに限り`max_consecutive_429`回まで
        Retry-Afterに従って再送する（POST・プローブ送信は自動再試行しない）。
        Retry-Afterが`max_backoff_seconds`を超える場合、または待機中にSTOPされた場合は
        再送せず直近の429応答をそのまま返す（`last_error`に理由を残す。未完了として扱う）。
        allow_redirects=True の場合のみ、hopごとに再検査・再予約しながら手動で
        リダイレクトを追跡する（GETの301/302/303/307/308、POSTの303→GETのみ）。
        POSTの301/302/307/308は初期版では追跡せず、その時点の応答をそのまま返す
        （呼び出し側で認証未確認として扱うことを想定）。
        """
        self._last_error = None
        try:
            self._check_origin(url)
        except OriginRejected:
            self._last_error = "origin_rejected"
            return None
        resp = self._send_with_429_retry(session, method, url, params=params,
                                         data=data, headers=headers)
        if resp is None or not allow_redirects:
            return resp

        hops = 0
        cur_method, cur_data = method, data
        while resp is not None and resp.status_code in _REDIRECT_CODES and hops < self.policy.max_redirect_hops:
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
            nxt = self._send_with_429_retry(session, cur_method, next_url, data=cur_data, headers=headers)
            if nxt is None:
                return None
            resp = nxt
        return resp

    def _send_with_429_retry(self, session: requests.Session, method: str, url: str, *,
                             params=None, data=None, headers=None) -> requests.Response | None:
        """429はGETに限り、Retry-Afterに従い有限回・予算内で再送する。

        POST（ログイン送信・状態変更を伴う可能性のある送信）は自動再試行しない
        （初期版の安全設計。プローブ送信も同様に扱う想定で、呼び出し側は本メソッドを
        通す限り自動では再試行されない）。
        """
        attempts = 0
        resp = self._send_one(session, method, url, params=params, data=data, headers=headers)
        while (resp is not None and resp.status_code == 429 and method == "GET"
               and attempts < self.policy.max_consecutive_429):
            wait = self._retry_after_seconds(resp)
            if wait > self.policy.max_backoff_seconds:
                # 実行期限超過とみなし、早く再送せず未完了として終了する
                self._last_error = "retry_after_exceeded"
                return resp
            if not self._sleep_interruptible(wait):
                self._last_error = "stopped"
                return resp  # STOPで中断。直近の429応答をそのまま返す(要再検査)
            attempts += 1
            nxt = self._send_one(session, method, url, params=params, data=data, headers=headers)
            if nxt is None:
                return None
            resp = nxt
        if resp is not None and resp.status_code == 429 and method == "GET":
            # max_consecutive_429に達して打ち切り（呼び出し側は429をそのまま観測する）
            self._last_error = "rate_limited"
        return resp

    def _send_one(self, session: requests.Session, method: str, url: str, *,
                  params=None, data=None, headers=None) -> requests.Response | None:
        """STOP確認→予算予約→レート制御→送信を行う（失敗した通信も予算を消費する）。"""
        if self.is_stopped():
            self._last_error = "stopped"
            return None
        if not self.reserve():
            self._last_error = "budget_exhausted"
            return None
        if not self._throttle():
            self._last_error = "stopped"
            return None
        if self.is_stopped():
            self._last_error = "stopped"
            return None
        try:
            resp = session.request(method, url, params=params, data=data,
                                   headers=headers, timeout=self.policy.timeout,
                                   allow_redirects=False, stream=True)
        except requests.RequestException:
            self._last_error = "network_error"
            return None
        self._cap_response_body(resp)
        self._last_error = None
        return resp

    def _cap_response_body(self, resp: requests.Response) -> None:
        """応答本文の読取を`max_response_bytes`・`timeout`（読取時間）で打ち切る
        （メモリ膨張・低速回線での引き延ばしDoS対策）。

        `stream=True`で送信するため、ここで明示的に読み切らないと接続が保持されたままになる。
        上限以内であれば通常の`.content`アクセスと同じ結果になる（切り詰めなし）。
        打ち切った場合は `resp.fz_truncated = True` を付与する（P1.2の証拠に
        「省略理由」として引き継ぐためのマーカー。現時点ではログ/証拠保存はしない）。
        """
        cap = self.policy.max_response_bytes
        resp.fz_truncated = False
        if not cap or cap <= 0:
            resp.content  # 通常どおり全文読み取り（アクセスした時点でrequestsが読む）
            return
        chunks: list[bytes] = []
        total = 0
        start = self._clock()
        truncated = False
        try:
            for chunk in resp.iter_content(chunk_size=65536):
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total >= cap:
                    truncated = True
                    break
                if self._clock() - start > self.policy.timeout:
                    truncated = True  # 低速回線での読取引き延ばし対策（時間上限）
                    break
        except requests.RequestException:
            pass
        finally:
            resp.close()
        body = b"".join(chunks)[:cap]
        resp._content = body
        resp._content_consumed = True
        resp.fz_truncated = truncated
