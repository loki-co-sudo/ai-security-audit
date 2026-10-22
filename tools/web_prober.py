"""
tools/web_prober.py — HTTP/Webターゲット列挙

技術スタック検出・セキュリティヘッダー評価・センシティブパス探索。
"""

from __future__ import annotations
import hashlib
import re
import random
import uuid
import time
import concurrent.futures
from typing import Callable
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from core.settings import (
    SENSITIVE_PATHS, SECURITY_HEADERS, WEB_REQUEST_TIMEOUT,
    SCAN_PROFILES, DEFAULT_SCAN_PROFILE, STEALTH_USER_AGENTS,
)

TECH_SIGNATURES = {
    "WordPress":    [r"wp-content", r"wp-includes", r"WordPress"],
    "Drupal":       [r"Drupal", r"/sites/default/"],
    "Joomla":       [r"Joomla", r"/components/com_"],
    "Django":       [r"csrfmiddlewaretoken", r"Django"],
    "Laravel":      [r"laravel_session", r"Laravel"],
    "React":        [r"react\.development\.js", r"__REACT_DEVTOOLS"],
    "Angular":      [r"ng-version", r"angular\.min\.js"],
    "Vue.js":       [r"vue\.min\.js", r"__VUE__"],
    "jQuery":       [r"jquery\.min\.js", r"jQuery v"],
    "Bootstrap":    [r"bootstrap\.min\.css", r"bootstrap\.bundle"],
    "ASP.NET":      [r"__VIEWSTATE", r"X-AspNet-Version", r"ASP\.NET"],
    "PHP":          [r"X-Powered-By: PHP", r"\.php"],
    "Ruby on Rails": [r"_rails_session", r"X-Runtime"],
    "Express.js":   [r"X-Powered-By: Express"],
    "Spring Boot":  [r"X-Application-Context", r"Whitelabel Error Page"],
    "Apache":       [r"Server: Apache"],
    "Nginx":        [r"Server: nginx"],
    "IIS":          [r"Server: Microsoft-IIS", r"X-Powered-By: ASP\.NET"],
    "Cloudflare":   [r"cf-ray", r"Server: cloudflare"],
}


class WebProber:
    def __init__(
        self,
        timeout: int = WEB_REQUEST_TIMEOUT,
        profile: str = DEFAULT_SCAN_PROFILE,
    ):
        self.timeout = timeout
        prof = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_SCAN_PROFILE])
        self.path_threads = prof["path_threads"]
        self.path_jitter  = prof["path_jitter"]
        self.max_paths    = prof["max_paths"]
        self.session = requests.Session()
        self.session.verify = False
        # 実在ブラウザを模したUAをローテーション（自己申告UAは検知を誘発するため不使用）
        self._user_agents = list(STEALTH_USER_AGENTS)
        self.session.headers.update({"User-Agent": random.choice(self._user_agents)})

    def _rotate_ua(self) -> str:
        """リクエストごとに使い回すUAを1つ返す。"""
        return random.choice(self._user_agents)

    def probe(
        self,
        base_url: str,
        on_progress: Callable[[str], None] | None = None,
        capture_body: bool = False,
    ) -> dict:
        """ターゲットURLを総合的にプローブし、収集情報をdictで返す。"""
        result: dict = {
            "url":              base_url,
            "status_code":      None,
            "headers":          {},
            "missing_headers":  [],
            "technologies":     [],
            "found_paths":      [],
            "soft_404":         None,     # 存在しないpathにも同じ応答を返すサーバーなら{status, note}
            "ssl_info":         None,
            "cookies":          [],
            "forms_info":       [],
            "body":             None,
        }

        def _log(msg): on_progress(msg) if on_progress else None

        # ── メインページ取得 ───────────────────────────────
        _log(f"Fetching {base_url} ...")
        try:
            resp = self.session.get(base_url, timeout=self.timeout, allow_redirects=True)
            result["status_code"] = resp.status_code
            result["headers"]     = dict(resp.headers)
            if capture_body:
                # CTF Flag Hunt向け（既定オフ）。capture_body=False（既定）では従来どおり
                # result["body"] は None のままで、メモリ/レポートへの影響は一切ない。
                result["body"] = resp.text[:200000]
            body = resp.text[:50000]

            # セキュリティヘッダー確認
            result["missing_headers"] = [
                h for h in SECURITY_HEADERS
                if h.lower() not in {k.lower() for k in resp.headers}
            ]

            # 技術スタック検出
            result["technologies"] = self._detect_technologies(resp.headers, body)
            _log(f"Detected {len(result['technologies'])} technologies")

            # Cookie分析
            result["cookies"] = self._analyze_cookies(resp.cookies)

        except requests.RequestException as e:
            _log(f"Main page error: {e}")

        # ── センシティブパス探索 ───────────────────────────
        # ステルスプロファイルでは探索パス数を絞ってノイズを抑える
        paths = SENSITIVE_PATHS if self.max_paths is None else SENSITIVE_PATHS[: self.max_paths]
        _log(f"Probing {len(paths)} sensitive paths ...")
        result["found_paths"], result["soft_404"] = self._scan_paths(base_url, paths)
        _log(f"Found {len(result['found_paths'])} accessible paths")

        # ── SSL情報 ────────────────────────────────────────
        if base_url.startswith("https://"):
            result["ssl_info"] = self._check_ssl(base_url)

        return result

    def _detect_technologies(self, headers: dict, body: str) -> list[str]:
        found = []
        combined = "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + body     # 'Server: nginx'形式でシグネチャに当てる
        for tech, patterns in TECH_SIGNATURES.items():
            if any(re.search(p, combined, re.I) for p in patterns):
                found.append(tech)
        return found

    @staticmethod
    def _fingerprint(status: int, content: bytes, path: str) -> tuple[int, str]:
        """応答の指紋。要求pathを本文から除いて(pathを反映するエラーページ対策)ハッシュする。"""
        return status, hashlib.sha256(content.replace(path.encode(), b"")).hexdigest()

    def _scan_paths(self, base_url: str, paths: list[str]) -> tuple[list[dict], dict | None]:
        """(見つかったpath, soft-404情報)。実在しないはずのpathを先に1回取得し、同じ応答を返すpathは実在の根拠にしない。

        found_pathsの各要素のexposedは2xx(内容を返した)か。3xx/401/5xx等は存在の兆候として残すがexposed=False。
        指紋はstatusと(path除去後の)本文ハッシュ。時刻など毎回変わる本文のcatch-allは見分けられず、報告側に残る。
        """
        base = base_url.rstrip("/")
        found = []
        soft: dict | None = None
        fingerprint = None
        canary = f"/{uuid.uuid4().hex}-nonexistent"
        try:
            r = self.session.get(base + canary, timeout=4, allow_redirects=False,
                                 headers={"User-Agent": self._rotate_ua()})
            if r.status_code not in (404, 400, 403):
                fingerprint = self._fingerprint(r.status_code, r.content, canary)
                soft = {"status": r.status_code, "note": "存在しないpathにも同じ応答を返すため、同一応答のpathは実在の根拠にしません"}
        except Exception:
            pass

        lo, hi = self.path_jitter

        def _check(path):
            # レート検知を回避するため各リクエスト前にランダム遅延
            if hi > 0:
                time.sleep(random.uniform(lo, hi))
            url = base + path
            try:
                r = self.session.get(
                    url, timeout=4, allow_redirects=False,
                    headers={"User-Agent": self._rotate_ua()},
                )
                if r.status_code not in (404, 400, 403):
                    if fingerprint and self._fingerprint(r.status_code, r.content, path) == fingerprint:
                        return None
                    return {"path": path, "status": r.status_code, "size": len(r.content),
                            "exposed": 200 <= r.status_code < 300}
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.path_threads) as ex:
            for result in ex.map(_check, paths):
                if result:
                    found.append(result)
        return found, soft

    def _analyze_cookies(self, cookies) -> list[dict]:
        result = []
        for c in cookies:
            issues = []
            if not c.secure:    issues.append("Missing Secure flag")
            if not any(str(k).lower() == "httponly" for k in getattr(c, "_rest", {})):      # 属性名の大文字小文字は応答次第
                issues.append("Missing HttpOnly flag")
            result.append({"name": c.name, "issues": issues})
        return result

    def _check_ssl(self, url: str) -> str:
        try:
            import ssl, socket
            host = url.replace("https://", "").split("/")[0]
            ctx  = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, 443))
                cert = s.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                return f"CN={subject.get('commonName','')} expires={cert.get('notAfter','')}"
        except Exception as e:
            return str(e)
