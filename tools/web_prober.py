"""
tools/web_prober.py — HTTP/Webターゲット列挙

技術スタック検出・セキュリティヘッダー評価・センシティブパス探索。
"""

from __future__ import annotations
import re
import concurrent.futures
from typing import Callable
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from core.settings import SENSITIVE_PATHS, SECURITY_HEADERS, WEB_REQUEST_TIMEOUT

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
    def __init__(self, timeout: int = WEB_REQUEST_TIMEOUT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Audit Tool / Authorized Test)"
        })

    def probe(
        self,
        base_url: str,
        on_progress: Callable[[str], None] | None = None,
    ) -> dict:
        """ターゲットURLを総合的にプローブし、収集情報をdictで返す。"""
        result: dict = {
            "url":              base_url,
            "status_code":      None,
            "headers":          {},
            "missing_headers":  [],
            "technologies":     [],
            "found_paths":      [],
            "ssl_info":         None,
            "cookies":          [],
            "forms_info":       [],
        }

        def _log(msg): on_progress(msg) if on_progress else None

        # ── メインページ取得 ───────────────────────────────
        _log(f"Fetching {base_url} ...")
        try:
            resp = self.session.get(base_url, timeout=self.timeout, allow_redirects=True)
            result["status_code"] = resp.status_code
            result["headers"]     = dict(resp.headers)
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
        _log(f"Probing {len(SENSITIVE_PATHS)} sensitive paths ...")
        result["found_paths"] = self._scan_paths(base_url, SENSITIVE_PATHS)
        _log(f"Found {len(result['found_paths'])} accessible paths")

        # ── SSL情報 ────────────────────────────────────────
        if base_url.startswith("https://"):
            result["ssl_info"] = self._check_ssl(base_url)

        return result

    def _detect_technologies(self, headers: dict, body: str) -> list[str]:
        found = []
        combined = str(headers) + body
        for tech, patterns in TECH_SIGNATURES.items():
            if any(re.search(p, combined, re.I) for p in patterns):
                found.append(tech)
        return found

    def _scan_paths(self, base_url: str, paths: list[str]) -> list[dict]:
        base = base_url.rstrip("/")
        found = []

        def _check(path):
            url = base + path
            try:
                r = self.session.get(url, timeout=4, allow_redirects=False)
                if r.status_code not in (404, 400, 403):
                    return {"path": path, "status": r.status_code, "size": len(r.content)}
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            for result in ex.map(_check, paths):
                if result:
                    found.append(result)
        return found

    def _analyze_cookies(self, cookies) -> list[dict]:
        result = []
        for c in cookies:
            issues = []
            if not c.secure:    issues.append("Missing Secure flag")
            if not c.has_nonstandard_attr("httponly") and "httponly" not in str(c).lower():
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
