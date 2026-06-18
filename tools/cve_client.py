"""
tools/cve_client.py — NVD (National Vulnerability Database) APIクライアント

CWE IDで関連CVEを検索し、監査レポートを充実させる。
API: https://nvd.nist.gov/developers/vulnerabilities (無料・APIキー不要)
レート制限: 5リクエスト/30秒（APIキーなし）のため、呼び出し間に遅延を設ける。
"""

from __future__ import annotations
from functools import lru_cache

try:
    import requests as _req
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT  = 12


@lru_cache(maxsize=256)
def search_by_cwe(cwe_id: str, max_results: int = 5) -> list[tuple[str, str, str]]:
    """
    CWE IDで最新の関連CVEを検索する。
    Returns: list of (cve_id, cvss_score, short_description)
    ネットワーク未接続・エラー時は空リストをサイレント返却する。
    """
    if not _AVAILABLE:
        return []
    try:
        resp = _req.get(
            _BASE_URL,
            params={"cweId": cwe_id, "resultsPerPage": max_results},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        results: list[tuple[str, str, str]] = []
        for v in vulns:
            cve  = v.get("cve", {})
            cid  = cve.get("id", "")
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )[:160]
            score = "N/A"
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    score = str(entries[0].get("cvssData", {}).get("baseScore", "N/A"))
                    break
            results.append((cid, score, desc))
        return results
    except Exception:
        return []


def format_results(results: list[tuple[str, str, str]]) -> str:
    """検索結果を表示用文字列にフォーマットする。"""
    if not results:
        return "  (CVEデータベースに関連エントリなし、またはネットワーク未接続)\n"
    lines = []
    for cid, score, desc in results:
        lines.append(f"  ▸ [{cid}]  CVSS: {score}")
        if desc:
            lines.append(f"    {desc}")
    return "\n".join(lines) + "\n"
