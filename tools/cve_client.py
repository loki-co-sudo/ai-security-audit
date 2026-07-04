"""
tools/cve_client.py — NVD (National Vulnerability Database) APIクライアント

CWE IDで関連CVEを検索し、監査レポートを充実させる。
API: https://nvd.nist.gov/developers/vulnerabilities (無料・APIキー不要)
レート制限: 5リクエスト/30秒（APIキーなし）のため、呼び出し間に遅延を設ける。
"""

from __future__ import annotations
import json
import os
import time
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor

try:
    import requests as _req
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT  = 12

# 永続キャッシュ: reports/cve_cache.json（TTL=1日）
_CACHE_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
_CACHE_FILE = os.path.join(_CACHE_DIR, "cve_cache.json")
_CACHE_TTL  = 86400  # 1日（秒）
_parallel_executor: ThreadPoolExecutor | None = None


def _get_executor() -> ThreadPoolExecutor:
    global _parallel_executor
    if _parallel_executor is None:
        _parallel_executor = ThreadPoolExecutor(max_workers=6)
    return _parallel_executor


def _load_persistent_cache() -> dict[str, list[tuple[str, str, str]]]:
    """永続キャッシュファイルを読み込む。TTL切れのエントリは破棄。"""
    if not os.path.isfile(_CACHE_FILE):
        return {}
    try:
        with open(_CACHE_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return {}
    now   = time.time()
    valid = {}
    for cwe_id, entry in raw.items():
        if isinstance(entry, dict) and now - entry.get("ts", 0) < _CACHE_TTL:
            valid[cwe_id] = [tuple(t) for t in entry.get("data", [])]
    return valid


def _save_persistent_cache(cache: dict[str, list[tuple[str, str, str]]]) -> None:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    now = time.time()
    out: dict[str, dict] = {}
    for cwe_id, results in cache.items():
        out[cwe_id] = {"ts": now, "data": [list(r) for r in results]}
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False)
    except Exception:
        pass


# メモリキャッシュ（起動中のみ有効）＋ 永続キャッシュ（ディスク）
@lru_cache(maxsize=256)
def search_by_cwe(cwe_id: str, max_results: int = 5) -> list[tuple[str, str, str]]:
    """
    CWE IDで最新の関連CVEを検索する。
    Returns: list of (cve_id, cvss_score, short_description)
    まず永続キャッシュを参照し、ヒットしなければNVD APIを呼び出す。
    ネットワーク未接続・エラー時は空リストをサイレント返却する。
    """
    if not _AVAILABLE:
        return []

    # 永続キャッシュを先に確認
    persistent = _load_persistent_cache()
    if cwe_id in persistent:
        return persistent[cwe_id][:max_results]

    # NVD API呼び出し
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

        # 永続キャッシュに保存
        if results:
            persistent[cwe_id] = results
            _save_persistent_cache(persistent)

        return results
    except Exception:
        return []


def search_batch(cwe_ids: list[str], max_results: int = 5) -> dict[str, list[tuple[str, str, str]]]:
    """複数CWEを並列検索し、CWE ID → 結果リスト のdictを返す。"""
    if not _AVAILABLE or not cwe_ids:
        return {}
    executor = _get_executor()
    futures = {executor.submit(search_by_cwe, cwe_id, max_results): cwe_id for cwe_id in cwe_ids}
    results: dict[str, list[tuple[str, str, str]]] = {}
    for future in futures:
        cwe_id = futures[future]
        try:
            results[cwe_id] = future.result(timeout=_TIMEOUT + 5)
        except Exception:
            results[cwe_id] = []
    return results


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