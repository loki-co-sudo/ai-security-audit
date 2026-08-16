"""
tools/subdomain_enum.py — バグバウンティ対応: 受動的サブドメイン列挙（BOUNTY_ROADMAP.md Phase B）

証明書透明化ログ（crt.sh）への単発GET照会のみでサブドメインを収集する。
対象への追加通信は発生しない（受動的偵察）。

注意: crt.sh は過去に発行された証明書の記録であり、発見したサブドメインが
現在も対象組織の管理下にあるとは限らない（dangling subdomainの可能性）。
生存確認・所有確認は呼び出し側（recon_agent の出力）で促す。
"""

from __future__ import annotations
import json

import requests

_CRTSH_URL = "https://crt.sh/"


def query_crtsh(domain: str, timeout: float = 10.0) -> list[str]:
    """crt.sh から domain のサブドメインを取得する（単発GETのみ）。

    ネットワーク失敗・非200・JSON異常はサイレントに [] を返す
    （tools/cve_client.py の「サイレント失敗」方針を踏襲）。
    """
    try:
        resp = requests.get(
            _CRTSH_URL, params={"q": f"%.{domain}", "output": "json"}, timeout=timeout,
        )
        if resp.status_code != 200:
            return []
        data = json.loads(resp.text)
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        return []

    names: set[str] = set()
    for entry in data if isinstance(data, list) else []:
        value = entry.get("name_value", "") if isinstance(entry, dict) else ""
        for name in value.split("\n"):
            name = name.strip().lstrip("*.").lower()
            if name and "@" not in name and "." in name:
                names.add(name)
    return sorted(names)
