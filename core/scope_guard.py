"""
core/scope_guard.py — バグバウンティ対応: 対象範囲（Scope）の機械的判定

v1の制約（advisorレビュー指摘・2026-08-16）: 許可リスト（allow-list）への一致判定のみに
対応する。「全体は対象だが特定のサブドメインは対象外」のような除外リスト（deny-list）表現
には非対応。実際のバグバウンティのスコープは包含と除外が混在するケースが多いため、
除外リストが必要な場合は allowed_targets に個別のホスト名を列挙する運用で回避すること
（将来検討）。
"""

from __future__ import annotations
import ipaddress


def in_scope(target: str, allowed: list[str]) -> tuple[bool, str]:
    """allowed が空なら常に (True, "")（後方互換・制限なし）。

    ドメインは完全一致 or "*.example.com" 形式のワイルドカード一致
    （apex ドメイン example.com 自体も含む）。CIDR ("/" を含むルール) は
    target がIPリテラルの場合のみ判定する（DNS解決は行わない = 副作用のない
    純粋な文字列/IP判定に留める。ドメイン文字列に対するCIDRルールは判定不能
    として範囲外扱いになる）。
    """
    if not allowed:
        return True, ""
    host = extract_host(target)
    for rule in allowed:
        rule = rule.strip()
        if not rule:
            continue
        if "/" in rule:
            if _cidr_match(host, rule):
                return True, ""
            continue
        if rule.startswith("*."):
            base = rule[2:].lower()
            if host == base or host.endswith("." + base):
                return True, ""
        elif host == rule.lower():
            return True, ""
    return False, f"'{target}' は許可リストの範囲外です"


def extract_host(target: str) -> str:
    """URLやホスト:ポート形式からホスト名/IPのみを取り出す（小文字化）。"""
    t = target.strip().lower()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    t = t.split("@")[-1]  # user@host 形式対応
    if t.startswith("["):  # IPv6リテラル [::1]:port
        t = t[1:].split("]")[0]
    else:
        t = t.split(":")[0]
    return t


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _cidr_match(host: str, cidr: str) -> bool:
    """host がIPリテラルの場合のみCIDR一致を判定する（DNS解決はしない）。"""
    if not is_ip_literal(host):
        return False
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
