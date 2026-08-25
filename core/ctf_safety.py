"""
core/ctf_safety.py — CTF Active Retrieval の安全装置（3層防御のうち層2・層3）

設計: docs/CTF_ACTIVE_FLAG_RETRIEVAL.md

この安全装置は、agents/recon_agent.py の CTF Active Retrieval フェーズからのみ
使われる。通常の ATTACK MODE（EXPLOIT_TRANSMISSION_ENABLED = False の経路）には
一切関与しない。

- is_destructive(): 送信直前のペイロード文字列を決定的なブロックリストで判定する。
  LLM がどう提案しようと、ここでマッチしたものは送信されない（層2）。
- CtfSafetyGuard: リクエスト予算・ジッター・連続エラー時の自動停止を1箇所に集約した
  送信ラッパー（層3）。web_fuzzer.WebFuzzer の予算/ジッター設計を踏襲する。
- require_explicit_scope(): allowed が空なら拒否する（通常の scope_guard.in_scope() は
  空リストを「制限なし」として許可する後方互換設計だが、送信を伴う本機能ではその
  後方互換を採用しない）。
"""
from __future__ import annotations
import random
import re
import time
from dataclasses import dataclass, field

import requests

# ── 層2: 破壊的操作の機械的ブロック ──────────────────────────────
# LLM の判断だけに頼らない決定的な拒否リスト。ここに触れたペイロードは、
# LLM がどう正当化しようと絶対に送信しない。
DESTRUCTIVE_PATTERNS: list[str] = [
    # SQL: 書き込み・スキーマ破壊系（読み取り目的の SELECT/UNION SELECT は対象外）
    r"(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b",
    r"(?i)\bDELETE\s+FROM\b",
    r"(?i)\bTRUNCATE\s+TABLE\b",
    r"(?i)\bUPDATE\s+\S+\s+SET\b",
    r"(?i)\bALTER\s+(TABLE|DATABASE)\b",
    r"(?i)\bINSERT\s+INTO\b",
    r"(?i)\bCREATE\s+(TABLE|DATABASE|USER)\b",
    r"(?i)\bGRANT\s+\S+\s+ON\b",
    # OS コマンド: 破壊・DoS・永続化・アカウント操作系
    r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*r",  # rm -rf / -fr（順不同）
    r"\bmkfs(\.\w+)?\b",
    r"\bdd\s+if=",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",  # fork bomb
    r"\bshutdown\b", r"\breboot\b", r"\bhalt\b", r"\bpoweroff\b",
    r"\bkill\s+-9\s+1\b",
    r">\s*/dev/(sd|nvme|hd)\w*",
    r"\bchmod\s+000\b", r"\bchmod\s+-R\s+000\b",
    r"\buseradd\b", r"\buserdel\b", r"\bpasswd\s+\S+",
    r"\bformat\s+[a-zA-Z]:",  # Windows format
    r"\bdel\s+/[fFsSqQ]\b",   # Windows del /f /s /q
    r"Remove-Item\s+.*-Recurse\s+.*-Force",  # PowerShell 再帰強制削除
]
_DESTRUCTIVE_RE = [re.compile(p) for p in DESTRUCTIVE_PATTERNS]


def is_destructive(payload: str) -> tuple[bool, str]:
    """payload が破壊的パターンに一致するか判定する。

    (True, 一致した理由) か (False, "") を返す。判定は純粋な文字列マッチのみで
    副作用はない。URL・クエリ文字列・POSTボディ・コマンド文字列のいずれにも使える。
    """
    if not payload:
        return False, ""
    for rx in _DESTRUCTIVE_RE:
        m = rx.search(payload)
        if m:
            return True, f"破壊的操作パターンに一致: {rx.pattern!r} (matched: {m.group(0)!r})"
    return False, ""


# ── 層1: スコープの厳格化（空リストは拒否） ────────────────────────
def require_explicit_scope(allowed: list[str] | None) -> tuple[bool, str]:
    """CTF Active Retrieval 専用のスコープ前提条件。

    通常の scope_guard.in_scope() は allowed が空なら「制限なし＝常に許可」
    （既存インストールとの後方互換のため）だが、送信を伴う本機能ではその
    後方互換を採用しない。allowed が空/未指定なら実行そのものを拒否する。
    実際のホスト一致判定は呼び出し側で scope_guard.in_scope() を使うこと
    （この関数は「そもそも1件も許可ホストが入力されていない」ことだけを弾く）。
    """
    if not allowed:
        return False, "CTF Active Retrieval は対象ホストの明示入力が必須です（空のままでは実行できません）"
    return True, ""


# ── 層3: 実行中のセーフティネット（予算・連続エラー・ログ） ─────────────
@dataclass
class CtfSafetyGuard:
    """CTF Active Retrieval 用の送信ラッパー。予算超過・連続エラーで自動停止する。

    web_fuzzer.WebFuzzer の max_requests / jitter 設計を踏襲。
    """
    max_requests: int = 30
    jitter: tuple[float, float] = (0.2, 0.8)
    timeout: int = 8
    max_consecutive_errors: int = 5

    _req_count: int = field(default=0, init=False)
    _consecutive_errors: int = field(default=0, init=False)
    log: list[dict] = field(default_factory=list, init=False)

    def budget_left(self) -> bool:
        return self._req_count < self.max_requests

    def should_stop(self) -> tuple[bool, str]:
        if not self.budget_left():
            return True, f"リクエスト予算({self.max_requests})に達しました"
        if self._consecutive_errors >= self.max_consecutive_errors:
            return True, f"連続{self._consecutive_errors}回エラー — 対象が不安定な可能性があるため停止します"
        return False, ""

    def send(
        self,
        session: requests.Session,
        method: str,
        url: str,
        *,
        tier: int,
        rationale: str = "",
        **kwargs,
    ) -> tuple[requests.Response | None, str]:
        """予算・ブロックリスト・ジッターを考慮して送信する。

        payload はブロックチェック対象として、URL・params・data の文字列表現を
        まとめて評価する。ブロック/予算切れ/エラーいずれの場合も Response は None。
        戻り値の2要素目は人間可読の状態メッセージ（ログ・UI表示用）。
        """
        stop, reason = self.should_stop()
        if stop:
            return None, f"SKIPPED（停止条件）: {reason}"

        payload_repr = " ".join(
            str(v) for v in (url, kwargs.get("params"), kwargs.get("data")) if v
        )
        blocked, block_reason = is_destructive(payload_repr)
        if blocked:
            self.log.append({
                "tier": tier, "method": method, "url": url, "rationale": rationale,
                "status": "BLOCKED", "detail": block_reason,
            })
            return None, f"BLOCKED（層2・破壊的操作）: {block_reason}"

        lo, hi = self.jitter
        if hi > 0:
            time.sleep(random.uniform(lo, hi))
        self._req_count += 1
        headers = kwargs.pop("headers", {})
        try:
            resp = session.request(
                method, url, timeout=self.timeout, allow_redirects=False,
                headers=headers, **kwargs,
            )
            self._consecutive_errors = 0
            self.log.append({
                "tier": tier, "method": method, "url": url, "rationale": rationale,
                "status": "SENT", "status_code": resp.status_code,
            })
            return resp, f"SENT: {method} {url} -> {resp.status_code}"
        except requests.RequestException as e:
            self._consecutive_errors += 1
            self.log.append({
                "tier": tier, "method": method, "url": url, "rationale": rationale,
                "status": "ERROR", "detail": str(e),
            })
            return None, f"ERROR: {e}"

    def format_log(self) -> str:
        """レポート添付用: 送信したペイロード一覧を人間可読な形式に整形する。"""
        if not self.log:
            return "(送信は発生しませんでした)"
        lines = []
        for e in self.log:
            base = f"- [Tier{e['tier']}] {e['method']} {e['url']}  status={e['status']}"
            if e.get("rationale"):
                base += f"  rationale={e['rationale']!r}"
            if e.get("status_code") is not None:
                base += f"  http={e['status_code']}"
            if e.get("detail"):
                base += f"  detail={e['detail']}"
            lines.append(base)
        return "\n".join(lines)
