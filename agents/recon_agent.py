"""
agents/recon_agent.py — ペネトレーションテスト偵察エージェント

Phase 0: 受動的サブドメイン列挙（crt.sh・バグバウンティ対応）
Phase 1: ネットワーク偵察（ポートスキャン・バナーグラブ）
Phase 2: Webターゲット列挙（ヘッダー・技術スタック・センシティブパス）
Phase 3: 既知サービスバナーのローカル照合 (known_vulns.yaml)
Phase 4: LLMが発見情報から脆弱性仮説を構築
"""

from __future__ import annotations
import json
import os
import re
import time
import requests
from agents.base_agent import BaseAgent, unparsed_output_note
from tools.network_scanner import NetworkScanner, passive_os_fingerprint
from tools.web_prober import WebProber
from tools import subdomain_enum
from tools.report_generator import _findings_and_counts
import core.config as config
from core import scope_guard
from core.ctf_safety import CtfSafetyGuard, is_destructive, require_explicit_scope
from core.findings import CoverageItem, Finding, ScanState, CoverageStatus, new_id
from core import redaction
from core.evidence_store import EvidenceStore
from core.settings import (
    SCAN_PROFILES, DEFAULT_SCAN_PROFILE,
    COMMON_PORTS, EXTENDED_PORTS, COMMON_UDP_PORTS,
)

STEPS = [
    "サブドメイン列挙中（crt.sh・受動）",
    "ターゲット解析・接続確認",
    "ポートスキャン実行中",
    "サービス・バナー取得中",
    "既知サービス脆弱性ローカル照合中",
    "Webターゲット列挙中",
    "受動OSフィンガープリント中",
    "AIが脆弱性仮説を構築中",
    "PoC生成中（ローカル生成・送信なし）",
    "リスクレポートを生成中",
]

# ─────────────────────────────────────────────────────────────
#  安全制御: 生成した PoC/エクスプロイトは絶対に対象へ送信・実行しない。
#  このエージェントは PoC を「LLMで生成し、画面表示・レポート保存する」のみで、
#  対象へ送信/実行する経路を一切持たない。下のフラグは不変条件の明示であり、
#  True にして送信する実装は本ツールに存在しない。
# ─────────────────────────────────────────────────────────────
EXPLOIT_TRANSMISSION_ENABLED = False


def _assert_no_transmission() -> None:
    """PoC送信が無効であることを保証する（万一の改変に対する安全ガード）。"""
    if EXPLOIT_TRANSMISSION_ENABLED:
        raise RuntimeError(
            "Safety violation: exploit transmission must remain disabled. "
            "This tool only generates and displays PoCs; it never sends them to a target."
        )


def _extract_domain(target: str) -> str | None:
    """サブドメイン列挙(crt.sh)に使うドメイン名を抽出する。IPリテラルや形式不明なら None。"""
    host = scope_guard.extract_host(target)
    if scope_guard.is_ip_literal(host) or "." not in host:
        return None
    return host


# ── 既知サービスバナーのローカル照合 (known_vulns.yaml) ──
# YAMLパーサが使えない環境でも動作するよう、簡易パーサを内蔵する。
# 標準ライブラリの yaml が利用可能ならそちらを使う。

_KV_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                           "tools", "known_vulns.yaml")

_KV_CACHE: dict[str, list[dict]] | None = None


def _load_known_vulns() -> dict[str, list[dict]]:
    """known_vulns.yaml を読み込み、サービス名 → 脆弱性リスト のdictを返す。"""
    global _KV_CACHE
    if _KV_CACHE is not None:
        return _KV_CACHE
    try:
        import yaml  # noqa: PLC0415
        with open(_KV_DB_PATH, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except Exception:
        try:
            raw = _parse_simple_yaml(_KV_DB_PATH)
        except Exception:
            _KV_CACHE = {}
            return _KV_CACHE
    _KV_CACHE = dict(raw) if isinstance(raw, dict) else {}
    return _KV_CACHE


def _parse_simple_yaml(path: str) -> dict:
    """PyYAML非依存の簡易YAMLパーサ（list/dict/文字列のみ対応）。"""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    lines = content.split("\n")
    root: dict = {}
    current_service: str | None = None
    current_vuln: dict | None = None
    in_list = False
    for line in lines:
        stripped = line.rstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        value = line.lstrip()

        if indent == 0 and stripped.endswith(":"):
            current_service = stripped[:-1].strip()
            root[current_service] = []
            current_vuln = None
        elif indent == 2 and value.startswith("- name:"):
            name_part = value[7:].strip().strip('"').strip("'")
            current_vuln = {"name": name_part}
            root.setdefault(current_service or "", []).append(current_vuln)
        elif indent == 4 and current_vuln is not None and ":" in value:
            key, _, val = value.partition(":")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and val:
                current_vuln[key] = val
    return root


def _safe_search(pattern: str, text: str) -> bool:
    try:
        return bool(re.search(pattern, text, re.IGNORECASE))
    except re.error:
        return False

def lookup_known_vulns(ports: list[dict], web_tech: list[str] | None = None) -> list[dict]:
    """スキャン結果のサービスバナーから既知の脆弱性をローカル照合する。

    Returns: ヒットした脆弱性のリスト [{service, name, cve, severity, desc, matched_banner}]
    """
    db  = _load_known_vulns()
    hits: list[dict] = []
    seen = set()  # CVE重複排除

    # 1) ポートバナーを照合
    for p in ports:
        banner = f"{p.get('service', '')} {p.get('banner', '')}"
        server_header = p.get("headers", {}) if isinstance(p, dict) else {}
        combined = banner
        if isinstance(server_header, dict):
            combined += " " + " ".join(str(v) for v in server_header.values())

        for svc_name, vulns in db.items():
            for v in vulns:
                pattern = v.get("pattern", "")
                if not pattern:
                    continue
                if _safe_search(pattern, combined):
                    cve = v.get("cve", "")
                    if cve in seen:
                        continue
                    seen.add(cve)
                    hits.append({
                        "service":       svc_name,
                        "name":          v.get("name", ""),
                        "cve":           cve,
                        "severity":      v.get("severity", "MEDIUM"),
                        "desc":          v.get("desc", ""),
                        "matched_banner": banner[:100].strip(),
                    })

    # 2) Web技術スタックを照合
    for tech in (web_tech or []):
        for svc_name, vulns in db.items():
            if svc_name.lower() in tech.lower():
                for v in vulns:
                    cve = v.get("cve", "")
                    if cve in seen:
                        continue
                    seen.add(cve)
                    hits.append({
                        "service":       svc_name,
                        "name":          v.get("name", ""),
                        "cve":           cve,
                        "severity":      v.get("severity", "MEDIUM"),
                        "desc":          v.get("desc", ""),
                        "matched_banner": f"Web technology: {tech}",
                    })

    return hits


EXPLOIT_SYSTEM_PROMPT = """You are assisting an AUTHORIZED penetration test performed in an \
isolated lab that the operator owns. Based on the confirmed/hypothesized findings, produce \
proof-of-concept (PoC) exploit code so the operator can validate the issues MANUALLY in \
their own authorized environment.

CRITICAL SAFETY CONTEXT — READ CAREFULLY:
- This tool ONLY displays and saves these PoCs as text. It does NOT, and must NOT, send, \
deliver, execute, or transmit them to any target. Never imply the tool will run them.
- Keep PoCs MINIMAL and detection/validation-oriented (prove the vulnerability exists).
- DO NOT include destructive or escalation payloads: no data destruction, ransomware, \
persistence/backdoors, credential exfiltration at scale, automated lateral movement, or \
denial-of-service. If a finding only allows such impact, describe it conceptually instead.
- For each PoC, include a one-line safe-usage note and the expected success indicator.

For each applicable finding, output exactly this block:

---EXPLOIT_START---
TITLE: [short name]
TARGET_FINDING: [which finding this validates]
TECHNIQUE: [e.g. CWE-89 SQL Injection / reflected XSS / path traversal]
PREREQUISITES: [what must be true to attempt this]
POC:
```
[minimal proof-of-concept code or request]
```
SUCCESS_INDICATOR: [how to know it worked, e.g. "DB error string in response"]
SAFE_USAGE_NOTE: [one line; authorized lab only, never against third parties]
---EXPLOIT_END---

Be precise and practical, but never destructive. Produce PoCs only for the findings that \
realistically warrant them."""

SYSTEM_PROMPT = """You are an expert red team operator and penetration tester. \
You have just completed automated reconnaissance on a target system. \
Your job is to analyze the discovered information and build an attack hypothesis.

Based on the reconnaissance data provided:

1. **Identify Attack Surface**: List all exposed services and potential entry points
2. **Version-based CVE Hypotheses**: For each service/version found, reason about likely CVEs
3. **Configuration Vulnerabilities**: Identify misconfigurations (missing headers, open admin panels, etc.)
4. **Attack Chain Construction**: Build realistic multi-step attack scenarios
5. **Unknown Vulnerability Hypotheses**: Reason about potential 0-day surface based on tech stack combinations

For each finding, output:

---FINDING_START---
TITLE: [Finding name]
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW]
CATEGORY: [Network|Web|Config|AuthLogic|InfoDisclosure]
EVIDENCE: [Specific data from reconnaissance that supports this]
ATTACK_SCENARIO:
[Detailed exploitation steps]
RECOMMENDED_ACTION:
[Next pentest steps or mitigations]
---FINDING_END---

Be thorough. Think like an attacker who has just done initial recon and is planning the next move."""


_EVIDENCE_INSTRUCTION = """

If (and only if) a line of the reconnaissance data carries an "evidence_id" and you rely on it \
for a finding, add this line to that finding's block after CATEGORY:
EVIDENCE_IDS: [comma-separated evidence_id value(s) that support this finding]. \
Only cite evidence_id values that were literally given to you — never invent one. \
An evidence_id only shows that the scanner observed that item; it does not prove the finding."""

# ── CTF FLAG HUNT: 認可された偵察レスポンスからのローカルフラグ検出（送信なし） ──
# 攻撃の動き（ペイロード送信・注入・認証回避・ブルートフォース等）は一切行わず、
# 既に実施した偵察で取得済みのバナー・Webボディ・ヘッダー内からフラグ形式を
# 正規表現で検出するだけ。追加リクエストや対象への送信は発生しない。
_FLAG_BRACE_RE = re.compile(r"((?:flag|ctf)\s*\{[^}]{1,200}\})", re.I)
# 裸の 32/40/64 桁 hex は HTTP では殆どフラグではない（MD5/SHA1/SHA256/ETag/CSPハッシュ/
# Cookie等の誤検知源）。文脈（flag/ctf ラベルの直後）に限定して初めて検出する。
_FLAG_HEX_RE = re.compile(
    r"(?:flag|ctf)\s*[:=_-]?\s*(?<![A-Fa-f0-9])"
    r"([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})(?![A-Fa-f0-9])",
    re.I,
)


def _detect_flags(*texts: str) -> list[str]:
    """与えられた文字列群からCTFフラグ形式（flag{...}/ctf{...}・文脈付きhex）を検出する。

    純ローカル・決定的な検出であり、対象への送信や追加リクエストは一切行わない。
    出現順を保ったまま重複を除去して返す。hex はラベル（flag/ctf）の直後に限る
    （裸の MD5/SHA/ETag 等を誤検出しないため）。
    """
    collected: list[str] = []
    for t in texts:
        if not t:
            continue
        collected.extend(_FLAG_BRACE_RE.findall(t))
        collected.extend(_FLAG_HEX_RE.findall(t))
    seen, out = set(), []
    for c in collected:
        key = c.lower()
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def _walk_leaves(obj, path: str = ""):
    """recon_dataを再帰的にたどり (フィールドパス, 文字列値) を返す。取得経路の記録用。"""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_leaves(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, (list, tuple, set)):
        for i, v in enumerate(obj):
            yield from _walk_leaves(v, f"{path}[{i}]")
    elif obj is not None:
        yield path, str(obj)


def _flag_excerpt(text: str, flag: str, width: int = 80) -> str:
    """応答本文からフラグ周辺の抜粋を取り、マスクして返す（フラグ自体はマスクしない）。"""
    i = text.lower().find(flag.lower())
    if i < 0:
        return ""
    return redaction.mask_body(text[max(0, i - width): i + len(flag) + width], max_len=2 * width + len(flag))


# ── CTF ACTIVE RETRIEVAL: 送信を伴うフラグ探索（docs/CTF_ACTIVE_FLAG_RETRIEVAL.md） ──
# EXPLOIT_TRANSMISSION_ENABLED / _assert_no_transmission() の経路とは完全に独立。
# 既定オフ・スコープ明示必須・破壊的操作は core.ctf_safety.is_destructive() で機械的に拒否。

# Tier1: 軽い・読み取り専用の拡張パス巡回。core.settings.SENSITIVE_PATHS（CMS/フレーム
# ワークの管理パス中心）とは別に、CTF演習でよく使われる「隠しメモ」系のファイル名に絞る。
_CTF_TIER1_WORDLIST = [
    "notes.txt", "note.txt", "secret.txt", "secrets.txt", "flag.txt", "flags.txt",
    "todo.txt", "credentials.txt", "backup.txt", "hidden.txt", ".secret",
    "flag", "config.bak", "config.old", "database.sql", "dump.sql", "users.txt",
]

_CTF_TIER_NOTES = {
    2: (
        "Tier 2: prefer read-only path traversal/LFI, UNION SELECT-only SQL injection, "
        "read-only SSRF, and non-destructive command injection probes (id/whoami/cat only)."
    ),
    3: (
        "Tier 3: you may also propose authentication-bypass probes (e.g. JWT tampering, "
        "session fixation) and read-only deserialization probes, as long as they only "
        "READ data and do not modify server state."
    ),
}

CTF_ACTIVE_SYSTEM_PROMPT = """You are assisting with an AUTHORIZED CTF (Capture The Flag) \
exercise on a platform the operator has explicit permission to test (e.g. TryHackMe). Your \
job is to propose READ-ONLY verification requests that the tool will actually SEND to the \
target, to help locate a hidden flag.

CRITICAL SAFETY CONTEXT — READ CAREFULLY:
- Propose ONLY requests whose effect is to READ/OBSERVE data. NEVER propose anything that \
writes, deletes, or modifies data, brute-forces credentials, or could degrade availability \
(DoS). A machine-enforced filter independently rejects destructive-looking payloads \
regardless of your rationale — do not try to word around it. If a technique requires any of \
those, skip it entirely.
- {tier_note}

Given the reconnaissance summary and attack hypotheses below, propose up to {n} distinct, \
READ-ONLY verification requests as a JSON array (and nothing else — no prose, no markdown \
fences). Each element must have this exact shape:
{{"method": "GET", "path": "/relative/path", "params": {{"key": "value"}}, "rationale": \
"one short sentence"}}
`method` is "GET" or "POST" only. `params` (for GET, query string) or `data` (for POST, form \
body) may be omitted if not needed. `path` is relative to the target root (starts with "/").
"""


class ReconAgent(BaseAgent):

    def run(self, target: str, scan_web: bool = True, intensity: str = DEFAULT_SCAN_PROFILE,
            generate_exploit: bool = True, port_scope: str = "common",
            scan_udp: bool = False, ctf_mode: bool = False,
            ctf_active: bool = False, ctf_active_targets: list[str] | None = None,
            ctf_active_max_tier: int = 2) -> None:
        self._current_mode, self._current_target = "ATTACK", target
        scan_id = self._begin_scan()  # フラグ取得時のHTTP証拠保存がfinalize前からscan_idを使うため
        self._flag_routes = {}        # フラグ(小文字) → 取得経路(レポート用)
        self._ev_store = None         # save_evidence有効時、偵察証拠とフラグ証拠で共有する
        self.bus.clear()
        if not self._check_scope(target):
            return
        t0 = time.time()
        self._status(f"偵察開始: {target}")

        # intensity = スキャンプロファイル名（stealth / passive / moderate / aggressive）
        if intensity not in SCAN_PROFILES:
            intensity = DEFAULT_SCAN_PROFILE

        # ポートスコープ（common=現行と同一 / extended=拡張 / full=全65535）
        if port_scope == "extended":
            scan_ports = EXTENDED_PORTS
        elif port_scope == "full":
            scan_ports = list(range(1, 65536))
        else:
            port_scope = "common"
            scan_ports = COMMON_PORTS
        scanner = NetworkScanner.from_profile(intensity, ports=scan_ports)
        prober  = WebProber(timeout=8, profile=intensity)

        recon_data: dict = {"target": target, "ports": [], "udp_ports": [], "web": {},
                            "subdomains": []}

        # ── Step 0: 受動的サブドメイン列挙（crt.sh・バグバウンティ対応） ──
        self._step(0, "running")
        self._out("─" * 56 + "\n", "sep")
        self._out("  PHASE 0 — PASSIVE SUBDOMAIN ENUMERATION (crt.sh)\n", "section")
        self._out("─" * 56 + "\n", "sep")
        domain = _extract_domain(target)
        if domain:
            self._status(f"サブドメイン列挙中（crt.sh）: {domain} ...")
            found = subdomain_enum.query_crtsh(domain)
            allowed = config.get("allowed_targets") or []
            in_scope_subs, out_of_scope_subs = [], []
            for sub in found:
                ok, _ = scope_guard.in_scope(sub, allowed)
                (in_scope_subs if ok else out_of_scope_subs).append(sub)
            if found:
                self._out(f"\n  {len(found)} 件のサブドメインを証明書ログから発見:\n\n", "green")
                for s in in_scope_subs:
                    self._out(f"    ▸ {s}\n", "medium")
                if out_of_scope_subs:
                    self._out(f"\n  発見したがスコープ外のため除外: {len(out_of_scope_subs)}件\n", "dim")
                    for s in out_of_scope_subs:
                        self._out(f"    ✗ {s}（スコープ外）\n", "dim")
                self._out(
                    "\n  [ NOTE ] 発見した資産が現在も対象組織の管理下にあるとは限りません"
                    "（証明書発行履歴に基づくため）。生存確認・所有確認は別途行ってください。\n"
                    "  [ NOTE ] v1では発見のみで、後続フェーズ（ポートスキャン等）への自動展開は行いません。\n",
                    "high",
                )
            else:
                self._out("\n  (crt.sh: 該当なし、または照会失敗)\n", "dim")
            recon_data["subdomains"] = in_scope_subs
        else:
            self._out("\n  (URLからドメイン名を抽出できないためスキップ — IPアドレス指定など)\n", "dim")
        self._step(0, "done")

        if self.is_stopped(): return

        # ── Step 1: ターゲット解析 ─────────────────────────
        self._step(1, "running")
        self._out(
            "╔══════════════════════════════════════════════════════╗\n"
            "║      ATTACK MODE — AUTONOMOUS RECON INITIATED        ║\n"
            "╚══════════════════════════════════════════════════════╝\n\n",
            "header",
        )
        stealthy = intensity in ("stealth", "passive")
        self._out(f"  TARGET    : {target}\n", "dim")
        self._out(f"  PROFILE   : {intensity.upper()}\n", "dim")
        self._out(
            f"  FOOTPRINT : {'LOW (jitter+randomized order)' if stealthy else 'HIGH (fast/noisy)'}\n",
            "green" if stealthy else "high",
        )
        self._out(f"  WEB PROBE : {'YES' if scan_web else 'NO'}\n", "dim")
        self._out(
            f"  PORTS     : {port_scope.upper()} ({len(scan_ports)} ports)"
            f"{'  +UDP' if scan_udp else ''}\n", "dim",
        )
        if port_scope == "full":
            self._out("  NOTE      : 全ポートスキャンは時間がかかります"
                      "（aggressive/隔離環境向け）。\n", "high")
        self._out("\n", "")

        # ホスト名 → IPアドレス解析
        host, resolved_ip = scanner.resolve(target)
        if resolved_ip:
            self._log(f"Resolved: {host} → {resolved_ip}")
            self._out(f"  HOST      : {host}\n", "dim")
            self._out(f"  IP        : {resolved_ip}\n\n", "dim")
            recon_data["host"] = host
            recon_data["ip"]   = resolved_ip
        else:
            self._out(f"[ WARNING ] ホスト解決失敗: {target}\n", "high")
        self._step(1, "done")

        if self.is_stopped(): return

        # ── Step 2: ポートスキャン ─────────────────────────
        self._step(2, "running")
        self._out("─" * 56 + "\n", "sep")
        self._out("  PHASE 1 — PORT SCAN\n", "section")
        self._out("─" * 56 + "\n", "sep")
        self._status(f"ポートスキャン中: {host} ...")
        self._log(f"Scanning {host} ...")

        open_ports = scanner.scan(host)
        recon_data["ports"] = open_ports

        if open_ports:
            self._out(f"\n  {len(open_ports)} open port(s) found:\n\n", "green")
            for p in open_ports:
                sev_tag = "critical" if p["port"] in (21, 23, 3389, 445) else "medium"
                self._out(
                    f"  [{p['port']:>5}/tcp]  {p['service']:<14}  {p['banner'][:60]}\n",
                    sev_tag,
                )
        else:
            self._out("  No open ports found (filtered or host down)\n", "dim")

        # UDPスキャン（オプション・参考情報）
        if scan_udp and not self.is_stopped():
            self._out("\n  UDP scan (参考: 無応答は open|filtered) ...\n", "dim")
            self._status(f"UDPスキャン中: {host} ...")
            udp_ports = scanner.scan_udp(host, COMMON_UDP_PORTS)
            recon_data["udp_ports"] = udp_ports
            if udp_ports:
                for p in udp_ports:
                    self._out(
                        f"  [{p['port']:>5}/udp]  {p['service']:<16}  {p['banner']}\n",
                        "medium" if p["banner"].startswith("open ") else "dim",
                    )
            else:
                self._out("  No UDP ports responded.\n", "dim")
        self._step(2, "done")

        if self.is_stopped(): return

        # ── Step 3: バナー詳細 ─────────────────────────────
        self._step(3, "running")
        time.sleep(0.2)
        self._step(3, "done")

        # ── Step 4: 既知サービス脆弱性ローカル照合 (P0) ───
        self._step(4, "running")
        known_hits = lookup_known_vulns(
            open_ports,
            recon_data.get("web", {}).get("technologies"),
        )
        if known_hits:
            self._out("\n" + "─" * 56 + "\n", "sep")
            self._out(
                f"  LOCAL KNOWN-VULN LOOKUP — {len(known_hits)} known CVE(s) matched "
                f"(LLMコストゼロ・即時判定)\n", "section")
            self._out("─" * 56 + "\n\n", "sep")
            # 深刻度でソート
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            known_hits.sort(key=lambda h: sev_order.get(h["severity"], 2))
            for hit in known_hits:
                sev = hit["severity"]
                tag = sev.lower() if sev.lower() in ("critical", "high", "medium", "low") else "medium"
                self._out(
                    f"  [{sev:8}] {hit['cve']} — {hit['name']}\n"
                    f"              Service: {hit['service']}  |  {hit['desc']}\n"
                    f"              Matched: {hit['matched_banner']}\n",
                    tag,
                )
        else:
            self._out("\n  (ローカル照合: ヒットなし)\n", "dim")
        self._step(4, "done")

        if self.is_stopped(): return

        # ── Step 5: Webプローブ ────────────────────────────
        self._step(5, "running")
        web_ran = scan_web and (any(p["port"] in (80, 443, 8080, 8443, 8000) for p in open_ports) or
                                target.startswith("http"))
        if web_ran:
            self._out("\n" + "─" * 56 + "\n", "sep")
            self._out("  PHASE 2 — WEB ENUMERATION\n", "section")
            self._out("─" * 56 + "\n", "sep")

            base_url = target if target.startswith("http") else \
                       ("https://" if any(p["port"] == 443 for p in open_ports) else "http://") + host

            self._log(f"Web probe: {base_url}")
            self._status(f"Webプローブ中: {base_url} ...")

            web_data = prober.probe(base_url, on_progress=self._log, capture_body=ctf_mode)
            recon_data["web"] = web_data

            # ヘッダー表示
            if web_data.get("headers"):
                self._out("\n  HTTP Headers:\n", "label")
                for k, v in web_data["headers"].items():
                    self._out(f"    {k}: {v}\n", "code")

            # テック表示
            if web_data.get("technologies"):
                self._out("\n  Detected Technologies:\n", "label")
                for t in web_data["technologies"]:
                    self._out(f"    ▸ {t}\n", "high")

            # センシティブパス
            if web_data.get("found_paths"):
                self._out("\n  Sensitive Paths Found:\n", "label")
                for p in web_data["found_paths"]:
                    tag = "critical" if any(x in p["path"] for x in [".git", ".env", "admin"]) else "medium"
                    self._out(f"    [{p['status']}] {p['path']}\n", tag)

            # セキュリティヘッダー欠如
            if web_data.get("missing_headers"):
                self._out("\n  Missing Security Headers:\n", "label")
                for h in web_data["missing_headers"]:
                    self._out(f"    ✗ {h}\n", "high")

        self._step(5, "done")

        if self.is_stopped(): return

        # ── Step 6: 受動OSフィンガープリント ──────────────
        self._step(6, "running")
        os_guess = passive_os_fingerprint(
            recon_data["ports"], recon_data.get("web", {}).get("headers"),
        )
        if os_guess:
            recon_data["os_guess"] = os_guess
            self._out("\n  Passive OS Fingerprint:\n", "label")
            self._out(f"    ▸ {os_guess}  (バナー解析による受動推定／追加通信なし)\n", "high")
        self._step(6, "done")

        # ── Step 7: AI 脆弱性仮説 ─────────────────────────
        self._step(7, "running")
        self._out("\n" + "─" * 56 + "\n", "sep")
        self._out("  PHASE 3 — AI ATTACK HYPOTHESIS  (streaming)\n", "section")
        self._out("─" * 56 + "\n\n", "sep")
        self._status("AI が攻撃仮説を構築中 ...")
        self._log("Sending recon data to LLM ...")

        # 証拠保存（P1.2・save_evidence設定時のみ。既定OFF）。観測=scannerが得た事実のみ。
        known_evidence_ids: set[str] = set()
        evidence_errors: list[str] = []
        recon_evidence: dict = {}
        if config.get("save_evidence", False):
            ev_store = self._ev_store = EvidenceStore(scan_id)  # フラグ証拠と共有(上限を二重に使わない)
            recon_evidence = self._save_recon_evidence(ev_store, recon_data)
            known_evidence_ids = set(recon_evidence.values())
            evidence_errors = [f"証拠保存エラー: {e}" for e in ev_store.save_errors]
            evidence_errors += [f"証拠保存を省略: {o}" for o in ev_store.omissions]
        # LLMへ渡す偵察サマリーは、ヘッダー(Set-Cookie等)・バナー内の機密値をマスクしてから送る
        recon_summary = redaction.mask_log_line(
            self._build_recon_summary(recon_data, known_hits, recon_evidence))
        full = self._stream_llm([
            self.llm.system(SYSTEM_PROMPT + (_EVIDENCE_INSTRUCTION if known_evidence_ids else "")),
            self.llm.user(f"Analyze this reconnaissance data and build attack hypotheses:\n\n{recon_summary}"),
        ], live_stats=True)

        # 品質エフォート: STRONGモデルで攻撃仮説を再検証し過剰主張を除去する。
        effort = self._effort()
        if effort.get("verify_pass") and not self.is_stopped():
            full = self._verify_findings(recon_summary, full, samples=effort.get("verify_samples", 1))
        self._step(7, "done")

        if self.is_stopped(): return

        # ── CTF FLAG HUNT（トグル時のみ・検出のみ・送信なし） ──
        if ctf_mode:
            self._detect_and_report_flags(recon_data)

        if self.is_stopped(): return

        # ── CTF ACTIVE RETRIEVAL（トグル時のみ・既定オフ・実送信あり） ──
        # docs/CTF_ACTIVE_FLAG_RETRIEVAL.md 参照。EXPLOIT_TRANSMISSION_ENABLED の経路
        # とは完全に独立しており、通常のATTACK MODE（本フラグ=False）には一切影響しない。
        # フラグ検出済み（Step7.5で見つかった）ならスキップ — 送信を伴う処理は最小限に。
        if ctf_active and not recon_data.get("flags"):
            self._ctf_active_retrieval(
                recon_data, recon_summary, prober.session,
                ctf_active_targets or [], ctf_active_max_tier,
            )

        # ── Step 8: エクスプロイト(PoC)生成 — ローカル生成のみ・送信なし ──
        self._step(8, "running")
        exploit_text = ""
        if generate_exploit:
            _assert_no_transmission()
            if EXPLOIT_TRANSMISSION_ENABLED:
                self._status("Aborted: safety constraint violated.")
                return
            self._out("\n" + "─" * 56 + "\n", "sep")
            self._out("  PHASE 4 — PoC GENERATION  (local display/save only)\n", "section")
            self._out("─" * 56 + "\n\n", "sep")
            self._status("AI が PoC を生成中（対象へは送信しません）...")
            self._log("Generating PoC (local only) ...")
            exploit_text = self._stream_llm([
                self.llm.system(EXPLOIT_SYSTEM_PROMPT),
                self.llm.user(
                    f"Reconnaissance analysis:\n{full}\n\n"
                    f"Generate validation-oriented PoC code for the applicable findings."
                ),
            ])
            self._save_poc(target, exploit_text)
        self._step(8, "done")

        # ── Step 9: レポート生成 ──────────────────────────
        self._step(9, "running")
        body = (
            f"## Reconnaissance Data\n{recon_summary}\n\n"
            + (f"## CTF Flags Detected\n{self._format_flags(recon_data.get('flags', []))}\n\n"
               if (ctf_mode or ctf_active) and recon_data.get("flags") else "")
            + (f"## CTF Active Retrieval — Sent Requests (audit log)\n{recon_data['ctf_active_log']}\n\n"
               if ctf_active and recon_data.get("ctf_active_log") else "")
            + f"## AI Attack Hypotheses\n{full}\n\n"
            + (f"## Generated PoCs (local only)\n{exploit_text}\n" if exploit_text else "")
        )
        self._save_investigation("ATTACK MODE", target, body)
        time.sleep(0.2)
        self._step(9, "done")

        total_ports = len(recon_data["ports"])
        parsed_findings, counts = _findings_and_counts("ATTACK MODE", full)
        self._record_telemetry("ATTACK MODE", target, counts, time.time() - t0)
        self._out("\n\n" + "═" * 56 + "\n", "sep")
        self._out(f"  RECON COMPLETE  |  {total_ports} open ports discovered\n", "green")
        self._out("═" * 56 + "\n", "sep")
        self._log(f"Recon complete. {total_ports} open ports.")
        self._status(f"Recon complete — {total_ports} open ports.")

        rejected: list[str] = []
        findings = self._findings_from_markers(
            parsed_findings, corroborated=bool(effort.get("verify_pass")),
            known_evidence_ids=known_evidence_ids or None, rejected_evidence_ids=rejected)
        flag_findings, flag_errors = self._flag_findings(recon_data, scan_id)
        findings = findings + flag_findings
        coverage = self._build_coverage(
            target, host, scan_ports, port_scope, scan_web, web_ran, scan_udp, domain,
        )
        state, errors = self._determine_state(triage_text=full, host_resolved=bool(resolved_ip))
        # 共有storeのエラー/省略はflag_errorsとevidence_errorsで重複しうるため、順序を保って畳む
        errors = list(dict.fromkeys(errors + evidence_errors + flag_errors + rejected))
        self._finalize(state=state, errors=errors, findings=findings, coverage=coverage,
                       mode="ATTACK", target=target)

    # ── 構造化所見・実行状態(P1.1) ─────────────────────────
    @staticmethod
    def _build_coverage(target: str, host: str, scan_ports: list[int], port_scope: str,
                        scan_web: bool, web_ran: bool, scan_udp: bool,
                        domain: str | None) -> list[CoverageItem]:
        """ポートスキャン・Web列挙・UDPスキャン・サブドメイン列挙の実施状況を
        CoverageItemへ変換する（P1.1）。CTF Flag Hunt/Active Retrievalは既存仕様どおり
        独立した機能のため、本計画のcoverageには含めない（roadmap §1）。
        """
        ref = host or target
        coverage = [CoverageItem(
            target_ref=ref, rule_id="PORT_SCAN", parameter=port_scope,
            status=CoverageStatus.TESTED.value,
            reason=f"{len(scan_ports)} port(s) scanned ({port_scope})",
        )]
        if scan_udp:
            coverage.append(CoverageItem(target_ref=ref, rule_id="UDP_SCAN",
                                         status=CoverageStatus.TESTED.value))
        else:
            coverage.append(CoverageItem(target_ref=ref, rule_id="UDP_SCAN",
                                         status=CoverageStatus.SKIPPED.value,
                                         reason="scan_udp未指定"))
        if not scan_web:
            coverage.append(CoverageItem(target_ref=target, rule_id="WEB_ENUM",
                                         status=CoverageStatus.SKIPPED.value,
                                         reason="scan_web=False"))
        elif web_ran:
            coverage.append(CoverageItem(target_ref=target, rule_id="WEB_ENUM",
                                         status=CoverageStatus.TESTED.value))
        else:
            coverage.append(CoverageItem(
                target_ref=target, rule_id="WEB_ENUM", status=CoverageStatus.SKIPPED.value,
                reason="Web関連ポート(80/443/8080/8443/8000)が未開放・httpスキームでもない",
            ))
        if domain:
            coverage.append(CoverageItem(target_ref=domain, rule_id="SUBDOMAIN_ENUM",
                                         status=CoverageStatus.TESTED.value))
        else:
            coverage.append(CoverageItem(
                target_ref=target, rule_id="SUBDOMAIN_ENUM", status=CoverageStatus.SKIPPED.value,
                reason="対象からドメイン名を抽出できない(IPアドレス指定等)",
            ))
        return coverage

    def _determine_state(self, *, triage_text: str, host_resolved: bool) -> tuple[str, list[str]]:
        """実行状態(completed/partial/failed/cancelled)を判定する（P1.1）。

        completedは「指定した検査範囲について完了した」意味であり、対象に脆弱性が
        無い保証ではない。ホスト解決失敗やAI推論の空応答は、検査の実績に応じて
        partialとする（検出0件の成功とは区別する）。
        """
        errors: list[str] = []
        if self.is_stopped():
            return ScanState.CANCELLED.value, errors
        if not host_resolved:
            errors.append("ホスト名解決に失敗しました（ポートスキャン等が制限された可能性）")
            return ScanState.PARTIAL.value, errors
        if not triage_text.strip():
            errors.append("AI攻撃仮説が空応答でした（LLM呼び出し失敗の可能性）")
            return ScanState.PARTIAL.value, errors
        if note := unparsed_output_note(triage_text):
            errors.append(note)
            return ScanState.PARTIAL.value, errors
        return ScanState.COMPLETED.value, errors

    # ── 偵察サマリー生成 ──────────────────────────────────
    def _save_recon_evidence(self, store: EvidenceStore, recon: dict) -> dict:
        """偵察の決定的観測（ポート/バナー・検出パス・応答ヘッダー・サブドメイン）を保存し、
        サマリーへ埋め込むための {観測キー: evidence_id} を返す（P1.2）。

        保存するのは scanner が実際に観測したもののみ。LLMの解釈は保存しない。
        保存できなかった項目（上限・失敗）はIDなしのまま残る（呼び出し側がstoreの
        omissions/save_errorsをerrorsへ反映する）。
        """
        ids: dict = {}
        host = recon.get("host") or recon.get("target", "")
        for proto, key in (("tcp", "ports"), ("udp", "udp_ports")):
            for p in recon.get(key, []) or []:
                eid = store.save_observation_evidence(
                    category="port", target_ref=f"{host}:{p['port']}/{proto}",
                    detail=f"service={p.get('service', '')} banner={p.get('banner', '')}")
                if eid:
                    ids[(proto, p["port"])] = eid
        web = recon.get("web", {}) or {}
        url = web.get("url") or recon.get("target", "")
        if web.get("headers"):
            eid = store.save_observation_evidence(
                category="web_headers", target_ref=url,
                detail="\n".join(f"{k}: {v}" for k, v in web["headers"].items())
                + ("\nmissing_security_headers: " + ", ".join(web["missing_headers"])
                   if web.get("missing_headers") else ""))
            if eid:
                ids["headers"] = eid
        for fp in web.get("found_paths", []) or []:
            eid = store.save_observation_evidence(
                category="web_path", target_ref=f"{url.rstrip('/')}{fp['path']}",
                detail=f"status={fp['status']}")
            if eid:
                ids[("path", fp["path"])] = eid
        for sub in recon.get("subdomains", []) or []:
            eid = store.save_observation_evidence(
                category="subdomain", target_ref=str(sub), detail="source=crt.sh (passive)")
            if eid:
                ids[("sub", sub)] = eid
        return ids

    def _build_recon_summary(self, recon: dict,
                             known_hits: list[dict] | None = None,
                             evidence_ids: dict | None = None) -> str:
        eids = evidence_ids or {}

        def _tag(key) -> str:
            return f"  [evidence_id={eids[key]}]" if key in eids else ""

        lines = [f"TARGET: {recon.get('target', 'N/A')}"]
        if recon.get("host"):
            lines.append(f"HOST: {recon['host']}")
        if recon.get("ip"):
            lines.append(f"IP: {recon['ip']}")
        if recon.get("os_guess"):
            lines.append(f"OS GUESS: {recon['os_guess']}")

        # 受動サブドメイン列挙結果（スコープ内のみ）
        subs = recon.get("subdomains", [])
        if subs:
            lines.append(f"\n## Passive Subdomain Enumeration (crt.sh, in-scope only) — {len(subs)} found")
            for s in subs:
                lines.append(f"- {s}{_tag(('sub', s))}")

        # ポート
        ports = recon.get("ports", [])
        if ports:
            lines.append("\n## Open TCP Ports")
            for p in ports:
                lines.append(
                    f"- {p['port']}/tcp  {p['service']}  {p.get('banner', '')[:100]}"
                    f"{_tag(('tcp', p['port']))}"
                )
        udp_ports = recon.get("udp_ports", [])
        if udp_ports:
            lines.append("\n## Open UDP Ports (reference)")
            for p in udp_ports:
                lines.append(
                    f"- {p['port']}/udp  {p['service']}  {p.get('banner', '')}"
                    f"{_tag(('udp', p['port']))}"
                )

        # 既知CVE照合結果をサマリーに追加
        if known_hits:
            lines.append(
                f"\n## Local Known-Vuln Results ({len(known_hits)} CVE(s) matched, "
                f"LLM cost: $0.00)"
            )
            for h in known_hits:
                lines.append(
                    f"- [{h['severity']}] {h['cve']} — {h['name']} "
                    f"(service: {h['service']})"
                )

        # Web
        web = recon.get("web", {})
        if web.get("headers"):
            lines.append("\n## HTTP Headers" + _tag("headers"))
            for k, v in web["headers"].items():
                lines.append(f"  {k}: {v}")
        if web.get("technologies"):
            lines.append("\n## Detected Technologies")
            for t in web["technologies"]:
                lines.append(f"  - {t}")
        if web.get("found_paths"):
            lines.append("\n## Sensitive Paths Found")
            for p in web["found_paths"]:
                lines.append(f"  [{p['status']}] {p['path']}{_tag(('path', p['path']))}")
        if web.get("missing_headers"):
            lines.append("\n## Missing Security Headers")
            for h in web["missing_headers"]:
                lines.append(f"  - {h}")
        return "\n".join(lines)

    # ── CTF FLAG HUNT（トグル時のみ・検出のみ・送信なし） ─────
    def _detect_and_report_flags(self, recon: dict) -> None:
        """既に取得した認可偵察レスポンスからフラグを検出して報告する。

        追加リクエストや対象への送信は一切発生しない。既存の recon_data を
        一遍にシリアライズして走査するため、フィールド（バナー・Webボディ・
        ヘッダー・パス名・TLS情報等）の取りこぼしがなく、また web 偵察が
        空/失敗でもバナー等のみで確実に走る。JSON化できない値は str へ落とす。
        """
        flags: list[str] = []
        seen: set[str] = set()
        for field, value in _walk_leaves(recon):
            for f in _detect_flags(value):
                route = self._routes().setdefault(
                    f.lower(), {"kind": "recon_field", "fields": []})
                if field not in route["fields"]:
                    route["fields"].append(field)
                if f.lower() not in seen:
                    seen.add(f.lower())
                    flags.append(f)
        recon["flags"] = flags

        self._out("\n" + "─" * 56 + "\n", "sep")
        self._out("  🔑 CTF FLAG HUNT  — local detection of recon responses\n", "section")
        self._out("─" * 56 + "\n", "sep")
        if flags:
            for f in flags:
                self._out("\n    FLAG  >>>  " + str(f) + "\n", "green")
            self._status(f"CTF Flag Hunt: {len(flags)} flag(s) detected")
            self._log(f"CTF Flag Hunt: detected {len(flags)} flag(s)")
        else:
            self._out("\n  (認可された偵察レスポンスにフラグ形式は検出されませんでした)\n", "mid")
            self._log("CTF Flag Hunt: no flags detected")

    @staticmethod
    def _format_flags(flags: list[str]) -> str:
        if not flags:
            return "(no flags)"
        return "\n".join(f"- {f}" for f in flags)

    # ── CTF ACTIVE RETRIEVAL（トグル時のみ・既定オフ・実送信あり） ──────────
    def _ctf_active_retrieval(
        self, recon: dict, recon_summary: str, session: requests.Session,
        allowed_targets: list[str], max_tier: int,
    ) -> None:
        """送信を伴うフラグ探索。docs/CTF_ACTIVE_FLAG_RETRIEVAL.md 参照。

        EXPLOIT_TRANSMISSION_ENABLED / _assert_no_transmission() とは完全に独立した
        経路。通常のATTACK MODE実行（ctf_active=False、既定）には一切影響しない。
        """
        self._out("\n" + "─" * 56 + "\n", "sep")
        self._out("  🎯 CTF ACTIVE RETRIEVAL  — sends non-destructive verification requests\n", "section")
        self._out("─" * 56 + "\n", "sep")

        ok, reason = require_explicit_scope(allowed_targets)
        if not ok:
            self._out(f"\n  [ABORTED] {reason}\n", "high")
            self._log(f"CTF Active Retrieval aborted: {reason}")
            return

        base_url = recon.get("web", {}).get("url")
        if not base_url:
            self._out("\n  [SKIPPED] Web対象が特定できないため実行できません（Web偵察が未実行/失敗）\n", "mid")
            self._log("CTF Active Retrieval skipped: no web target")
            return

        in_scope_ok, scope_reason = scope_guard.in_scope(base_url, allowed_targets)
        if not in_scope_ok:
            self._out(f"\n  [ABORTED] {scope_reason}\n", "high")
            self._log(f"CTF Active Retrieval aborted: {scope_reason}")
            return

        guard = CtfSafetyGuard(max_requests=30)
        found: list[str] = []

        self._out("\n  Tier 1 — extended path enumeration (read-only)\n", "label")
        found.extend(self._ctf_tier1(base_url, session, guard))

        for tier in (2, 3):
            if found or tier > max_tier or self.is_stopped():
                break
            stop, stop_reason = guard.should_stop()
            if stop:
                self._out(f"\n  [STOPPED before Tier {tier}] {stop_reason}\n", "mid")
                break
            self._out(f"\n  Tier {tier} — LLM-guided non-destructive probing\n", "label")
            found.extend(self._ctf_llm_guided_tier(tier, base_url, recon_summary, session, guard))

        existing = recon.get("flags", []) or []
        seen = {f.lower() for f in existing}
        for f in found:
            if f.lower() not in seen:
                existing.append(f)
                seen.add(f.lower())
        recon["flags"] = existing
        recon["ctf_active_log"] = guard.format_log()

        if found:
            for f in found:
                self._out("\n    FLAG  >>>  " + f + "\n", "green")
            self._status(f"CTF Active Retrieval: {len(found)} flag(s) found")
            self._log(f"CTF Active Retrieval: found {len(found)} flag(s)")
        else:
            self._out("\n  (Active Retrievalでもフラグは見つかりませんでした)\n", "mid")
            self._log("CTF Active Retrieval: no flags found")

        stop, stop_reason = guard.should_stop()
        if stop:
            self._out(f"\n  [{stop_reason}]\n", "mid")

    def _routes(self) -> dict:
        """フラグ取得経路の保持先（run()を経ずに個別メソッドが呼ばれても動くよう遅延生成）。"""
        return self.__dict__.setdefault("_flag_routes", {})

    def _record_active_route(self, hits: list[str], resp, guard: CtfSafetyGuard, *, tier: int,
                             method: str, url: str, rationale: str, params=None, data=None) -> None:
        """Active Retrievalでフラグが見つかったリクエストを取得経路として記録する（レポート用）。

        記録のみで送信ロジック・安全ガードには触れない。URL/パラメータは機密名ベースでマスク、
        応答抜粋はフラグ周辺のみ（フラグ自体はマスクしない）。
        """
        for f in hits:
            self._routes()[f.lower()] = {
                "kind": "active", "tier": tier, "method": method,
                "url": redaction.mask_url(url),
                "params": redaction.mask_body(json.dumps(params, ensure_ascii=False, default=str)) if params else "",
                "data": redaction.mask_body(json.dumps(data, ensure_ascii=False, default=str)) if data else "",
                "status": resp.status_code, "rationale": rationale,
                "request_no": len(guard.log),
                "excerpt": _flag_excerpt(resp.text, f),
                "_headers": dict(resp.headers), "_body": resp.text,  # 証拠保存用（レポートへは出さない）
            }

    def _flag_findings(self, recon: dict, scan_id: str) -> tuple[list[Finding], list[str]]:
        """取得したフラグを「中身・取得経路」付きのFindingへ変換する。

        フラグは成果物であり秘密として隠さない。severityはINFO（脆弱性の深刻度ではない）。
        `save_evidence`有効時は、Active Retrievalの応答を証拠として保存しevidence_idsを付ける。
        戻り値の2要素目は証拠保存のエラー/省略（ScanResult.errors用）。
        """
        flags = recon.get("flags") or []
        if not flags:
            return [], []
        store = (getattr(self, "_ev_store", None)
                 or (EvidenceStore(scan_id) if config.get("save_evidence", False) else None))
        out: list[Finding] = []
        for f in flags:
            route = self._routes().get(f.lower(), {})
            eids: list[str] = []
            if route.get("kind") == "active":
                loc = f"{route['method']} {route['url']}"
                how = [f"取得方法: CTF Active Retrieval（Tier{route['tier']}・送信を伴う読み取り専用リクエスト）",
                       f"リクエスト: {loc}" + (f" params={route['params']}" if route["params"] else "")
                       + (f" data={route['data']}" if route["data"] else ""),
                       f"応答ステータス: {route['status']}",
                       f"試行の目的: {route['rationale'] or '(記載なし)'}",
                       f"送信履歴上の位置: {route['request_no']}件目"]
                snippet = route["excerpt"]
                if store is not None:
                    eid = store.save_http_evidence(
                        method=route["method"], url=route["url"], status=route["status"],
                        headers=route["_headers"], body=route["_body"])
                    if eid:
                        eids.append(eid)
            elif route.get("kind") == "recon_field":
                loc = ", ".join(route["fields"][:3])
                how = ["取得方法: CTF Flag Hunt（取得済みの偵察結果の中から検出。追加送信なし）",
                       "検出されたフィールド: " + ", ".join(route["fields"])]
                snippet = ""
            else:
                loc, how, snippet = "", ["取得経路: 記録なし"], ""
            out.append(Finding(
                finding_id=new_id("finding"), rule_id="CTF_FLAG", location=loc,
                severity="INFO", verification_state="observed",
                description=f"CTF flag captured: {f}", remediation="",
                snippet=snippet, analysis="\n".join(how), evidence_ids=eids,
            ))
        errs: list[str] = []
        if store is not None:
            errs += [f"証拠保存エラー: {e}" for e in store.save_errors]
            errs += [f"証拠保存を省略: {o}" for o in store.omissions]
        return out, errs

    def _ctf_tier1(
        self, base_url: str, session: requests.Session, guard: CtfSafetyGuard,
    ) -> list[str]:
        """Tier1: CTF向けの隠しファイル名ワードリストを、既定GETで巡回するだけ。

        LLMは介さない決定的な処理。見つかった時点で即座に打ち切り、以降の候補への
        不要な送信をしない（層3のリクエスト予算節約と兼ねる）。
        """
        base = base_url.rstrip("/")
        for word in _CTF_TIER1_WORDLIST:
            stop, _ = guard.should_stop()
            if stop or self.is_stopped():
                break
            url = f"{base}/{word}"
            resp, msg = guard.send(session, "GET", url, tier=1, rationale=f"wordlist:{word}")
            self._log(f"  [Tier1] {msg}")
            if resp is not None and resp.status_code == 200:
                hits = _detect_flags(resp.text)
                if hits:
                    self._record_active_route(hits, resp, guard, tier=1, method="GET", url=url,
                                              rationale=f"wordlist:{word}")
                    return hits
        return []

    def _ctf_llm_guided_tier(
        self, tier: int, base_url: str, recon_summary: str,
        session: requests.Session, guard: CtfSafetyGuard,
    ) -> list[str]:
        """Tier2/3共通: LLMに読み取り専用の検証候補を提案させ、1件ずつ層2(is_destructive)・
        層3(CtfSafetyGuard)のガード付きで送信する。候補のフォーマットが崩れていたり
        LLM呼び出しが失敗した場合は、静かに空リストを返す（このTierは何も見つからなかった
        扱いにして次に進む／終了する。例外を上に投げてスキャン全体を落とさない）。
        """
        n = 5
        prompt = CTF_ACTIVE_SYSTEM_PROMPT.format(tier_note=_CTF_TIER_NOTES[tier], n=n)
        # _complete_llm は例外を握りつぶしログに記録したうえで "" を返す設計
        # （base_agent.py）。ここでの追加の try/except は不要。
        raw = self._complete_llm([
            self.llm.system(prompt),
            self.llm.user(
                f"Reconnaissance summary:\n{recon_summary}\n\n"
                f"Propose up to {n} read-only verification requests."
            ),
        ], role="fast")

        candidates = self._parse_ctf_candidates(raw)
        if not candidates:
            self._log(f"  [Tier{tier}] LLMから有効な候補が得られませんでした")
            return []

        base = base_url.rstrip("/")
        for cand in candidates[:n]:
            stop, _ = guard.should_stop()
            if stop or self.is_stopped():
                break
            method = str(cand.get("method", "GET")).upper()
            if method not in ("GET", "POST"):
                method = "GET"
            path = str(cand.get("path", ""))
            if not path.startswith("/"):
                path = "/" + path
            url = base + path
            rationale = str(cand.get("rationale", ""))
            kwargs: dict = {}
            if cand.get("params"):
                kwargs["params"] = cand["params"]
            if cand.get("data"):
                kwargs["data"] = cand["data"]
            resp, msg = guard.send(session, method, url, tier=tier, rationale=rationale, **kwargs)
            self._log(f"  [Tier{tier}] {msg} ({rationale})")
            if resp is not None and resp.status_code < 500:
                hits = _detect_flags(resp.text)
                if hits:
                    self._record_active_route(hits, resp, guard, tier=tier, method=method, url=url,
                                              rationale=rationale, params=kwargs.get("params"),
                                              data=kwargs.get("data"))
                    return hits
        return []

    @staticmethod
    def _parse_ctf_candidates(raw: str) -> list[dict]:
        """LLM応答からJSON配列を抽出する（```json フェンス・前後の説明文を許容）。

        パース不能・配列でない・要素がdictでない場合は空リストを返す（例外にしない —
        このTierを「候補なし」として扱えば、呼び出し側は安全にスキップできる）。
        """
        text = raw.strip()
        m = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.S)
        if m:
            text = m.group(1)
        else:
            start, end = text.find("["), text.rfind("]")
            if start != -1 and end != -1 and end > start:
                text = text[start:end + 1]
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return []
        if not isinstance(data, list):
            return []
        return [c for c in data if isinstance(c, dict) and c.get("path")]
