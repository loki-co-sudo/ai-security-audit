"""
agents/recon_agent.py — ペネトレーションテスト偵察エージェント

Phase 1: ネットワーク偵察（ポートスキャン・バナーグラブ）
Phase 2: Webターゲット列挙（ヘッダー・技術スタック・センシティブパス）
Phase 3: 既知サービスバナーのローカル照合 (known_vulns.yaml)
Phase 4: LLMが発見情報から脆弱性仮説を構築
"""

from __future__ import annotations
import os
import re
import time
from agents.base_agent import BaseAgent
from tools.network_scanner import NetworkScanner, passive_os_fingerprint
from tools.web_prober import WebProber
from core.settings import (
    SCAN_PROFILES, DEFAULT_SCAN_PROFILE,
    COMMON_PORTS, EXTENDED_PORTS, COMMON_UDP_PORTS,
)

STEPS = [
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


class ReconAgent(BaseAgent):

    def run(self, target: str, scan_web: bool = True, intensity: str = DEFAULT_SCAN_PROFILE,
            generate_exploit: bool = True, port_scope: str = "common",
            scan_udp: bool = False) -> None:
        self.bus.clear()
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

        recon_data: dict = {"target": target, "ports": [], "udp_ports": [], "web": {}}

        # ── Step 0: ターゲット解析 ─────────────────────────
        self._step(0, "running")
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
        self._step(0, "done")

        if self.is_stopped(): return

        # ── Step 1: ポートスキャン ─────────────────────────
        self._step(1, "running")
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
        self._step(1, "done")

        if self.is_stopped(): return

        # ── Step 2: バナー詳細 ─────────────────────────────
        self._step(2, "running")
        time.sleep(0.2)
        self._step(2, "done")

        # ── Step 3: 既知サービス脆弱性ローカル照合 (P0) ───
        self._step(3, "running")
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
        self._step(3, "done")

        if self.is_stopped(): return

        # ── Step 4: Webプローブ ────────────────────────────
        self._step(4, "running")
        if scan_web and (any(p["port"] in (80, 443, 8080, 8443, 8000) for p in open_ports) or
                         target.startswith("http")):
            self._out("\n" + "─" * 56 + "\n", "sep")
            self._out("  PHASE 2 — WEB ENUMERATION\n", "section")
            self._out("─" * 56 + "\n", "sep")

            base_url = target if target.startswith("http") else \
                       ("https://" if any(p["port"] == 443 for p in open_ports) else "http://") + host

            self._log(f"Web probe: {base_url}")
            self._status(f"Webプローブ中: {base_url} ...")

            web_data = prober.probe(base_url, on_progress=self._log)
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

        self._step(4, "done")

        if self.is_stopped(): return

        # ── Step 5: 受動OSフィンガープリント ──────────────
        self._step(5, "running")
        os_guess = passive_os_fingerprint(
            recon_data["ports"], recon_data.get("web", {}).get("headers"),
        )
        if os_guess:
            recon_data["os_guess"] = os_guess
            self._out("\n  Passive OS Fingerprint:\n", "label")
            self._out(f"    ▸ {os_guess}  (バナー解析による受動推定／追加通信なし)\n", "high")
        self._step(5, "done")

        # ── Step 6: AI 脆弱性仮説 ─────────────────────────
        self._step(6, "running")
        self._out("\n" + "─" * 56 + "\n", "sep")
        self._out("  PHASE 3 — AI ATTACK HYPOTHESIS  (streaming)\n", "section")
        self._out("─" * 56 + "\n\n", "sep")
        self._status("AI が攻撃仮説を構築中 ...")
        self._log("Sending recon data to LLM ...")

        recon_summary = self._build_recon_summary(recon_data, known_hits)
        full = self._stream_llm([
            self.llm.system(SYSTEM_PROMPT),
            self.llm.user(f"Analyze this reconnaissance data and build attack hypotheses:\n\n{recon_summary}"),
        ], live_stats=True)

        # 品質エフォート: STRONGモデルで攻撃仮説を再検証し過剰主張を除去する。
        if self._effort().get("verify_pass") and not self.is_stopped():
            full = self._verify_findings(recon_summary, full)
        self._step(6, "done")

        if self.is_stopped(): return

        # ── Step 7: エクスプロイト(PoC)生成 — ローカル生成のみ・送信なし ──
        self._step(7, "running")
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
        self._step(7, "done")

        # ── Step 8: レポート生成 ──────────────────────────
        self._step(8, "running")
        body = (
            f"## Reconnaissance Data\n{recon_summary}\n\n"
            f"## AI Attack Hypotheses\n{full}\n\n"
            + (f"## Generated PoCs (local only)\n{exploit_text}\n" if exploit_text else "")
        )
        self._save_investigation("ATTACK MODE", target, body)
        time.sleep(0.2)
        self._step(8, "done")

        total_ports = len(recon_data["ports"])
        self._out("\n\n" + "═" * 56 + "\n", "sep")
        self._out(f"  RECON COMPLETE  |  {total_ports} open ports discovered\n", "green")
        self._out("═" * 56 + "\n", "sep")
        self._log(f"Recon complete. {total_ports} open ports.")
        self._status(f"Recon complete — {total_ports} open ports.")
        self._done()

    # ── 偵察サマリー生成 ──────────────────────────────────
    def _build_recon_summary(self, recon: dict,
                             known_hits: list[dict] | None = None) -> str:
        lines = [f"TARGET: {recon.get('target', 'N/A')}"]
        if recon.get("host"):
            lines.append(f"HOST: {recon['host']}")
        if recon.get("ip"):
            lines.append(f"IP: {recon['ip']}")
        if recon.get("os_guess"):
            lines.append(f"OS GUESS: {recon['os_guess']}")

        # ポート
        ports = recon.get("ports", [])
        if ports:
            lines.append("\n## Open TCP Ports")
            for p in ports:
                lines.append(
                    f"- {p['port']}/tcp  {p['service']}  {p.get('banner', '')[:100]}"
                )
        udp_ports = recon.get("udp_ports", [])
        if udp_ports:
            lines.append("\n## Open UDP Ports (reference)")
            for p in udp_ports:
                lines.append(
                    f"- {p['port']}/udp  {p['service']}  {p.get('banner', '')}"
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
            lines.append("\n## HTTP Headers")
            for k, v in web["headers"].items():
                lines.append(f"  {k}: {v}")
        if web.get("technologies"):
            lines.append("\n## Detected Technologies")
            for t in web["technologies"]:
                lines.append(f"  - {t}")
        if web.get("found_paths"):
            lines.append("\n## Sensitive Paths Found")
            for p in web["found_paths"]:
                lines.append(f"  [{p['status']}] {p['path']}")
        if web.get("missing_headers"):
            lines.append("\n## Missing Security Headers")
            for h in web["missing_headers"]:
                lines.append(f"  - {h}")
        return "\n".join(lines)