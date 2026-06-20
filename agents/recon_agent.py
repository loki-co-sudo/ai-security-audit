"""
agents/recon_agent.py — ペネトレーションテスト偵察エージェント

Phase 1: ネットワーク偵察（ポートスキャン・バナーグラブ）
Phase 2: Webターゲット列挙（ヘッダー・技術スタック・センシティブパス）
Phase 3: LLMが発見情報から脆弱性仮説を構築
"""

from __future__ import annotations
import time
from agents.base_agent import BaseAgent
from tools.network_scanner import NetworkScanner, passive_os_fingerprint
from tools.web_prober import WebProber
from core.settings import SCAN_PROFILES, DEFAULT_SCAN_PROFILE

STEPS = [
    "ターゲット解析・接続確認",
    "ポートスキャン実行中",
    "サービス・バナー取得中",
    "Webターゲット列挙中",
    "受動OSフィンガープリント中",
    "AIが脆弱性仮説を構築中",
    "リスクレポートを生成中",
]

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

    def run(self, target: str, scan_web: bool = True, intensity: str = DEFAULT_SCAN_PROFILE) -> None:
        self.bus.clear()
        self._status(f"偵察開始: {target}")

        # intensity = スキャンプロファイル名（stealth / passive / moderate / aggressive）
        if intensity not in SCAN_PROFILES:
            intensity = DEFAULT_SCAN_PROFILE
        scanner = NetworkScanner.from_profile(intensity)
        prober  = WebProber(timeout=8, profile=intensity)

        recon_data: dict = {"target": target, "ports": [], "web": {}}

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
        self._out(f"  WEB PROBE : {'YES' if scan_web else 'NO'}\n\n", "dim")

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
        self._step(1, "done")

        if self.is_stopped(): return

        # ── Step 2: バナー詳細 ─────────────────────────────
        self._step(2, "running")
        time.sleep(0.2)
        self._step(2, "done")

        # ── Step 3: Webプローブ ────────────────────────────
        self._step(3, "running")
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

        self._step(3, "done")

        if self.is_stopped(): return

        # ── Step 4: 受動OSフィンガープリント ──────────────
        self._step(4, "running")
        os_guess = passive_os_fingerprint(
            recon_data["ports"], recon_data.get("web", {}).get("headers"),
        )
        if os_guess:
            recon_data["os_guess"] = os_guess
            self._out("\n  Passive OS Fingerprint:\n", "label")
            self._out(f"    ▸ {os_guess}  (バナー解析による受動推定／追加通信なし)\n", "high")
        self._step(4, "done")

        # ── Step 5: AI 脆弱性仮説 ─────────────────────────
        self._step(5, "running")
        self._out("\n" + "─" * 56 + "\n", "sep")
        self._out("  PHASE 3 — AI ATTACK HYPOTHESIS  (streaming)\n", "section")
        self._out("─" * 56 + "\n\n", "sep")
        self._status("AI が攻撃仮説を構築中 ...")
        self._log("Sending recon data to LLM ...")

        recon_summary = self._build_recon_summary(recon_data)
        full = self._stream_llm([
            self.llm.system(SYSTEM_PROMPT),
            self.llm.user(f"Analyze this reconnaissance data and build attack hypotheses:\n\n{recon_summary}"),
        ])
        self._step(5, "done")

        # ── Step 6: レポート完了 ───────────────────────────
        self._step(6, "running")
        import re
        counts = {s: len(re.findall(rf"SEVERITY:\s*{s}\b", full, re.I))
                  for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        self._stats(counts)
        time.sleep(0.2)
        self._step(6, "done")

        total = sum(counts.values())
        self._out("\n\n" + "═" * 56 + "\n", "sep")
        self._out(f"  RECON COMPLETE  |  {total} findings identified\n", "green")
        self._out("═" * 56 + "\n", "sep")
        self._log(f"Recon complete. {total} findings.")
        self._status(f"偵察完了 — {total} findings identified.")
        self._done()

    @staticmethod
    def _build_recon_summary(data: dict) -> str:
        lines = [f"TARGET: {data.get('target', 'unknown')}"]
        if data.get("ip"):
            lines.append(f"RESOLVED IP: {data['ip']}")
        if data.get("os_guess"):
            lines.append(f"PASSIVE OS GUESS: {data['os_guess']}")
        if data.get("ports"):
            lines.append("\nOPEN PORTS:")
            for p in data["ports"]:
                lines.append(f"  {p['port']}/tcp  {p['service']}  {p['banner']}")
        web = data.get("web", {})
        if web.get("technologies"):
            lines.append("\nDETECTED TECHNOLOGIES:")
            for t in web["technologies"]:
                lines.append(f"  - {t}")
        if web.get("missing_headers"):
            lines.append("\nMISSING SECURITY HEADERS:")
            for h in web["missing_headers"]:
                lines.append(f"  - {h}")
        if web.get("found_paths"):
            lines.append("\nSENSITIVE PATHS FOUND:")
            for p in web["found_paths"]:
                lines.append(f"  [{p['status']}] {p['path']}")
        if web.get("ssl_info"):
            lines.append(f"\nSSL: {web['ssl_info']}")
        return "\n".join(lines)
