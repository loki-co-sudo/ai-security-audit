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
            generate_exploit: bool = True) -> None:
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
        ], live_stats=True)
        self._step(5, "done")

        if self.is_stopped(): return

        # ── Step 6: エクスプロイト(PoC)生成 — ローカル生成のみ・送信なし ──
        self._step(6, "running")
        exploit_text = ""
        if generate_exploit:
            _assert_no_transmission()  # 送信が無効であることを保証
            self._out("\n" + "─" * 56 + "\n", "sep")
            self._out("  PHASE 4 — EXPLOIT PoC GENERATION  (streaming)\n", "section")
            self._out("─" * 56 + "\n", "sep")
            self._out(
                "  ⚠ 生成された PoC は画面表示・ファイル保存のみ。\n"
                "    対象へは一切【送信・実行されません】（DRY-RUN / NOT TRANSMITTED）。\n\n",
                "high",
            )
            self._status("AI が PoC を生成中 ...（送信は行いません）")
            self._log("Generating PoCs locally (never transmitted) ...")
            exploit_text = self._stream_llm([
                self.llm.system(EXPLOIT_SYSTEM_PROMPT),
                self.llm.user(
                    "Using the reconnaissance summary and the attack hypotheses below, "
                    "generate minimal, non-destructive PoCs for the findings that warrant "
                    "them. Remember: this tool only displays/saves them and never sends "
                    "them to any target.\n\n"
                    f"RECON SUMMARY:\n{recon_summary}\n\n"
                    f"ATTACK HYPOTHESES:\n{full}"
                ),
            ])
            self._out(
                "\n\n  ✔ PoC生成はローカルで完了しました。対象への送信・実行は行っていません。\n",
                "green",
            )
        else:
            self._out("\n  [ PoC生成: スキップ（チェックOFF） ]\n", "dim")
        self._step(6, "done")

        if self.is_stopped(): return

        # ── Step 7: レポート完了・成果物の保存 ─────────────
        self._step(7, "running")
        import re
        counts = {s: len(re.findall(rf"SEVERITY:\s*{s}\b", full, re.I))
                  for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        self._stats(counts)

        # PoC・調査レポートをファイルに保存する。
        self._save_artifacts(target, recon_summary, full, exploit_text)

        time.sleep(0.2)
        self._step(7, "done")

        total = sum(counts.values())
        self._out("\n\n" + "═" * 56 + "\n", "sep")
        self._out(f"  RECON COMPLETE  |  {total} findings identified\n", "green")
        self._out("═" * 56 + "\n", "sep")
        self._log(f"Recon complete. {total} findings.")
        self._status(f"偵察完了 — {total} findings identified.")
        self._done()

    def _save_artifacts(self, target: str, recon_summary: str,
                        hypotheses: str, exploit_text: str) -> None:
        """PoC と調査レポートを reports/ 配下に保存し、保存先を出力する。"""
        self._save_poc(target, exploit_text)
        body = (
            f"## Reconnaissance Summary\n```\n{recon_summary}\n```\n\n"
            f"## AI Attack Hypotheses\n{hypotheses}\n\n"
            f"## Generated PoCs (NOT TRANSMITTED)\n"
            f"{exploit_text.strip() or '(PoC generation skipped)'}\n"
        )
        self._save_investigation("ATTACK MODE", target, body)

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
