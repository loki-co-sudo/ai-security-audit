"""
agents/fuzz_agent.py — Webスマートファジングエージェント

フロー:
  Phase 1: 同一オリジンを浅くクロールし注入点（クエリ／フォーム）を抽出
  Phase 2: AIが各脆弱性クラスの検出プローブ（テストベクタ）を文脈推論で生成
  Phase 3: 注入点へプローブを送りレスポンス異常を観測（検出のみ・非エクスプロイト）
  Phase 4: AIが観測結果をトリアージし FINDING 形式のレポートを生成

安全設計: 認可された対象専用。総リクエスト数に上限を設け、ステルスプロファイルの
ジッター／低並列を流用してDoSを避ける。データ窃取やRCE等のエクスプロイトは行わない。
"""

from __future__ import annotations
import json
import re
from agents.base_agent import BaseAgent
from tools.web_fuzzer import WebFuzzer, DEFAULT_PROBES
from core.settings import SCAN_PROFILES, DEFAULT_SCAN_PROFILE

STEPS = [
    "ターゲット解析・接続確認",
    "クロール・注入点検出中",
    "AIが検出プローブを生成中",
    "ファジング実行中（検出のみ）",
    "AIが結果をトリアージ中",
    "レポートを生成中",
]

_PROBE_SYS = """You are a web application security tester generating *detection probes* \
for an authorized vulnerability assessment. For each vulnerability class, output a SMALL set \
of short test strings whose only purpose is to REVEAL whether an input is mishandled \
(error signatures, reflection, template evaluation). Do NOT produce data-exfiltration or \
destructive payloads — only minimal detection vectors.

Return ONLY a JSON object mapping category to a list of strings, using exactly these keys:
SQLI, XSS, TRAVERSAL, SSTI. Keep each list to 3-5 short entries. No commentary."""

_TRIAGE_SYS = """You are an expert web application penetration tester triaging the results of \
an authorized detection-only fuzzing run. You are given the injection points tested and the \
anomalies observed (reflected payloads, DB error signatures, template evaluation, file-content \
signatures). Assess each observation, discard likely false positives, and report confirmed or \
probable vulnerabilities.

For each finding, output EXACTLY this block (the report generator parses these markers):

---VULN_START---
NAME: [Vulnerability name and affected parameter]
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW]
CWE: [CWE-ID]
LINES: [affected URL + parameter]
SNIPPET:
```
[the probe that triggered the anomaly]
```
ATTACK:
[why this indicates a vulnerability and the realistic impact — analysis only, no working exploit]
FIX:
```
[concrete remediation: parameterized queries, output encoding, input validation, etc.]
```
---VULN_END---

If no credible vulnerability is supported by the evidence, say so plainly and recommend \
manual verification. Be precise and avoid overclaiming."""


class FuzzAgent(BaseAgent):

    def run(
        self,
        target: str,
        profile: str = DEFAULT_SCAN_PROFILE,
        max_requests: int = 200,
        max_pages: int = 20,
    ) -> None:
        self.bus.clear()
        self._status(f"ファジング開始: {target}")

        if profile not in SCAN_PROFILES:
            profile = DEFAULT_SCAN_PROFILE
        base_url = target if target.startswith("http") else "http://" + target

        # ── Step 0: ヘッダ ─────────────────────────────────
        self._step(0, "running")
        self._out(
            "╔══════════════════════════════════════════════════════╗\n"
            "║       WEB FUZZING — SMART INPUT TESTING (DETECT)     ║\n"
            "╚══════════════════════════════════════════════════════╝\n\n",
            "header",
        )
        self._out(f"  TARGET       : {base_url}\n", "dim")
        self._out(f"  PROFILE      : {profile.upper()}\n", "dim")
        self._out(f"  REQ BUDGET   : {max_requests} (DoS防止上限)\n", "dim")
        self._out("  MODE         : 検出のみ（兆候観測・非エクスプロイト）\n", "green")
        self._out("  SCOPE        : 同一オリジン限定 — 認可された対象のみ\n\n", "green")
        self._step(0, "done")
        if self.is_stopped():
            return

        fuzzer = WebFuzzer(
            profile=profile, max_pages=max_pages,
            max_requests=max_requests, log=self._log,
        )

        # ── Step 1: クロール・注入点検出 ───────────────────
        self._step(1, "running")
        self._out("─" * 56 + "\n", "sep")
        self._out("  PHASE 1 — CRAWL & INJECTION-POINT DISCOVERY\n", "section")
        self._out("─" * 56 + "\n", "sep")
        self._status("クロール中 ...")
        crawl = fuzzer.crawl(base_url)
        points = crawl["injection_points"]
        self._out(f"\n  {crawl['pages']} page(s) crawled, "
                  f"{len(points)} injection point(s) found:\n\n", "green")
        for ip in points[:40]:
            self._out(f"    [{ip['method']:<4}] {ip['param']:<18} "
                      f"({ip['where']})  {ip['url']}\n", "code")
        self._step(1, "done")
        if self.is_stopped():
            return

        if not points:
            self._out("\n  注入点が見つかりませんでした（パラメータ／フォーム無し、"
                      "またはJS依存のページ）。\n", "high")
            self._finish(0)
            return

        # ── Step 2: AIが検出プローブを生成 ─────────────────
        self._step(2, "running")
        self._out("\n" + "─" * 56 + "\n", "sep")
        self._out("  PHASE 2 — AI PROBE GENERATION\n", "section")
        self._out("─" * 56 + "\n", "sep")
        self._status("AIが検出プローブを生成中 ...")
        probes = self._gen_probes(points)
        total_probes = sum(len(v) for v in probes.values())
        self._out(f"\n  {total_probes} 検出プローブを {len(probes)} カテゴリで生成:\n", "green")
        for cat, lst in probes.items():
            self._out(f"    {cat:<10}: {len(lst)} probes\n", "dim")
        self._step(2, "done")
        if self.is_stopped():
            return

        # ── Step 3: ファジング（検出のみ） ─────────────────
        self._step(3, "running")
        self._out("\n" + "─" * 56 + "\n", "sep")
        self._out("  PHASE 3 — FUZZING (DETECTION ONLY)\n", "section")
        self._out("─" * 56 + "\n", "sep")
        self._status("ファジング実行中 ...")
        anomalies = fuzzer.fuzz(points, probes)
        self._out(f"\n  {fuzzer._req_count} リクエスト送信, "
                  f"{len(anomalies)} 件の異常兆候を観測:\n\n", "green")
        for a in anomalies:
            sev_tag = a["severity"].lower() if a["severity"] != "CRITICAL" else "critical"
            self._out(f"    [{a['category']}] {a['param']}@{a['url']}\n", sev_tag)
            self._out(f"        payload : {a['payload'][:60]}\n", "dim")
            self._out(f"        evidence: {a['evidence']}\n", "dim")
        self._step(3, "done")
        if self.is_stopped():
            return

        # ── Step 4: AIトリアージ ───────────────────────────
        self._step(4, "running")
        self._out("\n" + "─" * 56 + "\n", "sep")
        self._out("  PHASE 4 — AI TRIAGE & REPORT  (streaming)\n", "section")
        self._out("─" * 56 + "\n\n", "sep")
        self._status("AIが結果をトリアージ中 ...")
        summary = self._build_summary(base_url, points, anomalies)
        full = self._stream_llm([
            self.llm.system(_TRIAGE_SYS),
            self.llm.user(f"Triage these authorized fuzzing results:\n\n{summary}"),
        ])
        self._step(4, "done")

        # 調査レポートをファイルに保存する。
        body = f"## Fuzzing Summary\n```\n{summary}\n```\n\n## AI Triage\n{full}\n"
        self._save_investigation("WEB FUZZ", base_url, body)

        # ── Step 5: 完了 ───────────────────────────────────
        counts = {s: len(re.findall(rf"SEVERITY:\s*{s}\b", full, re.I))
                  for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        self._finish(sum(counts.values()), counts)

    # ── AI プローブ生成 ────────────────────────────────────
    def _gen_probes(self, points: list[dict]) -> dict[str, list[str]]:
        param_names = sorted({p["param"] for p in points})[:20]
        reply = self._complete_llm([
            self.llm.system(_PROBE_SYS),
            self.llm.user(
                "Target parameters under test (authorized): "
                + ", ".join(param_names)
                + "\nGenerate minimal detection probes as the specified JSON."
            ),
        ])
        probes = self._parse_probes(reply)
        # マーカー方式のXSS検出を機能させるため、組込みXSSプローブを必ず併用する
        merged = {k: list(v) for k, v in DEFAULT_PROBES.items()}
        for cat, lst in probes.items():
            if cat in merged:
                # AI生成を優先しつつ組込みXSSマーカープローブを温存
                merged[cat] = (DEFAULT_PROBES["XSS"] if cat == "XSS" else []) + lst
        return merged

    @staticmethod
    def _parse_probes(reply: str) -> dict[str, list[str]]:
        m = re.search(r"\{.*\}", reply, re.S)
        if not m:
            return {}
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return {}
        out = {}
        for cat in ("SQLI", "XSS", "TRAVERSAL", "SSTI"):
            vals = data.get(cat)
            if isinstance(vals, list):
                out[cat] = [str(v) for v in vals if isinstance(v, (str, int))][:5]
        return out

    @staticmethod
    def _build_summary(base_url, points, anomalies) -> str:
        lines = [f"TARGET: {base_url}",
                 f"INJECTION POINTS TESTED: {len(points)}"]
        for ip in points[:30]:
            lines.append(f"  {ip['method']} {ip['param']} ({ip['where']}) {ip['url']}")
        lines.append(f"\nANOMALIES OBSERVED: {len(anomalies)}")
        if not anomalies:
            lines.append("  (no anomalies — inputs appear to be handled safely)")
        for a in anomalies:
            lines.append(
                f"  - category={a['category']} param={a['param']} url={a['url']} "
                f"status={a['status']} severity_hint={a['severity']}\n"
                f"    payload={a['payload']}\n    evidence={a['evidence']}"
            )
        return "\n".join(lines)

    # ── 完了処理 ───────────────────────────────────────────
    def _finish(self, total: int, counts: dict | None = None) -> None:
        self._step(5, "running")
        if counts:
            self._stats(counts)
        self._out("\n\n" + "═" * 56 + "\n", "sep")
        self._out(f"  FUZZING COMPLETE  |  {total} findings reported\n", "green")
        self._out("═" * 56 + "\n", "sep")
        self._step(5, "done")
        self._status(f"ファジング完了 — {total} findings")
        self._done()
