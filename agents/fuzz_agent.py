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
import time
from agents.base_agent import BaseAgent
from tools.web_fuzzer import WebFuzzer, DEFAULT_PROBES
from tools.report_generator import _findings_and_counts
from core.settings import SCAN_PROFILES, DEFAULT_SCAN_PROFILE
from core.findings import (
    Finding, CoverageItem, ScanState, VerificationState, CoverageStatus, new_id,
)

def idor_skip_reason(fuzzer: WebFuzzer) -> str | None:
    """認証必須のIDORチェックをskipすべき理由を返す（skip不要ならNone、P0.2）。

    どちらのセッションであっても認証状態が"expired"（失敗の実証拠あり）なら、
    未認証セッション同士（またはそれに準ずる状態）の比較になり「アクセス制御が
    機能している」という誤判定を招くため実行しない。"unknown"（判定不能）は
    従来どおり実行し、所見側の「要人手確認」表記に委ねる。
    """
    if fuzzer.auth_state == "expired":
        return f"第1セッションの認証状態=expired — {fuzzer.auth_state_reason}"
    if fuzzer.auth_state_b == "expired":
        return f"第2セッションの認証状態=expired — {fuzzer.auth_state_reason_b}"
    return None


STEPS = [
    "ターゲット解析・接続確認",
    "クロール・注入点検出中",
    "AIが検出プローブを生成中",
    "ファジング実行中（検出のみ）",
    "認可チェック中（別セッション比較・第2アカウント設定時のみ）",
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
signatures). You may also receive an ACCESS CONTROL CHECK section (2nd-session GET-only \
comparison) — treat entries there as additional evidence of IDOR / broken access control. \
Assess each observation, discard likely false positives, and report confirmed or \
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
        auth: dict | None = None,
        auth_b: dict | None = None,
        tls_verify: bool | None = None,
        tls_ca_bundle: str | None = None,
    ) -> None:
        self._current_mode, self._current_target = "WEB FUZZ", target
        self.bus.clear()
        if not self._check_scope(target):
            return
        t0 = time.time()
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
        self._out("  SCOPE        : 同一オリジン限定 — 認可された対象のみ\n", "green")
        self._out(f"  AUTH         : {'設定あり（認証付きファジング）' if auth else 'なし'}\n",
                  "green" if auth else "dim")
        self._step(0, "done")
        if self.is_stopped():
            return

        fuzzer = WebFuzzer(
            profile=profile, max_pages=max_pages,
            max_requests=max_requests, log=self._log, auth=auth, auth_b=auth_b,
            target=base_url,  # 基準originを認証より前に確定する (P0.1)
            stop_event=self._stop_event,  # STOP後は新しい送信を開始しない (P0.2)
            tls_verify=tls_verify, tls_ca_bundle=tls_ca_bundle,
        )
        self._out(f"  TLS VERIFY   : {'有効' if fuzzer.tls_verify else '無効（既定・後方互換）'}\n\n",
                  "green" if fuzzer.tls_verify else "dim")

        # 認証を適用（Cookie / ヘッダー / ログインフォーム）
        if auth:
            ok, msg = fuzzer.authenticate()
            self._out(f"  [AUTH] {msg}\n", "green" if ok else "high")
            self._out(f"  [AUTH-STATE] {fuzzer.auth_state} — {fuzzer.auth_state_reason}\n",
                      "green" if fuzzer.auth_state == "authenticated" else "dim")
            self._log(f"auth: {msg} (state={fuzzer.auth_state})")
        if auth_b:
            ok_b, msg_b = fuzzer.authenticate_b()
            self._out(f"  [AUTH-B] {msg_b}\n", "green" if ok_b else "high")
            self._out(f"  [AUTH-B-STATE] {fuzzer.auth_state_b} — {fuzzer.auth_state_reason_b}\n",
                      "green" if fuzzer.auth_state_b == "authenticated" else "dim")
            self._log(f"auth_b: {msg_b} (state={fuzzer.auth_state_b})")

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
            self._finish(0, target=base_url, t0=t0)
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

        # ── Step 4: 認可チェック（第2アカウント設定時のみ・GET限定） ──
        self._step(4, "running")
        idor_findings: list[dict] = []
        idor_ran = False
        idor_skip_reason_val: str | None = None
        if auth_b:
            self._out("\n" + "─" * 56 + "\n", "sep")
            self._out("  PHASE — ACCESS CONTROL CHECK (2nd session, GET-only)\n", "section")
            self._out("─" * 56 + "\n", "sep")
            skip_reason = idor_skip_reason(fuzzer)
            if skip_reason:
                # 認証必須検査は失敗を検知した場合skipし理由を残す(P0.2)。未認証セッション
                # 同士の比較は「アクセス制御が機能している」との誤判定を招くため実行しない。
                idor_skip_reason_val = skip_reason
                self._out(f"\n  (スキップ: {skip_reason})\n", "high")
                self._log(f"idor: skip ({skip_reason})")
            else:
                idor_ran = True
                self._status("認可チェック中（別セッション比較）...")
                idor_findings = fuzzer._detect_idor(points)
                if idor_findings:
                    self._out(f"\n  {len(idor_findings)} 件のアクセス制御不備の兆候を観測:\n\n", "high")
                    for f in idor_findings:
                        self._out(f"    [IDOR?] {f['param']}@{f['url']}\n", "high")
                        self._out(f"        evidence: {f['evidence']}\n", "dim")
                else:
                    self._out("\n  (兆候なし)\n", "dim")
        else:
            self._out("\n  (第2アカウント未設定のためスキップ)\n", "dim")
        self._step(4, "done")
        if self.is_stopped():
            return

        # ── Step 5: AIトリアージ ───────────────────────────
        self._step(5, "running")
        self._out("\n" + "─" * 56 + "\n", "sep")
        self._out("  PHASE 4 — AI TRIAGE & REPORT  (streaming)\n", "section")
        self._out("─" * 56 + "\n\n", "sep")
        self._status("AIが結果をトリアージ中 ...")
        summary = self._build_summary(base_url, points, anomalies, idor_findings)
        full = self._stream_llm([
            self.llm.system(_TRIAGE_SYS),
            self.llm.user(f"Triage these authorized fuzzing results:\n\n{summary}"),
        ])

        # 品質エフォート: STRONGモデルで所見を再検証し誤検知を削減する。
        effort = self._effort()
        if effort.get("verify_pass") and not self.is_stopped():
            full = self._verify_findings(summary, full, samples=effort.get("verify_samples", 1))
        self._step(5, "done")

        # 調査レポートをファイルに保存する。
        body = f"## Fuzzing Summary\n```\n{summary}\n```\n\n## AI Triage\n{full}\n"
        self._save_investigation("WEB FUZZ", base_url, body)

        # ── Step 6: 完了 ───────────────────────────────────
        parsed, counts = _findings_and_counts("WEB FUZZ", full)
        findings = self._to_findings(parsed, corroborated=bool(effort.get("verify_pass")))
        coverage = self._build_coverage(points, auth, auth_b, idor_ran, idor_skip_reason_val)
        state, errors = self._determine_state(
            fuzzer, triage_ran=True, triage_text=full,
            had_signals=bool(anomalies or idor_findings),
        )
        self._finish(sum(counts.values()), counts, target=base_url, t0=t0,
                    findings=findings, coverage=coverage, state=state, errors=errors)

    # ── 構造化所見・実行状態(P1.1) ─────────────────────────
    @staticmethod
    def _to_findings(parsed: list[dict], corroborated: bool) -> list[Finding]:
        """AIトリアージのマーカー出力(report_generator._findings_and_counts)から
        Findingを構築する。verification_stateは、品質エフォートの検証パスを通過した
        所見のみ"corroborated"とし、アンサンブル少数意見(ENSEMBLE_MINORITY)や
        検証パス無しの場合は"observed"のままとする（LLMの同意だけで昇格させない）。
        """
        out = []
        for f in parsed:
            is_minority = f.get("confidence") == "ENSEMBLE_MINORITY"
            vstate = (VerificationState.CORROBORATED.value if (corroborated and not is_minority)
                      else VerificationState.OBSERVED.value)
            out.append(Finding(
                finding_id=new_id("finding"),
                rule_id=f.get("ref") or "UNSPECIFIED",
                location=f.get("lines") or "",
                severity=(f.get("severity") or "LOW").upper(),
                verification_state=vstate,
                description=f.get("name") or "",
                remediation=f.get("fix") or "",
                verifier_support={"ensemble_minority": True} if is_minority else {},
            ))
        return out

    @staticmethod
    def _build_coverage(points: list[dict], auth: dict | None, auth_b: dict | None,
                        idor_ran: bool, idor_skip_reason_val: str | None) -> list[CoverageItem]:
        """検査対象(endpoint/parameter)・IDORチェックの実施状況をCoverageItemへ変換する。

        現状の粒度: 注入点ごとに「検査した」ことは記録するが、カテゴリ(SQLI/XSS等)別・
        個々のプローブ別のtested/skipped/failedまでは追跡していない（今後の課題。
        予算切れで一部プローブしか送れなかった場合も、その注入点は"tested"のまま
        記録される — 全プローブ完遂の保証ではない点はScanResult.errorsで別途示す）。
        """
        auth_ctx = "authenticated" if auth else "anonymous"
        coverage = [
            CoverageItem(target_ref=p["url"], parameter=p["param"], rule_id="WEB_FUZZ_PROBE",
                        status=CoverageStatus.TESTED.value, auth_context=auth_ctx)
            for p in points
        ]
        if auth_b:
            if idor_ran:
                coverage.append(CoverageItem(
                    target_ref="(access-control-check)", rule_id="IDOR",
                    status=CoverageStatus.TESTED.value, auth_context="session_b",
                ))
            else:
                coverage.append(CoverageItem(
                    target_ref="(access-control-check)", rule_id="IDOR",
                    status=CoverageStatus.SKIPPED.value, auth_context="session_b",
                    reason=idor_skip_reason_val or "",
                ))
        return coverage

    def _determine_state(self, fuzzer: WebFuzzer, *, triage_ran: bool, triage_text: str,
                         had_signals: bool) -> tuple[str, list[str]]:
        """実行状態(completed/partial/failed/cancelled)を判定する（P1.1）。

        completedは「指定した検査範囲について完了した」意味であり、対象に脆弱性が
        無い保証ではない。予算切れやAIトリアージの空応答は、検査の実績に応じて
        partialとする（検出0件の成功とは区別する）。
        """
        errors: list[str] = []
        if self.is_stopped():
            return ScanState.CANCELLED.value, errors
        budget_exhausted = fuzzer.transport.req_count >= fuzzer.max_requests
        if budget_exhausted:
            errors.append("リクエスト予算切れのため一部の検査が未実施の可能性があります")
        if triage_ran and had_signals and not triage_text.strip():
            errors.append("AIトリアージが空応答でした（LLM呼び出し失敗の可能性）")
            return ScanState.PARTIAL.value, errors
        if budget_exhausted:
            return ScanState.PARTIAL.value, errors
        return ScanState.COMPLETED.value, errors

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
    def _build_summary(base_url, points, anomalies, idor_findings: list[dict] | None = None) -> str:
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
        idor_findings = idor_findings or []
        if idor_findings:
            lines.append(f"\nACCESS CONTROL CHECK (2nd session, GET-only) — {len(idor_findings)} signal(s):")
            for f in idor_findings:
                lines.append(f"  - param={f['param']} url={f['url']} evidence={f['evidence']}")
        return "\n".join(lines)

    # ── 完了処理 ───────────────────────────────────────────
    def _finish(self, total: int, counts: dict | None = None,
                target: str = "", t0: float | None = None,
                findings: list[Finding] | None = None,
                coverage: list[CoverageItem] | None = None,
                state: str = ScanState.COMPLETED.value,
                errors: list[str] | None = None) -> None:
        self._step(6, "running")
        if counts:
            self._stats(counts)
        if t0 is not None:
            self._record_telemetry("WEB FUZZ", target, counts or {}, time.time() - t0)
        self._out("\n\n" + "═" * 56 + "\n", "sep")
        self._out(f"  FUZZING COMPLETE  |  {total} findings reported\n", "green")
        self._out("═" * 56 + "\n", "sep")
        self._step(6, "done")
        self._status(f"ファジング完了 — {total} findings")
        self._finalize(state=state, errors=errors, findings=findings, coverage=coverage,
                       mode="WEB FUZZ", target=target)
