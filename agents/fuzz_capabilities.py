"""
agents/fuzz_capabilities.py — WEB FUZZ を capability + Policy Gate + Run Journal で実行する新経路

設計: docs/AUTONOMOUS_PHASE_A_DESIGN.md §2 / §11。既存の FuzzAgent / WebFuzzer のメソッドを**呼ぶだけ**の
薄い層で、既存経路(FuzzAgent.run)は変更しない。LLMによる計画は無く、固定の計画を ScriptedRunner が実行する。

現行経路との意図的な差(docs §11、tools/test_fuzz_autonomy.py で固定):
  - POST注入点は送信しない(T3は個別承認が必要)。coverage に skipped(post_requires_approval) で残し、
    実行状態は partial にする(未検査を completed にしない)。
  - coverage は検査単位(注入点×カテゴリ)の実績(WebFuzzer.fuzz_log)に基づく。予算切れで未実施の
    ものを tested にしない。
  - 許可対象(allowed_targets)の明示が必須(空は Gate が拒否)。config.json の scope 設定には依存しない。
  - 認証(web.authenticate)は T3: 役割(a/b)ごとに引数ハッシュへ結び付いた ApprovalGrant が無ければ実行せず、
    認証情報は一切セッションへ適用されない(承認が無い認証付き実行は crawl も行わず failed)。
  - IDOR比較(web.idor_compare)は T2: run() の permit_t2=True を明示した場合のみ実行する。

送信は WebFuzzer(=HttpTransport)だけが行い、本モジュールは requests / socket を直接呼ばない。
"""

from __future__ import annotations
import time

import core.config as config
from agents.fuzz_agent import FuzzAgent, _TRIAGE_SYS, idor_skip_reason
from core import redaction
from core.autonomy.actions import (
    Action, ActionResult, CapabilityRegistry, CapabilitySpec, SideEffect,
)
from core.autonomy.budget import BudgetLedger, LLMGate
from core.autonomy.journal import JOURNAL_ROOT, JournalError, RunJournal, new_run_id
from core.autonomy.policy_gate import EngagementPolicy, PolicyGate
from core.autonomy.runner import PlanTask, ScriptedRunner
from core.autonomy.task_graph import TaskState
from core.evidence_store import EvidenceStore
from core.findings import CoverageItem, CoverageStatus, ScanState
from core.settings import DEFAULT_SCAN_PROFILE, SCAN_PROFILES
from tools.report_generator import _findings_and_counts
from tools.web_fuzzer import DEFAULT_PROBES, WebFuzzer

T0, T1, T2, T3 = (SideEffect.T0_LOCAL, SideEffect.T1_OBSERVE, SideEffect.T2_DIFFERENTIAL,
                  SideEffect.T3_NEEDS_APPROVAL)
_URL = {"url": {"type": "str", "required": True}}
_AUTH_ARGS = {"url": {"type": "str", "required": True}, "role": {"type": "str", "required": True},
              "auth_ref": {"type": "str", "required": True}}


def normalize_base_url(target: str) -> str:
    return target if target.startswith("http") else "http://" + target


def auth_action_args(target: str, role: str) -> dict:
    """web.authenticate の引数。ApprovalGrant はこの引数のハッシュに結び付けて発行する
    (`new_grant("web.authenticate", auth_action_args(target, "a"), expires_at=...)`)。
    認証情報そのものは含めない(参照名のみ)。role は "a"(主セッション)または "b"(第2セッション)。"""
    if role not in ("a", "b"):
        raise ValueError("role は 'a' または 'b' です")
    return {"url": normalize_base_url(target), "role": role, "auth_ref": f"auth_{role}"}


def build_registry(max_requests: int, triage_llm_calls: int) -> CapabilityRegistry:
    r = CapabilityRegistry()
    r.register(CapabilitySpec("web.crawl", T1, args_schema=dict(_URL), target_arg="url",
                              max_requests=max_requests))
    # 認証情報をセッションへ適用する(ログインPOSTや確認URLへの送信を含み得る)ためT3。承認が無ければ実行しない。
    r.register(CapabilitySpec("web.authenticate", T3, mutating=True, args_schema=dict(_AUTH_ARGS),
                              target_arg="url", max_requests=3))
    r.register(CapabilitySpec("llm.gen_probes", T0, uses_llm="fast", llm_calls=1))
    r.register(CapabilitySpec("web.fuzz_get_points", T1, args_schema=dict(_URL), target_arg="url",
                              max_requests=max_requests))
    # 第2セッションとの読取り(GET)比較。副作用がない保証ではないためプロファイルでの明示許可が必要(T2)。
    r.register(CapabilitySpec("web.idor_compare", T2, args_schema=dict(_URL), target_arg="url",
                              max_requests=max_requests))
    # POST注入点への送信は状態を変え得るためT3。Phase Aでは登録のみで実行しない(設計 §11.1)。
    r.register(CapabilitySpec("web.fuzz_post_points", T3, mutating=True, enabled=False,
                              args_schema=dict(_URL), target_arg="url", max_requests=max_requests))
    r.register(CapabilitySpec("evidence.save", T0))
    r.register(CapabilitySpec("llm.triage", T0, uses_llm="strong", llm_calls=triage_llm_calls))
    return r


class _Ctx:
    """1回の実行で各capabilityが受け渡すローカル状態(対象由来の生テキストはプロンプト以外に出さない)。"""
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.points: list[dict] = []
        self.pages = 0
        self.probes: dict[str, list[str]] = {}
        self.anomalies: list[dict] = []
        self.idor_findings: list[dict] = []
        self.idor_ran = False
        self.idor_skip_reason: str | None = None
        self.known_evidence_ids: set[str] = set()
        self.evidence_errors: list[str] = []
        self.summary = ""
        self.full = ""


class AutonomousFuzzAgent(FuzzAgent):
    """FuzzAgent の新経路。run() だけを差し替え、LLM/証拠/所見変換の既存ヘルパーを再利用する。"""

    last_run_id: str | None = None

    def run(self, target: str, profile: str = DEFAULT_SCAN_PROFILE, max_requests: int = 200,
            max_pages: int = 20, allowed_targets: list[str] | None = None,
            journal_root: str = JOURNAL_ROOT, max_llm_calls: int | None = None,
            auth: dict | None = None, auth_b: dict | None = None,
            tls_verify: bool | None = None, tls_ca_bundle: str | None = None,
            approvals: list | None = None, permit_t2: bool = False) -> None:
        self._current_mode, self._current_target = "WEB FUZZ", target
        scan_id = self._begin_scan()
        self.bus.clear()
        t0 = time.time()
        if auth_b and not auth:
            self._finalize(state=ScanState.FAILED.value, target=target, errors=[
                "第2セッション(auth_b)は主セッション(auth)と併せて指定してください"])
            return
        if profile not in SCAN_PROFILES:
            profile = DEFAULT_SCAN_PROFILE
        base_url = normalize_base_url(target)
        known_secrets = self._known_secrets(auth, auth_b)
        mask = lambda t: redaction.mask_log_line(str(t), known_secrets)  # noqa: E731

        fuzzer = WebFuzzer(
            profile=profile, max_pages=max_pages, max_requests=max_requests,
            log=lambda m: self._log(mask(m)), auth=auth, auth_b=auth_b, target=base_url,
            stop_event=self._stop_event, tls_verify=tls_verify, tls_ca_bundle=tls_ca_bundle,
        )
        try:
            journal = RunJournal(new_run_id(), journal_root, known_secrets=known_secrets)
        except (JournalError, OSError) as e:
            self._finalize(state=ScanState.FAILED.value, target=base_url,
                           errors=[f"監査記録(Run Journal)を開始できません: {e}"])
            return
        self.last_run_id = journal.run_id

        effort = self._effort()
        verify_samples = effort.get("verify_samples", 1) if effort.get("verify_pass") else 0
        ledger = BudgetLedger(max_requests=max_requests, request_counter=lambda: fuzzer._req_count,
                              max_llm_calls=max_llm_calls)
        self._llm_gate = LLMGate(ledger)
        registry = build_registry(max_requests, 1 + verify_samples)
        effects = {T0, T1} | ({T2} if permit_t2 else set())
        policy = EngagementPolicy(base_origin=base_url, allowed_targets=list(allowed_targets or []),
                                  allowed_side_effects=frozenset(effects))
        gate = PolicyGate(registry, policy, ledger, journal, grants=list(approvals or []))
        ctx = _Ctx(base_url)
        save_evidence = bool(config.get("save_evidence", False))

        executors = {
            "web.authenticate": lambda a: self._cap_auth(a, fuzzer, mask),
            "web.idor_compare": lambda a: self._cap_idor(a, ctx, fuzzer, mask),
            "web.crawl": lambda a: self._cap_crawl(a, ctx, fuzzer, mask),
            "llm.gen_probes": lambda a: self._cap_gen_probes(a, ctx),
            "web.fuzz_get_points": lambda a: self._cap_fuzz(a, ctx, fuzzer, mask),
            "evidence.save": lambda a: self._cap_evidence(a, ctx, scan_id, known_secrets),
            "llm.triage": lambda a: self._cap_triage(a, ctx, base_url, mask, effort),
        }
        plan: list[PlanTask] = []
        if auth:
            plan.append(PlanTask("auth_a", "web.authenticate", auth_action_args(base_url, "a")))
        if auth_b:
            plan.append(PlanTask("auth_b", "web.authenticate", auth_action_args(base_url, "b")))
        plan += [PlanTask("crawl", "web.crawl", {"url": base_url}, ("auth_a",) if auth else ()),
                 PlanTask("probes", "llm.gen_probes", {}, ("crawl",)),
                 PlanTask("fuzz", "web.fuzz_get_points", {"url": base_url}, ("probes",))]
        last = "fuzz"
        if auth_b:
            plan.append(PlanTask("idor", "web.idor_compare", {"url": base_url},
                                 ("fuzz", "auth_a", "auth_b"), auth_context="session_b"))
            last = "idor"
        if save_evidence:
            plan.append(PlanTask("evidence", "evidence.save", {}, ("fuzz",)))
            last = "evidence"
        plan.append(PlanTask("triage", "llm.triage", {}, (last,)))

        runner = ScriptedRunner(gate=gate, journal=journal, registry=registry, executors=executors,
                                is_stopped=self.is_stopped, budget=ledger, plan=plan)
        finished = False
        try:
            outcome = runner.run(mode="WEB FUZZ", target=base_url, scan_id=scan_id)
            findings, counts, rejected = self._assemble_findings(ctx, effort)
            coverage = self._autonomy_coverage(ctx, fuzzer, outcome)
            state, errors = self._autonomy_state(ctx, fuzzer, outcome, rejected)
            audit_end_errors = runner.close_run(state=state, errors=errors)   # 通常Actionから独立した終了処理
            errors += audit_end_errors
            if audit_end_errors and state == ScanState.COMPLETED.value:
                state = ScanState.PARTIAL.value        # 監査記録が完結していない結果をcompletedにしない
            self._finish(sum(counts.values()), counts, target=base_url, t0=t0,
                         findings=findings, coverage=coverage, state=state, errors=errors)
            finished = True
        finally:
            if not finished:
                runner.close_run(state=ScanState.FAILED.value, errors=["内部エラーで中断しました"])
            journal.close()

    # ── capability 本体(既存メソッドを呼ぶだけ) ───────────────
    def _cap_auth(self, action: Action, fuzzer: WebFuzzer, mask) -> ActionResult:
        role = action.args["role"]
        ok, msg = fuzzer.authenticate() if role == "a" else fuzzer.authenticate_b()
        state, reason = ((fuzzer.auth_state, fuzzer.auth_state_reason) if role == "a"
                         else (fuzzer.auth_state_b, fuzzer.auth_state_reason_b))
        self._out(mask(f"  [AUTH-{role.upper()}] {msg}\n  [AUTH-{role.upper()}-STATE] {state} — {reason}\n"),
                  "green" if state == "authenticated" else "dim")
        # 認証状態(authenticated/unknown/expired)は要約に残す。理由文は対象由来になり得るため入れない。
        return ActionResult("done" if ok else "failed", {"role": role, "auth_state": state})

    def _cap_idor(self, action: Action, ctx: _Ctx, fuzzer: WebFuzzer, mask) -> ActionResult:
        reason = idor_skip_reason(fuzzer)
        if reason:
            ctx.idor_skip_reason = reason
            self._out(f"\n  (IDOR比較スキップ: {mask(reason)})\n", "high")
            return ActionResult("skipped", {"reason": "auth_expired"})
        self._status("認可チェック中（別セッション比較）...")
        ctx.idor_findings = fuzzer._detect_idor(ctx.points)
        ctx.idor_ran = True
        for f in ctx.idor_findings:
            self._out(mask(f"    [IDOR?] {f['param']}@{f['url']}\n"), "high")
        return ActionResult("done", {"signals": len(ctx.idor_findings)})

    def _cap_crawl(self, action: Action, ctx: _Ctx, fuzzer: WebFuzzer, mask) -> ActionResult:
        self._out("  PHASE 1 — CRAWL & INJECTION-POINT DISCOVERY\n", "section")
        self._status("クロール中 ...")
        crawl = fuzzer.crawl(ctx.base_url)
        ctx.points, ctx.pages = crawl["injection_points"], crawl["pages"]
        posts = sum(1 for p in ctx.points if p["method"] == "POST")
        self._out(f"\n  {ctx.pages} page(s) crawled, {len(ctx.points)} injection point(s) found "
                  f"({posts} POST: 送信しません)\n\n", "green")
        for ip in ctx.points[:40]:
            self._out(mask(f"    [{ip['method']:<4}] {ip['param']:<18} ({ip['where']})  {ip['url']}\n"), "code")
        if ctx.pages == 0:
            return ActionResult("failed", {"reason": "no_pages", "detail": fuzzer._transport_error_reason()})
        return ActionResult("done", {"pages": ctx.pages, "points": len(ctx.points),
                                     "post_points": posts})

    def _cap_gen_probes(self, action: Action, ctx: _Ctx) -> ActionResult:
        if not ctx.points:
            return ActionResult("skipped", {"reason": "no_injection_points"})
        self._status("AIが検出プローブを生成中 ...")
        ctx.probes = self._gen_probes(ctx.points)
        return ActionResult("done", {"categories": len(ctx.probes),
                                     "probes": sum(len(v) for v in ctx.probes.values())})

    def _cap_fuzz(self, action: Action, ctx: _Ctx, fuzzer: WebFuzzer, mask) -> ActionResult:
        get_points = [p for p in ctx.points if p["method"] == "GET"]
        if not get_points:
            return ActionResult("skipped", {"reason": "no_get_points"})
        self._out("  PHASE 3 — FUZZING (DETECTION ONLY, GET only)\n", "section")
        self._status("ファジング実行中 ...")
        ctx.anomalies = fuzzer.fuzz(get_points, ctx.probes)
        units = fuzzer.fuzz_log
        for a in ctx.anomalies:
            self._out(mask(f"    [{a['category']}] {a['param']}@{a['url']}\n"),
                      a["severity"].lower() if a["severity"] != "CRITICAL" else "critical")
        unfinished = [u for u in units if u["status"] != "completed"]
        summary = {"anomalies": len(ctx.anomalies), "units": len(units), "units_unfinished": len(unfinished)}
        if any(u["reason"] == "stopped" for u in unfinished):
            return ActionResult("skipped", dict(summary, reason="stopped"))
        if any(u["status"] in ("exhausted", "not_started") for u in unfinished):
            return ActionResult("exhausted", summary)
        return ActionResult("done", summary)

    def _cap_evidence(self, action: Action, ctx: _Ctx, scan_id: str, known_secrets: set[str]) -> ActionResult:
        ctx.known_evidence_ids, ctx.evidence_errors = self._save_evidence(
            EvidenceStore(scan_id), ctx.anomalies, ctx.idor_findings, known_secrets,
            action_id=action.action_id)
        return ActionResult("done", {"saved": len(ctx.known_evidence_ids),
                                     "errors": len(ctx.evidence_errors)},
                            evidence_ids=sorted(ctx.known_evidence_ids))

    def _cap_triage(self, action: Action, ctx: _Ctx, base_url: str, mask, effort: dict) -> ActionResult:
        self._out("  PHASE 4 — AI TRIAGE & REPORT  (streaming)\n", "section")
        self._status("AIが結果をトリアージ中 ...")
        ctx.summary = mask(self._build_summary(base_url, ctx.points, ctx.anomalies, ctx.idor_findings))
        full = self._stream_llm([
            self.llm.system(_TRIAGE_SYS),
            self.llm.user(f"Triage these authorized fuzzing results:\n\n{ctx.summary}"),
        ])
        if effort.get("verify_pass") and not self.is_stopped():
            full = self._verify_findings(ctx.summary, full, samples=effort.get("verify_samples", 1))
        ctx.full = full
        self._save_investigation("WEB FUZZ", base_url,
                                 f"## Fuzzing Summary\n```\n{ctx.summary}\n```\n\n## AI Triage\n{full}\n")
        return ActionResult("done", {"triage_chars": len(full)})

    # ── 最終結果の組み立て(終了処理の一部) ─────────────────
    def _assemble_findings(self, ctx: _Ctx, effort: dict):
        if not ctx.full:
            return [], {}, []
        parsed, counts = _findings_and_counts("WEB FUZZ", ctx.full)
        rejected: list[str] = []
        findings = self._findings_from_markers(
            parsed, corroborated=bool(effort.get("verify_pass")),
            known_evidence_ids=ctx.known_evidence_ids or None, rejected_evidence_ids=rejected)
        return findings, counts, rejected

    def _autonomy_coverage(self, ctx: _Ctx, fuzzer: WebFuzzer, outcome) -> list[CoverageItem]:
        """検査単位(注入点×カテゴリ)の実績に基づく。未実施・未承認を tested にしない。"""
        cats = list((ctx.probes or DEFAULT_PROBES).keys())
        log = {(u["url"], u["method"], u["param"], u["category"]): u for u in fuzzer.fuzz_log}
        fuzz_rec = outcome.tasks.get("fuzz")
        not_run = (fuzz_rec.reason if fuzz_rec and fuzz_rec.reason else "not_run")
        auth_ctx = fuzzer.auth_state if fuzzer.auth else "anonymous"   # 実際の認証状態(未確認を authenticated と書かない)
        items: list[CoverageItem] = []
        for p in ctx.points:
            for cat in cats:
                base = dict(target_ref=p["url"], parameter=p["param"], rule_id=f"WEB_FUZZ_{cat}",
                            auth_context=auth_ctx)
                if p["method"] == "POST":
                    items.append(CoverageItem(status=CoverageStatus.SKIPPED.value,
                                              reason="post_requires_approval", **base))
                    continue
                u = log.get((p["url"], p["method"], p["param"], cat))
                if u is None:
                    items.append(CoverageItem(status=CoverageStatus.SKIPPED.value, reason=not_run, **base))
                elif u["status"] == "completed":
                    items.append(CoverageItem(status=CoverageStatus.TESTED.value, reason=u["reason"], **base))
                elif u["status"] == "transport_error":
                    items.append(CoverageItem(status=CoverageStatus.FAILED.value, reason=u["reason"], **base))
                else:
                    items.append(CoverageItem(
                        status=CoverageStatus.SKIPPED.value,
                        reason=f"{u['status']}:{u['reason']} ({u['attempted']}/{u['planned']})", **base))
        if fuzzer.auth_b:
            idor = outcome.tasks.get("idor")
            if idor is not None and idor.state == TaskState.DONE:
                items.append(CoverageItem(target_ref="(access-control-check)", rule_id="IDOR",
                                          status=CoverageStatus.TESTED.value, auth_context="session_b"))
            else:
                why = (ctx.idor_skip_reason or (idor.reason if idor else "") or "not_run")
                items.append(CoverageItem(target_ref="(access-control-check)", rule_id="IDOR",
                                          status=CoverageStatus.SKIPPED.value, auth_context="session_b",
                                          reason=why))
        return items

    def _autonomy_state(self, ctx: _Ctx, fuzzer: WebFuzzer, outcome, rejected: list[str]):
        errors = list(outcome.errors) + ctx.evidence_errors + rejected
        errors += [f"LLM呼出を予算により拒否: {r}" for r in self._llm_denials]
        if self.is_stopped():
            return ScanState.CANCELLED.value, errors
        done = {k for k, r in outcome.tasks.items() if r.state == TaskState.DONE}
        if outcome.audit_failed:
            return (ScanState.PARTIAL.value if done else ScanState.FAILED.value), errors
        if "crawl" not in done:
            return ScanState.FAILED.value, errors
        auth_gaps = [t for t in ("auth_a", "auth_b") if t in outcome.tasks and t not in done]
        if fuzzer.auth and fuzzer.auth_state != "authenticated":
            auth_gaps.append("auth_a_state")
            errors.append(f"主セッションの認証状態が{fuzzer.auth_state}です({fuzzer.auth_state_reason})")
        if fuzzer.auth_b and "auth_b" in done and fuzzer.auth_state_b != "authenticated":
            auth_gaps.append("auth_b_state")
            errors.append(f"第2セッションの認証状態が{fuzzer.auth_state_b}です({fuzzer.auth_state_reason_b})")
        if not ctx.points:                                   # 現行経路と同じ: 注入点なしは完了
            return (ScanState.PARTIAL.value if auth_gaps else ScanState.COMPLETED.value), errors
        posts = sum(1 for p in ctx.points if p["method"] == "POST")
        if posts:
            errors.append(f"POST注入点{posts}件は個別承認が無いため未検査です")
        unfinished = [u for u in fuzzer.fuzz_log if u["status"] != "completed"]
        if unfinished:
            errors.append(f"検査単位{len(unfinished)}件が未完了です(予算切れ・中断・通信失敗)")
        if ctx.anomalies and ctx.full is not None and not ctx.full.strip() and "triage" in done:
            errors.append("AIトリアージが空応答でした（LLM呼び出し失敗の可能性）")
        incomplete = (posts or unfinished or auth_gaps or any(
            t not in done for t in outcome.tasks) or (ctx.anomalies and not ctx.full.strip())
            or self._llm_denials)
        return (ScanState.PARTIAL.value if incomplete else ScanState.COMPLETED.value), errors
