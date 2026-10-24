"""
core/autonomy/research_loop.py — 自律調査ループの実行（Stage 1）

既存の ScriptedRunner / PolicyGate / RunJournal / BudgetLedger / HttpTransport / EvidenceStore / Finding を再利用し、
人間が案件ファイルに書いていた研究判断（仮説・対照・期待値・次の調査対象）を research_planner / research_hypothesis に移した版。

安全:
  - 実行できるのは仕様にある読取りGET（research.get_anon=T1 / research.get_authed=T2）だけ。URL・ロール・パスパラメータは
    決定論的に検証し、観測していないIDや仕様外のパスは送信しない。Gate（スコープ・副作用・予算・重複）→HttpTransport（同一origin・予算）を通る。
  - LLMは使わない（max_llm_calls=0）。対象の応答本文はジャーナル・結果へ入れない（項目名・ステータス・マスク済み証拠の参照だけ）。
  - 認証情報は参照名（cred:*）だけが記録に出る。tokenは実行時にヘッダーへ入れ、既知の機密値としてマスク対象に登録する。
  - 状態を変える操作の部品は無い。仕様にあれば『検証不能（必要な能力つき）』として残す。
  - 再開できる（resume_run_id）。動的に追加した実験もRunStoreに保存し、判定に必要な項目だけのダイジェストを結果として保存する（本文は保存しない）。
設計: docs/AUTONOMOUS_DISCOVERY_STAGE1.md
"""
from __future__ import annotations
import re
import time
from dataclasses import dataclass, field
from typing import Callable

from core import redaction
from core.autonomy.actions import Action, ActionResult, CapabilityRegistry, CapabilitySpec, SideEffect
from core.autonomy.budget import BudgetLedger
from core.autonomy.journal import JOURNAL_ROOT, JournalError, RunJournal, new_run_id
from core.autonomy.policy_gate import EngagementPolicy, PolicyGate
from core.autonomy.research_case import BlindCase
from core.autonomy.research_hypothesis import (
    CONFORMS, DEVIATES, RULE_ID, SEVERITY_ESTIMATE, S_NOT_EXAMINED, S_REFUTED, S_SUPPORTED, S_UNDETERMINED,
    S_UNVERIFIABLE, S_UNVERIFIED, control_state, evaluate_check,
)
from core.autonomy.research_model import ExpResult, digest_json, retained_keys, safe_json
from core.autonomy.research_planner import CAP_ANON, CAP_AUTHED, CONFIRM_MAX_PER_RUN, Researcher, default_dedup
from core.autonomy.journal import replay
from core.autonomy.resume import ResumeError, profile_hash, reconcile
from core.autonomy.run_store import RunStore, RunStoreError
from core.autonomy.runner import ENGINE_VERSION, PlanTask, ScriptedRunner
from core.autonomy.task_graph import TaskState
from core.evidence_store import EvidenceStore
from core.findings import (
    CoverageItem, CoverageStatus, Finding, ScanState, VerificationState, new_id, new_scan_result,
)
from core.http_transport import HttpTransport, RequestPolicy, new_session

RESEARCH_ENGINE_VERSION = "research-stage1/6"   # /2: 再開に必要な記録を追加（/1のRunは再開不可）。/3: 重複確認の後回し（OP_SUPPORTED 0.1）で実験の選択順が変わった（/2のRunは再開不可）。/4: list_scopeの具体化（共有先の項目を必須にしない）と判定（情報不足を逸脱にしない）、重複抑制(dedup)の指定。/3のRunは再開不可。/5: 観測後の仮説は登録後の新しい確認実験（実験IDにtag）で検証する・一覧の閲覧条件を操作単位(visible_to)で定義・LLM呼出しの予約をジャーナルに残し再開で巻き戻さない（/4のRunは再開不可。tagの無い実験の実験ID・予測ハッシュは/4と同じ）。/6: 出力上限で切れたLLM返答から完全な提案を救済・空の一覧は棄却でなく判定不能（/5のRunは再開不可）
_ARGS = {"url": {"type": "str", "required": True}, "exp_id": {"type": "str", "required": True},
         "op_id": {"type": "str", "required": True}, "role": {"type": "str", "required": True},
         "path_params": {"type": "dict"}}
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_]{1,40}$")
REMEDIATION = {
    "object_authz": "オブジェクトごとに所有者/共有先を検査してから返す",
    "function_authz": "操作単位でロールを検査する（管理者専用機能はサーバー側で強制）",
    "unauth_access": "認証を必須にする",
    "field_exposure": "応答項目を許可リストで制限する",
    "list_scope": "一覧を呼出し者の所有/共有でサーバー側で絞る（管理者を含め例外を作らない）",
}


def build_registry() -> CapabilityRegistry:
    r = CapabilityRegistry()
    r.register(CapabilitySpec(CAP_ANON, SideEffect.T1_OBSERVE, args_schema=dict(_ARGS), target_arg="url", max_requests=1))
    r.register(CapabilitySpec(CAP_AUTHED, SideEffect.T2_DIFFERENTIAL, args_schema=dict(_ARGS), target_arg="url", max_requests=1))
    return r


@dataclass
class ResearchRunResult:
    case_id: str
    run_id: str
    scan_id: str
    state: str
    end_reason: str
    finish_reason: str
    clean_finish: bool
    resumable: bool = False
    model: dict = field(default_factory=dict)
    hypotheses: list = field(default_factory=list)
    rejected: list = field(default_factory=list)
    experiments: list = field(default_factory=list)
    decision_log: list = field(default_factory=list)
    findings: list = field(default_factory=list)          # supported（根拠付き）だけ
    candidates: list = field(default_factory=list)        # 逸脱は観測したが確定できない（対照未実施・期待値が推定 等）
    refuted: list = field(default_factory=list)
    undetermined: list = field(default_factory=list)
    unverifiable: list = field(default_factory=list)      # 検証不能（必要な能力つき）
    not_examined: list = field(default_factory=list)
    unknowns: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    llm: dict = field(default_factory=dict)               # LLM提案の内訳・使用量（LLM未使用なら calls=0）
    resume: dict = field(default_factory=dict)            # 再開した場合の復元の記録（通常は空）
    errors: list = field(default_factory=list)
    counters: dict = field(default_factory=dict)
    budget: dict = field(default_factory=dict)
    versions: dict = field(default_factory=dict)
    scan_result: dict = field(default_factory=dict)
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict:
        import json
        return json.loads(json.dumps(self.__dict__, ensure_ascii=False, default=str))


def _failed_result(case, sr, msg: str, run_id: str = "") -> "ResearchRunResult":
    sr.state, sr.errors = ScanState.FAILED.value, [msg]
    return ResearchRunResult(case.case_id, run_id, sr.scan_id, ScanState.FAILED.value, "error", "start_failed", False,
                             errors=[msg], scan_result=sr.to_dict())


def run_research_case(case: BlindCase, base_url: str, creds: dict[str, str], *, journal_root: str = JOURNAL_ROOT,
                      evidence_root: str | None = None, is_stopped: Callable[[], bool] | None = None,
                      budget_override: dict | None = None, clock=time.monotonic,
                      fault_hook: Callable[[str, str], None] | None = None, llm=None,
                      llm_max_tokens: int = 800, resume_run_id: str | None = None, strategy: str = "adaptive",
                      dedup: bool | None = None, prompt_version: str = "research-propose/1") -> ResearchRunResult:
    """1案件を1回、自律調査する。creds は `cred:<名前>` -> token（実行時にヘッダーへ入れるだけで記録しない）。
    llm（任意）: complete(messages, max_tokens, usage_out) を持つ提案役。使うには予算 max_llm_calls>0 が必要（0なら呼ばない）。
    strategy（任意）: 実験の選び方。adaptive(既定)／static(再計画しない)／checklist(仕様順の固定探索)。後の2つは比較実験用で、再開に対応しない。
    dedup（任意）: 重複抑制（支持済みと同じ欠陥の確認を後回しにする）。None=方式の既定（adaptiveはON、staticはOFF）。再計画との切り分け実験用。
    resume_run_id（任意）: 中断したRunを再開する。完了済みの実験は再送せず、結果不明の実験は自動で再実行しない
    （関連する仮説は判定不能）。予算は巻き戻さない。案件・対象・予算・版が開始時と違えば拒否する。時間予算は再開時に数え直す。"""
    t_start = time.time()
    stopped = is_stopped or (lambda: False)
    budget = {**case.budget, **(budget_override or {})}
    known_secrets = {v for v in creds.values() if v}
    registry = build_registry()
    effects = {SideEffect.T0_LOCAL} | {SideEffect(s) for s in case.side_effects}
    phash = profile_hash({"mode": "RESEARCH", "case": case.public_dict(), "base_url": base_url, "budget": budget,
                          "engine": ENGINE_VERSION, "research_engine": RESEARCH_ENGINE_VERSION, "strategy": strategy,
                          **({"dedup": bool(dedup)} if dedup is not None and bool(dedup) != default_dedup(strategy) else {}),
                          **({"prompt_version": prompt_version} if prompt_version != "research-propose/1" else {})})
    sr = new_scan_result("LAB", case.case_id, engagement_id=case.case_id)
    counters = {"gate_denied": 0, "budget_denied": 0, "experiments_failed": 0, "resumed": bool(resume_run_id), "prior_requests": 0}
    resuming = resume_run_id is not None
    if strategy != "adaptive" and resuming:
        return _failed_result(case, sr, "比較用の方式（static/checklist）は再開に対応しません", resume_run_id)
    journal = store = None
    prior = 0
    resume_notes: dict = {}
    try:
        journal = RunJournal(resume_run_id or new_run_id(), journal_root, known_secrets=known_secrets)
        store = RunStore(journal.run_id, journal_root, must_exist=resuming)
        if resuming:
            if store.get_meta("profile_hash") != phash:
                raise ResumeError("プロファイル(案件・対象・予算・版)が開始時と異なるため再開しません")
            sr.scan_id = store.get_meta("scan_id") or sr.scan_id
            report = reconcile(journal, store)
            prior = store.requests_consumed(0)
            for row in store.tasks().values():        # 結果不明は1リクエスト消費済みとみなす（巻き戻さない）
                if row["state"] in ("unknown_outcome", "running") or row["consumption_unknown"]:
                    prior += 1
            journal.append("run_resumed", profile_hash=phash, prior_requests=prior, notes=report.notes,
                           unknown_tasks=report.unknown_tasks)
            counters["prior_requests"] = prior
    except (ResumeError, JournalError, RunStoreError, OSError, ValueError) as e:
        for o in (store, journal):
            if o is not None:
                try:
                    o.close()
                except Exception:   # noqa: BLE001
                    pass
        return _failed_result(case, sr, f"{'再開' if resuming else '監査記録の開始'}に失敗しました: {e}", resume_run_id or "")
    max_req = int(budget["max_requests"])
    transport = HttpTransport(policy=RequestPolicy(max_requests=max(0, max_req - prior), timeout=5))
    transport.bind_origin(base_url)
    ledger = BudgetLedger(max_requests=max_req, request_counter=lambda: prior + transport.req_count,
                          deadline_seconds=float(budget["max_seconds"]), max_llm_calls=int(budget.get("max_llm_calls", 0)),
                          max_llm_input_chars=int(budget.get("max_llm_input_chars", 8000)), clock=clock)
    gate = PolicyGate(registry, EngagementPolicy(base_origin=base_url, allowed_targets=list(case.allowed_hosts),
                                                 allowed_side_effects=frozenset(effects)), ledger, journal, store=store)
    evidence = EvidenceStore(sr.scan_id, **({"root": evidence_root} if evidence_root else {}))
    researcher = Researcher(case, base_url, journal, ledger, stopped,
                            llm=llm if int(budget.get("max_llm_calls", 0)) > 0 else None, llm_max_tokens=llm_max_tokens,
                            strategy=strategy, dedup=dedup, prompt_version=prompt_version)
    researcher.fault_hook = fault_hook
    mask = lambda s: redaction.mask_log_line(str(s), known_secrets)  # noqa: E731
    keep = retained_keys(case)
    plan: list = []
    if resuming:
        try:
            resume_notes = researcher.rehydrate(replay(journal.run_id, journal_root).events, store.tasks())
            ledger.restore_llm_calls(researcher.llm_reserved_total)         # 前回までに予約したLLM呼出しを引き継ぐ（巻き戻さない）
            have = {r["task_id"] for r in store.plan()}
            plan = [PlanTask(r["task_id"], r["capability"], r["args"], tuple(r["depends_on"]), r["auth_context"])
                    for r in store.plan()]
            rejected_exps = {r["exp_id"] for r in researcher.rejected if "exp_id" in r}
            for exp_id, exp in researcher.experiments.items():      # 計画したが、保存前に中断した実験は未実行として復元する
                if exp_id not in have and exp_id not in rejected_exps:
                    t = researcher._to_task(exp)
                    store.append_task({"task_id": t.task_id, "capability": t.capability, "args": t.args,
                                       "depends_on": t.depends_on, "auth_context": t.auth_context})
                    plan.append(t)
        except (ResumeError, RunStoreError, JournalError, KeyError, ValueError) as e:
            for o in (store, journal):
                try:
                    o.close()
                except Exception:   # noqa: BLE001
                    pass
            return _failed_result(case, sr, f"再開に失敗しました: {type(e).__name__}: {e}", journal.run_id)

    def execute(action: Action) -> ActionResult:
        exp = researcher.experiments.get(action.args.get("exp_id"))
        if exp is None:
            return ActionResult("failed", {"reason": "unknown_experiment"})
        op = case.operations[exp.op_id]
        from core.autonomy.research_hypothesis import validate_experiment
        expected = base_url.rstrip("/") + op.path_for(exp.params())
        if (action.args.get("url") != expected or action.args.get("role") != exp.role
                or (action.args.get("path_params") or {}) != exp.params() or validate_experiment(exp, researcher.model)):
            return ActionResult("failed", {"reason": "args_mismatch"})      # 登録・観測と違う引数は送信しない

        def fail(why: str, status: str = "failed") -> ActionResult:
            researcher.buffer[exp.exp_id] = ExpResult(exp.exp_id, None, reason=why)
            return ActionResult(status, {"reason": why}, outputs={"status_code": None, "reason": why, "digest": None,
                                                                  "body_complete": True, "incomplete_reason": None, "evidence_id": None})
        headers = {}
        if exp.role != "anonymous":
            token = creds.get(case.accounts[exp.role].ref)
            if not token:
                return fail("credential_unavailable")
            headers["Authorization"] = f"Bearer {token}"
        if fault_hook:
            fault_hook("before_send", exp.exp_id)
        resp = transport.request(new_session(), "GET", expected, headers=headers)
        if fault_hook:
            fault_hook("after_send", exp.exp_id)
        if resp is None:
            why = transport.last_error or "network_error"
            return fail(why, "exhausted" if why == "budget_exhausted" else "failed")
        body = resp.text or ""
        cut = getattr(resp, "fz_incomplete_reason", None) if getattr(resp, "fz_truncated", False) else None
        eid = evidence.save_http_evidence(method="GET", url=resp.request.url or expected, status=resp.status_code,
                                          headers=dict(resp.headers), body=body, known_secrets=known_secrets,
                                          action_id=action.action_id, source_incomplete=cut)
        dg = digest_json(safe_json(body), keep)       # 判定に必要な項目だけ。ライブも再開後も、この同じ入力で評価する
        researcher.buffer[exp.exp_id] = ExpResult(exp.exp_id, resp.status_code, json=dg, body_complete=cut is None,
                                                  incomplete_reason=cut, evidence_id=eid)
        return ActionResult("done", {"exp_id": exp.exp_id, "status_code": resp.status_code},
                            evidence_ids=[eid] if eid else [],
                            outputs={"status_code": resp.status_code, "digest": dg, "body_complete": cut is None,
                                     "incomplete_reason": cut, "evidence_id": eid, "reason": ""})

    runner = ScriptedRunner(gate=gate, journal=journal, registry=registry,
                            executors={CAP_ANON: execute, CAP_AUTHED: execute}, is_stopped=stopped, budget=ledger,
                            plan=plan, store=store, resumed=resuming, restore_cb=lambda t, row: None,
                            selector=researcher.select, on_idle=researcher.step)
    finished = False
    try:
        outcome = runner.run(mode="LAB", target=base_url, scan_id=sr.scan_id, profile_hash=phash)
        try:
            researcher._ingest_new()
            researcher._refresh_states()
            researcher.close_unexamined()
        except JournalError as e:
            outcome.errors.append(f"最終状態を記録できません: {e}")
            outcome.audit_failed = True
        denied = [r.reason for r in outcome.tasks.values()
                  if r.state in (TaskState.SKIPPED, TaskState.NEEDS_APPROVAL) and r.reason
                  and not r.reason.startswith(("stopped", "dependency", "session"))]
        counters["budget_denied"] = sum(1 for r in denied if r.startswith("budget."))
        counters["gate_denied"] = len(denied) - counters["budget_denied"]
        counters["experiments_failed"] = sum(1 for r in outcome.tasks.values() if r.state == TaskState.FAILED)
        result = _assemble(case, researcher, outcome, runner, sr, journal.run_id, counters, ledger, evidence, mask,
                           budget, phash)
        result.resume = dict(resume_notes) if resuming else {}
        if resuming and researcher.llm_unknown:
            result.errors.append(f"前回のLLM提案の結果が不明です（段階: {', '.join(researcher.llm_unknown)}。自動では再呼出ししません）")
            if result.state == ScanState.COMPLETED.value:
                result.state = ScanState.PARTIAL.value
        result.errors = [mask(e) for e in result.errors]
        end_errors = runner.close_run(state=result.state, errors=result.errors)
        if end_errors:
            result.errors += end_errors
            result.clean_finish = False
            if result.state == ScanState.COMPLETED.value:
                result.state = ScanState.PARTIAL.value
        finished = True
    finally:
        if not finished:
            runner.close_run(state=ScanState.FAILED.value, errors=["内部エラーで中断しました"])
        for o in (store, journal):
            try:
                o.close()
            except Exception:   # noqa: BLE001
                pass
    result.elapsed_seconds = round(time.time() - t_start, 3)
    return result


def _detail(h, res, model) -> list:
    """判定の補足（項目名・件数だけ。値や本文は含めない）。"""
    if res is None:
        return []
    return [str(f) for f in evaluate_check(h.check, res, model)[2] if re.match(r"^[A-Za-z0-9_= ]{1,60}$", str(f))]


def _count_by(xs: list) -> dict:
    out: dict = {}
    for x in xs:
        out[x or "unknown"] = out.get(x or "unknown", 0) + 1
    return out


def _confirmation(researcher, h, results) -> dict:
    """確定の証拠の出どころ。mode: confirm（観測後の仮説を、登録後の新しい確認実験で検証）／discovery_send_after_registration
    （登録後に計画された探索の送信が probe 結果になった）／probe（仮説のために計画した実験）。登録前の観測は prior_* に分けて残す
    （確定の証拠・evidence_complete には数えない）。"""
    pid = h.probe.exp_id if h.probe else None
    purpose = researcher.planned_purpose.get(pid, "") if pid else ""
    mode = "confirm" if h.prior_probe else ("discovery_send_after_registration" if purpose == "discovery" else "probe")
    prior = results.get(h.prior_probe) if h.prior_probe else None
    # confirm は『登録後に新しく送って検証した』の意味で、独立した再現確認ではない（同じ操作の再測定）。別の送信での再現は corroborating_sends に分けて出す
    return {"mode": mode, "meaning": "post_registration_verification" if mode == "confirm" else "post_registration_send",
            "independent_reproduction": False, "probe_planned_purpose": purpose, "registered_seq": h.registered_seq,
            "probe_planned_seq": researcher.planned_seq.get(pid) if pid else None,
            "registered_before_send": (researcher.planned_seq.get(pid) or 0) > h.registered_seq if pid in researcher.planned_seq else None,
            "prior_exp_id": h.prior_probe or None, "prior_control_exp_id": h.prior_control or None,
            "prior_evidence_id": prior.evidence_id if prior is not None else None, "confirm_blocked": h.confirm_blocked or None}


def _llm_summary(researcher, ledger, findings, candidates) -> dict:
    st = researcher.llm_stats
    new_ids = {d["hypothesis_id"] for d in st["details"] if d["status"] == "new" or d["status"] == "duplicate_of_llm"}
    llm_hyps = {h.hypothesis_id for h in researcher.hyps.values() if h.source == "llm"}
    return {"enabled": researcher.llm is not None, "prompt_version": researcher.prompt_version, "calls": st["calls"], "skipped": st["skipped"],
            "parse_failures": st["parse_failures"], "proposals": st["proposals"], "new_registered": st["new_registered"],
            "duplicate_of_rule": st["duplicate_of_rule"], "duplicate_of_llm": st["duplicate_of_llm"],
            "rejected": dict(st["rejected"]), "valid_proposal_rate": (round((st["new_registered"] + st["duplicate_of_rule"] + st["duplicate_of_llm"])
                                                                           / st["proposals"], 4) if st["proposals"] else None),
            "llm_hypotheses": sorted(llm_hyps), "llm_findings": sorted(f["hypothesis_id"] for f in findings if f["hypothesis_id"] in llm_hyps),
            "llm_candidates": sorted(c["hypothesis_id"] for c in candidates if c["hypothesis_id"] in llm_hyps),
            "salvaged_replies": st["salvaged_replies"], "salvaged_proposals": st["salvaged_proposals"],
            "unknown_outcome_phases": list(researcher.llm_unknown), "details": st["details"], "calls_detail": st["calls_detail"], "usage": st["usage"],
            "ledger": ledger.llm_usage_summary()}


def _assemble(case, researcher, outcome, runner, sr, run_id, counters, ledger, evidence, mask, budget, phash):
    model, results = researcher.model, researcher.model.results
    hyps_out, findings, candidates, refuted, undetermined, unverifiable, not_examined = [], [], [], [], [], [], []
    for hid, h in researcher.hyps.items():
        state, reason = researcher.states.get(hid, (S_NOT_EXAMINED, "not_selected"))
        probe_res = results.get(h.probe.exp_id) if h.probe else None
        ctl, ctl_why = control_state(h, results)
        op = case.operations[h.op_id]
        ev_probe = probe_res.evidence_id if probe_res else None
        ctl_res = results.get(h.control.exp_id) if (h.control and ctl in ("passed", "failed", "inconclusive")) else None
        ev_ctl = ctl_res.evidence_id if ctl_res else None
        rec = {
            "hypothesis_id": hid, "family": h.family, "op_id": h.op_id, "probe_role": h.probe_role, "object_id": h.object_id,
            "claim": h.claim, "basis": h.basis, "preconditions": h.preconditions, "grounded": h.grounded,
            "ungrounded_reason": h.ungrounded_reason, "prediction_if_true": h.prediction_if_true,
            "falsification": h.falsification, "prediction_sha": h.prediction_sha(), "registered_seq": h.registered_seq,
            "probe": h.probe.exp_id if h.probe else None, "control": h.control.exp_id if h.control else None,
            "probe_planned_seq": researcher.planned_seq.get(h.probe.exp_id) if h.probe else None,
            "probe_preexisting": h.probe_preexisting, "state": state, "reason": reason, "control_state": ctl,
            "control_reason": ctl_why or h.control_reason, "probe_status_code": probe_res.status_code if probe_res else None,
            "source": h.source, "llm_rationale": h.llm_rationale,
            "evidence_ids": [e for e in (ev_probe, ev_ctl) if e], "gap": h.gap,
            "probe_origin": researcher.planned_purpose.get(h.probe.exp_id) if h.probe else None,
            "confirmation": _confirmation(researcher, h, results)}
        hyps_out.append(rec)
        if state == S_SUPPORTED:
            ev_ids = [e for e in (ev_probe, ev_ctl) if e]
            need = 1 + (1 if (h.control_required and h.control is not None) else 0)
            extra = _detail(h, probe_res, model)
            f = Finding(
                finding_id=new_id("find"), rule_id=RULE_ID[h.family],
                location=f"{op.method} {op.path_for(h.probe.params())} [{h.op_id}] role={h.probe_role}",
                severity=SEVERITY_ESTIMATE[h.family],
                verification_state=(VerificationState.CORROBORATED if ctl == "passed" else VerificationState.OBSERVED).value,
                evidence_ids=ev_ids, description=h.claim, remediation=REMEDIATION.get(h.family, ""),
                analysis=(f"事前登録した予測({h.prediction_sha()})と一致: {h.prediction_if_true}。対照: {ctl}。"
                          + (f"仕様外の項目: {extra}。" if extra else "") + "深刻度は型からの見積りで、影響の測定ではない"))
            fd = f.to_dict()
            fd.update({"hypothesis_id": hid, "family": h.family, "op_id": h.op_id, "probe_exp": h.probe.exp_id,
                       "control_exp": h.control.exp_id if h.control else None, "control_state": ctl,
                       "basis": h.basis, "prediction_sha": h.prediction_sha(), "registered_seq": h.registered_seq,
                       "evidence_complete": len(ev_ids) == need, "evidence_missing": need - len(ev_ids),
                       "unexpected_fields": extra, "probe_origin": rec["probe_origin"], "confirmation": rec["confirmation"],
                       "repro": [f"{'未認証' if h.probe_role == 'anonymous' else h.probe_role + 'のセッション'}で "
                                 f"GET {op.path_for(h.probe.params())} を送り、事前登録した予測と一致するか確認する"
                                 + ("（観測後に作った仮説。登録後に新しく送る確認実験で検証済み。登録前の観測は証拠に数えない）" if h.prior_probe else "")]
                                + ([f"対照: {h.control.role}で同じ操作を送り、到達できることを確認する"] if h.control else [])})
            findings.append(fd)
            sr.findings.append(f)
        elif state == S_UNVERIFIED:
            candidates.append({"hypothesis_id": hid, "family": h.family, "op_id": h.op_id, "probe_role": h.probe_role,
                               "reason": reason, "control_state": ctl, "grounded": h.grounded,
                               "ungrounded_reason": h.ungrounded_reason, "evidence_ids": rec["evidence_ids"],
                               "note": "逸脱は観測したが確定していない（所見・台帳には入れない）",
                               **({"evidence_basis": "pre_registration_observation", "unconfirmed_because": researcher.finish_reason or "not_selected",
                                   "prior_evidence_ids": [results[h.prior_probe].evidence_id] if (h.prior_probe in results and results[h.prior_probe].evidence_id) else [],
                                   "note": "登録前の観測では逸脱を確認したが、登録後の確認実験が実行できなかったため確定していない（所見・台帳には入れない）"}
                                  if reason == "confirmation_not_run" else {})})
        elif state == S_REFUTED:
            refuted.append({"hypothesis_id": hid, "reason": reason, "evidence_ids": rec["evidence_ids"]})
        elif state == S_UNDETERMINED:
            undetermined.append({"hypothesis_id": hid, "reason": reason, "control_state": ctl})
        elif state == S_UNVERIFIABLE:
            unverifiable.append({"hypothesis_id": hid, "op_id": h.op_id, "reason": reason,
                                 "needed_capability": h.gap["needed_capability"], "detail": h.gap["detail"]})
        else:
            not_examined.append({"hypothesis_id": hid, "reason": reason})
    for f in findings:                                  # 別の送信での再現: 同じ(型,操作)を別のロールの実験でも確定した所見（同じ実験の再測定ではない）
        f["corroborating_sends"] = sorted(g["probe_exp"] for g in findings
                                          if g is not f and (g["family"], g["op_id"]) == (f["family"], f["op_id"]))
    exps_out = []
    for exp_id, exp in researcher.experiments.items():
        rec_t = outcome.tasks.get(exp_id)
        r = results.get(exp_id)
        exps_out.append({"exp_id": exp_id, "role": exp.role, "op_id": exp.op_id, "path_params": exp.params(),
                         "purpose": researcher.exp_purpose.get(exp_id, ""), "planned_seq": researcher.planned_seq.get(exp_id),
                         "planned_purpose": researcher.planned_purpose.get(exp_id, ""), "tag": exp.tag,
                         "task_state": rec_t.state.value if rec_t else "not_in_plan", "task_reason": rec_t.reason if rec_t else "",
                         "status_code": r.status_code if r else None, "evidence_id": r.evidence_id if r else None,
                         "body_complete": r.body_complete if r else None})
    errors = list(outcome.errors)
    errors += [f"証拠保存エラー: {e}" for e in evidence.save_errors] + [f"証拠保存を省略: {e}" for e in evidence.omissions]
    errors += [f"仮説/実験を却下: {r['hypothesis_id']}: {r['problems']}" for r in researcher.rejected]
    # ── 指標（7.4。分母を明記） ──
    valid = len(researcher.hyps)
    examined = [x for x in hyps_out if x["probe_status_code"] is not None or x["state"] in (S_UNDETERMINED,) and x["probe"] in results]
    probed = [x for x in hyps_out if x["probe"] and x["probe"] in results]
    ctl_req = [x for x in probed if researcher.hyps[x["hypothesis_id"]].control_required]
    ctl_done = [x for x in ctl_req if x["control_state"] in ("passed", "failed", "inconclusive")]
    prereg_bad = [x["hypothesis_id"] for x in probed if x["probe_preexisting"] or
                  (x["probe_planned_seq"] is not None and x["probe_planned_seq"] < x["registered_seq"])]
    with_ev = [f for f in findings if f["evidence_complete"]]
    metrics = {
        "hypotheses_valid": valid, "hypotheses_rejected": len(researcher.rejected),
        "valid_hypothesis_rate": round(valid / (valid + len(researcher.rejected)), 4) if (valid + len(researcher.rejected)) else None,
        "hypotheses_probed": len(probed), "supported": len(findings), "unverified_deviation": len(candidates),
        "refuted": len(refuted), "undetermined": len(undetermined), "unverifiable": len(unverifiable), "not_examined": len(not_examined),
        "hypothesis_to_finding_rate": round(len(findings) / len(probed), 4) if probed else None,
        "control_rate": round(len(ctl_done) / len(ctl_req), 4) if ctl_req else None,
        "control_denominator": len(ctl_req), "evidence_complete_rate": round(len(with_ev) / len(findings), 4) if findings else None,
        "prereg_violations": prereg_bad, "requests_used": ledger.requests_used(), "human_interventions": 0,
        "confirmations_planned": sum(1 for h in researcher.hyps.values() if h.prior_probe or h.prior_control),
        "confirmations_run": sum(1 for h in researcher.hyps.values() if h.prior_probe and h.probe.exp_id in results
                                 and results[h.probe.exp_id].status_code is not None),
        "confirmed_supported": sum(1 for f in findings if f["confirmation"] and f["confirmation"]["mode"] == "confirm"),
        "confirmation_not_reproduced": sum(1 for x in undetermined if x["reason"] == "not_reproduced"),
        "confirmation_not_run": sum(1 for x in candidates if x["reason"] == "confirmation_not_run"),
        "confirmation_cap_blocked": sum(1 for h in researcher.hyps.values() if h.confirm_blocked),
        "confirmation_slots_used": researcher.confirm_count, "confirmation_slots_max": CONFIRM_MAX_PER_RUN,
        "probe_origins": _count_by([x["probe_origin"] for x in hyps_out if x["probe"] in results]),
        "experiments": len(exps_out), "discovery_experiments": sum(1 for e in exps_out if e["purpose"].startswith("discovery"))}
    # ── 状態・coverage ──
    coverage = []
    for x in hyps_out:
        op = case.operations[x["op_id"]]
        cov = (CoverageStatus.TESTED if x["state"] in (S_SUPPORTED, S_REFUTED, S_UNVERIFIED) else
               CoverageStatus.FAILED if x["state"] == S_UNDETERMINED else CoverageStatus.SKIPPED)
        coverage.append(CoverageItem(target_ref=op.path, status=cov.value, rule_id=RULE_ID.get(x["family"], x["family"]),
                                     parameter=x["object_id"], auth_context=x["probe_role"] or "n/a", reason=x["reason"]))
    all_decided = hyps_out and all(x["state"] in (S_SUPPORTED, S_REFUTED) for x in hyps_out)
    if outcome.audit_failed:
        scan_state = ScanState.FAILED.value
    elif runner.is_stopped() or researcher.finish_reason == "stopped":
        scan_state = ScanState.CANCELLED.value
    elif all_decided and not errors:
        scan_state = ScanState.COMPLETED.value
    else:
        scan_state = ScanState.PARTIAL.value        # 検証不能・未検査・未判定・候補があるものをcompletedにしない
    end_reason = ("policy_halt" if outcome.audit_failed else
                  "budget_exhausted" if researcher.finish_reason.startswith("budget") else
                  "stopped" if scan_state == ScanState.CANCELLED.value else researcher.finish_reason or outcome.end_reason)
    clean = not outcome.audit_failed and not any("内部エラー" in e for e in errors)
    sr.state, sr.errors, sr.coverage = scan_state, [mask(e) for e in errors], coverage
    sr.ended_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    sr.config_version = RESEARCH_ENGINE_VERSION
    sr.detector_version = RESEARCH_ENGINE_VERSION
    return ResearchRunResult(
        case_id=case.case_id, run_id=run_id, scan_id=sr.scan_id, state=scan_state, end_reason=end_reason,
        finish_reason=researcher.finish_reason, clean_finish=clean, resumable=True, model=model.summary(),
        hypotheses=hyps_out, rejected=list(researcher.rejected), experiments=exps_out, decision_log=researcher.decisions,
        findings=findings, candidates=candidates, refuted=refuted, undetermined=undetermined, unverifiable=unverifiable,
        not_examined=not_examined, unknowns=list(model.unknowns), metrics=metrics, errors=errors, counters=counters,
        llm=_llm_summary(researcher, ledger, findings, candidates),
        budget={**ledger.snapshot(), "configured": budget},
        versions={"engine": ENGINE_VERSION, "research_engine": RESEARCH_ENGINE_VERSION, "profile_hash": phash[:16],
                  "strategy": researcher.strategy, "dedup": researcher.dedup},
        scan_result=sr.to_dict())
