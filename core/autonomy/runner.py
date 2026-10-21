"""
core/autonomy/runner.py — ScriptedRunner(固定計画を実行する最小のRunner)

設計: docs/AUTONOMOUS_PHASE_A_DESIGN.md §3.4 / §11.6。LLMによる計画は無く、固定のタスク列を依存順に、
すべてPolicyGateを通して実行する。Runnerの責務は次の通り。
  - 各タスクのAction化→Gate判断→(許可時のみ)write-ahead開始記録→実行→完了記録
  - STOP・依存未達・Gate拒否・実行例外の扱い(いずれも黙殺せず結果と理由を残す)
  - 監査記録を書けなくなったら新規の実行を止める(以後の送信を行わない)
  - 終了処理(close_run)は通常Actionから独立。run_finishedの記録に失敗しても例外にせず、
    失敗をerrorsへ返す(呼び出し側がScanResultへ反映し、RESULT→DONEは必ず一度だけ通知する)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable

from core.autonomy.actions import (
    Action, ActionResult, CapabilityRegistry, make_action,
)
import sqlite3

from core.autonomy.budget import BudgetLedger
from core.autonomy.journal import JournalError, RunJournal
from core.autonomy.policy_gate import AuditUnavailable, PolicyGate
from core.autonomy.run_store import RunStore, RunStoreError
from core.autonomy.task_graph import TaskState

ENGINE_VERSION = "autonomy-phase-a/1"
_MAX_FINISH_ERRORS = 20
_MAX_ERROR_CHARS = 200


@dataclass
class PlanTask:
    task_id: str
    capability: str
    args: dict
    depends_on: tuple[str, ...] = ()
    auth_context: str = "anonymous"


@dataclass
class TaskRecord:
    state: TaskState
    reason: str = ""                       # 拒否・スキップ・失敗の理由コード
    result: ActionResult | None = None
    action: Action | None = None


@dataclass
class RunOutcome:
    tasks: dict[str, TaskRecord] = field(default_factory=dict)
    end_reason: str = "frontier_empty"     # frontier_empty / budget_exhausted / stopped / policy_halt / error
    errors: list[str] = field(default_factory=list)
    audit_failed: bool = False

    def state_of(self, task_id: str) -> TaskState | None:
        r = self.tasks.get(task_id)
        return r.state if r else None


class ScriptedRunner:
    def __init__(self, *, gate: PolicyGate, journal: RunJournal, registry: CapabilityRegistry,
                 executors: dict[str, Callable[[Action], ActionResult]],
                 is_stopped: Callable[[], bool], budget: BudgetLedger, plan: list[PlanTask],
                 store: RunStore | None = None, resumed: bool = False,
                 restore_cb: Callable[[PlanTask, dict], None] | None = None,
                 retry_unknown: frozenset = frozenset()):
        self.gate, self.journal, self.registry = gate, journal, registry
        self.executors, self.is_stopped, self.budget, self.plan = executors, is_stopped, budget, plan
        self.store, self.resumed, self.restore_cb = store, resumed, restore_cb
        self.retry_unknown = frozenset(retry_unknown)
        self.outcome = RunOutcome()
        self._rows: dict[str, dict] = store.tasks() if (store is not None and resumed) else {}
        self._plan_by_id = {t.task_id: t for t in plan}
        self._sessions_done: set[str] = set()    # このプロセスで(再)適用したセッション系タスク

    # ── 本体 ────────────────────────────────────────
    def run(self, *, mode: str, target: str, scan_id: str, profile_hash: str = "") -> RunOutcome:
        """新規Runの開始(run_started/task_added/計画の保存)から全タスクの実行まで。
        再開(resumed=True)では開始イベントは書かず(呼び出し側が run_resumed を記録済み)、残りを実行する。"""
        out = self.outcome
        try:
            self.budget.start()
            if not self.resumed:
                self.journal.append("run_started", mode=mode, target=target, scan_id=scan_id,
                                    engine_version=ENGINE_VERSION, budget=self.budget.snapshot(),
                                    profile_hash=profile_hash, tasks=[t.task_id for t in self.plan])
                for t in self.plan:
                    self.journal.append("task_added", task_id=t.task_id, capability=t.capability,
                                        depends_on=list(t.depends_on))
                if self.store is not None:
                    self.store.register_plan([
                        {"task_id": t.task_id, "capability": t.capability, "args": t.args,
                         "depends_on": t.depends_on, "auth_context": t.auth_context} for t in self.plan])
                    self.store.set_meta("scan_id", scan_id)
                    self.store.set_meta("profile_hash", profile_hash)
                    self.store.set_meta("mode", mode)
                    self.store.set_meta("target", target)
            for t in self.plan:
                out.tasks[t.task_id] = TaskRecord(TaskState.PENDING)
        except (JournalError, RunStoreError, sqlite3.Error) as e:
            return self._halt_audit(f"開始を記録できません: {e}")
        for t in self.plan:
            if out.audit_failed:
                break
            self._run_task(t)
        self._decide_end_reason()
        return out

    def _run_task(self, t: PlanTask) -> None:
        out, rec = self.outcome, self.outcome.tasks[t.task_id]
        spec = self.registry.get(t.capability)
        row = self._rows.get(t.task_id)
        reexec_reason = ""
        if row is not None and spec is not None:
            st = row["state"]
            if st in ("done", "exhausted") and not spec.session_scoped:
                self._restore(t, rec, row)               # 完了済みは再実行せず、出力だけ復元する
                return
            if st in ("done", "exhausted") and spec.session_scoped:
                reexec_reason = "session_reapply"       # セッションはプロセス内にしかないので再適用する(新しい承認が必要)
            elif st == "unknown_outcome" and spec.session_scoped:
                reexec_reason = "session_reapply"       # 認証は新しい承認を条件に再適用する(冪等な再確立)
            elif st == "unknown_outcome":
                if t.task_id not in self.retry_unknown:
                    rec.state, rec.reason = TaskState.UNKNOWN_OUTCOME, "unknown_outcome"
                    out.errors.append(f"{t.capability}: 前回の実行結果が不明です(自動では再実行しません)")
                    return
                reexec_reason = "retry_unknown"
        if self.is_stopped():
            self._skip(t, "stopped")
            return
        unmet = [d for d in t.depends_on
                 if out.state_of(d) not in (TaskState.DONE, TaskState.EXHAUSTED)]
        if unmet:
            self._skip(t, "dependency_not_done")
            return
        executor = self.executors.get(t.capability)
        if spec is None or executor is None:
            self._skip(t, "capability.unknown")
            return
        if self.resumed and spec.sends and not self._sessions_ready(t):
            self._skip(t, "session_not_restored")        # 認証の再適用が無いまま、認証前提の送信をしない
            return
        action = make_action(spec, t.task_id, t.args, auth_context=t.auth_context)
        rec.action = action
        if reexec_reason:
            try:
                self.gate.authorize_reexecution(action, reexec_reason)
            except AuditUnavailable as e:
                self._halt_audit(f"再実行を記録できません: {e}")
                return
        decision = self.gate.decide(action)
        if not decision.allowed:
            if self.gate.audit_failed:
                self._halt_audit("判断を記録できません")
                return
            rec.reason = ",".join(decision.reason_codes)
            if decision.verdict == "needs_approval":
                rec.state = TaskState.NEEDS_APPROVAL
            else:
                self._skip(t, rec.reason)
            out.errors.append(f"{t.capability}: 実行しませんでした({rec.reason})")
            return
        try:
            self.gate.start_action(action)             # 送信前に必ず記録(write-ahead)
        except AuditUnavailable as e:
            self._halt_audit(f"開始を記録できません: {e}")
            return
        rec.state = TaskState.RUNNING
        before = self.budget.requests_used()
        try:
            result = executor(action)
        except Exception as e:                          # 例外を握りつぶさず失敗として残す
            result = ActionResult("failed", {"error": type(e).__name__})
            out.errors.append(f"{t.capability}: 実行中に例外が発生しました({type(e).__name__}: {e})")
        if not result.requests_used:
            result.requests_used = max(0, self.budget.requests_used() - before)
        rec.result = result
        try:
            self.gate.finish_action(action, result)
        except AuditUnavailable as e:
            rec.state = TaskState.UNKNOWN_OUTCOME      # 実行した事実は記録できていない
            self._halt_audit(f"完了を記録できません: {e}")
            return
        rec.state = {"done": TaskState.DONE, "exhausted": TaskState.EXHAUSTED,
                     "skipped": TaskState.SKIPPED}.get(result.status, TaskState.FAILED)
        if rec.state == TaskState.DONE and spec.session_scoped:
            self._sessions_done.add(t.task_id)
        if rec.state == TaskState.FAILED:
            rec.reason = "failed"
        elif rec.state == TaskState.SKIPPED:
            rec.reason = str(result.summary.get("reason", "skipped"))

    # ── 補助 ────────────────────────────────────────
    def _restore(self, t: PlanTask, rec: TaskRecord, row: dict) -> None:
        res = row["result"]
        rec.state = TaskState.DONE if row["state"] == "done" else TaskState.EXHAUSTED
        rec.result = ActionResult(status=res.get("status", row["state"]), summary=res.get("summary", {}),
                                  evidence_ids=res.get("evidence_ids", []),
                                  requests_used=row["requests_used"], outputs=row["outputs"])
        if self.restore_cb is not None:
            self.restore_cb(t, row)

    def _ancestors(self, task_id: str) -> set[str]:
        seen: set[str] = set()
        stack = list(self._plan_by_id[task_id].depends_on)
        while stack:
            d = stack.pop()
            if d not in seen and d in self._plan_by_id:
                seen.add(d)
                stack.extend(self._plan_by_id[d].depends_on)
        return seen

    def _sessions_ready(self, t: PlanTask) -> bool:
        """このタスクの祖先にあるセッション系タスクが、このプロセスで全て(再)適用済みか。"""
        need = {a for a in self._ancestors(t.task_id)
                if (sp := self.registry.get(self._plan_by_id[a].capability)) is not None and sp.session_scoped}
        return need <= self._sessions_done

    def _skip(self, t: PlanTask, reason: str) -> None:
        rec = self.outcome.tasks[t.task_id]
        rec.state, rec.reason = TaskState.SKIPPED, reason
        if not self.gate.audit_failed:
            try:
                ev = self.journal.append("task_state", task_id=t.task_id, state="skipped", reason=reason)
                if self.store is not None:
                    self.store.set_state(t.task_id, "skipped", reason=reason, event_id=ev["event_id"])
            except (JournalError, RunStoreError, sqlite3.Error) as e:
                self._halt_audit(f"スキップを記録できません: {e}")

    def _halt_audit(self, message: str) -> RunOutcome:
        out = self.outcome
        out.audit_failed = True
        out.errors.append(f"監査記録を書けないため以後の実行を停止しました: {message}")
        return out

    def _decide_end_reason(self) -> None:
        out = self.outcome
        reasons = {r.reason for r in out.tasks.values()}
        if out.audit_failed:
            out.end_reason = "policy_halt"
        elif "stopped" in reasons or self.is_stopped():
            out.end_reason = "stopped"
        elif any(r.startswith("budget.") for rr in reasons for r in rr.split(",")) or any(
                r.state == TaskState.EXHAUSTED for r in out.tasks.values()):
            out.end_reason = "budget_exhausted"
        elif any(r.state == TaskState.FAILED for r in out.tasks.values()):
            out.end_reason = "error"
        else:
            out.end_reason = "frontier_empty"

    # ── 終了(通常Actionから独立) ───────────────────────
    def close_run(self, *, state: str, errors: list[str]) -> list[str]:
        """run_finishedを一度だけ・コンパクトに記録する。失敗しても例外にせず、追加のerrorsを返す。"""
        compact = [e if len(e) <= _MAX_ERROR_CHARS else e[:_MAX_ERROR_CHARS] + "..."
                   for e in errors[:_MAX_FINISH_ERRORS]]
        extra: list[str] = []
        try:
            self.journal.append("run_finished", state=state, end_reason=self.outcome.end_reason,
                                errors=compact, errors_total=len(errors),
                                tasks={k: v.state.value for k, v in self.outcome.tasks.items()},
                                budget=self.budget.snapshot(),
                                llm_usage=self.budget.llm_usage_summary())
        except JournalError as e:
            extra.append(f"監査記録の終了イベントを書けませんでした: {e}")
        return extra
