"""
core/autonomy/policy_gate.py — Policy Gate(実行前の決定論的な許可判断)

設計: docs/AUTONOMOUS_PHASE_A_DESIGN.md §3.3 / §11。LLMの出力は信頼しない前提で、Actionを実行する前に
必ずここを通す。判断(allow / deny / needs_approval と理由コード)は**実行前に**ジャーナルへ書き、
書けなければ実行しない(fail closed)。送信そのものの検査(同一origin・共有予算・レート・STOP)は
HttpTransport が引き続き担い、Gateはそれを置き換えず前段に追加する。

検査の順序(最初のdenyで確定):
  1 capabilityの存在・有効  2 引数スキーマ  3 スコープ(空の許可リストはdeny・除外優先・同一origin)
  4 副作用クラスの許可(T3は有効なApprovalGrantが必須)  5 予算  6 重複
承認の消費(approval_consumed)は全検査が通った後、gate_decisionより前に書く。
"""

from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Callable

from core.autonomy.actions import (
    Action, ActionResult, ApprovalGrant, CapabilityRegistry, CapabilitySpec, GateDecision,
    SideEffect, args_hash, validate_args,
)
from core.autonomy.budget import BudgetLedger
from core.autonomy.journal import JournalError, RunJournal
from core.autonomy.run_store import RunStore, RunStoreError
from core.findings import new_id
import sqlite3
from core.http_transport import normalize_origin
from core.scope_guard import extract_host, in_scope


class AuditUnavailable(Exception):
    """判断・開始・完了の記録を書けない。呼び出し側は実行(送信)してはならない。"""


@dataclass
class EngagementPolicy:
    base_origin: str                                   # このRunの基準origin(HttpTransportと同じ正規化)
    allowed_targets: list[str] = field(default_factory=list)   # 空は自律経路ではdeny
    excluded_targets: list[str] = field(default_factory=list)  # 許可より優先
    # T0は常に許可。T1/T2は利用者が明示した場合のみ。T3は許可クラスではなく個別承認で決まる。
    allowed_side_effects: frozenset = frozenset({SideEffect.T0_LOCAL})
    max_failed_retries: int = 1                        # 同一重複キーで失敗後に再試行できる回数


class PolicyGate:
    def __init__(self, registry: CapabilityRegistry, policy: EngagementPolicy, budget: BudgetLedger,
                 journal: RunJournal, *, grants: list[ApprovalGrant] | None = None,
                 clock: Callable[[], float] = time.time, store: RunStore | None = None):
        self.registry = registry
        self.store = store
        self.policy = policy
        self.budget = budget
        self.journal = journal
        self._clock = clock
        self._grants = {g.grant_id: g for g in (grants or [])}
        self._consumed: set[str] = set()
        self._key_state: dict[str, str] = {}      # dedupe_key -> running|done|exhausted|unknown_outcome
        self._key_failures: dict[str, int] = {}
        self._audit_failed = False
        if store is not None:
            self.restore_from_store()

    def restore_from_store(self) -> None:
        """再開用: 消費済み承認・重複キーの状態・失敗回数をストアから復元する。"""
        if self.store is None:
            return
        self._consumed |= set(self.store.consumed_grants())
        for t in self.store.tasks().values():
            key, st = t["dedupe_key"], t["state"]
            if not key:
                continue
            if st in ("done", "exhausted"):
                self._key_state[key] = st
            elif st in ("unknown_outcome", "running"):
                self._key_state[key] = "unknown_outcome"
            elif st == "failed":
                self._key_failures[key] = max(self._key_failures.get(key, 0), t["attempt"])

    def authorize_reexecution(self, action: Action, reason: str) -> None:
        """同じ重複キーの再実行を、理由付きで明示的に許可する(session_reapply / retry_unknown)。

        許可は監査記録に残る。記録できなければ AuditUnavailable(以後Gateは使えない)。再実行する場合でも、
        実行前にGateの通常の判断(スコープ・予算・承認)を通し直す。
        """
        if self._audit_failed:
            raise AuditUnavailable("監査記録を書けないため再実行を許可できません")
        try:
            self.journal.append("reexecution_authorized", task_id=action.task_id, action_id=action.action_id,
                                capability=action.capability, dedupe_key=action.dedupe_key, reason=reason)
        except JournalError as e:
            self._audit_failed = True
            raise AuditUnavailable(str(e)) from e
        self._key_state.pop(action.dedupe_key, None)
        self._key_failures.pop(action.dedupe_key, None)

    # ── 判断 ──────────────────────────────────────────
    def decide(self, action: Action) -> GateDecision:
        """Actionの可否を判断し、判断を実行前にジャーナルへ記録して返す。"""
        if self._audit_failed:
            return GateDecision("deny", ("audit.unavailable",), "監査記録を書けないため実行しません")
        decision, grant = self._evaluate(action)
        try:
            if grant is not None:
                eid = new_id("evt")
                if self.store is not None and not self.store.consume_grant(
                        grant.grant_id, action_id=action.action_id, event_id=eid):
                    decision, grant = GateDecision("deny", ("approval.reused",),
                                                   "この承認は使用済みです(状態ストアの記録)"), None
            if grant is not None:
                self.journal.append("approval_consumed", event_id=eid, grant_id=grant.grant_id,
                                    action_id=action.action_id, task_id=action.task_id,
                                    args_hash=args_hash(action.capability, action.args))
                self._consumed.add(grant.grant_id)
            self.journal.append(
                "gate_decision", action_id=action.action_id, task_id=action.task_id,
                capability=action.capability, args_hash=args_hash(action.capability, action.args),
                verdict=decision.verdict, reason_codes=list(decision.reason_codes),
                detail=decision.detail)
        except (JournalError, RunStoreError, sqlite3.Error) as e:
            self._audit_failed = True
            return GateDecision("deny", ("audit.unavailable",), f"判断を記録できません: {e}")
        return decision

    def _deny(self, *codes: str, detail: str = "") -> tuple[GateDecision, None]:
        return GateDecision("deny", tuple(codes), detail), None

    def _evaluate(self, action: Action) -> tuple[GateDecision, ApprovalGrant | None]:
        spec = self.registry.get(action.capability)
        if spec is None:
            return self._deny("capability.unknown", detail=action.capability)
        if not spec.enabled:
            return self._deny("capability.disabled", detail=spec.name)
        problems = validate_args(spec, action.args)
        if problems:
            return self._deny("args.invalid", detail="; ".join(problems))

        scope = self._check_scope(spec, action)
        if scope is not None:
            return scope, None

        # 副作用クラス
        needs_grant = spec.side_effect == SideEffect.T3_NEEDS_APPROVAL
        if not needs_grant and spec.side_effect not in self.policy.allowed_side_effects:
            return self._deny("side_effect.not_permitted", detail=spec.side_effect.value)

        budget = self._check_budget(spec)
        if budget is not None:
            return budget, None
        dup = self._check_dedupe(action)
        if dup is not None:
            return dup, None

        if needs_grant:
            return self._check_grant(spec, action)
        return GateDecision("allow"), None

    def _check_scope(self, spec: CapabilitySpec, action: Action) -> GateDecision | None:
        if not spec.target_arg:
            return None
        if not self.policy.allowed_targets:
            return GateDecision("deny", ("scope.empty_allowlist",),
                                "自律実行では許可対象の明示が必須です")
        target = action.args.get(spec.target_arg)
        origin = normalize_origin(target) if isinstance(target, str) else None
        if origin is None:
            return GateDecision("deny", ("scope.invalid_target",), "対象URLを解釈できません")
        base = normalize_origin(self.policy.base_origin)
        if base is None or origin != base:
            return GateDecision("deny", ("scope.cross_origin",), f"{origin} は基準origin外です")
        host = extract_host(str(target))
        if self.policy.excluded_targets and in_scope(host, self.policy.excluded_targets)[0]:
            return GateDecision("deny", ("scope.excluded",), host)
        if not in_scope(host, self.policy.allowed_targets)[0]:
            return GateDecision("deny", ("scope.out_of_scope",), host)
        return None

    def _check_budget(self, spec: CapabilitySpec) -> GateDecision | None:
        sends_or_llm = spec.sends or spec.uses_llm
        # 時間切れは送信・LLMを止める。ローカルのT0(最終化など)は終了のために許可し続ける。
        if sends_or_llm and self.budget.time_exhausted():
            return GateDecision("deny", ("budget.time_exhausted",))
        # Action単位の上限では拒否しない(旧経路は残予算まで進むため)。Run残が0のときだけ拒否する。
        if spec.sends and self.budget.requests_remaining() <= 0:
            return GateDecision("deny", ("budget.requests_exhausted",))
        if spec.llm_calls:
            left = self.budget.llm_calls_remaining()
            if left is not None and left < spec.llm_calls:
                return GateDecision("deny", ("budget.llm_calls_exhausted",))
        return None

    def _check_dedupe(self, action: Action) -> GateDecision | None:
        state = self._key_state.get(action.dedupe_key)
        if state in ("running", "done", "exhausted"):
            return GateDecision("deny", ("dedupe.already_done",), state)
        if state == "unknown_outcome":
            return GateDecision("deny", ("dedupe.unknown_outcome",), "結果不明のため自動再実行しません")
        if self._key_failures.get(action.dedupe_key, 0) > self.policy.max_failed_retries:
            return GateDecision("deny", ("dedupe.retry_limit",))
        return None

    def _check_grant(self, spec: CapabilitySpec, action: Action) -> tuple[GateDecision, ApprovalGrant | None]:
        h = args_hash(action.capability, action.args)
        candidates = [g for g in self._grants.values() if g.capability == action.capability]
        if not candidates:
            return GateDecision("needs_approval", ("approval.missing",), "個別承認が必要です"), None
        matching = [g for g in candidates if g.args_hash == h]
        if not matching:
            return self._deny("approval.args_mismatch", detail="承認は別の引数に対するものです")
        unused = [g for g in matching if g.grant_id not in self._consumed]
        if not unused:
            return self._deny("approval.reused", detail="この承認は使用済みです")
        valid = [g for g in unused if g.expires_at > self._clock()]
        if not valid:
            return self._deny("approval.expired", detail="承認の期限が切れています")   # タイムアウトは常にdeny
        return GateDecision("allow", ("approval.granted",)), valid[0]

    # ── 実行の開始・完了(write-ahead) ─────────────────
    def start_action(self, action: Action) -> None:
        """送信**前**に呼ぶ。記録できなければ AuditUnavailable(送信してはならない)。"""
        if self._audit_failed:
            raise AuditUnavailable("監査記録を書けないため開始できません")
        try:
            ev = self.journal.append("action_started", action_id=action.action_id, task_id=action.task_id,
                                     capability=action.capability, dedupe_key=action.dedupe_key,
                                     budget=self.budget.snapshot())
            if self.store is not None:
                self.store.start_task(action.task_id, action_id=action.action_id,
                                      dedupe_key=action.dedupe_key, event_id=ev["event_id"])
        except (JournalError, RunStoreError, sqlite3.Error) as e:
            self._audit_failed = True
            raise AuditUnavailable(str(e)) from e
        self._key_state[action.dedupe_key] = "running"

    def finish_action(self, action: Action, result: ActionResult) -> None:
        """実行後に呼ぶ。順序: ①状態ストアに結果と出力をcommit → ②ジャーナルに action_finished。

        ①に失敗した場合、結果は永続化されていないので不明扱い(unknown_outcome)にして以後の再実行を止める。
        ②だけに失敗した場合は結果はストアに残る(再開時に突合してジャーナルへ補う)。
        """
        if result.status == "failed":
            self._key_failures[action.dedupe_key] = self._key_failures.get(action.dedupe_key, 0) + 1
        final = ("failed" if result.status == "failed" else
                 "exhausted" if result.status == "exhausted" else
                 "skipped" if result.status == "skipped" else "done")
        eid = new_id("evt")
        committed = False          # 状態ストアにcommitできたか(ストアが無ければ永続化された結果は無い)
        try:
            if self._audit_failed:
                raise JournalError("監査記録を書けない状態です")
            if self.store is not None:
                self.store.finish_task(
                    action.task_id, state=final, reason=str(result.summary.get("reason", "")),
                    requests_used=result.requests_used,
                    result={"status": result.status, "summary": result.summary,
                            "evidence_ids": list(result.evidence_ids)},
                    outputs=result.outputs, event_id=eid)
                committed = True
            self.journal.append(
                "action_finished", event_id=eid, action_id=action.action_id, task_id=action.task_id,
                status=result.status, requests_used=result.requests_used, llm_usage=result.llm_usage,
                evidence_ids=list(result.evidence_ids), summary=result.summary,
                budget=self.budget.snapshot())
        except (JournalError, RunStoreError, sqlite3.Error) as e:
            self._audit_failed = True
            self._key_state[action.dedupe_key] = final if committed else "unknown_outcome"
            raise AuditUnavailable(f"完了を記録できません: {e}") from e
        self._key_state[action.dedupe_key] = final

    @property
    def audit_failed(self) -> bool:
        return self._audit_failed
