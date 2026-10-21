"""
core/autonomy/resume.py — 中断からの再開: プロファイルハッシュと、ジャーナルと状態ストアの突合(reconcile)

設計: docs/AUTONOMOUS_PHASE_B_DESIGN.md §3。書込み順序は ①journal action_started → ②実行 → ③store commit →
④journal action_finished。強制終了がどこで起きても、再開時にこの表で状態を確定する:

  journal action_finished あり / store 完了         → 一致(何もしない)
  journal action_started のみ / store 完了(commit済) → store から action_finished(reconciled=true)をjournalへ補う
  journal action_started のみ / store running・無し  → unknown_outcome(自動再実行しない。両方へ記録)
  journal approval_consumed あり / store に無い      → storeへ補う(再利用を防ぐ)
  store に完了があるのに journal に開始が無い          → 起こり得ない順序。破損として ResumeError
"""

from __future__ import annotations
import hashlib
import os
from dataclasses import dataclass, field

from core.autonomy.actions import canonical_json
from core.autonomy.journal import RunJournal, replay
from core.autonomy.run_store import RunStore
from core.autonomy.task_graph import TaskState, derive_task_states


class ResumeError(Exception):
    """再開できない(終了済み・破損・プロファイル不一致など)。実行は何もせずに止める。"""


def profile_hash(profile: dict) -> str:
    """再開時に一致を要求するプロファイル(対象・許可・予算・計画など)のハッシュ。秘密値は含めない。"""
    return hashlib.sha256(canonical_json(profile).encode()).hexdigest()


@dataclass
class ReconcileReport:
    notes: list[str] = field(default_factory=list)
    unknown_tasks: list[str] = field(default_factory=list)


def reconcile(journal: RunJournal, store: RunStore) -> ReconcileReport:
    rep = replay(journal.run_id, os.path.dirname(journal.dir))
    events = rep.events
    if any(e["type"] == "run_finished" for e in events):
        raise ResumeError("終了済みのRunは再開できません(クラッシュからの復旧用です)。新しいRunを開始してください")
    report = ReconcileReport()
    finished_ids = {e["event_id"] for e in events if e["type"] == "action_finished"}
    started_tasks = {e["task_id"] for e in events if e["type"] == "action_started"}
    derived = derive_task_states(events)

    # 承認: ジャーナルにあってストアに無い消費を補う
    store_grants = store.consumed_grants()
    for e in events:
        if e["type"] == "approval_consumed" and e["grant_id"] not in store_grants:
            store.consume_grant(e["grant_id"], action_id=e.get("action_id", ""), event_id=e["event_id"])
            report.notes.append(f"承認{e['grant_id']}の消費をストアへ補いました")

    for tid, row in store.tasks().items():
        st = row["state"]
        if row["finish_event_id"] and st != "running":      # 実行結果がストアにcommit済み
            if row["finish_event_id"] in finished_ids:
                continue
            if tid not in started_tasks:
                raise ResumeError(f"{tid}: 開始記録が無いのに完了がストアにあります(破損)")
            res = row["result"]
            journal.append("action_finished", event_id=row["finish_event_id"], action_id=row["action_id"],
                           task_id=tid, status=res.get("status", st), requests_used=row["requests_used"],
                           evidence_ids=res.get("evidence_ids", []), summary=res.get("summary", {}),
                           reconciled=True)
            report.notes.append(f"{tid}: 完了記録をストアからジャーナルへ補いました")
            continue
        if st == "running" and derived.get(tid) == TaskState.DONE:
            raise ResumeError(f"{tid}: ジャーナルは完了だがストアはrunningです(破損)")
        interrupted = (st == "running") or (derived.get(tid) == TaskState.UNKNOWN_OUTCOME and st != "unknown_outcome")
        if interrupted:
            journal.append("task_state", task_id=tid, state="unknown_outcome", reason="interrupted")
            store.set_state(tid, "unknown_outcome", reason="interrupted", consumption_unknown=True)
            report.unknown_tasks.append(tid)
            report.notes.append(f"{tid}: 実行結果が不明です(自動では再実行しません)")
        elif st == "unknown_outcome":
            report.unknown_tasks.append(tid)
    return report
