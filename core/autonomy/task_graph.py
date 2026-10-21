"""
core/autonomy/task_graph.py — タスク状態と、ジャーナルからの状態再構築

設計: docs/AUTONOMOUS_PHASE_A_DESIGN.md §11.4。`action_started` を送信前に必ず記録する(write-ahead)ため、
開始だけがあり完了が無いタスクは「送信済みかもしれない」= UNKNOWN_OUTCOME として扱い、自動再実行しない。
"""

from __future__ import annotations
from enum import Enum


class TaskState(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    EXHAUSTED = "exhausted"              # 上限到達。doneとは区別し、coverageのtestedに数えない
    NEEDS_APPROVAL = "needs_approval"
    UNKNOWN_OUTCOME = "unknown_outcome"  # 実行結果不明。自動再実行しない


TERMINAL = frozenset({TaskState.DONE, TaskState.FAILED, TaskState.SKIPPED,
                      TaskState.EXHAUSTED, TaskState.UNKNOWN_OUTCOME})

_ALLOWED = {
    TaskState.PENDING: {TaskState.READY, TaskState.NEEDS_APPROVAL, TaskState.SKIPPED},
    TaskState.READY: {TaskState.RUNNING, TaskState.NEEDS_APPROVAL, TaskState.SKIPPED},
    TaskState.NEEDS_APPROVAL: {TaskState.READY, TaskState.SKIPPED},   # 承認 / 拒否・期限切れ
    TaskState.RUNNING: {TaskState.DONE, TaskState.FAILED, TaskState.EXHAUSTED,
                        TaskState.SKIPPED, TaskState.UNKNOWN_OUTCOME},
    TaskState.FAILED: {TaskState.READY},                               # 再試行はGateを通し直す
    TaskState.DONE: set(), TaskState.SKIPPED: set(), TaskState.EXHAUSTED: set(),
    TaskState.UNKNOWN_OUTCOME: set(),                                  # 自動では動かさない
}


def can_transition(a: TaskState, b: TaskState) -> bool:
    return b in _ALLOWED[a]


_FINISH_STATUS = {"done": TaskState.DONE, "failed": TaskState.FAILED,
                  "exhausted": TaskState.EXHAUSTED, "skipped": TaskState.SKIPPED}


def derive_task_states(events: list[dict]) -> dict[str, TaskState]:
    """ジャーナルのイベント列から各タスクの現在状態を再構築する。

    再生の終わりに RUNNING のまま残るタスク(action_startedのみ)は UNKNOWN_OUTCOME にする。
    """
    states: dict[str, TaskState] = {}
    for e in events:
        t, tid = e.get("type"), e.get("task_id")
        if not tid:
            continue
        if t == "task_added":
            states[tid] = TaskState.PENDING
        elif t == "gate_decision":
            v = e.get("verdict")
            states[tid] = {"allow": TaskState.READY, "needs_approval": TaskState.NEEDS_APPROVAL,
                           "deny": TaskState.SKIPPED}.get(v, states.get(tid, TaskState.PENDING))
        elif t == "action_started":
            states[tid] = TaskState.RUNNING
        elif t == "action_finished":
            states[tid] = _FINISH_STATUS.get(e.get("status"), TaskState.FAILED)
        elif t == "task_state":
            try:
                states[tid] = TaskState(e.get("state"))
            except ValueError:
                pass
    return {tid: (TaskState.UNKNOWN_OUTCOME if st == TaskState.RUNNING else st)
            for tid, st in states.items()}
