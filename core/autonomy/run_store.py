"""
core/autonomy/run_store.py — RunStore(実行状態の永続化。標準ライブラリ sqlite3・WAL)

設計: docs/AUTONOMOUS_PHASE_B_DESIGN.md。監査記録(journal.jsonl)は判断・実行の時系列で、再開の正本ではない。
再開に必要な「タスクの状態・完了タスクの出力・消費済み承認・予算の消費」はここに transaction で保存する。

  - 書込みは単一connection・ロック付き・`synchronous=FULL`。結果と出力は1 transactionでcommitする。
  - 出力(outputs)は呼び出し側が**保存前にマスク済み**にして渡す(生の認証値・未マスクの応答本文を残さない)。
    本クラスは中身を解釈せず、JSONとして保存・復元するだけ。
  - event_id は journal の同名フィールドと同じ値を持たせ、片側だけにある更新の突合に使う。
  - 承認の消費は PRIMARY KEY で一意にし、再利用をストア側でも拒否する。
"""

from __future__ import annotations
import json
import os
import sqlite3
import threading
from datetime import datetime

from core.autonomy.journal import JOURNAL_ROOT, validate_run_id

SCHEMA_VERSION = "1"
STATE_FILE = "state.sqlite3"

_DDL = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tasks(
    task_id TEXT PRIMARY KEY, idx INTEGER NOT NULL, capability TEXT NOT NULL, args_json TEXT NOT NULL,
    depends_json TEXT NOT NULL, auth_context TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending', reason TEXT NOT NULL DEFAULT '',
    action_id TEXT NOT NULL DEFAULT '', dedupe_key TEXT NOT NULL DEFAULT '',
    attempt INTEGER NOT NULL DEFAULT 0, requests_used INTEGER NOT NULL DEFAULT 0,
    consumption_unknown INTEGER NOT NULL DEFAULT 0,
    result_json TEXT NOT NULL DEFAULT '{}', outputs_json TEXT NOT NULL DEFAULT '{}',
    start_event_id TEXT NOT NULL DEFAULT '', finish_event_id TEXT NOT NULL DEFAULT '',
    state_event_id TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS consumed_grants(
    grant_id TEXT PRIMARY KEY, action_id TEXT NOT NULL, event_id TEXT NOT NULL, consumed_at TEXT NOT NULL);
"""


class RunStoreError(Exception):
    pass


def _now() -> str:
    return datetime.now().isoformat(timespec="milliseconds")


class RunStore:
    def __init__(self, run_id: str, root: str = JOURNAL_ROOT, *, must_exist: bool = False):
        self.run_id = validate_run_id(run_id)
        self.dir = os.path.join(root, self.run_id)
        self.path = os.path.join(self.dir, STATE_FILE)
        if must_exist and not os.path.isfile(self.path):
            raise RunStoreError(f"状態ストアがありません: {self.path}")
        os.makedirs(self.dir, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(_DDL)
        v = self.get_meta("schema_version")
        if v is None:
            self.set_meta("schema_version", SCHEMA_VERSION)
        elif v != SCHEMA_VERSION:
            self.close()
            raise RunStoreError(f"未対応のschema_versionです: {v}")

    # ── transaction ─────────────────────────────────
    def _tx(self):
        store = self

        class _T:
            def __enter__(self_):
                store._lock.acquire()
                store._db.execute("BEGIN IMMEDIATE")
                return store._db

            def __exit__(self_, et, ev, tb):
                try:
                    store._db.execute("COMMIT" if et is None else "ROLLBACK")
                finally:
                    store._lock.release()
                return False
        return _T()

    # ── メタ ──────────────────────────────────────
    def set_meta(self, key: str, value: str) -> None:
        with self._tx() as db:
            db.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (key, value))

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    # ── 計画 ──────────────────────────────────────
    def register_plan(self, tasks: list[dict]) -> None:
        """計画(task_id/capability/args/depends_on/auth_context)を保存する。既にある場合は何もしない(再開時)。"""
        with self._tx() as db:
            if db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]:
                return
            for i, t in enumerate(tasks):
                db.execute(
                    "INSERT INTO tasks(task_id,idx,capability,args_json,depends_json,auth_context,updated_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (t["task_id"], i, t["capability"], json.dumps(t.get("args", {}), sort_keys=True),
                     json.dumps(list(t.get("depends_on", ()))), t.get("auth_context", "anonymous"), _now()))

    def append_task(self, t: dict) -> None:
        """実行中に計画へ1件追加する（動的な再計画用）。既にあれば何もしない（再開時の冪等性）。"""
        with self._tx() as db:
            if db.execute("SELECT 1 FROM tasks WHERE task_id=?", (t["task_id"],)).fetchone():
                return
            idx = db.execute("SELECT COALESCE(MAX(idx),-1)+1 FROM tasks").fetchone()[0]
            db.execute(
                "INSERT INTO tasks(task_id,idx,capability,args_json,depends_json,auth_context,updated_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (t["task_id"], idx, t["capability"], json.dumps(t.get("args", {}), sort_keys=True),
                 json.dumps(list(t.get("depends_on", ()))), t.get("auth_context", "anonymous"), _now()))

    def plan(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM tasks ORDER BY idx").fetchall()
        return [{"task_id": r["task_id"], "capability": r["capability"], "args": json.loads(r["args_json"]),
                 "depends_on": tuple(json.loads(r["depends_json"])), "auth_context": r["auth_context"]}
                for r in rows]

    # ── タスク状態 ─────────────────────────────────
    def start_task(self, task_id: str, *, action_id: str, dedupe_key: str, event_id: str) -> None:
        with self._tx() as db:
            cur = db.execute(
                "UPDATE tasks SET state='running', action_id=?, dedupe_key=?, start_event_id=?, "
                "finish_event_id='', attempt=attempt+1, updated_at=? WHERE task_id=?",
                (action_id, dedupe_key, event_id, _now(), task_id))
            if cur.rowcount != 1:
                raise RunStoreError(f"未登録のタスクです: {task_id}")

    def finish_task(self, task_id: str, *, state: str, reason: str = "", requests_used: int = 0,
                    result: dict | None = None, outputs: dict | None = None, event_id: str) -> None:
        """結果と出力を1 transactionでcommitする(これがコミットされた時点で「実行は完了した」が確定する)。"""
        with self._tx() as db:
            cur = db.execute(
                "UPDATE tasks SET state=?, reason=?, requests_used=?, result_json=?, outputs_json=?, "
                "finish_event_id=?, updated_at=? WHERE task_id=?",
                (state, reason, int(requests_used), json.dumps(result or {}, sort_keys=True, default=str),
                 json.dumps(outputs or {}, sort_keys=True, default=str), event_id, _now(), task_id))
            if cur.rowcount != 1:
                raise RunStoreError(f"未登録のタスクです: {task_id}")

    def set_state(self, task_id: str, state: str, *, reason: str = "", event_id: str = "",
                  consumption_unknown: bool = False) -> None:
        """実行を伴わない状態更新(skipped / needs_approval / unknown_outcome など)。"""
        with self._tx() as db:
            db.execute(
                "UPDATE tasks SET state=?, reason=?, consumption_unknown=?, state_event_id=?, "
                "updated_at=? WHERE task_id=?",
                (state, reason, 1 if consumption_unknown else 0, event_id, _now(), task_id))

    def task(self, task_id: str) -> dict | None:
        with self._lock:
            r = self._db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        return self._row(r) if r else None

    def tasks(self) -> dict[str, dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM tasks ORDER BY idx").fetchall()
        return {r["task_id"]: self._row(r) for r in rows}

    @staticmethod
    def _row(r) -> dict:
        d = dict(r)
        d["result"] = json.loads(d.pop("result_json"))
        d["outputs"] = json.loads(d.pop("outputs_json"))
        d["args"] = json.loads(d.pop("args_json"))
        d["depends_on"] = tuple(json.loads(d.pop("depends_json")))
        d["consumption_unknown"] = bool(d["consumption_unknown"])
        return d

    # ── 承認 ──────────────────────────────────────
    def consume_grant(self, grant_id: str, *, action_id: str, event_id: str) -> bool:
        """承認を消費済みにする。既に消費済みなら False(再利用の拒否。ストア側でも一意性を保証する)。"""
        try:
            with self._tx() as db:
                db.execute("INSERT INTO consumed_grants(grant_id,action_id,event_id,consumed_at) VALUES(?,?,?,?)",
                           (grant_id, action_id, event_id, _now()))
            return True
        except sqlite3.IntegrityError:
            return False

    def consumed_grants(self) -> dict[str, dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM consumed_grants").fetchall()
        return {r["grant_id"]: dict(r) for r in rows}

    # ── 消費(予算) ─────────────────────────────────
    def requests_consumed(self, assumed_for_unknown: int = 0) -> int:
        """完了したタスクの実測消費の合計。結果不明のタスクは assumed_for_unknown(宣言された上限等)を加算する
        (不明分を巻き戻さない＝安全側)。"""
        with self._lock:
            row = self._db.execute("SELECT COALESCE(SUM(requests_used),0) FROM tasks").fetchone()
            unknown = self._db.execute(
                "SELECT COUNT(*) FROM tasks WHERE state='unknown_outcome' OR consumption_unknown=1").fetchone()
        return int(row[0]) + int(unknown[0]) * int(assumed_for_unknown)

    def close(self) -> None:
        with self._lock:
            try:
                self._db.close()
            except sqlite3.Error:
                pass

    def __enter__(self) -> "RunStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
