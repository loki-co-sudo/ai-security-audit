"""core/autonomy/run_store.py の固定試験(実LLM・外部通信なし)。"""
import os
import sqlite3
import tempfile
import threading
import unittest

from core.autonomy import journal as jr
from core.autonomy.run_store import RunStore, RunStoreError, STATE_FILE


PLAN = [
    {"task_id": "crawl", "capability": "web.crawl", "args": {"url": "http://x/"}, "depends_on": ()},
    {"task_id": "fuzz", "capability": "web.fuzz_get_points", "args": {"url": "http://x/"},
     "depends_on": ("crawl",), "auth_context": "authenticated"},
]


class RunStoreTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root, self.rid = self._tmp.name, jr.new_run_id()

    def store(self, **kw):
        s = RunStore(self.rid, self.root, **kw)
        self.addCleanup(s.close)
        return s

    def test_plan_roundtrip_and_register_is_idempotent(self):
        s = self.store()
        s.register_plan(PLAN)
        s.register_plan([{"task_id": "other", "capability": "x.y", "args": {}}])   # 再開時は上書きしない
        self.assertEqual([t["task_id"] for t in s.plan()], ["crawl", "fuzz"])
        self.assertEqual(s.plan()[1]["depends_on"], ("crawl",))
        self.assertEqual(s.plan()[1]["auth_context"], "authenticated")

    def test_invalid_run_id_and_must_exist(self):
        with self.assertRaises(ValueError):
            RunStore("../x", self.root)
        with self.assertRaises(RunStoreError):
            RunStore(jr.new_run_id(), self.root, must_exist=True)

    def test_task_lifecycle_and_outputs_survive_reopen(self):
        s = self.store()
        s.register_plan(PLAN)
        s.start_task("crawl", action_id="act_1", dedupe_key="k1", event_id="evt_s")
        self.assertEqual(s.task("crawl")["state"], "running")
        s.finish_task("crawl", state="done", requests_used=6, result={"pages": 3},
                      outputs={"points": [{"url": "http://x/a", "param": "q"}]}, event_id="evt_f")
        s.close()
        s2 = self.store()                                    # 別接続(再開相当)で読み直す
        t = s2.task("crawl")
        self.assertEqual((t["state"], t["requests_used"], t["attempt"]), ("done", 6, 1))
        self.assertEqual(t["outputs"]["points"][0]["param"], "q")
        self.assertEqual((t["start_event_id"], t["finish_event_id"]), ("evt_s", "evt_f"))
        self.assertEqual(s2.task("fuzz")["state"], "pending")

    def test_unregistered_task_is_an_error_and_does_not_partially_write(self):
        s = self.store()
        s.register_plan(PLAN)
        with self.assertRaises(RunStoreError):
            s.start_task("nope", action_id="a", dedupe_key="k", event_id="e")
        with self.assertRaises(RunStoreError):
            s.finish_task("nope", state="done", event_id="e")

    def test_finish_is_atomic_when_the_transaction_fails(self):
        s = self.store()
        s.register_plan(PLAN)
        s.start_task("crawl", action_id="a", dedupe_key="k", event_id="e1")

        class Boom:
            def __str__(self): raise RuntimeError("cannot serialize")
        with self.assertRaises(Exception):
            s.finish_task("crawl", state="done", outputs={"x": Boom()}, event_id="e2")
        self.assertEqual(s.task("crawl")["state"], "running")          # 中途半端な更新は残らない

    def test_grant_consumption_is_unique(self):
        s = self.store()
        self.assertTrue(s.consume_grant("g1", action_id="a", event_id="e"))
        self.assertFalse(s.consume_grant("g1", action_id="a2", event_id="e2"))
        self.assertEqual(set(s.consumed_grants()), {"g1"})
        s.close()
        self.assertEqual(set(self.store().consumed_grants()), {"g1"})

    def test_requests_consumed_counts_unknown_conservatively(self):
        s = self.store()
        s.register_plan(PLAN)
        s.start_task("crawl", action_id="a", dedupe_key="k", event_id="e")
        s.finish_task("crawl", state="done", requests_used=6, event_id="f")
        self.assertEqual(s.requests_consumed(assumed_for_unknown=100), 6)
        s.start_task("fuzz", action_id="a2", dedupe_key="k2", event_id="e2")
        s.set_state("fuzz", "unknown_outcome", reason="interrupted", consumption_unknown=True)
        self.assertEqual(s.requests_consumed(assumed_for_unknown=100), 106)     # 不明分は巻き戻さない
        self.assertEqual(s.requests_consumed(), 6)

    def test_schema_version_mismatch_is_rejected(self):
        s = self.store()
        s.set_meta("schema_version", "999")
        s.close()
        with self.assertRaises(RunStoreError):
            RunStore(self.rid, self.root)

    def test_wal_and_full_sync(self):
        s = self.store()
        self.assertEqual(s._db.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
        self.assertEqual(s._db.execute("PRAGMA synchronous").fetchone()[0], 2)   # FULL

    def test_concurrent_writers_do_not_corrupt(self):
        s = self.store()
        s.register_plan([{"task_id": f"t{i}", "capability": "x.y", "args": {}} for i in range(20)])

        def work(i):
            s.start_task(f"t{i}", action_id=f"a{i}", dedupe_key=f"k{i}", event_id=f"e{i}")
            s.finish_task(f"t{i}", state="done", requests_used=1, event_id=f"f{i}")
        ts = [threading.Thread(target=work, args=(i,)) for i in range(20)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(s.requests_consumed(), 20)
        self.assertTrue(all(t["state"] == "done" for t in s.tasks().values()))

    def test_file_lives_next_to_the_journal(self):
        s = self.store()
        self.assertEqual(os.path.basename(s.path), STATE_FILE)
        self.assertEqual(os.path.dirname(s.path), os.path.join(self.root, self.rid))


if __name__ == "__main__":
    unittest.main()
