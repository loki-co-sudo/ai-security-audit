"""core/autonomy/journal.py の固定回帰テスト（実LLM・外部ネットワーク不要）。"""
import json
import os
import tempfile
import threading
import unittest
from unittest.mock import patch

from core.autonomy import journal as jr


class RunJournalTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.run_id = jr.new_run_id()

    def tearDown(self):
        self._tmp.cleanup()

    def _path(self):
        return os.path.join(self.root, self.run_id, jr.JOURNAL_FILE)

    def _lines(self):
        with open(self._path(), "rb") as f:
            return f.read().split(b"\n")[:-1]

    def test_append_and_replay_roundtrip(self):
        with jr.RunJournal(self.run_id, self.root) as j:
            j.append("run_started", mode="WEB FUZZ", target="http://127.0.0.1:1")
            j.append("gate_decision", action_id="a1", verdict="allow", reason_codes=[])
            last = j.append("run_finished", state="completed")
        rep = jr.replay(self.run_id, self.root)
        self.assertEqual([e["seq"] for e in rep.events], [1, 2, 3])
        self.assertEqual(rep.events[0]["prev_hash"], jr.GENESIS_HASH)
        self.assertEqual(rep.events[1]["prev_hash"], jr._line_hash(self._lines()[0]))
        self.assertEqual(rep.events[2]["event_id"], last["event_id"])
        self.assertTrue(all(e["schema_version"] == jr.SCHEMA_VERSION and e["run_id"] == self.run_id
                            for e in rep.events))
        self.assertEqual(rep.warnings, [])

    def test_reopen_continues_chain(self):
        with jr.RunJournal(self.run_id, self.root) as j:
            j.append("run_started")
        with jr.RunJournal(self.run_id, self.root) as j:
            self.assertEqual(j.event_count, 1)
            j.append("task_added", task_id="t1")
        self.assertEqual([e["seq"] for e in jr.replay(self.run_id, self.root).events], [1, 2])

    def test_invalid_run_id_rejected(self):
        for bad in ("", "../x", "run_zzzzzzzzzzzz", "run_0123456789abc", "scan_0123456789ab", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                jr.RunJournal(bad, self.root)
            with self.assertRaises(ValueError, msg=repr(bad)):
                jr.replay(bad, self.root)

    def test_invalid_type_and_reserved_fields(self):
        with jr.RunJournal(self.run_id, self.root) as j:
            for bad in ("", "Bad-Type", "x" * 100, 5):
                with self.assertRaises(ValueError):
                    j.append(bad)
            for name in ("seq", "prev_hash", "run_id", "ts", "type", "event_id", "schema_version"):
                with self.assertRaises(ValueError):
                    j.append("task_state", **{name: 1})
            self.assertEqual(j.event_count, 0)

    def test_partial_tail_recovered_with_warning(self):
        with jr.RunJournal(self.run_id, self.root) as j:
            j.append("run_started")
            j.append("task_added", task_id="t1")
        with open(self._path(), "ab") as f:
            f.write(b'{"seq":3,"type":"gate_dec')  # 書込み途中の残骸（改行なし）
        rep = jr.replay(self.run_id, self.root)
        self.assertEqual(len(rep.events), 2)
        self.assertTrue(rep.warnings)
        with jr.RunJournal(self.run_id, self.root) as j:
            self.assertTrue(j.warnings)
            e = j.append("task_state", task_id="t1", state="done")
        self.assertEqual(e["seq"], 3)
        rep = jr.replay(self.run_id, self.root)
        self.assertEqual([x["seq"] for x in rep.events], [1, 2, 3])
        self.assertEqual(rep.warnings, [])
        with open(os.path.join(self.root, self.run_id, jr.PARTIAL_FILE), "rb") as f:
            self.assertIn(b'"gate_dec', f.read())

    def test_mid_file_corruption_is_not_ignored(self):
        with jr.RunJournal(self.run_id, self.root) as j:
            for i in range(3):
                j.append("task_added", task_id=f"t{i}")
        lines = self._lines()
        cases = {
            "invalid_json": [lines[0], b"{broken", lines[2]],
            "edited_line": [lines[0], lines[1].replace(b"t1", b"tX"), lines[2]],
            "deleted_line": [lines[0], lines[2]],
            "not_object": [lines[0], b"[1]", lines[2]],
        }
        for name, content in cases.items():
            with self.subTest(name):
                with open(self._path(), "wb") as f:
                    f.write(b"\n".join(content) + b"\n")
                with self.assertRaises(jr.JournalCorrupt):
                    jr.replay(self.run_id, self.root)
                with self.assertRaises(jr.JournalCorrupt):
                    jr.RunJournal(self.run_id, self.root)

    def test_single_writer_lock(self):
        j = jr.RunJournal(self.run_id, self.root)
        try:
            with self.assertRaises(jr.JournalLocked):
                jr.RunJournal(self.run_id, self.root)
            # 読み取り専用の再生はロック中でも可能
            j.append("run_started")
            self.assertEqual(len(jr.replay(self.run_id, self.root).events), 1)
        finally:
            j.close()
        with jr.RunJournal(self.run_id, self.root) as j2:
            self.assertEqual(j2.event_count, 1)

    def test_failed_open_releases_lock(self):
        with jr.RunJournal(self.run_id, self.root) as j:
            j.append("run_started")
        with open(self._path(), "ab") as f:
            f.write(b"garbage\nmore\n")
        with self.assertRaises(jr.JournalCorrupt):
            jr.RunJournal(self.run_id, self.root)
        os.remove(self._path())
        with jr.RunJournal(self.run_id, self.root) as j:  # ロックが残っていない
            self.assertEqual(j.event_count, 0)

    def test_caps_fail_closed_but_run_finished_allowed(self):
        with jr.RunJournal(self.run_id, self.root, max_events=3) as j:
            for i in range(3):
                j.append("task_added", task_id=f"t{i}")
            before = self._lines()
            with self.assertRaises(jr.JournalFull):
                j.append("gate_decision", verdict="allow")
            self.assertEqual(self._lines(), before)  # 拒否された書込みは何も残さない
            j.append("run_finished", state="partial")
        self.assertEqual(len(jr.replay(self.run_id, self.root).events), 4)

        rid2 = jr.new_run_id()
        with jr.RunJournal(rid2, self.root, max_bytes=300) as j:
            j.append("task_added", task_id="a")
            with self.assertRaises(jr.JournalFull):
                j.append("task_added", note="x" * 400)

    def test_run_finished_once_bounded_and_terminal(self):
        with jr.RunJournal(self.run_id, self.root, max_events=1) as j:
            j.append("task_added", task_id="t0")
            with self.assertRaises(jr.JournalFull):  # 巨大な終了イベントは拒否され何も残さない
                j.append("run_finished", state="partial", errors=["x" * (jr.MAX_FINISH_BYTES + 1)])
            self.assertEqual(j.event_count, 1)
            j.append("run_finished", state="partial", errors=["compact"])  # 上限超過後でも一度は書ける
            for t in ("run_finished", "task_state"):  # 二度目以降・他種別も不可（終端）
                with self.assertRaises(jr.JournalError):
                    j.append(t, state="x")
            self.assertEqual(j.event_count, 2)
        with jr.RunJournal(self.run_id, self.root) as j:  # 再オープンしても終端のまま
            with self.assertRaises(jr.JournalError):
                j.append("task_state", state="x")
        self.assertEqual(len(jr.replay(self.run_id, self.root).events), 2)

    def test_secrets_are_masked_before_write(self):
        secret = "S3CR3T-cookie-value-9f2"
        with jr.RunJournal(self.run_id, self.root, known_secrets={secret}) as j:
            j.append("action_started", args={"note": f"sid={secret}", "nested": [f"v:{secret}"]},
                     summary="GET /x?token=abc123XYZ")
        with open(self._path(), "rb") as f:
            raw = f.read().decode("utf-8")
        self.assertNotIn(secret, raw)
        self.assertNotIn("abc123XYZ", raw)

    def test_write_failure_is_fail_closed(self):
        with jr.RunJournal(self.run_id, self.root) as j:
            j.append("run_started")
            with patch("core.autonomy.journal.os.fsync", side_effect=OSError("disk full")):
                with self.assertRaises(jr.JournalWriteError):
                    j.append("gate_decision", verdict="allow")
            self.assertEqual(j.event_count, 1)  # 記録できなかった判断は進行状態に含めない
            with self.assertRaises(jr.JournalWriteError):  # 以後は使えない
                j.append("gate_decision", verdict="allow")

    def test_explicit_event_id_is_accepted_and_validated(self):
        with jr.RunJournal(self.run_id, self.root) as j:
            e = j.append("task_added", event_id="evt_custom_123", task_id="t")
            self.assertEqual(e["event_id"], "evt_custom_123")
            for bad in ("", "a b", "x" * 80, "../x", 5):
                with self.assertRaises(ValueError):
                    j.append("task_added", event_id=bad, task_id="t")
            self.assertEqual(j.event_count, 1)

    def test_closed_journal_rejects_append(self):
        j = jr.RunJournal(self.run_id, self.root)
        j.close()
        j.close()  # 二重closeは無害
        with self.assertRaises(jr.JournalError):
            j.append("run_started")

    def test_concurrent_appends_keep_chain(self):
        with jr.RunJournal(self.run_id, self.root) as j:
            def work(n):
                for i in range(50):
                    j.append("task_state", task_id=f"{n}-{i}")
            ts = [threading.Thread(target=work, args=(n,)) for n in range(4)]
            [t.start() for t in ts]
            [t.join() for t in ts]
        rep = jr.replay(self.run_id, self.root)
        self.assertEqual([e["seq"] for e in rep.events], list(range(1, 201)))

    def test_replay_missing_journal(self):
        with self.assertRaises(FileNotFoundError):
            jr.replay(self.run_id, self.root)

    def test_unicode_and_event_json_shape(self):
        with jr.RunJournal(self.run_id, self.root) as j:
            j.append("gate_decision", detail="スコープ外: 許可リストにありません")
        line = self._lines()[0].decode("utf-8")
        self.assertIn("スコープ外", line)
        self.assertEqual(json.loads(line)["type"], "gate_decision")


if __name__ == "__main__":
    unittest.main()
