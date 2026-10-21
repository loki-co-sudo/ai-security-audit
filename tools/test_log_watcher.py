"""tools/log_watcher.py(P4.3)の固定試験。一時ディレクトリで実ファイルのローテーション等を再現する。"""
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

from tools.log_watcher import LogWatcher

TICK = 0.01


class Harness:
    """別スレッドでwatchし、受信行を集める。"""

    def __init__(self, path):
        self.w = LogWatcher(path)
        self.lines, self.stop, self.error = [], threading.Event(), None
        self.t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            for line in self.w.watch(interval=TICK, stop_fn=self.stop.is_set):
                self.lines.append(line)
        except Exception as e:      # noqa: BLE001
            self.error = e

    def __enter__(self):
        self.t.start()
        time.sleep(0.1)            # 初期位置(EOF)の確定を待つ
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.t.join(2)

    def wait(self, n, timeout=3.0):
        end = time.time() + timeout
        while time.time() < end and len(self.lines) < n:
            time.sleep(TICK)
        return self.lines


def append(path, data, mode="ab"):
    with open(path, mode) as f:
        f.write(data if isinstance(data, bytes) else data.encode())


class WatcherTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.p = os.path.join(self.d, "access.log")
        append(self.p, "old-line\n", "wb")

    def test_new_lines_only_and_existing_lines_are_skipped(self):
        with Harness(self.p) as h:
            append(self.p, "a\nb\n")
            self.assertEqual(h.wait(2), ["a\n", "b\n"])

    def test_partial_last_line_is_held_until_complete(self):
        with Harness(self.p) as h:
            append(self.p, "first\nsecond-par")
            self.assertEqual(h.wait(1), ["first\n"])
            time.sleep(0.15)
            self.assertEqual(h.lines, ["first\n"])                       # 書き込み途中の行を分割して返さない
            append(self.p, "t-done\n")
            self.assertEqual(h.wait(2), ["first\n", "second-part-done\n"])

    def test_multibyte_char_split_across_reads_is_not_corrupted(self):
        raw = "日本語ログ\n".encode()
        with Harness(self.p) as h:
            append(self.p, raw[:4])
            time.sleep(0.1)
            append(self.p, raw[4:])
            self.assertEqual(h.wait(1), ["日本語ログ\n"])

    def test_rename_create_reads_the_rest_of_the_old_file_then_the_new_one(self):
        with Harness(self.p) as h:
            append(self.p, "before\n")
            h.wait(1)
            append(self.p, "late-old\n")                                  # ローテーション直前に旧ファイルへ書かれた行
            os.rename(self.p, self.p + ".1")
            append(self.p, "new-1\nnew-2\n", "wb")
            self.assertEqual(h.wait(4), ["before\n", "late-old\n", "new-1\n", "new-2\n"])
            self.assertEqual(h.w.stats["rotations"], 1)

    def test_rename_with_partial_old_line_flushes_it_as_a_complete_line(self):
        with Harness(self.p) as h:
            append(self.p, "unterminated")
            os.rename(self.p, self.p + ".1")
            append(self.p, "next\n", "wb")
            self.assertEqual(h.wait(2), ["unterminated\n", "next\n"])
            self.assertEqual(h.w.stats["partial_flushed"], 1)

    def test_copytruncate_restarts_from_the_beginning(self):
        with Harness(self.p) as h:
            append(self.p, "x1\nx2\nx3\n")
            h.wait(3)
            with open(self.p, "r+b") as f:
                f.truncate(0)
            append(self.p, "y1\n")
            self.assertEqual(h.wait(4), ["x1\n", "x2\n", "x3\n", "y1\n"])
            self.assertEqual(h.w.stats["truncations"], 1)

    def test_temporary_absence_continues_and_recovers(self):
        with Harness(self.p) as h:
            append(self.p, "k1\n")
            h.wait(1)
            os.rename(self.p, self.p + ".gone")
            time.sleep(0.15)
            self.assertIsNone(h.error)                                    # 一時不在で例外終了しない
            self.assertGreater(h.w.stats["missing_polls"], 0)
            append(self.p, "k2\n", "wb")
            self.assertEqual(h.wait(2), ["k1\n", "k2\n"])

    def test_stop_ends_the_generator_promptly(self):
        h = Harness(self.p)
        with h:
            pass
        self.assertFalse(h.t.is_alive())
        self.assertIsNone(h.error)

    def test_missing_file_at_start_is_an_error_and_single_pass_reads_everything(self):
        with self.assertRaises(FileNotFoundError):
            list(LogWatcher(os.path.join(self.d, "none.log")).watch(single_pass=True))
        append(self.p, "no-newline-at-end")
        self.assertEqual(list(LogWatcher(self.p).watch(single_pass=True)), ["old-line\n", "no-newline-at-end"])

    def test_invalid_utf8_is_replaced_not_fatal(self):
        with Harness(self.p) as h:
            append(self.p, b"bad-\xff\xfe-bytes\n")
            (line,) = h.wait(1)
            self.assertIn("bad-", line)
            self.assertIn("�", line)


class NormalizeTest(unittest.TestCase):
    def test_plain_text_is_unchanged(self):
        from tools.log_watcher import normalize_log_line
        self.assertEqual(normalize_log_line('1.2.3.4 - - "GET / HTTP/1.1" 200  \n'), ('1.2.3.4 - - "GET / HTTP/1.1" 200', ""))

    def test_jsonl_is_flattened_so_payloads_in_any_field_are_visible(self):
        from tools.log_watcher import normalize_log_line
        text, problem = normalize_log_line('{"ts":"t","remote_addr":"10.0.0.9","req":{"path":"/a","q":"1 UNION SELECT 2"},'
                                           '"tags":["x","../../etc/passwd"]}')
        self.assertEqual(problem, "")
        self.assertTrue(text.startswith("10.0.0.9 "))                      # IPは先頭(アラートの集約キーに使われる)
        for needle in ("req.q=1 UNION SELECT 2", "tags.1=../../etc/passwd", "req.path=/a"):
            self.assertIn(needle, text)

    def test_invalid_json_is_reported_but_kept_as_raw_text_for_detection(self):
        from tools.log_watcher import normalize_log_line
        for raw in ('{"a": 1, "q": "UNION SELECT', '{not json}', '{"a":1}}', '[1,2]'):
            text, problem = normalize_log_line(raw)
            if raw.startswith("{"):
                self.assertEqual((text, problem), (raw, "invalid_json"), raw)
        self.assertEqual(normalize_log_line("{}")[1], "")                  # 空オブジェクトは有効なJSON
        long_text, _ = normalize_log_line(json.dumps({"k": "x" * 10000}))
        self.assertLessEqual(len(long_text), 4000)


class MitreTest(unittest.TestCase):
    def test_unknown_ids_are_never_confirmed_tags(self):
        from core import mitre
        self.assertEqual(mitre.format_ref("T1190"), "T1190")
        self.assertEqual(mitre.format_ref("t1190, T1059.004"), "T1190, T1059.004")
        self.assertEqual(mitre.format_ref("T9999"), "未確認:T9999")
        self.assertEqual(mitre.format_ref("T1190 and T0000.999"), "T1190, 未確認:T0000.999")
        for junk in ("", "N/A", "[T-code if applicable]", "unknown", None):
            self.assertEqual(mitre.format_ref(junk), "", junk)

    def test_report_parser_applies_the_check_only_to_mitre_field(self):
        from tools.report_generator import _parse
        block = "---THREAT_START---\nSEVERITY: HIGH\nTHREAT_TYPE: SQLi\nMITRE_TTP: T1190, T4242\n---THREAT_END---"
        (f,) = _parse(block, "---THREAT_START---", "---THREAT_END---")
        self.assertEqual(f["ref"], "T1190, 未確認:T4242")
        vuln = "---VULN_START---\nNAME: x\nSEVERITY: HIGH\nCWE: CWE-89\nMITRE_TTP: T9999\n---VULN_END---"
        (g,) = _parse(vuln, "---VULN_START---", "---VULN_END---")
        self.assertEqual(g["ref"], "CWE-89")


class MonitorIntegrationTest(unittest.TestCase):
    def test_jsonl_attack_is_detected_and_invalid_lines_are_counted(self):
        from agents.monitor_agent import MonitorAgent
        from core.event_bus import EventBus
        from tools.fuzz_characterization import MockLLM
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "app.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            f.write('{"remote_addr":"10.0.0.5","path":"/x","q":"1 UNION SELECT 1,2"}\n'
                    '{"remote_addr":"10.0.0.6","path":"/ok"}\n'
                    '{"broken": "UNION SELECT\n')
        bus = EventBus()
        agent = MonitorAgent(bus, MockLLM())
        with mock.patch.object(MonitorAgent, "_save_investigation", lambda *a, **k: None), \
             mock.patch.object(MonitorAgent, "_record_telemetry", lambda *a, **k: None):
            agent._safe_run(log_path=p, watch_mode=False)
        res = agent._last_scan_result
        self.assertTrue(any("JSONLとして不正な行が1件" in e for e in res.errors), res.errors)
        alerts = [e for e in bus.drain() if e.kind == "alert"]
        self.assertEqual(len(alerts), 2)               # 正常JSONL内の攻撃と、不正JSON行に紛れた攻撃の両方


if __name__ == "__main__":
    unittest.main()
