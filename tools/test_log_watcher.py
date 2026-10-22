"""tools/log_watcher.py(P4.3)の固定試験。一時ディレクトリで実ファイルのローテーション等を再現する。"""
import gzip
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

from tools import log_watcher
from tools.log_watcher import LogWatcher, normalize_log_line, parse_journal_target, parse_syslog, source_ip

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


class GzipArchiveTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def gz(self, data: bytes, name="access.log.2.gz"):
        p = os.path.join(self.d, name)
        with gzip.open(p, "wb") as f:
            f.write(data)
        return p

    def lines(self, w, **kw):
        return list(w.watch(interval=TICK, stop_fn=lambda: False, **kw))

    def test_gzip_is_read_once_even_in_watch_mode_and_counts_lines(self):
        w = LogWatcher(self.gz(b"a\nb\nlast-without-newline"))
        self.assertTrue(w.archive)
        self.assertEqual([x.rstrip("\n") for x in self.lines(w)], ["a", "b", "last-without-newline"])   # 追跡せず終了する
        self.assertEqual((w.stats["lines"], w.stats["archive_truncated"], w.stats["archive_error"]), (3, 0, ""))

    def test_concatenated_gzip_members_are_all_read(self):
        p = os.path.join(self.d, "multi.gz")
        with open(p, "wb") as f:
            f.write(gzip.compress(b"one\n") + gzip.compress(b"two\n"))
        self.assertEqual([x.strip() for x in self.lines(LogWatcher(p))], ["one", "two"])

    def test_corrupt_or_cut_archive_keeps_readable_lines_and_records_error(self):
        full = gzip.compress(b"".join(b"line %d\n" % i for i in range(5000)))
        p = os.path.join(self.d, "cut.gz")
        with open(p, "wb") as f:
            f.write(full[: len(full) // 2])                     # 途中で切れたアーカイブ
        w = LogWatcher(p)
        got = self.lines(w)
        self.assertTrue(0 < len(got) < 5000)
        self.assertEqual(w.stats["archive_error"], "EOFError")
        bad = os.path.join(self.d, "notgzip.gz")
        with open(bad, "wb") as f:
            f.write(b"plain text, not gzip\n")
        w = LogWatcher(bad)
        self.assertEqual(self.lines(w), [])
        self.assertEqual(w.stats["archive_error"], "BadGzipFile")

    def test_decompressed_size_and_line_length_are_capped(self):
        with mock.patch.object(log_watcher, "MAX_ARCHIVE_BYTES", 100):
            w = LogWatcher(self.gz(b"x" * 49 + b"\n" + b"y" * 49 + b"\n" + b"z" * 49 + b"\n"))
            self.assertEqual(len(self.lines(w)), 2)             # 3行目で合計が上限を超え、そこで終了
            self.assertEqual(w.stats["archive_truncated"], 1)
        with mock.patch.object(log_watcher, "_MAX_LINE_BYTES", 10):
            w = LogWatcher(self.gz(b"ok\n" + b"A" * 50 + b"\nnext\n"))
            self.assertEqual(len(self.lines(w)), 1)
            self.assertEqual(w.stats["archive_truncated"], 1)

    def test_defense_scans_a_gzip_archive_and_marks_partial_when_unreadable(self):
        from agents.monitor_agent import MonitorAgent
        from core.event_bus import EventBus
        from tools.fuzz_characterization import MockLLM

        def scan(path):
            bus = EventBus()
            agent = MonitorAgent(bus, MockLLM())
            with mock.patch.object(MonitorAgent, "_save_investigation", lambda *a, **k: None), \
                 mock.patch.object(MonitorAgent, "_record_telemetry", lambda *a, **k: None):
                agent._safe_run(log_path=path, watch_mode=True)         # .gzはwatch_modeでも1回通し
            return agent._last_scan_result, [e for e in bus.drain() if e.kind == "alert"]

        attack = b'10.0.0.5 - - [22/Oct/2026:01:00:00 +0900] "GET /?q=1 UNION SELECT 1,2 HTTP/1.1" 200 12 "-" "x"\n'
        res, alerts = scan(self.gz(attack * 3 + b"\n"))
        self.assertEqual(len(alerts), 1)                               # 同一IP・同一パターンは集約
        self.assertEqual(res.state, "completed", res.errors)
        full = gzip.compress(attack + b"".join(b"filler %d\n" % i for i in range(20000)))
        cut = os.path.join(self.d, "cut2.gz")
        with open(cut, "wb") as f:
            f.write(full[: len(full) // 2])
        res, alerts = scan(cut)
        self.assertEqual(len(alerts), 1)                               # 読めた分は検知する
        self.assertEqual(res.state, "partial")                         # 途中切れは検出0件の成功にしない
        self.assertTrue(any("gzipアーカイブを最後まで読めませんでした" in e for e in res.errors), res.errors)


class JournaldTest(unittest.TestCase):
    ATTACK = '{"MESSAGE":"GET /?q=1 UNION SELECT 1,2 from 10.0.0.5","_SYSTEMD_UNIT":"web.service","SYSLOG_IDENTIFIER":"web"}'

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.argv_file = os.path.join(self.d, "argv.txt")

    def fake(self, body: str):
        """journalctlの代わりの実行ファイル。受けた引数をargv.txtへ残す。"""
        path = os.path.join(self.d, "journalctl")
        with open(path, "w") as f:
            f.write(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{self.argv_file}"\n{body}\n')
        os.chmod(path, 0o755)
        return mock.patch("tools.log_watcher.shutil.which", lambda name: path if name == "journalctl" else None)

    def test_target_parsing_accepts_units_and_rejects_option_injection(self):
        self.assertIsNone(parse_journal_target("/var/log/auth.log"))
        self.assertEqual(parse_journal_target("journald"), "")
        self.assertEqual(parse_journal_target("journald:ssh.service"), "ssh.service")
        self.assertEqual(parse_journal_target("journald:user@1000.service"), "user@1000.service")
        for bad in ("journald:", "journald:-f", "journald:--vacuum-size=1", "journald:a b", "journald:a;rm", "journald:" + "a" * 101):
            with self.assertRaises(ValueError, msg=bad):
                parse_journal_target(bad)

    def test_single_pass_reads_recent_entries_with_fixed_arguments(self):
        with self.fake(f"echo '{self.ATTACK}'\necho '{{\"MESSAGE\":\"ok\"}}'"):
            w = LogWatcher("journald:web.service")
            got = list(w.watch(interval=TICK, stop_fn=lambda: False, single_pass=True))
        self.assertEqual(len(got), 2)
        self.assertEqual(w.stats["journal_error"], "")
        with open(self.argv_file) as fh:
            argv = fh.read().split()
        self.assertEqual(argv, ["--no-pager", "-o", "json", "-u", "web.service", "-n", "10000"])

    def test_message_byte_arrays_and_message_first_ordering(self):
        text, problem = normalize_log_line('{"_PID":"5","MESSAGE":[85,78,73,79,78,32,83,69,76,69,67,84],"x":{"a":1}}')
        self.assertEqual(problem, "")
        self.assertTrue(text.startswith("MESSAGE=UNION SELECT"), text)
        self.assertIn("x.a=1", text)

    def test_unreadable_journal_is_an_error_not_an_empty_success(self):
        from agents.monitor_agent import MonitorAgent
        from core.event_bus import EventBus
        from tools.fuzz_characterization import MockLLM
        body = 'echo "No journal files were opened due to insufficient permissions." >&2\nexit 1'
        with self.fake(body):
            w = LogWatcher("journald")
            self.assertEqual(list(w.watch(interval=TICK, stop_fn=lambda: False, single_pass=True)), [])
            self.assertIn("insufficient permissions", w.stats["journal_error"])
            agent = MonitorAgent(EventBus(), MockLLM())
            with mock.patch.object(MonitorAgent, "_save_investigation", lambda *a, **k: None), \
                 mock.patch.object(MonitorAgent, "_record_telemetry", lambda *a, **k: None):
                agent._safe_run(log_path="journald", watch_mode=False)
        res = agent._last_scan_result
        self.assertEqual(res.state, "partial")
        self.assertTrue(any("journaldを最後まで読めませんでした" in e for e in res.errors), res.errors)
        with mock.patch("tools.log_watcher.shutil.which", lambda n: None):
            w = LogWatcher("journald")
            self.assertEqual(list(w.watch(single_pass=True)), [])
            self.assertIn("見つかりません", w.stats["journal_error"])

    def test_follow_streams_new_entries_and_terminates_the_child_on_stop(self):
        with self.fake(f"echo '{self.ATTACK}'\nsleep 30"):
            w = LogWatcher("journald:web.service")
            stop = threading.Event()
            got = []
            t0 = time.time()
            for line in w.watch(interval=0.05, stop_fn=stop.is_set):
                got.append(line)
                stop.set()
            self.assertLess(time.time() - t0, 5)                      # sleep 30を待たない
        self.assertEqual(len(got), 1)
        with open(self.argv_file) as fh:
            argv = fh.read().split()
        self.assertEqual(argv[-3:], ["-f", "-n", "0"])
        self.assertEqual(w.stats["journal_error"], "")                 # terminateでの終了はエラーにしない

    def test_defense_detects_attack_in_a_journal_message(self):
        from agents.monitor_agent import MonitorAgent
        from core.event_bus import EventBus
        from tools.fuzz_characterization import MockLLM
        bus = EventBus()
        with self.fake(f"echo '{self.ATTACK}'"):
            agent = MonitorAgent(bus, MockLLM())
            with mock.patch.object(MonitorAgent, "_save_investigation", lambda *a, **k: None), \
                 mock.patch.object(MonitorAgent, "_record_telemetry", lambda *a, **k: None):
                agent._safe_run(log_path="journald:web.service", watch_mode=False)
        self.assertEqual(agent._last_scan_result.state, "completed", agent._last_scan_result.errors)
        self.assertEqual(len([e for e in bus.drain() if e.kind == "alert"]), 1)


class SyslogTest(unittest.TestCase):
    L3164 = "Oct 22 10:00:00 10.0.0.2 sshd[101]: Failed password for root from 203.0.113.9 port 4022 ssh2"
    L5424 = "<34>1 2026-10-22T10:00:00Z 10.0.0.2 sshd 101 ID47 - Failed password for root from 203.0.113.9 port 22 ssh2"

    def test_rfc3164_and_rfc5424_are_parsed_and_other_lines_are_not(self):
        a = parse_syslog(self.L3164)
        self.assertEqual((a["format"], a["host"], a["app"], a["pid"], a["pri"]), ("rfc3164", "10.0.0.2", "sshd", "101", None))
        self.assertTrue(a["msg"].startswith("Failed password"))
        b = parse_syslog(self.L5424)
        self.assertEqual((b["format"], b["pri"], b["app"], b["pid"], b["host"]), ("rfc5424", 34, "sshd", "101", "10.0.0.2"))
        self.assertEqual(parse_syslog("<13>Oct  2 01:02:03 h cron: job done")["pri"], 13)
        self.assertIsNone(parse_syslog('203.0.113.9 - - [22/Oct/2026:10:00:00 +0900] "GET / HTTP/1.1" 200 5'))
        self.assertIsNone(parse_syslog("random text"))
        self.assertIsNone(parse_syslog("<999>Oct 22 10:00:00 h app: x")["pri"])        # 範囲外のPRIは捨てる(行自体は読む)

    def test_source_ip_prefers_the_connection_source_over_the_header_host(self):
        self.assertEqual(source_ip(self.L3164), "203.0.113.9")                            # ホスト(10.0.0.2)ではない
        self.assertEqual(source_ip(self.L5424), "203.0.113.9")
        self.assertEqual(source_ip("Oct 22 10:00:00 h sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=198.51.100.7  user=root"),
                         "198.51.100.7")
        self.assertEqual(source_ip("Oct 22 10:00:00 h kernel: IN=eth0 SRC=192.0.2.8 DST=10.0.0.2 PROTO=TCP"), "192.0.2.8")
        self.assertEqual(source_ip("Oct 22 10:00:00 h app: connection reset 192.0.2.50"), "192.0.2.50")   # 標識なしは本文の最初
        self.assertEqual(source_ip("Oct 22 10:00:00 10.0.0.2 app: started"), "")        # 本文にIPが無ければ空(呼び出し側がフォールバック)

    def test_last_marker_wins_and_non_syslog_lines_never_use_markers(self):
        spoof = "Oct 22 10:00:00 h sshd[1]: Failed password for invalid user x from 9.9.9.9 from 203.0.113.9 port 22 ssh2"
        self.assertEqual(source_ip(spoof), "203.0.113.9")                                  # ユーザー名に仕込めない前半の標識より後ろを採る
        access = '203.0.113.9 - - [22/Oct/2026:10:00:00 +0900] "GET /?src=8.8.8.8 HTTP/1.1" 200 5 "-" "x"'
        self.assertEqual(source_ip(access), "")                                           # URLのsrc=で集約キーをずらされない

    def test_defense_alerts_each_attacker_behind_the_same_syslog_host(self):
        """以前はホストIP(10.0.0.2)が集約キーになり、別々の攻撃者2人のうち2人目のアラートが集約で消えた。"""
        from agents.monitor_agent import MonitorAgent
        from core.event_bus import EventBus
        from tools.fuzz_characterization import MockLLM
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "auth.log")
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.L3164 + "\n"
                    "Oct 22 10:00:03 10.0.0.2 sshd[102]: Failed password for admin from 198.51.100.7 port 5110 ssh2\n"
                    "Oct 22 10:00:05 10.0.0.2 sshd[103]: Failed password for root from 203.0.113.9 port 4023 ssh2\n")
        bus = EventBus()
        agent = MonitorAgent(bus, MockLLM())
        with mock.patch.object(MonitorAgent, "_save_investigation", lambda *a, **k: None), \
             mock.patch.object(MonitorAgent, "_record_telemetry", lambda *a, **k: None):
            agent._safe_run(log_path=p, watch_mode=False)
        alerts = [e for e in bus.drain(1000) if e.kind == "alert"]
        self.assertEqual(len(alerts), 2)                          # 攻撃者2人=2件。同じ攻撃者の3行目は集約される


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
