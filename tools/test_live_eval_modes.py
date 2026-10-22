"""tools/live_eval_modes.py の非LLM部分の固定試験: 正解データ・スコアラー・スクリプトしたLLMでのエンドツーエンド。"""
import json
import re
import unittest
from unittest import mock

from tools import live_eval_modes as m
from tools.fuzz_characterization import MockLLM


class FakeLLM(MockLLM):
    """CountingLLMの代わり(呼出し回数・文字数を数え、決めた応答を返す)。通信しない。"""
    calls = limit = chars_in = chars_out = 0
    reply = ""

    def stream(self, messages, on_chunk, on_done=None, on_error=None, max_tokens=None):
        self.calls += 1
        self.chars_in += sum(len(x["content"]) for x in messages)
        text = self.reply_for("\n".join(x["content"] for x in messages))
        self.chars_out += len(text)
        on_chunk(text)
        if on_done:
            on_done()
        return text

    def reply_for(self, prompt):
        return self.reply


def threat(ip, ttp="T1190"):
    return (f"---THREAT_START---\nSEVERITY: HIGH\nTHREAT_TYPE: x\nMITRE_TTP: {ttp}\nATTACKER_IP: {ip}\nTIMELINE: t\n"
            "ANALYSIS:\na\nIMMEDIATE_ACTIONS:\nb\n---THREAT_END---\n")


def fake_factory(reply):
    def make(model, max_calls, timeout):
        llm = FakeLLM()
        llm.reply = reply
        llm.limit = max_calls
        return llm
    return make


class FixtureTest(unittest.TestCase):
    def test_defense_truth_is_consistent(self):
        with open(m.TRUTH_DEFENSE, encoding="utf-8") as f:
            t = json.load(f)
        ips_in_log = {ip for line in t["log_lines"] for ip in m._IP.findall(line.split('"')[0] if '"' in line else line)}
        self.assertTrue(set(t["attackers"]) <= ips_in_log)                           # 攻撃者は全員ログに出る
        self.assertFalse(set(t["attackers"]) & set(t["benign_ips"]))
        self.assertTrue(any("sshd" in line and "10.0.0.2" in line for line in t["log_lines"]))   # ホストがIPのsyslog(誤帰属の罠)

    def test_attack_truth_has_tempting_closed_ports(self):
        with open(m.TRUTH_ATTACK, encoding="utf-8") as f:
            t = json.load(f)
        open_ports = {p["port"] for p in t["open_ports"]}
        self.assertFalse(open_ports & set(t["closed_but_tempting_ports"]))


class ScorerTest(unittest.TestCase):
    def test_defense_scoring(self):
        with open(m.TRUTH_DEFENSE, encoding="utf-8") as f:
            t = json.load(f)
        fs = [{"location": "203.0.113.9 (ログ上の送信元)", "rule_id": "T1190, T1595.003"},
              {"location": "10.0.0.2", "rule_id": "N/A"},                      # ホスト自身=誤帰属
              {"location": "198.51.100.7", "rule_id": "T1110"}]
        s = m.score_defense(fs, [], t)
        self.assertEqual(s["attackers_found"], ["198.51.100.7", "203.0.113.9"])
        self.assertEqual(s["attacker_recall"], round(2 / 3, 3))
        self.assertEqual(s["false_attributions"], ["10.0.0.2"])
        self.assertEqual((s["mitre_known"], s["mitre_unverified"]), (2, 1))      # T1190,T1110は収録済み・T1595.003は未確認
        self.assertTrue(m.score_defense([], ["AI脅威分析の一部が脅威マーカー(---THREAT_START---)を含まず"], t)["format_note"])

    def test_fuzz_scoring_distinguishes_vulnerable_and_safe_pages(self):
        with open(m.TRUTH_FUZZ, encoding="utf-8") as f:
            t = json.load(f)
        fs = [{"location": "http://127.0.0.1:1/search q", "description": "Reflected XSS in q"},
              {"location": "http://h/escaped?q=1", "description": "XSS in q"}]      # エスケープ済みページ=正常
        s = m.score_fuzz(fs, t)
        self.assertIn("XSS /search q", s["tp"])
        self.assertIn("XSS /escaped q", s["fp"])
        self.assertIn("SQLI /item id", s["fn"])
        self.assertTrue(0 < s["recall"] < 1)
        self.assertFalse(m._mentions("http://h/search-old?q", "/search", "q"))      # 別のpathに一致しない
        self.assertFalse(m._mentions("http://h:80/api/search?q=1", "/search", "q"))
        self.assertTrue(m._mentions("http://127.0.0.1:8080/search?q=1", "/search", "q"))   # ポート番号の直後でも一致
        self.assertTrue(m._mentions("`/search` の q パラメータ", "/search", "q"))

    def test_attack_scoring_flags_fabricated_ports_only_in_evidence(self):
        with open(m.TRUTH_ATTACK, encoding="utf-8") as f:
            t = json.load(f)
        fs = [{"location": "22/tcp open OpenSSH 8.4", "description": "SSH", "analysis": ""},
              {"location": "6379/tcp open Redis", "description": "Redis exposed", "analysis": ""},      # 観測していない
              {"location": "HTTP応答ヘッダー欠落", "description": "ポート 3306 の MySQL", "analysis": "ポート 21 は閉じている"}]
        s = m.score_attack(fs, t)
        self.assertEqual(s["fabricated_ports"], [6379])                       # 説明文(description/analysis)の言及は捏造と数えない
        self.assertEqual(s["covered_ports"], [22, 3306])
        self.assertEqual(s["port_coverage"], round(2 / 3, 3))
        by_name = m.score_attack([{"location": "Server: nginx/1.18.0", "description": "ヘッダー欠落", "analysis": ""}], t)
        self.assertEqual(by_name["covered_ports"], [80])                      # 番号が無くてもサービス名で取り上げたと数える


class EndToEndTest(unittest.TestCase):
    """スクリプトしたLLMで、各モードのパイプライン(入力生成→エージェント→採点)を通す。通信・費用なし。"""

    def run_mode(self, mode, reply):
        with mock.patch.object(m, "_llm", fake_factory(reply)):
            return m.evaluate_mode(mode, "fake", 1, 5)

    def test_defense_pipeline(self):
        out = self.run_mode("defense", threat("203.0.113.9") + threat("192.0.2.44", "T1059") + threat("198.51.100.200", "N/A"))
        r = out["results"][0]
        self.assertEqual(r["attackers_found"], ["192.0.2.44", "203.0.113.9"])
        self.assertEqual(r["false_attributions"], ["198.51.100.200"])           # 通常の閲覧者を攻撃元にした
        self.assertEqual(out["runs_invalid"], 0)

    def test_attack_pipeline_uses_fixed_recon_and_sends_no_network(self):
        reply = ("---FINDING_START---\nTITLE: SSH\nSEVERITY: LOW\nCATEGORY: Network\nEVIDENCE: 22/tcp OpenSSH_8.4p1\n"
                 "ATTACK_SCENARIO:\nx\nRECOMMENDED_ACTION:\ny\n---FINDING_END---\n"
                 "---FINDING_START---\nTITLE: Redis\nSEVERITY: HIGH\nCATEGORY: Network\nEVIDENCE: 6379/tcp open\n"
                 "ATTACK_SCENARIO:\nx\nRECOMMENDED_ACTION:\ny\n---FINDING_END---\n")
        import socket
        with mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network used")):
            out = self.run_mode("attack", reply)
        r = out["results"][0]
        self.assertEqual((r["fabricated_ports"], r["covered_ports"]), ([6379], [22]))
        self.assertEqual(r["state"], "completed", r["errors"])
        self.assertEqual(r["n_findings"], 2)

    def test_empty_output_is_invalid_not_a_zero_score(self):
        out = self.run_mode("defense", "")
        self.assertTrue(out["results"][0]["invalid"])
        self.assertEqual(out["attacker_recall_per_run"], [None])
        self.assertEqual(out["runs_invalid"], 1)

    def test_fuzz_pipeline(self):
        reply = ("---VULN_START---\nNAME: Reflected XSS in q\nSEVERITY: HIGH\nCWE: CWE-79\nLINES: /search q\nSNIPPET:\n```\nx\n```\n"
                 "ATTACK:\ny\nFIX:\n```\nz\n```\n---VULN_END---")
        out = self.run_mode("fuzz", reply)
        r = out["results"][0]
        self.assertIn("XSS /search q", r["tp"])
        self.assertEqual(r["fp"], [])


if __name__ == "__main__":
    unittest.main()
