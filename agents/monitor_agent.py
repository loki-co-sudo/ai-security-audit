"""
agents/monitor_agent.py — リアルタイム防御監視エージェント

ログファイルを継続監視し、AIが攻撃パターンを検知・分類・解説する。
"""

from __future__ import annotations
import re
import time
from datetime import datetime
from collections import deque
from agents.base_agent import BaseAgent
from tools.log_watcher import LogWatcher
from core.settings import (
    ATTACK_PATTERNS, LOG_BATCH_SIZE, LOG_MAX_CONTEXT,
    LOG_WATCH_INTERVAL,
)

SYSTEM_PROMPT = """You are an elite blue team SOC analyst and incident responder. \
You are analyzing real-time log entries for signs of ongoing attacks.

Your task:
1. **Classify the threat** type (SQL Injection, XSS, LFI, RFI, Command Injection, Brute Force, Scanner, APT, etc.)
2. **Assess severity** (CRITICAL if active exploitation, HIGH if probe with high success likelihood, etc.)
3. **Identify attacker TTPs** (Tactics, Techniques, Procedures) using MITRE ATT&CK framework
4. **Timeline the attack** — is this part of a larger campaign?
5. **Suggest immediate defensive actions**

Output format:

---THREAT_START---
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW]
THREAT_TYPE: [classification]
MITRE_TTP: [T-code if applicable]
ATTACKER_IP: [if identifiable]
TIMELINE: [Is this isolated or part of a sequence?]
ANALYSIS:
[Detailed threat analysis]
IMMEDIATE_ACTIONS:
[Specific steps to take right now]
---THREAT_END---

Be concise but thorough. Flag false positives explicitly."""


class MonitorAgent(BaseAgent):

    def run(self, log_path: str, watch_mode: bool = True) -> None:
        self.bus.clear()
        self._status(f"監視開始: {log_path}")

        self._out(
            "╔══════════════════════════════════════════════════════╗\n"
            "║      DEFENSE MODE — AUTONOMOUS THREAT MONITOR        ║\n"
            "╚══════════════════════════════════════════════════════╝\n\n",
            "header",
        )
        self._out(f"  LOG SOURCE : {log_path}\n", "dim")
        self._out(f"  MODE       : {'CONTINUOUS WATCH' if watch_mode else 'SINGLE PASS'}\n", "dim")
        self._out(f"  STARTED    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n", "dim")

        watcher = LogWatcher(log_path)
        context_buffer: deque[str] = deque(maxlen=LOG_MAX_CONTEXT)
        batch_buffer:   list[str]  = []
        total_alerts   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        last_ai_call   = 0.0
        AI_COOLDOWN    = 15.0  # 連続AI呼び出し間隔（秒）

        self._out("─" * 56 + "\n", "sep")
        self._out("  MONITORING STARTED — waiting for log entries ...\n", "section")
        self._out("─" * 56 + "\n\n", "sep")

        try:
            for line in watcher.watch(
                interval=LOG_WATCH_INTERVAL,
                stop_fn=self.is_stopped,
                single_pass=not watch_mode,
            ):
                if self.is_stopped():
                    break

                line = line.rstrip()
                if not line:
                    continue

                context_buffer.append(line)
                matched = self._pattern_match(line)

                if matched:
                    batch_buffer.append(line)
                    # パターンマッチ時にアラートを即時表示
                    for pattern_name in matched:
                        sev = self._quick_severity(pattern_name)
                        self._out(
                            f"  [{datetime.now().strftime('%H:%M:%S')}] "
                            f"[{sev:8}] {pattern_name:20} — {line[:80]}\n",
                            sev.lower(),
                        )
                        total_alerts[sev] = total_alerts.get(sev, 0) + 1
                    self._stats(total_alerts)

                # バッチサイズ到達 or タイムアウト → AI分析
                now = time.time()
                if (len(batch_buffer) >= LOG_BATCH_SIZE or
                        (batch_buffer and now - last_ai_call > AI_COOLDOWN)):
                    self._analyze_batch(batch_buffer, list(context_buffer))
                    batch_buffer.clear()
                    last_ai_call = now

        except Exception as e:
            self._log(f"Monitor error: {e}")

        # 残バッファを最終分析
        if batch_buffer and not self.is_stopped():
            self._analyze_batch(batch_buffer, list(context_buffer))

        total = sum(total_alerts.values())
        self._out("\n" + "═" * 56 + "\n", "sep")
        self._out(f"  MONITORING ENDED  |  {total} alerts generated\n",
                  "critical" if total_alerts.get("CRITICAL", 0) else "green")
        self._out("═" * 56 + "\n", "sep")
        self._log(f"Monitor stopped. Total alerts: {total}")
        self._status(f"監視終了 — {total} alerts.")
        self._done()

    def _pattern_match(self, line: str) -> list[str]:
        """ログ行に攻撃パターンが含まれるか検査。一致したパターン名を返す。"""
        matched = []
        for name, pattern in ATTACK_PATTERNS.items():
            if re.search(pattern, line):
                matched.append(name)
        return matched

    def _quick_severity(self, pattern_name: str) -> str:
        """パターン名から暫定深刻度を返す。AI分析前の速報用。"""
        critical = {"CMD_INJECTION", "SSRF"}
        high     = {"SQL_INJECTION", "LFI_RFI", "XSS"}
        medium   = {"BRUTE_FORCE", "PATH_TRAVERSAL", "SCANNER"}
        if pattern_name in critical: return "CRITICAL"
        if pattern_name in high:     return "HIGH"
        if pattern_name in medium:   return "MEDIUM"
        return "LOW"

    def _analyze_batch(self, lines: list[str], context: list[str]) -> None:
        """バッチログをLLMに送り、深層分析を実施する。"""
        self._out("\n" + "─" * 56 + "\n", "sep")
        self._out(f"  AI THREAT ANALYSIS  ({len(lines)} suspicious entries)\n", "section")
        self._out("─" * 56 + "\n\n", "sep")
        self._log(f"Sending {len(lines)} entries to AI ...")

        recent_ctx = "\n".join(context[-30:]) if len(context) > 30 else "\n".join(context)
        suspect    = "\n".join(lines)

        self._stream_llm([
            self.llm.system(SYSTEM_PROMPT),
            self.llm.user(
                f"RECENT LOG CONTEXT (last 30 lines):\n```\n{recent_ctx}\n```\n\n"
                f"SUSPICIOUS ENTRIES REQUIRING ANALYSIS:\n```\n{suspect}\n```\n\n"
                f"Analyze these log entries for threat classification and severity."
            ),
        ])
        self._out("\n", "")
