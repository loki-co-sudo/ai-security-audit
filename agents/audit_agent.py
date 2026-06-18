"""
agents/audit_agent.py — コードセキュリティ監査エージェント

ソースコードを読み込み、LLMがセマンティクス解析で未知の脆弱性を推論する。
"""

from __future__ import annotations
import os
import re
import time
from agents.base_agent import BaseAgent
from tools import cve_client

STEPS = [
    "ターゲットファイルを読み込み中",
    "コード構造を解析中 (AST/CFG)",
    "AIエージェントが論理バグを推論中",
    "脆弱性情報をストリーミング中",
    "深刻度スコアを評価中",
    "CVEデータベース照合中",
    "監査レポートを最終化中",
]

SYSTEM_PROMPT = """You are an elite white-hat penetration tester and code auditor specializing in discovering \
*novel, unknown vulnerabilities* that do NOT appear in any CVE database.

Analyze the provided code focusing on:

## PRIORITY 1 — Authentication & Session Logic Flaws
- Authentication bypass through business logic errors (NOT injection alone)
- Session fixation, token prediction, insecure token validation
- Privilege escalation via logic flaws

## PRIORITY 2 — Business Logic Vulnerabilities
- Race conditions and TOCTOU (Time-of-Check-Time-of-Use) flaws
- State machine violations, step-skipping in workflows
- Negative number / integer overflow abuse

## PRIORITY 3 — Architectural & Design Weaknesses
- Unsafe trust assumptions about caller inputs
- Missing security controls at API/module boundaries
- Indirect injection flows that scanners miss

For EVERY vulnerability found, use this EXACT format:

---VULN_START---
NAME: [Descriptive vulnerability name]
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW]
CWE: [CWE-XXX or "Novel — No CVE/CWE Match"]
LINES: [affected line numbers]
SNIPPET:
```
[exact vulnerable code]
```
ATTACK:
[Step-by-step exploitation scenario]
FIX:
```
[corrected code]
```
---VULN_END---

Think deeply. Find the semantic gap between *intent* and *implementation*."""


class AuditAgent(BaseAgent):

    def run(self, path: str) -> None:
        self.bus.clear()

        # Step 0: ファイル読み込み
        self._step(0, "running")
        self._log(f"Reading: {path}")
        time.sleep(0.2)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except OSError as e:
            self._log(f"File error: {e}")
            self._step(0, "error")
            self._done(error=True)
            return
        lines = source.count("\n") + 1
        self._log(f"Loaded {lines} lines ({len(source)} bytes)")
        self._step(0, "done")

        # Step 1: ヘッダー表示
        self._step(1, "running")
        self._out(
            "╔══════════════════════════════════════════════════════╗\n"
            "║      CODE AUDIT — AUTONOMOUS VULNERABILITY SCAN      ║\n"
            "╚══════════════════════════════════════════════════════╝\n\n",
            "header",
        )
        self._out(f"  TARGET : {path}\n", "dim")
        self._out(f"  LINES  : {lines}\n", "dim")
        self._out(f"  MODEL  : {self.llm.model}\n\n", "dim")
        time.sleep(0.3)
        self._step(1, "done")

        # Step 2-3: LLM 推論（ストリーミング）
        if self.is_stopped(): return
        self._step(2, "running")
        self._step(3, "running")
        self._status(f"AI が {os.path.basename(path)} を深層解析中 ...")
        self._log("Connecting to LLM ...")
        self._out("─" * 56 + "\n", "sep")
        self._out("  AI REASONING OUTPUT  (streaming)\n", "section")
        self._out("─" * 56 + "\n\n", "sep")

        full = self._stream_llm([
            self.llm.system(SYSTEM_PROMPT),
            self.llm.user(
                f"Analyze this code for unknown and logic-based security vulnerabilities:\n\n"
                f"```python\n{source}\n```"
            ),
        ])
        self._step(3, "done")
        self._step(2, "done")

        # Step 4: 深刻度集計
        self._step(4, "running")
        counts = {s: len(re.findall(rf"SEVERITY:\s*{s}\b", full, re.I))
                  for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        time.sleep(0.2)
        self._step(4, "done")

        # Step 5: CVEデータベース照合
        self._step(5, "running")
        cwe_nums = list(dict.fromkeys(re.findall(r'CWE-(\d+)', full)))[:4]
        if cwe_nums and not self.is_stopped():
            self._out("\n" + "─" * 56 + "\n", "sep")
            self._out("  CVE CORRELATION  (NVD Database)\n", "section")
            self._out("─" * 56 + "\n\n", "sep")
            for cwe_num in cwe_nums:
                if self.is_stopped():
                    break
                cwe_id = f"CWE-{cwe_num}"
                self._out(f"  Searching {cwe_id} ...\n", "dim")
                time.sleep(6.5)  # NVD レート制限: 5 req/30s
                results = cve_client.search_by_cwe(cwe_id)
                self._out(f"\n  ● {cwe_id} — 関連CVE:\n", "label")
                self._out(cve_client.format_results(results), "code")
                self._out("\n", "")
        else:
            self._out("\n  (CWE識別子なし — CVE照合スキップ)\n", "dim")
            time.sleep(0.3)
        self._step(5, "done")

        # Step 6: 最終化
        self._step(6, "running")
        time.sleep(0.2)
        self._step(6, "done")

        total = sum(counts.values())
        self._stats(counts)
        self._out("\n\n" + "═" * 56 + "\n", "sep")
        self._out(f"  SCAN COMPLETE  |  {total} vulnerabilities detected\n", "green")
        self._out("═" * 56 + "\n", "sep")
        self._log(f"Audit complete. {total} issues found.")
        self._status(f"Audit complete — {total} vulnerabilities detected.")
        self._done()
