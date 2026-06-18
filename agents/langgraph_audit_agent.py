"""
agents/langgraph_audit_agent.py — LangGraphを使った強化型監査エージェント

標準 AuditAgent の代替として、StateGraph による反復推論を実現する。
CRITICAL 発見時に自動的に深層解析ループを実行する。
"""

from __future__ import annotations
import os
from datetime import datetime
from agents.base_agent import BaseAgent

try:
    from core.orchestrator import build_audit_graph, AuditState, LANGGRAPH_AVAILABLE
except ImportError:
    LANGGRAPH_AVAILABLE = False


class LangGraphAuditAgent(BaseAgent):
    """LangGraph StateGraph を使った自律型コード監査エージェント。"""

    def run(self, path: str) -> None:
        self.bus.clear()
        self._status(f"[LangGraph] {os.path.basename(path)} を解析中 ...")

        self._out(
            "╔══════════════════════════════════════════════════════╗\n"
            "║   CODE AUDIT — LANGGRAPH ENHANCED ANALYSIS MODE     ║\n"
            "╚══════════════════════════════════════════════════════╝\n\n",
            "header",
        )
        self._out(f"  TARGET : {path}\n", "dim")
        self._out(f"  MODEL  : {self.llm.model}\n", "dim")
        self._out(f"  ENGINE : LangGraph StateGraph + 条件付き深層解析ループ\n", "dim")
        self._out(f"  STARTED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n", "dim")

        if not LANGGRAPH_AVAILABLE:
            self._out(
                "[ ERROR ] langgraph がインストールされていません。\n"
                "          pip install langgraph を実行後、再起動してください。\n",
                "critical",
            )
            self._log("langgraph not available.")
            self._done(error=True)
            return

        try:
            graph = build_audit_graph(self.llm, self.bus, self.is_stopped)
            initial_state: AuditState = {
                "source_path":     path,
                "source_code":     "",
                "outputs":         [],
                "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "iteration":       0,
                "phase":           "init",
            }
            graph.invoke(initial_state)
        except Exception as e:
            self._out(f"\n[ GRAPH ERROR ] {e}\n", "critical")
            self._log(f"LangGraph error: {e}")
            self._done(error=True)
            return

        self._log("LangGraph audit complete.")
        self._status("LangGraph audit complete.")
        self._done()
