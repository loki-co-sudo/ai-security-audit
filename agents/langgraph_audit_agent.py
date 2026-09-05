"""
agents/langgraph_audit_agent.py — LangGraphを使った強化型監査エージェント

標準 AuditAgent の代替として、StateGraph による反復推論を実現する。
CRITICAL 発見時に自動的に深層解析ループを実行する。
"""

from __future__ import annotations
import os
from datetime import datetime
from agents.base_agent import BaseAgent
from agents.audit_agent import AuditAgent
from tools.report_generator import _findings_and_counts
from core.findings import ScanState

try:
    from core.orchestrator import build_audit_graph, AuditState, LANGGRAPH_AVAILABLE, _MAX_SURFACE_CHARS
except ImportError:
    LANGGRAPH_AVAILABLE = False
    _MAX_SURFACE_CHARS = 12000


class LangGraphAuditAgent(BaseAgent):
    """LangGraph StateGraph を使った自律型コード監査エージェント。"""

    def run(self, path: str) -> None:
        self._current_mode, self._current_target = "AUDIT", path
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
            self._finalize(state=ScanState.FAILED.value,
                           errors=["langgraphがインストールされていません"],
                           mode="AUDIT", target=path)
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
            final_state = graph.invoke(initial_state)
        except Exception as e:
            self._out(f"\n[ GRAPH ERROR ] {e}\n", "critical")
            self._log(f"LangGraph error: {e}")
            self._finalize(state=ScanState.FAILED.value, errors=[str(e)], mode="AUDIT", target=path)
            return

        self._log("LangGraph audit complete.")
        self._status("LangGraph audit complete.")

        # 構造化所見・実行状態(P1.1)。verify_pass相当のアンサンブル検証は行わない
        # ワークフローのため、Findingはcorroborated=False（observedのまま）とする。
        combined = "\n".join(final_state.get("outputs", []) or [])
        parsed, _counts = _findings_and_counts("CODE AUDIT", combined)
        findings = self._findings_from_markers(parsed, corroborated=False)
        was_truncated = len(final_state.get("source_code", "") or "") > _MAX_SURFACE_CHARS
        coverage = AuditAgent._build_coverage(path, was_truncated)
        state, errors = self._determine_state(final_state, combined)
        self._finalize(state=state, errors=errors, findings=findings, coverage=coverage,
                       mode="AUDIT", target=path)

    def _determine_state(self, final_state: dict, combined_text: str) -> tuple[str, list[str]]:
        """実行状態(completed/partial/failed/cancelled)を判定する（P1.1）。

        load_codeノードはOSErrorを内部で捕捉しsource_codeを空文字のまま次工程へ
        進める設計であり、かつSTOPで中断された場合もsource_code/phaseが同様に
        空・"stopped"のままになりうる（orchestrator.load_code/surface_scan参照）。
        final_stateの内容だけでは「読み込み失敗」と「STOPによる中断」を区別できない
        ため、エージェント自身のis_stopped()を優先判定に使い誤ってcompleted/failedに
        しないようにする。
        """
        errors: list[str] = []
        if not final_state.get("source_code"):
            if self.is_stopped():
                return ScanState.CANCELLED.value, errors
            errors.append("ファイル読み込みに失敗しました（source_codeが空）")
            return ScanState.FAILED.value, errors
        if self.is_stopped() or final_state.get("phase") == "stopped":
            return ScanState.CANCELLED.value, errors
        if not combined_text.strip():
            errors.append("AI推論が空応答でした（LLM呼び出し失敗の可能性）")
            return ScanState.PARTIAL.value, errors
        return ScanState.COMPLETED.value, errors
