"""
agents/langgraph_audit_agent.py — LangGraphを使った強化型監査エージェント

標準 AuditAgent の代替として、StateGraph による反復推論を実現する。
CRITICAL 発見時に自動的に深層解析ループを実行する。
"""

from __future__ import annotations
import os
from datetime import datetime
from agents.base_agent import BaseAgent, unparsed_output_note
from agents.audit_agent import AuditAgent, ast_scan, save_ast_evidence, save_project_ast_evidence, _EVIDENCE_INSTRUCTION
import core.config as config
from core.evidence_store import EvidenceStore
from tools.report_generator import _findings_and_counts
from core.findings import CoverageItem, CoverageStatus, ScanState

try:
    from core.orchestrator import build_audit_graph, AuditState, LANGGRAPH_AVAILABLE, _MAX_SURFACE_CHARS
except ImportError:
    LANGGRAPH_AVAILABLE = False
    _MAX_SURFACE_CHARS = 12000


class LangGraphAuditAgent(BaseAgent):
    """LangGraph StateGraph を使った自律型コード監査エージェント。"""

    def run(self, path: str) -> None:
        if os.path.isdir(path):
            self._run_project(path)
            return
        self._current_mode, self._current_target = "AUDIT", path
        scan_id = self._begin_scan()  # 証拠保存がfinalize前からscan_idを使うため(P1.2)
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
            # 証拠保存（P1.2・save_evidence設定時のみ。既定OFF）。標準エンジンと同じく
            # ASTプリスキャンの決定的観測のみを保存する（load_codeでマスク済みのソースを受け取る）。
            known_evidence_ids: set[str] = set()
            evidence_errors: list[str] = []

            def _evidence_hook(code: str) -> tuple[str, str]:
                ast_result = ast_scan(code)
                if not (config.get("save_evidence", False) and ast_result["findings"]):
                    return "", ""
                ids, listing, errs = save_ast_evidence(EvidenceStore(scan_id), path, code, ast_result)
                known_evidence_ids.update(ids)
                evidence_errors.extend(errs)
                return listing, (_EVIDENCE_INSTRUCTION if ids else "")

            graph = build_audit_graph(self.llm, self.bus, self.is_stopped,
                                      evidence_hook=_evidence_hook)
            initial_state: AuditState = {
                "source_path":     path,
                "source_code":     "",
                "outputs":         [],
                "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "iteration":       0,
                "phase":           "init",
                "evidence_listing": "",
                "evidence_instruction": "",
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
        rejected: list[str] = []
        findings = self._findings_from_markers(
            parsed, corroborated=False,
            known_evidence_ids=known_evidence_ids or None, rejected_evidence_ids=rejected)
        was_truncated = len(final_state.get("source_code", "") or "") > _MAX_SURFACE_CHARS
        coverage = AuditAgent._build_coverage(path, was_truncated)
        state, errors = self._determine_state(final_state, combined)
        errors = errors + evidence_errors + rejected
        self._finalize(state=state, errors=errors, findings=findings, coverage=coverage,
                       mode="AUDIT", target=path)

    def _run_project(self, path: str) -> None:
        """ディレクトリ入力(P4.2): 標準エンジンと同じ索引・優先付き文脈をグラフの入力にする。

        表層スキャンと深層解析が同じ本文を見るよう、文脈は深層解析の上限(8000字)に合わせて作る
        (どちらのノードでもsmart_truncateが働かず、coverageと送信内容が一致する)。CVE照合は未対応。
        証拠保存(save_evidence有効時)は標準エンジンのプロジェクト監査と同じ: LLMへ送った関数内のAST観測だけ。
        """
        from tools import code_index
        from core import redaction
        from core.orchestrator import _MAX_DEEP_CHARS
        self._current_mode, self._current_target = "AUDIT", path
        scan_id = self._begin_scan()
        self.bus.clear()
        self._status(f"[LangGraph] {os.path.basename(path.rstrip('/')) or path} を索引化中 ...")
        if not LANGGRAPH_AVAILABLE:
            self._finalize(state=ScanState.FAILED.value, errors=["langgraphがインストールされていません"],
                           mode="AUDIT", target=path)
            return
        try:
            idx = code_index.build_index(path)
        except OSError as e:
            self._finalize(state=ScanState.FAILED.value, errors=[f"プロジェクトを読めません: {e}"],
                           mode="AUDIT", target=path)
            return
        if not idx.files:
            self._finalize(state=ScanState.FAILED.value, mode="AUDIT", target=path, coverage=[
                CoverageItem(target_ref=p, status=CoverageStatus.SKIPPED.value, rule_id="LLM_CODE_REVIEW", reason=r)
                for p, r in idx.skipped], errors=["解析できるPythonファイルがありません"])
            return
        idx.sources = {rel: redaction.mask_source(src) for rel, src in idx.sources.items()}
        ctx = code_index.render_context(idx, _MAX_DEEP_CHARS)
        self._out(f"  TARGET : {path}\n  FILES  : {len(idx.files)} analyzed, {len(idx.skipped)} not analyzed\n"
                  f"  CONTEXT: {len(ctx.included)} function(s) sent, {len(ctx.omitted)} omitted by budget\n"
                  f"  ENGINE : LangGraph StateGraph (multi-file)\n\n", "dim")
        header = ("Multi-file Python project excerpt. Each block is labelled `file:start-end` and lines carry their "
                  "real line numbers (`NN| code`). Report LINES as `file:line`. Code that is not shown was NOT "
                  "analyzed — do not claim it is safe.\n\n")
        known_evidence_ids: set[str] = set()
        evidence_errors: list[str] = []

        def _evidence_hook(_code: str) -> tuple[str, str]:
            if not config.get("save_evidence", False):
                return "", ""
            ids, listing, errs = save_project_ast_evidence(EvidenceStore(scan_id), idx, ctx)
            known_evidence_ids.update(ids)
            evidence_errors.extend(errs)
            return listing, (_EVIDENCE_INSTRUCTION if ids else "")

        try:
            graph = build_audit_graph(self.llm, self.bus, self.is_stopped,
                                      source_loader=lambda _p: header + ctx.text, evidence_hook=_evidence_hook)
            final_state = graph.invoke({
                "source_path": path, "source_code": "", "outputs": [],
                "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "iteration": 0, "phase": "init", "evidence_listing": "", "evidence_instruction": ""})
        except Exception as e:
            self._out(f"\n[ GRAPH ERROR ] {e}\n", "critical")
            self._finalize(state=ScanState.FAILED.value, errors=[str(e)], mode="AUDIT", target=path)
            return
        combined = "\n".join(final_state.get("outputs", []) or [])
        parsed, _counts = _findings_and_counts("CODE AUDIT", combined)
        rejected: list[str] = []
        findings = self._findings_from_markers(parsed, corroborated=False,
                                               known_evidence_ids=known_evidence_ids or None,
                                               rejected_evidence_ids=rejected)
        state, errors = self._determine_state(final_state, combined)
        errors = errors + AuditAgent._project_notes(ctx) + evidence_errors + rejected
        if state == ScanState.COMPLETED.value and (ctx.omitted or idx.limit_hit or idx.skipped):
            state = ScanState.PARTIAL.value
        self._finalize(state=state, errors=errors, findings=findings, coverage=AuditAgent._project_coverage(ctx),
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
        if note := unparsed_output_note(combined_text):
            errors.append(note)
            return ScanState.PARTIAL.value, errors
        return ScanState.COMPLETED.value, errors
