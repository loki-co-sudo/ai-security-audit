"""
core/orchestrator.py — LangGraphマルチエージェントオーケストレーター

StateGraph を使ったステートフルな自律監査ワークフロー。
CRITICAL 発見時に深層解析ループを自動実行する条件分岐を含む。
入力トランケーションは smart_truncate（末尾優先/importスキップ/制限値拡張）を使用。

グラフ構造:
  load_code → surface_scan → assess_severity
                                  ↓ (CRITICAL > 0 かつ iteration < max_deep_loops)
                            deep_analysis ──→ assess_severity (ループ)
                                  ↓ (else)
                            synthesize → END
"""

from __future__ import annotations
import re
import operator
import importlib.util
from typing import TypedDict, Annotated, Callable

# importlib.find_spec はファイルシステム確認だけなので 0ms 以下。
# 実際の langgraph インポートは build_audit_graph() 呼び出し時まで遅延させる。
LANGGRAPH_AVAILABLE: bool = importlib.util.find_spec("langgraph") is not None

from core.llm_client import LLMClient
from core.event_bus import EventBus
import core.event_bus as ev

_SURFACE_PROMPT = """\
You are an expert security auditor. Perform a comprehensive surface scan.
Identify ALL vulnerability types in the code.

For EVERY vulnerability found, use this EXACT format:

---VULN_START---
NAME: [vulnerability name]
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW]
CWE: [CWE-XXX or "Novel"]
LINES: [line numbers]
SNIPPET:
```
[vulnerable code]
```
ATTACK:
[exploitation scenario]
FIX:
```
[corrected code]
```
---VULN_END---"""

_DEEP_PROMPT = """\
You are performing DEEP exploitation analysis based on a prior surface scan.
Focus exclusively on CRITICAL and HIGH severity findings.
For each critical issue, provide:
- Exact step-by-step exploitation chain
- Specific payloads or attack inputs
- Concrete fix with corrected code
Use ---VULN_START---/---VULN_END--- markers for each finding."""

# 共通トランケーション関数（agents/audit_agent の smart_truncate をフォールバック付きでインポート）
try:
    from agents.audit_agent import smart_truncate as _smart_truncate
except ImportError:
    def _smart_truncate(source: str, max_chars: int = 12000) -> str:
        """フォールバック: 単純な末尾優先トランケーション。"""
        if len(source) <= max_chars:
            return source
        head_size = int(max_chars * 0.15)
        tail_size = max_chars - head_size - 80
        return source[:head_size] + "\n\n# ... (省略) ...\n\n" + source[-tail_size:]

# LangGraph 用の最大文字数（surface_scan と deep_analysis で使用）
_MAX_SURFACE_CHARS = 12000
_MAX_DEEP_CHARS    = 8000


class AuditState(TypedDict):
    source_path: str
    source_code: str
    outputs: Annotated[list[str], operator.add]
    severity_counts: dict
    iteration: int
    phase: str


def build_audit_graph(
    llm: LLMClient,
    bus: EventBus,
    is_stopped: Callable[[], bool],
):
    """CODE AUDIT 用 LangGraph StateGraph を構築してコンパイル済みグラフを返す。"""
    if not LANGGRAPH_AVAILABLE:
        raise ImportError(
            "langgraph がインストールされていません。\n"
            "pip install langgraph を実行してください。"
        )
    # 遅延インポート: スキャン開始時にのみ langgraph を読み込む（起動時間への影響ゼロ）
    from langgraph.graph import StateGraph, END  # noqa: PLC0415
    from core.model_router import current_effort  # noqa: PLC0415

    # 深層解析ループの最大反復回数はエフォート連動（速度=0 / バランス=1 / 品質=2）。
    max_deep_loops = current_effort().get("deep_loops", 1)

    def _emit(text: str, tag: str = "") -> None:
        bus.emit(ev.OUTPUT, {"text": text, "tag": tag})

    def _stream(messages: list[dict]) -> str:
        full = ""

        def on_chunk(chunk: str) -> None:
            nonlocal full
            full += chunk
            _emit(chunk)

        llm.stream(
            messages=messages,
            on_chunk=on_chunk,
            on_error=lambda e: _emit(f"\n[LLM ERROR] {e}\n", "critical"),
        )
        return full

    # ── ノード定義 ───────────────────────────────────────────

    def load_code(state: AuditState) -> dict:
        if is_stopped():
            return {"phase": "stopped"}
        _emit("\n  [GRAPH 1/5] load_code — ファイル読み込み中 ...\n", "dim")
        try:
            with open(state["source_path"], "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
            lines = code.count("\n") + 1
            _emit(f"  {lines} 行を読み込みました。\n\n", "dim")
        except OSError as e:
            _emit(f"  [ERROR] {e}\n", "critical")
            code = ""
        return {"source_code": code, "phase": "loaded"}

    def surface_scan(state: AuditState) -> dict:
        if is_stopped() or not state.get("source_code"):
            return {"phase": "stopped"}
        _emit("  [GRAPH 2/5] surface_scan — 表層スキャン実行中 ...\n", "section")
        _emit("─" * 56 + "\n\n", "sep")
        truncated = _smart_truncate(state["source_code"], _MAX_SURFACE_CHARS)
        output = _stream([
            llm.system(_SURFACE_PROMPT),
            llm.user(
                "Analyze this code for ALL security vulnerabilities:\n\n"
                f"```python\n{truncated}\n```"
            ),
        ])
        return {"outputs": [output], "phase": "surface_scanned"}

    def assess_severity(state: AuditState) -> dict:
        if is_stopped():
            return {"phase": "stopped"}
        combined = "\n".join(state.get("outputs", []))
        counts = {
            s: len(re.findall(rf"SEVERITY:\s*{s}\b", combined, re.I))
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        }
        bus.emit(ev.STATS, counts)
        _emit(
            f"\n  [GRAPH 3/5] assess_severity — "
            f"CRITICAL:{counts['CRITICAL']}  HIGH:{counts['HIGH']}  "
            f"MEDIUM:{counts['MEDIUM']}  LOW:{counts['LOW']}\n",
            "dim",
        )
        return {"severity_counts": counts, "phase": "assessed"}

    def deep_analysis(state: AuditState) -> dict:
        if is_stopped():
            return {"phase": "stopped"}
        it = state.get("iteration", 0) + 1
        _emit(f"\n  [GRAPH 4/5] deep_analysis — 深層解析ループ #{it} (CRITICALを検出) ...\n", "section")
        _emit("─" * 56 + "\n\n", "sep")
        prior  = (state.get("outputs") or [""])[-1]
        code   = _smart_truncate(state.get("source_code", ""), _MAX_DEEP_CHARS)
        output = _stream([
            llm.system(_DEEP_PROMPT),
            llm.user(
                f"Prior surface scan found CRITICAL vulnerabilities. Perform deep exploitation analysis.\n\n"
                f"Surface scan output:\n{prior[:3000]}\n\n"
                f"Source code:\n```python\n{code}\n```"
            ),
        ])
        return {"outputs": [output], "iteration": it, "phase": "deep_analyzed"}

    def synthesize(state: AuditState) -> dict:
        combined = "\n".join(state.get("outputs", []))
        counts = {
            s: len(re.findall(rf"SEVERITY:\s*{s}\b", combined, re.I))
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        }
        total = sum(counts.values())
        bus.emit(ev.STATS, counts)
        tag = "critical" if counts.get("CRITICAL") else "green"
        _emit("\n\n" + "═" * 56 + "\n", "sep")
        _emit(f"  [GRAPH 5/5] 解析完了 — {total} 件の脆弱性を検出\n", tag)
        _emit(
            f"  LangGraph ワークフロー終了 "
            f"(深層解析ループ: {state.get('iteration', 0)} 回)\n",
            "dim",
        )
        _emit("═" * 56 + "\n", "sep")
        return {"severity_counts": counts, "phase": "done"}

    # ── 条件分岐 ─────────────────────────────────────────────

    def should_deep_analyze(state: AuditState) -> str:
        """CRITICAL が1件以上 かつ iteration < max_deep_loops の場合のみ深層解析へ。"""
        if (
            not is_stopped()
            and max_deep_loops > 0
            and state.get("severity_counts", {}).get("CRITICAL", 0) > 0
            and state.get("iteration", 0) < max_deep_loops
        ):
            return "deep_analysis"
        return "synthesize"

    # ── グラフ構築 ───────────────────────────────────────────

    workflow: StateGraph = StateGraph(AuditState)
    workflow.add_node("load_code",       load_code)
    workflow.add_node("surface_scan",    surface_scan)
    workflow.add_node("assess_severity", assess_severity)
    workflow.add_node("deep_analysis",   deep_analysis)
    workflow.add_node("synthesize",      synthesize)

    workflow.set_entry_point("load_code")
    workflow.add_edge("load_code",    "surface_scan")
    workflow.add_edge("surface_scan", "assess_severity")
    workflow.add_conditional_edges(
        "assess_severity",
        should_deep_analyze,
        {"deep_analysis": "deep_analysis", "synthesize": "synthesize"},
    )
    workflow.add_edge("deep_analysis", "assess_severity")
    workflow.add_edge("synthesize",    END)

    return workflow.compile()