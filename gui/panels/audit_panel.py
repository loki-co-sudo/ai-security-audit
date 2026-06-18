"""
gui/panels/audit_panel.py — CODE AUDIT タブ
"""

from __future__ import annotations
import os
import tkinter as tk
from tkinter import filedialog
import customtkinter as ctk

import core.event_bus as ev
from core.event_bus import EventBus
from core.llm_client import LLMClient
from core.settings import BG_PANEL, BG_WIDGET, BG_INPUT, CYAN, TEXT_MID, TEXT_DIM, BG_ROOT, BORDER
from agents.audit_agent import AuditAgent, STEPS
from gui.widgets.output_box import OutputBox
from gui.widgets.progress_steps import ProgressSteps

try:
    from core.orchestrator import LANGGRAPH_AVAILABLE as _LG_AVAILABLE
except ImportError:
    _LG_AVAILABLE = False


class AuditPanel(ctk.CTkFrame):

    def __init__(self, master, bus: EventBus, llm: LLMClient, **kwargs):
        kwargs.setdefault("fg_color", "transparent")
        super().__init__(master, **kwargs)
        self._bus   = bus
        self._llm   = llm
        self._agent = AuditAgent(bus, llm)
        self._path  = tk.StringVar(value="検査対象ファイルを選択してください ...")
        self._engine_var = tk.StringVar(value="standard")
        self._build()

    def _build(self) -> None:
        # ── ファイル選択バー ──────────────────────────────
        fbar = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=48)
        fbar.pack(fill="x", pady=(0, 2))
        fbar.pack_propagate(False)

        self._start_btn = ctk.CTkButton(
            fbar, text="  AI 監査を開始  ▶ ", width=190, height=34,
            fg_color=CYAN, hover_color="#00B5DD",
            text_color=BG_ROOT, font=ctk.CTkFont("Segoe UI", 12, "bold"),
            command=self._start,
        )
        self._start_btn.pack(side="right", padx=12, pady=7)

        ctk.CTkButton(
            fbar, text="📂  ファイルを選択", width=150, height=34,
            fg_color="#152030", hover_color="#1E3040",
            border_color=CYAN, border_width=1,
            text_color=CYAN, font=ctk.CTkFont("Segoe UI", 11),
            command=self._browse,
        ).pack(side="left", padx=12, pady=7)

        ctk.CTkLabel(
            fbar, textvariable=self._path,
            font=ctk.CTkFont("Consolas", 10), text_color=TEXT_MID, anchor="w",
        ).pack(side="left", fill="x", expand=True, padx=6)

        # ── エンジン選択バー ──────────────────────────────
        ebar = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=34)
        ebar.pack(fill="x", pady=(0, 4))
        ebar.pack_propagate(False)

        ctk.CTkLabel(ebar, text="ENGINE:",
                     font=ctk.CTkFont("Segoe UI", 10), text_color=TEXT_DIM,
                     ).pack(side="left", padx=(14, 6), pady=5)

        seg = ctk.CTkSegmentedButton(
            ebar, values=["Standard", "LangGraph"],
            variable=self._engine_var,
            height=22, width=200,
            fg_color=BG_INPUT, selected_color=CYAN, selected_hover_color="#00B5DD",
            unselected_color=BG_INPUT, unselected_hover_color="#1A3050",
            text_color=TEXT_MID, text_color_disabled=TEXT_DIM,
            font=ctk.CTkFont("Segoe UI", 10),
        )
        seg.pack(side="left", pady=5)
        if not _LG_AVAILABLE:
            seg.configure(state="disabled")
            ctk.CTkLabel(ebar, text="→ pip install langgraph",
                         font=ctk.CTkFont("Segoe UI", 9), text_color=TEXT_DIM,
                         ).pack(side="left", padx=8)

        # ── メインペイン（左:進捗 / 右:出力） ─────────────
        pane = ctk.CTkFrame(self, fg_color="transparent")
        pane.pack(fill="both", expand=True)

        self._steps_widget = ProgressSteps(pane, steps=STEPS, show_stats=True, width=360)
        self._steps_widget.pack(side="left", fill="y", padx=(0, 4))

        right = ctk.CTkFrame(pane, fg_color=BG_PANEL, corner_radius=8)
        right.pack(side="left", fill="both", expand=True)

        hdr = ctk.CTkFrame(right, fg_color="transparent", height=34)
        hdr.pack(fill="x", padx=14, pady=(10, 2))
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="AI VULNERABILITY ANALYSIS OUTPUT",
                     font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=CYAN).pack(side="left")
        ctk.CTkButton(hdr, text="Clear", width=60, height=26,
                      fg_color="#152030", hover_color="#1E3040",
                      border_color=BORDER, border_width=1,
                      text_color=TEXT_DIM, font=ctk.CTkFont("Segoe UI", 10),
                      command=self._clear).pack(side="right")
        ctk.CTkButton(hdr, text="📊 レポート出力", width=106, height=26,
                      fg_color="#0A1E2A", hover_color="#0E2840",
                      border_color=CYAN, border_width=1,
                      text_color=CYAN, font=ctk.CTkFont("Segoe UI", 10),
                      command=self._export_report).pack(side="right", padx=(0, 6))

        self._out_box = OutputBox(right)
        self._out_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    # ── ロジック ──────────────────────────────────────────
    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            title="検査対象ファイルを選択",
            filetypes=[("Python files", "*.py"), ("All files", "*.*")],
        )
        if path:
            self._path.set(path)
            self._steps_widget.log(f"Target: {os.path.basename(path)}")

    def _start(self) -> None:
        path = self._path.get()
        if not os.path.isfile(path):
            self._out_box.append("[ ERROR ] 有効なファイルを選択してください。\n", "critical")
            return
        self._steps_widget.reset()
        self._start_btn.configure(state="disabled", text="  監査中 ...  ●", fg_color="#153040")
        self._bus.flush()
        if self._engine_var.get() == "LangGraph" and _LG_AVAILABLE:
            from agents.langgraph_audit_agent import LangGraphAuditAgent
            self._agent = LangGraphAuditAgent(self._bus, self._llm)
        else:
            self._agent = AuditAgent(self._bus, self._llm)
        self._agent.start(path=path)

    def _clear(self) -> None:
        self._out_box.clear()

    def _export_report(self) -> None:
        from tools import report_generator
        raw = self._out_box.get_text()
        html_content = report_generator.generate(
            mode="CODE AUDIT",
            target=self._path.get(),
            raw_text=raw,
            model=self._llm.model,
        )
        out_path = report_generator.save(html_content, "code_audit")
        self._steps_widget.log(f"レポート保存: {os.path.abspath(out_path)}")
        try:
            os.startfile(os.path.abspath(out_path))
        except Exception:
            pass

    # ── EventBus dispatch（app.py から呼ばれる） ──────────
    def dispatch(self, event: ev.Event) -> None:
        k, p = event.kind, event.payload
        if k == ev.OUTPUT:
            self._out_box.append(p["text"], p.get("tag", ""))
        elif k == ev.STEP:
            self._steps_widget.set_step(p["idx"], p["state"])
        elif k == ev.LOG:
            self._steps_widget.log(p)
        elif k == ev.STATS:
            self._steps_widget.set_stats(p)
        elif k == ev.CLEAR:
            self._out_box.clear()
        elif k == ev.DONE:
            self._start_btn.configure(
                state="normal", text="  AI 監査を開始  ▶ ", fg_color=CYAN,
            )
            if p and p.get("error"):
                self._steps_widget.set_progress(0)
            else:
                self._steps_widget.set_progress(1.0)
