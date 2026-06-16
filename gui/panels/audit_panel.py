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
from core.settings import BG_PANEL, BG_WIDGET, CYAN, TEXT_MID, TEXT_DIM, BG_ROOT
from agents.audit_agent import AuditAgent, STEPS
from gui.widgets.output_box import OutputBox
from gui.widgets.progress_steps import ProgressSteps


class AuditPanel(ctk.CTkFrame):

    def __init__(self, master, bus: EventBus, llm: LLMClient, **kwargs):
        kwargs.setdefault("fg_color", "transparent")
        super().__init__(master, **kwargs)
        self._bus   = bus
        self._agent = AuditAgent(bus, llm)
        self._path  = tk.StringVar(value="検査対象ファイルを選択してください ...")
        self._build()

    def _build(self) -> None:
        # ── ファイル選択バー ──────────────────────────────
        fbar = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=48)
        fbar.pack(fill="x", pady=(0, 4))
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
                      border_color="#1A3050", border_width=1,
                      text_color=TEXT_DIM, font=ctk.CTkFont("Segoe UI", 10),
                      command=self._clear).pack(side="right")

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
        self._agent.start(path=path)

    def _clear(self) -> None:
        self._out_box.clear()

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
