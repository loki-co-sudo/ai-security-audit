"""
gui/panels/attack_panel.py — ATTACK MODE タブ（ペネトレーションテスト）
"""

from __future__ import annotations
import os
import tkinter as tk
import customtkinter as ctk

import core.event_bus as ev
from core.event_bus import EventBus
from core.llm_client import LLMClient
from core.settings import (
    BG_PANEL, BG_WIDGET, BG_INPUT, CYAN, RED_C,
    TEXT_MID, TEXT_DIM, TEXT_PRI, BORDER, BG_ROOT,
)
from agents.recon_agent import ReconAgent, STEPS
from gui.widgets.output_box import OutputBox
from gui.widgets.progress_steps import ProgressSteps

class AttackPanel(ctk.CTkFrame):

    def __init__(self, master, bus: EventBus, llm: LLMClient, **kwargs):
        kwargs.setdefault("fg_color", "transparent")
        super().__init__(master, **kwargs)
        self._bus       = bus
        self._llm       = llm
        self._agent     = ReconAgent(bus, llm)
        self._intensity = tk.StringVar(value="stealth")
        self._scan_web  = tk.BooleanVar(value=True)
        self._build()

    def _build(self) -> None:
        # ── ターゲット入力バー ────────────────────────────
        tbar = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=6, height=52)
        tbar.pack(fill="x", pady=(0, 4))
        tbar.pack_propagate(False)

        self._scan_btn = ctk.CTkButton(
            tbar, text="  SCAN  ▶ ", width=130, height=34,
            fg_color=RED_C, hover_color="#CC2828",
            text_color="white", font=ctk.CTkFont("Segoe UI", 12, "bold"),
            command=self._start_scan,
        )
        self._scan_btn.pack(side="right", padx=12, pady=9)

        ctk.CTkButton(
            tbar, text="■  STOP", width=90, height=34,
            fg_color="#3A1010", hover_color="#4A1818",
            border_color=RED_C, border_width=1,
            text_color=RED_C, font=ctk.CTkFont("Segoe UI", 11),
            command=self._stop_scan,
        ).pack(side="right", padx=(0, 6), pady=9)

        ctk.CTkLabel(tbar, text="TARGET:", font=ctk.CTkFont("Segoe UI", 11, "bold"),
                     text_color=RED_C, width=60).pack(side="left", padx=(12, 4), pady=9)
        self._target_entry = ctk.CTkEntry(
            tbar, placeholder_text="https://example.com  または  192.168.1.1",
            font=ctk.CTkFont("Consolas", 11), fg_color=BG_INPUT,
            border_color=RED_C, border_width=1, text_color=TEXT_PRI,
        )
        self._target_entry.pack(side="left", fill="x", expand=True, padx=(0, 8), pady=9)

        # ── オプションバー ────────────────────────────────
        obar = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=6, height=40)
        obar.pack(fill="x", pady=(0, 6))
        obar.pack_propagate(False)

        ctk.CTkLabel(obar, text="PROFILE:", font=ctk.CTkFont("Segoe UI", 10),
                     text_color=TEXT_DIM).pack(side="left", padx=(14, 4), pady=8)
        ctk.CTkOptionMenu(
            obar, values=["stealth", "passive", "moderate", "aggressive"],
            variable=self._intensity, width=120, height=26,
            fg_color=BG_INPUT, button_color="#1A3050",
            font=ctk.CTkFont("Segoe UI", 10), text_color=TEXT_PRI,
        ).pack(side="left", padx=(0, 16), pady=7)

        ctk.CTkCheckBox(
            obar, text="Web Probe", variable=self._scan_web,
            font=ctk.CTkFont("Segoe UI", 10), text_color=TEXT_DIM,
            fg_color=CYAN, hover_color="#009BBD",
            checkbox_width=16, checkbox_height=16,
        ).pack(side="left", padx=8)

        # ── メインペイン ──────────────────────────────────
        pane = ctk.CTkFrame(self, fg_color="transparent")
        pane.pack(fill="both", expand=True)

        self._steps_widget = ProgressSteps(pane, steps=STEPS, show_stats=True, width=360)
        self._steps_widget.pack(side="left", fill="y", padx=(0, 4))

        right = ctk.CTkFrame(pane, fg_color=BG_PANEL, corner_radius=8)
        right.pack(side="left", fill="both", expand=True)

        hdr = ctk.CTkFrame(right, fg_color="transparent", height=34)
        hdr.pack(fill="x", padx=14, pady=(10, 2))
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="RECON & AI THREAT ANALYSIS",
                     font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=RED_C).pack(side="left")
        ctk.CTkButton(hdr, text="Clear", width=60, height=26,
                      fg_color="#1A0808", hover_color="#2A1010",
                      border_color=BORDER, border_width=1,
                      text_color=TEXT_DIM, font=ctk.CTkFont("Segoe UI", 10),
                      command=self._clear).pack(side="right")
        ctk.CTkButton(hdr, text="📊 レポート出力", width=106, height=26,
                      fg_color="#1A0808", hover_color="#2A1010",
                      border_color=RED_C, border_width=1,
                      text_color=RED_C, font=ctk.CTkFont("Segoe UI", 10),
                      command=self._export_report).pack(side="right", padx=(0, 6))

        self._out_box = OutputBox(right)
        self._out_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    # ── ロジック ──────────────────────────────────────────
    def _start_scan(self) -> None:
        target = self._target_entry.get().strip()
        if not target:
            self._out_box.append("[ ERROR ] ターゲットを入力してください。\n", "critical")
            return
        self._steps_widget.reset()
        self._scan_btn.configure(state="disabled", text="  SCANNING  ●", fg_color="#601010")
        self._bus.flush()
        self._agent.start(
            target=target,
            scan_web=self._scan_web.get(),
            intensity=self._intensity.get(),
        )

    def _stop_scan(self) -> None:
        self._agent.stop()

    def _clear(self) -> None:
        self._out_box.clear()

    def _export_report(self) -> None:
        from tools import report_generator
        raw = self._out_box.get_text()
        html_content = report_generator.generate(
            mode="ATTACK MODE",
            target=self._target_entry.get().strip(),
            raw_text=raw,
            model=self._llm.model,
        )
        out_path = report_generator.save(html_content, "attack_mode")
        self._steps_widget.log(f"レポート保存: {os.path.abspath(out_path)}")
        try:
            os.startfile(os.path.abspath(out_path))
        except Exception:
            pass

    # ── EventBus dispatch ─────────────────────────────────
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
            self._scan_btn.configure(
                state="normal", text="  SCAN  ▶ ", fg_color=RED_C,
            )
            if p and not p.get("error"):
                self._steps_widget.set_progress(1.0)
