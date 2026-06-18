"""
gui/panels/defense_panel.py — DEFENSE MODE タブ（リアルタイム監視）
"""

from __future__ import annotations
import os
import tkinter as tk
from tkinter import filedialog
from datetime import datetime
import customtkinter as ctk

import core.event_bus as ev
from core.event_bus import EventBus
from core.llm_client import LLMClient
from core.settings import (
    BG_PANEL, BG_WIDGET, BG_INPUT, GREEN, RED_C, ORANGE_H, YELLOW_M,
    TEXT_MID, TEXT_DIM, TEXT_PRI, BORDER, CYAN, BG_ROOT,
    SEV_COLORS,
)
from agents.monitor_agent import MonitorAgent
from tools.log_watcher import LogWatcher
from gui.widgets.output_box import OutputBox


class DefensePanel(ctk.CTkFrame):

    def __init__(self, master, bus: EventBus, llm: LLMClient, **kwargs):
        kwargs.setdefault("fg_color", "transparent")
        super().__init__(master, **kwargs)
        self._bus       = bus
        self._agent     = MonitorAgent(bus, llm)
        self._log_path  = tk.StringVar(value="監視するログファイルを選択してください ...")
        self._watch_mode = tk.BooleanVar(value=True)
        self._alert_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self._alert_vars:   dict[str, ctk.StringVar] = {}
        self._build()

    def _build(self) -> None:
        # ── ログソース選択バー ────────────────────────────
        sbar = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=6, height=50)
        sbar.pack(fill="x", pady=(0, 4))
        sbar.pack_propagate(False)

        # 右から: STOPボタン → STARTボタン
        self._stop_btn = ctk.CTkButton(
            sbar, text="■ STOP", width=90, height=34,
            fg_color="#0A2A0A", hover_color="#0F3A0F",
            border_color=GREEN, border_width=1,
            text_color=TEXT_DIM, font=ctk.CTkFont("Segoe UI", 11),
            command=self._stop, state="disabled",
        )
        self._stop_btn.pack(side="right", padx=(0, 10), pady=8)

        self._start_btn = ctk.CTkButton(
            sbar, text="▶  監視開始", width=130, height=34,
            fg_color=GREEN, hover_color="#00CC66",
            text_color=BG_ROOT, font=ctk.CTkFont("Segoe UI", 12, "bold"),
            command=self._start,
        )
        self._start_btn.pack(side="right", padx=8, pady=8)

        ctk.CTkButton(
            sbar, text="📄  ログ選択", width=120, height=34,
            fg_color="#0A200A", hover_color="#0F2A0F",
            border_color=GREEN, border_width=1,
            text_color=GREEN, font=ctk.CTkFont("Segoe UI", 11),
            command=self._browse,
        ).pack(side="left", padx=12, pady=8)

        ctk.CTkButton(
            sbar, text="🔧 サンプル生成", width=120, height=34,
            fg_color="#0A1A0A", hover_color="#0F200F",
            border_color="#1A3A1A", border_width=1,
            text_color=TEXT_DIM, font=ctk.CTkFont("Segoe UI", 10),
            command=self._generate_sample,
        ).pack(side="left", padx=(0, 8), pady=8)

        ctk.CTkLabel(
            sbar, textvariable=self._log_path,
            font=ctk.CTkFont("Consolas", 10), text_color=TEXT_MID, anchor="w",
        ).pack(side="left", fill="x", expand=True, padx=6)

        # ── オプションバー ────────────────────────────────
        obar = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=6, height=36)
        obar.pack(fill="x", pady=(0, 6))
        obar.pack_propagate(False)

        ctk.CTkCheckBox(
            obar, text="継続監視モード（ファイル末尾をリアルタイム追跡）",
            variable=self._watch_mode,
            font=ctk.CTkFont("Segoe UI", 10), text_color=TEXT_DIM,
            fg_color=GREEN, hover_color="#00CC66",
            checkbox_width=16, checkbox_height=16,
        ).pack(side="left", padx=14)

        ctk.CTkLabel(obar, text="※ OFF = ファイルを1回通読して終了",
                     font=ctk.CTkFont("Segoe UI", 9), text_color=TEXT_DIM).pack(side="left", padx=8)

        # ── メインペイン（左:アラートリスト / 右:AI解析） ─
        pane = ctk.CTkFrame(self, fg_color="transparent")
        pane.pack(fill="both", expand=True)

        # 左パネル
        left = ctk.CTkFrame(pane, fg_color=BG_PANEL, corner_radius=8, width=360)
        left.pack(side="left", fill="y", padx=(0, 4))
        left.pack_propagate(False)

        self._build_left(left)

        # 右パネル
        right = ctk.CTkFrame(pane, fg_color=BG_PANEL, corner_radius=8)
        right.pack(side="left", fill="both", expand=True)

        hdr = ctk.CTkFrame(right, fg_color="transparent", height=34)
        hdr.pack(fill="x", padx=14, pady=(10, 2))
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="AI THREAT ANALYSIS OUTPUT",
                     font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=GREEN).pack(side="left")
        ctk.CTkButton(hdr, text="Clear", width=60, height=26,
                      fg_color="#0A200A", hover_color="#0F2A0F",
                      border_color=BORDER, border_width=1,
                      text_color=TEXT_DIM, font=ctk.CTkFont("Segoe UI", 10),
                      command=self._clear).pack(side="right")
        ctk.CTkButton(hdr, text="📊 レポート出力", width=106, height=26,
                      fg_color="#0A200A", hover_color="#0F2A0F",
                      border_color=GREEN, border_width=1,
                      text_color=GREEN, font=ctk.CTkFont("Segoe UI", 10),
                      command=self._export_report).pack(side="right", padx=(0, 6))

        self._out_box = OutputBox(right)
        self._out_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _build_left(self, parent: ctk.CTkFrame) -> None:
        ctk.CTkLabel(parent, text="ALERT SUMMARY",
                     font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=GREEN,
                     ).pack(anchor="w", padx=14, pady=(12, 6))

        # 深刻度カウンター（2×2グリッド）
        grid = ctk.CTkFrame(parent, fg_color="transparent")
        grid.pack(fill="x", padx=10)
        grid.columnconfigure((0, 1), weight=1)

        for i, (sev, color) in enumerate(SEV_COLORS.items()):
            box = ctk.CTkFrame(grid, fg_color=BG_WIDGET, corner_radius=6)
            box.grid(row=i // 2, column=i % 2, padx=3, pady=3, sticky="ew")
            var = ctk.StringVar(value="0")
            self._alert_vars[sev] = var
            ctk.CTkLabel(box, text=sev, font=ctk.CTkFont("Segoe UI", 9, "bold"), text_color=color).pack(pady=(8, 2))
            ctk.CTkLabel(box, textvariable=var, font=ctk.CTkFont("Segoe UI", 19, "bold"), text_color=color).pack(pady=(0, 8))

        ctk.CTkFrame(parent, fg_color=BORDER, height=1).pack(fill="x", padx=12, pady=8)

        ctk.CTkLabel(parent, text="ALERT TIMELINE",
                     font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=GREEN,
                     ).pack(anchor="w", padx=14, pady=(0, 4))

        self._alert_list = ctk.CTkTextbox(
            parent, fg_color=BG_WIDGET, text_color=TEXT_DIM,
            font=ctk.CTkFont("Consolas", 9),
            corner_radius=6, wrap="word", state="disabled",
        )
        self._alert_list.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        # アラートタグ設定
        tb = self._alert_list._textbox
        tb.tag_configure("critical", foreground=RED_C,    font=("Consolas", 9, "bold"))
        tb.tag_configure("high",     foreground=ORANGE_H, font=("Consolas", 9))
        tb.tag_configure("medium",   foreground=YELLOW_M, font=("Consolas", 9))
        tb.tag_configure("low",      foreground=GREEN,    font=("Consolas", 9))

        ctk.CTkFrame(parent, fg_color=BORDER, height=1).pack(fill="x", padx=12, pady=(0, 8))

        ctk.CTkLabel(parent, text="SYSTEM LOG",
                     font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=GREEN,
                     ).pack(anchor="w", padx=14, pady=(0, 4))
        self._log_box = ctk.CTkTextbox(
            parent, fg_color=BG_WIDGET, text_color=TEXT_DIM,
            font=ctk.CTkFont("Consolas", 9),
            corner_radius=6, height=110, wrap="word", state="disabled",
        )
        self._log_box.pack(fill="x", padx=10, pady=(0, 10))

    # ── ロジック ──────────────────────────────────────────
    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            title="監視ログファイルを選択",
            filetypes=[("Log files", "*.log *.txt *.access"), ("All files", "*.*")],
        )
        if path:
            self._log_path.set(path)
            self._sys_log(f"Log source: {os.path.basename(path)}")

    def _generate_sample(self) -> None:
        import os
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "reports", "sample_access.log",
        )
        LogWatcher.generate_sample_log(path)
        self._log_path.set(path)
        self._sys_log(f"Sample log generated: {path}")

    def _start(self) -> None:
        path = self._log_path.get()
        if not os.path.isfile(path):
            self._out_box.append(
                "[ ERROR ] 有効なログファイルを選択してください。\n"
                "          「🔧 サンプル生成」でテスト用ログを作成できます。\n",
                "critical",
            )
            return
        # カウンターリセット
        for k in self._alert_counts: self._alert_counts[k] = 0
        for var in self._alert_vars.values(): var.set("0")
        self._alert_list.configure(state="normal")
        self._alert_list.delete("1.0", "end")
        self._alert_list.configure(state="disabled")

        self._start_btn.configure(state="disabled", text="  監視中 ...  ●", fg_color="#0F3A0F")
        self._stop_btn.configure(state="normal", text_color=GREEN)
        self._bus.flush()
        self._agent.start(log_path=path, watch_mode=self._watch_mode.get())

    def _stop(self) -> None:
        self._agent.stop()

    def _clear(self) -> None:
        self._out_box.clear()

    def _export_report(self) -> None:
        from tools import report_generator
        raw = self._out_box.get_text()
        html_content = report_generator.generate(
            mode="DEFENSE MODE",
            target=self._log_path.get(),
            raw_text=raw,
        )
        out_path = report_generator.save(html_content, "defense_mode")
        self._sys_log(f"レポート保存: {os.path.abspath(out_path)}")
        try:
            os.startfile(os.path.abspath(out_path))
        except Exception:
            pass

    def _sys_log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_box.configure(state="normal")
        self._log_box.insert("end", f"[{ts}] {msg}\n")
        self._log_box._textbox.see("end")
        self._log_box.configure(state="disabled")

    # ── EventBus dispatch ─────────────────────────────────
    def dispatch(self, event: ev.Event) -> None:
        k, p = event.kind, event.payload
        if k == ev.OUTPUT:
            self._out_box.append(p["text"], p.get("tag", ""))
        elif k == ev.LOG:
            self._sys_log(p)
        elif k == ev.ALERT:
            sev = p.get("severity", "LOW").upper()
            msg = p.get("message", "")
            ts  = p.get("time", datetime.now().strftime("%H:%M:%S"))
            tag = sev.lower()
            self._alert_list.configure(state="normal")
            self._alert_list._textbox.insert("end", f"[{ts}][{sev:8}] {msg[:70]}\n", tag)
            self._alert_list._textbox.see("end")
            self._alert_list.configure(state="disabled")
        elif k == ev.STATS:
            for sev, cnt in (p or {}).items():
                self._alert_counts[sev] = cnt
                if sev in self._alert_vars:
                    self._alert_vars[sev].set(str(cnt))
        elif k == ev.CLEAR:
            self._out_box.clear()
        elif k == ev.DONE:
            self._start_btn.configure(state="normal", text="▶  監視開始", fg_color=GREEN)
            self._stop_btn.configure(state="disabled", text_color=TEXT_DIM)
