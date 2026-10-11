"""
gui/panels/fuzz_panel.py — WEB FUZZ タブ（スマートファジング / 検出のみ）
"""

from __future__ import annotations
import threading
import tkinter as tk
import customtkinter as ctk

import core.event_bus as ev
from core.event_bus import EventBus
from core.llm_client import LLMClient
from core.settings import (
    BG_PANEL, BG_WIDGET, BG_INPUT, CYAN, AMBER, ORANGE_H, PURPLE,
    TEXT_DIM, TEXT_PRI, BORDER,
)
from agents.fuzz_agent import FuzzAgent, STEPS
from gui.widgets.output_box import OutputBox
from gui.widgets.progress_steps import ProgressSteps


class FuzzPanel(ctk.CTkFrame):

    def __init__(self, master, bus: EventBus, llm: LLMClient, **kwargs):
        kwargs.setdefault("fg_color", "transparent")
        super().__init__(master, **kwargs)
        self._bus       = bus
        self._llm       = llm
        self._agent     = FuzzAgent(bus, llm)
        self._profile   = tk.StringVar(value="stealth")
        self._budget    = tk.StringVar(value="200")
        self._auth: dict = {}   # 認証設定（🔐ボタンで設定）
        self._auth_b: dict = {}  # 第2アカウント設定（IDOR比較用・任意）
        self._auto_var  = tk.BooleanVar(value=False)
        self._build()

    def _build(self) -> None:
        # ── ターゲット入力バー ────────────────────────────
        tbar = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=6, height=52)
        tbar.pack(fill="x", pady=(0, 4))
        tbar.pack_propagate(False)

        self._scan_btn = ctk.CTkButton(
            tbar, text="  FUZZ  ▶ ", width=130, height=34,
            fg_color=AMBER, hover_color="#CC8400",
            text_color="#1A1000", font=ctk.CTkFont("Segoe UI", 12, "bold"),
            command=self._start,
        )
        self._scan_btn.pack(side="right", padx=12, pady=9)

        ctk.CTkButton(
            tbar, text="■  STOP", width=90, height=34,
            fg_color="#2A1A00", hover_color="#3A2400",
            border_color=AMBER, border_width=1,
            text_color=AMBER, font=ctk.CTkFont("Segoe UI", 11),
            command=self._stop,
        ).pack(side="right", padx=(0, 6), pady=9)

        ctk.CTkLabel(tbar, text="TARGET:", font=ctk.CTkFont("Segoe UI", 11, "bold"),
                     text_color=AMBER, width=60).pack(side="left", padx=(12, 4), pady=9)
        self._target_entry = ctk.CTkEntry(
            tbar, placeholder_text="https://example.com/search?q=test  （クエリ/フォームを持つURL）",
            font=ctk.CTkFont("Consolas", 11), fg_color=BG_INPUT,
            border_color=AMBER, border_width=1, text_color=TEXT_PRI,
        )
        self._target_entry.pack(side="left", fill="x", expand=True, padx=(0, 8), pady=9)

        # ── オプションバー ────────────────────────────────
        obar = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=6, height=40)
        obar.pack(fill="x", pady=(0, 6))
        obar.pack_propagate(False)

        ctk.CTkLabel(obar, text="PROFILE:", font=ctk.CTkFont("Segoe UI", 10),
                     text_color=TEXT_DIM).pack(side="left", padx=(14, 4), pady=8)
        ctk.CTkOptionMenu(
            obar, values=["stealth", "passive", "moderate", "aggressive", "bounty"],
            variable=self._profile, width=120, height=26,
            fg_color=BG_INPUT, button_color="#3A2400",
            font=ctk.CTkFont("Segoe UI", 10), text_color=TEXT_PRI,
        ).pack(side="left", padx=(0, 16), pady=7)

        ctk.CTkLabel(obar, text="REQ BUDGET:", font=ctk.CTkFont("Segoe UI", 10),
                     text_color=TEXT_DIM).pack(side="left", padx=(0, 4), pady=8)
        ctk.CTkOptionMenu(
            obar, values=["80", "200", "400", "800"],
            variable=self._budget, width=80, height=26,
            fg_color=BG_INPUT, button_color="#3A2400",
            font=ctk.CTkFont("Segoe UI", 10), text_color=TEXT_PRI,
        ).pack(side="left", padx=(0, 16), pady=7)

        self._auth_btn = ctk.CTkButton(
            obar, text="🔐 認証", width=84, height=26,
            fg_color=BG_INPUT, hover_color="#3A2400",
            border_color=AMBER, border_width=1,
            text_color=AMBER, font=ctk.CTkFont("Segoe UI", 10),
            command=self._open_auth,
        )
        self._auth_btn.pack(side="left", padx=(0, 8), pady=7)

        self._auth_b_btn = ctk.CTkButton(
            obar, text="🔐 認証B(IDOR比較・任意)", width=150, height=26,
            fg_color=BG_INPUT, hover_color="#3A2400",
            border_color=AMBER, border_width=1,
            text_color=AMBER, font=ctk.CTkFont("Segoe UI", 10),
            command=self._open_auth_b,
        )
        self._auth_b_btn.pack(side="left", padx=(0, 4), pady=7)
        ctk.CTkLabel(
            obar, text="※複数アカウント使用は対象プログラムの規約(ROE)で許可されているか要確認",
            font=ctk.CTkFont("Segoe UI", 8), text_color=AMBER,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkCheckBox(
            obar, text="AUTO", variable=self._auto_var,
            font=ctk.CTkFont("Segoe UI", 10), text_color=TEXT_DIM,
            fg_color=PURPLE, hover_color="#A96FE0",
            checkbox_width=16, checkbox_height=16,
        ).pack(side="left", padx=8)

        ctk.CTkLabel(
            obar, text="検出のみ・同一オリジン限定・認可された対象のみ",
            font=ctk.CTkFont("Segoe UI", 9), text_color=ORANGE_H,
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
        ctk.CTkLabel(hdr, text="SMART FUZZING & AI TRIAGE",
                     font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=AMBER).pack(side="left")
        ctk.CTkButton(hdr, text="Clear", width=60, height=26,
                      fg_color="#1A1000", hover_color="#2A1A00",
                      border_color=BORDER, border_width=1,
                      text_color=TEXT_DIM, font=ctk.CTkFont("Segoe UI", 10),
                      command=self._clear).pack(side="right")
        ctk.CTkButton(hdr, text="📄 PDF", width=66, height=26,
                      fg_color="#1A1000", hover_color="#2A1A00",
                      border_color=AMBER, border_width=1,
                      text_color=AMBER, font=ctk.CTkFont("Segoe UI", 10),
                      command=self._export_pdf).pack(side="right", padx=(0, 6))
        ctk.CTkButton(hdr, text="📊 HTML", width=78, height=26,
                      fg_color="#1A1000", hover_color="#2A1A00",
                      border_color=AMBER, border_width=1,
                      text_color=AMBER, font=ctk.CTkFont("Segoe UI", 10),
                      command=self._export_report).pack(side="right", padx=(0, 6))
        ctk.CTkButton(hdr, text="📝 MD", width=66, height=26,
                      fg_color="#1A1000", hover_color="#2A1A00",
                      border_color=AMBER, border_width=1,
                      text_color=AMBER, font=ctk.CTkFont("Segoe UI", 10),
                      command=self._export_markdown).pack(side="right", padx=(0, 6))
        ctk.CTkButton(hdr, text="{ } JSON", width=72, height=26,
                      fg_color="#1A1000", hover_color="#2A1A00",
                      border_color=AMBER, border_width=1,
                      text_color=AMBER, font=ctk.CTkFont("Segoe UI", 10),
                      command=self._export_json).pack(side="right", padx=(0, 6))

        self._out_box = OutputBox(right)
        self._out_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    # ── ロジック ──────────────────────────────────────────
    def _start(self) -> None:
        target = self._target_entry.get().strip()
        if not target:
            self._out_box.append("[ ERROR ] ターゲットURLを入力してください。\n", "critical")
            return
        self._steps_widget.reset()
        self._scan_btn.configure(state="disabled", text="  FUZZING  ●", fg_color="#6A4400")
        self._scan_result = None
        self._bus.flush()
        if self._auto_var.get():
            threading.Thread(target=self._auto_classify, args=(target,), daemon=True).start()
        else:
            self._agent.set_effort_override(None)
            self._launch_fuzz(target)

    def _auto_classify(self, target: str) -> None:
        """AUTO: FASTモデルで対象の難易度を分類し、エフォートを一時上書きする（§5.1）。

        分類・クライアント構築のどんな例外もここで揉み消し、balanced扱いでスキャンを続行する
        （バックグラウンドスレッドの例外は呼び出し元に伝播せず、揉み消さないとFUZZボタンが
        固まったままになる）。
        """
        level = "balanced"
        try:
            from core.model_router import build_fast_client, classify_effort
            desc = f"Web fuzzing target: {target}\nfuzz profile: {self._profile.get()}"
            client = build_fast_client(self._llm)
            level = classify_effort(desc, client)
        except Exception:
            pass
        self.after(0, lambda: self._on_auto_classified(level, target))

    def _on_auto_classified(self, level: str, target: str) -> None:
        self._steps_widget.log(f"AUTO: 難易度分類 → エフォート = {level}")
        self._agent.set_effort_override(level)
        self._launch_fuzz(target)

    def _launch_fuzz(self, target: str) -> None:
        try:
            budget = int(self._budget.get())
        except ValueError:
            budget = 200
        self._agent.start(
            target=target,
            profile=self._profile.get(),
            max_requests=budget,
            auth=self._auth or None,
            auth_b=self._auth_b or None,
        )

    def _open_auth(self) -> None:
        from gui.dialogs.auth_dialog import AuthDialog
        AuthDialog(self.winfo_toplevel(), initial=self._auth, on_save=self._on_auth_saved)

    def _on_auth_saved(self, data: dict) -> None:
        self._auth = data or {}
        self._auth_btn.configure(text="🔐 認証✓" if self._auth else "🔐 認証")

    def _open_auth_b(self) -> None:
        from gui.dialogs.auth_dialog import AuthDialog
        AuthDialog(
            self.winfo_toplevel(), initial=self._auth_b, on_save=self._on_auth_b_saved,
            title="🔐  認証設定（第2セッション・IDOR比較用）",
        )

    def _on_auth_b_saved(self, data: dict) -> None:
        self._auth_b = data or {}
        self._auth_b_btn.configure(
            text="🔐 認証B✓(IDOR比較)" if self._auth_b else "🔐 認証B(IDOR比較・任意)"
        )

    def _stop(self) -> None:
        self._agent.stop()

    def _clear(self) -> None:
        self._out_box.clear()

    def _export_report(self) -> None:
        from gui import export_util
        export_util.export_html(
            "WEB FUZZ", self._target_entry.get().strip(),
            self._out_box.get_text(), self._llm.model,
            "web_fuzz", self._steps_widget.log, scan_result=getattr(self, "_scan_result", None),
        )

    def _export_pdf(self) -> None:
        from gui import export_util
        export_util.export_pdf(
            "WEB FUZZ", self._target_entry.get().strip(),
            self._out_box.get_text(), self._llm.model,
            "web_fuzz", self._steps_widget.log, scan_result=getattr(self, "_scan_result", None),
        )

    def _export_markdown(self) -> None:
        from gui import export_util
        export_util.export_markdown(
            "WEB FUZZ", self._target_entry.get().strip(),
            self._out_box.get_text(), self._llm.model,
            "web_fuzz", self._steps_widget.log, scan_result=getattr(self, "_scan_result", None),
        )

    def _export_json(self) -> None:
        from gui import export_util
        export_util.export_json(
            "WEB FUZZ", self._target_entry.get().strip(),
            self._out_box.get_text(), self._llm.model,
            "web_fuzz", self._steps_widget.log, scan_result=getattr(self, "_scan_result", None),
        )

    # ── EventBus dispatch ─────────────────────────────────
    def dispatch(self, event: ev.Event) -> None:
        k, p = event.kind, event.payload
        if k == ev.RESULT:
            self._scan_result = p
        elif k == ev.OUTPUT:
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
                state="normal", text="  FUZZ  ▶ ", fg_color=AMBER,
            )
            if p and not p.get("error"):
                self._steps_widget.set_progress(1.0)
