"""
gui/app.py — メインウィンドウ（3タブ統合エントリポイント）
"""

from __future__ import annotations
import ctypes
import customtkinter as ctk

import core.event_bus as ev
import core.config as config
from core.event_bus import EventBus
from core.llm_client import LLMClient
from core.settings import (
    APP_TITLE, BG_ROOT, BG_PANEL, BG_WIDGET, BORDER,
    CYAN, GREEN, RED_C, TEXT_DIM, TEXT_MID,
    TAB_AUDIT, TAB_ATTACK, TAB_DEFENSE,
)
from gui.panels.audit_panel import AuditPanel
from gui.panels.attack_panel import AttackPanel
from gui.panels.defense_panel import DefensePanel
from gui.dialogs.settings_dialog import SettingsDialog


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

_TABS = [
    ("◉  CODE AUDIT",    CYAN,        "audit"),
    ("◉  ATTACK MODE",   RED_C,       "attack"),
    ("◉  DEFENSE MODE",  GREEN,       "defense"),
]


class App(ctk.CTk):

    def __init__(self):
        super().__init__()
        self._setup_window()

        cfg = config.load()
        self._buses: dict[str, EventBus] = {
            "audit":   EventBus(),
            "attack":  EventBus(),
            "defense": EventBus(),
        }
        self._llm = LLMClient(
            base_url=cfg["llm_base_url"],
            api_key=cfg["llm_api_key"],
            model=cfg["llm_model"],
            timeout=cfg["llm_timeout"],
        )
        self._panels: dict[str, ctk.CTkFrame] = {}
        self._tab_btns: dict[str, tuple] = {}
        self._active  = "audit"

        self._build()
        self._switch_tab("audit")
        self.after(30, self._poll_events)

    # ── DPI-aware ウィンドウ初期化 ──────────────────────────────
    def _setup_window(self) -> None:
        self.title(APP_TITLE)
        self.configure(fg_color=BG_ROOT)

        try:
            dpi   = ctypes.windll.user32.GetDpiForWindow(self.winfo_id())
            scale = dpi / 96.0
        except Exception:
            scale = 1.0

        phys_w = self.winfo_screenwidth()
        phys_h = self.winfo_screenheight()
        log_w  = int(phys_w / scale * 0.91)
        log_h  = int(phys_h / scale * 0.89)
        self.geometry(f"{log_w}x{log_h}+0+0")
        self.minsize(int(720 / scale), int(500 / scale))

    # ── GUI 構築 ────────────────────────────────────────────────
    def _build(self) -> None:
        # ステータスバーを先にpackしてから expand=True のフレームを配置
        self._status_var = ctk.StringVar(value="  Ready — Ollama エンジンに接続してください")
        sbar = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=26)
        sbar.pack(side="bottom", fill="x")
        sbar.pack_propagate(False)
        ctk.CTkLabel(sbar, textvariable=self._status_var,
                     font=ctk.CTkFont("Consolas", 10), text_color=TEXT_DIM,
                     anchor="w").pack(side="left", padx=12)
        ctk.CTkLabel(sbar,
                     text="DEFENSE ONLY  ·  NO EXPLOIT SEND  ·  LOCAL STORAGE ONLY",
                     font=ctk.CTkFont("Segoe UI", 9), text_color="#1A3050",
                     anchor="e").pack(side="right", padx=12)

        # ヘッダーバー
        hbar = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=52)
        hbar.pack(fill="x")
        hbar.pack_propagate(False)

        # 右側ウィジェット（先にpack）
        self._status_dot = ctk.CTkLabel(
            hbar, text="●", width=18,
            font=ctk.CTkFont("Segoe UI", 14), text_color="#1A4020",
        )
        self._status_dot.pack(side="right", padx=(0, 16))

        ctk.CTkButton(
            hbar, text="⚙", width=34, height=34,
            fg_color="transparent", hover_color=BG_WIDGET,
            border_color=BORDER, border_width=1,
            text_color=TEXT_DIM, font=ctk.CTkFont("Segoe UI", 14),
            command=self._open_settings,
        ).pack(side="right", padx=(0, 8))

        self._engine_label = ctk.CTkLabel(
            hbar, text=f"ENGINE: {self._llm.model}",
            font=ctk.CTkFont("Consolas", 10), text_color=TEXT_DIM,
        )
        self._engine_label.pack(side="right", padx=(0, 6))

        # 左側タイトル
        ctk.CTkLabel(
            hbar, text="AI SECURITY",
            font=ctk.CTkFont("Segoe UI", 19, "bold"), text_color=CYAN,
        ).pack(side="left", padx=(16, 0), pady=10)
        ctk.CTkLabel(
            hbar, text="  ·  Autonomous Penetration Testing & Defense Platform",
            font=ctk.CTkFont("Segoe UI", 11), text_color=TEXT_DIM,
        ).pack(side="left")

        # タブバー
        tbar = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=44)
        tbar.pack(fill="x")
        tbar.pack_propagate(False)

        for label, color, key in _TABS:
            btn = ctk.CTkButton(
                tbar, text=label, width=180, height=36,
                fg_color="transparent", hover_color=BG_PANEL,
                border_width=0, corner_radius=0,
                text_color=TEXT_DIM, font=ctk.CTkFont("Segoe UI", 11),
                command=lambda k=key: self._switch_tab(k),
            )
            btn.pack(side="left", padx=(6, 0), pady=4)
            self._tab_btns[key] = (btn, color)

        # セパレーター
        ctk.CTkFrame(self, fg_color=BORDER, height=1).pack(fill="x")

        # コンテンツエリア
        self._content = ctk.CTkFrame(self, fg_color="transparent")
        self._content.pack(fill="both", expand=True, padx=8, pady=(6, 4))

        # 3パネルを生成（パック前の状態で作成）
        self._panels["audit"]   = AuditPanel(
            self._content,   self._buses["audit"],   self._llm)
        self._panels["attack"]  = AttackPanel(
            self._content,  self._buses["attack"],  self._llm)
        self._panels["defense"] = DefensePanel(
            self._content, self._buses["defense"], self._llm)

    # ── 設定ダイアログ ──────────────────────────────────────────
    def _open_settings(self) -> None:
        def on_save(model: str) -> None:
            self._engine_label.configure(text=f"ENGINE: {model}")
            self._status_var.set("  設定を保存しました。次回スキャンから反映されます。")
        SettingsDialog(self, self._llm, on_save)

    # ── タブ切り替え ────────────────────────────────────────────
    def _switch_tab(self, key: str) -> None:
        for panel in self._panels.values():
            panel.pack_forget()

        for k, (btn, color) in self._tab_btns.items():
            if k == key:
                btn.configure(
                    text_color=color,
                    fg_color=BG_PANEL,
                    border_width=2,
                    border_color=color,
                )
            else:
                btn.configure(
                    text_color=TEXT_DIM,
                    fg_color="transparent",
                    border_width=0,
                )

        self._active = key
        self._panels[key].pack(fill="both", expand=True)

    # ── EventBus ポーリング（30ms ごと） ─────────────────────────
    def _poll_events(self) -> None:
        for key, bus in self._buses.items():
            panel = self._panels[key]
            for event in bus.drain(limit=50):
                panel.dispatch(event)
                if event.kind == ev.STATUS:
                    self._status_var.set(f"  [{key.upper()}] {event.payload}")
                    self._status_dot.configure(text_color=GREEN)
                elif event.kind == ev.DONE:
                    is_err = (isinstance(event.payload, dict)
                              and event.payload.get("error", False))
                    self._status_dot.configure(
                        text_color=RED_C if is_err else "#1A4020"
                    )
                    if not is_err:
                        self._status_var.set(f"  [{key.upper()}] 完了")

        self.after(30, self._poll_events)
