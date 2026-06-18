"""
gui/widgets/progress_steps.py — ステップ進捗ウィジェット（共通部品）
"""

from __future__ import annotations
import customtkinter as ctk
from core.settings import (
    BG_PANEL, BG_WIDGET, CYAN, GREEN, RED_C, TEXT_DIM, TEXT_PRI, BORDER,
    SEV_COLORS,
)

_STATES = {
    "idle":    ("⬜", TEXT_DIM,  TEXT_DIM),
    "running": ("▶ ", CYAN,     TEXT_PRI),
    "done":    ("✓ ", GREEN,    GREEN),
    "error":   ("✗ ", RED_C,    RED_C),
}


class ProgressSteps(ctk.CTkFrame):
    """
    ステップリスト + プログレスバー + 深刻度バッジ のまとまったウィジェット。
    """

    def __init__(
        self,
        master,
        steps: list[str],
        show_stats: bool = True,
        **kwargs,
    ):
        kwargs.setdefault("fg_color",     BG_PANEL)
        kwargs.setdefault("corner_radius", 8)
        super().__init__(master, **kwargs)

        self._steps      = steps
        self._show_stats = show_stats
        self._icons:  list[ctk.CTkLabel] = []
        self._labels: list[ctk.CTkLabel] = []
        self._stat_vars: dict[str, ctk.StringVar] = {}

        self._build()

    def _build(self) -> None:
        # タイトル
        ctk.CTkLabel(
            self, text="SCAN PROGRESS",
            font=ctk.CTkFont("Segoe UI", 11, "bold"),
            text_color=CYAN,
        ).pack(anchor="w", padx=14, pady=(12, 4))

        # プログレスバー
        self._pbar = ctk.CTkProgressBar(
            self, mode="determinate",
            fg_color=BG_WIDGET, progress_color=CYAN, height=5,
        )
        self._pbar.set(0)
        self._pbar.pack(fill="x", padx=14, pady=(0, 8))

        # ステップリスト
        sf = ctk.CTkScrollableFrame(self, fg_color="transparent", height=260)
        sf.pack(fill="x", padx=8)

        for i, label_text in enumerate(self._steps):
            row = ctk.CTkFrame(sf, fg_color="transparent", height=32)
            row.pack(fill="x", pady=1)
            row.pack_propagate(False)

            icon = ctk.CTkLabel(row, text="⬜", width=24,
                                font=ctk.CTkFont("Segoe UI", 13), text_color=TEXT_DIM)
            icon.pack(side="left", padx=(4, 2))
            self._icons.append(icon)

            ctk.CTkLabel(row, text=f"[{i+1}/{len(self._steps)}]",
                         font=ctk.CTkFont("Consolas", 10), text_color=TEXT_DIM, width=50
                         ).pack(side="left")

            lbl = ctk.CTkLabel(row, text=label_text,
                               font=ctk.CTkFont("Segoe UI", 11), text_color=TEXT_DIM, anchor="w")
            lbl.pack(side="left", padx=4)
            self._labels.append(lbl)

        # 区切り線
        ctk.CTkFrame(self, fg_color=BORDER, height=1).pack(fill="x", padx=12, pady=8)

        if self._show_stats:
            self._build_stats()

        # システムログ
        ctk.CTkLabel(self, text="SYSTEM LOG",
                     font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=CYAN,
                     ).pack(anchor="w", padx=14, pady=(0, 4))

        self._log_box = ctk.CTkTextbox(
            self, fg_color=BG_WIDGET, text_color=TEXT_DIM,
            font=ctk.CTkFont("Consolas", 9),
            corner_radius=6, height=130, wrap="word", state="disabled",
        )
        self._log_box.pack(fill="x", padx=10, pady=(0, 10))

    def _build_stats(self) -> None:
        ctk.CTkLabel(self, text="DETECTION SUMMARY",
                     font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=CYAN,
                     ).pack(anchor="w", padx=14, pady=(0, 6))

        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.pack(fill="x", padx=10)
        grid.columnconfigure((0, 1), weight=1)

        for i, (sev, color) in enumerate(SEV_COLORS.items()):
            box = ctk.CTkFrame(grid, fg_color=BG_WIDGET, corner_radius=6)
            box.grid(row=i // 2, column=i % 2, padx=3, pady=3, sticky="ew")
            var = ctk.StringVar(value="0")
            self._stat_vars[sev] = var
            ctk.CTkLabel(box, text=sev, font=ctk.CTkFont("Segoe UI", 9, "bold"), text_color=color).pack(pady=(8, 2))
            ctk.CTkLabel(box, textvariable=var, font=ctk.CTkFont("Segoe UI", 19, "bold"), text_color=color).pack(pady=(0, 8))

        ctk.CTkFrame(self, fg_color=BORDER, height=1).pack(fill="x", padx=12, pady=8)

    # ── 公開 API ──────────────────────────────────────────
    def set_step(self, idx: int, state: str) -> None:
        """GUIスレッドから呼ぶこと。"""
        if idx < 0 or idx >= len(self._icons):
            return
        icon_txt, icon_color, txt_color = _STATES.get(state, _STATES["idle"])
        self._icons[idx].configure(text=icon_txt, text_color=icon_color)
        self._labels[idx].configure(text_color=txt_color)
        progress = (idx + (1 if state == "done" else 0.45)) / len(self._steps)
        self._pbar.set(progress)

    def set_progress(self, value: float) -> None:
        self._pbar.set(max(0.0, min(1.0, value)))

    def set_stats(self, counts: dict) -> None:
        for sev, var in self._stat_vars.items():
            var.set(str(counts.get(sev, 0)))

    def log(self, msg: str) -> None:
        self._log_box.configure(state="normal")
        self._log_box.insert("end", msg + "\n")
        self._log_box._textbox.see("end")
        self._log_box.configure(state="disabled")

    def reset(self) -> None:
        for icon, lbl in zip(self._icons, self._labels):
            icon.configure(text="⬜", text_color=TEXT_DIM)
            lbl.configure(text_color=TEXT_DIM)
        self._pbar.set(0)
        for var in self._stat_vars.values():
            var.set("0")
        self._log_box.configure(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.configure(state="disabled")
