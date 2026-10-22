"""
gui/dialogs/expectations_dialog.py — IDOR期待権限表の入力ダイアログ（WEB FUZZ・第2セッション比較用）

1行1ルール `PATH PARAM [VALUE] a=allow|deny b=allow|deny`。path/param/期待権限だけを入力し、秘密値は入れない。
保存時に core.engagement.parse_expectation_lines で検証し、エラーは行番号つきで表示して閉じない。
"""

from __future__ import annotations
import customtkinter as ctk

from core.engagement import EngagementError, format_expectation_lines, parse_expectation_lines
from core.settings import (
    BG_PANEL, BG_WIDGET, BG_INPUT, CYAN, AMBER, TEXT_PRI, TEXT_DIM, BORDER, RED_C,
)
from gui.dialogs.base import RobustToplevel

_HELP = (
    "セッションA(主)・B(第2)の期待権限を、1行に1ルールで書きます。\n"
    "  書式: PATH PARAM [VALUE] a=allow|deny b=allow|deny\n"
    "  例  : /account id 1 a=allow b=deny   (所有者Aだけが読める。Bが読めたら違反の根拠)\n"
    "        /public id a=allow b=allow     (公開。VALUE省略=そのparamの全値)\n"
    "空行と # で始まる行は無視されます。表に無いURLは従来どおり『要人手確認』の観測として扱います。"
)


class ExpectationsDialog(RobustToplevel):

    def __init__(self, master, initial: list | None = None, on_save: callable = None):
        super().__init__(master)
        self._on_save = on_save
        self.title("IDOR 期待権限表")
        self.configure(fg_color=BG_PANEL)
        self.geometry("680x520")
        self.minsize(560, 400)
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self._build(format_expectation_lines(initial))
        self._apply_dark_titlebar()
        self.after(80, lambda: self._bring_to_front(grab=True))

    def _build(self, text: str) -> None:
        hdr = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="📋  IDOR 期待権限表（第2セッション比較用）",
                     font=ctk.CTkFont("Segoe UI", 14, "bold"), text_color=AMBER).pack(side="left", padx=16, pady=12)

        # ボタン行を先にpackする(side="bottom"は本体より前。小さい窓でも保存が見える)
        btn_row = self._btn_row = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=56)
        btn_row.pack(fill="x", side="bottom")
        btn_row.pack_propagate(False)
        ctk.CTkButton(
            btn_row, text="キャンセル", width=110, height=36, fg_color="#152030", hover_color="#1E3040",
            border_color=BORDER, border_width=1, text_color=TEXT_DIM,
            font=ctk.CTkFont("Segoe UI", 11), command=self.destroy,
        ).pack(side="right", padx=12, pady=10)
        ctk.CTkButton(
            btn_row, text="保存", width=110, height=36, fg_color=CYAN, hover_color="#00B5DD", text_color=BG_PANEL,
            font=ctk.CTkFont("Segoe UI", 12, "bold"), command=self._save,
        ).pack(side="right", padx=(0, 6), pady=10)
        ctk.CTkButton(
            btn_row, text="クリア", width=100, height=36, fg_color="#2A1A00", hover_color="#3A2400",
            border_color=AMBER, border_width=1, text_color=AMBER,
            font=ctk.CTkFont("Segoe UI", 11), command=lambda: self._text.delete("1.0", "end"),
        ).pack(side="left", padx=12, pady=10)

        self._error = ctk.CTkLabel(self, text="", font=ctk.CTkFont("Segoe UI", 10), text_color=RED_C,
                                   anchor="w", justify="left", wraplength=620)
        self._error.pack(side="bottom", fill="x", padx=20, pady=(0, 4))

        ctk.CTkLabel(self, text=_HELP, font=ctk.CTkFont("Consolas", 10), text_color=TEXT_DIM,
                     anchor="w", justify="left", wraplength=640).pack(fill="x", padx=20, pady=(10, 4))
        self._text = ctk.CTkTextbox(self, font=ctk.CTkFont("Consolas", 12), fg_color=BG_INPUT, border_color=BORDER,
                                    border_width=1, text_color=TEXT_PRI)
        self._text.pack(fill="both", expand=True, padx=20, pady=(0, 6))
        self._text.insert("1.0", text)

    def _save(self) -> None:
        try:
            rows = parse_expectation_lines(self._text.get("1.0", "end"))
        except EngagementError as e:
            self._error.configure(text=f"⚠ {e}")
            return
        if self._on_save:
            self._on_save(rows)
        self.destroy()
