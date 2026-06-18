"""
gui/widgets/output_box.py — カラータグ付きスクロール出力ボックス（共通部品）
"""

import customtkinter as ctk
import tkinter.font as tkfont
from core.settings import (
    BG_WIDGET, TEXT_PRI, TEXT_DIM, TEXT_MID,
    CYAN, GREEN, RED_C, ORANGE_H, YELLOW_M, GREEN_L, PURPLE, BORDER,
)


def _best_mono(size: int, bold: bool = False) -> tuple:
    fams   = tkfont.families()
    weight = "bold" if bold else "normal"
    for name in ("Cascadia Code", "Cascadia Mono", "JetBrains Mono", "Fira Code", "Consolas"):
        if name in fams:
            return (name, size, weight)
    return ("Courier New", size, weight)


class OutputBox(ctk.CTkTextbox):
    """
    カラータグ付きスクロール可能テキストボックス。
    バックグラウンドスレッドからは insert_tagged() ではなく
    EventBus 経由で呼び出すこと（tkinter はスレッドセーフでない）。
    """

    TAG_CONFIG = {
        "header":   (CYAN,     True,  12),
        "section":  (PURPLE,   True,  11),
        "critical": (RED_C,    True,  11),
        "high":     (ORANGE_H, True,  11),
        "medium":   (YELLOW_M, False, 11),
        "low":      (GREEN_L,  False, 11),
        "code":     ("#9CDCFE", False, 10),
        "fix":      (GREEN,    False, 10),
        "attack":   (ORANGE_H, False, 10),
        "dim":      (TEXT_DIM, False, 10),
        "label":    (CYAN,     True,  10),
        "green":    (GREEN,    False, 11),
        "sep":      (BORDER,   False, 11),
    }

    def __init__(self, master, **kwargs):
        kwargs.setdefault("fg_color",   BG_WIDGET)
        kwargs.setdefault("text_color", TEXT_PRI)
        kwargs.setdefault("font",       ctk.CTkFont("Consolas", 11))
        kwargs.setdefault("wrap",       "word")
        kwargs.setdefault("state",      "disabled")
        super().__init__(master, **kwargs)

        tb = self._textbox
        for tag, (color, bold, size) in self.TAG_CONFIG.items():
            tb.tag_configure(tag, foreground=color, font=_best_mono(size, bold))

    # ── 公開 API ──────────────────────────────────────────
    def append(self, text: str, tag: str = "") -> None:
        """テキストを末尾に追記する。GUIスレッドから呼ぶこと。"""
        tb = self._textbox
        self.configure(state="normal")
        if tag:
            tb.insert("end", text, tag)
        else:
            tb.insert("end", text)
        tb.see("end")
        self.configure(state="disabled")

    def get_text(self) -> str:
        """現在表示されているテキストを文字列で返す（レポート出力用）。"""
        return self._textbox.get("1.0", "end")

    def clear(self) -> None:
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.configure(state="disabled")
