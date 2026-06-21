"""
gui/dialogs/base.py — ダイアログ共通の基底クラス

CTkToplevel は __init__ 内の _windows_set_titlebar_color() で super().withdraw()+
update() を呼びウィンドウを一時的に隠す。これがマルチモニター環境やスプラッシュ
併用時に「ウィンドウが最背面へ飛ぶ」「同期構築したウィジェットが空/白箱になる」
原因になる。タイトルバー処理を無効化し、メインウィンドウ同様の通常マップ状態で
構築する。ダークタイトルバーは withdraw 無しで自前適用する。
"""
from __future__ import annotations
import sys
import tkinter as tk
import customtkinter as ctk


class RobustToplevel(ctk.CTkToplevel):
    """確実に前面・正常描画される CTkToplevel。"""

    _deactivate_windows_window_header_manipulation = True

    def _apply_dark_titlebar(self) -> None:
        """withdraw せずにダークタイトルバーを適用する（Windows のみ）。"""
        if not sys.platform.startswith("win"):
            return
        try:
            import ctypes
            self.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            value = ctypes.c_int(1)
            for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (20H1 と旧)
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(value), ctypes.sizeof(value))
        except Exception:
            pass

    def _bring_to_front(self, grab: bool = True) -> None:
        """前面化・フォーカス。grab=True ならモーダル化する。"""
        self.lift()
        # マルチモニターで z 順が乱れることがあるため一時的に最前面化する。
        self.attributes("-topmost", True)
        self.after(300, lambda: self.attributes("-topmost", False))
        self.focus_force()
        if grab:
            try:
                self.grab_set()
            except tk.TclError:
                # ウィンドウがまだ viewable でない場合はリトライ
                self.after(50, lambda: self._bring_to_front(grab=True))
