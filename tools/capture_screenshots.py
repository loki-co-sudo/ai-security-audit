#!/usr/bin/env python3
"""
tools/capture_screenshots.py — README用スクリーンショット自動撮影

Usage (プロジェクトルートから実行):
    py tools/capture_screenshots.py
"""
import sys
import os

# プロジェクトルートを sys.path に追加
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _root)
os.chdir(_root)

# openai を事前ロードして App 生成時のフリーズを防ぐ
try:
    import openai  # noqa: F401
except ImportError:
    pass

import core.config as config
config.load()

from PIL import ImageGrab
import customtkinter as ctk

import ctypes
import ctypes.wintypes
import gui.app as _app_module
_OrigApp = _app_module.App

_OUT   = os.path.join(_root, "docs")
_u32   = ctypes.windll.user32
_dwmapi = ctypes.windll.dwmapi


def _window_rect(hwnd: int) -> tuple[int, int, int, int]:
    """DWM ビジュアル境界を取得（影・余白なし）。失敗時は GetWindowRect で代替。"""
    rect = ctypes.wintypes.RECT()
    try:
        _dwmapi.DwmGetWindowAttribute(hwnd, 9, ctypes.byref(rect), ctypes.sizeof(rect))
        if rect.right > rect.left:
            return rect.left, rect.top, rect.right, rect.bottom
    except Exception:
        pass
    _u32.GetWindowRect(hwnd, ctypes.byref(rect))
    return rect.left, rect.top, rect.right, rect.bottom


class _ScreenshotApp(_OrigApp):
    """スクリーンショット撮影専用: 起動後に最大化して全タブを撮影し終了する。"""

    def _setup_window(self) -> None:
        super()._setup_window()
        self.state("zoomed")           # 最大化

    def __init__(self):
        super().__init__()
        self.after(2500, self._step_audit)   # 最大化アニメーション完了待ち

    # ── 撮影ユーティリティ ──────────────────────────────────
    def _grab(self, filename: str) -> None:
        self.lift()
        self.focus_force()
        self.update()
        # ctypes で実際の物理ピクセル矩形を取得 (winfo は論理座標のため)
        hwnd = _u32.GetForegroundWindow()
        l, t, r, b = _window_rect(hwnd)
        path = os.path.join(_OUT, filename)
        ImageGrab.grab(bbox=(l, t, r, b)).save(path)
        print(f"  Saved: {path}  ({r-l}x{b-t}px)")

    # ── 撮影シーケンス ──────────────────────────────────────
    def _step_audit(self):
        self._switch_tab("audit")
        self.after(500, self._do_audit)

    def _do_audit(self):
        self._grab("screenshot_audit.png")
        self.after(300, self._step_attack)

    def _step_attack(self):
        self._switch_tab("attack")
        self.after(500, self._do_attack)

    def _do_attack(self):
        self._grab("screenshot_attack.png")
        self.after(300, self._step_defense)

    def _step_defense(self):
        self._switch_tab("defense")
        self.after(500, self._do_defense)

    def _do_defense(self):
        self._grab("screenshot_defense.png")
        self.after(300, self.quit)


if __name__ == "__main__":
    os.makedirs(_OUT, exist_ok=True)
    print("Starting screenshot capture...")
    app = _ScreenshotApp()
    app.mainloop()
    print("Done!")
