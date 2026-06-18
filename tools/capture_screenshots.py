#!/usr/bin/env python3
"""
tools/capture_screenshots.py — README用スクリーンショット自動撮影

Usage (プロジェクトルートから実行):
    py tools/capture_screenshots.py
"""
import sys
import os

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _root)
os.chdir(_root)

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

_OUT = os.path.join(_root, "docs")
_u32 = ctypes.windll.user32


class _ScreenshotApp(_OrigApp):
    """スクリーンショット撮影専用。タイトルバーなし全画面ウィンドウで撮影する。"""

    def _setup_window(self) -> None:
        super()._setup_window()

        # winfo_screenwidth/height は DPI 対応プロセスでは物理ピクセルを返す
        phys_w = self.winfo_screenwidth()
        phys_h = self.winfo_screenheight()

        # tkinter の geometry は論理ピクセルなので DPI スケールで割る
        try:
            dpi   = _u32.GetDpiForWindow(self.winfo_id())
            scale = dpi / 96.0
        except Exception:
            scale = 1.0

        log_w = int(phys_w / scale)
        log_h = int(phys_h / scale)

        self.geometry(f"{log_w}x{log_h}+0+0")  # 画面全体を論理サイズで指定
        self.overrideredirect(True)             # タイトルバー・ボーダーなし
        self.attributes("-topmost", True)       # 常に最前面

        # キャプチャ時に参照する物理サイズを保存
        self._phys_w = phys_w
        self._phys_h = phys_h

    def __init__(self):
        super().__init__()
        self.after(2500, self._step_audit)

    # ── 撮影ユーティリティ ──────────────────────────────────
    def _grab(self, filename: str) -> None:
        self.lift()
        self.update()
        path = os.path.join(_OUT, filename)
        # 物理座標 (0,0)-(phys_w, phys_h) でプライマリモニターを撮影
        img = ImageGrab.grab(bbox=(0, 0, self._phys_w, self._phys_h))
        img.save(path)
        print(f"  Saved: {path}  ({img.width}x{img.height}px)")

    # ── 撮影シーケンス ──────────────────────────────────────
    def _step_audit(self):
        self._switch_tab("audit")
        self.after(600, self._do_audit)

    def _do_audit(self):
        self._grab("screenshot_audit.png")
        self.after(300, self._step_attack)

    def _step_attack(self):
        self._switch_tab("attack")
        self.after(600, self._do_attack)

    def _do_attack(self):
        self._grab("screenshot_attack.png")
        self.after(300, self._step_defense)

    def _step_defense(self):
        self._switch_tab("defense")
        self.after(600, self._do_defense)

    def _do_defense(self):
        self._grab("screenshot_defense.png")
        self.after(300, self.quit)


if __name__ == "__main__":
    os.makedirs(_OUT, exist_ok=True)
    print("Starting screenshot capture...")
    app = _ScreenshotApp()
    app.mainloop()
    print("Done!")
