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

import gui.app as _app_module
_OrigApp = _app_module.App

_OUT = os.path.join(_root, "docs")


class _ScreenshotApp(_OrigApp):
    """スクリーンショット撮影専用: 起動 2 秒後に全タブを撮影して終了する。"""

    def __init__(self):
        super().__init__()
        self.after(2000, self._step_audit)

    # ── 撮影ユーティリティ ──────────────────────────────────
    def _grab(self, filename: str) -> None:
        self.lift()
        self.focus_force()
        self.update()
        x = self.winfo_rootx()
        y = self.winfo_rooty()
        w = self.winfo_width()
        h = self.winfo_height()
        path = os.path.join(_OUT, filename)
        ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(path)
        print(f"  Saved: {path}  ({w}x{h}px)")

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
