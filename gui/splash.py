"""
gui/splash.py — 起動スプラッシュスクリーン

customtkinter を使わず標準 tkinter のみで構成し、Python 起動から
0.1 秒以内にウィンドウを表示する。重いモジュールの読み込み状況を
プログレスバーで可視化する。
"""
from __future__ import annotations
import tkinter as tk

_BG   = "#070C14"
_CYAN = "#00D4FF"
_DIM  = "#1A3050"
_MID  = "#4A6A8A"


class SplashScreen:
    """重いモジュール読み込み中に表示する起動画面。"""

    W, H = 540, 210

    def __init__(self) -> None:
        root = tk.Tk()
        root.overrideredirect(True)          # タイトルバーなし
        root.configure(bg=_DIM)              # 1 px ボーダー効果
        root.attributes("-topmost", True)
        root.resizable(False, False)

        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        x  = (sw - self.W) // 2
        y  = (sh - self.H) // 2
        root.geometry(f"{self.W}x{self.H}+{x}+{y}")

        # 内部フレーム（背景色）
        inner = tk.Frame(root, bg=_BG)
        inner.pack(fill="both", expand=True, padx=1, pady=1)

        # タイトル
        tk.Label(
            inner,
            text="AI SECURITY AUDIT SYSTEM",
            fg=_CYAN, bg=_BG,
            font=("Segoe UI", 20, "bold"),
        ).pack(pady=(26, 4))

        tk.Label(
            inner,
            text="Autonomous Penetration Testing & Defense Platform  v2.1",
            fg=_MID, bg=_BG,
            font=("Segoe UI", 9),
        ).pack()

        # プログレスバー
        bar_bg = tk.Frame(inner, bg=_DIM, height=3)
        bar_bg.pack(fill="x", padx=44, pady=(20, 6))
        bar_bg.pack_propagate(False)

        self._bar = tk.Frame(bar_bg, bg=_CYAN, height=3)
        self._bar.place(x=0, y=0, relwidth=0.0, height=3)

        # ステータステキスト
        self._status = tk.StringVar(value="Initializing ...")
        tk.Label(
            inner,
            textvariable=self._status,
            fg=_DIM, bg=_BG,
            font=("Consolas", 9),
        ).pack()

        self._root = root
        root.update()

    # ────────────────────────────────────────────────
    def set(self, ratio: float, status: str = "") -> None:
        """プログレスバーを ratio (0.0–1.0) に更新し、ステータスを表示。"""
        ratio = max(0.0, min(1.0, ratio))
        self._bar.place(relwidth=ratio, height=3)
        if status:
            self._status.set(status)
        self._root.update()

    def close(self) -> None:
        """スプラッシュウィンドウを破棄する。"""
        try:
            self._root.destroy()
        except Exception:
            pass
