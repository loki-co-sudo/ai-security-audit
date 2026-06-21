"""
main.py — エントリポイント

起動順序:
  1. ディレクトリ / __init__.py を確認（高速）
  2. スプラッシュスクリーンを表示（tkinter のみ、~0.1s）
  3. 設定ロード
  4. 初回のみアイコン生成
  5. customtkinter を含む GUI モジュールをインポート（~1s）
  6. openai を明示的にプリロード（~4s、プログレス可視化）
  7. App を生成してメインループへ
"""

import os
import sys


def _ensure_dirs() -> None:
    for d in ("reports", "assets", "gui/panels", "gui/widgets", "agents", "tools", "core"):
        os.makedirs(d, exist_ok=True)


def _ensure_inits() -> None:
    for pkg in ("gui", "gui/panels", "gui/widgets", "gui/dialogs", "core", "agents", "tools"):
        init = os.path.join(pkg, "__init__.py")
        if not os.path.exists(init):
            open(init, "w").close()


def _ensure_icon(splash=None) -> None:
    """初回起動時のみアイコンを生成する（Pillow が利用可能な場合）。"""
    root_dir  = os.path.dirname(os.path.abspath(__file__))
    ico_path  = os.path.join(root_dir, "assets", "icon.ico")
    if os.path.exists(ico_path):
        return
    try:
        import importlib.util
        if importlib.util.find_spec("PIL") is None:
            return
        if splash:
            splash.set(0.12, "アイコンを生成中 ...")
        script = os.path.join(root_dir, "assets", "create_icon.py")
        spec   = importlib.util.spec_from_file_location("create_icon", script)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod.main()
    except Exception:
        pass  # アイコンなしで続行


def _set_app_user_model_id() -> None:
    """Windowsタスクバーで自前アイコンを表示させる。

    未設定だと python.exe のアイコンでグルーピングされ icon.ico が反映されない。
    GUIウィンドウ生成より前に呼ぶ必要がある。
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "AISecurity.AuditSystem.2"
        )
    except Exception:
        pass


def main() -> None:
    _ensure_dirs()
    _ensure_inits()
    _set_app_user_model_id()

    # ── 1. スプラッシュを即時表示（tkinter のみ、~0.1s） ─────────
    from gui.splash import SplashScreen
    splash = SplashScreen()
    splash.set(0.05, "設定を読み込み中 ...")

    # ── 2. 設定 ─────────────────────────────────────────────────
    import core.config as config
    config.load()

    # ── 3. アイコン生成（初回のみ） ──────────────────────────────
    _ensure_icon(splash)
    splash.set(0.14, "UIフレームワークを読み込み中 ...")

    # ── 4. GUI モジュール（customtkinter ~1s、openai は遅延済み） ─
    from gui.app import App  # noqa: E402
    splash.set(0.58, "LLMクライアントを初期化中 ...")

    # ── 5. openai を明示的にプリロード（~4s） ───────────────────
    #       ここで読み込むことでプログレスバーに 4s を正確に反映する。
    #       App() 内の LLMClient.__init__ は Python のキャッシュを利用するため即時。
    try:
        import openai  # noqa: F401, E402
    except ImportError:
        pass
    splash.set(0.90, "インターフェースを構築中 ...")

    # ── 6. App 生成 ──────────────────────────────────────────────
    app = App()

    # スプラッシュは独自の一時 tk.Tk() ルートを持ち、これが tkinter の
    # デフォルトルートを占有している。splash.close() で破棄するとデフォルト
    # ルートが None になり、以降に master 未指定で生成する tkinter.Variable や
    # Font（= 設定ダイアログ等）が "no default root" 例外で失敗する。
    # App を明示的にデフォルトルートにしておくことで破棄後も None にならない。
    import tkinter as _tk
    _tk._default_root = app

    splash.set(1.0, "起動完了")
    splash.close()

    app.mainloop()


if __name__ == "__main__":
    main()
