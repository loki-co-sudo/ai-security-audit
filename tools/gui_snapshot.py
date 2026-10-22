#!/usr/bin/env python3
"""GUIの目視確認用スナップショット(Linux)。仮想ディスプレイ(xvfb-run)で起動するため、利用者の画面には何も出さない。

  python tools/gui_snapshot.py OUTDIR

4タブ・設定ダイアログ・認証ダイアログ・期待権限表ダイアログのPNGをOUTDIRへ保存する(ImageMagickのimportが必要。xfwm4があればウィンドウマネージャ付き)。
実スキャンは行わず、設定の保存もしない(ダイアログは開くだけ)。画像を人が/AIが見て確認するための補助で、自動判定はしない。
レイアウトの回帰は tools/test_gui_layout.py が固定する。
"""
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _child(out: str) -> int:
    sys.path.insert(0, ROOT)
    os.chdir(ROOT)
    import gui.app as app_module

    app = app_module.App()

    def shot(name: str) -> None:
        for _ in range(5):
            app.update_idletasks()
            app.update()
            time.sleep(0.3)
        subprocess.run(["import", "-window", "root", os.path.join(out, name + ".png")], check=True)

    for key in ("audit", "attack", "fuzz", "defense"):
        app._switch_tab(key)
        shot(f"tab_{key}")
    app._open_settings()
    shot("settings")
    app._settings_dialog.destroy()
    app.update()
    app._switch_tab("fuzz")
    from gui.dialogs.auth_dialog import AuthDialog
    dlg = AuthDialog(app, initial={}, on_save=lambda *a, **k: None)
    shot("auth")
    dlg.destroy()
    from gui.dialogs.expectations_dialog import ExpectationsDialog
    exp = ExpectationsDialog(app, initial=[{"path": "/account", "param": "id", "value": "1", "a": "allow", "b": "deny"}],
                             on_save=lambda *a, **k: None)
    exp._text.insert("end", "\n/bad id a=maybe b=deny")
    exp._save()                       # 不正行のエラー表示も撮る
    shot("expectations")
    exp.destroy()
    app.destroy()
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    out = os.path.abspath(argv[1])
    if os.environ.get("GUI_SNAPSHOT_CHILD") == "1":
        return _child(out)
    for tool in ("xvfb-run", "import"):
        if not shutil.which(tool):
            print(f"{tool} が見つかりません(xvfb と imagemagick が必要です)")
            return 2
    os.makedirs(out, exist_ok=True)
    wm = "xfwm4 --compositor=off >/dev/null 2>&1 & sleep 2; " if shutil.which("xfwm4") else ""
    cmd = f'{wm}exec "$0" "$1" "$2"'
    env = {**os.environ, "GUI_SNAPSHOT_CHILD": "1"}
    return subprocess.run(["xvfb-run", "-a", "-s", "-screen 0 1600x1000x24", "bash", "-c", cmd,
                           sys.executable, os.path.abspath(__file__), out], env=env, timeout=120).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv))
