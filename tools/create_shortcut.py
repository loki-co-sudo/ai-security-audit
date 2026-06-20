#!/usr/bin/env python3
"""
tools/create_shortcut.py — デスクトップにアプリ起動ショートカットを作成する

実行:
    py tools/create_shortcut.py

生成物:
    （Windows）デスクトップに「AI Security Audit.lnk」
        - コンソール窓を出さずに起動（pythonw.exe）
        - assets/icon.ico をアイコンに使用
        - 作業ディレクトリをプロジェクトルートに設定

依存なし（PowerShell の WScript.Shell COM を利用）。Windows 専用。
"""
from __future__ import annotations
import os
import sys
import subprocess


def _pythonw() -> str:
    """コンソール窓を出さない pythonw.exe を探す。無ければ通常の実行体。"""
    exe = sys.executable
    cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
    return cand if os.path.exists(cand) else exe


def create(name: str = "AI Security Audit") -> str | None:
    if sys.platform != "win32":
        print("[INFO] デスクトップショートカットは Windows 専用です。")
        return None

    root     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    main_py  = os.path.join(root, "main.py")
    icon     = os.path.join(root, "assets", "icon.ico")
    pythonw  = _pythonw()

    # 初回起動前でも見栄えが良いようアイコンを生成しておく
    if not os.path.exists(icon):
        try:
            sys.path.insert(0, root)
            from assets import create_icon  # type: ignore
            create_icon.main()
        except Exception:
            pass

    # デスクトップの実パスは OneDrive 等にリダイレクトされ得るため
    # ~/Desktop と決め打ちせず PowerShell 側で正規に取得する。
    ps = f"""
$desktop = [Environment]::GetFolderPath('Desktop')
$lnk = Join-Path $desktop '{name}.lnk'
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut($lnk)
$sc.TargetPath = '{pythonw}'
$sc.Arguments = '"{main_py}"'
$sc.WorkingDirectory = '{root}'
$sc.IconLocation = '{icon}'
$sc.Description = 'AI Security Audit System'
$sc.WindowStyle = 1
$sc.Save()
Write-Output $lnk
"""
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            check=True, capture_output=True, text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        detail = getattr(e, "stderr", "") or str(e)
        print(f"[ERROR] ショートカット作成に失敗: {detail}")
        return None

    lnk_path = res.stdout.strip()
    print(f"[OK] ショートカットを作成しました: {lnk_path}")
    return lnk_path


if __name__ == "__main__":
    create()
