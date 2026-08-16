#!/usr/bin/env python3
"""
tools/create_shortcut.py — デスクトップにアプリ起動ショートカットを作成する

実行:
    py tools/create_shortcut.py            （Windows）
    .venv/bin/python3 tools/create_shortcut.py   （Linux）

生成物:
    （Windows）デスクトップに「AI Security Audit.lnk」
        - コンソール窓を出さずに起動（pythonw.exe）
        - assets/icon.ico をアイコンに使用
        - 作業ディレクトリをプロジェクトルートに設定
    （Linux）デスクトップと ~/.local/share/applications/ に
        「AI Security Audit.desktop」（XDGデスクトップエントリ）
        - .venv/bin/python3（無ければ python3）で main.py を起動
        - assets/icon.png をアイコンに使用
        - xdg-user-dir で実際のデスクトップパスを取得（日本語ロケール等の
          「デスクトップ」フォルダ名にも対応。~/Desktop 決め打ちにしない）

依存なし。Windows は PowerShell の WScript.Shell COM、Linux は標準の
XDGデスクトップエントリ形式（.desktop）を使う。macOS 等その他は未対応。
"""
from __future__ import annotations
import os
import stat
import sys
import subprocess


def _pythonw() -> str:
    """コンソール窓を出さない pythonw.exe を探す。無ければ通常の実行体。"""
    exe = sys.executable
    cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
    return cand if os.path.exists(cand) else exe


def _venv_python(root: str) -> str:
    """プロジェクト専用 .venv の python3 を優先する。無ければ system の python3/python。

    本プロジェクトの依存（customtkinter 等）は .venv にのみインストールされる方針
    （CLAUDE.md）のため、素の python3 だと ModuleNotFoundError になる。
    """
    venv_py = os.path.join(root, ".venv", "bin", "python3")
    if os.path.exists(venv_py):
        return venv_py
    for cand in ("python3", "python"):
        found = _which(cand)
        if found:
            return found
    return sys.executable


def _which(cmd: str) -> str | None:
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, cmd)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _build_desktop_entry(name: str, exec_line: str, icon_path: str, workdir: str,
                          comment: str = "AI Security Audit System") -> str:
    """XDGデスクトップエントリ（.desktop）の中身を組み立てる純粋関数（副作用なし）。

    ファイルI/Oを含まないため、生成内容だけを単体テストできる
    （tools/run_selftest.py の「18. TOOLS — DesktopShortcut」参照）。
    """
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={name}\n"
        f"Comment={comment}\n"
        f"Exec={exec_line}\n"
        f"Path={workdir}\n"
        f"Icon={icon_path}\n"
        "Terminal=false\n"
        "Categories=Security;Development;\n"
    )


def _linux_desktop_dir() -> str:
    """実際のデスクトップパスを取得する（xdg-user-dir 経由。日本語ロケール等の
    リダイレクトにも対応。取得できなければ ~/Desktop にフォールバック）。
    """
    xdg = _which("xdg-user-dir")
    if xdg:
        try:
            out = subprocess.run(
                [xdg, "DESKTOP"], check=True, capture_output=True, text=True,
            ).stdout.strip()
            if out and os.path.isdir(out):
                return out
        except (subprocess.CalledProcessError, OSError):
            pass
    return os.path.expanduser("~/Desktop")


def _create_linux(name: str, root: str) -> str | None:
    main_py = os.path.join(root, "main.py")
    icon    = os.path.join(root, "assets", "icon.png")
    python  = _venv_python(root)
    exec_line = f'"{python}" "{main_py}"'
    content = _build_desktop_entry(name, exec_line, icon, root)

    targets = []
    desktop_dir = _linux_desktop_dir()
    if os.path.isdir(desktop_dir):
        targets.append(os.path.join(desktop_dir, f"{name}.desktop"))
    apps_dir = os.path.expanduser("~/.local/share/applications")
    os.makedirs(apps_dir, exist_ok=True)
    targets.append(os.path.join(apps_dir, f"{name}.desktop"))

    written: list[str] = []
    for path in targets:
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            # 多くのデスクトップ環境は実行ビットが無いとランチャーとして扱わない。
            st = os.stat(path)
            os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            written.append(path)
        except OSError as e:
            print(f"[WARN] {path} への書き込みに失敗: {e}")

    if not written:
        print("[ERROR] デスクトップショートカットの作成に失敗しました。")
        return None

    # GNOME/Nautilus 系は初回、ユーザーによる「起動を許可」の手動操作が必要な場合がある
    # （信頼済みマーク。gio が無い環境や対象外の環境では何もしない）。
    gio = _which("gio")
    if gio:
        for path in written:
            try:
                subprocess.run(
                    [gio, "set", path, "metadata::trusted", "true"],
                    check=False, capture_output=True,
                )
            except OSError:
                pass

    for path in written:
        print(f"[OK] ショートカットを作成しました: {path}")
    print("[INFO] デスクトップ環境によっては、アイコンを右クリックして「起動を許可する」")
    print("       等の初回確認が必要な場合があります。")
    return written[0]


def create(name: str = "AI Security Audit") -> str | None:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    if sys.platform.startswith("linux"):
        return _create_linux(name, root)

    if sys.platform != "win32":
        print(f"[INFO] デスクトップショートカットは Windows / Linux のみ対応です（platform={sys.platform}）。")
        return None

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
