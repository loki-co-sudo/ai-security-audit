"""
main.py — エントリポイント
"""

import os
import sys


def _ensure_dirs() -> None:
    for d in ("reports", "gui/panels", "gui/widgets", "agents", "tools", "core"):
        os.makedirs(d, exist_ok=True)


def main() -> None:
    _ensure_dirs()

    # gui/__init__.py が無い場合に備えて作成
    for pkg in ("gui", "gui/panels", "gui/widgets", "core", "agents", "tools"):
        init = os.path.join(pkg, "__init__.py")
        if not os.path.exists(init):
            open(init, "w").close()

    from gui.app import App
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
