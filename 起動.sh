#!/bin/bash
# AI Security Audit System - Linux Launcher
cd "$(dirname "$0")"

# 依存パッケージ（customtkinter等）は本リポジトリ専用の .venv にのみ入っている
# 方針（CLAUDE.md）のため、.venv があれば最優先で使う。
if [ -x ".venv/bin/python3" ]; then
    .venv/bin/python3 main.py
elif command -v python3 >/dev/null 2>&1; then
    python3 main.py
elif command -v python >/dev/null 2>&1; then
    python main.py
else
    echo ""
    echo "  Python 3.10 or later is required."
    echo "  Download: https://www.python.org/downloads/"
    echo ""
    read -rp "  Press Enter to exit..."
fi
