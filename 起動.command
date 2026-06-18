#!/bin/bash
# AI Security Audit System - macOS Launcher
# Finder でダブルクリックすると Terminal.app で実行されます
cd "$(dirname "$0")"

if command -v python3 >/dev/null 2>&1; then
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
