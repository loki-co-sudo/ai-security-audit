@echo off
cd /d "%~dp0"
echo AI Security Audit System を起動しています...
py main.py
if %errorlevel% neq 0 (
    echo.
    echo エラーが発生しました。上記のメッセージを確認してください。
    pause
)
