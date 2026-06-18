@echo off
cd /d "%~dp0"

where py >nul 2>&1
if %errorlevel% equ 0 (
    py main.py
    goto :done
)

where python >nul 2>&1
if %errorlevel% equ 0 (
    python main.py
    goto :done
)

echo.
echo  Python 3.10 or later is required.
echo  Download: https://www.python.org/downloads/
echo.
pause

:done
