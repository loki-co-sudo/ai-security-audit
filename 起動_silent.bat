@echo off
cd /d "%~dp0"

for /f "delims=" %%W in ('where pythonw 2^>nul') do (
    start "" "%%W" "%~dp0main.py"
    goto :done
)

py main.py

:done
