@echo off
rem ===================================================================
rem  Network Traffic Monitor (Isolation Forest) - Windows launcher
rem
rem  NOTE: this file is intentionally ASCII-only. cmd.exe parses batch
rem  files using the ANSI code page, so non-ASCII characters here would
rem  be mis-decoded and break the script. The Python program itself
rem  prints Chinese output normally.
rem
rem  Double-click / no arguments -> demo mode (replays sample.pcap,
rem  no administrator rights and no Npcap required).
rem
rem  For live capture: right-click "Run as administrator", then:
rem      run.bat -i "Ethernet" -w 5
rem ===================================================================
setlocal
chcp 65001 >nul
cd /d "%~dp0"

set PYTHONIOENCODING=utf-8
set PY=python
where python >nul 2>nul || set PY=py

%PY% -c "import scapy, sklearn, pandas" >nul 2>nul
if errorlevel 1 (
    echo [1/2] Installing dependencies ...
    %PY% -m pip install -r requirements.txt
    if errorlevel 1 goto :fail
) else (
    echo [1/2] Dependencies OK
)

echo [2/2] Starting monitor ...
if "%~1"=="" (
    echo      no arguments given, entering demo mode: python main.py --demo
    %PY% main.py --demo
) else (
    %PY% main.py %*
)
goto :eof

:fail
echo.
echo Dependency installation failed. Please run manually:
echo     python -m pip install -r requirements.txt
pause
exit /b 1
