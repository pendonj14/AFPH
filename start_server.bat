@echo off
rem Self-elevate (hosts/client files live under admin-owned paths), then start the server.
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'" & exit /b)
cd /d "%~dp0"
set "AF_CLIENT_ROOT=C:\Games\AssaultFirePH"
set "AF_GAME_DIR=C:\Games\AssaultFirePH\Binaries\Win32"
set "AF_DS_SPAWNER_ENABLED=1"
".venv\Scripts\python.exe" server\assaultfire_server_v143b.py
pause
