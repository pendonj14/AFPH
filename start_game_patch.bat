@echo off
rem Run AFTER logging in at the launcher and stopping at START. Then click START when it says TCLS ARMED.
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'" & exit /b)
cd /d "%~dp0"
".venv\Scripts\python.exe" tools\patches\patch_tcls_suspended_launch.py
pause
