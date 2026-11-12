@echo off
rem Lance NetWatch en mode console (Ctrl+C pour arrêter). Pour tester sans toucher au port 53 :
rem   run.bat --dns-port 5300 --web-port 8796 --no-blockpage
cd /d "%~dp0"
set "PY=python"
if exist "%~dp0python\python.exe" set "PY=%~dp0python\python.exe"
"%PY%" netwatch.py %*
pause
