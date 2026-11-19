@echo off
rem Cross-compile macOS (arm64/amd64) and Windows binaries via build-mac.ps1.
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-mac.ps1" %*
set "CODE=%errorlevel%"
if /I not "%~1"=="--no-pause" pause
exit /b %CODE%
