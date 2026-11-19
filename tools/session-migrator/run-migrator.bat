@echo off
rem Launch ant-session-migrator.exe (auto-builds if missing; interactive menu when no args).
setlocal
cd /d "%~dp0"

if not exist "ant-session-migrator.exe" (
    echo [INFO] ant-session-migrator.exe not found. Building standalone binary first...
    call "%~dp0build.bat" --no-pause
    if errorlevel 1 (
        echo [ERROR] Build failed. Ensure Go is installed, or copy a prebuilt ant-session-migrator.exe here.
        pause
        exit /b 1
    )
)

"%~dp0ant-session-migrator.exe" %*
set "CODE=%errorlevel%"
if "%~1"=="" pause
exit /b %CODE%
