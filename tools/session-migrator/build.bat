@echo off
setlocal
cd /d "%~dp0"

echo [1/2] Tidying standalone Go module dependencies...
go mod tidy
if errorlevel 1 (
    echo [ERROR] go mod tidy failed.
    pause
    exit /b 1
)

echo [2/2] Building ant-session-migrator.exe (pure Go, zero external runtime dependencies)...
set "CGO_ENABLED=0"
go build -trimpath -ldflags="-s -w" -o ant-session-migrator.exe .
if errorlevel 1 (
    echo [ERROR] go build failed.
    pause
    exit /b 1
)

echo.
echo [OK] Build succeeded: %~dp0ant-session-migrator.exe
echo You can copy ant-session-migrator.exe alone to any Windows PC (dev or release Ant Browser).
echo.
if /I not "%~1"=="--no-pause" pause
exit /b 0
