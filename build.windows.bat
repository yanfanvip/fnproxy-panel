@echo off
setlocal

cd /d "%~dp0"

if not exist "build" mkdir "build"

set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64

echo Building Windows executable...
go -C src build -trimpath -o "..\build\fnproxy-panel-windows-amd64.exe" .
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

echo Build completed: build\fnproxy-panel-windows-amd64.exe
endlocal
