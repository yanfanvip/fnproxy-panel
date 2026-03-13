@echo off
setlocal

cd /d "%~dp0"

if not exist "build" mkdir "build"

set CGO_ENABLED=0
set GOOS=linux
set GOARCH=amd64

echo Building Linux executable...
go -C src build -trimpath -o "..\build\fnproxy-panel-linux-amd64" .
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

echo Build completed: build\fnproxy-panel-linux-amd64
endlocal
