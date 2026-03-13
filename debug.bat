@echo off
setlocal

cd /d "%~dp0"

if not exist "build" mkdir "build"
if not exist "debug" mkdir "debug"

set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64

echo Building debug executable...
go -C src build -trimpath -o "..\build\fnproxy-panel-debug.exe" .
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

echo Starting from debug directory...
pushd "debug"
"..\build\fnproxy-panel-debug.exe"
set EXIT_CODE=%ERRORLEVEL%
popd

exit /b %EXIT_CODE%
