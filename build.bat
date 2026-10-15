@echo off
REM ============================================================
REM  SecTrace multi-arch build script
REM  Output: outputs\SecTrace_windows_{x86,x64,arm,arm64}.exe
REM  Requires: Go 1.24+ (GOTOOLCHAIN=auto downloads toolchain)
REM ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM Clear polluted GOROOT if it points to a different Go install
set "GOROOT="

set GOEXE=go
where go >nul 2>&1 || (
    echo [!] go not found in PATH, please install Go 1.24+
    exit /b 1
)

REM ---------- 1) install / locate rsrc tool (icon resource) ----------
echo [1/3] preparing rsrc tool...
set "GOTOOLCHAIN=auto"
%GOEXE% install github.com/akavel/rsrc@latest >nul 2>&1

set "GBIN_DIR="
for /f "delims=" %%i in ('%GOEXE% env GOBIN') do set "GBIN_DIR=%%i"
if "!GBIN_DIR!"=="" for /f "delims=" %%i in ('%GOEXE% env GOPATH') do set "GBIN_DIR=%%i\bin"
set "RSRC=!GBIN_DIR!\rsrc.exe"
if not exist "!RSRC!" (
    echo [!] rsrc install failed, building without icon
    set "RSRC="
)

REM ---------- 2) generate arch-specific .syso (icon only) ----------
echo [2/3] generating icon resources...
if defined RSRC (
    "!RSRC!" -arch 386   -ico assets\sectrace.ico -o rsrc_windows_386.syso
    "!RSRC!" -arch amd64 -ico assets\sectrace.ico -o rsrc_windows_amd64.syso
    "!RSRC!" -arch arm64 -ico assets\sectrace.ico -o rsrc_windows_arm64.syso 2>nul
)

REM ---------- 3) cross compile ----------
echo [3/3] building...
if not exist outputs mkdir outputs
set CGO_ENABLED=0

call :build_one 386   x86
call :build_one amd64 x64
call :build_one arm64 arm64

echo.
echo ============================================
echo  done: outputs\
dir /b outputs\*.exe 2>nul
echo ============================================
endlocal
exit /b 0

:build_one
REM %1=GOARCH %2=output name
echo   - windows/%~1 ...
set GOOS=windows
set GOARCH=%~1
%GOEXE% build -trimpath -ldflags "-s -w -H windowsgui" -o "outputs\SecTrace_windows_%~2.exe" .
if errorlevel 1 (
    echo     [X] %~1 build failed
    exit /b 1
)
exit /b 0
