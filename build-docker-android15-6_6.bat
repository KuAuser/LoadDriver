@echo off
setlocal EnableExtensions
cd /d "%~dp0"

REM Build paradise.ko inside the same DDK container as CI (matrix: android15-6.6).
REM Requires Docker Desktop with Linux containers. Device fingerprint: device_kernel_from_adb.txt

where docker >nul 2>&1
if errorlevel 1 (
  echo [ERROR] docker not found. Install Docker Desktop, enable Linux engine, retry.
  exit /b 1
)

echo Pulling/using ghcr.io/ylarod/ddk:android15-6.6 ...
REM -j8 avoids $(nproc) escaping issues in cmd.exe; increase if you want.
docker run --rm -v "%CD%:/m" -w /m ghcr.io/ylarod/ddk:android15-6.6 bash -lc "make -j8 all && ls -la paradise.ko"
if errorlevel 1 exit /b 1

echo.
echo OK: paradise.ko should be here: "%CD%\paradise.ko"
exit /b 0
