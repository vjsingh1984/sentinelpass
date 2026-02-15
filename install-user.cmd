@echo off
setlocal
cd /d "%~dp0"

echo SentinelPass user-level installer launcher
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File ".\install.ps1" -SkipBuild %*
set EXITCODE=%ERRORLEVEL%

if not "%EXITCODE%"=="0" (
  echo.
  echo SentinelPass installation failed with exit code %EXITCODE%.
  pause
  exit /b %EXITCODE%
)

echo.
echo SentinelPass installation completed.
pause
exit /b 0

