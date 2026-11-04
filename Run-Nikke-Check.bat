@echo off
rem Author: Serio_ai
setlocal DisableDelayedExpansion
set "SCRIPT=%~dp0Check-Nikke.ps1"
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%SCRIPT%" (
    echo Check-Nikke.ps1 must be in the same folder as this batch file.
    pause
    exit /b 2
)
if "%~1"=="" (
    "%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
) else (
    "%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -InstallPath "%~f1\."
)
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%
