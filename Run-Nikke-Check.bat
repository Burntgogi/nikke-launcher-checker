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
if /i "%~1"=="-Restore" (
    if "%~2"=="" (
        echo Run-Nikke-Check.bat -Restore "path-to-backup.nikke-backup"
        pause
        exit /b 2
    )
    "%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -RestoreBackup "%~f2"
) else if "%~1"=="" (
    "%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -OfferRemediation
) else (
    "%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -OfferRemediation -InstallPath "%~f1\."
)
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%
