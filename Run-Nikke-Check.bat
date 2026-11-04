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
set "NIKKE_LANGUAGE=Auto"
if /i not "%~1"=="-Language" goto :run
set "NIKKE_LANGUAGE="
for %%L in (Auto ko en ja) do if /i "%~2"=="%%L" set "NIKKE_LANGUAGE=%%L"
if not defined NIKKE_LANGUAGE goto :usage
shift
shift

:run
if /i "%~1"=="-Restore" (
    if "%~2"=="" goto :usage
    "%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -Language "%NIKKE_LANGUAGE%" -RestoreBackup "%~f2"
) else if "%~1"=="" (
    "%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -Language "%NIKKE_LANGUAGE%" -OfferRemediation
) else (
    "%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -Language "%NIKKE_LANGUAGE%" -OfferRemediation -InstallPath "%~f1\."
)
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%

:usage
echo Run-Nikke-Check.bat [-Language Auto^|ko^|en^|ja] ["Install folder"]
echo Run-Nikke-Check.bat [-Language Auto^|ko^|en^|ja] -Restore "path-to-backup.nikke-backup"
pause
exit /b 2
