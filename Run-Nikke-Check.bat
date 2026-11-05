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
if /i "%~1"=="-Restore" goto :inspect
if /i "%~1"=="-InspectBackup" goto :inspect
if "%~1"=="" (
    "%PS%" -NoLogo -NoProfile -File "%SCRIPT%" -Language "%NIKKE_LANGUAGE%" -OfferRemediation
) else (
    "%PS%" -NoLogo -NoProfile -File "%SCRIPT%" -Language "%NIKKE_LANGUAGE%" -OfferRemediation -InstallPath "%~f1\."
)
goto :done

:inspect
if "%~2"=="" goto :usage
"%PS%" -NoLogo -NoProfile -File "%SCRIPT%" -Language "%NIKKE_LANGUAGE%" -InspectBackup "%~f2"

:done
set "RESULT=%ERRORLEVEL%"
if "%RESULT%"=="1" echo If the script did not start, see the Windows execution policy guide in the GitHub README.
pause
exit /b %RESULT%

:usage
echo Run-Nikke-Check.bat [-Language Auto^|ko^|en^|ja] ["Install folder"]
echo Run-Nikke-Check.bat [-Language Auto^|ko^|en^|ja] -InspectBackup "path-to-backup.nikke-backup"
pause
exit /b 2
