@echo off
title SOC Alert Triage Engine
setlocal enabledelayedexpansion

rem Scanning this PC reads Security 4688, which holds the process command lines
rem and needs administrative rights. Ask once, before the menu, so the scan is
rem never quietly half-blind.
rem
rem /elevated marks the relaunched copy. Without a marker, a privilege check that
rem misreads an already-elevated session would prompt again on every restart, and
rem the user would face a second dialog after the window is already open.
set "DROPPED=%~1"
set "ELEVATED="
if /i "%~1"=="/elevated" (
  set "ELEVATED=1"
  set "DROPPED=%~2"
)

if not defined ELEVATED (
  fltmc >nul 2>&1
  if errorlevel 1 (
    echo.
    echo    Requesting administrator rights so process-creation events can be read...
    if "!DROPPED!"=="" (
      powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '/elevated' -Verb RunAs" >nul 2>&1
    ) else (
      powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '/elevated','\"!DROPPED!\"' -Verb RunAs" >nul 2>&1
    )
    if not errorlevel 1 exit /b 0
    echo.
    echo    Elevation was declined. Continuing without it - scanning this PC will
    echo    skip Security 4688, and the other options are unaffected.
    echo.
    pause
  )
)

cd /d "%~dp0"
color 0B

where python >nul 2>nul
if errorlevel 1 (
  echo.
  echo      Python was not found on PATH.
  echo      Install Python 3.8+ from https://www.python.org/downloads/
  echo      and tick "Add python.exe to PATH" in the installer.
  echo.
  pause
  exit /b 1
)

rem A findings file dropped onto this launcher skips the menu entirely.
if defined DROPPED (
  set "INPUT=!DROPPED!"
  goto run
)

:menu
cls
echo.
echo    ================================================
echo      SOC Alert Triage Engine
echo      enrich - score - correlate - report
echo    ================================================
echo.
echo      [1]  Scan this PC    (hunt the local event logs, then triage)
echo      [2]  Triage a file   (a findings JSON you already have)
echo      [3]  Demo            (bundled sample findings, offline)
echo      [4]  Quit
echo.
echo      Tip: you can also drag a findings.json onto this file.
echo.
choice /c 1234 /n /m "    Select 1, 2, 3 or 4: "
if errorlevel 4 exit /b 0
if errorlevel 3 (
  set "INPUT=%~dp0samples\findings.json"
  goto run
)
if errorlevel 2 goto pickfile

:hunt
rem Stage 1 is a separate project, so a real copy is preferred wherever one is
rem installed: an override, a clone beside this folder, a folder on the Desktop.
rem The vendored snapshot under vendor\ is the last resort and always present, so
rem this option works from a downloaded ZIP with nothing else set up.
set "HUNTER="
call :try "%THREAT_HUNTER%"
call :try "%~dp0..\windows-log-threat-hunter\Invoke-ThreatHunt.ps1"
call :try "%~dp0..\..\windows-log-threat-hunter\Invoke-ThreatHunt.ps1"
call :try "%USERPROFILE%\Desktop\Windows Log Threat Hunter\Invoke-ThreatHunt.ps1"
call :try "%~dp0vendor\windows-log-threat-hunter\Invoke-ThreatHunt.ps1"

if not defined HUNTER (
  echo.
  echo      The bundled copy of Windows Log Threat Hunter is missing from
  echo      vendor\windows-log-threat-hunter, so there is nothing to collect with.
  echo      Re-download this project, or set THREAT_HUNTER to the full path of an
  echo      Invoke-ThreatHunt.ps1. Option [3] needs none of this.
  echo.
  pause
  goto menu
)

set "INPUT=%~dp0reports\hunt.json"
if exist "!INPUT!" del "!INPUT!"
cls
echo.
echo    ================================================
echo      Stage 1 - hunting the local event logs
echo    ================================================
echo.
echo      Reading the last 72 hours. This takes a moment...
echo.

rem The hunter prints every finding it matches, which on a real machine is
rem hundreds of lines and buries the part that matters. The findings are about to
rem be triaged and rendered anyway, so only the collection summary is shown here.
set "HUNTLOG=%TEMP%\soc-triage-hunt.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "!HUNTER!" -Hours 72 -Json "!INPUT!" > "!HUNTLOG!" 2>&1
powershell -NoProfile -Command "Select-String -Path $env:TEMP\soc-triage-hunt.log -Pattern 'PowerShell:|Security:|Sysmon:|Scanned |Summary:|No events' | ForEach-Object { $_.Line }"
del "!HUNTLOG!" >nul 2>&1

rem The hunter returns early without writing anything when no log was readable,
rem which is a different problem from a quiet 72 hours.
if not exist "!INPUT!" (
  echo.
  echo      No events could be collected, so there is nothing to triage.
  echo      Real telemetry needs PowerShell script-block logging enabled,
  echo      or this launcher run as Administrator for process creation events.
  echo      Option [3] runs the bundled sample data instead.
  echo.
  pause
  goto menu
)
goto run

:pickfile
rem Windows' own file dialog, so nobody has to type a path. The filter string
rem needs pipe characters, which cmd would read as operators, so they are built
rem from [char]124 instead of appearing on this line.
set "INPUT="
for /f "usebackq delims=" %%F in (`powershell -NoProfile -STA -Command "Add-Type -AssemblyName System.Windows.Forms; $bar=[char]124; $d=New-Object System.Windows.Forms.OpenFileDialog; $d.Title='Select a findings JSON export'; $d.InitialDirectory=[Environment]::GetFolderPath('Desktop'); $d.Filter='JSON files (*.json)'+$bar+'*.json'+$bar+'All files (*.*)'+$bar+'*.*'; if($d.ShowDialog() -eq 'OK'){$d.FileName}"`) do set "INPUT=%%F"

if not defined INPUT goto menu
if not exist "!INPUT!" (
  echo.
  echo      File not found: !INPUT!
  echo.
  pause
  goto menu
)

:run
cls
echo.
echo    ================================================
echo      SOC Alert Triage Engine
echo    ================================================
echo.
echo      Input: !INPUT!
echo.
python "%~dp0soc-triage.py" -i "!INPUT!" --html "%~dp0reports\triage.html" --open --no-breakdown

rem The engine exits 1 when a case reaches High or above - that is the scheduler
rem signal, not a failure. Only 2 and up mean it could not run.
if errorlevel 2 (
  echo.
  echo    ------------------------------------------------
  echo      That file could not be triaged. It needs to be
  echo      a JSON array of findings, such as the output of
  echo      Invoke-ThreatHunt.ps1 -Json
  echo    ------------------------------------------------
  echo.
  pause
  goto menu
)

rem The report is in the browser now, so the console has nothing left to say.
rem It closes on its own; only the failure paths above wait, because those are
rem the ones with something to read.
echo.
echo    ------------------------------------------------
echo      Done. The report opened in your browser.
echo      Expand any alert there to see why it scored
echo      what it scored.
echo    ------------------------------------------------
timeout /t 4 /nobreak >nul 2>&1
exit /b 0

rem First candidate that exists wins; later calls are no-ops once one has.
:try
if defined HUNTER exit /b 0
if "%~1"=="" exit /b 0
if exist "%~1" set "HUNTER=%~1"
exit /b 0
