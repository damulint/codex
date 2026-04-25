@echo off
chcp 65001 >nul
setlocal

set "SCRIPT_DIR=%~dp0"
set "SCRIPT=%SCRIPT_DIR%kisa_mssql_windows_audit.ps1"

if not exist "%SCRIPT%" (
    echo PowerShell script not found:
    echo %SCRIPT%
    pause
    exit /b 1
)

echo Running KISA MSSQL Windows Audit...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"

echo.
echo Finished.
pause
