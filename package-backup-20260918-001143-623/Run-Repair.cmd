@echo off
setlocal
set "RepairPS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "RepairPS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
echo Run this launcher as administrator. It never reboots automatically.
"%RepairPS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Repair-WindowsCatalogCorruption.ps1" %*
set "RepairExit=%ERRORLEVEL%"
echo.
echo Repair finished with exit code %RepairExit%. Read the result and evidence path above.
pause
exit /b %RepairExit%
