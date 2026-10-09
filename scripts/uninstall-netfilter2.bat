@echo off
setlocal

fltmc >nul 2>&1
if errorlevel 1 (
    echo Error: Run this script as Administrator.
    exit /b 1
)

set "DRIVER=%SystemRoot%\System32\drivers\netfilter2.sys"

sc.exe query netfilter2 >nul 2>&1
if not errorlevel 1 (
    echo Stopping netfilter2...
    sc.exe stop netfilter2 >nul 2>&1

    echo Deleting the netfilter2 service...
    sc.exe delete netfilter2
    if errorlevel 1 (
        echo Error: Failed to delete the netfilter2 service.
        exit /b 1
    )
) else (
    echo The netfilter2 service is not registered.
)

if exist "%DRIVER%" (
    echo Deleting %DRIVER%...
    del /f "%DRIVER%" >nul 2>&1
    if exist "%DRIVER%" (
        echo Error: The driver is still in use. Restart Windows, then run this script again.
        exit /b 1
    )
)

echo netfilter2 was uninstalled successfully.
exit /b 0
