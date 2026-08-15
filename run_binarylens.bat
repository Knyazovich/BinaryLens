@echo off
setlocal enabledelayedexpansion
title BinaryLens v1.0 - Launcher

echo.
echo ============================================
echo   BinaryLens v1.0 - Static Binary Analysis
echo ============================================
echo.

REM ------------------------------------------------------------------
REM 1. Check Python is installed and is 3.11+
REM ------------------------------------------------------------------
where python >nul 2>&1
if errorlevel 1 (
    echo [X] Python was not found in PATH.
    echo     Install Python 3.11 or newer from https://www.python.org/downloads/
    echo     ^(make sure to check "Add python.exe to PATH" during install^)
    echo.
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [OK] Found Python %PYVER%

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if errorlevel 1 (
    echo [X] Python 3.11+ is required, found %PYVER%.
    echo     Install a newer Python from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------------------------------
REM 2. Check pip is available
REM ------------------------------------------------------------------
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [X] pip is not available for this Python installation.
    echo     Reinstall Python and ensure pip is included.
    echo.
    pause
    exit /b 1
)
echo [OK] pip is available

REM ------------------------------------------------------------------
REM 3. Check required dependencies, install any that are missing
REM ------------------------------------------------------------------
echo.
echo Checking dependencies...

set MISSING=0

python -c "import pefile" >nul 2>&1
if errorlevel 1 (
    echo [!] Missing: pefile
    set MISSING=1
) else (
    echo [OK] pefile
)

python -c "import lief" >nul 2>&1
if errorlevel 1 (
    echo [!] Missing: lief
    set MISSING=1
) else (
    echo [OK] lief
)

python -c "import capstone" >nul 2>&1
if errorlevel 1 (
    echo [!] Missing: capstone
    set MISSING=1
) else (
    echo [OK] capstone
)

python -c "import rich" >nul 2>&1
if errorlevel 1 (
    echo [!] Missing: rich
    set MISSING=1
) else (
    echo [OK] rich
)

if %MISSING%==1 (
    echo.
    echo Some dependencies are missing. Installing from requirements.txt...
    echo.
    python -m pip install -r "%~dp0requirements.txt"
    if errorlevel 1 (
        echo.
        echo [X] Dependency installation failed. Check your internet connection
        echo     and try running this script again.
        echo.
        pause
        exit /b 1
    )
    echo.
    echo [OK] Dependencies installed successfully.
) else (
    echo.
    echo [OK] All dependencies are already installed.
)

REM ------------------------------------------------------------------
REM 4. Check BinaryLens itself is installed as a package; install if not
REM ------------------------------------------------------------------
echo.
python -c "import binarylens" >nul 2>&1
if errorlevel 1 (
    echo Installing BinaryLens package...
    python -m pip install -e "%~dp0"
    if errorlevel 1 (
        echo [X] Failed to install BinaryLens.
        pause
        exit /b 1
    )
)

REM ------------------------------------------------------------------
REM 5. Launch BinaryLens
REM ------------------------------------------------------------------
echo.
echo ============================================
echo   Launching BinaryLens...
echo ============================================
echo.

if "%~1"=="" (
    REM No arguments / no dropped file: run interactively so the user
    REM can drag and drop a binary into the console window.
    python -m binarylens.cli
) else (
    REM A file was dropped directly onto this .bat file, or arguments
    REM were passed on the command line: forward them all as-is.
    python -m binarylens.cli %*
)

echo.
pause
endlocal
