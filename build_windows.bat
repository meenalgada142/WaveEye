@echo off
REM ─────────────────────────────────────────────────────────────
REM  WaveEye — Windows build script
REM  Run from the project root (where main.py lives):
REM    build_windows.bat
REM
REM  Output: standalone\WaveEye-windows\  +  standalone\WaveEye-windows.zip
REM ─────────────────────────────────────────────────────────────

setlocal

set "ROOT=%~dp0"
set "DIST=%ROOT%standalone"
set "OUT=%DIST%\WaveEye-windows"
set "ZIP=%DIST%\WaveEye-windows.zip"

echo.
echo [BUILD] WaveEye Windows executable
echo [BUILD] Project root : %ROOT%
echo [BUILD] Output       : %OUT%
echo.

REM ── Prerequisites check ──────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] python not found. Install Python 3.10+ and add it to PATH.
    exit /b 1
)

pyinstaller --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pyinstaller not found. Run:  pip install pyinstaller
    exit /b 1
)

REM ── Clean previous build ─────────────────────────────────────
if exist "%OUT%" rmdir /s /q "%OUT%"
if exist "%ZIP%"  del /q "%ZIP%"
if exist "%ROOT%dist\waveeye" rmdir /s /q "%ROOT%dist\waveeye"

REM ── Run PyInstaller ──────────────────────────────────────────
cd /d "%ROOT%"
pyinstaller waveeye.spec --distpath "%DIST%\temp_dist" --workpath "%ROOT%build\pyinstaller_work" --noconfirm
if errorlevel 1 (
    echo [ERROR] PyInstaller failed.
    exit /b 1
)

REM ── Rename output folder ─────────────────────────────────────
move "%DIST%\temp_dist\waveeye" "%OUT%"
rmdir /s /q "%DIST%\temp_dist" 2>nul

REM ── Zip it ───────────────────────────────────────────────────
echo [BUILD] Creating zip archive...
powershell -Command "Compress-Archive -Path '%OUT%' -DestinationPath '%ZIP%' -Force"

echo.
echo [DONE] Windows build complete.
echo        Folder : %OUT%
echo        Zip    : %ZIP%
echo.
endlocal
