@echo off
title Sentinel - AI Privacy Desktop
echo ======================================================================
echo Launching Sentinel (NVIDIA Nemotron x Nebius Token Factory)
echo ======================================================================
echo.

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python main.py
    goto end
)

if exist "%USERPROFILE%\anaconda3\python.exe" (
    "%USERPROFILE%\anaconda3\python.exe" main.py
    goto end
)

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" main.py
    goto end
)

echo [ERROR] Python not found in PATH or standard locations.
echo Please install Python 3.10+ or ensure Python is added to your PATH.
pause

:end
