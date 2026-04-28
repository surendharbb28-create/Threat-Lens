@echo off
title ThreatLens Setup
color 0A
echo.
echo ============================================
echo   THREATLENS - Auto Setup
echo ============================================
echo.

echo [1/3] Fixing settings...
python fix_settings.py
if errorlevel 1 (
    echo ERROR: Python not found or script failed.
    pause
    exit /b 1
)

echo.
echo [2/3] Installing dependencies...
pip install django pymongo dnspython djangorestframework --quiet
if errorlevel 1 (
    echo ERROR: pip install failed.
    pause
    exit /b 1
)

echo.
echo [3/3] Starting ThreatLens server...
echo.
echo ============================================
echo   Open your browser at: http://127.0.0.1:8000
echo   Press CTRL+C to stop the server
echo ============================================
echo.
python manage.py runserver

pause
