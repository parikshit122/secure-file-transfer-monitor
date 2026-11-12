@echo off
title Secure File Transfer Monitoring System (SFTMS)
cd /d "%~dp0"

echo ===================================================
echo   Starting SFTMS Security Engine & Web Dashboard
echo ===================================================

:: Start Backend in background
start /min "SFTMS Backend Engine" cmd /c "call .\.venv\Scripts\activate.bat && cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000"

:: Wait 3 seconds for FastAPI startup
timeout /t 3 /nobreak > nul

:: Open Dashboard in Default Web Browser
start http://localhost:5173

:: Start Frontend Vite Server
cd apps\web
npm run dev

pause