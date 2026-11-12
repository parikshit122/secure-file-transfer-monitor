@echo off
title SFTMS FastAPI Backend
cd /d "%~dp0backend"
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --reload-dir app --reload-include "*.py"