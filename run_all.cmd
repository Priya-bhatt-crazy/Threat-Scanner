@echo off
cd /d "%~dp0"
start "Backend" cmd /k ".venv\Scripts\python.exe backend\main.py"
start "Frontend" cmd /k "cd frontend && npm.cmd run dev"
