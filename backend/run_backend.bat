@echo off
setlocal
cd /d "%~dp0"

if not exist ".env.backend" (
  echo ERROR: backend\.env.backend is missing.
  echo Copy .env.backend.example to .env.backend and fill the values first.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  py -m venv .venv
  if errorlevel 1 exit /b 1
)

call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
