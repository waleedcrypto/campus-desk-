$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".env.backend")) {
    throw "backend/.env.backend is missing. Copy .env.backend.example to .env.backend and fill it first."
}

if (-not (Test-Path ".venv/Scripts/python.exe")) {
    py -m venv .venv
}

& ./.venv/Scripts/python.exe -m pip install --upgrade pip
& ./.venv/Scripts/python.exe -m pip install -r requirements.txt
& ./.venv/Scripts/python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000
