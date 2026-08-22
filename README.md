# AEGIS — Classified Intelligence Access System

AEGIS is a fictional cybersecurity learning environment. All future identities,
organizations, intelligence records, classifications, and events will be synthetic.

**Phase 1 - Foundation & Architecture** is complete under local development. It
established the minimal FastAPI/Python application and documented the future
security and PostgreSQL architecture. PostgreSQL remains uninstalled and
unconnected; Phase 2 has not started.

## Local setup (Windows PowerShell)

Python 3.11 or newer is required.

```powershell
cd C:\Python\Projects\AEGIS
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
```

To customize safe local settings, copy `.env.example` to `.env` and edit it.
The `.env` file is intentionally excluded from Git.

Run the tests:

```powershell
python -m pytest
```

Start the local development server:

```powershell
python -m uvicorn aegis.main:app --reload
```

The local API will be available at `http://127.0.0.1:8000`.

## Current endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | AEGIS development status |
| `GET` | `/health` | Minimal process health check |

Authentication, authorization, classified records, database persistence, abuse
protection, a frontend, and production deployment have not been implemented.
