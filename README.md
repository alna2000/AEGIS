# AEGIS — Classified Intelligence Access System

AEGIS is a fictional cybersecurity learning environment. All future identities,
organizations, intelligence records, classifications, and events will be synthetic.

**Phase 1 - Foundation & Architecture** is complete. **Phase 2 - Authentication
& 2FA** is in progress: Part 1 implements the authentication persistence model,
reviewed Alembic migration, canonical user identifiers, Argon2id password
security, and a service-level authentication boundary. PostgreSQL remains
unprovisioned and unconnected; login HTTP routes, sessions, and MFA are deferred.

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
The `.env` file is intentionally excluded from Git. Set `AEGIS_DATABASE_URL`
there with local PostgreSQL credentials; the tracked example contains no
password.

Run the tests:

```powershell
python -m pytest
```

Apply reviewed migrations to a configured local PostgreSQL database:

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
```

SQLite is used only as a disposable deterministic database in automated tests;
PostgreSQL remains the application and deployment architecture.

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

No login endpoint exists yet. Sessions, cookies, MFA/TOTP, authorization,
classified records, abuse protection, frontend work, and deployment have not
been implemented.
