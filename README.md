# AEGIS — Classified Intelligence Access System

AEGIS is a fictional cybersecurity learning environment. All future identities,
organizations, intelligence records, classifications, and events will be synthetic.

**Phase 1 - Foundation & Architecture** is complete. **Phase 2 - Authentication
& 2FA** is in progress. Parts 1-4 implement user/password persistence, generic
login-attempt security and non-persistent credential-audit logging, HTTP login,
finite hash-only server-side sessions, and the encrypted service-layer TOTP
credential foundation. Authentication proves identity only; final login/MFA
integration and all authorization remain deferred. PostgreSQL remains the
application target and is not provisioned by this repository.

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
password. The default eight-hour session lifetime is configurable with
`AEGIS_SESSION_LIFETIME_SECONDS` from 300 through 86400 seconds. The
`aegis_session` cookie is `HttpOnly`, `SameSite=Strict`, and path-root. Local
development deliberately permits `AEGIS_SESSION_COOKIE_SECURE=false` for plain
HTTP; every environment other than explicit `development` or `test` refuses to
start unless secure cookies are enabled.

MFA functionality requires `AEGIS_MFA_ENCRYPTION_KEY` in the untracked `.env`
file. Generate a dedicated Fernet key locally (for example with
`Fernet.generate_key()` from `cryptography`) and never reuse a password, database
credential, or session token. The tracked `.env.example` contains only an empty
placeholder. `AEGIS_MFA_ENCRYPTION_KEY_ID` is a non-secret version label that
defaults to `v1` and is stored beside ciphertext for future rotation.

Run the tests:

```powershell
.\.venv\Scripts\python.exe -m pytest --basetemp=.pytest-temp
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
| `POST` | `/auth/login` | Verify a synthetic username/password and create a server-side session |
| `GET` | `/auth/me` | Return safe identity for a usable current session |
| `POST` | `/auth/logout` | Revoke the current server-side session and clear its cookie |

For local manual testing, first apply migrations and create an active synthetic
user through a trusted local database/bootstrap workflow; no public account
creation endpoint exists. Start Uvicorn, use one in-memory HTTP client/session to
`POST /auth/login`, `GET /auth/me`, `POST /auth/logout`, then confirm a final
`GET /auth/me` returns `401`. Do not place session credentials in URLs, JSON,
localStorage, logs, or a checked-in cookie jar.

`SameSite=Strict` supplies useful baseline CSRF protection but is not a complete
CSRF design. Authenticated state-changing browser functionality must not expand
beyond the reviewed idempotent logout endpoint until dedicated CSRF protection is
implemented. TOTP enrollment and verification intentionally have no HTTP routes
in Part 4 because dedicated CSRF protection is not yet implemented. `/auth/login`
still does not require TOTP. Final login/MFA integration, authorization,
classified records, abuse protection, frontend work, persistent audit storage,
and deployment remain unimplemented.
