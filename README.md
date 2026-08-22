# AEGIS — Classified Intelligence Access System

AEGIS is a fictional cybersecurity learning environment. All future identities,
organizations, intelligence records, classifications, and events will be synthetic.

**Phase 1 - Foundation & Architecture** and **Phase 2 - Authentication & 2FA**
are complete. Phase 2 implements user/password persistence, generic
login-attempt security and non-persistent credential-audit logging, HTTP login,
finite hash-only server-side sessions, and the encrypted service-layer TOTP
credential foundation plus short-lived hash-only MFA challenges and final TOTP
session issuance. **Phase 3 - Authorization & Classified Records has not
started.** Authentication proves identity only and grants no authorization.
PostgreSQL remains the application target and is not provisioned by this repository.

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
MFA challenges default to five minutes and may be configured from 60 through 600
seconds with `AEGIS_MFA_CHALLENGE_LIFETIME_SECONDS`. Their separate cookie name
defaults to `aegis_mfa_challenge`; it must differ from the normal session cookie.

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
| `POST` | `/auth/login` | Verify a synthetic password; issue a session or require TOTP |
| `POST` | `/auth/mfa/totp/verify` | Complete a valid password-issued MFA challenge with TOTP |
| `GET` | `/auth/me` | Return safe identity for a usable current session |
| `POST` | `/auth/logout` | Revoke the current server-side session and clear its cookie |

For local manual testing, first apply migrations and create an active synthetic
user through a trusted local database/bootstrap workflow; no public account or
MFA enrollment endpoint exists. Keep one in-memory HTTP client/session so cookies
are handled automatically. Use only synthetic values or placeholders:

```powershell
$aegisWeb = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$loginBody = @{username='<SYNTHETIC_USERNAME>'; password='<SYNTHETIC_PASSWORD>'} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/auth/login' -ContentType 'application/json' -Body $loginBody -WebSession $aegisWeb
```

If the response reports `mfa_required: true`, obtain the current code from the
synthetic account's authenticator and submit it without repeating the password:

```powershell
$mfaBody = @{code='<CURRENT_TOTP_CODE>'} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/auth/mfa/totp/verify' -ContentType 'application/json' -Body $mfaBody -WebSession $aegisWeb
Invoke-RestMethod -Method Get -Uri 'http://127.0.0.1:8000/auth/me' -WebSession $aegisWeb
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/auth/logout' -WebSession $aegisWeb
```

Users without enabled TOTP receive the normal session directly from `/auth/login`.
Do not place passwords, TOTP codes, session credentials, challenge credentials,
or provisioning URIs in URLs, logs, source files, localStorage, or a checked-in
cookie jar.

`SameSite=Strict` supplies useful baseline CSRF protection but is not a complete
CSRF design. The reviewed pre-authentication MFA completion also requires a
current TOTP proof, and logout is idempotent. MFA enrollment/disablement and future
authenticated browser state changes must not be exposed until dedicated CSRF
protection is designed. Authorization, classified records, frontend work, abuse
protection, persistent audit storage, and deployment remain unimplemented.
