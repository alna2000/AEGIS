# AEGIS — Classified Intelligence Access System

AEGIS is a fictional cybersecurity learning environment. All future identities,
organizations, intelligence records, classifications, and events will be synthetic.

**Phase 1 - Foundation & Architecture** and **Phase 2 - Authentication & 2FA**
are complete. Phase 2 implements user/password persistence, generic
login-attempt security and non-persistent credential-audit logging, HTTP login,
finite hash-only server-side sessions, and the encrypted service-layer TOTP
credential foundation plus short-lived hash-only MFA challenges and final TOTP
session issuance. **Phase 3 - Authorization & Classified Records is complete;
Parts 1-4 are implemented, security-reviewed, verified, and checkpointed. Phase
4 - Modern Security Interface is complete, security-reviewed, verified, and
checkpointed. Phase 5 - Bot Detection & Abuse Protection has not started.**
Authentication still proves identity only and grants no authorization.
PostgreSQL remains the application target and is not provisioned by this repository.

```text
Phase 2: COMPLETE
Phase 3: COMPLETE
Phase 4: COMPLETE
Phase 5: NOT STARTED
```

Phase 3 Part 1 adds controlled role, department, clearance, and compartment
reference data; normalized current user assignments; a separately loaded
immutable `AuthorizationSubject`; a version-controlled role capability map; and
a pure typed default-deny evaluator over content-free resource-policy snapshots.
Existing users have nullable transitional department and clearance references,
and missing authorization state denies. At the Part 1 checkpoint,
classified-record tables, record/search endpoints, HTTP authorization
enforcement, assignment APIs, and persistent authorization audit storage were
not implemented. Record persistence is now implemented by Part 2 below; the
other listed boundaries remain deferred. Role capability is only an input to
continued evaluation and does not waive future action-specific workflow/context
checks.

Phase 3 Part 2 adds bounded synthetic `intelligence_records` persistence plus
normalized record-department and record-compartment policy relationships. A
read-only repository loads content-free policy facts, and a fail-closed service
converts them to the existing immutable `ResourcePolicy`; the existing central
`authorize()` evaluator remains authoritative. Record UUIDs, codes, and creators
never grant access. Draft and retired records are unusable; active records require
a controlled classification and at least one active authorized department. Zero
record compartments means no compartment requirement, while every listed active
compartment is required.

Phase 3 Part 3 adds the first authorization-enforced classified-record backend
path: `GET /records/{record_code}`. A usable session resolves identity only;
current server-side authorization facts are reloaded for every request. The code
selects a content-free policy candidate, the existing central evaluator must
return explicit `ALLOW`, and only then does a separate projection load title,
summary, content, and classification. Missing and ordinarily inaccessible
records share `404 {"detail":"Record not found"}`; evaluator and record-read
infrastructure failures use a generic `503`.

Phase 3 Part 4 adds `GET /records`, a deterministic metadata-only collection.
Every valid content-free candidate must receive explicit central `SEARCH` and
`READ` allows before its title and classification are batch-loaded by internal
UUID. The response contains only record code, title, and classification, sorted
by record code; it has no summaries, content, totals, filters, or pagination.
Zero authorized records returns `[]`. At most 100 candidates are evaluated; a
101st candidate, malformed policy, evaluator failure, or inconsistent metadata
fails the entire operation with generic `503`. Record mutations, assignment
workflows, rich search, frontend authorization, and persistent authorization
audit storage remain unimplemented.

At Phase 3 closure, authorization remains entirely backend-owned and read-only.
The controlled clearance hierarchy is `UNCLASSIFIED=10`, `CONFIDENTIAL=20`,
`SECRET=30`, and `TOP SECRET=40`; arbitrary ranks fail closed. `DRAFT` and
`RETIRED` records are authorization-unusable, while `ACTIVE` records are only
potentially usable when their complete RBAC/ABAC policy passes. AEGIS is a local
learning/portfolio application and makes no production PostgreSQL execution,
deployment, real-classified-data, or production-scale collection claim.

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
| `GET` | `/ui` | Same-origin read-only authentication and authorized-record interface |
| `POST` | `/auth/login` | Verify a synthetic password; issue a session or require TOTP |
| `POST` | `/auth/mfa/totp/verify` | Complete a valid password-issued MFA challenge with TOTP |
| `GET` | `/auth/me` | Return safe identity for a usable current session |
| `POST` | `/auth/logout` | Revoke the current server-side session and clear its cookie |
| `GET` | `/records` | Return metadata only for records centrally allowed for both SEARCH and READ |
| `GET` | `/records/{record_code}` | Return one classified record only after current centralized authorization allows READ |

For local manual testing, first apply migrations and create an active synthetic
user through the explicit local bootstrap command; no public account or MFA
enrollment endpoint exists. The command refuses every environment except
`development` and `test`, requires the database to be exactly at Alembic revision
`20260823_0006`, and commits its deterministic synthetic fixture atomically.
It never runs during application startup or migration execution.

Set the demo password only in the current process environment, run the command,
then remove the variable when finished. The value is Argon2id-hashed through the
normal password service and is neither printed nor stored in source:

```powershell
$env:AEGIS_DEMO_PASSWORD = Read-Host 'Synthetic demo password'
python -m aegis.dev.bootstrap_demo
Remove-Item Env:AEGIS_DEMO_PASSWORD
```

Successful provisioning reports each deterministic user and record as created,
already existing, or updated. Re-running it is safe and does not duplicate rows.
The primary password-only account is `demo.analyst`: Analyst role, Cyber
Intelligence department, SECRET clearance, and NIGHTFALL compartment. The
limited `demo.limited` account and records `INT-90001` through `INT-90005`
exercise positive and negative clearance, department, and compartment cases.
All names and content are fictional.

**Local synthetic development data only. Never use this bootstrap mechanism in
production.** Start AEGIS with `python -m uvicorn aegis.main:app --reload`, then
open `http://127.0.0.1:8000/ui`. The primary account should see `INT-90001` and
`INT-90002`; the three higher-classification, department-mismatched, or
compartment-mismatched records remain hidden by backend authorization.

Keep one in-memory HTTP client/session so cookies are handled automatically. Use
only synthetic values or placeholders:

```powershell
$aegisWeb = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$loginBody = @{username='demo.analyst'; password='<SYNTHETIC_PASSWORD>'} | ConvertTo-Json
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
protection is designed. The classified-record routes are safe, idempotent GETs
and introduce no authenticated state change. The frontend must never perform
authorization. Record mutation and assignment workflows, rich search, abuse
protection, persistent audit storage, and deployment remain unimplemented.

Phase 4's read-only interface over the existing authentication and record GET
routes is complete. It renders only backend-authorized responses, uses safe
text-only DOM construction, stores no tokens, and performs no authorization.
`GET /ui` has a strict route-scoped CSP, no-store/nosniff/no-referrer/restrictive-
permissions headers, accessible state and focus handling, responsive local CSS,
stale-operation guards, and a safe JavaScript-failure fallback. Record creation
or mutation, assignment administration, rich search, pagination, persistent
authorization audit, bot protection, monitoring, and deployment are not
available backend capabilities.

See `Phase_4_Completion_Summary.md` for the completed UI/security boundary.
Phase 5 must begin by reading `AEGIS_Phase5_Opening_Prompt.md` and reviewing the
authentication/session abuse surface before any bot-protection implementation.
