# AEGIS Easy Local Demo

The launcher provides one explicit Windows command for the already-configured
local synthetic demonstration environment. It does not activate PowerShell,
run migrations, change PostgreSQL privileges, or expose a provisioning route.

## Prerequisites

- PostgreSQL is running.
- The ignored `.env` contains the separate runtime and migration/setup URLs.
- The database is already migrated to `20260827_0010`.
- The ignored `.env` contains a valid MFA encryption key, synthetic demo
  password, and 32-character unpadded Base32 demo MFA secret.

Never commit or paste those local values into documentation, terminal commands,
screenshots, or issue reports.

## Start AEGIS

From the repository root, without activating the virtual environment:

```powershell
.\.venv\Scripts\python.exe -m aegis.dev.run_demo
```

The launcher is restricted to `development` and `test`, verifies the runtime
database connection, uses the separate setup connection through the existing
transactional/idempotent bootstrap, and refuses any database revision other
than `20260827_0010`. It never upgrades or downgrades the database.

On success it binds only to `127.0.0.1:8000` and reports safe local links:

- UI: <http://127.0.0.1:8000/ui>
- Health: <http://127.0.0.1:8000/health>

Stop the server with `Ctrl+C`.

## Safe failure behavior

Missing or invalid configuration, an unreachable runtime database, a setup
connection failure, an incorrect migration revision, or a failed transactional
bootstrap produces a concise refusal without printing credentials or internal
database details. Correct the local configuration or migrate explicitly using
the separate setup workflow in `AEGIS_Local_PostgreSQL_Setup.md`, then retry.
