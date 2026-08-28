# AEGIS Local PostgreSQL Role Separation

This local-development workflow keeps schema/setup authority separate from the
normal AEGIS process. It contains no credentials and performs no automatic role
or privilege repair.

```text
AEGIS_MIGRATION_DATABASE_URL
→ local migration/setup role (`aegis_owner`)
→ Alembic, exact revision inspection, explicit synthetic bootstrap

AEGIS_DATABASE_URL
→ restricted runtime role (`aegis_app`)
→ normal FastAPI requests only
```

Both URLs belong only in the ignored local `.env`. Alembic fails if the migration
URL is absent and never falls back to runtime credentials. Normal application
settings neither load nor expose the migration URL.

## Explicit local setup

1. Confirm PostgreSQL is available and both ignored `.env` URLs are configured.
2. Apply migrations explicitly:

   ```powershell
   .\.venv\Scripts\python.exe -m alembic upgrade head
   ```

3. As the migration/setup role, apply the reviewed runtime matrix:

   ```powershell
   psql --host localhost --username aegis_owner --dbname aegis --file scripts/local_postgres_grants.sql
   ```

   Let `psql` prompt securely or use a local PostgreSQL password file. Do not put
   a credential on the command line or in this document.

4. Provide ephemeral synthetic demo password and MFA values, then run:

   ```powershell
   .\.venv\Scripts\python.exe -m aegis.dev.bootstrap_demo
   ```

The bootstrap is an explicit development/test setup command. It uses the setup
connection, requires exact revision `20260827_0010`, is transactional and
idempotent, and never prints supplied secret values. It is not a startup seeder
or public provisioning endpoint.

## Runtime privilege matrix

| Tables | Runtime privileges | Reason |
|---|---|---|
| `users` | SELECT, UPDATE | Authentication/authorization reads and password-verifier upgrade |
| `sessions` | SELECT, INSERT, UPDATE | Resolve, establish, touch, and revoke sessions |
| `mfa_credentials` | SELECT, INSERT, UPDATE | TOTP lifecycle and replay counter |
| `mfa_challenges` | SELECT, INSERT, UPDATE | Issue, fail, consume, and revoke challenges |
| roles/departments/clearances/compartments and user assignments | SELECT | Current authorization subject facts |
| intelligence records and record policy relationships | SELECT | Authorized collection/detail reads |
| `audit_events` | SELECT, INSERT | Mandatory evidence plus authorized audit/detection queries |
| `alembic_version` | none | Migration metadata is setup-only |

The runtime role receives no DELETE, DDL, ownership, database/schema CREATE,
superuser, or blanket privileges. Re-run the reviewed grant script explicitly
after a future migration changes the runtime table set.

This separation prepares the later Local Manual Demo / Easy Startup launcher;
that launcher is not implemented here. Phase 7, deployment, and security testing
remain deferred.
