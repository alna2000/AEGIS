# Phase 6 Structured Synthetic Security Exercise

Date: 2026-08-28
Status: COMPLETED LOCALLY / PENDING REVIEW

## Scope and environment

The exercise used only fictional AEGIS identities and records. The configured
local PostgreSQL server was reachable, but the application role lacked read
permission on `alembic_version`; therefore no live database state was changed.
Execution continued in the repository's isolated test environment with the real
FastAPI application, services, repositories, transactions, cookies, audit
writer/query, and detection engine over an ephemeral SQLite database.

Ephemeral passwords, TOTP secrets, encryption keys, challenge credentials, and
session credentials were generated in memory. None is recorded here or in a
tracked file.

## Exercise evidence

| Scenario | Expected HTTP | Observed HTTP | Durable evidence observed | Detection observed | Privacy | Result |
|---|---|---|---|---|---|---|
| A/E: valid password and MFA challenge | 200, MFA required, no session | 200; challenge cookie only | `PASSWORD_AUTH_SUCCEEDED`, `MFA_CHALLENGE_ISSUED` | Not applicable | No password or challenge credential in audit projection | PASS |
| B: one wrong password | Generic 401 | 401 | `PASSWORD_AUTH_FAILED` | Not expected from one event | Generic response; submitted password absent | PASS |
| C: repeated known-user password failures | Five generic 401 responses | Five 401 responses | Five grouped `PASSWORD_AUTH_FAILED` events | `REPEATED_PASSWORD_FAILURE`, MEDIUM, count 5 | Internal subject UUID only | PASS |
| D: login admission limit | Generic 429 after bounded attempts | Ten 401 responses, then 429 | Password failures persisted before admission denial; no Part 6 denial event is emitted by this path | No `ABUSE_PRESSURE` claimed | No limiter scope or key returned | PASS |
| F/G: wrong MFA and exhaustion | Generic failures; cooldown 429 where active | Five 401 factor failures with three controlled cooldown 429 responses | Five `MFA_FACTOR_FAILED`; one `MFA_CHALLENGE_EXHAUSTED` | `MFA_FAILURE_PATTERN` MEDIUM count 5; `MFA_CHALLENGE_EXHAUSTION` HIGH count 1 | No TOTP or challenge credential exposed | PASS |
| H: MFA recovery | New challenge then authenticated session | 200 challenge; 200 verification | `PASSWORD_AUTH_SUCCEEDED`, `MFA_CHALLENGE_ISSUED`, `MFA_FACTOR_SUCCEEDED`, `SESSION_ESTABLISHED` | No additional finding required | Credentials remained cookie-only and unreported | PASS |
| J: current identity | 200 safe identity | 200; only `username`, `display_name` | No new audit event required | Not applicable | No policy or session fields | PASS |
| K: authorized collection | 200, authorized records only | 200; only the two permitted synthetic records | Exactly one `RESOURCE_COLLECTION_READ` | Not applicable | No candidate or result counts in evidence | PASS |
| L: authorized detail | 200 | 200 | `AUTHORIZATION_ALLOWED`, `RESOURCE_READ_SUCCEEDED` | Not applicable | Audit projection contained no record content | PASS |
| M/N: hidden denied and missing detail | Identical generic 404 | Identical 404 body for known denied and nonexistent codes | `RESOURCE_READ_INACCESSIBLE` | Contributed only to probing review signal | No denial facts in response | PASS |
| O/P/Q: clearance, department, compartment denial | Generic hidden 404 | Generic hidden 404 for each | `RESOURCE_READ_INACCESSIBLE` | Contributed only to probing review signal | No policy attribute disclosed | PASS |
| S: inaccessible-resource pattern | Ten generic hidden 404 responses | Ten 404 responses | Ten additional `RESOURCE_READ_INACCESSIBLE` events | `RESOURCE_ACCESS_PROBING`, MEDIUM, count 14 across the exercise window | Finding exposed no record codes or policy facts | PASS |
| U: logout | 204; revoked credential unusable | 204; subsequent `/auth/me` returned 401 | One `LOGOUT_SUCCEEDED` | Not applicable | No session credential exposed | PASS |
| X: health | 200 `{"status":"ok"}` | 200 with exact body | None | None | No dependency or diagnostic detail | PASS |
| Y/Z: audit and detection authorization | Auditor 200; Administrator/Analyst 403; unauthenticated 401 | Exact expected statuses | Querying added no self-audit event | Authorized findings returned | Fixed safe projections only | PASS |

## Durable evidence summary

The authorized audit projection contained controlled fields only. Observed
exercise codes included password success/failure, MFA challenge/factor outcomes,
challenge exhaustion, session establishment, authorization allow/deny,
collection read, resource read success/inaccessibility, and logout success.
Exactly one collection event was emitted. No per-candidate collection audit
amplification occurred.

The projection exposed no password/verifier, attempted username, TOTP value or
secret, provisioning URI, session/challenge credential or hash, cookie, IP,
user agent, request body, authorization-attribute dump, classified content,
limiter key, or source-correlation secret.

## Detection review and benign explanations

| Finding | Severity | Observed count(s) | Plausible benign explanation |
|---|---|---:|---|
| `REPEATED_PASSWORD_FAILURE` | MEDIUM | 5 and 10 for separate synthetic subjects | A legitimate user forgot or mistyped a password. |
| `MFA_FAILURE_PATTERN` | MEDIUM | 5 | Authenticator clock drift or repeated user entry mistakes. |
| `MFA_CHALLENGE_EXHAUSTION` | HIGH | 1 | A legitimate user exhausted a short-lived challenge. |
| `RESOURCE_ACCESS_PROBING` | MEDIUM | 14 | Mistyped, stale, or imported record references. |

These findings are review signals, not claims that a user is malicious,
compromised, or an attacker.

## Scenarios covered by deterministic tests instead of manual execution

- TOTP replay: live counter timing would make manual reproduction unreliable;
  deterministic MFA tests cover replay rejection and state preservation.
- Authorization-denial spike: the exercise generated 14 legitimate central
  denials, below the 25-event threshold; no events were fabricated merely to
  trigger a finding. The detector threshold is covered by deterministic tests.
- Session replacement: a second successful MFA completion would require a new
  TOTP counter; existing deterministic HTTP tests cover old-session revocation
  and replacement evidence without unsafe timing manipulation.
- Concurrency saturation and abuse-store outage: no uncontrolled load or global
  store breakage was attempted. Existing deterministic injection tests cover
  saturation, controlled outage behavior, logout recovery, and health
  independence.
- Source/distributed detection was not attempted because source correlation
  remains intentionally deferred.

No application defect was observed. The local PostgreSQL `alembic_version`
permission prevents live exercise bootstrap and should be handled as an
environment/database-privilege follow-up, not by weakening application guards.
