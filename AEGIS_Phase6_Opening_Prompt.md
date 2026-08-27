# AEGIS Phase 6 Opening Prompt

Project root:

```text
C:\Python\Projects\AEGIS
```

## Mission

Begin Phase 6 - Security Logging, Monitoring, Audit Visibility, and Detection.
Phase 5 is complete. Do not implement Phase 7 deployment, shared rate limiting,
edge/CDN enforcement, or a full SIEM during this phase.

Start design-first. Before changing code, inspect the repository, Git history,
tests, migrations, and the current authoritative documents, especially:

```text
AEGIS_Project_Plan.md
AEGIS_Current_Status_and_Handover.md
AEGIS_Architecture_and_Security_Design.md
AEGIS_Decision_Log.md
Phase_5_Completion_Summary.md
README.md
```

Confirm branch, working-tree state, local/remote divergence, current Alembic head,
and the automated baseline. Git history is authoritative for the Phase 5 closure
commit created after this prompt. The accepted pre-closure implementation
baseline is `2b323baea4a8310c7560fbf0d25fe8f12279fc30`, Alembic head is
`20260826_0007`, and the accepted suite is `362 passed, 2 known warnings`.

## Required opening inspection

Map the existing authentication, MFA, session, logout, authorization, record,
public availability, health, error, and abuse-control flows. Locate every current
logging/audit call, sink, event type, transaction boundary, persistence model,
configuration surface, and test. Distinguish:

- durable database facts from best-effort application logs;
- security audit evidence from operational diagnostics;
- expected deny/limit outcomes from infrastructure and programming failures;
- identity references safe for correlation from secrets or sensitive attributes;
- events that must be atomic with state change from events that may be emitted
  after a response boundary;
- user-visible status from administrator/investigator-only detail.

Do not assume the current non-persistent authentication logging sink is an
immutable audit trail. Do not expose internal authorization reasons, limiter
scope, secrets, raw bearer material, passwords, TOTP values, request bodies,
database URLs, or classified record content.

## Design questions to answer before implementation

Produce a concise threat model and proposed architecture covering:

1. A controlled security-event taxonomy and schema, including event identity,
   timestamps, outcome, actor/subject references, request correlation, source
   handling, target category, severity, and stable machine-readable reason codes.
2. Authentication visibility for password verification, MFA challenge lifecycle,
   TOTP success/failure/replay, session issuance/resolution/revocation, and logout
   without creating enumeration or credential leakage.
3. Authorization visibility for explicit allow/deny/error outcomes while keeping
   internal policy facts and hidden record existence away from HTTP clients.
4. Abuse visibility for admission denial, cooldown, capacity/cardinality pressure,
   expected store outage, and concurrency saturation without logging limiter keys
   or attacker-controlled high-cardinality identifiers.
5. Operational visibility for database, audit-sink, application, and unexpected
   failures with safe exception treatment and useful correlation.
6. Persistence and transaction semantics: which events require durable,
   append-oriented storage; which must commit atomically with security state;
   what fail-closed/fail-open behavior is justified; and how duplicates,
   retries, ordering, and rollback are handled.
7. Query and visibility boundaries for a future administrator/security-auditor
   view, including backend authorization, pagination/bounds, safe projections,
   and avoidance of client-side policy decisions.
8. Initial detection patterns and thresholds, such as distributed authentication
   failure, repeated MFA challenge exhaustion, session anomalies, authorization
   denial/error spikes, abuse-store failure, concurrency saturation, and unusual
   record-access patterns. Separate evidence-based detection from speculative
   scoring and address false positives.
9. Privacy, minimization, retention, redaction, integrity, access control, clock,
   testing, and synthetic-data requirements.
10. A future integration boundary for SIEM/Wazuh or similar tooling without
    installing or operating a full SIEM in Phase 6.

Evaluate whether a migration and persistent audit model are necessary. If so,
design ownership, indexes, immutability expectations, bounded queries, retention,
and transaction integration before writing it. Preserve PostgreSQL least
privilege and Alembic ownership conventions.

## Invariants to preserve

- Authentication and authorization remain backend-owned, typed, generic at HTTP
  denial boundaries, and deny/fail closed where currently specified.
- No authorization caching or client-side authorization is introduced.
- Hidden record 404 behavior and policy-first/content-second reads remain intact.
- Phase 5 abuse state remains bounded, HMAC-correlated, and free of record-code or
  authorization-attribute keys.
- `/health` remains database-independent and abuse-store-independent; do not turn
  it into a detailed unauthenticated diagnostic endpoint.
- Logout's controlled abuse-store recovery boundary is not widened.
- No real identities, credentials, classified data, or production secrets are
  used. `.env` remains ignored and undisplayed.
- Existing cookie, CSP, CSRF, MFA replay, session, migration, and collection-cap
  decisions remain in force unless a separately reviewed defect requires the
  smallest correction.

## Scope discipline

Phase 6 may implement the smallest coherent logging, monitoring, persistent audit,
query, and local detection foundation justified by the approved design. It must
not implement production deployment, reverse-proxy trust, Cloudflare, Redis/shared
abuse state, infrastructure monitoring rollout, full SIEM operation, account
lockout, CAPTCHA, fingerprinting, record mutation workflows, or unrelated UI
features. Preserve Phase 7 ownership of deployment and edge controls.

Use deterministic tests, injectable clocks/IDs where appropriate, bounded result
sets, generic client errors, and explicit failure tests. Update architecture,
decision, status, and completion documentation as work is accepted. Keep each
checkpoint narrowly staged and inspect diffs for secrets before committing.

## Required post-Phase 6 local exercise

After Phase 6 is reviewed, use fully configured synthetic accounts with password,
enrolled MFA/TOTP, roles, departments, clearances, compartments, and controlled
authorized/unauthorized records. Run a structured local browser/API exercise for
wrong passwords, login limits, MFA cooldown/fifth-failure revocation/recovery,
session and logout paths, collection/detail allow and hidden deny, rate and
concurrency behavior, and the corresponding audit/monitoring evidence. Confirm
that logs reveal neither secrets nor classified content and that detection output
is useful without exposing internal policy to the browser.

## First deliverable

Return an inspection report, threat model, proposed event taxonomy, persistence
and transaction design, privacy/retention policy, detection candidates, phased
implementation plan, expected files/migrations/tests, and explicit deferred
items. Stop for review before broad implementation. Do not begin Phase 7.
