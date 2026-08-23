# AEGIS - Phase 4 Opening Prompt

We are continuing AEGIS, a fictional Classified Intelligence Access System and
cybersecurity learning/portfolio environment. Every identity, organization,
record, classification, compartment, credential, and security event is synthetic.
AEGIS must never be described or used as a repository for real classified data.

## Authoritative phase state

```text
Phase 1 - Foundation & Architecture: COMPLETE
Phase 2 - Authentication & 2FA: COMPLETE
Phase 3 - Authorization & Classified Records: COMPLETE
Phase 4 - Modern Security Interface: NOT STARTED
Deployment: local development only
Alembic head: 20260823_0006
Final Phase 3 closure checkpoint: use current GitHub main/HEAD as authoritative
```

Phase 4 must begin in a new chat by reviewing the repository and proposing a
design. Do not ask Codex to implement UI work until that design and its security
boundaries have been reviewed and accepted. Do not prescribe a complete frontend
architecture before inspecting actual backend behavior and project dependencies.

## Read first

Review these documents and the actual repository before planning implementation:

```text
AEGIS_Phase4_Opening_Prompt.md
AEGIS_Current_Status_and_Handover.md
AEGIS_Project_Plan.md
AEGIS_Architecture_and_Security_Design.md
AEGIS_Decision_Log.md
Phase_3_Completion_Summary.md
README.md
```

Use this source-of-truth hierarchy when facts conflict:

1. Actual repository implementation and tests.
2. `AEGIS_Current_Status_and_Handover.md`.
3. `AEGIS_Architecture_and_Security_Design.md`.
4. `AEGIS_Decision_Log.md`.
5. `AEGIS_Project_Plan.md`.
6. Phase completion summaries.
7. `README.md`.

Investigate and reconcile inconsistencies rather than guessing. GitHub `main`
and the local repository at a verified synchronized checkpoint are the durable
project record; routine ZIP handovers are neither required nor authoritative.

## Inherited authentication backend

Phase 2 provides:

```text
POST /auth/login
POST /auth/mfa/totp/verify
GET  /auth/me
POST /auth/logout
```

Password login either issues a finite hash-only server-side session or, for an
enabled-TOTP user, issues only a short-lived hash-only MFA challenge. Successful
TOTP completion consumes the challenge and issues the normal session. Cookies are
`HttpOnly` and `SameSite=Strict`; `Secure` is required outside explicit local/test
environments. MFA enrollment and disablement remain service-only because a
dedicated authenticated state-changing CSRF design is not implemented.

`AuthenticatedPrincipal` contains identity only. Sessions and cookies contain no
role, department, clearance, compartment, record permission, or administrative
grant.

## Inherited authorization backend

Phase 3 provides a separate current immutable `AuthorizationSubject` loaded from
server-side persistence on every protected request and one typed central
default-deny `authorize()` evaluator. The backend never trusts client roles or
attributes. Identifiers and creator provenance select or describe candidates but
never authorize. Role capability permits evaluation to continue and never
bypasses classification, department, compartment, lifecycle, or other applicable
policy.

Controlled roles are Analyst, Senior Analyst, Supervisor, Security Auditor, and
System Administrator. System administration and security auditing do not
automatically grant classified intelligence access. Controlled clearance ranks
are `UNCLASSIFIED=10`, `CONFIDENTIAL=20`, `SECRET=30`, and `TOP SECRET=40`.
Classified access additionally requires an authorized current department and all
required compartments. DRAFT and RETIRED records are inaccessible; ACTIVE is
only potentially usable with complete valid policy.

## Inherited classified-record HTTP backend

Phase 3 exposes two read-only routes:

```text
GET /records
GET /records/{record_code}
```

`GET /records` returns only backend-authorized metadata with exactly
`record_code`, `title`, and `classification`. Every entry requires central SEARCH
and READ allows. There are no query search terms, filters, totals, or pagination.
The backend evaluates at most 100 deterministic policy candidates; a 101st fails
closed with generic `503`. A valid empty authorized set is `200 []`. FastAPI
currently ignores unknown query parameters, which have no filter or authorization
effect.

`GET /records/{record_code}` requires central READ allow before loading title,
summary, content, and classification. Missing, malformed, and ordinarily
inaccessible candidates share a hidden generic `404`; evaluator and record
infrastructure failures use generic `503`. Authentication infrastructure retains
its separate generic `503`.

The UI must never authorize records, compare clearance, filter for security,
trust client-side roles, or decide department/compartment access. It may render
only what the backend already authorizes. Button visibility and navigation are
usability choices, never security controls. Direct API requests remain protected
without the UI.

## Phase 4 goal and initial direction

Phase 4 is **Modern Security Interface**. Begin by inspecting the application,
routes, dependencies, response shapes, existing assets, and development workflow,
then propose a coherent design in substantial parts.

The initial UI should be read-only and may cover:

- a modern security/command-center visual language;
- synthetic/classified handling banners without fake security claims;
- the existing password authentication flow;
- the supported MFA challenge flow;
- session identity and logout;
- an authorized record collection/index;
- an authorized classified-record detail view;
- access-denied, hidden-record, authentication-required, loading, empty, session,
  and service-error states;
- accessibility, responsive behavior, and browser security appropriate to the
  selected frontend approach.

The Phase 4 chat must inspect actual capabilities before defining pages,
components, build tooling, or integration. Prefer a small coherent design over
premature architecture or decorative features that suggest nonexistent controls.

## Backend capabilities Phase 4 must not assume

Do not assume support for record creation, editing, deletion, retirement,
activation, policy mutation, record-code allocation, role/clearance/department/
compartment assignment administration, administrative authorization endpoints,
query or full-text search, ranking, pagination, totals, persistent audit viewing,
bot detection, monitoring/SIEM, production deployment, RLS, or AI/RAG.

Persistent authorization audit remains primarily Phase 6 scope. Bot and abuse
protection belongs to Phase 5. Deployment belongs to Phase 7. The current
policy-first/content-second read design validates representation consistency but
does not claim to solve future concurrent-mutation TOCTOU; mutation work requires
an approved isolation/versioning and atomic audit design first.

## Project working method

Responsibilities are deliberately separated:

```text
ChatGPT:
planning
design
security review
verification
status tracking
Codex prompts
handover

Codex:
implementation
file edits
tests
migrations
local verification
Git/GitHub actions only when explicitly authorized
```

Work in substantial, reviewable parts rather than tiny fragments:

```text
design/review
-> Codex implementation prompt
-> Codex result review
-> security review/correction
-> verification
-> checkpoint
```

At the start of Phase 4, first verify the inherited baseline, inspect current
dependencies and route behavior, identify the smallest useful read-only UI slice,
threat-model client-side authorization mistakes and session/error handling, and
propose the design, files, tests, security constraints, and exclusions. Only then
prepare an implementation request.

## Testing rules

Preserve the complete backend pytest suite, Phase 2 authentication regression,
Phase 3 authorization/record/detail/collection regressions, and direct API
protection. Once frontend work exists, add proportionate browser/frontend tests
for authentication, MFA, session expiry, authorized list/detail rendering, empty
and error states, accessibility, and direct navigation. Frontend tests do not
replace backend authorization tests. Begin every substantial part from a verified
baseline and stop on unexpected regression.

## Git and GitHub rules

- `main` is the authoritative branch.
- GitHub and repository living documents are the source of truth; do not create
  routine ZIP handovers.
- Fetch before a checkpoint and verify `origin/main...main` divergence.
- Stop on unexpected files, artifacts, secrets, conflicts, unexpected remote
  changes, authentication failure, rejected push, or failing verification.
- Never force-push, hard-reset, rewrite history, or automatically resolve a
  conflict in a way that could discard work without explicit approval.
- Create a meaningful checkpoint only after implementation and security review
  are accepted and verification passes.
- Codex performs Git/GitHub actions only when the user explicitly authorizes them.

## What the Phase 4 chat must do first

1. Read the complete handover package and inspect the repository.
2. Fetch and verify the current `main` checkpoint and clean working tree.
3. Re-run the inherited backend baseline and report exact results.
4. Confirm the actual authentication and record API contracts.
5. Confirm authorization remains backend-owned and the UI will perform no
   security filtering or attribute comparison.
6. Review available frontend approaches and existing dependencies without
   prematurely selecting an architecture.
7. Propose a Phase 4 design divided into substantial, reviewable parts, including
   pages/states, accessibility, browser testing, security boundaries, likely
   files/dependencies, and explicit exclusions.
8. Only after review, prepare the first Codex implementation request. Do not
   implement Phase 4 merely by reading this prompt.
