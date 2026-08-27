# AEGIS Project Plan

AEGIS is a fictional cybersecurity learning project that will use synthetic data.
The roadmap is intentionally flexible: later details may change when a clearer
learning path or stronger security approach is discovered.

## Roadmap

1. **Phase 1 — Foundation & Architecture**
   Establish the project foundation, then design security and data architecture.
2. **Phase 2 — Authentication & 2FA**
   Establish user identity and a second authentication factor.
3. **Phase 3 — Authorization & Classified Records**
   Enforce access decisions and introduce synthetic intelligence records.
   **Complete.**
4. **Phase 4 — Modern Security Interface**
   Build a clear, professional user interface over proven backend controls.
   **Complete.**
5. **Phase 5 — Bot Detection & Abuse Protection**
   Add layered defenses for automated and abusive requests.
   **Complete.**
6. **Phase 6 — Audit, Monitoring & Security Testing**
   Improve observability and systematically test the security controls.
7. **Phase 7 — Home Server Deployment & Public Access**
   Harden and deploy AEGIS after private review and recovery testing.
8. **Phase 8 — Final Review, Documentation & Portfolio Release**
   Complete verification and prepare the AEGIS v1 portfolio release.

## Current milestone

```text
Phase 2: COMPLETE
Phase 3: COMPLETE
Phase 4: COMPLETE
Phase 5: COMPLETE
Phase 6: NOT STARTED
```

Phase 1 is complete: Part 1 established the verified minimal FastAPI foundation,
Part 2 designed the security architecture, and Part 3 designed the database
architecture. Phase 2 - Authentication & 2FA is complete. Part 1 implemented
minimum user persistence, migration, password security, and its service boundary.
Part 2 implemented generic login-attempt orchestration,
enumeration-cost mitigation, bounded request context, and a required
credential-verification logging interface. Part 3 implemented HTTP login,
hash-only server-side sessions, secure cookies, centralized session validation,
current-identity
resolution, and logout/revocation. Part 4 implemented encrypted TOTP credential
persistence, service-layer enrollment and confirmation, a narrow verification
window, counter-based replay protection, disablement, and controlled TOTP audit
semantics. Part 5 completed password-to-MFA challenge integration, hash-only
short-lived challenge state, final session issuance, bypass/replay/transaction
tests, and the Phase 2 security review. Phase 3 - Authorization & Classified
Records is complete. Part 1 implements normalized current subject attributes,
server-side `AuthorizationSubject` loading, controlled reference data, an explicit
version-controlled role capability map, and a pure typed default-deny policy over
content-free resource snapshots. Part 2 implements bounded synthetic classified
record persistence, normalized department/compartment policy relationships, a
restricted read-only policy-fact repository, and fail-closed conversion into the
existing `ResourcePolicy`. Authentication state still grants no authorization,
and identifiers or creator provenance never authorize. Part 3 implements the
first protected single-record backend READ path: it reloads current subject state,
authorizes content-free record policy through the existing evaluator, and loads
an intentionally bounded content representation only after explicit `ALLOW`.
Missing and inaccessible records share a generic external 404, while evaluator
and infrastructure failures use a generic 503. Part 4 implements the bounded
`GET /records` collection path: current subject facts and content-free candidate
policies are loaded first, every returned entry requires explicit central SEARCH
and READ allows, and metadata is batch-loaded only for allowed internal UUIDs.
The output is sorted record code/title/classification only, with no totals or
pagination; zero accessible records returns `[]`, while candidate overflow above
100, evaluator failure, corrupted policy, or inconsistent batch state fails the
whole operation with generic 503. Record CRUD, rich search, production mutation
and activation workflows, assignment workflows, frontend authorization, and
persistent authorization audit storage remain deferred. Role capability is only
eligibility for further evaluation and does not waive future action-specific
workflow/context checks. Phase 4 - Modern Security Interface is complete: its
same-origin FastAPI/Jinja2/local-CSS/plain-JavaScript interface presents existing
authentication, MFA, session, authorized collection, and protected detail
contracts without moving policy into the browser. Final hardening adds strict
route-scoped browser headers/CSP, accessible and responsive states, safe
text-only rendering, stale-operation guards, and an explicit local synthetic
demo workflow. Phase 5 - Bot Detection & Abuse Protection is complete. It adds
a centralized typed and bounded abuse-control engine, process-local ephemeral
state behind a storage abstraction, HMAC correlation, layered authentication and
availability controls, challenge-only MFA revocation, expensive-work concurrency,
public GET/HEAD protection, an independent health endpoint, and minimal 429 UI
compatibility. Phase 6 has not started and must begin with logging and monitoring
inspection and design.

## Phase Completion and Handover Protocol

AEGIS is developed in phases. The normal project rule requires each substantial
phase to start in a new ChatGPT chat so that conversation history remains
manageable. The user should not need to restate this protocol at later phase
boundaries.

At the end of every phase, complete this workflow before starting the next one:

1. Complete the phase implementation.
2. Run the appropriate automated tests and security/quality checks.
3. Review the completed scope and confirm that the next phase was not started
   accidentally.
4. Update `AEGIS_Current_Status_and_Handover.md`.
5. Update architecture, decision, and project-plan documents where necessary.
6. Create `Phase_X_Completion_Summary.md` for the completed phase.
7. Create `AEGIS_PhaseX_Opening_Prompt.md` for the phase being started next.
8. Perform a meaningful Git/GitHub checkpoint.
9. Confirm that the repository is clean and synchronized.
10. Start the next phase in a new ChatGPT chat.

The next-phase opening prompt is mandatory. It must identify what AEGIS is and
that all data is synthetic; the completed and newly starting phases; implemented
versus architecture-only work; inherited security decisions; latest tests,
warnings, Git checkpoint, and deployment state; the new phase's scope and
explicit exclusions; the Codex working method; verification and Git/GitHub
policies; authoritative documents; and what the new chat must do first. The new
chat must review the supplied project and handover documents before asking Codex
to implement the next phase.

The recommended minimum new-chat handover package is:

```text
AEGIS_PhaseX_Opening_Prompt.md
AEGIS_Current_Status_and_Handover.md
AEGIS_Project_Plan.md
Phase_Previous_Completion_Summary.md
```

Include `AEGIS_Architecture_and_Security_Design.md` and
`AEGIS_Decision_Log.md` when relevant. They should normally be included and
reviewed for security-sensitive phases such as authentication, authorization,
database implementation, deployment, and AI/RAG.

### Git/GitHub phase checkpoint

Git/GitHub is the normal source-code checkpoint and version history. At a
meaningful phase completion, when authorized, Codex may save interactive time by
running tests and `git diff --check`, reviewing status and intended changes,
checking for secrets and local artifacts, staging the phase changes, committing
with an appropriate checkpoint message, pushing to `origin/main`, and verifying
the final status and latest commit.

Codex must stop and report failing tests, unexpected files, possible credentials
or secrets, merge conflicts, unexpected remote commits, authentication failures,
or a rejected push. `git push --force`, `git reset --hard`, destructive history
rewriting, and automatic conflict resolution that could discard work always
require explicit approval.

### ZIP policy

A full project ZIP is not required at every phase boundary and must not routinely
duplicate Git checkpoints. Create one only for a specific reason, such as an
offline/archive backup, a risky architectural change, GitHub being unavailable,
moving between machines, a new chat needing direct access to the full tree, a
major release such as AEGIS v1.0, or an explicit user request.

```text
New chat every phase:          YES
Updated handover every phase:  YES
Completion summary:            YES
Next-phase opening prompt:      YES
Git/GitHub checkpoint:          YES
Full ZIP every phase:           NO, unless useful
```

### Project source of truth

Use this hierarchy for normal project continuity:

1. Actual repository implementation and tests at verified `main` checkpoints.
2. `AEGIS_Current_Status_and_Handover.md`.
3. `AEGIS_Architecture_and_Security_Design.md`.
4. `AEGIS_Decision_Log.md`.
5. `AEGIS_Project_Plan.md`.
6. Latest `Phase_X_Completion_Summary.md`.
7. `README.md`.
8. Next-phase opening prompt for operating instructions.

A ZIP is not the primary source of truth.

## Post-Project Learning and Security-Testing Roadmap

This is future learning and authorized assessment work. It is **not complete**
and does not replace or restructure the development phases above. AEGIS should
be the primary practical teaching example wherever possible.

```text
Build AEGIS
→ Learn AEGIS deeply
→ Safely attack/test AEGIS
→ Remediate weaknesses
→ Retest
→ Document learning and professional security assessment
```

### Application and backend foundations

Study FastAPI, SQLAlchemy, PostgreSQL, Alembic, dependency injection, the
request/response lifecycle, ORM and transaction behavior, migrations, and schema
ownership by tracing real AEGIS flows and tests.

### Authentication and identity security

Practice password authentication, Argon2id password hashing, server-side
sessions, cookies and secure attributes, session fixation prevention, session
revocation, MFA/TOTP, and replay protection against the implemented boundaries.

### Authorization

Study RBAC, ABAC, combined RBAC/ABAC decisions, default deny, backend authority,
clearance, departments, compartments, and object/resource authorization. Verify
that direct requests cannot bypass the central evaluator.

### Frontend and browser boundaries

Learn HTML, CSS, JavaScript, Jinja2, browser request flow, and frontend/backend
trust boundaries through the same-origin interface. The browser remains a
presentation client, not an authorization authority.

### Web application security

Study CSP, security headers, XSS, CSRF, IDOR/BOLA, authentication and session
attacks, authorization bypass testing, information disclosure, and safe error
handling through both normal and adversarial requests.

### Abuse protection

Study rate limiting, throttling, cooldowns, concurrency limits, bot protection,
false positives, NAT/shared-IP considerations, proxy/client-IP trust, and CAPTCHA
tradeoffs. Compare Phase 5's bounded local controls with later distributed and
edge designs.

### Logging and monitoring

Study security-event logging for authentication, authorization, abuse, and
operational errors; alerting concepts; incident investigation; log privacy; and
sensitive-data handling. Phase 6 should establish safe visibility before
realistic structured attack exercises.

### Development workflow

Practice Git, GitHub, commits, branches, review, versioning, rollback/checkpoint
concepts, and secure repository hygiene without committing secrets or generated
local artifacts.

### Deployment and infrastructure

Later study server deployment, applicable Linux/server administration, HTTPS/TLS,
certificates, DNS, Cloudflare, reverse proxies, trusted proxy headers,
secrets/configuration, PostgreSQL deployment, least privilege, backups, and
restore testing. These are not current implementation claims.

### Vulnerability assessment and penetration testing

Use AEGIS as the main authorized target. Practice vulnerability-assessment
methodology, threat modeling, attack-surface mapping, manual testing,
authenticated versus unauthenticated testing, API testing, and web application
testing. Learn Burp Suite, OWASP ZAP, browser developer tools, safe command-line
and API testing, and applicable OWASP testing methodology.

### Network and server security testing

After deployment readiness, assess exposed ports/services, firewall policy, TLS
and server configuration, SSH and PostgreSQL exposure, reverse-proxy behavior,
DNS/Cloudflare configuration, and service-account permissions. Testing must stay
strictly within the user's own authorized lab, server, and application.

### Remediation lifecycle

```text
Find weakness
→ understand root cause
→ assess severity
→ implement remediation
→ regression test
→ retest exploit/path
→ document evidence
```

### Professional security assessment report

The final learning output should include an executive summary, scope,
methodology, architecture summary, threat model, findings, severity/risk,
evidence, remediation, retest results, residual risk, and lessons learned. It
must distinguish verified evidence from assumptions and document authorization
and synthetic-data constraints.
