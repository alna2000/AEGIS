# AEGIS Phase 5 Opening Prompt

**The next Phase 5 chat must read this file first.**

AEGIS is a fictional cybersecurity learning and portfolio environment. All
identities, credentials, organizations, records, classifications, compartments,
and security events are synthetic. Phase 4 is complete; Phase 5 implementation
has not started.

## Phase 5 objective

Phase 5 is **Bot Detection & Abuse Protection**. It must begin with inspection,
threat modeling, and design—not implementation.

Bot detection is defense in depth. It does not replace password authentication,
MFA, server-side sessions, centralized authorization, generic error handling, or
availability engineering. The backend remains authoritative.

## Mandatory opening sequence

Before preparing the first implementation prompt:

1. Verify the repository branch, clean state, synchronized `origin/main`, current
   Alembic head, dependency health, and full pytest baseline.
2. Review the implemented password login, MFA challenge/TOTP completion,
   current-session resolution, logout, and session lifecycle.
3. Review the existing threat model and update it for automation and abuse.
4. Inventory the bot/automation abuse surface, especially login, MFA, session-
   sensitive endpoints, health/availability behavior, and future public routes.
5. Compare rate-limit, throttling, cooldown, and lockout architectures, including
   identity-, IP-, network-, session-, and endpoint-scoped keys.
6. Review challenge/CAPTCHA escalation tradeoffs without assuming a third-party
   service is required.
7. Assess privacy, accessibility, false positives, recovery, and user support.
8. State local-development and future deployment/proxy assumptions explicitly,
   including trusted client-IP handling and distributed-state needs.
9. Produce and review a concrete design before any Codex implementation prompt.

## Required principles

- Preserve generic authentication failures and no-user-enumeration behavior.
- Protect login, MFA, and session-sensitive operations without disclosing whether
  an account exists or which factor/state failed.
- Prefer progressively stronger friction: rate limits, cooldowns, bounded
  lockouts, and challenge escalation should be justified independently.
- Avoid invasive fingerprinting and unnecessary third-party tracking.
- Use IP/network or browser/device signals only where their reliability, privacy,
  proxy behavior, and evasion limits are explicit.
- Avoid a hard dependency on paid or external services for this learning project.
- Account for shared networks, NAT, accessibility needs, clock behavior,
  legitimate automation, and false positives.
- Fail safely when rate-limit storage or challenge infrastructure is unavailable;
  define whether each protected operation fails closed, degrades, or sheds load.
- Keep secrets, raw credentials, TOTP codes, session/challenge tokens, and
  sensitive fingerprint material out of logs and persistent counters.
- Do not move authorization, record visibility, or policy evaluation into the
  browser.

## Read first

Review the actual repository and at least:

```text
AEGIS_Phase5_Opening_Prompt.md
AEGIS_Current_Status_and_Handover.md
AEGIS_Project_Plan.md
AEGIS_Architecture_and_Security_Design.md
AEGIS_Decision_Log.md
Phase_4_Completion_Summary.md
README.md
```

Use this source-of-truth order when facts conflict:

1. Actual implementation and tests.
2. `AEGIS_Current_Status_and_Handover.md`.
3. `AEGIS_Architecture_and_Security_Design.md`.
4. `AEGIS_Decision_Log.md`.
5. `AEGIS_Project_Plan.md`.
6. Phase completion summaries.
7. `README.md`.

Investigate inconsistencies rather than guessing.

## Inherited boundaries

Phase 4 provides a same-origin, read-only FastAPI/Jinja2/local-CSS/plain-JavaScript
interface at `GET /ui`. It renders only backend-authorized responses from the
existing authentication and record routes. Cookies are backend-managed and
`HttpOnly`; the UI stores no tokens and performs no authorization.

The current authenticated browser state-changing surface remains deliberately
small. `SameSite=Strict` is a useful baseline, not a universal CSRF design. Do
not expand enrollment, account administration, record mutation, or other state-
changing UI scope as part of abuse protection without their owning security
designs.

## Explicit exclusions at Phase 5 opening

Do not begin Phase 6 persistent audit work, Phase 7 deployment, production proxy
configuration, record CRUD, assignment administration, rich search, RLS, AI/RAG,
or frontend authorization. Phase 5 must not redesign the completed Phase 4 UI
unless a reviewed abuse-protection interaction requires a small accessible state.
