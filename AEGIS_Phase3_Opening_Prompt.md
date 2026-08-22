# AEGIS - Phase 3 Opening Prompt

We are continuing AEGIS, a fictional Classified Intelligence Access System and
cybersecurity learning environment. All users, organizations, intelligence
records, classifications, compartments, credentials, and security events are
synthetic.

## Current checkpoint

Phase 1 - Foundation & Architecture and Phase 2 - Authentication & 2FA are
**complete**. Phase 3 - Authorization & Classified Records is **not started** and
is the phase this chat will begin.

Phase 2 implemented typed synthetic users, Argon2id password verification and
upgrades, enumeration-cost mitigation, generic login failures, precise
non-persistent authentication logging, finite hash-only server-side sessions,
session rotation/revocation, encrypted TOTP credentials, enrollment and
confirmation services, TOTP replay protection, short-lived hash-only MFA
challenges, final TOTP-gated session issuance, and authenticated identity
resolution through `GET /auth/me`.

Latest Phase 2 closure verification at document creation:

```text
Python: 3.13.15
pytest: 96 passed, 2 warnings in 11.85s
PostgreSQL Alembic offline SQL: PASS through revision 20260822_0004
Latest committed checkpoint before closure: e5b93a3
Final Phase 2 checkpoint identifier: use current Git history as authoritative
Deployment: local development only
```

The known non-blocking warning is the `StarletteDeprecationWarning`. Some Codex
environments also report a `PytestCacheWarning` because `.pytest_cache` access is
denied. Verify the current results instead of assuming warning counts.

## Implemented authentication boundary

- `POST /auth/login` verifies a password and either issues a normal session for a
  user without enabled TOTP or issues only a short-lived MFA challenge.
- `POST /auth/mfa/totp/verify` requires the challenge-bound user's valid TOTP,
  consumes the challenge, and issues a fresh normal session only after commit.
- `GET /auth/me` returns safe current identity for a usable session.
- `POST /auth/logout` revokes presented session/challenge state and clears cookies.
- Authentication principals contain identity only. They carry no role,
  department, clearance, compartment, record permission, or administrative grant.
- MFA enrollment/disablement remains service-only pending dedicated CSRF design.
- The current audit sink is ordinary non-persistent, non-transactional logging;
  persistent audit evidence is not implemented.

## Inherited security invariants

- Default deny applies to missing, invalid, ambiguous, stale, incomplete, or
  unevaluable authentication and authorization state.
- FastAPI/backend policy is authoritative. UI visibility and caller-supplied
  attributes are never authorization boundaries; direct API calls receive the
  same checks.
- Authentication proves identity but never grants authorization.
- System administration does not automatically grant classified-content access.
- A record identifier identifies a candidate resource and never authorizes it.
- Authorization must evaluate current server-side subject, resource, action, and
  applicable context. It must not trust role, clearance, department, or
  compartment claims supplied by the client.
- Role capability and resource-specific ABAC checks are both required. No role
  bypasses classification, department, compartment, lifecycle, or other
  applicable policy.
- The ordered classification rule is `UNCLASSIFIED < CONFIDENTIAL < SECRET < TOP
  SECRET`; subject clearance must dominate the resource classification.
- Each user has one primary department. Each record must list at least one
  authorized department; missing department policy denies. Department membership
  alone is never sufficient.
- Zero record-compartment rows means no compartment requirement. When rows exist,
  the subject must hold every required compartment.
- System administrators manage system functions but receive no implicit
  intelligence-record access. Security auditors receive only explicitly designed
  audit capabilities.
- Passwords, raw sessions, raw MFA challenges, TOTP secrets, encryption keys,
  entered codes, and provisioning URIs must not enter logs, errors, source
  control, or unauthorized persistence.
- PostgreSQL remains private. Runtime, migration, backup, and administration
  privileges remain separate; the runtime account is not a superuser or schema
  owner. RLS may later provide defense in depth but is not the primary policy
  engine.

## Phase 3 direction

Begin with the smallest secure centralized authorization slice built on the
existing authenticated principal. Before implementation, inspect and reconcile
the Phase 1 authorization/database design with the actual Phase 2 models and
migrations.

A suitable first slice should define a typed authorization decision boundary and
the minimum normalized persistence needed for current subject attributes, without
yet building the full classified-record product. It should make action, subject,
resource, and deny reasons explicit; default deny when any required policy is
absent; and be independently unit-testable before broad HTTP integration.

Plan Phase 3 in controlled parts. Likely later Phase 3 work includes reviewed
roles and user-role assignments, departments and primary user department,
ordered clearance, compartments and user-compartment assignments, classified
record persistence, record-department and record-compartment policy, centralized
RBAC+ABAC evaluation, backend endpoint enforcement, negative direct-API tests,
and appropriate audit semantics. Do not implement all of this in one unreviewed
change.

## Explicit exclusions at Phase 3 opening

Do not begin the Phase 4 frontend, visual login page, dashboard, Phase 5 bot or
abuse platform, CAPTCHA, Phase 6 monitoring/SIEM program, Phase 7 deployment,
Cloudflare, Nginx, Proxmox, public access, Phase 8 release work, or AI/RAG.

Do not redesign the accepted password/session/MFA workflow merely to begin
authorization. Do not expose service-only MFA enrollment before its CSRF and
account-management workflow is deliberately designed.

## How this project works with Codex

Use substantial but controlled parts. The chat plans each part and prepares a
clear Codex request; Codex performs implementation, file creation, migrations,
bulk editing, and tests; the chat reviews and verifies the result; then living
documentation and current status are updated. Avoid unnecessary tiny fragments.

Before each implementation part, re-run the accepted baseline and stop on
unexpected failure. Add positive and negative tests with every policy change.
Use deterministic time and disposable SQLite where portable behavior is under
test, while PostgreSQL remains the application target. Render/review PostgreSQL
Alembic SQL for every new migration and do not claim live PostgreSQL concurrency
or RLS verification unless it was actually performed.

Use Git/GitHub only at meaningful stable checkpoints and only when authorized.
Stop on failing tests, whitespace errors, unexpected files, secrets, conflicts,
unexpected remote commits, authentication failures, or rejected pushes. Never
force-push, hard-reset, destructively rewrite history, or automatically resolve a
conflict in a way that could discard work.

## Authoritative handover package

Review all of these before asking Codex to implement Phase 3:

```text
AEGIS_Phase3_Opening_Prompt.md
AEGIS_Current_Status_and_Handover.md
AEGIS_Project_Plan.md
Phase_2_Completion_Summary.md
AEGIS_Architecture_and_Security_Design.md
AEGIS_Decision_Log.md
```

The current local repository is the first source of truth, followed by verified
GitHub `main`, the handover, architecture/security design, decision log, project
plan, completion summary, and this opening prompt. A ZIP is not the routine source
of truth.

## What the Phase 3 chat must do first

1. Review the complete handover package and current repository.
2. Re-run the full baseline and report the exact result.
3. Confirm Phase 2 authentication invariants and that authentication still grants
   no authorization.
4. Reconcile the planned Phase 1 RBAC/ABAC schema with actual migrations and
   identify the smallest secure Phase 3 slice.
5. Threat-model missing policy, stale assignments, client-supplied claims,
   identifier-based bypass, administrator overreach, and direct API access.
6. Propose files, migration impact, centralized decision types, positive/negative
   tests, transaction/audit ownership, and explicit exclusions.
7. Only then prepare the first Phase 3 implementation request. Do not implement
   Phase 3 merely by reading this prompt.
