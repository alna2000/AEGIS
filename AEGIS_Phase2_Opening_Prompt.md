# AEGIS - Phase 2 Opening Prompt

We are continuing AEGIS, a fictional Classified Intelligence Access System and
cybersecurity learning environment. All users, organizations, intelligence
records, classifications, compartments, credentials, and security events are
synthetic.

## Current checkpoint

Phase 1 - Foundation & Architecture is **complete**. Phase 2 - Authentication &
2FA is **not started** and is the phase this chat will begin.

Phase 1 implemented and verified a minimal installable FastAPI application,
environment-based local configuration, safe `.env` handling, public `GET /` and
`GET /health` endpoints, and two endpoint tests. It also designed the security
and PostgreSQL architecture. Those designs are contracts for later work, not
operational controls.

PostgreSQL, SQLAlchemy, Alembic, user persistence, password hashing, login,
sessions, MFA/TOTP, authorization enforcement, classified records, a frontend,
bot protection, persistent auditing, and deployment are not implemented.

Latest Phase 1 checkpoint:

```text
Python: 3.13.15
pytest: 2 passed, 2 warnings in 0.53s
git diff --check: exit 0, no whitespace errors; LF-to-CRLF notices emitted
Branch: main
Remote: origin
GitHub: https://github.com/alna2000/AEGIS.git
Commit: 26f4375 (Complete AEGIS Phase 1 foundation and architecture)
Checkpoint state: clean; main up to date with origin/main
Deployment: local development only
```

Known non-blocking warnings at Phase 1 completion were a
`StarletteDeprecationWarning` concerning `httpx` with `starlette.testclient` and
a `PytestCacheWarning` caused by denied `.pytest_cache` access. Verify the latest
results rather than assuming these warnings are unchanged. The system `python`
does not currently have pytest installed and PowerShell policy blocks the venv
activation script; direct `.venv\Scripts\python.exe -m pytest` invocation works.

## Inherited security decisions

- Default deny applies to incomplete, invalid, ambiguous, stale, or failed
  security decisions.
- FastAPI/backend enforcement is authoritative; UI state is not a security
  boundary, and direct API calls receive the same checks.
- Authentication proves identity but does not grant authorization.
- System administration does not automatically grant classified-content access.
- Passwords and reusable session tokens must never be stored in plaintext.
- Recoverable TOTP secrets require encryption, with keys outside PostgreSQL and
  source control.
- Security-relevant changes must produce append-oriented audit events that do not
  contain secrets.
- PostgreSQL must remain private, and the runtime account must not be a
  superuser or schema owner.

## Phase 2 scope

Plan and implement Authentication & 2FA in controlled, testable slices. Begin
with the smallest secure password-authentication slice: the user account model;
password hashing, verification, and upgrades; generic login errors; disabled-user
behavior; failed-login and audit boundaries; and secure session creation,
hash-only persistence, cookies, expiry, rotation, revocation, and invalidation.
TOTP/MFA should follow only after password authentication is established and
verified.

Do not implement Phase 3 authorization or classified records, the Phase 4 UI,
Phase 5 abuse platform, Phase 6 monitoring program, Phase 7 deployment/public
access, Phase 8 release work, or later AI/RAG integration. Do not treat successful
authentication as authorization.

## How this project works with Codex

Use substantial but controlled parts. This chat plans each part and prepares a
clear Codex request; Codex performs implementation, file creation, bulk editing,
and tests; this chat reviews and verifies the result; then documentation and
current status are updated. Avoid fragmenting the work into unnecessary tiny
steps.

For user-run PowerShell verification, provide one command or one small related
block at a time, state the expected result, and review the actual output before
continuing. Automated positive and negative tests should accompany each security
feature, with deeper abuse/security checks at phase milestones.

Use Git/GitHub at meaningful stable checkpoints, not after every small change.
When authorized, Codex may perform routine phase-end checks, staging, commit,
push to `origin/main`, and verification. Stop on failing tests, unexpected files,
secrets, conflicts, unexpected remote commits, authentication failure, or push
rejection. Never force-push, hard-reset, rewrite history destructively, or resolve
conflicts in a way that may discard work without explicit approval.

## Authoritative handover package

Review all of these before asking Codex to implement Phase 2:

```text
AEGIS_Phase2_Opening_Prompt.md
AEGIS_Current_Status_and_Handover.md
AEGIS_Project_Plan.md
Phase_1_Completion_Summary.md
AEGIS_Architecture_and_Security_Design.md
AEGIS_Decision_Log.md
```

For continuity, the current local repository is the first source of truth,
followed by verified GitHub `main`, the current-status handover, architecture and
security design, decision log, project plan, latest completion summary, and this
opening prompt. A ZIP is not the primary source of truth and is not required for
routine phase handover.

## What to do first

1. Review the complete handover package above and inspect the current repository.
2. Confirm the exact Phase 2 scope and inherited security invariants.
3. Confirm that Phase 3 or later functionality has not been introduced.
4. Re-run baseline verification and report the actual result.
5. Propose the first substantial but controlled password-authentication slice,
   including files, migrations/dependencies if justified, threat considerations,
   positive and negative tests, and explicit exclusions.
6. Only then prepare the first Codex implementation request. Do not begin Phase 2
   implementation merely by reading this prompt.
