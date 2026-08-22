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
4. **Phase 4 — Modern Security Interface**
   Build a clear, professional user interface over proven backend controls.
5. **Phase 5 — Bot Detection & Abuse Protection**
   Add layered defenses for automated and abusive requests.
6. **Phase 6 — Audit, Monitoring & Security Testing**
   Improve observability and systematically test the security controls.
7. **Phase 7 — Home Server Deployment & Public Access**
   Harden and deploy AEGIS after private review and recovery testing.
8. **Phase 8 — Final Review, Documentation & Portfolio Release**
   Complete verification and prepare the AEGIS v1 portfolio release.

## Current milestone

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
Records has not started. Authentication state grants no authorization.

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

1. Current local AEGIS repository.
2. GitHub `main` at verified checkpoints.
3. `AEGIS_Current_Status_and_Handover.md`.
4. `AEGIS_Architecture_and_Security_Design.md`.
5. `AEGIS_Decision_Log.md`.
6. `AEGIS_Project_Plan.md`.
7. Latest `Phase_X_Completion_Summary.md`.
8. Next-phase opening prompt.

A ZIP is not the primary source of truth.
