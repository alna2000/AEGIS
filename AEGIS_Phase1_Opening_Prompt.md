# AEGIS — Phase 1 Opening Prompt

We are starting a new cybersecurity learning project:

# AEGIS — Classified Intelligence Access System

AEGIS is a **fictional cybersecurity training environment**. All users, intelligence records, organizations, classifications, and events are synthetic.

The purpose of the project is to learn and demonstrate secure application design, especially:

- Authentication
- Authorization
- RBAC
- ABAC
- Clearance/classification controls
- Need-to-know
- Least privilege
- Multi-factor authentication
- TOTP/OTP concepts
- Secure sessions
- PostgreSQL security
- Audit logging
- Bot/abuse protection
- Security testing
- Secure deployment
- Later: secure AI/RAG integration

## Important Working Method

We work in **phases**.

Each phase normally gets a **new ChatGPT chat** so the conversation does not become too large.

Each phase can contain several substantial parts, but do **not** divide the work into tiny parts that make the project unnecessarily slow.

For every substantial implementation part:

1. This chat plans the work.
2. This chat prepares a clear prompt/instruction for **Codex**.
3. **Codex performs code implementation, file creation, bulk editing, and test implementation.**
4. This chat reviews Codex's changes.
5. We verify the implementation.
6. Documentation and current project status are updated.
7. Then we move to the next substantial part.

Do not manually perform large code/file changes in this chat when Codex should do them.

## Verification Style

When asking me to run PowerShell verification commands:

- Give me **one PowerShell command** or one small related block at a time.
- Tell me the **expected result**.
- Wait for my actual output.
- Review it before giving the next command.

Do not give me a long sequence of commands at once unless they must be executed together.

## Git / GitHub

Do **not** commit/push to GitHub after every small part.

GitHub updates should happen at meaningful checkpoints, such as:

- Phase completion
- Major milestone completion
- Stable tested checkpoint
- Before an important risky architectural change
- Phase handover

The goal is to avoid wasting time on Git operations after every small implementation.

## Documentation

Maintain these main project documents from the beginning:

```text
AEGIS_Project_Plan.md
AEGIS_Architecture_and_Security_Design.md
AEGIS_Current_Status_and_Handover.md
AEGIS_Decision_Log.md
```

`AEGIS_Current_Status_and_Handover.md` is especially important.

It must always tell the next chat:

- What AEGIS is
- Current phase and part
- What is completed
- What is verified
- Important files/components changed
- Important security/architecture decisions
- Latest test result
- Known issues
- What remains
- What the next chat should do first
- Latest Git checkpoint
- Deployment status

At meaningful phase completions, we may also create:

```text
Phase_1_Completion_Summary.md
Phase_2_Completion_Summary.md
...
```

## Current Technology Direction

Initial direction:

```text
Backend:       FastAPI / Python
Database:      PostgreSQL
Testing:       pytest
Frontend:      Modern security-focused web interface
Development:   Local Windows PC
Deployment:    Ubuntu VM on Proxmox later
Web Server:    Nginx when deployed
Public Access: Cloudflare Tunnel later
Git:           Git / GitHub
```

We will build and test AEGIS **locally first**.

Later it will be moved to our home server:

```text
Development PC
      ↓
Build + test locally
      ↓
Proxmox
      ↓
AEGIS Ubuntu VM
      ↓
PostgreSQL VM
      ↓
Private security review
      ↓
Cloudflare Tunnel
      ↓
Public AEGIS
```

Only the AEGIS HTTPS website should eventually be public.

The following remain private:

```text
Proxmox
PostgreSQL
SSH
Wazuh
OPNsense management
RDP
Active Directory
SMB
Cyber range
```

## Security Testing Philosophy

Security testing is continuous but practical.

### Per feature

Use fast positive and negative tests.

Examples:

```text
SECRET user → authorized SECRET record → ALLOW
SECRET user → TOP SECRET record → DENY
TOP SECRET user without NIGHTFALL → NIGHTFALL record → DENY
Changed record ID → unauthorized record → DENY
```

### Per phase/milestone

Perform deeper abuse/security checks.

### Before public exposure

Perform a dedicated pre-public security review.

Do not enable the public Cloudflare Tunnel while authentication/authorization is unfinished.

---

# Current Phase: Phase 1 — Foundation & Architecture

Phase 1 contains three substantial parts.

## Part 1 — Project Foundation

Create:

- Project/repository structure
- Python/FastAPI environment
- Dependency management
- Configuration structure
- `.env` strategy
- Development settings
- Initial tests
- Initial README
- Initial documentation files

The first application only needs to run locally and prove the foundation works.

Example:

```text
AEGIS
Status: Development
API: Available
```

## Part 2 — Security Architecture

Define and document:

- Users
- Roles
- Departments
- Clearance levels
- Classification levels
- Need-to-know compartments
- Actions such as READ / SEARCH / UPDATE
- Access-control decision model
- Threat model
- Trust boundaries
- Public/private services
- Security assumptions

Core concept:

```text
Clearance sufficient
AND
Department permitted
AND
Need-to-know satisfied
AND
Action permitted
        ↓
ACCESS
```

Important:

```text
TOP SECRET clearance ≠ access to every TOP SECRET record
```

## Part 3 — Database Architecture

Design PostgreSQL schema for:

- Users
- Roles
- Departments
- Clearance levels
- Intelligence records
- Compartments
- Assignments
- Sessions
- MFA
- Audit events

Do not rush into implementing later-phase features during Phase 1.

---

# Future Phases — For Context Only

```text
Phase 1 — Foundation & Architecture
Phase 2 — Authentication & 2FA
Phase 3 — Authorization & Classified Records
Phase 4 — Modern Security Interface
Phase 5 — Bot Detection & Abuse Protection
Phase 6 — Audit, Monitoring & Security Testing
Phase 7 — Home Server Deployment & Public Access
Phase 8 — Final Review, Documentation & Portfolio Release
```

Later extensions such as Wazuh, OPNsense, VLANs, Active Directory, Kali/cyber range, AI/RAG, and WebAuthn are **not required for AEGIS v1**.

---

# What I Want You To Do First

Before asking Codex to implement anything:

1. Review this plan.
2. Confirm the scope of **Phase 1 Part 1 — Project Foundation**.
3. Check that we are not accidentally introducing Phase 2+ features early.
4. Propose the exact files/folders and foundation components that Part 1 should create.
5. Then prepare the **first Codex implementation prompt**.

Do not start with a huge implementation request.

The first Codex task should be a substantial but controlled foundation milestone that we can review and verify before continuing.

Also, keep explanations educational and clear because this is a learning project, not only a coding exercise.
