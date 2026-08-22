# AEGIS Decision Log

| Decision | Reason |
| --- | --- |
| Use `C:\Python\Projects\AEGIS` as the project root. | Keeps all work in the agreed location. |
| Use FastAPI with Python 3.11 or newer. | Provides a clear, typed foundation with a supported Python baseline. |
| Plan for PostgreSQL without implementing it in this milestone. | Avoids premature data architecture and dependencies. |
| Use pytest and FastAPI's HTTP test client. | Keeps API tests small, deterministic, and independent of external services. |
| Use `pyproject.toml` for package and dependency configuration. | Centralizes modern Python project configuration. |
| Use the project-local `.venv` and point `.vscode/settings.json` to its interpreter. | Keeps the AEGIS Python environment isolated and lets VS Code resolve it even when PowerShell does not visibly show `(.venv)`. |
| Load safe development settings from environment variables and optional `.env`. | Supports local configuration without hard-coded secrets. |
| Exclude `.env` from Git while retaining `.env.example`. | Prevents accidental versioning of local or secret values. |
| Develop and verify locally first. | Keeps the first milestone understandable and deployment-independent. |
| Implement security features phase by phase. | Allows each control to be designed and tested deliberately. |
| Keep the roadmap flexible. | Better learning or security approaches may emerge during the project. |
| Combine a small RBAC capability model with resource-specific ABAC. | Roles remain understandable while clearance, department, compartments, resource policy, and context enforce need-to-know. |
| Use Analyst, Senior Analyst, Supervisor, Security Auditor, and System Administrator as the initial roles. | Covers intelligence work, oversight, independent review, and administration without unnecessary role proliferation. |
| Separate system administration from classified intelligence access. | Enforces least privilege and separation of duties; administrative authority alone cannot read intelligence content. |
| Use four ordered classification levels and one current subject clearance for AEGIS v1. | `UNCLASSIFIED < CONFIDENTIAL < SECRET < TOP SECRET` is deterministic and sufficient for the learning goal without unnecessary real-world complexity. |
| Model each intelligence resource with one or more authorized departments. | Supports explicit cross-department access while ensuring same-department membership is never an automatic grant. |
| Require all listed resource compartments. | An all-required rule provides explicit, deterministic need-to-know behavior that is straightforward to test. |
| Centralize authorization conceptually and default to deny. | Every applicable policy must pass; missing, invalid, ambiguous, stale, or unevaluable policy data cannot produce access. |
| Treat the backend as the authorization boundary and all client state as untrusted. | UI hiding and client-supplied attributes cannot secure direct API access. |
| Normalize users, roles, departments, clearance levels, compartments, and record policy relationships. | Foreign keys and explicit join tables avoid duplicated free-text authorization attributes and make invalid state easier to reject. |
| Keep the v1 role-to-action capability mapping in versioned backend policy rather than a dynamically editable permissions table. | Prevents database content changes from silently redefining authorization and keeps the initial policy small and testable. |
| Treat missing `record_departments` rows as deny and do not support unrestricted-by-department records in AEGIS v1. | Prevents incomplete policy data from becoming an accidental allow. |
| Treat zero `record_compartments` rows as no compartment requirement and require all rows when present. | Gives zero, one, and multiple requirements explicit deterministic semantics while preserving all other checks. |
| Keep current security assignments in normalized tables and preserve changes through append-oriented audit events. | Provides useful v1 provenance without introducing a broad temporal-versioning subsystem. |
| Disable users and retire records/reference data instead of routinely hard-deleting them. | Preserves referential integrity, investigations, and audit context while avoiding dangerous cascades. |
| Store only hashes of reusable session tokens and encrypted recoverable MFA secrets. | A database leak should not expose immediately reusable tokens; TOTP secrets require encryption rather than password hashing. |
| Separate runtime, migration, backup, and administrative database privileges. | The application account can remain least-privileged and must not be a PostgreSQL superuser or schema owner. |
| Keep FastAPI authorization authoritative; consider PostgreSQL RLS only as defense in depth. | Central policy remains consistent across workflows while database controls can later reduce impact without becoming the sole security boundary. |
| Use a new ChatGPT chat for each substantial project phase. | Keeps conversation history manageable while the documented handover package preserves continuity. |
| Require a completion summary, updated current-status handover, and next-phase opening prompt at every phase boundary. | Makes phase transitions repeatable without requiring the user to restate the workflow. |
| Use the local repository and verified GitHub `main` checkpoints as the primary project record. | Git provides synchronized version history; living documents preserve design and handover context. |
| Do not create a full project ZIP for routine phase handover. | ZIPs duplicate Git checkpoints and are reserved for a specific backup, transfer, recovery, direct-access, major-release, or user-requested need. |
| Allow Codex to perform routine phase-end Git/GitHub checkpoint work when authorized. | Saves interactive time while requiring Codex to stop on failed checks, unexpected changes, secrets, conflicts, remote divergence, authentication failures, or rejected pushes. |
| Require explicit approval for force pushes, hard resets, destructive history rewriting, or conflict resolution that could discard work. | Prevents routine automation from damaging recoverable project history or user work. |
| Use SQLAlchemy 2.x typed models and reviewed Alembic migrations for authentication persistence. | Implements the approved PostgreSQL architecture without unmanaged schema mutation. |
| Implement the `users` table incrementally and defer department and clearance foreign keys. | Password authentication does not require Phase 3 authorization reference data; later migrations can extend the same model without replacing it. |
| Canonicalize usernames by trimming, restricting to a documented ASCII syntax, and lowercasing. | Prevents case-only duplicates and avoids surprising Unicode equivalence rules for login identity. |
| Canonicalize optional email by trimming and ASCII-lowercasing the complete address. | Provides one deterministic identity comparison rule and database uniqueness when email is present. |
| Use Argon2id with versioned parameters behind a dedicated password service. | Provides salted, memory-hard password storage, controlled verification failure, and automatic detection of verifiers that need stronger parameters. |
| Require new passwords to contain at least eight Unicode characters and no more than 1024 UTF-8 bytes, without composition rules. | Establishes a small creation-policy baseline, preserves passphrases and Unicode, and bounds unreasonable password-hashing input. Existing valid legacy verifiers remain verifiable even when their password is shorter than the current creation minimum. |
| Treat an account as usable for password authentication only when active and not disabled. | Fails closed at the service boundary before any future HTTP login or session behavior exists. |
| Use SQLite only for isolated deterministic persistence and migration tests. | Tests do not require provisioned infrastructure while PostgreSQL remains the configured application and deployment target. |
