# AEGIS Architecture and Security Design

## Document status

```text
Phase: 1 - Foundation & Architecture
Part: 3 - Database Architecture
DESIGNED: Yes
IMPLEMENTED: No
```

This document defines the target security and database architecture for AEGIS v1.
It is a design contract for later implementation and testing, not evidence that a
control already exists. AEGIS contains synthetic identities, organizations,
intelligence, classifications, compartments, and events only.

## Security model

AEGIS will combine role-based access control (RBAC) with attribute-based access
control (ABAC). A role grants the capability to attempt an action. Attributes and
resource policy determine whether that action is allowed on a particular resource.

```text
Authenticated subject
AND usable account and session
AND role permits the requested action
AND subject clearance >= resource classification
AND resource department policy permits the subject's department
AND subject satisfies ALL resource compartments
AND additional resource and context policy permits the request
    -> ALLOW

Otherwise
    -> DENY
```

Clearance is necessary for classified content, but never sufficient by itself.
In particular, TOP SECRET clearance does not give unrestricted access to every
TOP SECRET resource.

## Terminology

- **Subject:** the authenticated actor requesting an action, such as a user,
  analyst, auditor, or administrator. Authorization uses authoritative subject
  attributes loaded and validated by the backend.
- **Resource:** the protected object or collection being acted upon. Future
  examples include an intelligence record, search result, user account, audit
  event, or administrative configuration.
- **Action:** the operation requested by a subject. The initial vocabulary is
  `READ`, `SEARCH`, `CREATE`, `UPDATE`, `DELETE`, `EXPORT`, `ADMINISTER`, and
  `AUDIT`. These actions may be refined when endpoints and workflows are designed,
  but new actions should represent distinct security capabilities rather than
  implementation details.
- **Context:** validated facts about the request that are not intrinsic to the
  subject or resource, such as session state or an approved workflow constraint.
- **Policy:** the complete set of rules evaluated for a subject, action, resource,
  and context.

## Authentication and authorization

Authentication answers **who are you?** Future authentication mechanisms include
username/password verification, TOTP MFA, and session validation.

Authorization answers **what are you allowed to do?** It evaluates roles and
attributes for every protected action. Authentication and authorization remain
separate: a successfully authenticated subject may still receive `DENY` for a
resource. Authentication, MFA, and sessions are not implemented in this part.

## Roles and capabilities

The starting role set is deliberately small. Capability descriptions are policy
inputs, not unconditional grants.

| Role | Responsibility | Typical capabilities | Not automatic |
| --- | --- | --- | --- |
| Analyst | Perform routine intelligence work. | `READ`, `SEARCH`, `CREATE`, and limited `UPDATE` within approved workflows. | `DELETE`, `EXPORT`, `ADMINISTER`, `AUDIT`, or access outside ABAC policy. |
| Senior Analyst | Perform advanced analysis and approved dissemination. | Analyst capabilities plus policy-controlled `EXPORT`. | Administration, audit administration, deletion, or an ABAC bypass. |
| Supervisor | Oversee intelligence workflows and controlled record lifecycle actions. | Analyst capabilities plus policy-controlled `DELETE` and `EXPORT`. | Account administration, unrestricted audit access, or an ABAC bypass. |
| Security Auditor | Review security and audit evidence independently. | `AUDIT` on authorized audit/security resources. | Intelligence-content access, record mutation, or account administration solely because of this role. |
| System Administrator | Operate accounts and approved system configuration. | `ADMINISTER` for authorized administrative resources and workflows. | Classified intelligence access, audit independence, or the ability to grant itself intelligence access. |

Subjects may hold one or more explicitly approved roles. The role check passes
when at least one active role permits the requested action for the resource type;
combining roles does not remove or weaken any ABAC requirement.

Every role remains subject to the policy applicable to the resource type and
action. For classified intelligence, role never bypasses classification,
department, compartment, or contextual restrictions. A person who legitimately
needs both administrative and intelligence duties requires separately approved
assignments; the system must not infer one from the other.

## Departments

AEGIS v1 uses four synthetic operational departments:

- Cyber Intelligence
- Counterintelligence
- Strategic Analysis
- Operations

A subject has one current department for AEGIS v1. An intelligence resource has
an explicit non-empty set of authorized departments, allowing either one
department or approved cross-department access without duplicating resources.
The subject's department must be a member of that set. Same-department membership
does not grant access; all other checks still apply. Missing or invalid department
policy is a denial.

Administrative and audit resources use policies appropriate to their resource
types rather than pretending that system administration is an intelligence
department.

## Clearance and classification

Each subject has one current AEGIS clearance. Each classified resource has one
classification. The ordered hierarchy is:

```text
UNCLASSIFIED < CONFIDENTIAL < SECRET < TOP SECRET
```

The clearance check passes only when the subject's clearance is equal to or
higher than the resource classification:

```text
SECRET subject -> CONFIDENTIAL resource = PASS
SECRET subject -> SECRET resource       = PASS
SECRET subject -> TOP SECRET resource   = FAIL
```

A passing clearance check only permits policy evaluation to continue. It does
not grant access. Unknown, missing, or malformed clearance/classification values
cause denial.

## Need-to-know compartments

The initial fictional compartments are `NIGHTFALL`, `ORION`, and `SENTINEL`.
Compartment membership is explicitly assigned and is not implied by clearance,
role, or department.

A resource may require no compartment or a set of compartments. For AEGIS v1,
the subject must hold **all** compartments required by the resource. This rule is
simple, deterministic, and testable. An empty requirement passes; any missing
required membership denies access.

```text
Subject:  TOP SECRET, Cyber Intelligence, no NIGHTFALL
Resource: TOP SECRET, Cyber Intelligence, requires NIGHTFALL
Result:   DENY - missing compartment
```

## Central authorization decision

Future code should expose one central policy decision point conceptually similar
to, but not yet implemented as:

```python
authorize(subject, action, resource, context)
```

The decision flow is:

1. Require an authenticated subject and validated request context.
2. Require a usable account and session.
3. Require the subject's role to permit the action for the resource type.
4. For classified content, require sufficient clearance.
5. Require the department policy to permit the subject's department.
6. Require all resource compartments to be held by the subject.
7. Require every additional validated resource or context restriction to pass.
8. Return one explicit `ALLOW` or `DENY` decision.
9. Record the security-relevant decision in the future audit system.

The sequence is primarily conceptual and supports clear denial reasoning and
efficient evaluation. It must not create a bypass: every applicable check is
mandatory regardless of evaluation order. Policy evaluation is **default deny**.
Missing, invalid, ambiguous, stale, or unevaluable policy information results in
`DENY`. Exceptions and backend failures must not turn into an allow decision.

Collection operations such as `SEARCH` must authorize both the action and the
resources represented in results. Untrusted record identifiers select candidates;
they never establish authorization.

## Denial and information exposure

Resource visibility is itself an authorization decision. Future policy may use:

- **Hidden:** an unauthorized subject cannot distinguish a resource from one that
  does not exist. This is the preferred default for classified intelligence.
- **Existence visible, content restricted:** used only when a workflow has an
  explicit need to reveal existence.
- **Partially redacted:** a later Phase 3 policy that must authorize each exposed
  field or representation rather than relying on UI masking.

APIs, searches, and logs exposed to users must avoid leaking protected existence
or content through distinct error detail, result counts, identifiers, metadata,
verbose exceptions, or response timing where practical. External responses may
be deliberately generic while internal audit records retain an authorized denial
reason. Exact response and redaction behavior belongs to Phase 3.

## Security principles

- **Least privilege:** grant only the minimum actions and attributes needed for
  current duties.
- **Separation of duties:** administration, intelligence work, and independent
  auditing are distinct capabilities.
- **Need-to-know:** classification eligibility is narrowed by explicit department,
  compartment, action, resource, and context policy.
- **Default deny:** access is denied unless every applicable requirement passes.
- **Explicit authorization:** protected operations require a backend decision;
  absence of a denial is not an allow.
- **Backend enforcement:** the frontend is not a security boundary. Hidden buttons
  and filtered UI views are usability measures only.

Browser actions and direct API requests must receive the same backend checks.
No client claim, frontend state, hidden field, or URL identifier is authoritative.

## Administrative privilege

System administration is separate from intelligence-content authorization. A
System Administrator may manage users, disable accounts, assign approved roles or
attributes through controlled workflows, and manage operational configuration.
That role does not automatically permit `READ`, `SEARCH`, or `EXPORT` of classified
intelligence.

Administrative workflows must eventually validate who may assign each role and
attribute, prevent self-escalation, enforce separation of duties for sensitive
changes where appropriate, and audit changes. Security Auditors review evidence
but do not gain mutation or intelligence access from the auditor role. These are
design requirements, not implemented controls.

## Threat model

### Assets and actors

Important assets are user identities, credentials, sessions, MFA secrets,
authorization attributes, intelligence records, audit logs, administrative
functions, the database, and application configuration and secrets.

Relevant threat actors include unauthenticated external attackers, authenticated
low-privilege users, malicious or curious insiders, compromised accounts,
automated bots, and administrators who misuse or exceed their authority.

### Threats and planned defense areas

| Threat | Planned defense area |
| --- | --- |
| Credential attacks, authentication bypass, MFA bypass, session theft or misuse | Phase 2: password handling, MFA, secure session lifecycle, and authentication tests. |
| Broken access control, IDOR/BOLA, horizontal or vertical access, privilege escalation | Phase 3: centralized backend authorization, object-level checks, default deny, and negative tests. |
| Parameter tampering and direct API abuse | Phases 3 and 5: trusted server-side attributes, input validation, authorization on every path, and abuse controls. |
| Information leakage through errors, search, identifiers, metadata, or timing | Phases 3 and 6: visibility policy, generic external failures, security tests, and monitoring. |
| SQL injection and unsafe data access | Phase 1 Part 3 and Phase 3: parameterized data access, constrained models, validation, and tests. |
| Audit-log manipulation or missing evidence | Phase 6: restricted append-oriented audit handling, integrity controls, monitoring, and review. |
| Brute force and automated abuse | Phases 2 and 5: authentication defenses, rate controls, bot/abuse detection, and alerting. |
| Misconfiguration and secret exposure | Phases 6 and 7: validated configuration, secret management, least-privilege deployment, and review. |
| Administrator misuse | Phases 3 and 6: separated privileges, controlled attribute assignment, audit trails, and monitoring. |

No defense in this table is claimed to be implemented merely because it is
planned.

## Trust boundaries

The future request path is conceptually:

```text
Untrusted user browser
        |
Public HTTPS boundary
        |
Nginx / Cloudflare (future)
        |
FastAPI application and authorization boundary
        |
Private database connection
        |
PostgreSQL (future private infrastructure)
```

The browser, frontend state, request input, identifiers, and client-supplied
attributes are untrusted. Authorization attributes become trusted inputs only
after the backend loads them from an authoritative source and validates their
type, value, status, and relationship. Database contents are not assumed valid
merely because they are stored; security-sensitive records require integrity and
validation controls.

The database must not be directly reachable from the Internet. Management
interfaces remain private. TLS termination, proxy headers, service identity, and
database credentials will require explicit trust configuration in their later
phases; this document does not implement deployment.

## Public and private services

The only future public service is the AEGIS HTTPS application. PostgreSQL,
Proxmox, SSH, Wazuh, OPNsense management, RDP, Active Directory, SMB, and the cyber
range remain private. Cloudflare, Nginx, Proxmox, and public exposure are deferred
to Phase 7.

## Security assumptions

These assumptions constrain the design; they are not implemented controls:

- AEGIS v1 contains synthetic data only and no real classified information.
- The backend is authoritative for authentication and authorization decisions.
- PostgreSQL will reside on private infrastructure when introduced.
- Secrets are not committed to source control.
- Users cannot select or modify their own roles, clearance, department, or
  compartments.
- Authorization attributes are changed only through authorized administrative
  workflows.
- Sensitive operations and security-relevant decisions should be auditable.
- Public exposure occurs only after security review and deployment hardening.

## Example authorization decisions

Example subjects:

- **Sarah:** Analyst, SECRET, Cyber Intelligence, `NIGHTFALL`.
- **Omar:** Senior Analyst, TOP SECRET, Strategic Analysis, `ORION`.
- **Lina:** Supervisor, TOP SECRET, Cyber Intelligence, `NIGHTFALL` and `ORION`.
- **Noah:** System Administrator, TOP SECRET, Cyber Intelligence, `NIGHTFALL`.

All accounts and sessions in this example are valid. Resources not listing a
compartment have no compartment requirement.

| Subject and action | Resource policy | Decision | Reason |
| --- | --- | --- | --- |
| Sarah `READ` | INT-0001: CONFIDENTIAL; Cyber Intelligence | ALLOW | Role, clearance, department, and compartment checks pass. |
| Sarah `READ` | INT-0002: TOP SECRET; Cyber Intelligence | DENY | Insufficient clearance. |
| Omar `READ` | INT-0003: SECRET; Cyber Intelligence | DENY | Strategic Analysis is not an authorized department. |
| Omar `READ` | INT-0004: TOP SECRET; Strategic Analysis; requires `NIGHTFALL` | DENY | Omar lacks `NIGHTFALL`, despite TOP SECRET clearance. |
| Sarah `DELETE` | INT-0005: SECRET; Cyber Intelligence; requires `NIGHTFALL` | DENY | Analyst role does not permit `DELETE`. |
| Lina `READ` | INT-0006: TOP SECRET; Cyber Intelligence and Operations; requires `NIGHTFALL` and `ORION` | ALLOW | Every applicable condition passes, including all compartments. |
| Sarah `EXPORT` | INT-0007: TOP SECRET; Strategic Analysis; requires `ORION` | DENY | Role/action, clearance, department, and compartment checks fail. |
| Noah `READ` | INT-0003: SECRET; Cyber Intelligence | DENY | System Administrator does not receive intelligence `READ` capability from the administrative role. |
| Noah `ADMINISTER` | Active user account within an approved admin workflow | ALLOW | Administrative role and resource policy permit the action; this grants no intelligence access. |

## Security invariants

1. Default deny.
2. Backend authorization cannot be bypassed by the frontend.
3. Authentication success does not imply resource authorization.
4. No role automatically bypasses classification or other ABAC controls.
5. Clearance alone never grants access.
6. All required compartments must be explicitly held.
7. Same-department membership alone never grants access.
8. Administrative privilege does not automatically grant intelligence access.
9. Untrusted identifiers and client-supplied attributes cannot determine access.
10. Direct API requests receive the same checks as browser/UI requests.
11. Missing, invalid, ambiguous, stale, or unevaluable policy data results in
    denial.
12. Security-relevant authorization decisions should be auditable without leaking
    protected information to unauthorized users.

These invariants are intended to become negative and positive tests in later
phases.

## Phase 1 Part 2 deferred implementation

This part does not implement authentication, password hashing, login endpoints,
MFA/TOTP, sessions, authorization code, RBAC middleware, ABAC code, database
tables, SQLAlchemy, PostgreSQL, Alembic, intelligence records, frontend, rate
limiting, bot detection, audit persistence, Nginx, Cloudflare, Docker, Proxmox,
AI, or RAG.

## Phase 1 Part 3 - Database architecture

### Database design principles

The future PostgreSQL schema will reinforce, but not replace, the centralized
backend authorization policy. Its design follows these rules:

- Apply least privilege to application users, administrators, and database roles.
- Normalize security-relevant values and relationships.
- Use identifiers, foreign keys, uniqueness, nullability, and check constraints
  instead of repeating security-critical names as arbitrary text.
- Preserve referential integrity and use restrictive deletion behavior by default.
- Avoid duplicating authoritative role, clearance, department, or compartment
  values in unrelated rows.
- Treat missing or invalid policy relationships as denial, never permission.
- Keep audit events append-oriented and difficult for ordinary application paths
  to alter.
- Validate database data in the application even when schema constraints exist.

The backend remains authoritative for access decisions. Database constraints are
defense against invalid state, not a complete authorization engine.

### Identifier direction

Core entities use generated internal primary keys, with PostgreSQL UUIDs as the
preferred implementation direction. Intelligence records also have a unique,
stable human-facing `record_code`, such as `INT-00482`. Internal keys support
relationships without coupling them to display formats; record codes support
human workflows and may have separate generation rules.

Neither UUID unpredictability nor knowledge of a record code is an access control.
Knowing or changing any identifier must never grant access. Every resolved
resource still requires centralized authorization.

### Core entity model

Field types and exact lengths will be finalized with migrations, but the initial
logical schema is:

#### `users`

| Field | Purpose and constraints |
| --- | --- |
| `id` | Internal primary key. |
| `username` | Required canonical login name; unique using defined case-normalization rules. |
| `display_name` | Required synthetic display name; not an authorization attribute. |
| `email` | Optional for v1; unique when present after canonical normalization. |
| `password_hash` | Future password verifier; nullable until authentication exists and never plaintext. |
| `is_active` | Required account usability flag, default false for safely provisioned accounts. |
| `department_id` | Required foreign key to one primary `departments` row. |
| `clearance_level_id` | Required foreign key to one `clearance_levels` row. |
| `created_at`, `updated_at` | Required timezone-aware lifecycle timestamps. |
| `disabled_at` | Nullable timezone-aware timestamp consistent with account state. |

Users have one primary department and one current clearance in AEGIS v1. Multiple
departments are a possible future extension, not part of this schema. Role and
compartment values are not stored as text or arrays on `users`.

#### `roles` and `user_roles`

`roles` contains `id`, unique `name`, optional non-authoritative `description`, and
an active/reference-data flag if lifecycle management requires it. Controlled
initial names are Analyst, Senior Analyst, Supervisor, Security Auditor, and
System Administrator.

`user_roles` contains `user_id`, `role_id`, `assigned_at`, and `assigned_by_user_id`.
Its composite primary key or unique constraint on `(user_id, role_id)` prevents
duplicate current assignments. Removal of an assignment is accompanied by an
audit event; AEGIS v1 does not add a full temporal role-history table. The assigner
foreign key may be null only for a documented bootstrap/system operation.

AEGIS v1 does not add a dynamically editable `permissions` or `role_permissions`
matrix. The controlled role-to-action capability mapping remains part of the
versioned, centrally tested backend policy. A data-driven permission model may be
considered later only with equivalent change control, auditability, and tests.

Role membership supplies action capability only. It never bypasses clearance,
department, compartment, resource, or context policy.

#### `departments`

`departments` contains `id`, unique `name`, optional `description`, and an active
flag if reference values need retirement. Initial controlled values are Cyber
Intelligence, Counterintelligence, Strategic Analysis, and Operations.

Each user references one department. Each intelligence record is related to one
or more authorized departments through `record_departments`. Department equality
alone never grants access.

#### `clearance_levels`

`clearance_levels` contains `id`, unique `name`, and unique integer `rank`. Initial
controlled rows are:

| Name | Rank |
| --- | ---: |
| `UNCLASSIFIED` | 10 |
| `CONFIDENTIAL` | 20 |
| `SECRET` | 30 |
| `TOP SECRET` | 40 |

Positive, spaced ranks keep comparison simple while leaving controlled room for a
future level if genuinely required. Authorization compares ranks, never names:
`user_clearance.rank >= resource_classification.rank`. Every user and classified
record has exactly one valid clearance/classification foreign key.

#### `compartments`, `user_compartments`, and `record_compartments`

`compartments` contains `id`, unique `name`, optional `description`, and an active
flag if lifecycle management requires it. Initial controlled values are
`NIGHTFALL`, `ORION`, and `SENTINEL`.

`user_compartments` contains `user_id`, `compartment_id`, `assigned_at`, and
`assigned_by_user_id`. A composite primary key or unique constraint on
`(user_id, compartment_id)` prevents duplicate current membership. Removal is
recorded in `audit_events` rather than a separate temporal subsystem.

`record_compartments` contains `record_id` and `compartment_id`, with uniqueness
on the pair. Zero rows explicitly means the record has no compartment requirement.
One or more rows means the subject must hold **all** listed compartments. Clearance
never implies compartment membership.

#### `intelligence_records`

| Field | Purpose and constraints |
| --- | --- |
| `id` | Internal primary key. |
| `record_code` | Required unique human-facing code such as `INT-00482`. |
| `title` | Required concise subject/title. |
| `summary` | Optional or required according to the later content workflow. |
| `content` | Future synthetic intelligence body; exact structure deferred. |
| `classification_level_id` | Required foreign key to `clearance_levels`. |
| `created_by_user_id` | Required creator foreign key; ownership metadata, not an authorization grant. |
| `status` | Required constrained lifecycle state such as draft, active, or retired. |
| `created_at`, `updated_at` | Required timezone-aware lifecycle timestamps. |
| `retired_at` | Nullable timestamp for controlled soft deletion/retirement. |

The content model remains intentionally small. Classification, authorized
departments, required compartments, and creator metadata are explicit security
relationships. A creator does not automatically retain access if later policy
checks fail.

#### `record_departments`

`record_departments` contains `record_id` and `department_id`, with a composite
primary key or unique constraint on the pair.

AEGIS v1 does not support a department-unrestricted intelligence record. An active
or published record must have at least one authorized department. Zero rows means
the department policy is incomplete and access is denied; it never means all
departments. Draft creation may temporarily lack a relationship inside a controlled
workflow, but the record remains inaccessible until policy validation succeeds.
Later implementation must enforce this publication invariant transactionally in
the application and, where practical, with a deferred database constraint or
trigger reviewed for correctness.

#### `sessions`

| Field | Purpose and constraints |
| --- | --- |
| `id` | Internal session primary key and non-secret lookup identifier. |
| `user_id` | Required foreign key to the account. |
| `token_hash` | Required unique hash of a high-entropy reusable session token; never the raw token. |
| `created_at`, `expires_at` | Required timezone-aware validity bounds. |
| `last_seen_at` | Nullable operational timestamp updated under a defined policy. |
| `revoked_at` | Nullable revocation timestamp. |
| `source_ip`, `user_agent` | Optional, minimized investigation metadata with retention limits. |

A session is usable only when its account is active, it has not expired, and
`revoked_at` is null. Disabling a user must revoke active sessions in the same
authorized workflow. Raw reusable tokens are shown once to the client and are not
stored. Phase 2 Part 3 implements token generation, hashing, cookie handling,
replacement, expiration, and revocation as detailed in its implementation status
below.

#### `mfa_credentials`

`mfa_credentials` contains `id`, `user_id`, constrained `method_type`,
`encrypted_secret`, `encryption_key_id`, `enabled`, `created_at`, `last_used_at`,
optional `disabled_at`, and optional `last_accepted_counter`. Phase 2 Part 4
implements a partial unique index allowing only one non-disabled TOTP credential
per user. Disabled rows remain as lifecycle history and do not prevent a later
fresh pending enrollment.

TOTP secrets are recoverable operational secrets and therefore require encryption,
not password hashing. Password verifiers require a password-hashing algorithm and
are not decryptable. TOTP secrets must never be plaintext in the database, logs,
or source control. Part 4 uses Fernet authenticated encryption with an independent
environment-configured URL-safe Base64 32-byte key. Only a non-secret key ID and
randomized ciphertext are persisted. Missing, invalid, mismatched, modified, or
wrong-key material fails closed.

#### `audit_events`

| Field | Purpose and constraints |
| --- | --- |
| `id` | Internal primary key. |
| `event_type` | Required controlled event code. |
| `actor_user_id` | Nullable foreign key for authenticated actors; null supports anonymous/system events. |
| `target_type`, `target_id` | Optional controlled target reference suitable for entities with different lifecycles. |
| `action`, `outcome`, `reason_code` | Controlled, non-secret decision context. |
| `request_id` | Correlation identifier indexed for investigation. |
| `source_ip`, `user_agent` | Minimized request metadata subject to retention policy. |
| `metadata` | Optional allowlisted structured metadata; never an unrestricted dump. |
| `created_at` | Required immutable event timestamp. |

Controlled authentication event types now include `PASSWORD_AUTH_SUCCESS`,
`PASSWORD_AUTH_FAILURE`, `TOTP_VERIFICATION_SUCCESS`, and
`TOTP_VERIFICATION_FAILURE`. Planned later event types include `ACCESS_ALLOWED`,
`ACCESS_DENIED`, `ROLE_CHANGED`,
`CLEARANCE_CHANGED`, `COMPARTMENT_CHANGED`, `ACCOUNT_DISABLED`, `ADMIN_ACTION`,
and `BOT_SUSPECTED`. The exact controlled vocabulary will be defined with the
owning feature.

Audit paths must never record passwords, session tokens, TOTP secrets, encryption
keys, or unnecessary intelligence content. Events are append-oriented: ordinary
application roles receive insert capability through tightly controlled paths, not
update or delete capability. Audit readers are separately authorized. Later
retention, archival, integrity monitoring, and Wazuh/SIEM export belong to Phase 6.

### Security-sensitive changes

For AEGIS v1, `users` stores current department, clearance, and account state;
`user_roles` and `user_compartments` store current assignments. Assignment rows
include `assigned_at` and `assigned_by_user_id` because provenance materially
improves administrative review. Authorized removal deletes the current join row
and writes an audit event containing controlled identifiers and the change reason.

Department, clearance, role, compartment, and account-status changes must be
atomic with their audit event; if the audit write fails, the security-sensitive
change rolls back. This provides useful history without building a general
temporal/versioning system. Future regulatory or forensic needs may justify
immutable assignment-history tables, but they are not part of AEGIS v1
architecture.

### Deletion and lifecycle strategy

Broad cascading deletion is inappropriate for security-sensitive entities.

| Entity | Recommended behavior |
| --- | --- |
| Users | Disable/soft deactivate; preserve identity and audit references. Revoke sessions. Hard deletion is exceptional and retention-policy controlled. |
| Roles | Retire controlled roles rather than delete referenced rows. Prevent deletion while assignments/history depend on them. |
| Departments | Retire rather than delete while referenced by users, records, or audit context. |
| Clearance levels | Controlled immutable reference data in normal operation; restrict deletion. |
| Compartments | Retire rather than delete while assignments or record requirements exist. |
| Intelligence records | Retire/soft delete using status and timestamp; preserve auditability. Hard deletion requires a separate approved retention process. |
| Sessions | Revoke immediately when needed; purge expired/revoked rows later under a retention job without deleting the user. |
| MFA credentials | Disable, then remove encrypted material only under an audited credential lifecycle policy. |
| Audit events | No ordinary update or delete; retain and archive under a dedicated policy and privileged maintenance path. |

Join rows may use targeted cascade deletion only when the parent is legitimately
and safely hard-deleted under the exceptional policies above. Reference entities,
users, records, and audit events default to `RESTRICT` or equivalent deliberate
handling. Audit preservation must not depend on a cascading relationship.

### Constraints and indexes

Required uniqueness and integrity constraints include:

- `users.username` unique under canonical normalization.
- `users.email` unique when non-null under canonical normalization.
- Unique names for `roles`, `departments`, `clearance_levels`, and `compartments`.
- Unique positive `clearance_levels.rank` values.
- Unique `intelligence_records.record_code`.
- Unique current pairs in `user_roles`, `user_compartments`,
  `record_departments`, and `record_compartments`.
- Foreign keys for every normalized relationship, explicit nullability, and check
  constraints for controlled statuses, outcomes, timestamps, and rank validity.
- Temporal checks such as `expires_at > created_at` and state consistency checks
  where PostgreSQL can enforce them without obscuring the model.

Useful initial indexes support `user_roles(user_id)`,
`user_compartments(user_id)`, `record_departments(record_id)`,
`record_compartments(record_id)`, active sessions by user and expiry,
`audit_events(actor_user_id, created_at)`,
`audit_events(event_type, created_at)`, and `audit_events(request_id)`.
Primary-key and unique constraints may already provide some indexes; migrations
should avoid redundant indexes. Additional indexes require measured query need.

### Conceptual relationships

```text
departments 1 ----- many users many ----- many roles
        |                 |                 via user_roles
        |                 |
        |                 +----- many sessions
        |                 +----- many mfa_credentials
        |                 +----- many compartments via user_compartments
        |                 +----- many created intelligence_records
        |                 +----- many audit_events as actor
        |
        +----- many intelligence_records via record_departments

clearance_levels 1 ----- many users
clearance_levels 1 ----- many intelligence_records as classification

intelligence_records many ----- many departments via record_departments
intelligence_records many ----- many compartments via record_compartments
```

Audit targets are intentionally represented by controlled `target_type` and
`target_id` values rather than foreign keys to every possible table. This keeps an
event append-oriented when targets have different retention lifecycles. The
application validates the target vocabulary and never treats an audit target ID
as authorization evidence.

### Authorization data flow

To evaluate `authorize(subject, action, resource, context)`, a repository/service
boundary will load validated current facts:

```text
Subject: active account, active roles, clearance rank, primary department,
         explicit compartments, usable session

Resource: lifecycle status, classification rank, authorized departments,
          required compartments, creator and other explicit restrictions
```

The application then evaluates the centralized policy defined in Part 2. Query
helpers may efficiently fetch policy facts or prefilter candidates, but security
logic must not be copied into arbitrary endpoint-specific SQL. Search and list
queries must avoid returning unauthorized rows and must still preserve central
policy semantics. Transaction boundaries must prevent decisions based on a
partially updated security state.

### Database trust boundary

```text
Database data is trusted only after schema constraints,
application validation, and authorized administrative workflows.
```

PostgreSQL storage does not make a value inherently safe. Application-supplied
IDs, query parameters, stored structured metadata, and policy relationships remain
untrusted until resolved, validated, and authorized. Parameterized database access
is required later; string-built SQL is not acceptable.

### PostgreSQL security direction

- PostgreSQL is private infrastructure and is never publicly reachable.
- AEGIS uses a dedicated database and a dedicated application database account.
- The application account is not a PostgreSQL superuser, database owner, migration
  owner, replication role, or general administrator.
- Runtime, migration, backup, and human administration privileges are separated.
- Credentials and encryption keys are strong, rotated under policy, and managed
  outside source control.
- Network access is restricted to required application and administration paths.
- Connections use encryption where the deployment trust boundary requires it.
- Backups will use an approved mechanism such as `pg_dump`; restore testing is a
  required later operational control, not merely backup creation.

PostgreSQL Row-Level Security may later provide defense in depth for selected
tables after the application policy and connection model are understood. RLS must
not become the only authorization mechanism and must not create a false assumption
that non-row actions, audit access, or application workflows are protected. The
FastAPI backend remains the authoritative policy enforcement point.

### Migration and reference-data strategy

Later implementation should use Alembic migrations rather than manual schema
edits:

```text
reviewed schema change
        -> migration
        -> automated and security-focused tests
        -> reviewed application
```

Migrations must be reproducible, reviewed, tested both forward and, when safe,
for rollback/recovery, and executed with a separate migration role. Alembic is not
installed or configured in this architecture task.

Controlled reference/seed data will include roles, departments, clearance levels,
and the initial compartments. Seed operations must be idempotent or conflict-safe
and must not create real users, production credentials, secrets, sessions, or real
intelligence. Demonstration identities and records remain synthetic.

### Database architecture invariants

1. No plaintext passwords or reversible password storage.
2. No plaintext reusable session tokens.
3. No plaintext TOTP secrets; encryption keys remain outside the database and
   source repository.
4. PostgreSQL is not publicly reachable.
5. The runtime application database account is not a superuser or schema owner.
6. Security relationships use validated foreign keys rather than arbitrary text.
7. Missing authorized-department relationships deny record access.
8. Zero required compartments means no compartment requirement; it does not bypass
   role, clearance, department, or other policy.
9. All listed record compartments must be held by the subject.
10. Record identifiers identify candidates and never authorize access.
11. Creator/ownership metadata does not bypass policy.
12. Audit records contain no secrets and are not ordinarily mutable or deletable.
13. User deactivation revokes active sessions and preserves audit references.
14. Database administration is separate from AEGIS application authorization.
15. PostgreSQL RLS, if adopted, is defense in depth rather than the sole policy
    enforcement mechanism.
16. Schema changes use reviewed migrations, not unmanaged manual edits.

### Part 3 implementation status

This database architecture is **designed but not implemented**. PostgreSQL was not
installed; no database, tables, ORM models, migrations, connections, seed scripts,
or database-dependent application behavior were created. SQLAlchemy and Alembic
were not installed or configured.

## Phase 2 Part 1 implementation status

The Phase 1 design statements above remain the historical architecture contract.
Phase 2 Part 1 now implements its first controlled subset:

- SQLAlchemy 2.x persistence and an Alembic migration targeting PostgreSQL.
- The incremental `users` table with a UUID primary key, canonical unique
  username, synthetic display name, nullable canonical unique email, Argon2
  verifier, active state, and timezone-aware lifecycle fields.
- Explicit database constraints for canonical identifiers, required lengths,
  non-empty password verifiers, and active/disabled consistency.
- A repository boundary plus a password-authentication service that returns an
  identity only for an active, non-disabled account with a valid verifier.
- Argon2id verifier upgrade detection and replacement inside the caller-owned
  database transaction.

New password verifiers require at least eight Unicode characters and at most
1024 UTF-8 bytes. Spaces, whitespace, Unicode, and passphrases remain valid; no
composition rule is imposed. Verification retains compatibility with valid
legacy verifiers whose historical password is shorter than the current creation
minimum. Malformed, non-UTF-8-encodable Python strings fail closed without being
included in validation messages.

Usernames are trimmed, restricted to 3-64 ASCII letters, digits, dots,
underscores, or hyphens, then lowercased. Optional emails are trimmed, restricted
to a simple valid ASCII address form, and lowercased as one identity value.
Restricting these login identifiers to ASCII avoids implicit or surprising
Unicode canonicalization. Display names remain separate and may contain Unicode.

Department and clearance foreign keys will be added to this same `users` table
with their normalized reference entities in a later controlled slice. They are
not technically required for password authentication, and adding them now would
introduce authorization data before its owning phase. Roles, compartments,
records, sessions, MFA credentials, and audit persistence also remain designed
and deferred.

SQLite is not an application architecture choice. It is used only as an isolated,
disposable test backend for portable ORM behavior and migration upgrade/downgrade
tests. PostgreSQL remains the production target, and the migration is also
verified by rendering PostgreSQL SQL offline.

Part 1 deliberately deferred username-enumeration timing mitigation because it
owned only persistence and password verification. The Part 2 status below records
the application-service mitigation that now performs password work for
nonexistent and unusable accounts.

## Phase 2 Part 2 implementation status

Phase 2 Part 2 now implements the application-service boundary for a password
login attempt, without exposing HTTP behavior or creating a session:

- Every ordinary rejection returns the same `FAILURE` result with no internal
  reason. Only `SUCCESS` contains the previously defined identity principal,
  which grants no authorization.
- Nonexistent, malformed-identifier, inactive, and disabled-account paths perform
  one verification against a pre-generated valid Argon2id dummy verifier using
  the current parameters. The dummy input was randomly generated and discarded;
  the verifier belongs to no account and its verification result is ignored.
- Dummy work mitigates the dominant password-processing cost signal but is not a
  mathematical constant-time guarantee for database, network, interpreter, or
  operating-system behavior.
- `PASSWORD_AUTH_SUCCESS` and `PASSWORD_AUTH_FAILURE` events describe password
  credential verification only. They use controlled event, outcome, and internal
  reason enums plus allowlisted fields. No arbitrary metadata container or
  credential field exists in the event model.
- Authentication context requires a UUID correlation ID. Optional IP addresses
  are parsed and canonicalized, invalid IPs are discarded, and user agents are
  stripped, rejected when they contain control characters, and limited to 256
  characters. These values are audit context only, never identity or policy.

Credential-verification audit emission is required. An unexpected sink failure
raises a controlled `AuthenticationAuditError`; the service returns neither
success nor an ordinary failure result. For a valid outdated password verifier,
the credential-success event is emitted before the replacement verifier is
assigned and flushed. An audit failure therefore leaves the stored verifier unchanged. Repository helpers
still do not commit: transaction ownership and later coordination with persistent
audit/session storage remain with the calling workflow.

Persistent `audit_events`, retry/queue behavior, retention, querying, integrity
monitoring, SIEM export, and audit authorization remain deferred. The Part 3
HTTP/session workflow below preserves the generic result semantics, required
audit behavior, and caller-owned transaction boundary.

## Phase 2 Part 3 implementation status

Phase 2 Part 3 implements authentication state over HTTP without implementing
authorization:

- `POST /auth/login` accepts only a strict username and password object and
  delegates password decisions to the existing Part 2 service. Wrong passwords,
  nonexistent or malformed identifiers, unusable accounts, and malformed stored
  verifiers all return the same `401` response. Login-body validation is also
  sanitized so rejected password input is not echoed. Unexpected audit, session,
  or database failures return a small `503` response without internal detail.
- Each successful credential verification generates 32 bytes (256 bits) from
  Python's cryptographic randomness source and encodes them as 43 unpadded
  URL-safe Base64 characters. The server never accepts caller-selected session
  material. Only a lowercase 64-character SHA-256 digest is persisted and used
  for indexed lookup. SHA-256 is appropriate here because the source credential
  is uniformly random and high entropy; Argon2 remains exclusive to passwords.
- The session lifetime defaults to eight hours and is environment-backed with a
  300-to-86400-second safety range. All application timestamps are UTC-aware. A
  session is valid while `created_at <= now < expires_at`; equality at expiry is
  invalid. `last_seen_at` remains nullable and is not updated in this slice, which
  avoids an unconditional write on every authenticated request.
- The `aegis_session` cookie is path-root, `HttpOnly`, and `SameSite=Strict`.
  `Secure=false` is permitted only in explicit `development` or `test`
  environments for local plain HTTP. Any other environment fails configuration
  validation unless `Secure=true`. The token is never returned in JSON, a URL,
  audit data, or an exception, and secret-bearing object fields suppress their
  default representations.
- One `SessionService` owns token creation, deterministic lookup hashing,
  usability validation, and revocation. `GET /auth/me` uses the central dependency
  and returns only username and display name. Missing, malformed, unknown,
  expired, revoked, or otherwise invalid sessions deny authentication. Current
  user usability is checked on every resolution, so a newly inactive or disabled
  user cannot continue using an existing session.
- `POST /auth/logout` revokes a known token hash server-side, commits the
  revocation, and clears the client cookie. Missing, unknown, and already revoked
  tokens are handled idempotently. A copied revoked token remains unusable.
- A successful login always creates fresh server-selected material. If the
  browser presents a known prior AEGIS session, that session is revoked in the
  same transaction before the replacement is created. Arbitrary pre-login cookie
  material is neither persisted nor promoted, preventing session fixation.

The HTTP workflow owns the complete database transaction. The existing
authentication service first emits its required `PASSWORD_AUTH_SUCCESS`
credential-verification event, then may stage a verifier upgrade. The HTTP
workflow stages prior-session revocation and fresh session creation and commits
all database changes together. A session flush or commit failure rolls back the
verifier upgrade and all session changes, returns no successful HTTP response,
and emits no cookie. The current sink writes controlled events to ordinary
application logging; it is non-persistent, non-transactional, and does not provide immutable audit
evidence. `PASSWORD_AUTH_SUCCESS` means only that credentials were verified and
the required logging call completed. Durable login/session establishment is the
separate fact that the session transaction committed and the HTTP response issued
its cookie. No session lifecycle events or persistent audit infrastructure are
introduced in this slice, avoiding a false atomicity claim between logging and
PostgreSQL.

`SameSite=Strict` is a useful CSRF baseline, not a complete universal defense.
Until a dedicated browser CSRF design is implemented, authenticated state-changing
routes must not expand beyond the reviewed idempotent logout operation. The future
authorized account-disable workflow must revoke all active sessions in the same
transaction as account disablement; per-request current-account validation is the
implemented interim guarantee. Authorization, roles, clearance,
departments, compartments, classified records, frontend behavior, abuse controls,
persistent audit storage, and deployment remain designed or deferred rather than
implemented.

## Phase 2 Part 4 implementation status

Phase 2 Part 4 implements the TOTP/MFA foundation without changing password
login or creating authorization state:

- The `mfa_credentials` migration and typed model store UUID identity, user
  ownership, constrained `TOTP` method type, Fernet ciphertext, a non-secret key
  ID, pending/enabled/disabled lifecycle timestamps, and the last accepted TOTP
  counter. Plaintext secrets and QR images are never persisted.
- `AEGIS_MFA_ENCRYPTION_KEY` is optional at general application startup but is
  required when constructing MFA functionality. It must be an independently
  supplied Fernet key and is represented as a secret setting. There is no
  hard-coded fallback. `AEGIS_MFA_ENCRYPTION_KEY_ID` defaults to the non-secret
  identifier `v1`; a mismatched ID fails decryption closed.
- `cryptography` Fernet provides randomized authenticated encryption. Tampering,
  malformed ciphertext, a wrong key, or an unexpected key ID cannot yield a
  usable secret and produces only a controlled non-secret failure.
- PyOTP generates a fresh 160-bit Base32 secret and an `otpauth://` URI using
  issuer `AEGIS` and the canonical synthetic username, with standard URI
  encoding and no internal database identifier. Enrollment returns the plaintext
  secret and secret-bearing URI once in fields excluded from object repr.
- A new credential starts pending (`enabled=false`, `disabled_at=null`). Only a
  valid current TOTP proof enables it. Normal factor verification refuses pending
  and disabled credentials. Disablement sets lifecycle metadata, retains the
  encrypted row, and permits a later independently generated pending credential.
- TOTP parameters are SHA-1, six digits, and 30-second steps. Verification accepts
  only the current counter or exactly one adjacent counter in either direction
  (+/-30 seconds). Codes must be six ASCII decimal digits, and tests inject time.
- Every accepted confirmation or normal verification stores its counter and
  timestamp. The credential row is selected `FOR UPDATE` for PostgreSQL transaction
  serialization, and any counter less than or equal to the last accepted counter
  is rejected. Failed attempts do not change replay state.
- Required non-persistent audit events use the precise names
  `TOTP_VERIFICATION_SUCCESS` and `TOTP_VERIFICATION_FAILURE`. Their allowlisted
  structure contains no secret, entered code, encryption key, or provisioning URI.

No Part 4 HTTP enrollment, confirmation, disable, or verification routes were
added. `SameSite=Strict` remains only a baseline and the project has no dedicated
CSRF mechanism, so expanding authenticated state-changing browser endpoints was
deliberately deferred. `/auth/login` still performs password authentication and
session issuance without requiring TOTP. Part 5 owns the password-to-MFA challenge
and final session-issuance integration. No authorization or Phase 3 behavior is
introduced.
