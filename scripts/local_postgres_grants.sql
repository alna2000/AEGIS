BEGIN;

REVOKE ALL PRIVILEGES ON TABLE alembic_version FROM aegis_app;
REVOKE ALL PRIVILEGES ON TABLE users, sessions, mfa_credentials, mfa_challenges,
    roles, departments, clearance_levels, compartments, user_roles,
    user_compartments, intelligence_records, record_departments,
    record_compartments, audit_events FROM aegis_app;

GRANT USAGE ON SCHEMA public TO aegis_app;

GRANT SELECT, UPDATE ON TABLE users TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON TABLE sessions, mfa_credentials, mfa_challenges
    TO aegis_app;
GRANT SELECT ON TABLE roles, departments, clearance_levels, compartments,
    user_roles, user_compartments, intelligence_records, record_departments,
    record_compartments TO aegis_app;
GRANT SELECT, INSERT ON TABLE audit_events TO aegis_app;

REVOKE CREATE ON SCHEMA public FROM aegis_app;
REVOKE CREATE ON DATABASE aegis FROM aegis_app;

COMMIT;
