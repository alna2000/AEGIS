"""Server-side contract tests for the Phase 4 Part 1 UI foundation."""

import re

from fastapi.testclient import TestClient

from aegis.core.config import Settings, get_settings
from aegis.main import create_app


def get_test_settings() -> Settings:
    return Settings(_env_file=None)


def ui_client() -> TestClient:
    application = create_app()
    application.dependency_overrides[get_settings] = get_test_settings
    return TestClient(application)


def test_ui_returns_semantic_authentication_shell() -> None:
    with ui_client() as client:
        response = client.get("/ui")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<main" in response.text
    assert (
        '<form id="login-form" method="post" action="/auth/login" novalidate>'
        in response.text
    )
    assert '<label for="username">Username</label>' in response.text
    assert '<label for="password">Password</label>' in response.text
    assert (
        '<form id="mfa-form" method="post" '
        'action="/auth/mfa/totp/verify" novalidate>' in response.text
    )
    assert '<label for="totp-code">Six-digit code</label>' in response.text
    assert 'role="status"' in response.text
    assert 'role="alert"' in response.text
    assert "Synthetic cybersecurity learning environment" in response.text


def test_dynamic_state_focus_targets_are_programmatically_focusable() -> None:
    with ui_client() as client:
        response = client.get("/ui")
        script = client.get("/static/js/aegis-ui.js").text

    for target in ("authenticated-title", "service-title", "unexpected-title"):
        assert f'id="{target}" tabindex="-1"' in response.text
    assert "authenticatedTitle.focus();" in script
    assert "serviceTitle.focus();" in script
    assert "unexpectedTitle.focus();" in script


def test_ui_contains_no_authorization_or_credential_material() -> None:
    with ui_client() as client:
        response = client.get("/ui")
        script = client.get("/static/js/aegis-ui.js").text

    combined = f"{response.text}\n{script}".lower()
    for forbidden in (
        "system administrator",
        "security auditor",
        "clearance",
        "department",
        "compartment",
        "aegis_session",
        "aegis_mfa_challenge",
        "localstorage",
        "sessionstorage",
    ):
        assert forbidden not in combined


def test_authenticated_shell_contains_accessible_record_states() -> None:
    with ui_client() as client:
        response = client.get("/ui")

    assert 'class="record-workspace" aria-labelledby="records-title"' in response.text
    assert 'id="records-status" class="sr-only" role="status"' in response.text
    for state in (
        "records-state-idle",
        "records-state-loading",
        "records-state-ready",
        "records-state-empty",
        "records-state-service-unavailable",
        "records-state-unexpected-error",
    ):
        assert f'id="{state}"' in response.text
    assert '<ul id="record-list" class="record-list"' in response.text
    assert "No records are currently available to this authenticated session." in response.text
    assert 'id="records-service-title" tabindex="-1"' in response.text
    assert 'id="records-unexpected-title" tabindex="-1"' in response.text


def test_record_workspace_introduces_no_unsupported_controls() -> None:
    with ui_client() as client:
        response = client.get("/ui")

    lowered = response.text.lower()
    assert 'type="search"' not in lowered
    assert "classification filter" not in lowered
    assert "department filter" not in lowered
    assert "pagination" not in lowered
    assert "total records" not in lowered
    assert "hidden records" not in lowered
    assert "record detail" not in lowered


def test_static_assets_are_local_and_available() -> None:
    with ui_client() as client:
        page = client.get("/ui")
        stylesheet = client.get("/static/css/aegis.css")
        script = client.get("/static/js/aegis-ui.js")

    assert 'href="http://testserver/static/css/aegis.css"' in page.text
    assert 'src="http://testserver/static/js/aegis-ui.js"' in page.text
    assert stylesheet.status_code == 200
    assert stylesheet.headers["content-type"].startswith("text/css")
    assert script.status_code == 200
    assert "javascript" in script.headers["content-type"]
    assert "https://" not in page.text
    assert "http://" not in page.text.replace("http://testserver/static/", "")


def test_ui_script_uses_only_existing_authentication_endpoints() -> None:
    with ui_client() as client:
        script = client.get("/static/js/aegis-ui.js").text

    paths = set(re.findall(r'"(/auth/[a-z/]+)"', script))
    assert paths == {
        "/auth/me",
        "/auth/login",
        "/auth/mfa/totp/verify",
        "/auth/logout",
    }
    assert 'credentials: "same-origin"' in script
    assert "document.cookie" not in script


def test_ui_script_uses_only_the_record_collection_endpoint() -> None:
    with ui_client() as client:
        script = client.get("/static/js/aegis-ui.js").text

    assert set(re.findall(r'"(/records[^" ]*)"', script)) == {"/records"}
    assert 'records: "/records"' in script
    assert '"/records/' not in script


def test_record_rendering_uses_safe_dom_construction() -> None:
    with ui_client() as client:
        script = client.get("/static/js/aegis-ui.js").text

    for forbidden in (
        "innerHTML",
        "insertAdjacentHTML",
        "document.write",
        "localStorage",
        "sessionStorage",
        "document.cookie",
        "new Function",
    ):
        assert forbidden not in script
    assert 'document.createElement("li")' in script
    assert 'document.createElement("article")' in script
    assert "code.textContent = record.record_code;" in script
    assert "title.textContent = record.title;" in script
    assert "classification.textContent = record.classification;" in script


def test_collection_flow_is_guarded_and_fails_closed_structurally() -> None:
    with ui_client() as client:
        script = client.get("/static/js/aegis-ui.js").text

    assert "const RECORD_STATES = Object.freeze" in script
    assert "let recordLoadInProgress = false;" in script
    assert "let recordRequestVersion = 0;" in script
    assert "function recordRequestIsCurrent(version)" in script
    assert "if (currentState !== UI_STATES.AUTHENTICATED || recordLoadInProgress)" in script
    assert "const records = validateRecordCollection(payload);" in script
    assert "if (records === null)" in script
    assert "if (records.length === 0)" in script
    assert "if (response.status === 401)" in script
    assert "clearAuthenticatedPresentation();" in script
    assert "if (response.status === 503)" in script
    assert "void loadRecords();" in script
    assert "recordRequestVersion += 1;" in script


def test_mfa_operations_share_one_exclusion_guard() -> None:
    with ui_client() as client:
        script = client.get("/static/js/aegis-ui.js").text

    assert "let mfaOperationInProgress = false;" in script
    assert "function beginMfaOperation(activeButton)" in script
    assert "function endMfaOperation()" in script
    assert "mfaSubmit.disabled = inProgress;" in script
    assert "mfaCancel.disabled = inProgress;" in script
    assert "if (!beginMfaOperation(mfaSubmit))" in script
    assert "if (!beginMfaOperation(mfaCancel))" in script
    assert script.count("endMfaOperation();") == 2


def test_ui_has_route_scoped_browser_security_headers() -> None:
    with ui_client() as client:
        ui_response = client.get("/ui")
        docs_response = client.get("/docs")

    policy = ui_response.headers["content-security-policy"]
    assert "default-src 'none'" in policy
    assert "script-src 'self'" in policy
    assert "style-src 'self'" in policy
    assert "connect-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert ui_response.headers["x-content-type-options"] == "nosniff"
    assert ui_response.headers["referrer-policy"] == "no-referrer"
    assert "camera=()" in ui_response.headers["permissions-policy"]
    assert ui_response.headers["cache-control"] == "no-store"
    assert docs_response.status_code == 200
    assert "content-security-policy" not in docs_response.headers


def test_existing_system_json_contracts_are_unchanged() -> None:
    with ui_client() as client:
        root = client.get("/")
        health = client.get("/health")

    assert root.status_code == 200
    assert root.json() == {
        "name": "AEGIS",
        "status": "Development",
        "api": "Available",
    }
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
