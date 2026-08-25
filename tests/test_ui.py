"""Server-side contract tests for the Phase 4 authenticated UI."""

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
    for target in ("login-error", "mfa-error", "logout-error"):
        assert f'id="{target}" class="form-message" role="alert" tabindex="-1"' in response.text


def test_ui_has_a_safe_javascript_failure_fallback() -> None:
    with ui_client() as client:
        response = client.get("/ui")
        script = client.get("/static/js/aegis-ui.js").text

    assert 'id="script-required" class="state-panel error-panel"' in response.text
    assert "JavaScript is required" in response.text
    assert "No authenticated content has been loaded." in response.text
    assert 'id="state-bootstrapping"' in response.text
    assert 'aria-labelledby="bootstrapping-title" hidden' in response.text
    assert "scriptRequired.hidden = true;" in script


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


def test_authenticated_shell_contains_accessible_detail_states() -> None:
    with ui_client() as client:
        response = client.get("/ui")

    assert 'id="record-detail-view" class="detail-workspace"' in response.text
    assert 'id="detail-status" class="sr-only" role="status"' in response.text
    for state in (
        "detail-state-idle",
        "detail-state-loading",
        "detail-state-ready",
        "detail-state-not-found",
        "detail-state-service-unavailable",
        "detail-state-unexpected-error",
    ):
        assert f'id="{state}"' in response.text
    assert 'id="detail-back"' in response.text
    assert "Return to record collection" in response.text
    assert response.text.count("detail-retry-action") == 2
    assert "Record not found or unavailable" in response.text
    not_found = response.text.split('id="detail-state-not-found"', 1)[1].split(
        "</section>", 1
    )[0].lower()
    for forbidden in (
        "access denied",
        "clearance",
        "department",
        "compartment",
        "permission",
    ):
        assert forbidden not in not_found


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
    assert "next page" not in lowered
    assert "previous page" not in lowered


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


def test_ui_script_uses_only_the_record_collection_and_detail_endpoints() -> None:
    with ui_client() as client:
        script = client.get("/static/js/aegis-ui.js").text

    assert set(re.findall(r'"(/records[^" ]*)"', script)) == {"/records"}
    assert 'records: "/records"' in script
    assert "request(API_PATHS.records)" in script
    assert "`${API_PATHS.records}/${encodeURIComponent(recordCode)}`" in script
    assert 'method: "POST"' not in script.split("async function loadRecordDetail", 1)[1].split(
        "function openRecordDetail", 1
    )[0]


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
    assert 'document.createElement("button")' in script
    assert "code.textContent = record.record_code;" in script
    assert "title.textContent = record.title;" in script
    assert "classification.textContent = record.classification;" in script
    assert "detailRecordCode.textContent = record.record_code;" in script
    assert "detailTitle.textContent = record.title;" in script
    assert "detailContent.textContent = record.content;" in script


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


def test_detail_payload_validation_is_strict_and_representation_consistent() -> None:
    with ui_client() as client:
        script = client.get("/static/js/aegis-ui.js").text

    assert "const DETAIL_RESPONSE_FIELDS = Object.freeze" in script
    for field in ("classification", "content", "record_code", "summary", "title"):
        assert f'"{field}"' in script
    assert "payload.record_code !== requestedRecordCode" in script
    assert "payload.summary === null" in script
    assert 'typeof payload.summary === "string"' in script
    assert "RECORD_CLASSIFICATION_CLASSES.has(payload.classification)" in script
    assert "const record = validateRecordDetail(payload, recordCode);" in script
    assert "if (record === null)" in script


def test_detail_flow_is_authenticated_guarded_and_invalidated_structurally() -> None:
    with ui_client() as client:
        script = client.get("/static/js/aegis-ui.js").text

    assert "const DETAIL_STATES = Object.freeze" in script
    assert "let detailLoadInProgress = false;" in script
    assert "let detailRequestVersion = 0;" in script
    assert "let currentDetailRecordCode = null;" in script
    assert "function detailRequestIsCurrent(version, recordCode)" in script
    assert "currentState !== UI_STATES.AUTHENTICATED" in script
    assert "currentDetailRecordCode === recordCode" in script
    assert "detailRequestVersion += 1;" in script
    assert "function returnToRecordCollection()" in script
    assert "clearAuthenticatedPresentation();" in script
    assert "if (response.status === 404)" in script
    assert "if (response.status === 503)" in script
    assert "detailContent.textContent = record.content;" in script


def test_identity_resolution_rejects_overlap_and_stale_responses() -> None:
    with ui_client() as client:
        script = client.get("/static/js/aegis-ui.js").text

    assert "let identityLoadInProgress = false;" in script
    assert "let identityRequestVersion = 0;" in script
    assert "function cancelIdentityLoad()" in script
    assert "function identityRequestIsCurrent(version)" in script
    assert "if (identityLoadInProgress)" in script
    assert "const requestVersion = ++identityRequestVersion;" in script
    assert script.count("if (!identityRequestIsCurrent(requestVersion))") == 2
    assert "cancelIdentityLoad();" in script.split(
        "async function logout", 1
    )[1].split("logoutButton.addEventListener", 1)[0]


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
    assert set(policy.split("; ")) == {
        "default-src 'none'",
        "base-uri 'none'",
        "connect-src 'self'",
        "font-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "img-src 'self'",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
    }
    assert ui_response.headers["x-content-type-options"] == "nosniff"
    assert ui_response.headers["referrer-policy"] == "no-referrer"
    assert "camera=()" in ui_response.headers["permissions-policy"]
    assert ui_response.headers["cache-control"] == "no-store"
    assert docs_response.status_code == 200
    assert "content-security-policy" not in docs_response.headers


def test_ui_has_no_inline_active_content_and_wraps_record_codes() -> None:
    with ui_client() as client:
        response = client.get("/ui")
        stylesheet = client.get("/static/css/aegis.css").text

    assert re.search(r"<script[^>]+src=", response.text)
    assert not re.search(r"<script(?![^>]+src=)", response.text)
    assert "<style" not in response.text
    assert not re.search(r"\son[a-z]+\s*=", response.text, re.IGNORECASE)
    record_code_rule = stylesheet.split(".record-code {", 1)[1].split("}", 1)[0]
    assert "overflow-wrap: anywhere;" in record_code_rule


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
