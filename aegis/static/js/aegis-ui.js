"use strict";

const UI_STATES = Object.freeze({
  BOOTSTRAPPING: "BOOTSTRAPPING",
  LOGIN: "LOGIN",
  MFA: "MFA",
  AUTHENTICATED: "AUTHENTICATED",
  AUTHENTICATION_SERVICE_UNAVAILABLE: "AUTHENTICATION_SERVICE_UNAVAILABLE",
  UNEXPECTED_ERROR: "UNEXPECTED_ERROR",
});

const API_PATHS = Object.freeze({
  identity: "/auth/me",
  login: "/auth/login",
  mfa: "/auth/mfa/totp/verify",
  logout: "/auth/logout",
  records: "/records",
});

const RECORD_STATES = Object.freeze({
  IDLE: "RECORDS_IDLE",
  LOADING: "RECORDS_LOADING",
  READY: "RECORDS_READY",
  EMPTY: "RECORDS_EMPTY",
  SERVICE_UNAVAILABLE: "RECORDS_SERVICE_UNAVAILABLE",
  UNEXPECTED_ERROR: "RECORDS_UNEXPECTED_ERROR",
});

const DETAIL_STATES = Object.freeze({
  IDLE: "DETAIL_IDLE",
  LOADING: "DETAIL_LOADING",
  READY: "DETAIL_READY",
  NOT_FOUND: "DETAIL_NOT_FOUND",
  SERVICE_UNAVAILABLE: "DETAIL_SERVICE_UNAVAILABLE",
  UNEXPECTED_ERROR: "DETAIL_UNEXPECTED_ERROR",
});

const RECORD_CLASSIFICATION_CLASSES = new Map([
  ["UNCLASSIFIED", "classification-unclassified"],
  ["CONFIDENTIAL", "classification-confidential"],
  ["SECRET", "classification-secret"],
  ["TOP SECRET", "classification-top-secret"],
]);

const RECORD_RESPONSE_FIELDS = Object.freeze([
  "classification",
  "record_code",
  "title",
]);

const DETAIL_RESPONSE_FIELDS = Object.freeze([
  "classification",
  "content",
  "record_code",
  "summary",
  "title",
]);

const panels = Object.freeze({
  [UI_STATES.BOOTSTRAPPING]: document.querySelector("#state-bootstrapping"),
  [UI_STATES.LOGIN]: document.querySelector("#state-login"),
  [UI_STATES.MFA]: document.querySelector("#state-mfa"),
  [UI_STATES.AUTHENTICATED]: document.querySelector("#state-authenticated"),
  [UI_STATES.AUTHENTICATION_SERVICE_UNAVAILABLE]: document.querySelector("#state-service-unavailable"),
  [UI_STATES.UNEXPECTED_ERROR]: document.querySelector("#state-unexpected-error"),
});

const globalStatus = document.querySelector("#global-status");
const loginForm = document.querySelector("#login-form");
const usernameInput = document.querySelector("#username");
const passwordInput = document.querySelector("#password");
const loginSubmit = document.querySelector("#login-submit");
const loginError = document.querySelector("#login-error");
const mfaForm = document.querySelector("#mfa-form");
const totpInput = document.querySelector("#totp-code");
const mfaSubmit = document.querySelector("#mfa-submit");
const mfaCancel = document.querySelector("#mfa-cancel");
const mfaError = document.querySelector("#mfa-error");
const displayName = document.querySelector("#display-name");
const identityUsername = document.querySelector("#identity-username");
const authenticatedTitle = document.querySelector("#authenticated-title");
const logoutButton = document.querySelector("#logout-button");
const logoutError = document.querySelector("#logout-error");
const serviceTitle = document.querySelector("#service-title");
const unexpectedTitle = document.querySelector("#unexpected-title");
const recordsStatus = document.querySelector("#records-status");
const recordList = document.querySelector("#record-list");
const recordsServiceTitle = document.querySelector("#records-service-title");
const recordsUnexpectedTitle = document.querySelector("#records-unexpected-title");
const recordRetryButtons = document.querySelectorAll(".record-retry-action");
const recordCollectionView = document.querySelector("#record-collection-view");
const recordsTitle = document.querySelector("#records-title");
const recordDetailView = document.querySelector("#record-detail-view");
const detailBackButton = document.querySelector("#detail-back");
const detailStatus = document.querySelector("#detail-status");
const detailLoadingTitle = document.querySelector("#detail-loading-title");
const detailTitle = document.querySelector("#detail-title");
const detailRecordCode = document.querySelector("#detail-record-code");
const detailClassification = document.querySelector("#detail-classification");
const detailSummarySection = document.querySelector("#detail-summary-section");
const detailSummary = document.querySelector("#detail-summary");
const detailContent = document.querySelector("#detail-content");
const detailNotFoundTitle = document.querySelector("#detail-not-found-title");
const detailServiceTitle = document.querySelector("#detail-service-title");
const detailUnexpectedTitle = document.querySelector("#detail-unexpected-title");
const detailRetryButtons = document.querySelectorAll(".detail-retry-action");

const recordPanels = Object.freeze({
  [RECORD_STATES.IDLE]: document.querySelector("#records-state-idle"),
  [RECORD_STATES.LOADING]: document.querySelector("#records-state-loading"),
  [RECORD_STATES.READY]: document.querySelector("#records-state-ready"),
  [RECORD_STATES.EMPTY]: document.querySelector("#records-state-empty"),
  [RECORD_STATES.SERVICE_UNAVAILABLE]: document.querySelector("#records-state-service-unavailable"),
  [RECORD_STATES.UNEXPECTED_ERROR]: document.querySelector("#records-state-unexpected-error"),
});

const detailPanels = Object.freeze({
  [DETAIL_STATES.IDLE]: document.querySelector("#detail-state-idle"),
  [DETAIL_STATES.LOADING]: document.querySelector("#detail-state-loading"),
  [DETAIL_STATES.READY]: document.querySelector("#detail-state-ready"),
  [DETAIL_STATES.NOT_FOUND]: document.querySelector("#detail-state-not-found"),
  [DETAIL_STATES.SERVICE_UNAVAILABLE]: document.querySelector("#detail-state-service-unavailable"),
  [DETAIL_STATES.UNEXPECTED_ERROR]: document.querySelector("#detail-state-unexpected-error"),
});

let currentState = UI_STATES.BOOTSTRAPPING;
let mfaOperationInProgress = false;
let currentRecordState = RECORD_STATES.IDLE;
let recordLoadInProgress = false;
let recordRequestVersion = 0;
let currentDetailState = DETAIL_STATES.IDLE;
let detailLoadInProgress = false;
let detailRequestVersion = 0;
let currentDetailRecordCode = null;
let detailReturnFocus = null;

function announce(message) {
  globalStatus.textContent = "";
  window.requestAnimationFrame(() => {
    globalStatus.textContent = message;
  });
}

function setState(nextState, announcement = "") {
  currentState = nextState;
  for (const [state, panel] of Object.entries(panels)) {
    panel.hidden = state !== nextState;
  }

  if (announcement) {
    announce(announcement);
  }

  if (nextState === UI_STATES.LOGIN) {
    usernameInput.focus();
  } else if (nextState === UI_STATES.MFA) {
    if (!mfaOperationInProgress) {
      setMfaControls(false);
    }
    totpInput.focus();
  } else if (nextState === UI_STATES.AUTHENTICATED) {
    authenticatedTitle.focus();
  } else if (nextState === UI_STATES.AUTHENTICATION_SERVICE_UNAVAILABLE) {
    serviceTitle.focus();
  } else if (nextState === UI_STATES.UNEXPECTED_ERROR) {
    unexpectedTitle.focus();
  }
}

function setMessage(element, message) {
  element.textContent = message;
  element.hidden = !message;
}

function announceRecordStatus(message) {
  recordsStatus.textContent = "";
  window.requestAnimationFrame(() => {
    recordsStatus.textContent = message;
  });
}

function setRecordState(nextState, announcement = "") {
  currentRecordState = nextState;
  for (const [state, panel] of Object.entries(recordPanels)) {
    panel.hidden = state !== nextState;
  }
  if (announcement) {
    announceRecordStatus(announcement);
  }
  if (nextState === RECORD_STATES.SERVICE_UNAVAILABLE) {
    recordsServiceTitle.focus();
  } else if (nextState === RECORD_STATES.UNEXPECTED_ERROR) {
    recordsUnexpectedTitle.focus();
  }
}

function setRecordRetryBusy(busy) {
  for (const button of recordRetryButtons) {
    button.disabled = busy;
    button.setAttribute("aria-busy", String(busy));
  }
}

function announceDetailStatus(message) {
  detailStatus.textContent = "";
  window.requestAnimationFrame(() => {
    detailStatus.textContent = message;
  });
}

function setDetailState(nextState, announcement = "") {
  currentDetailState = nextState;
  for (const [state, panel] of Object.entries(detailPanels)) {
    panel.hidden = state !== nextState;
  }
  if (announcement) {
    announceDetailStatus(announcement);
  }
  if (nextState === DETAIL_STATES.LOADING) {
    detailLoadingTitle.focus();
  } else if (nextState === DETAIL_STATES.READY) {
    detailTitle.focus();
  } else if (nextState === DETAIL_STATES.NOT_FOUND) {
    detailNotFoundTitle.focus();
  } else if (nextState === DETAIL_STATES.SERVICE_UNAVAILABLE) {
    detailServiceTitle.focus();
  } else if (nextState === DETAIL_STATES.UNEXPECTED_ERROR) {
    detailUnexpectedTitle.focus();
  }
}

function setDetailRetryBusy(busy) {
  for (const button of detailRetryButtons) {
    button.disabled = busy;
    button.setAttribute("aria-busy", String(busy));
  }
}

function clearDetailContent() {
  detailRecordCode.textContent = "";
  detailTitle.textContent = "";
  detailClassification.textContent = "";
  detailClassification.className = "classification-label";
  detailSummary.textContent = "";
  detailSummarySection.hidden = true;
  detailContent.textContent = "";
}

function cancelDetailLoad() {
  detailRequestVersion += 1;
  detailLoadInProgress = false;
  setDetailRetryBusy(false);
}

function showCollectionView() {
  recordCollectionView.hidden = false;
  recordDetailView.hidden = true;
}

function showDetailView() {
  recordCollectionView.hidden = true;
  recordDetailView.hidden = false;
}

function clearDetailWorkspace() {
  cancelDetailLoad();
  clearDetailContent();
  detailStatus.textContent = "";
  currentDetailRecordCode = null;
  detailReturnFocus = null;
  setDetailState(DETAIL_STATES.IDLE);
  showCollectionView();
}

function clearRecordEntries() {
  recordList.replaceChildren();
}

function cancelRecordLoad() {
  recordRequestVersion += 1;
  recordLoadInProgress = false;
  setRecordRetryBusy(false);
}

function clearRecordWorkspace() {
  cancelRecordLoad();
  clearRecordEntries();
  setRecordState(RECORD_STATES.IDLE);
}

function clearAuthenticatedPresentation() {
  displayName.textContent = "";
  identityUsername.textContent = "";
  clearRecordWorkspace();
  clearDetailWorkspace();
}

function setSubmitting(button, submitting) {
  button.disabled = submitting;
  button.setAttribute("aria-busy", String(submitting));
  button.closest("form")?.setAttribute("aria-busy", String(submitting));
}

function setMfaControls(inProgress, activeButton = null) {
  mfaSubmit.disabled = inProgress;
  mfaCancel.disabled = inProgress;
  mfaSubmit.setAttribute(
    "aria-busy",
    String(inProgress && activeButton === mfaSubmit),
  );
  mfaCancel.setAttribute(
    "aria-busy",
    String(inProgress && activeButton === mfaCancel),
  );
  mfaForm.setAttribute("aria-busy", String(inProgress));
}

function beginMfaOperation(activeButton) {
  if (currentState !== UI_STATES.MFA || mfaOperationInProgress) {
    return false;
  }
  mfaOperationInProgress = true;
  setMfaControls(true, activeButton);
  return true;
}

function endMfaOperation() {
  mfaOperationInProgress = false;
  if (currentState === UI_STATES.MFA) {
    setMfaControls(false);
  }
}

async function request(path, options = {}) {
  return fetch(path, {
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
    ...options,
  });
}

function validateRecordCollection(payload) {
  if (!Array.isArray(payload)) {
    return null;
  }

  const records = [];
  for (const entry of payload) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      return null;
    }
    const fields = Object.keys(entry).sort();
    if (
      fields.length !== RECORD_RESPONSE_FIELDS.length ||
      !fields.every((field, index) => field === RECORD_RESPONSE_FIELDS[index]) ||
      typeof entry.record_code !== "string" ||
      entry.record_code.trim().length === 0 ||
      typeof entry.title !== "string" ||
      entry.title.trim().length === 0 ||
      typeof entry.classification !== "string" ||
      !RECORD_CLASSIFICATION_CLASSES.has(entry.classification)
    ) {
      return null;
    }
    records.push({
      record_code: entry.record_code,
      title: entry.title,
      classification: entry.classification,
    });
  }
  return records;
}

function validateRecordDetail(payload, requestedRecordCode) {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return null;
  }
  const fields = Object.keys(payload).sort();
  if (
    fields.length !== DETAIL_RESPONSE_FIELDS.length ||
    !fields.every((field, index) => field === DETAIL_RESPONSE_FIELDS[index]) ||
    typeof payload.record_code !== "string" ||
    payload.record_code !== requestedRecordCode ||
    typeof payload.title !== "string" ||
    payload.title.trim().length === 0 ||
    !(
      payload.summary === null ||
      (typeof payload.summary === "string" && payload.summary.trim().length > 0)
    ) ||
    typeof payload.content !== "string" ||
    payload.content.trim().length === 0 ||
    typeof payload.classification !== "string" ||
    !RECORD_CLASSIFICATION_CLASSES.has(payload.classification)
  ) {
    return null;
  }
  return {
    record_code: payload.record_code,
    title: payload.title,
    summary: payload.summary,
    content: payload.content,
    classification: payload.classification,
  };
}

function renderRecordCollection(records) {
  const fragment = document.createDocumentFragment();
  for (const record of records) {
    const item = document.createElement("li");
    const card = document.createElement("button");
    const identity = document.createElement("span");
    const code = document.createElement("span");
    const title = document.createElement("span");
    const classification = document.createElement("span");
    const openLabel = document.createElement("span");

    item.className = "record-item";
    card.className = "record-card";
    card.type = "button";
    identity.className = "record-identity";
    code.className = "record-code";
    title.className = "record-title";
    classification.classList.add(
      "classification-label",
      RECORD_CLASSIFICATION_CLASSES.get(record.classification),
    );
    openLabel.className = "record-open-label";

    code.textContent = record.record_code;
    title.textContent = record.title;
    classification.textContent = record.classification;
    openLabel.textContent = "Open record";

    identity.append(code, title);
    card.append(identity, classification, openLabel);
    card.addEventListener("click", () => {
      openRecordDetail(record.record_code, card);
    });
    item.append(card);
    fragment.append(item);
  }
  recordList.replaceChildren(fragment);
}

function renderRecordDetail(record) {
  detailRecordCode.textContent = record.record_code;
  detailTitle.textContent = record.title;
  detailClassification.classList.add(
    RECORD_CLASSIFICATION_CLASSES.get(record.classification),
  );
  detailClassification.textContent = record.classification;
  if (record.summary === null) {
    detailSummarySection.hidden = true;
  } else {
    detailSummary.textContent = record.summary;
    detailSummarySection.hidden = false;
  }
  detailContent.textContent = record.content;
}

function recordRequestIsCurrent(version) {
  return (
    version === recordRequestVersion &&
    currentState === UI_STATES.AUTHENTICATED
  );
}

function detailRequestIsCurrent(version, recordCode) {
  return (
    version === detailRequestVersion &&
    currentState === UI_STATES.AUTHENTICATED &&
    currentDetailRecordCode === recordCode &&
    !recordDetailView.hidden
  );
}

async function loadRecordDetail() {
  const recordCode = currentDetailRecordCode;
  if (
    currentState !== UI_STATES.AUTHENTICATED ||
    typeof recordCode !== "string" ||
    recordCode.length === 0 ||
    detailLoadInProgress
  ) {
    return;
  }

  detailLoadInProgress = true;
  const requestVersion = ++detailRequestVersion;
  clearDetailContent();
  setDetailRetryBusy(true);
  setDetailState(DETAIL_STATES.LOADING, "Loading selected record detail.");

  try {
    const response = await request(
      `${API_PATHS.records}/${encodeURIComponent(recordCode)}`,
    );
    if (!detailRequestIsCurrent(requestVersion, recordCode)) {
      return;
    }
    if (response.status === 401) {
      clearAuthenticatedPresentation();
      setState(UI_STATES.LOGIN, "Your session is no longer available. Sign in again.");
      return;
    }
    if (response.status === 404) {
      setDetailState(
        DETAIL_STATES.NOT_FOUND,
        "Record not found or unavailable.",
      );
      return;
    }
    if (response.status === 503) {
      setDetailState(
        DETAIL_STATES.SERVICE_UNAVAILABLE,
        "Classified record service unavailable.",
      );
      return;
    }
    if (response.status !== 200) {
      setDetailState(
        DETAIL_STATES.UNEXPECTED_ERROR,
        "Unable to load record detail.",
      );
      return;
    }

    const payload = await response.json();
    if (!detailRequestIsCurrent(requestVersion, recordCode)) {
      return;
    }
    const record = validateRecordDetail(payload, recordCode);
    if (record === null) {
      setDetailState(
        DETAIL_STATES.UNEXPECTED_ERROR,
        "Unable to load record detail.",
      );
      return;
    }
    renderRecordDetail(record);
    setDetailState(DETAIL_STATES.READY, "Selected record detail loaded.");
  } catch {
    if (detailRequestIsCurrent(requestVersion, recordCode)) {
      setDetailState(
        DETAIL_STATES.UNEXPECTED_ERROR,
        "Unable to load record detail.",
      );
    }
  } finally {
    if (requestVersion === detailRequestVersion) {
      detailLoadInProgress = false;
      setDetailRetryBusy(false);
    }
  }
}

function openRecordDetail(recordCode, trigger) {
  if (currentState !== UI_STATES.AUTHENTICATED) {
    return;
  }
  cancelDetailLoad();
  currentDetailRecordCode = recordCode;
  detailReturnFocus = trigger;
  showDetailView();
  void loadRecordDetail();
}

function returnToRecordCollection() {
  const focusTarget = detailReturnFocus;
  clearDetailWorkspace();
  announceRecordStatus("Returned to the available record collection.");
  window.requestAnimationFrame(() => {
    if (focusTarget?.isConnected) {
      focusTarget.focus();
    } else {
      recordsTitle.focus();
    }
  });
}

async function loadRecords() {
  if (currentState !== UI_STATES.AUTHENTICATED || recordLoadInProgress) {
    return;
  }

  recordLoadInProgress = true;
  const requestVersion = ++recordRequestVersion;
  clearRecordEntries();
  setRecordRetryBusy(true);
  setRecordState(RECORD_STATES.LOADING, "Loading available record metadata.");

  try {
    const response = await request(API_PATHS.records);
    if (!recordRequestIsCurrent(requestVersion)) {
      return;
    }
    if (response.status === 401) {
      clearAuthenticatedPresentation();
      setState(UI_STATES.LOGIN, "Your session is no longer available. Sign in again.");
      return;
    }
    if (response.status === 503) {
      setRecordState(
        RECORD_STATES.SERVICE_UNAVAILABLE,
        "Classified record service unavailable.",
      );
      return;
    }
    if (response.status !== 200) {
      setRecordState(
        RECORD_STATES.UNEXPECTED_ERROR,
        "Unable to load record metadata.",
      );
      return;
    }

    const payload = await response.json();
    if (!recordRequestIsCurrent(requestVersion)) {
      return;
    }
    const records = validateRecordCollection(payload);
    if (records === null) {
      setRecordState(
        RECORD_STATES.UNEXPECTED_ERROR,
        "Unable to load record metadata.",
      );
      return;
    }
    if (records.length === 0) {
      setRecordState(
        RECORD_STATES.EMPTY,
        "No records are currently available to this authenticated session.",
      );
      return;
    }

    renderRecordCollection(records);
    setRecordState(RECORD_STATES.READY, "Available record metadata loaded.");
  } catch {
    if (recordRequestIsCurrent(requestVersion)) {
      setRecordState(
        RECORD_STATES.UNEXPECTED_ERROR,
        "Unable to load record metadata.",
      );
    }
  } finally {
    if (requestVersion === recordRequestVersion) {
      recordLoadInProgress = false;
      setRecordRetryBusy(false);
    }
  }
}

function showServiceUnavailable() {
  setState(
    UI_STATES.AUTHENTICATION_SERVICE_UNAVAILABLE,
    "Authentication service unavailable. Retry when ready.",
  );
}

function showUnexpectedError() {
  setState(UI_STATES.UNEXPECTED_ERROR, "Unable to complete the request.");
}

async function resolveIdentity() {
  clearAuthenticatedPresentation();
  setState(UI_STATES.BOOTSTRAPPING, "Verifying authenticated identity.");

  try {
    const response = await request(API_PATHS.identity);
    if (response.status === 401) {
      setState(UI_STATES.LOGIN, "Sign in is required.");
      return;
    }
    if (response.status === 503) {
      showServiceUnavailable();
      return;
    }
    if (response.status !== 200) {
      showUnexpectedError();
      return;
    }

    const identity = await response.json();
    if (
      typeof identity.display_name !== "string" ||
      !identity.display_name ||
      typeof identity.username !== "string" ||
      !identity.username
    ) {
      showUnexpectedError();
      return;
    }

    displayName.textContent = identity.display_name;
    identityUsername.textContent = `@${identity.username}`;
    setState(UI_STATES.AUTHENTICATED, "Authenticated identity confirmed.");
    void loadRecords();
  } catch {
    showUnexpectedError();
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (currentState !== UI_STATES.LOGIN || loginSubmit.disabled) {
    return;
  }

  setMessage(loginError, "");
  if (!loginForm.reportValidity()) {
    return;
  }

  const body = JSON.stringify({
    username: usernameInput.value,
    password: passwordInput.value,
  });
  passwordInput.value = "";
  setSubmitting(loginSubmit, true);

  try {
    const response = await request(API_PATHS.login, { method: "POST", body });
    if (response.status === 401) {
      setMessage(loginError, "Invalid username or password.");
      passwordInput.focus();
      return;
    }
    if (response.status === 503) {
      showServiceUnavailable();
      return;
    }
    if (response.status !== 200) {
      showUnexpectedError();
      return;
    }

    const result = await response.json();
    if (result.authenticated === true && result.mfa_required === false) {
      usernameInput.value = "";
      await resolveIdentity();
      return;
    }
    if (result.authenticated === false && result.mfa_required === true) {
      usernameInput.value = "";
      totpInput.value = "";
      setState(UI_STATES.MFA, "A six-digit verification code is required.");
      return;
    }
    showUnexpectedError();
  } catch {
    showUnexpectedError();
  } finally {
    passwordInput.value = "";
    setSubmitting(loginSubmit, false);
  }
});

mfaForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (currentState !== UI_STATES.MFA || mfaOperationInProgress) {
    return;
  }

  setMessage(mfaError, "");
  if (!mfaForm.reportValidity() || !/^[0-9]{6}$/.test(totpInput.value)) {
    setMessage(mfaError, "MFA verification failed.");
    return;
  }
  if (!beginMfaOperation(mfaSubmit)) {
    return;
  }

  const body = JSON.stringify({ code: totpInput.value });
  totpInput.value = "";

  try {
    const response = await request(API_PATHS.mfa, { method: "POST", body });
    if (response.status === 401) {
      setMessage(mfaError, "MFA verification failed.");
      totpInput.focus();
      return;
    }
    if (response.status === 503) {
      showServiceUnavailable();
      return;
    }
    if (response.status !== 200) {
      showUnexpectedError();
      return;
    }

    const result = await response.json();
    if (result.authenticated === true && result.mfa_required === false) {
      await resolveIdentity();
      return;
    }
    showUnexpectedError();
  } catch {
    showUnexpectedError();
  } finally {
    totpInput.value = "";
    endMfaOperation();
  }
});

async function logout({ errorTarget, button, manageButton = true }) {
  const shouldResumeRecordLoad =
    currentState === UI_STATES.AUTHENTICATED &&
    currentRecordState === RECORD_STATES.LOADING;
  const detailCodeAtLogout = currentDetailRecordCode;
  const shouldResumeDetailLoad =
    currentState === UI_STATES.AUTHENTICATED &&
    currentDetailState === DETAIL_STATES.LOADING &&
    typeof detailCodeAtLogout === "string";
  if (currentState === UI_STATES.AUTHENTICATED) {
    cancelRecordLoad();
    cancelDetailLoad();
  }
  setMessage(errorTarget, "");
  if (manageButton) {
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
  }

  try {
    const response = await request(API_PATHS.logout, { method: "POST" });
    if (response.status === 204) {
      clearAuthenticatedPresentation();
      usernameInput.value = "";
      passwordInput.value = "";
      totpInput.value = "";
      setState(UI_STATES.LOGIN, "You have signed out.");
      return;
    }
    if (response.status === 503) {
      setMessage(errorTarget, "Authentication service unavailable. Sign out was not completed.");
      return;
    }
    setMessage(errorTarget, "Unable to complete sign out. Try again.");
  } catch {
    setMessage(errorTarget, "Unable to complete sign out. Try again.");
  } finally {
    if (manageButton) {
      button.disabled = false;
      button.setAttribute("aria-busy", "false");
    }
    if (
      shouldResumeRecordLoad &&
      currentState === UI_STATES.AUTHENTICATED &&
      currentRecordState === RECORD_STATES.LOADING
    ) {
      void loadRecords();
    }
    if (
      shouldResumeDetailLoad &&
      currentState === UI_STATES.AUTHENTICATED &&
      currentDetailState === DETAIL_STATES.LOADING &&
      currentDetailRecordCode === detailCodeAtLogout
    ) {
      void loadRecordDetail();
    }
  }
}

logoutButton.addEventListener("click", () => {
  if (currentState === UI_STATES.AUTHENTICATED) {
    void logout({ errorTarget: logoutError, button: logoutButton });
  }
});

mfaCancel.addEventListener("click", async () => {
  if (!beginMfaOperation(mfaCancel)) {
    return;
  }
  try {
    await logout({
      errorTarget: mfaError,
      button: mfaCancel,
      manageButton: false,
    });
  } finally {
    endMfaOperation();
  }
});

for (const retryButton of document.querySelectorAll(".retry-action")) {
  retryButton.addEventListener("click", () => {
    void resolveIdentity();
  });
}

for (const retryButton of recordRetryButtons) {
  retryButton.addEventListener("click", () => {
    void loadRecords();
  });
}

for (const retryButton of detailRetryButtons) {
  retryButton.addEventListener("click", () => {
    void loadRecordDetail();
  });
}

detailBackButton.addEventListener("click", returnToRecordCollection);

void resolveIdentity();
