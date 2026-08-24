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
});

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

let currentState = UI_STATES.BOOTSTRAPPING;
let mfaOperationInProgress = false;

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
  setMessage(errorTarget, "");
  if (manageButton) {
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
  }

  try {
    const response = await request(API_PATHS.logout, { method: "POST" });
    if (response.status === 204) {
      displayName.textContent = "";
      identityUsername.textContent = "";
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

void resolveIdentity();
