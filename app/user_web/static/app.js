"use strict";

const POLL_DELAY_MS = 1500;
const TERMINAL_STATES = new Set(["SIGNED", "FAILED", "EXPIRED"]);
const ACTIVE_STATES = new Set([
  "PENDING",
  "CLAIMED",
  "AUTHENTICATING",
  "AUTHENTICATED",
]);
const STATE_PRESENTATION = Object.freeze({
  PENDING: {
    title: "Waiting for your strong authentication",
    message: "Authenticate on the ESP32 device.",
  },
  CLAIMED: {
    title: "Device connected",
    message: "The request was retrieved by the ESP32 device.",
  },
  AUTHENTICATING: {
    title: "Authentication in progress",
    message: "The device is checking your RFID and fingerprint.",
  },
  AUTHENTICATED: {
    title: "Identity verified",
    message: "Cryptographic signing in progress.",
  },
  SIGNED: {
    title: "Document signed successfully",
    message: "Cryptographic signing is complete.",
  },
  FAILED: {
    title: "Signature denied",
    message: "You can start again with new consent.",
  },
  EXPIRED: {
    title: "Request expired",
    message: "You can start again with new consent.",
  },
});

const elements = {
  alert: document.getElementById("global-alert"),
  userName: document.getElementById("user-name"),
  sessionIndicator: document.getElementById("session-indicator"),
  logoutForm: document.getElementById("logout-form"),
  logoutButton: document.getElementById("logout-button"),
  documentsList: document.getElementById("documents-list"),
  consentPanel: document.getElementById("consent-panel"),
  consentDocumentName: document.getElementById("consent-document-name"),
  consentForm: document.getElementById("consent-form"),
  documentViewed: document.getElementById("document-viewed"),
  signatureConfirmed: document.getElementById("signature-confirmed"),
  cancelConsent: document.getElementById("cancel-consent"),
  requestButton: document.getElementById("request-signature"),
  requestStatus: document.getElementById("request-status"),
  requestState: document.getElementById("request-state"),
  requestMessage: document.getElementById("request-message"),
};

let csrfToken = "";
let selectedDocument = null;
let pollTimer = null;
let documentsRefreshTimer = null;

class SessionExpiredError extends Error {}

function showAlert(message, kind = "error") {
  elements.alert.textContent = message;
  elements.alert.className = `alert alert-${kind}`;
  elements.alert.hidden = false;
}

function clearAlert() {
  elements.alert.textContent = "";
  elements.alert.hidden = true;
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleString("en-US");
}

function formatBytes(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount)) return "—";
  if (amount < 1024) return `${amount} bytes`;
  if (amount < 1024 * 1024) return `${(amount / 1024).toFixed(1)} KiB`;
  return `${(amount / (1024 * 1024)).toFixed(1)} MiB`;
}

function redirectToLogin() {
  window.location.replace("/user/login?error=session_expired");
}

async function readJson(response) {
  try {
    return await response.json();
  } catch (_error) {
    return null;
  }
}

async function apiFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");

  if (csrfToken) headers.set("X-CSRF-Token", csrfToken);

  const response = await fetch(url, {
    ...options,
    headers,
    credentials: "same-origin",
    cache: "no-store",
  });

  if (response.status === 401) {
    redirectToLogin();
    throw new SessionExpiredError();
  }

  return response;
}

function statePresentation(request) {
  return request && typeof request.state === "string"
    ? STATE_PRESENTATION[request.state]
    : null;
}

function renderDocuments(documents) {
  elements.documentsList.replaceChildren();

  if (!documents.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No documents are currently assigned to you.";
    elements.documentsList.append(empty);
    return false;
  }

  let hasActiveRequest = false;

  for (const item of documents) {
    const article = document.createElement("article");
    article.className = "user-document-card";

    const details = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = String(item.filename);
    const meta = document.createElement("p");
    meta.className = "user-document-meta";
    meta.textContent = `${formatDate(item.created_at)} · ${formatBytes(item.size_bytes)}`;
    const presentation = statePresentation(item.request);
    const state = document.createElement("span");
    state.className = item.request
      ? `user-state user-state-${item.request.state.toLowerCase()}`
      : "user-state";
    state.textContent = presentation ? presentation.title : "No request";
    const stateMessage = document.createElement("p");
    stateMessage.className = "user-request-message";
    stateMessage.textContent = presentation
      ? presentation.message
      : "No active signature request.";
    details.append(title, meta, state, stateMessage);

    if (item.request && item.request.state === "SIGNED") {
      const signatureMeta = document.createElement("p");
      signatureMeta.className = "user-signature-meta";
      const metadata = [];
      if (item.request.signer_name) metadata.push(`Signer: ${item.request.signer_name}`);
      if (item.request.signed_at) metadata.push(`Signing date: ${formatDate(item.request.signed_at)}`);
      if (item.request.signature_id) metadata.push(`Signature: ${item.request.signature_id}`);
      if (item.request.algorithm) metadata.push(String(item.request.algorithm));
      if (item.request.pades_profile) metadata.push(`Profile: ${item.request.pades_profile}`);
      if (item.request.certificate_subject) metadata.push(`Certificate: ${item.request.certificate_subject}`);
      if (item.request.timestamp_time) metadata.push(`Timestamp: ${formatDate(item.request.timestamp_time)}`);
      if (item.request.tsa_certificate_subject) metadata.push(`TSA: ${item.request.tsa_certificate_subject}`);
      signatureMeta.textContent = metadata.join(" · ");
      if (metadata.length) details.append(signatureMeta);
    }

    const actions = document.createElement("div");
    actions.className = "user-document-actions";
    const view = document.createElement("a");
    view.className = "button button-quiet";
    view.textContent = "View document";
    view.href = `/user/documents/${encodeURIComponent(item.document_id)}/view`;
    view.target = "_blank";
    view.rel = "noopener";

    actions.append(view);

    if (item.request && item.request.state === "SIGNED") {
      const signedBadge = document.createElement("span");
      signedBadge.className = "user-state user-state-signed";
      signedBadge.textContent = "Signed";
      actions.append(signedBadge);

      if (item.request.signed_document_available === true) {
        const download = document.createElement("a");
        download.className = "button button-primary";
        download.textContent = "Download signed PDF";
        download.href = `/user/documents/${encodeURIComponent(item.document_id)}/signed`;
        actions.append(download);
      }
    } else if (!(item.request && ACTIVE_STATES.has(item.request.state))) {
      const sign = document.createElement("button");
      sign.className = "button button-accent";
      sign.type = "button";
      sign.textContent = "Sign this document";
      sign.addEventListener("click", () => openConsent(item));
      actions.append(sign);
    }

    hasActiveRequest = hasActiveRequest || Boolean(
      item.request && ACTIVE_STATES.has(item.request.state),
    );
    article.append(details, actions);
    elements.documentsList.append(article);
  }

  return hasActiveRequest;
}

function scheduleDocumentsRefresh(hasActiveRequest) {
  if (documentsRefreshTimer !== null) {
    window.clearTimeout(documentsRefreshTimer);
    documentsRefreshTimer = null;
  }

  if (hasActiveRequest) {
    documentsRefreshTimer = window.setTimeout(() => {
      documentsRefreshTimer = null;
      loadSessionAndDocuments();
    }, POLL_DELAY_MS);
  }
}

async function loadSessionAndDocuments() {
  try {
    const sessionResponse = await fetch("/user/api/session", {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
      cache: "no-store",
    });

    if (!sessionResponse.ok) {
      redirectToLogin();
      return;
    }

    const session = await readJson(sessionResponse);
    if (!session || !session.user || typeof session.csrf_token !== "string") {
      redirectToLogin();
      return;
    }

    csrfToken = session.csrf_token;
    elements.userName.textContent = String(session.user.full_name);
    elements.sessionIndicator.textContent = "User session active";
    elements.logoutButton.disabled = false;

    const documentsResponse = await apiFetch("/user/api/documents");
    const payload = await readJson(documentsResponse);

    if (!documentsResponse.ok || !payload || !Array.isArray(payload.documents)) {
      throw new Error("Unable to load your documents.");
    }

    scheduleDocumentsRefresh(renderDocuments(payload.documents));
  } catch (error) {
    if (!(error instanceof SessionExpiredError)) {
      showAlert(error instanceof Error ? error.message : "Unable to load data.");
    }
  }
}

function openConsent(documentData) {
  clearAlert();
  selectedDocument = documentData;
  elements.consentDocumentName.textContent = String(documentData.filename);
  elements.documentViewed.checked = false;
  elements.signatureConfirmed.checked = false;
  elements.consentForm.hidden = false;
  elements.requestStatus.hidden = true;
  elements.consentPanel.hidden = false;
  elements.consentPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function closeConsent() {
  selectedDocument = null;
  elements.consentForm.reset();
  elements.consentForm.hidden = false;
  elements.consentPanel.hidden = true;
  if (pollTimer !== null) window.clearTimeout(pollTimer);
  pollTimer = null;
}

function displayRequestState(payload) {
  elements.requestStatus.hidden = false;
  const presentation = STATE_PRESENTATION[payload.state];
  elements.requestState.textContent = presentation
    ? presentation.title
    : "Unknown status";
  const message = presentation
    ? presentation.message
    : "Status updated.";
  const metadata = [];

  if (payload.state === "SIGNED") {
    if (payload.filename) metadata.push(String(payload.filename));
    if (payload.signer_name) metadata.push(`Signer: ${payload.signer_name}`);
    if (payload.signed_at) metadata.push(`Signing date: ${formatDate(payload.signed_at)}`);
    if (payload.signature_id) metadata.push(`Signature: ${payload.signature_id}`);
    if (payload.algorithm) metadata.push(String(payload.algorithm));
    if (payload.pades_profile) metadata.push(`Profile: ${payload.pades_profile}`);
    if (payload.certificate_subject) metadata.push(`Certificate: ${payload.certificate_subject}`);
    if (payload.timestamp_time) metadata.push(`Timestamp: ${formatDate(payload.timestamp_time)}`);
    if (payload.tsa_certificate_subject) metadata.push(`TSA: ${payload.tsa_certificate_subject}`);
  }

  elements.requestMessage.textContent = metadata.length
    ? `${message} ${metadata.join(" · ")}`
    : message;
}

function displayConsentAccepted() {
  elements.consentForm.hidden = true;
  elements.requestStatus.hidden = false;
  elements.requestState.textContent = "Strong authentication required";
  elements.requestMessage.textContent = (
    "Your signature request has been recorded.\n"
    + "Authenticate now on your ESP32 device."
  );
}

function schedulePoll(requestId) {
  pollTimer = window.setTimeout(() => pollRequest(requestId), POLL_DELAY_MS);
}

async function pollRequest(requestId) {
  try {
    const response = await apiFetch(
      `/user/api/signature-requests/${encodeURIComponent(requestId)}`,
    );
    const payload = await readJson(response);

    if (!response.ok || !payload || typeof payload.state !== "string") {
      throw new Error("Unable to track the request.");
    }

    displayRequestState(payload);

    if (TERMINAL_STATES.has(payload.state)) {
      pollTimer = null;
      elements.consentForm.reset();
      elements.consentForm.hidden = true;
      elements.requestButton.disabled = payload.state === "SIGNED";
      await loadSessionAndDocuments();

      if (payload.state !== "SIGNED") {
        selectedDocument = null;
        elements.consentForm.hidden = false;
        elements.consentPanel.hidden = true;
      }

      return;
    }

    schedulePoll(requestId);
  } catch (error) {
    if (!(error instanceof SessionExpiredError)) {
      showAlert(error instanceof Error ? error.message : "Unable to track the request.");
      schedulePoll(requestId);
    }
  }
}

async function requestSignature(event) {
  event.preventDefault();

  if (!selectedDocument) return;

  if (!elements.documentViewed.checked || !elements.signatureConfirmed.checked) {
    showAlert("Both confirmations are required.");
    return;
  }

  clearAlert();
  elements.requestButton.disabled = true;

  try {
    const response = await apiFetch("/user/api/signature-requests", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        document_id: selectedDocument.document_id,
        document_viewed: true,
        signature_confirmed: true,
      }),
    });
    const payload = await readJson(response);

    if (!response.ok || !payload || typeof payload.request_id !== "string") {
      const detail = payload && typeof payload.detail === "string"
        ? payload.detail
        : "The request was denied.";
      throw new Error(detail);
    }

    displayConsentAccepted();
    await loadSessionAndDocuments();
    schedulePoll(payload.request_id);
  } catch (error) {
    if (!(error instanceof SessionExpiredError)) {
      showAlert(error instanceof Error ? error.message : "Unable to submit the request.");
      elements.requestButton.disabled = false;
    }
  }
}

async function logout(event) {
  event.preventDefault();
  elements.logoutButton.disabled = true;

  try {
    const response = await apiFetch("/user/logout", { method: "POST" });
    if (!response.ok) throw new Error("Unable to sign out.");
    csrfToken = "";
    window.location.replace("/user/login");
  } catch (error) {
    if (!(error instanceof SessionExpiredError)) {
      showAlert(error instanceof Error ? error.message : "Unable to sign out.");
      elements.logoutButton.disabled = false;
    }
  }
}

elements.consentForm.addEventListener("submit", requestSignature);
elements.cancelConsent.addEventListener("click", closeConsent);
elements.logoutForm.addEventListener("submit", logout);

loadSessionAndDocuments();
