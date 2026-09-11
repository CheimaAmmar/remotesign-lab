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
    title: "En attente de votre authentification forte",
    message: "Authentifiez-vous sur le terminal ESP32.",
  },
  CLAIMED: {
    title: "Terminal connecté",
    message: "La demande a été récupérée par le terminal ESP32.",
  },
  AUTHENTICATING: {
    title: "Authentification en cours",
    message: "Le terminal vérifie votre RFID et votre empreinte.",
  },
  AUTHENTICATED: {
    title: "Identité vérifiée",
    message: "Signature cryptographique en cours.",
  },
  SIGNED: {
    title: "Document signé avec succès",
    message: "La signature cryptographique est terminée.",
  },
  FAILED: {
    title: "Signature refusée",
    message: "Vous pouvez recommencer avec un nouveau consentement.",
  },
  EXPIRED: {
    title: "Demande expirée",
    message: "Vous pouvez recommencer avec un nouveau consentement.",
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
    : date.toLocaleString("fr-FR");
}

function formatBytes(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount)) return "—";
  if (amount < 1024) return `${amount} octets`;
  if (amount < 1024 * 1024) return `${(amount / 1024).toFixed(1)} Kio`;
  return `${(amount / (1024 * 1024)).toFixed(1)} Mio`;
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
    empty.textContent = "Aucun document ne vous est actuellement attribué.";
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
    state.textContent = presentation ? presentation.title : "Aucune demande";
    const stateMessage = document.createElement("p");
    stateMessage.className = "user-request-message";
    stateMessage.textContent = presentation
      ? presentation.message
      : "Aucune demande de signature active.";
    details.append(title, meta, state, stateMessage);

    if (item.request && item.request.state === "SIGNED") {
      const signatureMeta = document.createElement("p");
      signatureMeta.className = "user-signature-meta";
      const metadata = [];
      if (item.request.signer_name) metadata.push(`Signataire : ${item.request.signer_name}`);
      if (item.request.signed_at) metadata.push(`Date de signature : ${formatDate(item.request.signed_at)}`);
      if (item.request.signature_id) metadata.push(`Signature : ${item.request.signature_id}`);
      if (item.request.algorithm) metadata.push(String(item.request.algorithm));
      if (item.request.pades_profile) metadata.push(`Profil : ${item.request.pades_profile}`);
      if (item.request.certificate_subject) metadata.push(`Certificat : ${item.request.certificate_subject}`);
      if (item.request.timestamp_time) metadata.push(`Horodatage : ${formatDate(item.request.timestamp_time)}`);
      if (item.request.tsa_certificate_subject) metadata.push(`TSA : ${item.request.tsa_certificate_subject}`);
      signatureMeta.textContent = metadata.join(" · ");
      if (metadata.length) details.append(signatureMeta);
    }

    const actions = document.createElement("div");
    actions.className = "user-document-actions";
    const view = document.createElement("a");
    view.className = "button button-quiet";
    view.textContent = "Voir le document";
    view.href = `/user/documents/${encodeURIComponent(item.document_id)}/view`;
    view.target = "_blank";
    view.rel = "noopener";

    actions.append(view);

    if (item.request && item.request.state === "SIGNED") {
      const signedBadge = document.createElement("span");
      signedBadge.className = "user-state user-state-signed";
      signedBadge.textContent = "Signé";
      actions.append(signedBadge);

      if (item.request.signed_document_available === true) {
        const download = document.createElement("a");
        download.className = "button button-primary";
        download.textContent = "Télécharger le PDF signé";
        download.href = `/user/documents/${encodeURIComponent(item.document_id)}/signed`;
        actions.append(download);
      }
    } else if (!(item.request && ACTIVE_STATES.has(item.request.state))) {
      const sign = document.createElement("button");
      sign.className = "button button-accent";
      sign.type = "button";
      sign.textContent = "Signer ce document";
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
    elements.sessionIndicator.textContent = "Session utilisateur active";
    elements.logoutButton.disabled = false;

    const documentsResponse = await apiFetch("/user/api/documents");
    const payload = await readJson(documentsResponse);

    if (!documentsResponse.ok || !payload || !Array.isArray(payload.documents)) {
      throw new Error("Impossible de charger vos documents.");
    }

    scheduleDocumentsRefresh(renderDocuments(payload.documents));
  } catch (error) {
    if (!(error instanceof SessionExpiredError)) {
      showAlert(error instanceof Error ? error.message : "Chargement impossible.");
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
    : "État inconnu";
  const message = presentation
    ? presentation.message
    : "État mis à jour.";
  const metadata = [];

  if (payload.state === "SIGNED") {
    if (payload.filename) metadata.push(String(payload.filename));
    if (payload.signer_name) metadata.push(`Signataire : ${payload.signer_name}`);
    if (payload.signed_at) metadata.push(`Date de signature : ${formatDate(payload.signed_at)}`);
    if (payload.signature_id) metadata.push(`Signature : ${payload.signature_id}`);
    if (payload.algorithm) metadata.push(String(payload.algorithm));
    if (payload.pades_profile) metadata.push(`Profil : ${payload.pades_profile}`);
    if (payload.certificate_subject) metadata.push(`Certificat : ${payload.certificate_subject}`);
    if (payload.timestamp_time) metadata.push(`Horodatage : ${formatDate(payload.timestamp_time)}`);
    if (payload.tsa_certificate_subject) metadata.push(`TSA : ${payload.tsa_certificate_subject}`);
  }

  elements.requestMessage.textContent = metadata.length
    ? `${message} ${metadata.join(" · ")}`
    : message;
}

function displayConsentAccepted() {
  elements.consentForm.hidden = true;
  elements.requestStatus.hidden = false;
  elements.requestState.textContent = "Authentification forte requise";
  elements.requestMessage.textContent = (
    "Votre demande de signature a été enregistrée.\n"
    + "Authentifiez-vous maintenant sur votre terminal ESP32."
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
      throw new Error("Impossible de suivre la demande.");
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
      showAlert(error instanceof Error ? error.message : "Suivi impossible.");
      schedulePoll(requestId);
    }
  }
}

async function requestSignature(event) {
  event.preventDefault();

  if (!selectedDocument) return;

  if (!elements.documentViewed.checked || !elements.signatureConfirmed.checked) {
    showAlert("Les deux confirmations sont obligatoires.");
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
        : "La demande a été refusée.";
      throw new Error(detail);
    }

    displayConsentAccepted();
    await loadSessionAndDocuments();
    schedulePoll(payload.request_id);
  } catch (error) {
    if (!(error instanceof SessionExpiredError)) {
      showAlert(error instanceof Error ? error.message : "Demande impossible.");
      elements.requestButton.disabled = false;
    }
  }
}

async function logout(event) {
  event.preventDefault();
  elements.logoutButton.disabled = true;

  try {
    const response = await apiFetch("/user/logout", { method: "POST" });
    if (!response.ok) throw new Error("Déconnexion impossible.");
    csrfToken = "";
    window.location.replace("/user/login");
  } catch (error) {
    if (!(error instanceof SessionExpiredError)) {
      showAlert(error instanceof Error ? error.message : "Déconnexion impossible.");
      elements.logoutButton.disabled = false;
    }
  }
}

elements.consentForm.addEventListener("submit", requestSignature);
elements.cancelConsent.addEventListener("click", closeConsent);
elements.logoutForm.addEventListener("submit", logout);

loadSessionAndDocuments();
