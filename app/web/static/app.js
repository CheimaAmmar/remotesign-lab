"use strict";

const STATES = Object.freeze({
  DOCUMENT_SELECTED: "DOCUMENT_SELECTED",
  UPLOADING: "UPLOADING",
  DOCUMENT_READY: "DOCUMENT_READY",
  WAITING_AUTHENTICATION: "WAITING_AUTHENTICATION",
  AUTHENTICATION_SUCCEEDED: "AUTHENTICATION_SUCCEEDED",
  SIGNATURE_SUCCEEDED: "SIGNATURE_SUCCEEDED",
  SIGNATURE_REFUSED: "SIGNATURE_REFUSED",
});

const STATE_COPY = Object.freeze({
  [STATES.DOCUMENT_SELECTED]: {
    title: "Document sélectionné",
    message: "Le PDF peut maintenant être envoyé au serveur.",
  },
  [STATES.UPLOADING]: {
    title: "Upload en cours",
    message: "Le document est transféré et son empreinte est calculée.",
  },
  [STATES.DOCUMENT_READY]: {
    title: "Document prêt",
    message: "En attente d’une demande de signature depuis l’espace utilisateur.",
  },
  [STATES.WAITING_AUTHENTICATION]: {
    title: "Attente d’authentification",
    message: "Demande créée par l’utilisateur. En attente d’authentification forte.",
  },
  [STATES.AUTHENTICATION_SUCCEEDED]: {
    title: "Authentification réussie",
    message: "L’identité a été validée. La signature est en cours.",
  },
  [STATES.SIGNATURE_SUCCEEDED]: {
    title: "Signature réussie",
    message: "Signature réussie.",
  },
  [STATES.SIGNATURE_REFUSED]: {
    title: "Signature refusée",
    message: "La demande de signature n’a pas été autorisée.",
  },
});

const TERMINAL_STATES = new Set([
  "SIGNED",
  "FAILED",
  "EXPIRED",
]);

const REQUEST_TO_UI_STATE = Object.freeze({
  PENDING: STATES.WAITING_AUTHENTICATION,
  CLAIMED: STATES.WAITING_AUTHENTICATION,
  AUTHENTICATING: STATES.WAITING_AUTHENTICATION,
  AUTHENTICATED: STATES.AUTHENTICATION_SUCCEEDED,
  SIGNED: STATES.SIGNATURE_SUCCEEDED,
  FAILED: STATES.SIGNATURE_REFUSED,
  EXPIRED: STATES.SIGNATURE_REFUSED,
});

const REQUEST_STATE_MESSAGES = Object.freeze({
  PENDING: "Demande créée par l’utilisateur. En attente d’authentification forte.",
  CLAIMED: "Demande récupérée par le terminal.",
  AUTHENTICATING: "Authentification forte en cours.",
  AUTHENTICATED: "Identité vérifiée. Signature cryptographique en cours.",
  SIGNED: "Signature réussie.",
  FAILED: "Signature refusée.",
  EXPIRED: "Demande expirée.",
});

const POLL_DELAY_MS = 1500;
const TERMINAL_POLL_DELAY_MS = 5000;
const MAX_DOCUMENT_SIZE = 20 * 1024 * 1024;

const elements = {
  alert: document.getElementById("global-alert"),
  sessionIndicator: document.getElementById("session-indicator"),
  logoutForm: document.getElementById("logout-form"),
  logoutButton: document.getElementById("logout-button"),
  uploadForm: document.getElementById("upload-form"),
  ownerSelect: document.getElementById("document-owner"),
  fileInput: document.getElementById("pdf-file"),
  fileSummary: document.getElementById("file-summary"),
  uploadButton: document.getElementById("upload-button"),
  documentPanel: document.getElementById("document-panel"),
  documentFilename: document.getElementById("document-filename"),
  documentSize: document.getElementById("document-size"),
  documentId: document.getElementById("document-id"),
  documentHash: document.getElementById("document-hash"),
  statusTitle: document.getElementById("status-title"),
  statusMessage: document.getElementById("status-message"),
  stateItems: Array.from(document.querySelectorAll("[data-state]")),
  queueStateReference: document.getElementById("queue-state-reference"),
  queueState: document.getElementById("queue-state"),
  requestReference: document.getElementById("request-reference"),
  auditIntegrity: document.getElementById("audit-integrity"),
  auditExport: document.getElementById("audit-export"),
  auditFilters: document.getElementById("audit-filters"),
  auditRows: document.getElementById("audit-rows"),
  auditPrevious: document.getElementById("audit-previous"),
  auditNext: document.getElementById("audit-next"),
  auditPage: document.getElementById("audit-page"),
  auditDetails: document.getElementById("audit-details"),
  auditDetailsContent: document.getElementById("audit-details-content"),
  auditDetailsClose: document.getElementById("audit-details-close"),
};

let csrfToken = "";
let selectedFile = null;
let currentDocument = null;
let pollingTimer = null;
let pollingGeneration = 0;
const reachedStates = new Set();
const AUDIT_PAGE_SIZE = 25;
let auditOffset = 0;
let auditTotal = 0;

class SessionExpiredError extends Error {}

function formatBytes(value) {
  if (!Number.isFinite(value) || value < 0) {
    return "—";
  }

  if (value < 1024) {
    return `${value} octet${value > 1 ? "s" : ""}`;
  }

  const units = ["Kio", "Mio", "Gio"];
  let amount = value / 1024;
  let unitIndex = 0;

  while (amount >= 1024 && unitIndex < units.length - 1) {
    amount /= 1024;
    unitIndex += 1;
  }

  return `${amount.toLocaleString("fr-FR", { maximumFractionDigits: 2 })} ${units[unitIndex]}`;
}

function showAlert(message, kind = "error") {
  elements.alert.textContent = message;
  elements.alert.className = `alert alert-${kind}`;
  elements.alert.hidden = false;
}

function clearAlert() {
  elements.alert.textContent = "";
  elements.alert.hidden = true;
}

function setState(state, message) {
  const copy = STATE_COPY[state];

  if (!copy) {
    return false;
  }

  reachedStates.add(state);

  if (state === STATES.AUTHENTICATION_SUCCEEDED || state === STATES.SIGNATURE_SUCCEEDED) {
    reachedStates.add(STATES.WAITING_AUTHENTICATION);
  }

  if (state === STATES.SIGNATURE_SUCCEEDED) {
    reachedStates.add(STATES.AUTHENTICATION_SUCCEEDED);
  }

  document.body.dataset.workflowState = state;
  elements.statusTitle.textContent = copy.title;
  elements.statusMessage.textContent = message || copy.message;

  for (const item of elements.stateItems) {
    const itemState = item.dataset.state;
    item.classList.toggle("is-current", itemState === state);
    item.classList.toggle("is-complete", reachedStates.has(itemState) && itemState !== state);
    item.classList.toggle("is-refused", itemState === STATES.SIGNATURE_REFUSED && itemState === state);

    if (itemState === state) {
      item.setAttribute("aria-current", "step");
    } else {
      item.removeAttribute("aria-current");
    }
  }

  return true;
}

function resetRequest() {
  pollingGeneration += 1;

  if (pollingTimer !== null) {
    window.clearTimeout(pollingTimer);
    pollingTimer = null;
  }

  elements.requestReference.textContent = "";
  elements.requestReference.hidden = true;
  elements.queueState.textContent = "—";
  elements.queueStateReference.hidden = true;
}

function resetDocument() {
  resetRequest();
  currentDocument = null;
  elements.documentPanel.hidden = true;
  elements.documentFilename.textContent = "—";
  elements.documentSize.textContent = "—";
  elements.documentId.textContent = "—";
  elements.documentHash.textContent = "—";
  reachedStates.clear();
}

function isPdf(file) {
  return Boolean(file && file.name.toLocaleLowerCase("fr-FR").endsWith(".pdf"));
}

function errorMessage(payload, fallback) {
  if (payload && typeof payload.detail === "string") {
    return payload.detail;
  }

  if (payload && typeof payload.message === "string") {
    return payload.message;
  }

  return fallback;
}

async function readJson(response) {
  try {
    return await response.json();
  } catch (_error) {
    return null;
  }
}

function redirectToLogin() {
  window.location.replace("/ui/login?error=session_expired");
}

async function apiFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");

  if (csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }

  const response = await fetch(url, {
    ...options,
    headers,
    credentials: "same-origin",
    cache: "no-store",
  });

  if (response.status === 401) {
    redirectToLogin();
    throw new SessionExpiredError("Session expired");
  }

  return response;
}

function displayDocument(documentData) {
  elements.documentFilename.textContent = String(documentData.filename);
  elements.documentSize.textContent = `${formatBytes(Number(documentData.size_bytes))} (${documentData.size_bytes} octets)`;
  elements.documentId.textContent = String(documentData.document_id);
  elements.documentHash.textContent = String(documentData.document_hash);
  elements.documentPanel.hidden = false;
}

function validateDocumentResponse(payload) {
  return Boolean(
    payload
      && typeof payload.filename === "string"
      && Number.isFinite(Number(payload.size_bytes))
      && typeof payload.document_id === "string"
      && typeof payload.document_hash === "string"
  );
}

function updateSelectedDocumentUrl(documentId) {
  const url = new URL(window.location.href);

  if (documentId) {
    url.searchParams.set("document_id", documentId);
  } else {
    url.searchParams.delete("document_id");
  }

  window.history.replaceState({}, "", `${url.pathname}${url.search}`);
}

async function restoreDocumentFromUrl() {
  const documentId = new URL(window.location.href).searchParams.get("document_id");

  if (!documentId) {
    return;
  }

  const response = await apiFetch(`/ui/api/documents/${encodeURIComponent(documentId)}`, {
    method: "GET",
  });
  const payload = await readJson(response);

  if (!response.ok || !validateDocumentResponse(payload)) {
    updateSelectedDocumentUrl(null);
    throw new Error(errorMessage(payload, "Impossible de restaurer le document sélectionné."));
  }

  currentDocument = payload;
  displayDocument(payload);
  setState(
    STATES.DOCUMENT_READY,
    "En attente d’une demande de signature depuis l’espace utilisateur.",
  );

  if (typeof payload.user_id === "string") {
    elements.ownerSelect.value = payload.user_id;
  }

  startDocumentPolling(payload.document_id);
}

async function loadSession() {
  try {
    const response = await fetch("/ui/api/session", {
      method: "GET",
      headers: { Accept: "application/json" },
      credentials: "same-origin",
      cache: "no-store",
    });

    if (!response.ok) {
      redirectToLogin();
      return;
    }

    const payload = await readJson(response);

    if (!payload || payload.authenticated !== true || typeof payload.csrf_token !== "string" || !payload.csrf_token) {
      redirectToLogin();
      return;
    }

    csrfToken = payload.csrf_token;
    elements.sessionIndicator.textContent = "Session sécurisée active";
    elements.logoutButton.disabled = false;
    await loadAssignableUsers();
    await restoreDocumentFromUrl();
    await Promise.all([loadAuditEvents(), loadAuditIntegrity()]);
  } catch (error) {
    if (!(error instanceof SessionExpiredError)) {
      showAlert("Impossible de vérifier la session. Vérifiez la connexion au serveur.");
      elements.sessionIndicator.textContent = "Session indisponible";
    }
  }
}

function auditQueryParameters(includePagination = true) {
  const parameters = new URLSearchParams();
  const formData = new FormData(elements.auditFilters);

  for (const [name, rawValue] of formData.entries()) {
    const value = String(rawValue).trim();
    if (value) {
      parameters.set(name, value);
    }
  }

  if (includePagination) {
    parameters.set("limit", String(AUDIT_PAGE_SIZE));
    parameters.set("offset", String(auditOffset));
  }

  return parameters;
}

function shortIdentifier(value) {
  if (typeof value !== "string" || !value) {
    return "—";
  }
  return value.length > 13 ? `${value.slice(0, 8)}…` : value;
}

function auditCell(row, value, className = "") {
  const cell = document.createElement("td");
  cell.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
  if (className) {
    cell.className = className;
  }
  row.append(cell);
}

async function showAuditDetails(eventId) {
  const response = await apiFetch(`/ui/api/audit/${encodeURIComponent(eventId)}`, { method: "GET" });
  const payload = await readJson(response);

  if (!response.ok || !payload) {
    throw new Error(errorMessage(payload, "Impossible de charger l’événement d’audit."));
  }

  elements.auditDetailsContent.textContent = JSON.stringify(payload, null, 2);
  elements.auditDetails.hidden = false;
  elements.auditDetails.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function renderAuditEvents(payload) {
  elements.auditRows.replaceChildren();
  const items = payload && Array.isArray(payload.items) ? payload.items : [];
  auditTotal = Number(payload && payload.total) || 0;

  if (items.length === 0) {
    const row = document.createElement("tr");
    auditCell(row, "Aucun événement pour ces filtres.");
    row.firstElementChild.colSpan = 11;
    elements.auditRows.append(row);
  }

  for (const item of items) {
    const row = document.createElement("tr");
    row.tabIndex = 0;
    row.className = "audit-row";
    row.title = "Afficher les détails";
    const open = () => showAuditDetails(item.id).catch((error) => showAlert(error.message));
    row.addEventListener("click", open);
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        open();
      }
    });
    auditCell(row, item.created_at ? formatDateTime(item.created_at) : "—");
    auditCell(row, item.category);
    auditCell(row, item.event_type, "monospace");
    auditCell(row, item.actor_type);
    auditCell(row, shortIdentifier(item.user_id), "monospace");
    auditCell(row, shortIdentifier(item.device_id), "monospace");
    auditCell(row, shortIdentifier(item.document_id), "monospace");
    auditCell(row, shortIdentifier(item.signature_request_id), "monospace");
    auditCell(row, shortIdentifier(item.signature_id), "monospace");
    auditCell(row, item.outcome);
    auditCell(row, item.failure_code, "monospace");
    elements.auditRows.append(row);
  }

  const first = auditTotal === 0 ? 0 : auditOffset + 1;
  const last = Math.min(auditOffset + items.length, auditTotal);
  elements.auditPage.textContent = `${first}–${last} sur ${auditTotal}`;
  elements.auditPrevious.disabled = auditOffset === 0;
  elements.auditNext.disabled = auditOffset + items.length >= auditTotal;
  const exportParameters = auditQueryParameters(false);
  elements.auditExport.href = `/ui/api/audit/export.csv?${exportParameters.toString()}`;
}

async function loadAuditEvents() {
  const parameters = auditQueryParameters(true);
  const response = await apiFetch(`/ui/api/audit?${parameters.toString()}`, { method: "GET" });
  const payload = await readJson(response);

  if (!response.ok || !payload || !Array.isArray(payload.items)) {
    throw new Error(errorMessage(payload, "Impossible de charger le journal d’audit."));
  }

  renderAuditEvents(payload);
}

async function loadAuditIntegrity() {
  const response = await apiFetch("/ui/api/audit/integrity", { method: "GET" });
  const payload = await readJson(response);

  if (!response.ok || !payload) {
    elements.auditIntegrity.textContent = "Vérification indisponible";
    elements.auditIntegrity.className = "audit-integrity is-invalid";
    return;
  }

  elements.auditIntegrity.textContent = payload.valid
    ? `Chaîne valide · ${payload.chained_events} événements scellés`
    : `Chaîne invalide · événement ${shortIdentifier(payload.first_invalid_event_id)}`;
  elements.auditIntegrity.className = `audit-integrity ${payload.valid ? "is-valid" : "is-invalid"}`;
}

async function loadAssignableUsers() {
  const response = await apiFetch("/ui/api/users", { method: "GET" });
  const payload = await readJson(response);

  if (!response.ok || !payload || !Array.isArray(payload.users)) {
    throw new Error("Impossible de charger les utilisateurs actifs.");
  }

  for (const user of payload.users) {
    const option = document.createElement("option");
    option.value = String(user.user_id);
    option.textContent = user.email
      ? `${user.full_name} · ${user.email}`
      : `${user.full_name} · accès Web non configuré`;
    elements.ownerSelect.append(option);
  }

  const hasUsers = payload.users.length > 0;
  elements.ownerSelect.disabled = !hasUsers;
  elements.fileInput.disabled = !hasUsers;

  if (!hasUsers) {
    showAlert("Créez d’abord un utilisateur actif depuis l’API ADMIN.");
  }
}

function handleFileSelection() {
  clearAlert();
  resetDocument();
  updateSelectedDocumentUrl(null);
  selectedFile = elements.fileInput.files && elements.fileInput.files[0]
    ? elements.fileInput.files[0]
    : null;

  if (!selectedFile) {
    elements.fileSummary.textContent = "Aucun document sélectionné";
    elements.uploadButton.disabled = true;
    elements.statusTitle.textContent = "En attente d’un document";
    elements.statusMessage.textContent = "Choisissez un PDF pour commencer.";
    return;
  }

  elements.fileSummary.textContent = `${selectedFile.name} · ${formatBytes(selectedFile.size)}`;

  if (!isPdf(selectedFile)) {
    elements.uploadButton.disabled = true;
    showAlert("Le fichier sélectionné doit porter l’extension .pdf.");
    return;
  }

  if (selectedFile.size === 0) {
    elements.uploadButton.disabled = true;
    showAlert("Le document sélectionné est vide.");
    return;
  }

  if (selectedFile.size > MAX_DOCUMENT_SIZE) {
    elements.uploadButton.disabled = true;
    showAlert("Le document dépasse la limite de 20 Mio.");
    return;
  }

  elements.uploadButton.disabled = false;
  setState(STATES.DOCUMENT_SELECTED);
}

async function uploadDocument(event) {
  event.preventDefault();

  if (!selectedFile || !isPdf(selectedFile)) {
    showAlert("Sélectionnez d’abord un fichier PDF valide.");
    return;
  }

  if (!elements.ownerSelect.value) {
    showAlert("Sélectionnez le propriétaire du document.");
    return;
  }

  clearAlert();
  setState(STATES.UPLOADING);
  elements.fileInput.disabled = true;
  elements.ownerSelect.disabled = true;
  elements.uploadButton.disabled = true;

  const formData = new FormData();
  formData.append("file", selectedFile, selectedFile.name);
  formData.append("user_id", elements.ownerSelect.value);

  try {
    const response = await apiFetch("/ui/api/documents/upload", {
      method: "POST",
      body: formData,
    });
    const payload = await readJson(response);

    if (!response.ok) {
      throw new Error(errorMessage(payload, "Le document n’a pas pu être uploadé."));
    }

    if (!validateDocumentResponse(payload)) {
      throw new Error("La réponse du serveur pour ce document est incomplète.");
    }

    currentDocument = payload;
    displayDocument(payload);
    setState(STATES.DOCUMENT_READY, typeof payload.message === "string" ? payload.message : undefined);
    updateSelectedDocumentUrl(payload.document_id);
    startDocumentPolling(payload.document_id);
  } catch (error) {
    if (!(error instanceof SessionExpiredError)) {
      showAlert(error instanceof Error ? error.message : "L’upload a échoué.");
      reachedStates.delete(STATES.UPLOADING);
      setState(STATES.DOCUMENT_SELECTED, "L’upload a échoué. Vous pouvez réessayer.");
      elements.uploadButton.disabled = false;
    }
  } finally {
    elements.fileInput.disabled = false;
    elements.ownerSelect.disabled = false;
  }
}

function scheduleDocumentPoll(documentId, generation, delay = POLL_DELAY_MS) {
  pollingTimer = window.setTimeout(() => {
    pollDocumentSignatureRequest(documentId, generation);
  }, delay);
}

function applyRequestState(payload) {
  if (!payload || typeof payload.state !== "string") {
    return false;
  }

  const uiState = REQUEST_TO_UI_STATE[payload.state];

  if (!uiState) {
    return false;
  }

  elements.queueState.textContent = payload.state;
  elements.queueStateReference.hidden = false;

  return setState(
    uiState,
    REQUEST_STATE_MESSAGES[payload.state]
      || (typeof payload.message === "string" ? payload.message : undefined),
  );
}

function formatDateTime(value) {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString("fr-FR");
}

function displayRequestMetadata(payload) {
  const details = [`Demande : ${payload.request_id}`];

  if (typeof payload.signature_id === "string") {
    details.push(`Signature : ${payload.signature_id}`);
  }

  if (typeof payload.signed_at === "string") {
    details.push(`Date : ${formatDateTime(payload.signed_at)}`);
  }

  if (typeof payload.algorithm === "string") {
    details.push(`Algorithme : ${payload.algorithm}`);
  }

  if (typeof payload.pades_profile === "string") {
    details.push(`Profil : ${payload.pades_profile}`);
  }

  if (typeof payload.signer_name === "string") {
    details.push(`Signataire : ${payload.signer_name}`);
  }

  if (typeof payload.certificate_subject === "string") {
    details.push(`Certificat : ${payload.certificate_subject}`);
  }

  if (typeof payload.timestamp_time === "string") {
    details.push(`Horodatage : ${formatDateTime(payload.timestamp_time)}`);
  }

  if (typeof payload.tsa_certificate_subject === "string") {
    details.push(`TSA : ${payload.tsa_certificate_subject}`);
  }

  elements.requestReference.textContent = details.join("\n");
  elements.requestReference.hidden = false;
}

function startDocumentPolling(documentId) {
  resetRequest();
  const generation = pollingGeneration;
  pollDocumentSignatureRequest(documentId, generation);
}

async function pollDocumentSignatureRequest(documentId, generation) {
  if (generation !== pollingGeneration) {
    return;
  }

  try {
    const response = await apiFetch(`/ui/api/documents/${encodeURIComponent(documentId)}/signature-request`, {
      method: "GET",
    });

    if (response.status === 204) {
      clearAlert();
      elements.queueState.textContent = "—";
      elements.queueStateReference.hidden = true;
      elements.requestReference.textContent = "";
      elements.requestReference.hidden = true;
      setState(
        STATES.DOCUMENT_READY,
        "En attente d’une demande de signature depuis l’espace utilisateur.",
      );
      scheduleDocumentPoll(documentId, generation);
      return;
    }

    const payload = await readJson(response);

    if (!response.ok) {
      throw new Error(errorMessage(payload, "Impossible de lire l’état de la demande."));
    }

    if (!applyRequestState(payload)) {
      throw new Error("Le serveur a renvoyé un état de signature inconnu.");
    }

    clearAlert();
    displayRequestMetadata(payload);

    if (TERMINAL_STATES.has(payload.state)) {
      scheduleDocumentPoll(documentId, generation, TERMINAL_POLL_DELAY_MS);
      return;
    }

    scheduleDocumentPoll(documentId, generation);
  } catch (error) {
    if (error instanceof SessionExpiredError || generation !== pollingGeneration) {
      return;
    }

    showAlert(error instanceof Error ? error.message : "Le suivi de la demande a échoué.");
    scheduleDocumentPoll(documentId, generation, TERMINAL_POLL_DELAY_MS);
  }
}

async function logout(event) {
  event.preventDefault();
  elements.logoutButton.disabled = true;
  resetRequest();

  try {
    const response = await apiFetch("/ui/logout", { method: "POST" });

    if (!response.ok) {
      const payload = await readJson(response);
      throw new Error(errorMessage(payload, "La déconnexion a échoué."));
    }

    csrfToken = "";
    window.location.replace("/ui/login");
  } catch (error) {
    if (!(error instanceof SessionExpiredError)) {
      showAlert(error instanceof Error ? error.message : "La déconnexion a échoué.");
      elements.logoutButton.disabled = false;
    }
  }
}

elements.fileInput.addEventListener("change", handleFileSelection);
elements.uploadForm.addEventListener("submit", uploadDocument);
elements.logoutForm.addEventListener("submit", logout);
elements.auditFilters.addEventListener("submit", (event) => {
  event.preventDefault();
  auditOffset = 0;
  loadAuditEvents().catch((error) => showAlert(error.message));
});
elements.auditPrevious.addEventListener("click", () => {
  auditOffset = Math.max(0, auditOffset - AUDIT_PAGE_SIZE);
  loadAuditEvents().catch((error) => showAlert(error.message));
});
elements.auditNext.addEventListener("click", () => {
  if (auditOffset + AUDIT_PAGE_SIZE < auditTotal) {
    auditOffset += AUDIT_PAGE_SIZE;
    loadAuditEvents().catch((error) => showAlert(error.message));
  }
});
elements.auditDetailsClose.addEventListener("click", () => {
  elements.auditDetails.hidden = true;
  elements.auditDetailsContent.textContent = "";
});

loadSession();
