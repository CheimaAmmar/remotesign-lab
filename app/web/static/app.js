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
};

let csrfToken = "";
let selectedFile = null;
let currentDocument = null;
let pollingTimer = null;
let pollingGeneration = 0;
const reachedStates = new Set();

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
  } catch (error) {
    if (!(error instanceof SessionExpiredError)) {
      showAlert("Impossible de vérifier la session. Vérifiez la connexion au serveur.");
      elements.sessionIndicator.textContent = "Session indisponible";
    }
  }
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

loadSession();
