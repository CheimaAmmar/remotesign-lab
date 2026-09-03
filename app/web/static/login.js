"use strict";

const feedback = document.getElementById("login-feedback");
const query = new URLSearchParams(window.location.search);
const errorCode = query.get("error");

const errorMessages = {
  1: "La clé fournie est incorrecte.",
  invalid: "La clé fournie est incorrecte.",
  expired: "Votre session a expiré. Veuillez vous authentifier à nouveau.",
  session_expired: "Votre session a expiré. Veuillez vous authentifier à nouveau.",
  required: "Une authentification est nécessaire pour ouvrir cette page.",
};

if (errorCode && feedback) {
  feedback.textContent = errorMessages[errorCode] || "La connexion a échoué. Veuillez réessayer.";
  feedback.hidden = false;
}
