"use strict";

const feedback = document.getElementById("login-feedback");
const errorCode = new URLSearchParams(window.location.search).get("error");

const messages = {
  invalid: "Adresse e-mail ou mot de passe incorrect.",
  expired: "Votre session a expiré. Veuillez vous reconnecter.",
  session_expired: "Votre session a expiré. Veuillez vous reconnecter.",
  required: "Une connexion utilisateur est nécessaire.",
};

if (errorCode && feedback) {
  feedback.textContent = messages[errorCode] || "La connexion a échoué.";
  feedback.hidden = false;
}
