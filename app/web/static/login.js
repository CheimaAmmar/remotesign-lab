"use strict";

const feedback = document.getElementById("login-feedback");
const query = new URLSearchParams(window.location.search);
const errorCode = query.get("error");

const errorMessages = {
  1: "The supplied key is incorrect.",
  invalid: "The supplied key is incorrect.",
  expired: "Your session has expired. Please sign in again.",
  session_expired: "Your session has expired. Please sign in again.",
  required: "Authentication is required to open this page.",
};

if (errorCode && feedback) {
  feedback.textContent = errorMessages[errorCode] || "Sign-in failed. Please try again.";
  feedback.hidden = false;
}
