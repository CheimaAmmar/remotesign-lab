"use strict";

const feedback = document.getElementById("login-feedback");
const errorCode = new URLSearchParams(window.location.search).get("error");

const messages = {
  invalid: "Incorrect email address or password.",
  expired: "Your session has expired. Please sign in again.",
  session_expired: "Your session has expired. Please sign in again.",
  required: "User sign-in is required.",
};

if (errorCode && feedback) {
  feedback.textContent = messages[errorCode] || "Sign-in failed.";
  feedback.hidden = false;
}
