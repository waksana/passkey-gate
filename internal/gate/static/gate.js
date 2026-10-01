"use strict";

const root = document.getElementById("gate");
const statusNode = document.getElementById("status");
const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";

function decodeBase64URL(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const raw = atob(padded);
  return Uint8Array.from(raw, character => character.charCodeAt(0));
}

function encodeBase64URL(value) {
  const bytes = new Uint8Array(value);
  let raw = "";
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeCreation(options) {
  options.publicKey.challenge = decodeBase64URL(options.publicKey.challenge);
  options.publicKey.user.id = decodeBase64URL(options.publicKey.user.id);
  for (const item of options.publicKey.excludeCredentials || []) item.id = decodeBase64URL(item.id);
  return options;
}

function decodeAssertion(options) {
  options.publicKey.challenge = decodeBase64URL(options.publicKey.challenge);
  for (const item of options.publicKey.allowCredentials || []) item.id = decodeBase64URL(item.id);
  return options;
}

function credentialJSON(credential) {
  const response = {
    clientDataJSON: encodeBase64URL(credential.response.clientDataJSON),
  };
  if ("attestationObject" in credential.response) {
    response.attestationObject = encodeBase64URL(credential.response.attestationObject);
    response.transports = credential.response.getTransports?.() || [];
    const authenticatorData = credential.response.getAuthenticatorData?.();
    const publicKey = credential.response.getPublicKey?.();
    const algorithm = credential.response.getPublicKeyAlgorithm?.();
    if (authenticatorData) response.authenticatorData = encodeBase64URL(authenticatorData);
    if (publicKey) response.publicKey = encodeBase64URL(publicKey);
    if (algorithm !== undefined) response.publicKeyAlgorithm = algorithm;
  } else {
    response.authenticatorData = encodeBase64URL(credential.response.authenticatorData);
    response.signature = encodeBase64URL(credential.response.signature);
    response.userHandle = credential.response.userHandle
      ? encodeBase64URL(credential.response.userHandle)
      : "";
  }
  return {
    id: credential.id,
    rawId: encodeBase64URL(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response,
  };
}

async function request(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (csrf) headers.set("X-CSRF-Token", csrf);
  const response = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    ...options,
    headers,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || "Request failed");
  return payload;
}

function message(value) {
  if (statusNode) statusNode.textContent = value;
}

async function authenticate(optionsURL, finishURL) {
  const options = decodeAssertion(await request(optionsURL));
  const credential = await navigator.credentials.get(options);
  if (!credential) throw new Error("No passkey was selected");
  return request(finishURL, {
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(credentialJSON(credential)),
  });
}

async function register(label) {
  const options = decodeCreation(await request(
    `/_gate/register/options?label=${encodeURIComponent(label)}`,
  ));
  const credential = await navigator.credentials.create(options);
  if (!credential) throw new Error("No passkey was created");
  return request("/_gate/register/finish", {
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(credentialJSON(credential)),
  });
}

async function login() {
  const retry = document.getElementById("retry");
  retry.hidden = true;
  retry.disabled = true;
  message("正在验证 Passkey…");
  try {
    const destination = root.dataset.return || "/";
    const result = await authenticate(
      `/_gate/auth/options?return=${encodeURIComponent(destination)}`,
      "/_gate/auth/finish",
    );
    location.assign(result.redirect);
  } catch {
    message("验证未完成");
    retry.hidden = false;
    retry.disabled = false;
  }
}

async function bootstrap() {
  const button = document.getElementById("register");
  button.disabled = true;
  try {
    const label = document.getElementById("label").value.trim();
    const result = await register(label);
    location.assign(result.redirect);
  } catch (error) {
    message(error.message || "Passkey registration failed");
    button.disabled = false;
  }
}

async function claimBootstrap() {
  const button = document.getElementById("register");
  try {
    const fragment = new URLSearchParams(location.hash.slice(1));
    const token = fragment.get("token");
    if (location.hash) history.replaceState(null, "", location.pathname);
    if (token) {
      await request("/_gate/bootstrap/claim", {
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({token}),
      });
    } else if (root.dataset.authorized !== "true") {
      throw new Error("Open a fresh bootstrap link generated over SSH.");
    }
    message("");
    button.disabled = false;
  } catch (error) {
    message(error.message || "Bootstrap link is invalid or expired");
  }
}

let freshUntil = Number(root?.dataset.freshUntil || 0);

async function ensureFresh() {
  if (Date.now() + 1000 < freshUntil) return;
  message("Verify a passkey to continue.");
  const result = await authenticate("/_gate/fresh/options", "/_gate/fresh/finish");
  freshUntil = result.fresh_until;
  message("");
}

async function manageAction(action) {
  try {
    await action();
  } catch (error) {
    message(error.message || "Operation failed");
  }
}

function manage() {
  document.getElementById("register").addEventListener("click", () => manageAction(async () => {
    await ensureFresh();
    const input = document.getElementById("label");
    const result = await register(input.value.trim());
    location.assign(result.redirect);
  }));

  document.querySelectorAll(".rename").forEach(button => {
    button.addEventListener("click", () => manageAction(async () => {
      const item = button.closest("[data-credential-id]");
      const current = item.querySelector(".credential-label").textContent;
      const label = prompt("Passkey name", current);
      if (label === null || label.trim() === current) return;
      await request(`/_gate/credentials/${item.dataset.credentialId}/rename`, {
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({label: label.trim()}),
      });
      location.reload();
    }));
  });

  document.querySelectorAll(".delete").forEach(button => {
    button.addEventListener("click", () => manageAction(async () => {
      if (!confirm("Delete this passkey and revoke every active session and device?")) return;
      await ensureFresh();
      const item = button.closest("[data-credential-id]");
      const result = await request(`/_gate/credentials/${item.dataset.credentialId}/delete`);
      location.assign(result.redirect);
    }));
  });

  document.getElementById("revoke").addEventListener("click", () => manageAction(async () => {
    if (!confirm("Revoke every active session and device?")) return;
    const result = await request("/_gate/sessions/revoke");
    location.assign(result.redirect);
  }));

  document.getElementById("logout").addEventListener("click", () => manageAction(async () => {
    const result = await request("/_gate/logout");
    location.assign(result.redirect);
  }));
  document.querySelectorAll(".device-revoke").forEach(button => {
    button.addEventListener("click", () => manageAction(async () => {
      if (!confirm("Revoke this device's site access? Existing streams may remain connected.")) return;
      await request(`/_gate/devices/${button.dataset.deviceId}/revoke`);
      location.reload();
    }));
  });
}

function deviceApproval() {
  const approve = document.getElementById("device-approve");
  const deny = document.getElementById("device-deny");
  if (!approve || !deny) return;
  const code = root.dataset.userCode;
  approve.addEventListener("click", () => manageAction(async () => {
    approve.disabled = true;
    deny.disabled = true;
    try {
      const confirmed = document.getElementById("confirm-code").value.trim();
      await authenticate(
        `/_gate/device/options?user_code=${encodeURIComponent(code)}&confirm_code=${encodeURIComponent(confirmed)}`,
        "/_gate/device/finish",
      );
      message("Device approved. Return to your device.");
    } catch (error) {
      approve.disabled = false;
      deny.disabled = false;
      throw error;
    }
  }));
  deny.addEventListener("click", () => manageAction(async () => {
    await request(`/_gate/device/deny?user_code=${encodeURIComponent(code)}`);
    approve.disabled = true;
    deny.disabled = true;
    message("Device denied.");
  }));
}

if (root?.dataset.page === "login") {
  document.getElementById("retry").addEventListener("click", login);
  login();
} else if (root?.dataset.page === "bootstrap") {
  document.getElementById("register").addEventListener("click", bootstrap);
  claimBootstrap();
} else if (root?.dataset.page === "manage") {
  manage();
} else if (root?.dataset.page === "device") {
  deviceApproval();
}
