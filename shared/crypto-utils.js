"use strict";

// ---------------------------------------------------------------------------
// API key encryption at rest — AES-256-GCM with PBKDF2-derived key
//
// The key is never stored in plaintext. Storage layout:
//   vtApiKeyEncrypted: { encrypted: base64, iv: base64 }
//   vtKeySalt:         base64  (random 16-byte salt, generated once)
//
// Derivation: PBKDF2(password=extensionId, salt=vtKeySalt, iter=200000, hash=SHA-256)
// The extension ID is not secret but it is consistent and means the encrypted
// blob is bound to this specific extension — not portable to other contexts.
// ---------------------------------------------------------------------------

const ALGO       = "AES-GCM";
const KEY_LENGTH = 256;
const PBKDF2_ITER = 200000;

// -- Buffer helpers ----------------------------------------------------------

function bufToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function b64ToBuf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

// -- Salt (one-time, persisted) ----------------------------------------------

async function getOrCreateSalt() {
  const stored = await browser.storage.local.get("vtKeySalt");
  if (stored.vtKeySalt) return b64ToBuf(stored.vtKeySalt);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  await browser.storage.local.set({ vtKeySalt: bufToB64(salt) });
  return salt.buffer;
}

// -- Key derivation ----------------------------------------------------------

async function deriveKey(salt) {
  const password   = new TextEncoder().encode(browser.runtime.id);
  const baseKey    = await crypto.subtle.importKey("raw", password, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" },
    baseKey,
    { name: ALGO, length: KEY_LENGTH },
    false,
    ["encrypt", "decrypt"]
  );
}

// -- Public API --------------------------------------------------------------

async function encryptApiKey(plaintext) {
  const salt      = await getOrCreateSalt();
  const key       = await deriveKey(salt);
  const iv        = crypto.getRandomValues(new Uint8Array(12));
  const encoded   = new TextEncoder().encode(plaintext);
  const encrypted = await crypto.subtle.encrypt({ name: ALGO, iv }, key, encoded);
  return { encrypted: bufToB64(encrypted), iv: bufToB64(iv) };
}

async function decryptApiKey(payload) {
  const salt      = await getOrCreateSalt();
  const key       = await deriveKey(salt);
  const iv        = b64ToBuf(payload.iv);
  const encrypted = b64ToBuf(payload.encrypted);
  const decrypted = await crypto.subtle.decrypt({ name: ALGO, iv }, key, encrypted);
  return new TextDecoder().decode(decrypted);
}

async function hasStoredApiKey() {
  const data = await browser.storage.local.get("vtApiKeyEncrypted");
  return !!data.vtApiKeyEncrypted;
}
