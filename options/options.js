"use strict";

const SETTINGS_KEY = "vtSettings";

const DEFAULT_SETTINGS = {
  cacheHours:       24,
  threshSuspicious: 1,
  threshMalicious:  5
};

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

async function loadSettings() {
  const data = await browser.storage.local.get(SETTINGS_KEY);
  return { ...DEFAULT_SETTINGS, ...(data[SETTINGS_KEY] || {}) };
}

async function persistSettings(settings) {
  await browser.storage.local.set({
    [SETTINGS_KEY]: {
      cacheHours:       settings.cacheHours,
      threshSuspicious: settings.threshSuspicious,
      threshMalicious:  settings.threshMalicious
    }
  });
}

// ---------------------------------------------------------------------------
// Populate form on load
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", async () => {
  // Migrate legacy plaintext key if present
  const legacy = await browser.storage.local.get("vtApiKey");
  if (legacy.vtApiKey) {
    const encrypted = await encryptApiKey(legacy.vtApiKey);
    await browser.storage.local.set({ vtApiKeyEncrypted: encrypted });
    await browser.storage.local.remove("vtApiKey");
  }

  const settings = await loadSettings();
  const keyExists = await hasStoredApiKey();

  // Never render the key back into the input — show a placeholder instead
  const apiKeyEl = document.getElementById("api-key");
  if (keyExists) {
    apiKeyEl.placeholder = "API key saved — enter a new one to replace it";
  }

  document.getElementById("cache-hours").value       = settings.cacheHours;
  document.getElementById("thresh-suspicious").value = String(settings.threshSuspicious);
  document.getElementById("thresh-malicious").value  = String(settings.threshMalicious);

  await refreshStats();
});

// ---------------------------------------------------------------------------
// Save handler
// ---------------------------------------------------------------------------

document.getElementById("btn-save").addEventListener("click", async () => {
  const apiKeyEl  = document.getElementById("api-key");
  const apiKey    = apiKeyEl.value.trim();
  const cacheHours       = parseInt(document.getElementById("cache-hours").value) || 24;
  const threshSuspicious = parseInt(document.getElementById("thresh-suspicious").value) || 1;
  const threshMalicious  = parseInt(document.getElementById("thresh-malicious").value)  || 5;

  // Validate API key format (64 hex chars) if a new key was entered
  apiKeyEl.classList.remove("error");
  if (apiKey && !/^[A-Fa-f0-9]{64}$/.test(apiKey)) {
    apiKeyEl.classList.add("error");
    setStatus("API key looks invalid — expected 64 hexadecimal characters.", "err");
    return;
  }

  // Encrypt and store the key only if the user typed a new one
  if (apiKey) {
    const encrypted = await encryptApiKey(apiKey);
    await browser.storage.local.set({ vtApiKeyEncrypted: encrypted });
    // Clear the input after saving so the key is never visible at rest in the DOM
    apiKeyEl.value = "";
    apiKeyEl.placeholder = "API key saved — enter a new one to replace it";
  }

  await persistSettings({ cacheHours, threshSuspicious, threshMalicious });

  setStatus("Settings saved.", "ok");
  setTimeout(() => setStatus("", ""), 3000);
});

// ---------------------------------------------------------------------------
// Clear cache
// ---------------------------------------------------------------------------

document.getElementById("btn-clear-cache").addEventListener("click", async () => {
  // Remove any result_ prefixed entries from storage
  const allData = await browser.storage.local.get(null);
  const staleKeys = Object.keys(allData).filter(k => k.startsWith("result_"));
  if (staleKeys.length) await browser.storage.local.remove(staleKeys);

  // Tell background to clear in-memory cache
  try {
    await browser.runtime.sendMessage({ type: "CLEAR_CACHE" });
  } catch (_) {}

  document.getElementById("cache-count").textContent = "0";
  setStatus("Cache cleared.", "ok");
  setTimeout(() => setStatus("", ""), 2500);
});

// ---------------------------------------------------------------------------
// Stats refresh
// ---------------------------------------------------------------------------

async function refreshStats() {
  // Private window (incognito) access
  const incognitoEl = document.getElementById("incognito-status");
  const allowed = await browser.extension.isAllowedIncognitoAccess();
  if (allowed) {
    incognitoEl.textContent = "Enabled";
    incognitoEl.style.color = "#2e7d32";
  } else {
    incognitoEl.textContent = "Disabled — enable in about:addons";
    incognitoEl.style.color = "#b71c1c";
  }

  // Cache size (from background)
  try {
    const stats = await browser.runtime.sendMessage({ type: "GET_STATS" });
    document.getElementById("cache-count").textContent = stats?.cacheSize ?? 0;
  } catch (_) {
    document.getElementById("cache-count").textContent = "—";
  }
}

// ---------------------------------------------------------------------------
// UI helper
// ---------------------------------------------------------------------------

function setStatus(msg, type) {
  const el = document.getElementById("status");
  el.textContent  = msg;
  el.className    = type === "ok" ? "status-ok" : type === "err" ? "status-err" : "";
}
