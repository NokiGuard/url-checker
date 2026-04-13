"use strict";

// ---------------------------------------------------------------------------
// In-memory state
// ---------------------------------------------------------------------------

// url -> { timestamp: ms, data: vtResponseObject }
const analysisCache = new Map();

// windowId -> { url, resolve }
const pendingResults = new Map();

// Simple rate-limiter: track last request time
let lastRequestTime = 0;
const RATE_WINDOW_MS = 15500; // 4 req/min = 1 per 15s (add buffer)

// ---------------------------------------------------------------------------
// Startup: register context menu
// ---------------------------------------------------------------------------

browser.runtime.onInstalled.addListener(registerContextMenu);
registerContextMenu();

function registerContextMenu() {
  browser.contextMenus.removeAll().then(() => {
    browser.contextMenus.create({
      id: "check-and-sandbox",
      title: "Check and Open in Private Browser",
      contexts: ["link"]
    });
  });
}

// ---------------------------------------------------------------------------
// Context menu click handler
// ---------------------------------------------------------------------------

browser.contextMenus.onClicked.addListener(async (info, _tab) => {
  if (info.menuItemId !== "check-and-sandbox") return;

  const url = info.linkUrl;
  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
    notify("Unsupported URL", "Only http:// and https:// links are supported.");
    return;
  }

  // Show spinner badge
  setBadge("...", "#607d8b");

  try {
    const apiKey = await getApiKey();
    if (!apiKey) {
      notify("API Key Required", "Set your VirusTotal API key in the extension options.");
      browser.runtime.openOptionsPage();
      return;
    }

    const result = await getOrFetchAnalysis(url, apiKey);
    await openResultsWindow(url, result);
  } catch (err) {
    notify("Error", err.message || String(err));
  } finally {
    setBadge("", "");
  }
});

// ---------------------------------------------------------------------------
// VirusTotal API v3
// ---------------------------------------------------------------------------

function vtUrlId(url) {
  // VT v3 URL identifier = URL-safe base64 (no padding).
  // btoa() throws on characters outside Latin-1 (e.g. IDN domains in Unicode
  // form). Fall back to UTF-8 encoding so the extension never crashes silently
  // on international URLs.
  let b64;
  try {
    b64 = btoa(url);
  } catch {
    b64 = btoa(unescape(encodeURIComponent(url)));
  }
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function checkExistingReport(url, apiKey) {
  const id = vtUrlId(url);
  const resp = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
    headers: { "x-apikey": apiKey }
  });

  if (resp.status === 404) return null;
  if (resp.status === 429) throw new Error("VirusTotal rate limit reached. Please wait and try again.");
  if (resp.status === 401) throw new Error("Invalid VirusTotal API key. Check your settings.");
  if (!resp.ok) throw new Error(`VirusTotal error: ${resp.status} ${resp.statusText}`);

  return resp.json();
}

async function submitUrlForScan(url, apiKey) {
  const body = new FormData();
  body.append("url", url);

  const resp = await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: { "x-apikey": apiKey },
    body
  });

  if (resp.status === 429) throw new Error("VirusTotal rate limit reached. Please wait and try again.");
  if (resp.status === 401) throw new Error("Invalid VirusTotal API key. Check your settings.");
  if (!resp.ok) throw new Error(`VirusTotal submission error: ${resp.status} ${resp.statusText}`);

  const data = await resp.json();
  return pollAnalysis(data.data.id, apiKey);
}

async function pollAnalysis(analysisId, apiKey) {
  // Poll aggressively at first, then back off. Most analyses complete in 1–3s.
  const delays = [800, 1200, 1500, 1500, 2000, 2000, 2000, 2000, 2000, 2000];
  for (const delay of delays) {
    await sleep(delay);
    const resp = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { "x-apikey": apiKey }
    });
    if (!resp.ok) throw new Error(`VT poll error: ${resp.status}`);
    const data = await resp.json();
    if (data.data?.attributes?.status === "completed") return data;
  }
  throw new Error("VirusTotal analysis timed out. Try again later.");
}

async function getOrFetchAnalysis(url, apiKey) {
  const settings = await loadSettings();
  const cacheTTL = (settings.cacheHours || 24) * 3600 * 1000;

  // 1. Check in-memory cache
  const cached = analysisCache.get(url);
  if (cached && Date.now() - cached.timestamp < cacheTTL) {
    return { ...cached.data, fromCache: true };
  }

  // 2. Rate-limit gate
  await waitForRateLimit();

  // 3. Try existing VT report
  let result = await checkExistingReport(url, apiKey);

  if (result) {
    const lastDate = result.data?.attributes?.last_analysis_date;
    const ageMs = lastDate ? Date.now() - lastDate * 1000 : Infinity;
    if (ageMs > cacheTTL) {
      // VT's own report is stale — re-scan
      await waitForRateLimit();
      result = await submitUrlForScan(url, apiKey);
    }
  } else {
    // No report at all — submit new scan
    result = await submitUrlForScan(url, apiKey);
  }

  analysisCache.set(url, { timestamp: Date.now(), data: result });
  return result;
}

// ---------------------------------------------------------------------------
// Results popup window
// ---------------------------------------------------------------------------

async function openResultsWindow(url, analysisResult) {
  const randBytes = crypto.getRandomValues(new Uint8Array(16));
  const randHex   = Array.from(randBytes, b => b.toString(16).padStart(2, "0")).join("");
  const token     = `result_${Date.now()}_${randHex}`;

  await browser.storage.local.set({
    [token]: { url, analysisResult, ts: Date.now() }
  });

  const popupUrl = browser.runtime.getURL(`popup/results.html?token=${encodeURIComponent(token)}`);

  const win = await browser.windows.create({
    url: popupUrl,
    type: "popup",
    width: 540,
    height: 700
  });

  return new Promise((resolve) => {
    pendingResults.set(win.id, { url, resolve });
  });
}

// ---------------------------------------------------------------------------
// Message handler
// ---------------------------------------------------------------------------

browser.runtime.onMessage.addListener((message, sender) => {
  if (message.type === "GET_RESULT_DATA") {
    const { token } = message;
    return browser.storage.local.get(token).then(store => {
      browser.storage.local.remove(token);
      return store[token] || null;
    });
  }

  if (message.type === "USER_DECISION") {
    const windowId = sender.tab?.windowId;
    const pending = pendingResults.get(windowId);
    if (pending) {
      pendingResults.delete(windowId);
      const closePopup = () => browser.windows.remove(windowId).catch(() => {});
      if (message.decision === "open") {
        // Open sandbox window first, then close the popup
        openInPrivateBrowser(pending.url).then(closePopup);
      } else {
        closePopup();
      }
      pending.resolve(message.decision);
    }
    return Promise.resolve({ ok: true });
  }

  if (message.type === "CLEAR_CACHE") {
    analysisCache.clear();
    return Promise.resolve({ ok: true });
  }

  if (message.type === "GET_STATS") {
    return Promise.resolve({ cacheSize: analysisCache.size });
  }
});

// ---------------------------------------------------------------------------
// Private Browser: private browsing window
// ---------------------------------------------------------------------------

async function openInPrivateBrowser(url) {
  // Check if the extension is allowed to open private windows.
  // The user must enable "Use in Private Windows" for this extension in about:addons.
  const allowed = await browser.extension.isAllowedIncognitoAccess();
  if (!allowed) {
    notify(
      "Enable Private Window Access",
      "To open the Private Browser, go to about:addons → URL Checker → Allow in Private Windows."
    );
    return;
  }

  try {
    await browser.windows.create({
      url,
      incognito: true,
      type: "normal"
    });
  } catch (err) {
    notify("Private Browser Error", `Could not open private window: ${err.message}`);
  }
}

// ---------------------------------------------------------------------------
// Settings helpers
// ---------------------------------------------------------------------------

async function getApiKey() {
  // Migrate legacy plaintext key on first run after this update
  const legacy = await browser.storage.local.get("vtApiKey");
  if (legacy.vtApiKey) {
    const encrypted = await encryptApiKey(legacy.vtApiKey);
    await browser.storage.local.set({ vtApiKeyEncrypted: encrypted });
    await browser.storage.local.remove("vtApiKey");
  }

  const data = await browser.storage.local.get("vtApiKeyEncrypted");
  if (!data.vtApiKeyEncrypted) return "";
  try {
    return await decryptApiKey(data.vtApiKeyEncrypted);
  } catch {
    return "";
  }
}

async function loadSettings() {
  const data = await browser.storage.local.get("vtSettings");
  return {
    cacheHours: 24,
    threshSuspicious: 1,
    threshMalicious: 5,
    ...(data.vtSettings || {})
  };
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function waitForRateLimit() {
  return new Promise(resolve => {
    const check = () => {
      const elapsed = Date.now() - lastRequestTime;
      if (elapsed >= RATE_WINDOW_MS) {
        lastRequestTime = Date.now();
        resolve();
      } else {
        setTimeout(check, RATE_WINDOW_MS - elapsed);
      }
    };
    check();
  });
}

function setBadge(text, color) {
  browser.browserAction.setBadgeText({ text });
  if (color) browser.browserAction.setBadgeBackgroundColor({ color });
}

function notify(title, message) {
  browser.notifications.create({
    type: "basic",
    iconUrl: browser.runtime.getURL("icons/icon48.png"),
    title,
    message
  });
}
