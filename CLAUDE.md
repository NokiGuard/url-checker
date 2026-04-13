# CLAUDE.md — URL Checker

Firefox browser extension (Manifest V2) that checks links via VirusTotal and opens them in a private browsing window.

## Git workflow

Commit and push to `NokiGuard/url-checker` after every meaningful unit of work.

## Loading / reloading in Firefox

No build step. Load directly from source:

1. Navigate to `about:debugging` → **This Firefox** → **Load Temporary Add-on...**
2. Select `manifest.json`
3. After any code change, click **Reload** on the extension card at `about:debugging`

To see background script console output: click **Inspect** on the extension card.

## Architecture

All privileged logic lives in **`background.js`** (persistent MV2 background script). The popup and options pages are thin UI layers that communicate with it exclusively via `browser.runtime.sendMessage`.

```
Right-click link
  → background.js (context menu handler)
      → VirusTotal API v3 (fetch)
      → stores result in storage.local under a session token
      → opens popup/results.html?token=... as a browser popup window
          → results.js requests data via GET_RESULT_DATA message
          → user clicks Open → USER_DECISION message → background.js
              → browser.windows.create({ incognito: true })  ← private window
          → background.js closes the popup window
```

**Key flows in `background.js`:**
- `getOrFetchAnalysis(url, apiKey)` — cache → existing VT report → new scan + poll
- `checkExistingReport(url)` — GET `/api/v3/urls/{base64url-id}` (fast path, ~1s)
- `submitUrlForScan(url)` + `pollAnalysis(id)` — POST then poll `/api/v3/analyses/{id}`; first poll at 800ms then backs off
- `openInPrivateBrowser(url)` — opens a Firefox private (incognito) window with the URL
- Rate limiter: `waitForRateLimit()` enforces 15.5s between VT API requests (free tier = 4 req/min)
- In-memory cache: `analysisCache` Map, TTL configurable (default 24h)

**`storage.local` keys:**
- `vtApiKeyEncrypted` — AES-256-GCM encrypted API key `{ encrypted: base64, iv: base64 }`
- `vtKeySalt` — base64 PBKDF2 salt (generated once, persisted)
- `vtSettings` — `{ cacheHours, threshSuspicious, threshMalicious }`
- `result_<token>` — ephemeral per-analysis payload; written before popup opens, deleted when results.js reads it

## VT URL identifier

VirusTotal v3 uses URL-safe base64 with no padding. Non-ASCII URLs (IDN domains) are UTF-8 encoded first:
```js
try {
  b64 = btoa(url);
} catch {
  b64 = btoa(unescape(encodeURIComponent(url)));
}
return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
```

## Risk classification (results.js)

| Level | Condition |
|-------|-----------|
| Clean | 0 malicious detections |
| Suspicious | ≥ `threshSuspicious` (default 1) malicious, OR ≥ 3 suspicious |
| Malicious | ≥ `threshMalicious` (default 5) malicious |

## Private Browser scope

Opens a Firefox private (incognito) window: no cookies, no history, no saved storage — all cleared when closed. Does **not** provide OS-level process isolation or block file downloads. Requires "Allow in Private Windows" to be enabled in `about:addons`.
