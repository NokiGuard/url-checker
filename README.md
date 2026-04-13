# URL Checker

A Firefox extension that checks any link against VirusTotal before you open it, then lets you open it in a private browsing window if you choose to proceed.

## What It Does

Right-click any link → **Check and Open in Private Browser** → get an instant safety report powered by VirusTotal showing how many antivirus engines flagged the URL. You then decide whether to open it in an isolated private window or cancel.

---

## Requirements

- Firefox (version 77+)
- A free [VirusTotal API key](https://www.virustotal.com/gui/join-us)

---

## Installation

1. Download or clone this repo
2. Open Firefox and navigate to `about:debugging`
3. Click **This Firefox** → **Load Temporary Add-on...**
4. Select `manifest.json` from the repo folder

> **Note:** Temporary add-ons are removed when Firefox restarts. For a permanent install, the extension would need to be signed by Mozilla.

---

## Setup

### 1. Add Your VirusTotal API Key

1. Click the URL Checker icon in your Firefox toolbar
2. The options page will open — paste your VirusTotal API key into the **API Key** field
3. Click **Save Settings**

> Get a free API key at [virustotal.com](https://www.virustotal.com/gui/join-us). The free tier allows 4 requests/minute and 500/day.

### 2. Enable Private Window Access

To open links in a private window, you need to grant the extension permission:

1. Go to `about:addons`
2. Find **URL Checker** → click the three-dot menu → **Manage**
3. Scroll down and enable **Run in Private Windows**

---

## How to Use

1. **Right-click any link** on a webpage
2. Select **Check and Open in Private Browser** from the context menu
3. A results window appears showing:
   - A **Clean / Suspicious / Malicious** risk rating
   - Detection counts from antivirus engines (malicious, suspicious, clean)
   - A breakdown by individual engine and their verdict
   - When the URL was last scanned
4. Click **Open in Private Browser** to visit the link in an isolated private window, or **Cancel** to stay safe

---

## Results Window

| Badge | Meaning |
|-------|---------|
| 🟢 Clean | No engines flagged the URL |
| 🟠 Suspicious | At least 1 engine flagged it, or 3+ marked it suspicious |
| 🔴 Malicious | 5 or more engines flagged it as malicious |

These thresholds are configurable in the options page.

---

## Settings

Open the options page via the toolbar icon to configure:

| Setting | Default | Description |
|---------|---------|-------------|
| API Key | — | Your VirusTotal API key |
| Cache Duration | 24 hours | How long to reuse a previous scan result before re-checking |
| Suspicious threshold | 1 | Minimum malicious detections to show as Suspicious |
| Malicious threshold | 5 | Minimum malicious detections to show as Malicious |

---

## Private Browser Scope

Opening a link in a **Private Browser** window means:
- No cookies or session data from your main profile are sent
- History is not recorded
- Local storage is cleared when the window closes

It does **not** provide OS-level process isolation and does **not** block file downloads. Use it for a safer look at a suspicious link — not as a full sandbox.

---

## Caching & Rate Limits

- Results are cached in memory for the duration set in options (default 24h) — repeated checks of the same URL are instant and don't use API quota
- The free VirusTotal tier allows 4 requests/minute. The extension enforces a 15.5-second gap between requests automatically
- A **Cached** badge appears on results that were served from cache
