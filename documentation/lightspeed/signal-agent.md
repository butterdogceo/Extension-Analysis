# Lightspeed Signal Agent — Extension Analysis

**Version:** 0.6.1.1776950773  
**Publisher:** Lightspeed Systems  
**Manifest Version:** 3

---

## Overview

The Lightspeed Signal Agent is a device telemetry and health monitoring extension. It collects device performance metrics, network quality data, geolocation, battery status, and page performance timings from the student's Chromebook and reports them to Lightspeed's cloud infrastructure. It is **not** a content filter — it does not block URLs or scan page content.

---

## Architecture

| Component | Role |
|-----------|------|
| `worker.js` (background, 726 KB, obfuscated) | Core telemetry collection and reporting, WASM runtime |
| `timings.js` (content script) | Collects Navigation and Resource Timing API data from every page |
| `offscreen.js` (offscreen document) | Handles geolocation and battery data collection |
| `lsone.wasm` | Compiled WebAssembly — the signal agent's core logic |

---

## Data Collection Methods

---

### 1. Page Performance Timings (Content Script)

**File:** `timings.js`  
**Trigger:** Runs on every page load on all URLs

Uses the browser's native **`PerformanceObserver` API** to collect timing data:

**Observed entry types:**
- `navigation` — Full page load metrics (DNS lookup, TCP connect, TTFB, DOM load, etc.)
- `resource` — Timing data for every sub-resource loaded on the page (scripts, images, stylesheets, API calls)

**How it works:**
1. Creates a `PerformanceObserver` with `{ buffered: true }` to also capture entries that occurred before the observer was attached.
2. For each timing entry, calls `entry.toJSON()` to serialize all timing fields.
3. Sends the serialized data to the background service worker via `chrome.runtime.sendMessage({ action: 'timingsGet', target: 'ext', data: entry.toJSON() })`.

**Data collected per entry:** `startTime`, `duration`, `fetchStart`, `domainLookupStart`, `domainLookupEnd`, `connectStart`, `connectEnd`, `requestStart`, `responseStart`, `responseEnd`, `transferSize`, `encodedBodySize`, `decodedBodySize`, `initiatorType`, `name` (URL), plus navigation-specific fields.

---

### 2. Network Speed Testing

**File:** `worker.js` — `runSpeedTest()` / `runSpeedTestWithCallback()`

Performs active network speed tests using the **WebTransport API** (an HTTP/3-based protocol):

**Upload test:**
1. Opens a WebTransport connection to a Lightspeed speed test server.
2. Generates random byte data of size `ChunkSize * ChunkCount`.
3. Writes the data to the outbound stream and measures throughput.
4. Records per-chunk timing and total upload duration.

**Download test:**
1. Reads inbound stream data from the server after sending upload payload.
2. Receives upload statistics JSON from the server (chunk count, upload size, duration).
3. Measures download throughput via per-chunk timing.

**Metrics reported:**
- `UploadSize`, `UploadDuration`, `UploadChunks` (upload speed)
- `DownloadSize`, `DownloadDuration`, `DownloadChunks` (download speed)
- `ChunkSize`, `ChunkCount`, `TransactionId`, `RanAt` (metadata)

---

### 3. Geolocation Collection

**File:** `offscreen.js`  
**Permission:** `geolocation`

When triggered by the background (via `chrome.runtime.onMessage` with `action: 'locationGet'`):

1. Calls `navigator.geolocation.getCurrentPosition()`.
2. Extracts the `coords` object (latitude, longitude, accuracy, altitude, speed, etc.).
3. Sends the coordinates back to the background via `chrome.runtime.sendMessage({ action: 'locationGet', target: 'ext', data: coords })`.

---

### 4. Battery Status Collection

**File:** `offscreen.js`  
**Permission:** Implicit (uses `navigator.getBattery()` Web API)

When triggered by the background (via `action: 'batteryGet'`):

1. Calls `navigator.getBattery()` to get the `BatteryManager`.
2. Collects:
   - `charging` (boolean — is device plugged in?)
   - `level` (0–100 percentage; the native `BatteryManager.level` returns 0.0–1.0, which is converted by `Math.round(100 * battery.level)`)
   - `dischargingTime` (seconds until empty)
   - `chargingTime` (seconds until full)
3. Sends the data to the background for reporting.

---

### 5. System Hardware Metrics

**Permissions:** `system.cpu`, `system.memory`, `system.storage`, `enterprise.hardwarePlatform`, `enterprise.networkingAttributes`

The background service worker collects device hardware information:
- **CPU info**: `chrome.system.cpu.getInfo()` — processor architecture, physical/logical cores, usage
- **Memory info**: `chrome.system.memory.getInfo()` — total and available capacity
- **Storage info**: `chrome.system.storage.getInfo()` — storage device capacities and types
- **Hardware platform**: `chrome.enterprise.hardwarePlatform.getHardwarePlatformInfo()` — device model and manufacturer
- **Network attributes**: `chrome.enterprise.networkingAttributes.getNetworkDetails()` — local IPv4 address, MAC address

---

### 6. Exploit/Banned Tab Detection

**File:** `worker.js` — `startListening()` (from `ls-exploits-js`)

Reuses the same exploit detection module described in the Chrome Filter:

- Monitors `chrome.tabs.onUpdated` and `chrome.tabs.onCreated`.
- Checks tab URLs and titles against a list of known exploit app IDs and paths:
  - Extension IDs: Same set as Chrome Filter (`adkcpkpghahmbopkjchobieckeoaoeem`, etc.)
  - App paths: `/main.js`, `/worker.js`, `/index.js`, `/in_page.js`, `/manifest.json`, `*.png`
- **Removes** tabs that match known exploit extension chrome-extension:// URLs.
- **Removes** `data:text/html` tabs containing specific exploit signatures (e.g., "Blobby-Boi", "print3r" in title).
- Monitors bookmarks (create/update) for any that point to known exploit extension IDs.
- Runs `validRequest()` checks (URL length ≤ 64,000 chars, hostname ≤ 255 chars) on all monitored URLs.
- Runs a periodic scan of all open tabs every 2 seconds.

---

### 7. WebAssembly Runtime (`lsone.wasm`)

The Signal Agent uses a WASM binary (`lsone.wasm`) compiled from Go (evident from the `Go` class runtime bootstrap in `worker.js`). The WASM module handles the core signal processing and telemetry dispatch logic. It is loaded at startup and restarted automatically if it exits.

---

## Permissions Summary

| Permission | Purpose |
|---|---|
| `action` | Browser toolbar button |
| `activeTab` | Access current tab metadata |
| `alarms` | Schedule periodic telemetry collection |
| `bookmarks` | Monitor for exploit bookmarks |
| `enterprise.deviceAttributes` | Get device serial number |
| `enterprise.hardwarePlatform` | Get hardware model info |
| `enterprise.networkingAttributes` | Get local IP/MAC address |
| `geolocation` | Collect device GPS coordinates |
| `identity` + `identity.email` | Resolve student identity |
| `offscreen` | Run geolocation/battery collection in background |
| `storage` | Cache telemetry and state |
| `system.cpu` | Collect CPU usage and specs |
| `system.memory` | Collect RAM capacity and availability |
| `system.storage` | Collect storage device info |
| `tabs` | Monitor tab URLs for exploit detection |
| `webRequest` | Intercept web requests (monitoring) |
| `host_permissions: <all_urls>` | Run content script on all pages |

---

## Relevance to Your Own Websites

The Signal Agent does **not block or filter URLs** — it is purely a telemetry collector. However:

1. **Page load performance data from your site is reported** — the `timings.js` content script runs on every page and sends navigation and resource timing data for your site to Lightspeed.

2. **Resource URLs are included in timing data** — every request made by your page (scripts, images, API calls) has its URL included in the `PerformanceResourceTiming` data sent to Lightspeed.

3. **No content blocking** — this extension alone cannot block access to your websites.

4. **Exploit detection is active** — if your site's Chrome extension (if any) matches known exploit signatures (extension IDs or file paths like `/worker.js`), it could be flagged and removed.
