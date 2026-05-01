# Lightspeed Chrome Filter Agent — Extension Analysis

**Version:** 4.3.0.1777107754  
**Publisher:** Lightspeed Systems  
**Manifest Version:** 2 (with MV3-style service worker)

---

## Overview

The Lightspeed Chrome Filter Agent is the primary content filtering extension in the Lightspeed "Relay" product suite. It is a commercial, enterprise-grade web filter for K-12 Chromebooks. The JavaScript code is obfuscated (minified + string-array encoding), but the key behaviors are identifiable through its use of the Chrome `webRequest` API, a compiled WebAssembly (`filter.wasm`) policy engine, and communication with Lightspeed's cloud infrastructure.

---

## Architecture

| Component | Role |
|-----------|------|
| `worker.js` (background service worker, 726 KB) | Obfuscated — intercepts all web requests, applies policy, reports violations |
| `main.js` (3.7 MB, obfuscated) | Core library bundle: filtering engine, relay API, proxy detection, reporting |
| `content.js` (66 KB, obfuscated) | Content script — gathers page intent/typed content from specific sites |
| `filter.wasm` | Compiled WebAssembly binary — contains the actual URL classification and policy logic |
| `in_page.js` | In-page injection helper |
| `block_screen.html` / `blocked.png` | Block page assets |

---

## Filtering Methods & Detection Techniques

---

### 1. URL Pre-Scanning (`webRequest.onBeforeRequest`)

**Trigger:** Every outbound web request, all resource types (`main_frame`, `sub_frame`, `stylesheet`, `script`, `image`, `font`, `object`, `xmlhttprequest`, `ping`, `other`, `websocket`)

**How it works:**
1. Calls `f.PreScan(request)` on the request URL.
2. If `PreScan` returns a result with `cancel: true`, the request is immediately cancelled and the event is logged to Lightspeed's reporting pipeline.
3. Passes the URL to `f.Warm(request)` (pre-warms the policy cache for this URL) if not cancelled.

**Skip conditions (never filtered):**
- Requests originating from the extension itself (`initiator === chrome.runtime.id`)
- When filtering is administratively disabled (`osDisable` or `disabled` flags)
- Google OAuth URLs (`accounts.google.com/`)
- Globally allowed hosts/URLs (hardcoded internal list)
- `chrome:`, `chrome-extension:`, `file:` protocol URLs
- Google Earth initiator
- YouTube-to-YouTube requests

---

### 2. Response Header Scoring (`webRequest.onHeadersReceived`)

**Trigger:** When response headers are received for any web request (same resource types as above)

This is the main filtering checkpoint. The response headers are scored by the WASM-based policy engine.

**Scoring process:**
1. Calls `f.Score(responseDetails)` which internally uses the `filter.wasm` WebAssembly module to classify the URL/content.
2. The score result contains:
   - `blocked` (boolean): Whether the URL is blocked
   - `reason` / `r`: The blocking reason code
   - `redirect`: URL to redirect to (the block page)
   - `onHold`: Whether the URL is waiting for cloud classification

**On-Hold (Cloud Lookup) Handling:**
- If `onHold` is true, the extension implements an exponential delay loop (up to 20 retries) waiting for a cloud classification result.
- Uses a per-tab/URL counter stored in `z[tabId][url]` to track retry attempts.
- If `BypassOnFail` policy is set and 15 retries are exceeded, the request is allowed.

**Redirect behavior:**
- `main_frame`/`sub_frame` requests are redirected to the block page URI.
- Image requests are redirected to `blocked-image-search.png`.
- Other resource types with a different destination hostname are cancelled.
- For `xmlhttprequest` to `googlevideo.com`, the redirect is skipped (prevents breaking YouTube).

---

### 3. Request Header Injection (`webRequest.onBeforeSendHeaders`)

**Trigger:** Before request headers are sent (all URLs)

The extension injects custom HTTP headers on outbound requests:

#### a. Lightspeed Identity Header
- **Header:** `lspkey: <value>`
- Injects the administrator's LSP identity key into every request, allowing Lightspeed's infrastructure to identify the managed device.

#### b. YouTube Restricted Mode Enforcement
- **Header:** `YouTube-Restrict: Strict` (or `Moderate`)
- Added to requests to YouTube domains: `www.youtube.com`, `m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `www.youtube-nocookie.com`
- Enforces YouTube's built-in Safe Search / Restricted Mode at the HTTP level — students cannot disable it from settings because it's injected by the browser extension.

#### c. Google Workspace Domain Restriction
- **Header:** `X-GoogApps-Allowed-Domains: <domain>`
- Added to all `*.google.com` requests (excluding certain image/API endpoints)
- Forces Google Workspace to only allow sign-in with accounts from the specified school domain
- Prevents students from signing in with personal Google accounts to access content the school domain would block

---

### 4. WASM-Based URL Classification (`filter.wasm`)

The `filter.wasm` binary is the core of the filtering engine. It is compiled WebAssembly (from the `filtering-js` npm library) and provides:

- **URL categorization**: Classifies URLs into content categories (adult content, games, social media, etc.)
- **Policy application**: Checks categories against the active user policy fetched from Lightspeed's servers
- **Search term filtering**: Can score search queries (not just URLs) for blocked content

The WASM module is not human-readable. Its inputs are URL strings and response metadata; its output is a block/allow/hold decision with a reason code.

---

### 5. User Identity Resolution

**File:** `main.js` — `checkIdentity()` / `V()`

The extension resolves the current user's identity through a cascade:

1. **Chrome Identity API** (`chrome.identity.getProfileUserInfo`): Gets the signed-in Google account email.
2. **Device Serial Number** (`chrome.enterprise.deviceAttributes.getDeviceSerialNumber`): Falls back to `Serial-<serial>` if no email.
3. **Guest GUID**: If neither is available, generates or retrieves a persistent GUID from `localStorage`, stored as `Guest-<guid>`.

The resolved identity is sent to Lightspeed's API at `https://devices.filter.relay.school/filter/chrome/v2/user_policy` to fetch the user's specific content filtering policy.

**Re-check interval:** Every 5 minutes for identified users; every 5 seconds for unidentified ("base") users.

---

### 6. Real-Time Policy Sync (Relay WebSocket)

**Endpoint:** `wss://production-gc.lsfilter.com`  
**Auth:** `0ef9b862-b74f-4e8d-8aad-be549c5f452a` (relay socket auth key)

The extension maintains a WebSocket connection to Lightspeed's Relay service. When the admin changes the filtering policy in the Lightspeed console, the change is pushed to the extension in real-time via this socket without requiring a browser restart.

---

### 7. Violation Reporting (AWS SQS)

**Queue URL:** `https://sqs.us-west-2.amazonaws.com/499473022646/lsrelay-reports-production`

Every blocked or flagged request is logged to Lightspeed's AWS SQS reporting queue. Logged fields include:
- Username (resolved identity)
- URL
- Block reason
- Timestamp
- Tab ID
- Resource type

Reports are also used to populate the Lightspeed reporting dashboard for administrators.

---

### 8. Image Scanning (Google Search)

**Trigger:** When the tab URL matches `google.com/search` and the `SearchEngines.GoogleFilterImages` policy is enabled.

After a **1.5-second delay**, the background sends an `{ action: "imageScan" }` message to the content script, which then scans image URLs on the search results page. Individual image URLs are scored through `f.Score()` and marked as blocked if needed.

---

### 9. Content Intent Gathering (Content Script)

**File:** `content.js` (obfuscated)  
**Trigger:** Runs on all pages at document load

The content script contains site-specific modules that extract user-typed content from the page for content analysis:

| Module | Site | What It Extracts |
|--------|------|-----------------|
| ChatGPT module | `chatgpt.com` | Content of the prompt textarea (`#prompt-textarea`) |
| Facebook module | `facebook.com` | Content of all `[role="textbox"]` elements |
| Gemini module | `gemini.google.com` | Content of Gemini prompt fields |
| Gmail module | `mail.google.com` | Content of all `[role="textbox"]` elements |
| Google Docs module | `docs.google.com` | `document.body.innerText` (entire document) |
| Google Search module | `google.com` | Content of `input[name="q"]` (search box value) |

This data is used to detect and potentially block content based on typed search queries, prompts, or document content — not just URLs.

**GatherIntent flow:**
1. Listens for DOM events (input, textarea, keydown, or explicit "scan" triggers)
2. Collects text from the appropriate site module
3. Scores the text through the relay's flagged-terms API
4. If flagged terms are found, can trigger a redirect to the block page

---

### 10. Proxy Detection (ls-exploits-js)

The `main.js` bundle imports a library called `ls-exploits-js` that provides `StartListening` and `ValidRequest` functions. From visible string artifacts, this module:

- Monitors bookmark creation and tab events for known Lightspeed extension IDs to detect spoofing
- Validates request URLs (max URL length 64,000 chars; max hostname length 255 chars)
- Detects and closes tabs pointing to:
  - `chrome-extension://` URLs of non-Lightspeed apps that match known exploit paths
  - `data:text/html` tabs with "Blobby-Boi" content (a specific exploit payload)
  - `about:blank` tabs with "print3r" in the title (printer exploit)

---

### 11. Device Attribute Collection

**Permissions used:** `enterprise.deviceAttributes`, `enterprise.networkingAttributes`

On startup, the extension collects:
- **Device serial number** (for identity fallback)
- **Local IPv4 address** (sent to Lightspeed for device identification)
- **Platform info** (architecture and OS)

---

### 12. RocketAutoDetect (Captive Portal / Network Detection)

The extension includes a `RocketAutoDetect` component (`C.Init()`) that detects whether the device is behind a captive portal (e.g., hotel/airport Wi-Fi) or direct internet connection. This affects filtering behavior:
- On a captive portal, "onHold" URLs are allowed through to prevent breaking portal login pages.
- Disabled when `osDisable` or the main `disabled` flag is set.

---

## Permissions Used

| Permission | Purpose |
|---|---|
| `webRequest` + `webRequestBlocking` | Intercept and block/redirect all requests |
| `tabs` | Monitor tabs |
| `storage` | Cache policy and user data |
| `history` | Access browsing history for scanning |
| `identity` + `identity.email` | Resolve user identity |
| `management` | Detect installed extensions |
| `enterprise.deviceAttributes` | Get device serial number |
| `enterprise.networkingAttributes` | Get local IP address |
| `proxy` | Manage proxy settings |
| `bookmarks` | Monitor bookmark creation for exploit detection |
| `idle` | Detect device idle state |
| `host_permissions: <all_urls>` | Access all URLs |

---

## Relevance to Your Own Websites

Your websites could be flagged or blocked by Lightspeed Chrome Filter if:

1. **The URL is categorized as blocked** by Lightspeed's WASM classification engine — this is the primary mechanism. Lightspeed maintains a continuously-updated URL database. If your domain falls in a blocked category (games, social, adult content, etc.), it will be blocked.

2. **The URL is on a Lightspeed blacklist** — explicitly added by the school admin.

3. **The website contains text content that triggers flagged-term detection** — if a student types something in a text box and the content matches a flagged term list, a redirect can occur even from an otherwise-allowed site.

4. **YouTube is handled specially** — if your site embeds YouTube, requests to YouTube from your page will have `YouTube-Restrict` headers injected, which may cause some content to be unavailable.

5. **Google account restrictions** — if your site uses Google OAuth or Google Workspace, the `X-GoogApps-Allowed-Domains` header will restrict sign-in to school-managed accounts only.

6. **The block page is customizable** — the school can configure a custom block page. The filter serves a hosted block page from either `lsrelay-config-production.s3.amazonaws.com` or a local copy.
