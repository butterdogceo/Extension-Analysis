# You Shall Not Pass — Extension Analysis

**Version:** 3.0.5  
**Author:** Jim Tyler (Microsoft MVP)  
**Manifest Version:** 3  
**GitHub:** https://github.com/jimrtyler/youshallnotpass

---

## Overview

"You Shall Not Pass" is a comprehensive, open-source anti-evasion extension designed for K-12 managed Chromebooks. It targets the entire ecosystem of student filter-bypass tools: web proxies, proxy service workers, exploit scripts, tab spam, Google Sites abuse, and browser history manipulation attacks.

---

## Detection & Filtering Methods

---

### 1. Declarative Net Request (DNR) Blocking Rules

**File:** `rules.json`  
**Method:** Chrome's `declarativeNetRequest` API — rules evaluated natively before any JavaScript runs.

These 24 static rules block specific URL patterns for `main_frame`, `sub_frame`, and/or `script` resource types. All rules have a large shared whitelist of educational domains that are excluded from blocking.

| Rule ID | Priority | Pattern / Filter | Resource Types | Description |
|---------|----------|-----------------|----------------|-------------|
| 1002 | 2 | `blob:*` | `sub_frame` | Blocks all blob: URL iframes initiated from `sites.google.com` (excludes docs/drive) |
| 1003 | 1 | `.*unblock.*(game\|site\|web).*` | `main_frame`, `sub_frame` | Blocks any URL with "unblock" followed by "game", "site", or "web" |
| 1005 | 1 | `*titaniumnetwork*` | `main_frame`, `sub_frame` | Blocks the Titanium Network proxy infrastructure |
| 1006 | 1 | `.*(mercurywork(shop\|\.shop)).*` | `main_frame`, `sub_frame` | Blocks Mercury Workshop proxy |
| 1007 | 1 | `.*(vercel\|netlify\|render\|replit).*app.*(game\|unblo\|proxy).*` | `main_frame`, `sub_frame` | Blocks games/proxies hosted on popular cloud platforms |
| 1008 | 1 | `.*((ultraviolet.*(proxy\|unblo\|bypass\|service))\|(uv[.-](bundle\|service\|config))).*` | `main_frame`, `sub_frame`, `script` | Blocks Ultraviolet proxy and UV bundle scripts |
| 1009 | 1 | `*rammerhead*` | `main_frame`, `sub_frame`, `script` | Blocks Rammerhead proxy |
| 1010 | 1 | `.*uv\.bundle.*` | `script` | Blocks UV bundle script files specifically |
| 1011 | 1 | `*bare-client*` | `script` | Blocks Bare Client (TompHTTP transport layer) |
| 1017 | 1 | `.*(github\.io\|pages\.dev).*(game\|unblo\|proxy).*` | `main_frame`, `sub_frame` | Blocks GitHub Pages / Cloudflare Pages hosting games or proxies |
| 1018 | 1 | `*raw.githubusercontent.com*` | `main_frame`, `sub_frame` | Blocks loading raw GitHub content directly in frames |
| 1019 | 1 | `.*ltbeef.*` | `main_frame`, `sub_frame`, `script` | Blocks LTBEEF exploit tool |
| 1020 | 1 | `.*ltmeat.*` | `main_frame`, `sub_frame`, `script` | Blocks LTMEAT exploit tool |
| 1021 | 1 | `.*ingot.*exploit.*` | `main_frame`, `sub_frame`, `script` | Blocks Ingot exploit framework |
| 1022 | 1 | `*ext-remover*` | `main_frame`, `sub_frame`, `script` | Blocks extension-removal exploit scripts |
| 1023 | 1 | `.*cloudflare.*worker.*(proxy\|game\|unblo).*` | `main_frame`, `sub_frame` | Blocks Cloudflare Worker-based proxies/games |
| 1024 | 1 | `*.workers.dev*` | `main_frame`, `sub_frame` | Blocks all `*.workers.dev` domains (Cloudflare Workers) |
| 1026 | 1 | `.*scramjet.*` | `main_frame`, `sub_frame`, `script` | Blocks Scramjet proxy framework |
| 1027 | 1 | `.*holy[-_.]?unblocker.*` | `main_frame`, `sub_frame`, `script` | Blocks Holy Unblocker proxy |
| 1028 | 1 | `.*(epoxy[-_.]?(transport\|client\|worker)).*` | `main_frame`, `sub_frame`, `script` | Blocks Epoxy transport layer |
| 1029 | 1 | `.*(wisp[-_.]?(client\|server\|transport)).*` | `script` | Blocks Wisp WebSocket transport protocol |
| 1030 | 1 | `.*(libcurl[-_.]?(transport\|worker)).*` | `script` | Blocks libcurl-based transport layers |
| 1031 | 1 | `.*bare[-_.]?mux.*` | `script` | Blocks BareMux multiplexer |
| 1032 | 1 | `.*tomphttp.*` | `main_frame`, `sub_frame`, `script` | Blocks TompHTTP server/framework |
| 1033 | 1 | `*holyunblocker*` | `main_frame`, `sub_frame` | Blocks Holy Unblocker (alternative pattern) |

**Whitelist (excluded from all rules):** ~60 educational platforms including Wikipedia, Khan Academy, Google Docs, IXL, Kahoot, Desmos, Quizlet, etc. See the full list in `rules.json`.

---

### 2. Service Worker Proxy Detection

**File:** `background.js` — `detectServiceWorkerProxy()`  
**Trigger:** `chrome.webNavigation.onCommitted` event (every page navigation)

Checks the navigated URL against a set of regex patterns that identify known proxy service worker signatures. If the URL matches, the tab is immediately closed.

**Patterns checked:**

| Pattern | What It Targets |
|---------|----------------|
| `/ultraviolet.*(proxy\|unblo\|bypass)/i` | Ultraviolet proxy |
| `/rammerhead/i` | Rammerhead proxy |
| `/scramjet/i` | Scramjet proxy |
| `/mercurywork/i` | Mercury Workshop |
| `/holy[-_.]?unblocker/i` | Holy Unblocker |
| `/corrosion[-_.]?proxy/i` | Corrosion proxy |
| `/stomp[-_.]?(bootstrap\|rewrite)/i` | Stomp service worker |
| `/uv\.bundle/i` | Ultraviolet bundle |
| `/bare[-_.]?client/i` | Bare Client |
| `/bare[-_.]?mux/i` | BareMux |
| `/epoxy[-_.]?(transport\|client\|worker)/i` | Epoxy transport |
| `/wisp[-_.]?(client\|server\|transport)/i` | Wisp WebSocket |
| `/libcurl[-_.]?(transport\|worker)/i` | libcurl transport |
| `/tomphttp/i` | TompHTTP |
| `/service[-_.]?worker[-_.]?proxy/i` | Generic SW proxy |

**Whitelist:** The same ~60 educational domains are excluded from this check.

---

### 3. History Flooding ("Point-Blank") Attack Detection

**File:** `content_guard.js` — `initializeHistoryMonitor()` / `handleHistoryFlood()`  
**Trigger:** Runs in every tab/frame at `document_start`

The "Point-Blank" attack is a technique where a page rapidly calls `history.pushState()` or `history.replaceState()` to overwhelm content-filtering extensions (many extensions check URLs on navigation events and can be flooded).

**How detection works:**

1. Monkey-patches `window.history.pushState` and `window.history.replaceState` with intercepting wrappers.
2. Counts calls within each 1-second window.
3. If the count exceeds **50 calls per second** (configurable via the `contentGuard.maxHistoryPushesPerSecond` admin setting — see [Admin Configuration System](#9-admin-configuration-system) below), the flood handler fires:
   - Calls `window.stop()` to halt all page loading.
   - Replaces `document.body.innerHTML` with a red security violation notice showing the attack details.
   - Subsequent `pushState`/`replaceState` calls are silently dropped.

---

### 4. LTBEEF Exploit GUI Detection

**File:** `content_guard.js` — `detectLTBEEFGUI()`  
**Trigger:** Runs every **5 seconds** in every tab/frame

LTBEEF and related tools inject visible GUI elements into the page to help students interact with filter-bypass exploits.

**DOM selectors checked:**

| Selector | Tool |
|----------|------|
| `.ingot-overlay` | Ingot exploit overlay |
| `#ext-remover` | Extension remover UI |
| `#ltbeef-ui` | LTBEEF primary UI |
| `[data-exploit="ltbeef"]` | LTBEEF data attribute marker |
| `.spork-gui` | Spork GUI framework |

**Response on detection:**
1. The matching DOM element is removed from the page.
2. `window.location.reload()` is called after 100ms to disrupt the exploit's execution.

---

### 5. Google Sites Iframe Inspector

**File:** `google_sites_inspector.js`  
**Trigger:** Runs only on `sites.google.com` pages at `document_idle`, scans every **2 seconds**

Google Sites is commonly abused to embed blocked content in iframes. This script monitors all iframes on Google Sites pages.

#### 5a. Blob URL Detection

Checks for `<iframe src="blob:...">` elements that are at least **400×400 pixels** in size.

**Logic:**
- If `iframe.src.startsWith('blob:')` and size ≥ 400px wide × 400px tall → blocked.
- Action: Sets `iframe.src = 'about:blank'`, hides the iframe, inserts a red "Content Blocked — Blob URL embedding detected" message.

**Why blob URLs?** Students use `URL.createObjectURL()` to wrap blocked content inside a blob URL, bypassing URL-based filter rules.

#### 5b. Game Engine Signature Detection

Attempts to read the HTML of same-origin iframes and checks for game engine signatures.

**Signatures scanned:**

| Signature | Engine/Tool |
|-----------|------------|
| `/UnityLoader\.js/i`, `/unityInstance/i`, `/\.unity3d/i`, `/UnityWebGL/i` | Unity |
| `/c2runtime\.js/i`, `/c3runtime\.js/i`, `/construct\.net/i` | Construct 2/3 |
| `/phaser\.js/i`, `/phaser\.min\.js/i` | Phaser |
| `/godot\.js/i` | Godot |
| `/pixi\.js/i` | PixiJS |
| `/three\.js.*game/i` | Three.js (game use) |
| `/ruffle/i`, `/emulator/i` | Flash emulators (Ruffle) |
| `/\/rom\//i`, `/\.nes$/i`, `/\.gba$/i`, `/\.gb$/i` | ROM files |
| `/unblocked/i`, `/unblocker/i`, `/game.*proxy/i` | Unblocked game keywords |
| `/ruffle.*swf/i`, `/flashplayer/i` | Flash player |

**Action on match:** Sets iframe src to `about:blank`, hides it, inserts a yellow "Game Content Blocked" notice with the matched signature.

#### 5c. Cloudflare Worker Proxy Detection

Checks iframe `src` attributes for Cloudflare Worker hosting patterns.

**Patterns:**
- `/.workers.dev/i`
- `/.pages.dev/i`
- `/cloudflare.*proxy/i`

**Additional heuristic:** Also checks if the subdomain portion of the URL appears random — the subdomain (the leftmost label) is tested against `/^[a-z0-9]{8,}$/` (lowercase alphanumeric, exactly matching the subdomain label, 8 or more characters). Subdomains matching this pattern are flagged as suspicious, indicative of auto-generated proxy hostnames (e.g., `ab3f9d12.workers.dev`).

#### 5d. Base64 Encoded Content Detection

Scans all `<script>` elements on the page for very long base64 strings.

**Trigger:** Any base64 string ≥ **1,000 characters** (`/[A-Za-z0-9+/]{1000,}/g`).

**Elevated warning:** If the script also contains `atob(` **and** `createObjectURL`, a higher-severity warning is logged (indicates the encoded content is being decoded and embedded as a blob).

**Action:** Currently logs a warning — does not block. Serves as detection/alerting.

#### 5e. MutationObserver — Dynamic Iframe Monitoring

Watches the DOM for dynamically inserted iframes using `MutationObserver` on `document.body`.

When a new `<iframe>` is added, all four detection methods above (blob URL, Cloudflare worker, game engine, base64) are run against it after a 500ms delay.

---

### 6. Tab Spam Detection

**File:** `background.js` — `detectTabSpam()` / `handleBulkTabCreation()`  
**Trigger:** `chrome.tabs.onCreated` event

Students sometimes use scripts that rapidly open many tabs to disrupt monitoring or overwhelm filters.

**Detection logic:**
- Maintains a sliding window of tab creation timestamps.
- Window size: **2,000 ms** (configurable).
- Threshold: **5 tabs within the window** = spam.
- When spam is detected, the newly created non-active tab is closed.

**Bulk creation handling:**
- If more than **20 tabs** are created at once (e.g., on startup), all but the most recent `maxTabs` tabs are closed.

---

### 7. Tab Limit Enforcement

**File:** `background.js` — `enforceTabLimit()`  
**Trigger:** Tab creation, startup, and every **10 seconds** via `setInterval`

Enforces a hard maximum of **15 tabs** (configurable). When the limit is exceeded:
- Sorts all open tabs by `lastAccessed` timestamp (oldest first).
- Closes the least-recently-accessed non-active tabs until the count is at or below the limit.

---

### 8. Heartbeat Anti-Tamper System

**Files:** `background.js` + `content_guard.js`  
**Trigger:** Continuous, every 30 seconds per tab

The heartbeat system maintains persistent port connections between content scripts and the background service worker. This serves as an anti-tamper mechanism — if the extension's content script is killed or disabled, the port disconnects, and the background can detect this.

**Mechanism:**
1. Content script opens a `chrome.runtime.connect({ name: 'heartbeat' })` port.
2. Sends `{ type: 'ping' }` messages every 30 seconds.
3. Background responds with `{ type: 'pong', timestamp }`.
4. If the port disconnects, the background logs it and the content script attempts reconnection after 5 seconds (only if the page is still visible).

---

### 9. Admin Configuration System

**File:** `background.js` — `loadConfig()` / `applyRuleChanges()`  
**Schema:** `managed_schema.json`

The extension supports full remote configuration via Google Workspace Managed Storage:

- **`configUrl`**: URL to a hosted JSON config file, fetched on startup and refreshed every **60 minutes**.
- **`config`**: Inline config object in managed storage.

**Configurable parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `tabLimits.maxTabs` | 15 | Max total open tabs |
| `tabLimits.tabCreationWindow` | 2000 ms | Spam detection window |
| `tabLimits.maxTabsInWindow` | 5 | Max tabs in spam window |
| `contentGuard.enabled` | true | Enable content guard |
| `contentGuard.maxHistoryPushesPerSecond` | 50 | History flood threshold |
| `contentGuard.enableLTBEEFDetection` | true | Enable LTBEEF scanning |
| `googleSitesInspector.enableBlobBlocking` | true | Block blob: iframes |
| `googleSitesInspector.enableGameDetection` | true | Block game engine iframes |
| `googleSitesInspector.enableWorkerDetection` | true | Block CF Worker iframes |
| `googleSitesInspector.enableBase64Detection` | true | Detect base64 content |
| `googleSitesInspector.scanInterval` | 2000 ms | Iframe scan frequency |
| `googleSitesInspector.minSuspiciousFrameSize` | 400 px | Min size for suspicious iframe |
| `heartbeat.enabled` | true | Enable heartbeat |
| `heartbeat.interval` | 5000 ms | Heartbeat check interval |
| `domains.additionalBlacklist` | [] | Extra domains to block (dynamic DNR) |
| `domains.additionalWhitelist` | [] | Extra domains to allow (overrides blocks) |

**Dynamic rule management:** Admins can toggle individual static rules on/off by ID, and add/remove domains via dynamic `declarativeNetRequest` rules (priority 3 for blacklist, priority 10 for whitelist).

---

## Permissions Used

| Permission | Purpose |
|---|---|
| `tabs` | Monitor tab creation, updates, and closures |
| `scripting` | Inject content scripts dynamically |
| `storage` | Read managed config and cache it locally |
| `webNavigation` | Monitor page navigations for proxy detection |
| `declarativeNetRequest` + `declarativeNetRequestFeedback` | Static and dynamic URL blocking rules |
| `host_permissions: <all_urls>` | Apply rules to all URLs |

---

## Relevance to Your Own Websites

Your websites may be flagged if they:

1. **Contain the word "unblock", "unblocker", or "proxy" in their URL** — Rule 1003 matches any URL with `unblock` + `game/site/web`, Rule 1027 matches `holy.*unblocker`, etc.
2. **Are hosted on `*.workers.dev`** (Cloudflare Workers) — Rule 1024 blocks ALL `*.workers.dev` domains with no exceptions.
3. **Are hosted on `*.pages.dev`** — The Google Sites inspector flags iframes from this domain.
4. **Have URLs that include any of the blocked proxy names** (rammerhead, scramjet, tomphttp, etc.) — these are string/regex matches on the full URL.
5. **Use Google Sites to embed iframes** — any blob: URL iframe ≥400px, or any iframe with game engine signatures in its HTML, will be blocked.
6. **Have very long base64 strings in `<script>` tags** combined with `atob()` and `createObjectURL()`.
7. **Rapidly manipulate `history.pushState`** more than 50 times per second (e.g., single-page apps with animation or rapid routing).

**Safe patterns:**
- Domains explicitly in the whitelist (educational platforms) are excluded from all DNR rules and the service worker proxy check.
- The admin can add custom domains to `additionalWhitelist` to allow them at priority 10.
