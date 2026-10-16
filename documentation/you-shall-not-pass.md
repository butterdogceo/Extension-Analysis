# You Shall Not Pass — Extension Analysis

**Version:** 3.3.0  
**Manifest Version:** 3  
**Scope:** Multi-layer anti-evasion extension for managed Chromebooks

---

## Overview

You Shall Not Pass (YSNP) uses layered controls: static/dynamic network rules, navigation heuristics, content-script detection, and Google-surface-specific scanners. Most controls are policy-configurable via managed storage (`managed_schema.json`).

---

## 1) Network Filtering: Declarative Net Request (DNR)

**File:** `rules.json`  
**Rules:** **70 static rules** (IDs `1002`–`1078`)

### What it targets

- Proxy frameworks and variants (Ultraviolet, Scramjet, Rammerhead, Holy Unblocker, TompHTTP, etc.)
- Transport/runtime components (Bare-Mux, Epoxy, Wisp, libcurl transport, bare server signatures)
- Evasion hub naming patterns and known distribution paths
- High-risk hosting patterns frequently used for bypass deployments
- Exploit/tamper loader signatures

### Rule behavior notes

- Uses multiple resource classes (`main_frame`, `sub_frame`, `script`, `xmlhttprequest`, `websocket`, etc.)
- Ships with broad educational/vendor allowlist handling (`excludedRequestDomains`)
- Supports managed per-rule toggles, including split-rule sibling expansion

---

## 2) Dynamic Rule Generation and Admin Overrides

**File:** `background.js` (`applyRuleChanges()`)

YSNP rebuilds dynamic rules on config load/update for:

1. `domains.additionalBlacklist` (block)
2. `domains.additionalWhitelist` (allow, higher priority)
3. `domains.additionalUrlFilters` (path/pattern blocks for main/sub-frame)
4. Classroom controls:
   - `blockYouTubeInDocs` (`docs.google.com`-initiated YouTube surfaces)
   - `blockYouTubeInSearch` (search-engine-initiated embedded players)

---

## 3) Navigation-Time Detection in Background Worker

**File:** `background.js`

### A) Service-worker/proxy URL signature detector

On `webNavigation.onCommitted` (top frame), YSNP matches navigated URLs against extensive proxy/runtime regex signatures. Matched tabs are closed.

### B) `data:text/html` launcher detector

Top-frame `data:text/html` navigations are decoded (where possible) and scanned for conclusive game/proxy fingerprints (launcher vars, ad-fraud hooks, known game-brand catalog signatures, runtime markers). Matched tabs are closed.

---

## 4) History Flood (Point-Blank) Defense

**Files:** `history_guard_main.js`, `content_guard.js`

- MAIN-world wrapper intercepts `History.prototype.pushState`/`replaceState`
- Nonce-authenticated config channel from isolated-world content script
- Configurable threshold (default `50` calls/sec)
- On violation, page is stopped and replaced with a block notice

---

## 5) Content Guard (All-Frames Runtime Protections)

**File:** `content_guard.js`

### A) Anti-extension tamper overlay detection

Detects extension-disabling/tampering control-panel behavior via:

- coined-token selector checks
- high-z-index overlay + hard text-signature checks

On detection: remove element and disrupt flow via capped reload logic.

### B) Cross-page iframe guard (`blob:` / `srcdoc` / dangerous schemes)

Scans iframes for:

- `javascript:` / `vbscript:` sources
- suspicious `srcdoc` content
- inspectable `blob:` frames with conclusive game/hub signatures

### C) Hub-shell bootstrap detector

Scans inline scripts and DOM markers for conclusive hub bootstrap fingerprints (including normalized variants: decoded, reversed, base64-derived text).

### D) Service-worker source scan

Reads same-origin registered SW script(s) and imports, searching for compiled proxy-runtime signatures (Scramjet/UV/Bare-Mux/Sapphire/Rammerhead/Epoxy). On hit, page is neutralized.

### E) Symbaloo hub detection

Adds Symbaloo page-level URL/title/heading checks for unblock-hub keywords that can evade pure URL-rule matching.

---

## 6) Google Sites Inspector (Sites-Specific Pipeline)

**File:** `google_sites_inspector.js` (`*://sites.google.com/*`)

### Techniques

1. **Blob iframe inspection** with size gating + corroboration logic
2. **Iframe content scanning** for game-engine signatures
3. **`srcdoc` inspection** for inline game/launcher signatures
4. **Dangerous scheme blocking** (`javascript:`/`vbscript:` iframe src)
5. **Serverless/static-host embed detection** with random-subdomain + corroboration heuristics
6. **Google-hosted embed evasion detection** (Apps Script / gstatic Atari embed layers / atari-embeds frames), gated by parent-page hub signals
7. **Strict Sites Mode** (optional default-deny iframe allowlist model with built-in and admin-extended allowlists)
8. **Base64 decode+blob payload detection** with corroboration/strict-mode gating
9. **Page-body game catalog scan** (structural marker + multi-brand accumulation)
10. **Service-worker anomaly check** on Sites origin (log-first; aggressive unregistering only under strict+hub conditions)

---

## 7) Apps Script Inspector (Google Apps Script Hosted Content)

**File:** `apps_script_inspector.js`

Runs inside Apps Script-rendered frames (`script.googleusercontent.com` and `*-script.googleusercontent.com`) and blocks pages when rendered HTML matches conclusive game/proxy/ad-fraud fingerprint sets, with corroboration logic for medium-confidence signals.

---

## 8) Classroom-Control UI Scripts

### A) Google AI Overview hider

**File:** `ai_overview_hider.js`  
Optional (`classroomControls.hideGoogleAiOverview`). Hides Google AI Overview and AI Mode entry points on Google Search using selectors + mutation handling + style injection.

### B) Docs/Sheets/Slides YouTube preview blocker

**File:** `docs_youtube_blocker.js`  
Optional (`classroomControls.blockYouTubeInDocs`). Removes/hides embedded YouTube preview surfaces in Docs editors and watches dynamic DOM/attribute changes.

---

## 9) Anti-Tamper Heartbeat and Tab Controls

**File:** `background.js` + `content_guard.js`

- Port heartbeat between content scripts and service worker (`ping`/`pong`)
- Stale-heartbeat monitoring and logging
- Tab-spam detector (sliding window)
- Max-tab enforcement with periodic cleanup
- Bulk-tab-creation handling

---

## 10) Managed Configuration Surface

**File:** `managed_schema.json`

Key admin-tunable groups:

- `rules` (static rule enable/disable)
- `tabLimits`
- `contentGuard`
- `googleSitesInspector`
- `appsScriptInspector`
- `heartbeat`
- `domains` (`additionalWhitelist`, `additionalBlacklist`, `additionalUrlFilters`)
- `classroomControls` (`hideGoogleAiOverview`, `blockYouTubeInDocs`, `blockYouTubeInSearch`)

---

## Relevance to Website Operators

Your site is more likely to be impacted if it:

- uses proxy-framework naming/runtime artifacts
- resembles unblock/proxy/game-hub templates
- embeds high-risk iframe schemes or suspicious serverless deploy patterns on Google Sites
- surfaces game-launcher signatures in inline payloads (`data:`, `srcdoc`, base64 decode + blob flows)

Lower-risk characteristics:

- legitimate educational/vendor domains in YSNP allowlist context
- ordinary non-proxy web apps without evasion signatures
- direct YouTube browsing behavior (unless separately blocked by broader policy)
