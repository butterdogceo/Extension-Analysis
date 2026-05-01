# Lightspeed Classroom Agent — Extension Analysis

**Version:** 5.3.0.1777318718  
**Publisher:** Lightspeed Systems  
**Manifest Version:** 3

---

## Overview

The Lightspeed Classroom Agent is the student-side component of Lightspeed's real-time classroom management system. It runs on student Chromebooks and allows teachers to monitor browsing activity, see student screens, send alerts, and manage what students can view during lessons. The code is heavily obfuscated.

---

## Architecture

| Component | Role |
|-----------|------|
| `worker.js` (background service worker) | Obfuscated — manages tabs, screen sharing, and communication with Classroom server |
| `content.js` (66 KB, obfuscated) | Content script — gathers page intent/typed content from specific sites |
| `rtc_connection.js` | WebRTC connection management for screen sharing |
| `console.html` / `offscreen.html` | Offscreen documents for screen capture |
| `menu.html` | Browser action popup (status indicator) |

---

## Filtering & Monitoring Methods

---

### 1. Content Intent Gathering (Content Script)

**File:** `content.js` (obfuscated, shared architecture with Chrome Filter)  
**Trigger:** Runs on all pages, all frames

The content script contains site-specific modules that extract user-typed content from pages:

| Module | Site | What It Extracts |
|--------|------|-----------------|
| ChatGPT module | `chatgpt.com` | Content of the prompt textarea (`#prompt-textarea`) |
| Facebook module | `facebook.com` | Content of all `[role="textbox"]` elements (posts, comments) |
| Gemini module | `gemini.google.com` | Content of Gemini AI prompt fields |
| Gmail module | `mail.google.com` | Content of all `[role="textbox"]` elements (email compose) |
| Google Docs module | `docs.google.com` | `document.body.innerText` (full document text) |
| Google Search module | `google.com` | `input[name="q"]` value (search query) |

**Intent scoring flow:**
1. Listens for DOM input events on `<input>`, `<textarea>`, and `[role="textbox"]` elements.
2. Also handles explicit "scan" action messages from the background.
3. Collected text is scored against a flagged-terms list via the relay API.
4. If terms are matched (`RelayFlaggedTerms`), the finding is stored and can be reported to the teacher dashboard.

---

### 2. Tab Monitoring and Web Request Interception

**Permission:** `webRequest`, `tabs`, `activeTab`

The background service worker monitors all tab activity:
- Tracks which URLs the student visits (tab title and URL reported to teacher dashboard)
- Can receive commands from the teacher to close tabs or navigate the student's browser
- The teacher can see the student's current active tab URL in real time

---

### 3. Screen Capture and Sharing

**Permissions:** `desktopCapture`, `tabCapture`, `offscreen`

The Classroom Agent enables teachers to view student screens in real-time via WebRTC:

1. **`desktopCapture`**: Captures the entire desktop or specific application windows.
2. **`tabCapture`**: Captures the content of individual browser tabs.
3. **`offscreen`** + `offscreen.html`: Uses an offscreen document (Chrome MV3 pattern) to maintain a MediaStream capture context without a visible window.
4. **`rtc_connection.js`**: Manages the WebRTC peer connection, ICE negotiation, and stream transmission to the teacher's browser.

The screen sharing is triggered by the teacher from the Classroom console. The student does **not** need to accept or approve the capture request — it is initiated server-side.

---

### 4. Notifications

**Permission:** `notifications`

The extension can display Chrome OS native notifications on the student's device — used by teachers to send alerts or announcements directly to student Chromebooks.

---

### 5. Bookmarks Monitoring

**Permission:** `bookmarks`

Monitors bookmark creation events. This is likely used to detect if students are bookmarking blocked sites or proxy tools, consistent with the `ls-exploits-js` library behavior described in the Chrome Filter analysis.

---

### 6. Identity Resolution

**Permissions:** `identity`, `identity.email`, `enterprise.deviceAttributes`

Resolves the student's Google account email (same cascade as the Chrome Filter: email → serial number → guest GUID) and reports it to Lightspeed's Classroom server for associating activity with a specific student.

---

### 7. Idle State Monitoring

**Permission:** `idle`

Detects when the student's device is idle (screen locked, no activity). Likely used to pause monitoring or report student inactivity to the teacher.

---

## External Connectivity

| Endpoint | Purpose |
|----------|---------|
| Lightspeed Classroom servers | Real-time teacher/student synchronization |
| `lsrelay-extensions-production.s3.amazonaws.com` | Extension updates |
| WebRTC peer connection (teacher browser) | Screen sharing stream |

The extension is configured to accept connections only from the extension ID `kkbmdgjggcdajckdlbngdjonpchpaiea` via `externally_connectable` — this is the Lightspeed Classroom teacher-side extension.

---

## Permissions Summary

| Permission | Purpose |
|---|---|
| `activeTab` | Access current tab URL and content |
| `background` | Persistent background worker |
| `bookmarks` | Monitor bookmark creation |
| `desktopCapture` | Capture student screen (teacher-initiated) |
| `enterprise.deviceAttributes` | Get device serial for identity |
| `identity` + `identity.email` | Resolve student's Google account |
| `idle` | Detect device idle state |
| `offscreen` | Maintain screen capture context |
| `storage` | Store session state and cached data |
| `tabCapture` | Capture individual tab content |
| `tabs` | Monitor and control browser tabs |
| `notifications` | Display teacher alerts on student device |
| `webRequest` | Intercept outbound requests |
| `host_permissions: <all_urls>` | Access all page content |

---

## Relevance to Your Own Websites

The Classroom Agent primarily focuses on **teacher visibility**, not URL-based blocking (that is handled by the Chrome Filter). However:

1. **Content typed on your website may be reported** — if students use text inputs on your site, and the content triggers flagged-term detection, this could be reported to the teacher.

2. **Browsing activity is visible to teachers** — any visit to your website will appear in the teacher's real-time activity view.

3. **No URL-based blocking** — the Classroom Agent does not independently block URLs; it relies on the Chrome Filter for that function.

4. **Screen contents are visible** — if a teacher initiates screen sharing while a student is on your site, the teacher will see the page content in real time.
