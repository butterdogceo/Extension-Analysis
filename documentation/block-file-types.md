# Block File Types — Extension Analysis

**Version:** 0.0.3  
**Author:** Clay Smith  
**Manifest Version:** 3

---

## Overview

Block File Types is a simple extension that prevents students from opening local files of specific, administrator-configured extensions via the `file://` URL scheme. When a blocked file type is detected, the tab is closed and replaced with a "blocked" page.

---

## Filtering Methods & Detection Techniques

### 1. File Extension Matching on `file://` URLs

**Trigger:** Any tab activation (`tabs.onActivated`) or tab update (`tabs.onUpdated`).

**How it works:**

1. Retrieves the list of blocked file extensions from local storage (populated by managed storage policy).
2. For each blocked extension, constructs a case-insensitive regular expression: `<ext>$` (e.g., for `exe`, the regex is `/exe$/i`).
3. Checks whether the current tab's URL starts with `file://` using `/file:///`.
4. If both the `file://` scheme regex **and** the extension regex match the URL, the tab is closed.
5. A new tab is opened with a `data:text/html` URL containing a "This file type is not allowed." message.

**Example blocked URL:** `file:///C:/Users/student/Downloads/game.exe`

**Key code logic:**
```js
const ext = `${type}$`;
const re = new RegExp(ext, 'i');
const schema = new RegExp('file://');
if (schema.test(res.url) && re.test(res.url)) {
  block = true;
}
```

**Scope:** Only applies to `file://` URLs — does not intercept web traffic.

---

### 2. Managed Policy Configuration

**How it works:**

The list of blocked file extensions is set by a Google Workspace administrator via Chrome's managed storage API. On startup, the extension reads the `blocktypes` array from `chrome.storage.managed` and copies it to `chrome.storage.local`.

**Schema (`schema.json`):**
```json
{
  "blocktypes": ["exe", "bat", "vbs", "ps1", ...]
}
```

Administrators can define any array of file extension strings. The extension checks each one as a case-insensitive suffix match against the full URL.

---

## Permissions Used

| Permission | Purpose |
|---|---|
| `storage` | Reads managed policy and stores blocked types locally |
| `tabs` | Listens for tab activation/updates and closes blocked tabs |
| `host_permissions: file://*` | Allows access to `file://` tab URLs |

---

## What This Extension Does NOT Do

- Does not intercept HTTP/HTTPS traffic.
- Does not scan page content.
- Does not report blocked events to any server.
- Does not detect proxies or bypass tools.

---

## Relevance to Your Own Websites

This extension **only triggers on local file:// URLs**. Websites served over HTTP/HTTPS are completely unaffected by this extension regardless of their URL or content.
