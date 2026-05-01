# Lightspeed Identity Agent — Extension Analysis

**Version:** 1.0.2.1776213267  
**Publisher:** Lightspeed Systems  
**Manifest Version:** 3

---

## Overview

The Lightspeed Identity Agent is a lightweight OAuth2 identity broker. Its sole purpose is to resolve and share the signed-in user's Google account email with other Lightspeed extensions. It acts as a centralized identity provider so that each Lightspeed extension doesn't need to independently manage OAuth flows.

---

## How It Works

### 1. OAuth2 Token Acquisition

**Scopes requested:**
- `https://www.googleapis.com/auth/userinfo.email`
- `https://www.googleapis.com/auth/userinfo.profile`

**OAuth2 Client ID:** `456445855346-fbctaog1osups8vh5p8jndn3evcnt3b8.apps.googleusercontent.com`

The extension uses Chrome's built-in `chrome.identity` API to request an OAuth2 access token from Google using the Chromebook's managed device identity. This is a silent, non-interactive flow — no login prompt appears for the user.

The token is used to obtain the user's Google account email address and profile information.

---

### 2. Identity Sharing with Other Extensions

The Identity Agent exposes its resolved identity to other Lightspeed extensions via Chrome's `externally_connectable` messaging API.

**Authorized extension IDs (can request identity):**

| Extension ID | Extension |
|---|---|
| `molgbfminhipdelmipmknlibjddljlne` | Lightspeed Filter (variant) |
| `ijmiopojbbpfnaobejkkjpcdipbijgcd` | Lightspeed Filter (variant) |
| `oabgjilkcpjhblbghejemfighgjhecjl` | Lightspeed Filter/Agent (variant) |
| `njdniclgegijdcdliklgieicanpmcngj` | Lightspeed Agent (variant) |
| `ehnniokiiebpinnfegpkdlcamgdcaaje` | Lightspeed Agent (variant) |
| `opckliiodihlmpliejjddbpdjdhdkefm` | Lightspeed Agent (variant) |
| `deognlgdmdbhpkjgickmfaiilpjpbcna` | Lightspeed Agent (variant) |

The background worker uses `chrome.alarms` to periodically refresh the token.

---

### 3. Device Attribute Collection

**Permission:** `enterprise.deviceAttributes`

Reads the device serial number via `chrome.enterprise.deviceAttributes.getDeviceSerialNumber()`. This is used as a fallback identifier when no Google account email is available (e.g., for shared/guest sessions).

---

## What This Extension Does NOT Do

- Does not intercept web traffic.
- Does not block any URLs.
- Does not scan page content.
- Does not report browsing activity.
- Solely provides OAuth identity to other Lightspeed components.

---

## Permissions Summary

| Permission | Purpose |
|---|---|
| `alarms` | Periodically refresh OAuth token |
| `enterprise.deviceAttributes` | Get device serial number as fallback identity |
| `identity` + `identity.email` | Acquire OAuth2 token and user email |
| `storage` | Cache resolved identity and token |

---

## Relevance to Your Own Websites

The Identity Agent has **no direct impact** on website filtering. It operates entirely in the background and does not touch web traffic. Its output (the user's email) is consumed by the Chrome Filter and Classroom Agent to personalize filtering policy and reporting.
