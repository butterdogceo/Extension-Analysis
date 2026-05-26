# Lightspeed Filter Helper — Extension Analysis

**Version:** 1.3.3.1779238475
**Publisher:** Lightspeed Systems
**Manifest Version:** 3

---

## Overview

The Lightspeed Filter Helper extension is a companion to the main Lightspeed Chrome Filter. It does **not** perform network-layer blocking on its own. Instead, it adds three client-side enforcement and detection layers:

1. **Category-gated image blurring** using a local TensorFlow.js model
2. **Proxy / bypass-page detection** using DOM, metadata, and URL heuristics
3. **AI prompt / response logging** for supported AI chat sites

It relies on the Lightspeed filtering stack for policy and category decisions, then applies extra enforcement or reporting inside the rendered page.

---

## Architecture

| Component | Role |
|-----------|------|
| `worker.js` | Background service worker; loads policy, checks whether a page category should be blurred, brokers image classification, handles detection reports, buffers AI chat logs |
| `content.js` | Content script on all pages; scans images and CSS background images, applies/removes blur, runs proxy/bypass detectors, captures AI chat activity |
| `offscreen.js` | Offscreen TensorFlow.js runtime; loads the MobileNet V2 model, renders images to canvas, classifies them, and returns class scores |
| `offscreen.html` | Hidden offscreen document used for image classification |
| `models/mobilenet_v2/model.json` + shard | Bundled MobileNet V2 model used for local image scoring |
| `action.html` | Minimal popup UI; mostly status branding |

---

## Filtering Methods & Detection Techniques

### 1. Category-Gated Image Blur

**Trigger:** Page load, existing images, newly inserted images, image `src` changes, and CSS `background-image` changes.

**How it works:**
1. The content script asks the worker whether the current tab **should blur images**.
2. The worker checks whether the helper is enabled and whether the current host's category is in the configured `categories` list.
3. If the host is not cached yet, the worker asks the main Lightspeed filtering stack for the host category, then caches the result by hostname.
4. If the category is eligible, the content script activates continuous scanning.

**Important detail:** the helper only blurs on pages whose category is explicitly included in policy. By default, the built-in `categories` list is empty, so managed policy has to turn this on.

---

### 2. Local NSFW Image Classification

**Files:** `content.js`, `worker.js`, `offscreen.js`, `models/mobilenet_v2/model.json`

**How it works:**
1. The content script finds candidate images from:
   - normal `<img>` tags
   - dynamically added images
   - elements whose computed CSS contains `background-image: url(...)`
2. Each candidate is assigned a deterministic ID based on a SHA-256 hash of its image URL.
3. The worker forwards the image URL to the offscreen document.
4. The offscreen document loads the image into a canvas / `ImageBitmap`, converts it with TensorFlow.js, and runs the bundled **MobileNet V2** model.
5. The model returns per-class scores, which are sent back to the worker.
6. The worker evaluates those scores against policy thresholds and tells the content script whether to blur or unblur the matching image elements.

**Subjects scored by default:**
- `neutral`
- `drawing`
- `hentai`
- `porn`
- `sexy`

**Default thresholds:**

| Subject | Relaxed | Normal | Strict | Notes |
|---------|---------|--------|--------|-------|
| `neutral` | 0.85 | 0.90 | 0.98 | High neutral score suppresses blur |
| `drawing` | 0.50 | 0.50 | 0.50 | Marked ignored by default |
| `hentai` | 0.35 | 0.20 | 0.10 | Lower threshold = more aggressive blur |
| `porn` | 0.35 | 0.10 | 0.02 | Most aggressive category |
| `sexy` | 0.35 | 0.10 | 0.02 | Most aggressive category |

**Notable behavior:**
- A high `neutral` score explicitly prevents blur.
- `drawing` is present but ignored by default.
- The extension supports `relaxed`, `normal`, and `strict` modes.

---

### 3. What the Blur Actually Does

When an image is classified as blur-worthy, the content script:

- adds the `nsfw-blur` class to the matching image/element
- stores a tooltip explaining the reason and scores
- prevents clicks on blurred elements
- blocks the context menu on blurred elements
- shows a hover tooltip panel with the block reason when available

If an image is later reclassified as safe, the blur class and tooltip state are removed.

---

### 4. Image-Scanning Exclusions

The helper avoids or skips several cases:

- browser/internal protocols and excluded hosts such as `localhost`
- pages/categories where blur is not enabled
- broken images or zero-dimension images
- tiny data URLs that look like tracking pixels
- inline SVG data URLs
- some cross-origin images that cannot be safely processed

This means the image blur system is targeted at real, viewable page media rather than every image-like resource.

---

### 5. Mutation-Driven Continuous Scanning

Once blur mode is active for the page, the content script keeps scanning via a `MutationObserver`.

It reacts to:
- newly inserted DOM nodes
- newly inserted `<img>` elements
- `src` changes on existing `<img>` elements
- `style` changes that introduce or change `background-image`

This makes the blur system effective on modern SPAs and infinite-scroll pages, not just on initial page load.

---

### 6. Proxy / Bypass Page Detection

**Trigger:** Content script startup, deferred rescans, and optional DOM observation.

The helper contains a second detection system aimed at finding **web proxies, unblockers, and game-launcher / bypass pages**.

#### a. Runtime / framework fingerprints

It looks for artifacts associated with known proxy frameworks, including:
- **Scramjet**
- **Ultraviolet**
- **BareMux / bare-mux**
- `ob-fonts` runtime assets

Examples include URL/script patterns like:
- `/runtime/scramjet/`
- `scramjet.all.js`
- `new Ultraviolet`
- `uv.bundle.js`, `uv.config.js`, `uv.sw.js`, `uv.handler.js`
- `new BareClient`
- `BareMux`
- `ob-fonts.css` / `ob-fonts.js`

#### b. Proxy UI heuristics

It scores pages that look like proxy front-ends by searching for:
- URL input fields
- proxy-themed forms
- proxy-themed submit buttons
- embedded proxy iframes
- server-selection dropdowns
- button text such as `proxy`, `go anonymous`, `unblock`, `browse privately`

#### c. Proxy-template detection

It has framework-specific signatures for classic proxy templates:
- **Glype Proxy**
- **PHProxy**
- **CGIProxy**
- **UltraSurf**
- a generic “modern web proxy” pattern

Those signatures check form actions, hidden field names, select names, checkbox names, and proxy-branded text markers.

#### d. Keyword scoring

It searches page text for weighted phrases such as:
- `unblock websites`
- `hide my ip`
- `anonymous`
- `vpn`
- `bypass`
- `secure browsing`
- `zero logs`
- `logless`

It also uses higher-level regexes for requests like:
- entering/pasting a URL to browse
- bypassing a filter/firewall
- anonymous browsing / hiding identity
- unblocking platforms like YouTube, Facebook, Instagram, TikTok, Discord
- school/work/library proxy language

#### e. Education-brand spoofing

The detector also tries to catch launcher or proxy pages impersonating school-approved sites.

It compares the current host against:
- canonical-domain metadata
- Open Graph domain metadata
- Open Graph image hosts
- title/meta description text
- page-shape metrics such as element count, text length, link count, and navigation count

It specifically treats domains like `khanacademy.org` and `classroom.google.com` as trusted education-brand references and flags pages that claim those brands on unrelated hosts.

#### f. Known-domain fallback

The detector has a built-in list of known or suspicious proxy domains and also supports administrator-supplied `customProxyDomains`.

---

### 7. Detection Reporting / Proxy Blocking Integration

When the bypass detector finds a proxy/game page, the content script sends a detection report containing:

- full URL
- hostname
- top-frame hostname
- whether it matched **proxy**
- whether it matched **game**
- timestamp

The worker forwards that report to the broader Lightspeed filtering stack. Visible code paths show support for:
- `detect:init`
- `detect:report`
- `proxyBlock`
- `filterCategory`

So the helper acts as an in-page sensor, while the main filter agent decides what broader enforcement or reporting should happen next.

---

### 8. AI Prompt / Response Logging

The helper also monitors supported AI chat sites and reports AI-session content to an SQS-backed pipeline.

**Captured fields include:**
- product / service name
- prompt text
- response text
- derived category
- academic subject classification
- response type classification
- auth status
- service user
- service tier
- conversation ID
- model name
- whether file upload was used
- upload file names/types

**Worker behavior:**
- buffers AI chat events locally
- deduplicates near-identical events
- stores the buffer in `chrome.storage.local`
- flushes buffered logs on an alarm and on service-worker suspend
- sends to AWS SQS: `https://sqs.us-west-2.amazonaws.com/019914387469/ai-prompt-reporting`

**Response-type analysis detects:**
- refusal / no-response behavior
- partial refusal / caveated response
- normal responses

**Prompt analysis looks for topics such as:**
- entering a target URL
- bypassing a filter or firewall
- anonymous browsing / hiding IP
- unblocking social/video platforms
- school/work/library circumvention

This is not URL filtering, but it is still a filtering-related detection layer because it watches for user intent to bypass school restrictions.

---

### 9. Policy and Persistence

The worker loads managed policy overrides from `chrome.storage.managed`.

Relevant policy-controlled fields include:
- `enabled`
- `categories`
- `level`
- `subjects`
- `bypassDetectEnabled`
- `bypassDetectLevel`
- `bypassDetectGameAggregators`
- `customProxyDomains`
- `detectionCache`
- `showBlockReason`
- `enableAIChatLogging`

The extension also persists:
- host-category cache in memory
- detector cache data
- AI chat buffers in `chrome.storage.local`
- TensorFlow model artifacts in IndexedDB inside the offscreen runtime

---

## Practical Takeaways

### What can affect your site?

Your site can be affected if it:

1. lands in a category that administrators configured for image blurring
2. serves images that score as `porn`, `sexy`, or `hentai`
3. looks like a proxy front-end or unblocker UI
4. imitates school-trusted brands on an unrelated host
5. contains well-known proxy framework artifacts
6. encourages users to bypass filters, unblock sites, or browse anonymously

### What it does **not** do

- It does **not** block network requests directly like the Chrome Filter Agent.
- It does **not** decide categories by itself; it depends on Lightspeed policy/category data.
- Its image model runs locally and only blurs rendered media on pages where policy says blur is enabled.
