# Browser Extension Filtering Analysis

This documentation covers every filtering and detection method used by the browser extensions installed on managed Chromebooks. It is organized by extension, with a detailed breakdown of each technique.

---

## Extensions Analyzed

| Extension | Purpose | Detailed Documentation |
|-----------|---------|----------------------|
| **Block File Types** | Blocks local files with specific extensions from opening in the browser | [View →](./block-file-types.md) |
| **You Shall Not Pass** | Comprehensive anti-bypass extension targeting web proxies, exploit tools, and Google Sites abuse | [View →](./you-shall-not-pass.md) |
| **Lightspeed Suite** | Commercial K-12 content filter, classroom monitor, and device telemetry platform | [View →](./lightspeed/overview.md) |
| ↳ Lightspeed Chrome Filter Agent | URL categorization, WASM-based policy engine, request blocking/redirecting | [View →](./lightspeed/chrome-filter.md) |
| ↳ Lightspeed Filter Helper | Client-side image blurring, proxy/bypass-page detection, AI prompt logging | [View →](./lightspeed/filter-helper.md) |
| ↳ Lightspeed Classroom Agent | Teacher monitoring, real-time screen sharing, browsing visibility | [View →](./lightspeed/classroom-agent.md) |
| ↳ Lightspeed Identity Agent | OAuth2 identity broker for other Lightspeed extensions | [View →](./lightspeed/identity-agent.md) |
| ↳ Lightspeed Signal Agent | Device telemetry, speed testing, page timing, geolocation | [View →](./lightspeed/signal-agent.md) |

---

## Extension Summaries

---

### 1. Block File Types

**Extension:** `Block File Types/`  
**What it does:** Monitors all tab navigations. If the URL begins with `file://` and ends with a blocked file extension (configured by administrators via managed storage), the tab is immediately closed and replaced with a "blocked" notice.

**Filtering methods:**
- Case-insensitive file extension suffix matching against `file://` URLs
- Only triggers on local filesystem URLs — has no effect on HTTP/HTTPS traffic

**[→ Full Documentation](./block-file-types.md)**

---

### 2. You Shall Not Pass

**Extension:** `You Shall Not Pass/`  
**What it does:** A layered, open-source anti-evasion extension that blocks the entire ecosystem of student filter-bypass tools. It combines static URL rules, dynamic service worker detection, DOM-level exploit detection, and abuse-resistant tab management.

**Filtering methods:**
1. **24 Declarative Net Request rules** — Static URL pattern/regex blocks targeting specific proxy frameworks (Ultraviolet, Rammerhead, Scramjet, Holy Unblocker, TompHTTP, etc.), Cloudflare Workers, GitHub Pages games, and exploit loaders
2. **Service worker proxy detection** — Regex pattern matching on navigated URLs to detect proxy frameworks by name in the URL
3. **History flooding defense** — Monkey-patches `history.pushState`/`replaceState`; blocks requests if >50 calls/second (stops "Point-Blank" attacks)
4. **LTBEEF GUI detector** — Scans DOM every 5 seconds for exploit tool UI elements (`.ingot-overlay`, `#ltbeef-ui`, `#ext-remover`, etc.)
5. **Google Sites iframe scanner** — Inspects all iframes on `sites.google.com` for blob URLs, game engine signatures, Cloudflare Worker hostnames, and base64 content in scripts
6. **Tab spam detection** — Closes excess tabs if >5 are created within 2 seconds
7. **Tab limit enforcement** — Hard cap of 15 open tabs; closes least-recently-used tabs
8. **Heartbeat anti-tamper** — Continuous ping/pong between content scripts and background to detect tampering

**[→ Full Documentation](./you-shall-not-pass.md)**

---

### 3. Lightspeed Chrome Filter Agent

**Extension:** `Lightspeed/Chrome Filter/`  
**What it does:** The primary commercial content filter. Uses a compiled WebAssembly policy engine to classify and block URLs in real-time based on Lightspeed's cloud-managed category database and per-user policies.

**Filtering methods:**
1. **WASM URL classification** (`filter.wasm`) — Classifies every URL into content categories; blocks if category is policy-restricted
2. **`onBeforeRequest` pre-scan** — Fast early-stage check before the request is sent
3. **`onHeadersReceived` scoring** — Full policy evaluation on response headers; redirects to block page or cancels
4. **Cloud-based "on-hold" lookup** — Unknown URLs are held pending cloud classification (up to 20 retry cycles)
5. **YouTube Restricted Mode injection** — Adds `YouTube-Restrict: Strict/Moderate` header to all YouTube requests
6. **Google Workspace domain restriction** — Adds `X-GoogApps-Allowed-Domains` header to force school-only Google sign-in
7. **Search term & typed content scoring** — Content script extracts text from ChatGPT, Gmail, Docs, Google Search, Facebook, Gemini and scores it against flagged-terms list
8. **Proxy/exploit tab detection** — `ls-exploits-js` monitors tabs and bookmarks for known exploit tool signatures
9. **Real-time policy sync** — WebSocket to `wss://production-gc.lsfilter.com` for instant policy updates
10. **Violation reporting** — All blocked requests logged to AWS SQS

**[→ Full Documentation](./lightspeed/chrome-filter.md)**

---

### 4. Lightspeed Filter Helper

**Extension:** `Lightspeed/Filter Helper/`
**What it does:** A companion extension that applies client-side filtering and detection inside the page. It can blur images on policy-selected page categories, detect proxy/unblocker pages by their UI and runtime artifacts, and log AI prompts/responses related to circumvention.

**Filtering/detection methods:**
1. **Category-gated image blur** — asks the Lightspeed filtering stack for the current host category and only enables blur on configured categories
2. **Local NSFW image classification** — MobileNet V2 model in an offscreen document scores images as `neutral`, `drawing`, `hentai`, `porn`, or `sexy`
3. **Continuous image rescanning** — scans existing `<img>` tags, new DOM nodes, `src` changes, and CSS `background-image` URLs
4. **Proxy framework detection** — looks for Scramjet, Ultraviolet, BareMux, `ob-fonts`, and similar runtime artifacts
5. **Proxy template/UI detection** — matches proxy URL fields, buttons, iframes, hidden form fields, and classic templates like Glype, PHProxy, CGIProxy, and UltraSurf
6. **Education-brand spoofing detection** — compares canonical/Open Graph metadata and page structure against trusted school-oriented brands
7. **Known-domain fallback** — flags hardcoded and admin-configured proxy domains even if page heuristics are weak
8. **AI circumvention intent logging** — captures AI prompts/responses and classifies requests about unblocking, bypassing filters, anonymous browsing, and similar behavior

**[→ Full Documentation](./lightspeed/filter-helper.md)**

---

### 5. Lightspeed Classroom Agent

**Extension:** `Lightspeed/Classroom/`  
**What it does:** Student-side classroom monitoring agent. Shares its content script architecture with the Chrome Filter. Primary functions are teacher visibility and real-time screen monitoring — not URL blocking.

**Filtering/monitoring methods:**
1. **Real-time tab monitoring** — Reports all visited URLs to the teacher dashboard
2. **Content intent extraction** — Extracts typed text from Gmail, Docs, Google Search, Facebook, Gemini, ChatGPT
3. **Screen capture** — `desktopCapture`/`tabCapture` allows teachers to view student screens without approval
4. **Teacher notifications** — Can display native OS notifications on student's device
5. **Bookmarks monitoring** — Watches for bookmarks pointing to exploit tools

**[→ Full Documentation](./lightspeed/classroom-agent.md)**

---

### 6. Lightspeed Identity Agent

**Extension:** `Lightspeed/Identity Agent/`  
**What it does:** Silent OAuth2 identity broker. Acquires the student's Google account email and shares it with other Lightspeed extensions. No filtering or content analysis — purely infrastructure.

**[→ Full Documentation](./lightspeed/identity-agent.md)**

---

### 7. Lightspeed Signal Agent

**Extension:** `Lightspeed/Signal Agent/`  
**What it does:** Device telemetry collector. No URL blocking. Collects performance, network, hardware, and location data from the student device and sends it to Lightspeed's cloud.

**Data collection methods:**
1. **Navigation/Resource Timing API** — Collects page load and resource timing data from every page visited
2. **Network speed tests** — Active upload/download speed tests via WebTransport (HTTP/3)
3. **Geolocation** — GPS coordinates via `navigator.geolocation`
4. **Battery status** — Charge level, charging state, time-to-empty via `navigator.getBattery()`
5. **System hardware metrics** — CPU, memory, storage, hardware model, local IP address
6. **Exploit tab detection** — Same `ls-exploits-js` module as Chrome Filter; closes tabs matching exploit signatures

**[→ Full Documentation](./lightspeed/signal-agent.md)**

---

## Key Takeaways for Your Own Websites

### What Could Trigger a Block

| Trigger | Extension Responsible |
|---------|----------------------|
| URL categorized as games, adult content, social media, etc. | Lightspeed Chrome Filter (WASM engine) |
| Page is in a configured blur category and an image scores as `porn`, `sexy`, or `hentai` | Lightspeed Filter Helper |
| Page contains proxy/unblocker UI, proxy framework artifacts, or spoofed education-brand metadata | Lightspeed Filter Helper |
| AI prompt/response asks how to unblock sites, bypass filters, or browse anonymously | Lightspeed Filter Helper |
| URL contains "unblock" + "game/site/web" | You Shall Not Pass (Rule 1003) |
| Site hosted on `*.workers.dev` | You Shall Not Pass (Rule 1024) |
| Site hosted on `*.pages.dev` + has game/proxy in URL | You Shall Not Pass (Rules 1017, 1023) |
| URL matches any known proxy framework name (rammerhead, ultraviolet, scramjet, etc.) | Both You Shall Not Pass and Lightspeed |
| Google Sites embedding iframe ≥400px using blob: URL | You Shall Not Pass |
| Google Sites embedding iframe with game engine signatures | You Shall Not Pass |
| Page calls `history.pushState` >50 times/second | You Shall Not Pass |
| `<script>` contains base64 string >1000 chars + `atob()` + `createObjectURL` | You Shall Not Pass (warning) |
| Local `file://` URL with blocked file extension | Block File Types |

### What Does NOT Trigger a Block

- Sites on the educational whitelist (Wikipedia, Khan Academy, Google Workspace, etc.) are excluded from You Shall Not Pass's DNR rules.
- The Classroom Agent and Signal Agent **never block URLs** — they only observe and report.
- The Identity Agent has **no filtering behavior** whatsoever.
- The Filter Helper does **not** block requests itself; it blurs page images and reports bypass/AI activity.
- Normal HTTP/HTTPS websites served without proxy-tool naming patterns are not affected by You Shall Not Pass.
- Lightspeed blocking is policy-configurable — the school admin controls which categories are blocked.

### Techniques You Can Learn From

- **Declarative Net Request rules** are fast, efficient, and cannot be bypassed by page scripts — excellent for static URL pattern blocking.
- **Regex matching on navigation events** (service worker proxy detection) is a lightweight way to catch known bad URL patterns without the overhead of DNR rule deployment.
- **DOM mutation observers** combined with periodic polling are effective at catching dynamically-injected exploit elements.
- **History API monkey-patching** catches client-side navigation abuse that URL-based rules miss entirely.
- **Response header injection** (YouTube-Restrict, X-GoogApps-Allowed-Domains) enforces platform-level restrictions that are independent of URL filtering.
- **Typed content analysis** (extracting text from input boxes) extends filtering beyond URLs to actual intent signals.
