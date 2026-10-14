// You Shall Not Pass - Enterprise Hardened v3.3.0
// Apps Script Inspector
// Maintained by TeacherMagic.org
//
// Runs inside the frame that hosts the actual rendered content of a Google
// Apps Script web app. HtmlService apps (every game launcher) render in a
// sandboxed per-deployment frame at
//   https://n-<hash>-0lu-script.googleusercontent.com/userCodeAppPanel
// and ContentService output redirects to script.googleusercontent.com/macros/.
// Builds before 3.2.4 only matched the latter, so this inspector never ran on
// HtmlService web apps at all. The manifest now also matches
// *.googleusercontent.com/userCodeAppPanel*, and the host guard below keeps
// the script inert on every other googleusercontent.com surface. Catches the
// case where a student deploys their own Apps Script web app (often
// from their school Workspace account via the /a/macros/{domain}/
// deployment form) and uses it to host a game directly, bypassing the
// Google Sites embedding flow that google_sites_inspector.js covers.
//
// We can't inspect this content from the parent script.google.com page
// because of cross-origin restrictions — but a content script targeted
// at script.googleusercontent.com runs inside the iframe and has full
// access to the rendered HTML/JS.

(function() {
  'use strict';

  // Host guard. The userCodeAppPanel match pattern is scoped by path, but its
  // host wildcard covers all of googleusercontent.com; only act on Apps Script
  // hosts. about:blank child frames have no hostname of their own, so use the
  // origin they inherit from their creator.
  function effectiveHostname() {
    try {
      const o = self.origin;
      if (o && o !== 'null') return new URL(o).hostname;
    } catch (e) {}
    return location.hostname || '';
  }
  const HOST = effectiveHostname();
  if (!(HOST === 'script.googleusercontent.com' || /-script\.googleusercontent\.com$/i.test(HOST))) return;

  // ============================================================================
  // CONFIGURATION
  // ============================================================================

  let CONFIG = {
    ENABLED: true
  };

  function loadConfigFromBackground() {
    try {
      chrome.runtime.sendMessage({ type: 'GET_CONFIG' }, (response) => {
        if (chrome.runtime.lastError || !response) return;
        if (response.appsScriptInspector) {
          CONFIG.ENABLED = response.appsScriptInspector.enabled !== false;
        }
      });
    } catch (e) {
      // Extension context may not be available yet
    }
  }

  // Listen for config updates from background. Only accept messages from
  // our own extension's service worker.
  chrome.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== chrome.runtime.id || sender.tab) return;
    if (message.type === 'CONFIG_UPDATED' && message.config?.appsScriptInspector) {
      CONFIG.ENABLED = message.config.appsScriptInspector.enabled !== false;
    }
  });

  // ============================================================================
  // GAME CONTENT FINGERPRINTING
  // ============================================================================

  // Apps Script is widely used legitimately for teacher forms, surveys,
  // dashboards, attendance trackers, and custom UIs. These patterns are
  // characteristic of game content and essentially do not appear in
  // legitimate teacher use:

  // HIGH-confidence patterns — any single match blocks alone.
  // CONCLUSIVE — any single match blocks. Proxy frameworks, ad-fraud
  // distribution networks, launcher variable conventions, Flash/base64
  // payload plumbing, referrer/IMA spoofing, and the hub grid marker. None of
  // these occur in a teacher-built dashboard, form, or catalog.
  const CONCLUSIVE_GAME_PATTERNS = [
    // Ad-fraud distribution networks
    /\b(api\.)?gamemonetize\.com\b/i,
    /\b(ads\.)?gamedistribution\.com\b/i,
    // Web-proxy frameworks (an Apps Script deployment can host a proxy too).
    /scramjet\.(all|sync|wasm|worker|shared|controller)\.(?:js|wasm)/i,
    /\$scramjetLoad(?:Controller|Worker)\b/,
    /\bScramjet(?:ServiceWorker|Controller)\b/,
    /\bBareMux(?:Connection)?\b/,
    /\bEpoxyClient\b/,
    /\/baremux\/worker\.js/i,
    /\buv\.bundle\.js\b/i,
    // SWF Flash blob URL conversion — hubs supporting classic flash games
    /\bswfToBlobUrl\b/,
    /application\/x-shockwave-flash/,
    // Base64-encoded game payloads
    /data:@file\/(xml|html);base64/i,
    // IMA ad SDK URL spoofing — purely ad-fraud behavior
    /google\.ima\.AdsRequest/,
    /Object\.defineProperty\s*\(\s*document\s*,\s*['"]referrer['"]/i,
    // Game-launcher variable naming conventions
    /\bgameXmlUrl\b/,
    /\bgoogleScriptUrl\b/,
    // Structural marker — the dominant hub template uses this exact id
    // for its games grid container.
    /id\s*=\s*["']free-game-grid["']/i
  ];

  // CORROBORATING — require TWO distinct matches. Game engines are used in
  // K-12 game-design coursework (a student's Construct 3 or Unity project
  // deployed as a web app is legitimate), consumer portals get linked from
  // brain-break pages, and a single brand name is an offhand mention: a PE
  // page saying "Duck Life challenge", a library catalog with a book called
  // "OvO". Two or more together is a catalog. (Before 3.3.0 every one of
  // these blocked alone; this inspector had never actually run on
  // HtmlService apps before 3.2.4, so the list was never field-tested.)
  const CORROBORATING_GAME_PATTERNS = [
    // Game engines — each engine is ONE signal, however many of its markers
    // appear, so a lone class project never corroborates itself.
    /createUnityInstance\s*\(|\bunity-canvas\b/i,
    /\bc3runtime\b|\bruntimeScriptList\s*:/i,
    // Consumer game portals that hubs proxy/embed content from
    /\b(?:www\.)?poki\.com\b/i,
    /\b(?:www\.)?crazygames\.com\b/i,
    /\by8\.com\b/i,
    /\barmorgames\.com\b/i,
    /\baddictinggames\.com\b/i,
    /\bnewgrounds\.com\b/i,
    // Commercial game brand names (kept in sync with google_sites_inspector.js
    // GAME_BRAND_PATTERNS and background.js DATA_URL_GAME_PATTERNS)
    /\bRetro\s*Bowl\b/i,
    /\bBitLife\b/i,
    /\bPolytrack\b/i,
    /\bSnow\s*Rider\s*3D\b/i,
    /\bGranny\s+Original\b/i,
    /\bEaglercraft\b/i,
    /\b1v1\.lol\b/i,
    /\bDrift\s*Hunters\b/i,
    /\bTunnel\s*Rush\b/i,
    /\bBasket(?:ball)?\s*(?:Random|Bros|Stars)\b/i,
    /\bTime\s*Shooter\s*\d/i,
    /\bSubway\s*Surfers\b/i,
    /\bFriday\s*Night\s*Funkin/i,
    /\bCookie\s*Clicker\b/i,
    /\bSlope\s*(?:Game|Ball|3D|Tunnel|Run)\b/i,
    /\bTomb\s*of\s*the\s*Mask\b/i,
    /\bStick\s*War\b/i,
    /\bSlither\.io\b/i,
    /\bPaper\.io\b/i,
    /\bMoto\s*X3M\b/i,
    /\bGetaway\s*Shootout\b/i,
    /\bSmash\s*Karts\b/i,
    /\bBloxd\.io\b/i,
    /\bShell\s*Shockers\b/i,
    /\bKrunker\b/i,
    /\bGeometry\s*Dash\b/i,
    /\bMinecraft\s*(?:Classic|Unblocked)\b/i,
    /\bIdle\s*Breakout\b/i,
    /\bVex\s*\d\b/,
    /\bDuck\s*Life\b/i,
    /\bPapa'?s\s+(?:Freezeria|Pizzeria|Burgeria|Scooperia|Sushiria|Wingeria|Taco\s*Mia|Pancakeria|Cheeseria|Bakeria|Hot\s*Doggeria|Cupcakeria)\b/i,
    /\bHappy\s*Wheels\b/i,
    /\bDoodle\s*Jump\b/i,
    /\bOvO\b/,
    /\bBaldi'?s\s+Basics\b/i,
    /\bHouse\s*of\s*Hazards\b/i
  ];

  function pageLooksLikeGame() {
    // Single regex scan over the full rendered HTML. Apps Script content
    // pages are typically small, so this is cheap. We use the rendered DOM
    // (not network responses) so we catch content even when it's injected
    // dynamically by the user's deployed script.
    let html = '';
    try {
      html = document.documentElement.outerHTML || '';
    } catch (e) {
      return false;
    }

    if (!html) return false;

    // Inline images are base64 runs of random letters; a short brand token
    // like "OvO" or "Vex 3" can occur inside one by chance. Strip data: URIs
    // before matching so an embedded logo can't trip the catalog test.
    html = html.replace(/data:[a-z0-9.+/-]+;base64,[A-Za-z0-9+/=]+/gi, '');

    for (const pattern of CONCLUSIVE_GAME_PATTERNS) {
      if (pattern.test(html)) return true;
    }
    let corroborating = 0;
    for (const pattern of CORROBORATING_GAME_PATTERNS) {
      if (pattern.test(html) && ++corroborating >= 2) return true;
    }
    return false;
  }

  // ============================================================================
  // PAGE NEUTRALIZATION
  // ============================================================================

  // Replace the iframe content with the unified neutral block notice.
  // Same DOM-construction pattern (no innerHTML) as the other inspectors so
  // attacker-controlled values can't inject markup.
  function blockPage() {
    try { window.stop(); } catch (e) {}

    try {
      const container = document.createElement('div');
      container.style.cssText = 'font-family:Arial,sans-serif;max-width:600px;margin:100px auto;padding:40px;background:#f8d7da;border:2px solid #721c24;border-radius:8px;color:#721c24;';

      const h1 = document.createElement('h1');
      h1.style.cssText = 'margin-top:0;';
      h1.textContent = '🛡️ Content Blocked';

      const reasonP = document.createElement('p');
      reasonP.style.cssText = 'font-size:16px;font-weight:bold;';
      reasonP.textContent = 'Blocked by district policy';

      const detailP = document.createElement('p');
      detailP.style.cssText = 'font-size:14px;line-height:1.6;';
      detailP.textContent = 'This content is not permitted on this device. Contact your IT administrator if you believe this is in error.';

      container.append(h1, reasonP, detailP);

      // Replace body if available, else documentElement
      if (document.body) {
        document.body.replaceChildren(container);
      } else if (document.documentElement) {
        document.documentElement.replaceChildren(container);
      }
    } catch (error) {
      console.error('[APPS SCRIPT] Failed to replace page content:', error);
    }
  }

  // ============================================================================
  // INSPECTION RUNNER
  // ============================================================================

  let alreadyBlocked = false;

  function check() {
    if (alreadyBlocked) return;
    if (!CONFIG.ENABLED) return;
    if (!pageLooksLikeGame()) return;

    alreadyBlocked = true;
    console.log(`[APPS SCRIPT] Game content blocked: ${location.href}`);
    blockPage();
  }

  // ============================================================================
  // INITIALIZATION
  // ============================================================================

  loadConfigFromBackground();

  // Apps Script web apps often inject content dynamically after initial load,
  // so we scan at multiple points: as soon as DOM exists, on DOMContentLoaded,
  // on load, and a couple of follow-up scans for late-loaded game assets.
  check();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', check);
  }
  window.addEventListener('load', check);
  setTimeout(check, 1500);
  setTimeout(check, 4000);
  setTimeout(check, 8000);

  // Watch for DOM mutations in case game content arrives later (Unity loaders
  // commonly inject canvas after a network fetch). Debounced via the
  // alreadyBlocked guard.
  try {
    const observer = new MutationObserver(() => {
      if (alreadyBlocked) {
        observer.disconnect();
        return;
      }
      check();
    });
    // Observe the Document node itself, not <body>: the userCodeAppPanel
    // sandbox writes the user's HTML into the frame after we are injected,
    // which can replace <body> and would orphan a body-scoped observer.
    observer.observe(document, { childList: true, subtree: true });
  } catch (e) {
    // MutationObserver unavailable or document not ready — periodic
    // setTimeout scans above still cover most cases.
  }

})();
// Maintained by TeacherMagic.org
