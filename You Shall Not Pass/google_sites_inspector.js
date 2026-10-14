// You Shall Not Pass - Enterprise Hardened v3.3.0
// Google Sites Inspector
// Maintained by TeacherMagic.org
// Detects blob URL obfuscation and embedded game content

(function() {
  'use strict';
  
  // ============================================================================
  // CONFIGURATION
  // ============================================================================
  
  // Defaults matching the original hardcoded values
  let CONFIG = {
    // Master toggle. When false, the inspector loads but does no scanning
    // or DOM inspection — admins can use this as a panic switch if a
    // new release interferes with a legitimate Google Sites resource.
    ENABLED: true,
    MIN_SUSPICIOUS_FRAME_SIZE: 400, // pixels
    SCAN_INTERVAL: 2000, // 2 seconds
    ENABLE_BLOB_BLOCKING: true,
    ENABLE_GAME_DETECTION: true,
    ENABLE_WORKER_DETECTION: true,
    ENABLE_BASE64_DETECTION: true,
    ENABLE_APPS_SCRIPT_DETECTION: true,
    ENABLE_SRCDOC_INSPECTION: true,
    ENABLE_SERVERLESS_PROXY_DETECTION: true,
    ENABLE_PAGE_BODY_CATALOG_SCAN: true,
    ENABLE_SERVICE_WORKER_CHECK: true,
    // Tier 3: opt-in default-deny mode. When true, ALL cross-origin iframes
    // on sites.google.com are blocked unless their origin matches the
    // built-in or admin-extended allowlist. Default off: districts must
    // explicitly enable and are responsible for maintaining additions.
    ENABLE_STRICT_SITES_MODE: false,
    ADDITIONAL_IFRAME_ALLOWLIST: []
  };

  // Handles to periodic timers / observer so we can tear them down
  // when the master toggle flips to disabled via CONFIG_UPDATED.
  let scanTimer = null;
  let iframeObserver = null;

  // Load config from background service worker
  function loadConfigFromBackground() {
    try {
      chrome.runtime.sendMessage({ type: 'GET_CONFIG' }, (response) => {
        if (chrome.runtime.lastError || !response) return;
        if (response.googleSitesInspector) {
          applyGsiConfig(response.googleSitesInspector);
        }
      });
    } catch (e) {
      // Extension context may not be available yet
    }
  }

  function applyGsiConfig(gsi) {
    CONFIG.ENABLED = gsi.enabled !== false;
    CONFIG.ENABLE_BLOB_BLOCKING = gsi.enableBlobBlocking !== false;
    CONFIG.ENABLE_GAME_DETECTION = gsi.enableGameDetection !== false;
    CONFIG.ENABLE_WORKER_DETECTION = gsi.enableWorkerDetection !== false;
    CONFIG.ENABLE_BASE64_DETECTION = gsi.enableBase64Detection !== false;
    CONFIG.ENABLE_APPS_SCRIPT_DETECTION = gsi.enableAppsScriptDetection !== false;
    CONFIG.ENABLE_SRCDOC_INSPECTION = gsi.enableSrcdocInspection !== false;
    CONFIG.ENABLE_SERVERLESS_PROXY_DETECTION = gsi.enableServerlessProxyDetection !== false;
    CONFIG.ENABLE_PAGE_BODY_CATALOG_SCAN = gsi.enablePageBodyCatalogScan !== false;
    CONFIG.ENABLE_SERVICE_WORKER_CHECK = gsi.enableServiceWorkerCheck !== false;
    // Strict mode is opt-in (default-off), so we require explicit true
    CONFIG.ENABLE_STRICT_SITES_MODE = gsi.enableStrictSitesMode === true;
    if (Array.isArray(gsi.additionalIframeAllowlist)) {
      CONFIG.ADDITIONAL_IFRAME_ALLOWLIST = gsi.additionalIframeAllowlist;
    }
    if (typeof gsi.scanInterval === 'number') CONFIG.SCAN_INTERVAL = gsi.scanInterval;
    if (typeof gsi.minSuspiciousFrameSize === 'number') CONFIG.MIN_SUSPICIOUS_FRAME_SIZE = gsi.minSuspiciousFrameSize;
  }

  function stopScanning() {
    if (scanTimer) {
      clearInterval(scanTimer);
      scanTimer = null;
    }
    if (iframeObserver) {
      try { iframeObserver.disconnect(); } catch (e) {}
      iframeObserver = null;
    }
  }

  // Listen for config updates from background.
  // Only accept messages from our own extension's service worker.
  chrome.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== chrome.runtime.id || sender.tab) return;
    if (message.type === 'CONFIG_UPDATED' && message.config?.googleSitesInspector) {
      const wasEnabled = CONFIG.ENABLED;
      applyGsiConfig(message.config.googleSitesInspector);
      // If admin just flipped the master switch off, stop scanning immediately
      // (don't wait for page reload).
      if (wasEnabled && !CONFIG.ENABLED) {
        stopScanning();
      }
    }
  });
  
  // ============================================================================
  // GAME ENGINE SIGNATURES
  // ============================================================================
  
  const GAME_ENGINE_SIGNATURES = [
    // Unity
    /UnityLoader\.js/i,
    /unityInstance/i,
    /\.unity3d/i,
    /UnityWebGL/i,
    
    // Construct 2/3
    /c2runtime\.js/i,
    /c3runtime\.js/i,
    /construct\.net/i,
    
    // Phaser
    /phaser\.js/i,
    /phaser\.min\.js/i,
    
    // Game engines
    /godot\.js/i,
    /pixi\.js/i,
    /three\.js.*game/i,
    
    // Common game frameworks
    /ruffle/i,
    /emulator/i,
    /\/rom\//i,
    /\.nes$/i,
    /\.gba$/i,
    /\.gb$/i,
    
    // Unblocked games indicators
    /unblocked/i,
    /unblocker/i,
    /game.*proxy/i,
    
    // Flash emulators
    /ruffle.*swf/i,
    /flashplayer/i
  ];

  // ============================================================================
  // GAME BRAND-NAME CATALOG SIGNATURES
  // ============================================================================

  // Commercial game titles that essentially only appear on unblocked-games
  // hubs. Kept in sync with apps_script_inspector.js HIGH_CONFIDENCE_GAME_PATTERNS
  // and background.js DATA_URL_GAME_PATTERNS (if you add a brand in one, add it
  // in all three). Used for the Sites page-BODY catalog scan and srcdoc
  // inspection — the dominant hub UX is a grid of these titles rendered
  // directly in the Sites page (not inside an Embed Code widget), which the
  // data-code fingerprinting never saw.
  const GAME_BRAND_PATTERNS = [
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

  // ============================================================================
  // SAFE DOM HELPERS
  // ============================================================================

  // Builds a block-notice element without innerHTML so that any
  // untrusted string (e.g. a regex signature or URL fragment) can't
  // inject markup into the page.
  function buildBlockMessage(title, reason, detail, styleCssText) {
    const box = document.createElement('div');
    box.style.cssText = styleCssText;

    const h3 = document.createElement('h3');
    h3.textContent = title;

    const reasonP = document.createElement('p');
    const reasonLabel = document.createElement('strong');
    reasonLabel.textContent = 'Reason:';
    reasonP.append(reasonLabel, document.createTextNode(' ' + reason));

    const detailP = document.createElement('p');
    detailP.textContent = detail;

    box.append(h3, reasonP, detailP);
    return box;
  }

  // ============================================================================
  // BLOB URL DETECTION
  // ============================================================================
  
  function inspectBlobURL(iframe) {
    const src = iframe.src;
    
    if (!src || !src.startsWith('blob:')) {
      return false;
    }
    
    // Check frame size (games are typically large/fullscreen). The size gate
    // is the false-positive firewall for blob iframes that carry no other
    // signal — but a launcher can defeat it by rendering the blob game in a
    // tiny/hidden/unpainted iframe. So we bypass the size gate when the page
    // itself already looks like an evasion hub (URL/title/launcher signals):
    // on a confirmed hub, a blob iframe of any size is conclusive.
    const width = iframe.offsetWidth;
    const height = iframe.offsetHeight;
    const tooSmall = width < CONFIG.MIN_SUSPICIOUS_FRAME_SIZE ||
                     height < CONFIG.MIN_SUSPICIOUS_FRAME_SIZE;

    if (tooSmall && !pageLooksLikeEvasionHub()) {
      return false; // Too small to be a game, and no corroborating hub signal
    }

    // Use console.log (not console.warn) so successful blocks don't surface
    // in Chrome's Errors panel — that panel aggregates warn+error and would
    // misleadingly suggest YSNP is failing when it's actually working.
    // Object fields inlined into the template so the panel doesn't render
    // them as "[object Object]".
    console.log(`[GOOGLE SITES] Blob iframe blocked: ${src} (${width}x${height}) on ${window.location.href}`);
    
    // Block the iframe
    if (CONFIG.ENABLE_BLOB_BLOCKING) {
      iframe.src = 'about:blank';
      iframe.style.display = 'none';

      const blockMessage = buildBlockMessage(
        '🛡️ Content Blocked',
        'Blocked by district policy',
        'This content is not permitted on this device. Contact your IT administrator if you believe this is in error.',
        'padding:20px;background:#f8d7da;border:2px solid #721c24;border-radius:8px;margin:20px;font-family:Arial,sans-serif;color:#721c24;'
      );

      if (iframe.parentElement) {
        iframe.parentElement.insertBefore(blockMessage, iframe);
      }
    }
    
    return true;
  }
  
  // ============================================================================
  // GAME ENGINE DETECTION
  // ============================================================================
  
  async function inspectFrameContent(iframe) {
    // Try to access iframe content (only works for same-origin or when we have permissions)
    try {
      const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document;
      if (!iframeDoc) return false;
      
      const html = iframeDoc.documentElement.outerHTML;
      
      // Check for game engine signatures
      for (const signature of GAME_ENGINE_SIGNATURES) {
        if (signature.test(html)) {
          console.log(`[GOOGLE SITES] Game engine iframe blocked: pattern=${signature.toString()} on ${window.location.href}`);

          // Block the iframe
          if (CONFIG.ENABLE_GAME_DETECTION) {
            iframe.src = 'about:blank';
            iframe.style.display = 'none';

            const blockMessage = buildBlockMessage(
              '🛡️ Content Blocked',
              'Blocked by district policy',
              'This content is not permitted on this device. Contact your IT administrator if you believe this is in error.',
              'padding:20px;background:#f8d7da;border:2px solid #721c24;border-radius:8px;margin:20px;font-family:Arial,sans-serif;color:#721c24;'
            );

            if (iframe.parentElement) {
              iframe.parentElement.insertBefore(blockMessage, iframe);
            }
          }
          
          return true;
        }
      }
    } catch (error) {
      // Cross-origin frame - can't inspect content
      // This is expected for many iframes
      return false;
    }

    return false;
  }

  // ============================================================================
  // SRCDOC + DANGEROUS-SCHEME IFRAME INSPECTION
  // ============================================================================

  // A <iframe srcdoc="...game..."> runs with the PARENT origin and leaves no
  // network request, blob, or data: URL — so it evades every network-layer and
  // URL-based detector. It is the natural successor to the about:blank/data:
  // vectors closed in 3.0.12/3.0.13. Because the srcdoc attribute is inline in
  // the same-origin Sites DOM, we can read and fingerprint it directly.
  function inspectSrcdoc(iframe) {
    let doc;
    try {
      doc = iframe.getAttribute('srcdoc');
    } catch (e) {
      return false;
    }
    if (!doc) return false;

    const matched =
      GAME_ENGINE_SIGNATURES.some(p => p.test(doc)) ||
      HIGH_CONFIDENCE_LAUNCHER_PATTERNS.some(p => p.test(doc)) ||
      GAME_BRAND_PATTERNS.some(p => p.test(doc));

    if (!matched) return false;

    console.log(`[GOOGLE SITES] srcdoc game iframe blocked on ${window.location.href}`);

    // Neutralize: strip srcdoc so the inline document can't re-render.
    try { iframe.removeAttribute('srcdoc'); } catch (e) {}
    iframe.src = 'about:blank';
    iframe.style.display = 'none';

    const blockMessage = buildBlockMessage(
      '🛡️ Content Blocked',
      'Blocked by district policy',
      'This content is not permitted on this device. Contact your IT administrator if you believe this is in error.',
      'padding:20px;background:#f8d7da;border:2px solid #721c24;border-radius:8px;margin:20px;font-family:Arial,sans-serif;color:#721c24;'
    );
    if (iframe.parentElement) {
      iframe.parentElement.insertBefore(blockMessage, iframe);
    }
    return true;
  }

  // An iframe whose src is a javascript:/vbscript: URL executes arbitrary
  // script in the frame. Legitimate Sites embeds never do this; hub launchers
  // use it to bootstrap a game without a network request. Neutralize
  // unconditionally when found (independent of strict mode).
  function inspectDangerousScheme(iframe) {
    const src = iframe.src || iframe.getAttribute('src') || '';
    if (!/^\s*(javascript|vbscript):/i.test(src)) return false;

    console.log(`[GOOGLE SITES] Dangerous-scheme iframe blocked: ${src.slice(0, 60)} on ${window.location.href}`);

    try { iframe.removeAttribute('src'); } catch (e) {}
    iframe.src = 'about:blank';
    iframe.style.display = 'none';

    const blockMessage = buildBlockMessage(
      '🛡️ Content Blocked',
      'Blocked by district policy',
      'This content is not permitted on this device. Contact your IT administrator if you believe this is in error.',
      'padding:20px;background:#f8d7da;border:2px solid #721c24;border-radius:8px;margin:20px;font-family:Arial,sans-serif;color:#721c24;'
    );
    if (iframe.parentElement) {
      iframe.parentElement.insertBefore(blockMessage, iframe);
    }
    return true;
  }

  // ============================================================================
  // SERVERLESS / STATIC-HOST PROXY DETECTION
  // ============================================================================

  // Serverless and static hosts are the default deployment surface for the
  // 2026 crop of self-contained proxies and unblocked-games launchers (no
  // origin server needed). We can't block these hosts outright — they carry
  // enormous legitimate traffic — so an embedded iframe pointing at one is
  // blocked only when EITHER:
  //   (a) the subdomain looks machine-generated (long random label), which is
  //       the signature of a throwaway proxy deployment, OR
  //   (b) the parent Sites page already looks like an evasion hub.
  const SERVERLESS_HOST_PATTERNS = [
    /\.workers\.dev$/i,        // Cloudflare Workers
    /\.pages\.dev$/i,          // Cloudflare Pages
    /\.vercel\.app$/i,         // Vercel
    /\.netlify\.app$/i,        // Netlify
    /\.onrender\.com$/i,       // Render
    /\.web\.app$/i,            // Firebase Hosting
    /\.firebaseapp\.com$/i,    // Firebase Hosting (legacy)
    /\.appspot\.com$/i,        // Google App Engine
    /\.glitch\.me$/i,          // Glitch
    /\.surge\.sh$/i,           // Surge
    /\.neocities\.org$/i,      // Neocities
    /\.koyeb\.app$/i,          // Koyeb
    /\.replit\.app$/i,         // Replit deployments
    /\.repl\.co$/i,             // Replit (legacy)
    // 3.2.4 additions — the surfaces the cherri/Fern hub family staged on:
    /(^|\.)s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com$/i, // raw S3 bucket URLs (all addressing forms)
    /\.b-cdn\.net$/i,          // Bunny CDN pull zones
    /\.ts\.net$/i,             // Tailscale Funnel
    /\.githack\.com$/i,        // raw-GitHub CDN mirrors rendered as documents
    /(^|\.)githubraw\.com$/i,
    /^cdn\.statically\.io$/i
  ];

  // Hosts where the "random-looking subdomain" shortcut is NOT allowed. S3
  // bucket names and Bunny pull zones routinely contain digits
  // (h5pcontent2024, storyline360export) and legitimately host course
  // exports that teachers embed in Sites. An embed from these hosts is
  // blocked only with a corroborating hub signal on the parent page.
  const CORROBORATION_ONLY_HOST_PATTERNS = [
    /(^|\.)s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com$/i,
    /\.b-cdn\.net$/i
  ];

  function looksLikeRandomSubdomain(hostname) {
    const label = hostname.split('.')[0] || '';
    // Machine-generated deploy names: long, and either mixed alnum with a
    // digit or a long unbroken alnum run.
    if (label.length < 10) return false;
    const hasDigit = /\d/.test(label);
    const longAlnumRun = /[a-z0-9]{10,}/i.test(label);
    return (hasDigit && /[a-z]/i.test(label) && longAlnumRun) || /[a-z0-9]{14,}/i.test(label);
  }

  function detectServerlessProxyIframe(iframe) {
    const src = iframe.src;
    if (!src) return false;

    // Explicit "cloudflare...proxy" style URLs are conclusive on their own.
    const explicitProxy = /cloudflare.*proxy/i.test(src);

    let hostname = '';
    try { hostname = new URL(src).hostname; } catch (e) { return false; }

    const onServerlessHost = SERVERLESS_HOST_PATTERNS.some(p => p.test(hostname));
    if (!onServerlessHost && !explicitProxy) return false;

    // False-positive firewall: a serverless host alone is not enough (these
    // host countless legitimate sites). Require a random-looking deploy name
    // or a corroborating evasion-hub signal on the parent page. For object
    // storage / CDN hosts the random-name shortcut does not apply at all.
    const corroborationOnly = CORROBORATION_ONLY_HOST_PATTERNS.some(p => p.test(hostname));
    if (!explicitProxy &&
        !(looksLikeRandomSubdomain(hostname) && !corroborationOnly) &&
        !pageLooksLikeEvasionHub()) {
      return false;
    }

    console.log(`[GOOGLE SITES] Serverless proxy iframe blocked: ${src} on ${window.location.href}`);

    if (CONFIG.ENABLE_SERVERLESS_PROXY_DETECTION) {
      iframe.src = 'about:blank';
      iframe.style.display = 'none';

      const blockMessage = buildBlockMessage(
        '🛡️ Content Blocked',
        'Blocked by district policy',
        'This content is not permitted on this device. Contact your IT administrator if you believe this is in error.',
        'padding:20px;background:#f8d7da;border:2px solid #721c24;border-radius:8px;margin:20px;font-family:Arial,sans-serif;color:#721c24;'
      );

      if (iframe.parentElement) {
        iframe.parentElement.insertBefore(blockMessage, iframe);
      }
    }

    return true;
  }
  
  // ============================================================================
  // PARENT URL EVASION PATTERNS
  // ============================================================================

  // Composite evasion-keyword patterns that essentially never appear in
  // legitimate teacher-built Google Sites paths. Used as a gating signal
  // for blocking Google Apps Script iframes — which are otherwise widely
  // used legitimately and must not be blocked on iframe content alone.
  const PARENT_URL_EVASION_PATTERNS = [
    /drive-u-?\d+/i,                                       // drive-u-7, drive-u2, drive-u-12
    /unblocked-?(games?|gamez|hub|portal|arcade|fun)/i,
    /(games?|gamez)-?(unblocked|hub|portal|arcade)/i,
    /\/proxy-?(site|page|hub|portal|games?|\d+)/i,
    /(tunnel|bypass|evade)-?(site|page|games?|\d+)/i,
    /classroom-?[6-9]\s*-?\s*x/i,                          // classroom-6x, classroom7x, classroom 8 x
    /tyrone-?s?-?unblocked/i,                              // tyrones-unblocked, tyrone-unblocked
    /game-?pluto\b/i,                                      // game-pluto, gamepluto
    // Any Google Site whose NAME contains "unblocked" (3.2.4). Covers consumer
    // /site/ and /view/ paths and Workspace /<domain>/<site> paths, e.g.
    // /site/unblockedwtf — the suffix list above missed "wtf" and every other
    // novel suffix. A teacher naming a Site this way is not a realistic case.
    /^https?:\/\/sites\.google\.com\/(?:site|view|[a-z0-9.-]+\.[a-z]{2,})\/[^/?#]*unblocked/i
  ];

  function parentUrlLooksLikeEvasionHub() {
    const href = window.location.href;
    return PARENT_URL_EVASION_PATTERNS.some(p => p.test(href));
  }

  // ============================================================================
  // PAGE TITLE / HEADING EVASION PATTERNS
  // ============================================================================

  // Hub identifiers that hubs put in their page title/H1 for SEO discovery,
  // even when they sanitize the URL. Catches the case where the URL alone
  // is clean but the page itself is clearly an evasion hub.
  const PAGE_TITLE_EVASION_PATTERNS = [
    /\bunblocked\s+games?\b/i,
    /\bclassroom\s*[6-9]\s*x\b/i,
    /\btyrone'?s\s+unblocked/i,
    /\bgame\s*pluto\b/i,
    /\b(drive|game)\s*-?\s*u\s*-?\s*\d+/i
  ];

  function pageTitleLooksLikeEvasionHub() {
    const title = document.title || '';
    if (PAGE_TITLE_EVASION_PATTERNS.some(p => p.test(title))) return true;

    const h1 = document.querySelector('h1');
    if (h1) {
      const h1Text = h1.textContent || '';
      if (PAGE_TITLE_EVASION_PATTERNS.some(p => p.test(h1Text))) return true;
    }
    return false;
  }

  // ============================================================================
  // EMBED-CODE GAME LAUNCHER FINGERPRINTING
  // ============================================================================

  // The Google Sites "Embed code" widget stores user-supplied HTML/JS in a
  // data-code attribute on a div.w536ob in the parent page DOM. That parent
  // page is sites.google.com — same-origin to this content script — so we can
  // read the launcher source directly.
  //
  // Patterns are split into two tiers by false-positive risk:
  //
  // HIGH-confidence: essentially never appear in legitimate teacher embeds.
  // Variable-name conventions specific to evasion-hub templates, ad-fraud
  // distribution hosts, referrer/title spoofing, IMA ad SDK hooking, SWF
  // converter, Construct 3 runtime patterns. Any single match is conclusive.
  const HIGH_CONFIDENCE_LAUNCHER_PATTERNS = [
    // Variable naming conventions used by the dominant hub launcher templates
    /\bgameXmlUrl\b/,
    /\bgoogleScriptUrl\b/,
    // Base64-encoded game payloads embedded directly in launcher
    /data:@file\/(xml|html);base64/i,
    // Google IMA ad SDK URL spoofing — purely ad-fraud behavior
    /google\.ima\.AdsRequest/,
    /setPageUrl\s*\(\s*siteUrl\s*\)/,
    // document.referrer spoofing — used to defeat Google ad-fraud detection
    /Object\.defineProperty\s*\(\s*document\s*,\s*['"]referrer['"]/i,
    // Page-title spoofing to "classroom.google.com" so popup/fullscreen
    // tabs are disguised as Google Classroom in the user's tab strip
    /pageTitle\s*=\s*["']classroom\.google\.com["']/i,
    // Ad-fraud distribution networks the hubs proxy through
    /\b(api\.)?gamemonetize\.com\b/i,
    /\b(ads\.)?gamedistribution\.com\b/i,
    // SWF Flash blob URL conversion — hubs support classic flash games
    /\bswfToBlobUrl\b/,
    /application\/x-shockwave-flash/
  ];

  // MEDIUM-confidence: could theoretically appear in legitimate teacher
  // embeds (Unity educational games, jsDelivr-hosted ed libraries,
  // Construct 3 game-design class projects). Requires corroboration from
  // another signal (title or URL match) before blocking.
  const MEDIUM_CONFIDENCE_LAUNCHER_PATTERNS = [
    /createUnityInstance\s*\(/,
    /\bunity-canvas\b/i,
    /cdn\.jsdelivr\.net\/gh\/[^/]+\/[^/]+@[a-f0-9]{6,}/,
    // Construct 3 runtime — second most common engine on evasion hubs, but
    // also used in K-12 game-design coursework. Downgraded from high to
    // medium so a student portfolio showcasing a legitimate C3 class
    // project doesn't get blocked from launcher fingerprint alone.
    /\bc3runtime\b/i,
    /\bruntimeScriptList\s*:/i
  ];

  // Returns 'high', 'medium', or null based on the strongest tier matched
  // across all embed widgets on the page.
  function detectGameLauncherCodeConfidence() {
    const widgets = document.querySelectorAll('div[data-code]');
    let bestSoFar = null;
    for (const w of widgets) {
      const code = w.getAttribute('data-code') || '';
      if (!code) continue;
      // High-confidence: short-circuit on any match
      for (const pattern of HIGH_CONFIDENCE_LAUNCHER_PATTERNS) {
        if (pattern.test(code)) return 'high';
      }
      // Medium-confidence: remember but keep scanning later widgets for high
      if (bestSoFar === null) {
        for (const pattern of MEDIUM_CONFIDENCE_LAUNCHER_PATTERNS) {
          if (pattern.test(code)) {
            bestSoFar = 'medium';
            break;
          }
        }
      }
    }
    return bestSoFar;
  }

  // ============================================================================
  // COMBINED EVASION-HUB DETECTION
  // ============================================================================

  // Three-tier model:
  //   - URL match alone is conclusive (the URL patterns are very narrow —
  //     "drive-u-7" essentially does not appear in legitimate content).
  //   - High-confidence launcher code alone is conclusive (variable-name
  //     conventions, ad-fraud hosts, referrer spoofing, IMA hooks etc. are
  //     not patterns that appear in legitimate teacher embeds, so we don't
  //     need URL or title corroboration — and indeed cannot rely on those,
  //     since hubs have begun sanitizing URLs and misspelling page titles
  //     ("Nblocked Games") specifically to defeat keyword matching).
  //   - Otherwise, require 2 corroborating signals from
  //     {title/H1 evasion keyword, medium-confidence launcher code}.
  //
  // The medium tier preserves a real false-positive firewall: a legit Unity
  // educational embed on a normally-named class page trips only the medium
  // launcher signal with no title match, so it is NOT blocked.
  function pageLooksLikeEvasionHub() {
    if (parentUrlLooksLikeEvasionHub()) return true;

    const launcherConfidence = detectGameLauncherCodeConfidence();
    if (launcherConfidence === 'high') return true;

    let corroborating = 0;
    if (pageTitleLooksLikeEvasionHub()) corroborating++;
    if (launcherConfidence === 'medium') corroborating++;
    return corroborating >= 2;
  }

  // ============================================================================
  // GOOGLE-HOSTED EMBED EVASION DETECTION
  // ============================================================================

  // Google-hosted iframe surfaces commonly used to wrap game content on
  // Sites evasion hubs. All three are widely used legitimately by teachers
  // (Apps Script quizzes/dashboards/forms; Embed Code widgets for
  // simulations, code playgrounds, calendars), so we only block when BOTH:
  //   1. iframe src matches one of the Google-hosted embed surfaces
  //   2. parent Google Sites URL matches an evasion-hub keyword pattern
  // The parent-URL condition is the false-positive firewall — without it
  // we'd break legitimate teacher embeds on normal-named class pages.
  //
  // No size gate: layout-time measurements (offsetWidth/Height) are
  // unreliable here — the iframe may not be painted when the periodic
  // scan first runs, and some Sites layouts render embeds narrower than
  // typical game canvases. The URL + parent-URL combination is a strong
  // enough signal on its own.
  //
  // Each surface is listed explicitly rather than via a catch-all so that
  // adding or removing a vector is auditable.
  const GOOGLE_HOSTED_EMBED_PATTERNS = [
    // Google Apps Script web-app endpoint.
    // Covers both the standard form (script.google.com/macros/s/{id}/exec)
    // and the domain-restricted Workspace form
    // (script.google.com/a/macros/{domain}/s/{id}/exec) — students can deploy
    // Apps Script web apps from their school Workspace account, which produces
    // the /a/macros/ form. Both are caught.
    /^https:\/\/script\.google\.com\/(?:a\/macros\/[^/]+|macros)\/s\/[^/]+\/exec/i,
    // Google Sites "Embed code" widget — shared static intermediate frame
    /^https:\/\/www\.gstatic\.com\/atari\/embeds\/[a-f0-9]+\/(?:intermediate|inner)-frame-minified\.html/i,
    // Google Sites "Embed code" widget — per-tenant user-content frame
    /^https:\/\/[a-z0-9-]+\.atari-embeds\.googleusercontent\.com\/embeds\/[a-f0-9]+\/(?:intermediate|inner)-frame-minified\.html/i
  ];

  function detectAppsScriptEvasion(iframe) {
    const src = iframe.src;
    if (!src) return false;

    if (!GOOGLE_HOSTED_EMBED_PATTERNS.some(p => p.test(src))) {
      return false;
    }

    if (!pageLooksLikeEvasionHub()) {
      return false;
    }

    console.log(`[GOOGLE SITES] Hub embed blocked: ${src} on ${window.location.href}`);

    // Block (gated for managed-config override). Mirrors inspectBlobURL.
    if (CONFIG.ENABLE_APPS_SCRIPT_DETECTION) {
      iframe.src = 'about:blank';
      iframe.style.display = 'none';

      const blockMessage = buildBlockMessage(
        '🛡️ Content Blocked',
        'Blocked by district policy',
        'This content is not permitted on this device. Contact your IT administrator if you believe this is in error.',
        'padding:20px;background:#f8d7da;border:2px solid #721c24;border-radius:8px;margin:20px;font-family:Arial,sans-serif;color:#721c24;'
      );

      if (iframe.parentElement) {
        iframe.parentElement.insertBefore(blockMessage, iframe);
      }
    }

    return true;
  }

  // ============================================================================
  // STRICT SITES MODE (Tier 3: opt-in default-deny iframe allowlisting)
  // ============================================================================

  // Origins admitted by default when strict mode is enabled. Covers Google's
  // own services, major educational platforms, common code playgrounds, and
  // general legitimate embed sources. Intentionally conservative — districts
  // extend via additionalIframeAllowlist managed-config field.
  //
  // Entry formats:
  //   'host.example.com'  — exact hostname match
  //   '.example.com'      — suffix match (matches example.com and any subdomain)
  //
  // NOT in default allowlist (intentional — these are the most-abused surfaces):
  //   script.google.com (Apps Script)
  //   www.gstatic.com (Sites Embed Code intermediate frame)
  //   *.atari-embeds.googleusercontent.com (Sites Embed Code inner frame)
  // Districts that need these in strict mode can add them explicitly.
  const BUILT_IN_IFRAME_ALLOWLIST = [
    // ---- Google services ----
    'docs.google.com',
    'calendar.google.com',
    'drive.google.com',
    'www.google.com',
    'maps.google.com',
    'www.youtube.com',
    'youtube.com',
    '.youtube-nocookie.com',

    // ---- Major educational platforms ----
    'phet.colorado.edu',
    '.geogebra.org',
    '.desmos.com',
    'edpuzzle.com',
    'khanacademy.org',
    'www.khanacademy.org',
    'quizlet.com',
    'nearpod.com',
    'padlet.com',
    'flip.com',
    '.flipgrid.com',
    'wakelet.com',
    'kahoot.it',
    'quizizz.com',
    'blooket.com',
    'commonlit.org',
    'newsela.com',
    'brainpop.com',
    'mentimeter.com',
    'bookcreator.com',
    'thinglink.com',
    'canva.com',
    'prezi.com',

    // ---- Code playgrounds ----
    'codepen.io',
    'jsfiddle.net',
    'replit.com',
    '.scratch.mit.edu',
    'tinkercad.com',

    // ---- General legitimate embed sources ----
    'player.vimeo.com',
    'vimeo.com',
    'w.soundcloud.com',
    'open.spotify.com'
  ];

  function hostnameMatchesAllowlistEntry(hostname, entry) {
    if (entry.startsWith('.')) {
      // Suffix match: '.example.com' matches example.com and any subdomain
      const base = entry.slice(1);
      return hostname === base || hostname.endsWith(entry);
    }
    return hostname === entry;
  }

  function iframeAllowedByStrictMode(iframe) {
    const src = iframe.src;

    // srcdoc is inline content with no allowlistable origin — under a
    // default-deny policy it is not allowed (inspectSrcdoc also fingerprints
    // it, but strict mode blocks it regardless of content).
    if (iframe.hasAttribute && iframe.hasAttribute('srcdoc')) return false;

    if (!src) return true; // genuinely empty iframe
    // about: is inert / used as our own neutralization target.
    if (src.startsWith('about:')) return true;
    if (src.startsWith('blob:')) return true; // inspectBlobURL handles separately
    // data:, javascript:, vbscript: carry arbitrary inline content/script with
    // no origin to allowlist — deny under strict mode.
    if (/^\s*(data|javascript|vbscript):/i.test(src)) return false;

    let url;
    try { url = new URL(src); } catch (e) { return false; }
    const hostname = url.hostname;

    // Built-in allowlist
    for (const entry of BUILT_IN_IFRAME_ALLOWLIST) {
      if (hostnameMatchesAllowlistEntry(hostname, entry)) return true;
    }

    // Admin extensions — accepts either hostname patterns or full URL prefixes
    for (const entry of (CONFIG.ADDITIONAL_IFRAME_ALLOWLIST || [])) {
      if (typeof entry !== 'string' || !entry) continue;
      if (entry.startsWith('http://') || entry.startsWith('https://')) {
        // URL-prefix match: lets admins allow a specific path
        // e.g. 'https://script.google.com/macros/' allows Apps Script overall,
        //      'https://www.gstatic.com/atari/embeds/' allows Embed Code widgets
        if (src.startsWith(entry)) return true;
      } else if (hostnameMatchesAllowlistEntry(hostname, entry)) {
        return true;
      }
    }

    return false;
  }

  function applyStrictMode(iframe) {
    if (!CONFIG.ENABLE_STRICT_SITES_MODE) return false;
    if (iframeAllowedByStrictMode(iframe)) return false;

    console.log(`[GOOGLE SITES] Strict-mode iframe blocked: ${iframe.src} on ${window.location.href}`);

    // Strip srcdoc first — it takes precedence over src, so setting src alone
    // would leave a srcdoc document rendering (merely hidden).
    try { iframe.removeAttribute('srcdoc'); } catch (e) {}
    iframe.src = 'about:blank';
    iframe.style.display = 'none';

    const blockMessage = buildBlockMessage(
      '🛡️ Content Blocked',
      'Blocked by district policy',
      'This content is not permitted on this device. Contact your IT administrator if you believe this is in error.',
      'padding:20px;background:#f8d7da;border:2px solid #721c24;border-radius:8px;margin:20px;font-family:Arial,sans-serif;color:#721c24;'
    );

    if (iframe.parentElement) {
      iframe.parentElement.insertBefore(blockMessage, iframe);
    }

    return true;
  }

  // ============================================================================
  // COMPREHENSIVE IFRAME SCANNER
  // ============================================================================

  let scanPassCount = 0;

  function scanAllIframes() {
    const iframes = document.querySelectorAll('iframe');
    let violationsDetected = 0;
    scanPassCount++;

    // Base64→blob game-payload detection is heavier (scans every inline
    // script), so run it on the first pass and then every 3rd pass rather
    // than every 2s — late-injected payloads are still caught within a few
    // seconds. Previously this ran exactly once at +2s and only warned.
    if (CONFIG.ENABLE_BASE64_DETECTION && (scanPassCount === 1 || scanPassCount % 3 === 0)) {
      if (detectBase64Encoding()) violationsDetected++;
    }

    iframes.forEach(iframe => {
      // Tier 3 strict mode (opt-in default-deny) runs first so other
      // detectors don't waste cycles on already-neutralized iframes.
      if (CONFIG.ENABLE_STRICT_SITES_MODE && applyStrictMode(iframe)) {
        violationsDetected++;
        return;
      }

      // Dangerous inline schemes (javascript:/vbscript:) — always neutralize.
      if (inspectDangerousScheme(iframe)) {
        violationsDetected++;
        return;
      }

      // srcdoc inline documents (no network request / blob / data: URL).
      if (CONFIG.ENABLE_SRCDOC_INSPECTION && inspectSrcdoc(iframe)) {
        violationsDetected++;
        return;
      }

      // Check blob URLs
      if (CONFIG.ENABLE_BLOB_BLOCKING && inspectBlobURL(iframe)) {
        violationsDetected++;
      }

      // Check for serverless / static-host proxy embeds
      if (CONFIG.ENABLE_SERVERLESS_PROXY_DETECTION && detectServerlessProxyIframe(iframe)) {
        violationsDetected++;
      }

      // Check for Apps Script evasion embeds (gated on parent-URL match
      // so legitimate teacher Apps Script tools are untouched)
      if (CONFIG.ENABLE_APPS_SCRIPT_DETECTION && detectAppsScriptEvasion(iframe)) {
        violationsDetected++;
      }

      // Check frame content for game engines
      if (CONFIG.ENABLE_GAME_DETECTION) {
        inspectFrameContent(iframe);
      }
    });

    // Page-body catalog scan (grid of game titles rendered directly in the
    // Sites page, outside any Embed Code widget). Throttled like base64 —
    // first pass, then every 3rd — since it reads document.body.textContent.
    if (scanPassCount === 1 || scanPassCount % 3 === 0) {
      if (scanPageBodyForCatalog()) violationsDetected++;
    }

    if (violationsDetected > 0) {
      console.log(`[GOOGLE SITES] Scan complete: ${violationsDetected} violation(s) blocked`);
    }
  }
  
  // ============================================================================
  // BASE64 ENCODED CONTENT DETECTION
  // ============================================================================
  
  function detectBase64Encoding() {
    // Look for extremely long Base64 blobs being decoded into an object URL —
    // the signature of a game payload smuggled inline. Previously this only
    // logged; it now BLOCKS, but only when corroborated so we don't nuke a
    // legitimate page that happens to inline a large asset:
    //   - the parent page already looks like an evasion hub, OR
    //   - strict mode is enabled (default-deny posture).
    const scripts = document.querySelectorAll('script');
    const base64Pattern = /[A-Za-z0-9+/]{1000,}/;

    let suspicious = false;
    for (const script of scripts) {
      const content = script.textContent || '';
      if (!base64Pattern.test(content)) continue;
      // The decode-and-blob combination is what turns a big base64 string
      // into runnable content.
      if (/atob\s*\(/.test(content) && /createObjectURL/.test(content)) {
        suspicious = true;
        break;
      }
    }

    if (!suspicious) return false;

    const corroborated = pageLooksLikeEvasionHub() || CONFIG.ENABLE_STRICT_SITES_MODE;
    if (!corroborated) {
      // Signal present but uncorroborated — log for admin visibility, don't block.
      console.log('[GOOGLE SITES] Base64→blob decode present but uncorroborated; not blocking');
      return false;
    }

    console.log(`[GOOGLE SITES] Base64-encoded game payload blocked on ${window.location.href}`);
    try { window.stop(); } catch (e) {}
    try {
      const container = buildBlockMessage(
        '🛡️ Content Blocked',
        'Blocked by district policy',
        'This content is not permitted on this device. Contact your IT administrator if you believe this is in error.',
        'font-family:Arial,sans-serif;max-width:600px;margin:100px auto;padding:40px;background:#f8d7da;border:2px solid #721c24;border-radius:8px;color:#721c24;'
      );
      if (document.body) {
        document.body.replaceChildren(container);
      }
    } catch (error) {
      console.error('[GOOGLE SITES] Failed to replace base64 page content:', error);
    }
    return true;
  }

  // ============================================================================
  // PAGE-BODY GAME CATALOG SCAN
  // ============================================================================

  // The dominant hub UX is a CATALOG: a grid of game thumbnails/titles
  // rendered directly in the Sites page body — NOT inside an Embed Code widget,
  // so the data-code launcher fingerprinting never saw it (the open follow-up
  // from 3.0.11). We scan the visible page text for the free-game-grid marker
  // or an accumulation of commercial game brand names.
  //
  // A single brand name in prose could be innocent (a teacher mentioning a
  // game), so the brand path requires TWO or more distinct brand matches — a
  // grid of them is conclusive, an offhand mention is not. The structural
  // free-game-grid marker is conclusive alone.
  function scanPageBodyForCatalog() {
    if (!CONFIG.ENABLE_PAGE_BODY_CATALOG_SCAN) return false;

    // Cheap structural check first (no HTML serialization).
    let conclusive = false;
    try {
      conclusive = !!document.querySelector('#free-game-grid, [id="free-game-grid"]');
    } catch (e) {}

    if (!conclusive) {
      let text = '';
      try {
        text = document.body ? (document.body.textContent || '') : '';
      } catch (e) {
        return false;
      }
      let brandHits = 0;
      for (const p of GAME_BRAND_PATTERNS) {
        if (p.test(text)) {
          brandHits++;
          if (brandHits >= 2) { conclusive = true; break; }
        }
      }
    }

    if (!conclusive) return false;

    console.log(`[GOOGLE SITES] Page-body game catalog blocked on ${window.location.href}`);
    try { window.stop(); } catch (e) {}
    try {
      const container = buildBlockMessage(
        '🛡️ Content Blocked',
        'Blocked by district policy',
        'This content is not permitted on this device. Contact your IT administrator if you believe this is in error.',
        'font-family:Arial,sans-serif;max-width:600px;margin:100px auto;padding:40px;background:#f8d7da;border:2px solid #721c24;border-radius:8px;color:#721c24;'
      );
      if (document.body) {
        document.body.replaceChildren(container);
      }
    } catch (error) {
      console.error('[GOOGLE SITES] Failed to replace catalog page content:', error);
    }
    return true;
  }
  
  // ============================================================================
  // SERVICE WORKER ANOMALY CHECK (obfuscation-proof)
  // ============================================================================

  // Name-based proxy detection is defeated by obfuscating the bundle
  // (js-confuser/obfuscator.io rename every symbol and string). This check
  // reads NO code: it asks the browser whether a service worker is registered
  // on this origin — an active SW is exactly how Ultraviolet/Scramjet-class
  // proxies intercept navigation, and legitimate Google Sites pages don't
  // register one.
  //
  // Because we cannot be 100% certain Google will never ship a SW on this
  // surface, the default action is LOG ONLY (an obfuscation-proof, zero-FP
  // diagnostic for admins). We only UNREGISTER — which disrupts the proxy —
  // when it's safe to be aggressive: strict mode is on AND the page already
  // looks like an evasion hub. See README "Threat model": a novel, self-hosted,
  // obfuscated proxy on its own domain is a DNR/Workspace problem, not one a
  // content script can fully solve.
  function checkServiceWorkers() {
    if (!CONFIG.ENABLE_SERVICE_WORKER_CHECK) return;
    let swc;
    try { swc = navigator.serviceWorker; } catch (e) { return; }
    if (!swc || typeof swc.getRegistrations !== 'function') return;

    swc.getRegistrations().then((regs) => {
      if (!regs || regs.length === 0) return;
      const aggressive = CONFIG.ENABLE_STRICT_SITES_MODE && pageLooksLikeEvasionHub();
      console.log(`[GOOGLE SITES] ${regs.length} service worker registration(s) on ${location.origin}` +
                  (aggressive ? ' — unregistering (strict mode + hub signal)' : ' (log only)'));
      if (!aggressive) return;
      for (const reg of regs) {
        try { reg.unregister(); } catch (e) {}
      }
    }).catch(() => {});
  }

  // ============================================================================
  // INITIALIZATION
  // ============================================================================

  // Two-phase scan cadence (runtime-cost concern): fast at first to catch
  // load-time dynamics, then downshift to a slow persistent safety net. We do
  // NOT stop entirely — the observer catches DOM insertions instantly, but only
  // the poll catches attribute src-changes on existing iframes and covers
  // same-Site soft-navigation.
  const MAX_FAST_SCAN_PASSES = 30;    // ~60s at the default 2s interval
  const SLOW_SCAN_INTERVAL = 12000;   // persistent safety net after the fast phase

  function stopPeriodicScan() {
    if (scanTimer) {
      clearInterval(scanTimer);
      scanTimer = null;
    }
  }

  function initialize() {
    console.log('[GOOGLE SITES INSPECTOR] Initializing...');

    // Load config from background. The fetch is async, so we start scans
    // based on current (default) CONFIG and the CONFIG_UPDATED handler will
    // tear them down later if the admin has master-disabled the inspector.
    loadConfigFromBackground();

    if (!CONFIG.ENABLED) {
      console.log('[GOOGLE SITES INSPECTOR] Disabled by config; idle.');
      return;
    }

    // Initial scan
    setTimeout(() => {
      if (CONFIG.ENABLED) scanAllIframes();
    }, 1000);

    // Two-phase periodic scanning. Fast for the first stretch after load (when
    // dynamic content is most likely to arrive), then DOWNSHIFT to a slow
    // persistent safety net — it never stops entirely. Stopping outright (an
    // earlier 3.2.0 draft) opened a coverage gap: Google Sites soft-navigation
    // within the same Site does not re-run the content script, so after the
    // scan stopped a student could navigate to the games page and the
    // page-body catalog / base64 payload / src-changed iframe was no longer
    // caught. The slow poll (plus the observer below) closes that.
    function startFastScan() {
      stopPeriodicScan();
      scanTimer = setInterval(() => {
        if (!CONFIG.ENABLED) { stopScanning(); return; }
        scanAllIframes();
        if (scanPassCount >= MAX_FAST_SCAN_PASSES) startSlowScan();
      }, CONFIG.SCAN_INTERVAL);
    }
    function startSlowScan() {
      stopPeriodicScan();
      scanTimer = setInterval(() => {
        if (!CONFIG.ENABLED) { stopScanning(); return; }
        scanAllIframes();
      }, SLOW_SCAN_INTERVAL);
    }
    startFastScan();

    // Obfuscation-proof service-worker check (initial + a couple of follow-ups,
    // since a proxy SW may register shortly after load).
    checkServiceWorkers();
    setTimeout(checkServiceWorkers, 2500);
    setTimeout(checkServiceWorkers, 8000);

    // Debounced FULL re-scan on any DOM mutation. Running the full scanAllIframes
    // (not a per-node check) is deliberate: it covers iframes nested inside an
    // inserted container (the dominant hub injection pattern — an earlier
    // per-node observer only saw addedNodes whose nodeName was IFRAME and missed
    // an iframe wrapped in a div), plus late page-body catalogs and base64
    // payloads. Idempotent and loop-safe: neutralized iframes no longer match,
    // and the block-notice text matches no signature.
    let obsScheduled = false;
    function scheduleObserverScan() {
      if (obsScheduled) return;
      obsScheduled = true;
      setTimeout(() => {
        obsScheduled = false;
        if (CONFIG.ENABLED) scanAllIframes();
      }, 500);
    }
    iframeObserver = new MutationObserver(() => {
      if (!CONFIG.ENABLED) return;
      scheduleObserverScan();
    });

    if (document.body) {
      iframeObserver.observe(document.body, {
        childList: true,
        subtree: true
      });
    }

    console.log('[GOOGLE SITES INSPECTOR] Active');
  }
  
  // Wait for page to be somewhat loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
  } else {
    initialize();
  }
  
})();
// Maintained by TeacherMagic.org