// You Shall Not Pass - Enterprise Hardened v3.3.0
// Maintained by TeacherMagic.org
// Background Service Worker
// Comprehensive defense against K-12 filter evasion ecosystem

// ============================================================================
// CONFIGURATION
// ============================================================================

const DEFAULT_CONFIG = {
  version: 1,
  // Static rules that ship OFF. A rule listed here stays in rules.json so a
  // district can turn it on with "rules": { "<id>": { "enabled": true } }.
  //   1037 — *.translate.goog (Google Translate's "translate this website"
  //          proxy). Off by default since 3.2.5: English-learner students and
  //          families rely on it, and a default block is the wrong trade for
  //          most districts.
  rules: {
    '1037': { enabled: false }
  },
  tabLimits: {
    maxTabs: 15,
    tabCreationWindow: 2000,
    maxTabsInWindow: 5
  },
  contentGuard: {
    enabled: true,
    maxHistoryPushesPerSecond: 50,
    // Master toggle for the anti-extension-tamper subsystem. Legacy key name
    // (the LTBEEF/Ingot-specific detection it was named for was removed in
    // 3.2.0 — those exploits can't run on Chrome 111+); the subsystem now
    // targets current tooling by behavior. Default on.
    enableLTBEEFDetection: true,
    // Heuristic anti-extension GUI detection: a high-z-index injected overlay
    // whose text matches a tampering signature (webstorePrivate, "disable
    // extensions", noguardian, …). Default on.
    enableAntiExtensionHeuristics: true,
    // Cross-origin blob:/srcdoc/javascript: game-iframe guard on all pages
    // (closes the "spawn the game from a blob on a cheap domain / file: URL"
    // bypass that the Sites-scoped inspector can't see). High-confidence
    // signatures only. Default on.
    enableBlobGuard: true,
    // Hub-shell detector (3.2.4): fingerprints the INLINE bootstrap scripts of
    // bare-shell proxy hubs (cherri/Fern family: service-worker takeover
    // snippet, hub globals, renamed-runtime symbol names, Adcash popunder
    // call, known hub CDN account paths). Every signature is a coined token
    // or vendor API call — no dictionary words. Default on.
    enableHubShellDetection: true,
    // Service-worker source scan: read the page's registered service worker
    // (and the files it imports) and block on the proxy frameworks'
    // compiled-in symbols. Survives renaming of every file and global, since
    // renaming those means rebuilding the framework. Legitimate PWAs never
    // contain them. Default on.
    enableServiceWorkerScan: true
  },
  googleSitesInspector: {
    // Master toggle for the entire Google Sites content-script pipeline.
    // Admins can flip this off in managed config to disable all sites.google.com
    // inspection if they suspect it's interfering with a legitimate resource.
    enabled: true,
    enableBlobBlocking: true,
    enableGameDetection: true,
    enableWorkerDetection: true,
    enableBase64Detection: true,
    enableAppsScriptDetection: true,
    // Inspect iframe srcdoc content for game/launcher signatures. srcdoc runs
    // with the parent origin and leaves no network request, blob, or data:
    // URL, so it is the natural successor to the about:blank/data: vectors
    // closed in 3.0.12/3.0.13. Default on.
    enableSrcdocInspection: true,
    // Detect games/proxies embedded from serverless/static hosts (workers.dev,
    // pages.dev, *.vercel.app, *.netlify.app, *.web.app, appspot.com, etc.)
    // via random-subdomain heuristic OR evasion-hub corroboration. Default on.
    enableServerlessProxyDetection: true,
    // Scan the Sites page BODY (not just embed-widget data-code attributes)
    // for an unblocked-games catalog: brand-name grid or free-game-grid
    // marker rendered directly in the page. Closes the 3.0.11 follow-up.
    enablePageBodyCatalogScan: true,
    // Obfuscation-proof service-worker anomaly check: reads no code, just asks
    // the browser whether a SW is registered on the Sites origin (how
    // UV/Scramjet-class proxies intercept). Logs by default; only unregisters
    // under strict mode + a hub signal. Default on.
    enableServiceWorkerCheck: true,
    // Tier 3 strict mode: opt-in default-deny for cross-origin iframes on
    // sites.google.com. Off by default; districts opt in via managed config.
    enableStrictSitesMode: false,
    additionalIframeAllowlist: [],
    scanInterval: 2000,
    minSuspiciousFrameSize: 400
  },
  appsScriptInspector: {
    // Runs inside the script.googleusercontent.com iframe that hosts the
    // rendered content of a Google Apps Script web app. Catches the case
    // where a student deploys their own Apps Script web app (from their
    // school Workspace account, producing the /a/macros/{domain}/ form)
    // and uses it to host a game directly.
    //
    // Apps Script has many legitimate uses (teacher forms, surveys,
    // dashboards), so detection requires a high-confidence game pattern
    // in the rendered HTML (Unity loader, Construct 3 runtime, ad-fraud
    // SDK hooks, base64 game payloads, etc.). Default on.
    enabled: true
  },
  heartbeat: {
    enabled: true,
    interval: 5000
  },
  domains: {
    additionalWhitelist: [],
    additionalBlacklist: [],
    // DNR urlFilter patterns pushed as dynamic block rules. Covers cases
    // that requestDomains cannot — e.g. path-prefix blocks like
    // "||sites.google.com/classroom.center/" where the network origin is
    // allowlisted but a specific path on it should be blocked.
    additionalUrlFilters: []
  },
  // Trusted-platform evasions: ways around the filter that run through an
  // allowed Google feature instead of a proxy site. Blocking them changes how
  // a legitimate product behaves, so every one ships OFF and does nothing
  // until an admin sets it to true.
  classroomControls: {
    // Hide Google's AI Overview and AI Mode entry points on google.com search
    // so students engage with primary sources (ai_overview_hider.js).
    hideGoogleAiOverview: false,
    // Block YouTube preview popups, link-preview cards, smart chips and
    // embedded players inside Google Docs/Sheets/Slides — a common way to
    // watch video past the filter. Adds a dynamic DNR rule scoped to requests
    // initiated by docs.google.com, plus docs_youtube_blocker.js for the UI.
    // Browsing youtube.com directly is unaffected.
    blockYouTubeInDocs: false,
    // Block YouTube players embedded in search-engine result pages (Google
    // Search, Bing, DuckDuckGo and others play videos in place, so a blocked
    // YouTube is watchable without ever visiting youtube.com). Adds a dynamic
    // DNR rule scoped to requests initiated by the search engines' own hosts.
    // Clicking through to youtube.com is unaffected (your filter decides that).
    blockYouTubeInSearch: false
  }
};

// Active config starts as defaults, updated by loadConfig()
let activeConfig = structuredClone(DEFAULT_CONFIG);

// Config refresh interval (60 minutes) for URL-based configs
const CONFIG_REFRESH_INTERVAL = 60 * 60 * 1000;
// After this age the cache is considered unusable and is purged.
// Long enough to survive summer break / extended offline windows,
// short enough that an abandoned config URL eventually clears out.
const CONFIG_CACHE_MAX_AGE = 30 * 24 * 60 * 60 * 1000;
// Soft staleness threshold — we still serve the cache past this age
// but log loudly so operators can see the URL hasn't been reachable.
const CONFIG_CACHE_STALE_AFTER = 24 * 60 * 60 * 1000;
let configRefreshTimer = null;

// ============================================================================
// CONFIG LOADING SYSTEM
// ============================================================================

function deepMerge(target, source) {
  const result = structuredClone(target);
  for (const key of Object.keys(source)) {
    if (
      source[key] !== null &&
      typeof source[key] === 'object' &&
      !Array.isArray(source[key]) &&
      typeof result[key] === 'object' &&
      !Array.isArray(result[key])
    ) {
      result[key] = deepMerge(result[key], source[key]);
    } else {
      result[key] = structuredClone(source[key]);
    }
  }
  return result;
}

async function loadConfig() {
  let adminConfig = null;

  try {
    // Try managed storage first (Google Workspace Admin Console)
    const managed = await chrome.storage.managed.get(['configUrl', 'config']);

    if (managed.configUrl) {
      // Fetch config from URL
      try {
        // Bounded so a hung config host can't stall initialization (GET_CONFIG
        // replies wait on it); on timeout we fall through to the cached copy.
        const response = await fetch(managed.configUrl, {
          cache: 'no-cache',
          signal: AbortSignal.timeout(10000)
        });
        if (response.ok) {
          adminConfig = await response.json();
          // Cache the fetched config locally
          await chrome.storage.local.set({
            _cachedConfig: adminConfig,
            _cachedConfigTime: Date.now()
          });
          console.log('[CONFIG] Loaded config from URL:', managed.configUrl);
        } else {
          throw new Error(`HTTP ${response.status}`);
        }
      } catch (fetchError) {
        console.warn('[CONFIG] Failed to fetch config URL:', fetchError.message);
        // Fall back to cached version, gated by age.
        const cached = await chrome.storage.local.get(['_cachedConfig', '_cachedConfigTime']);
        const cachedAt = cached._cachedConfigTime || 0;
        const age = Date.now() - cachedAt;
        if (cached._cachedConfig && age < CONFIG_CACHE_MAX_AGE) {
          adminConfig = cached._cachedConfig;
          if (age > CONFIG_CACHE_STALE_AFTER) {
            console.warn(`[CONFIG] Using STALE cached config (age: ${Math.round(age / 3600000)}h). Admin should verify configUrl is reachable.`);
          } else {
            console.log(`[CONFIG] Using cached config (age: ${Math.round(age / 60000)}m)`);
          }
        } else if (cached._cachedConfig) {
          // Cache past hard expiry — purge so we don't keep serving indefinitely
          // outdated policy on a device that may have changed hands.
          console.error(`[CONFIG] Cached config exceeded max age (${Math.round(age / 86400000)}d); discarding and falling back to defaults.`);
          await chrome.storage.local.remove(['_cachedConfig', '_cachedConfigTime']);
        }
      }

      // Schedule periodic re-fetch
      if (!configRefreshTimer) {
        configRefreshTimer = setInterval(() => loadConfig(), CONFIG_REFRESH_INTERVAL);
      }
    } else if (managed.config) {
      // Use inline config from managed storage
      adminConfig = managed.config;
      console.log('[CONFIG] Loaded inline managed config');
    }
  } catch (error) {
    // managed storage not available (e.g., not enterprise-managed)
    console.log('[CONFIG] No managed config available, using defaults');
  }

  // Merge admin config over defaults
  if (adminConfig) {
    activeConfig = deepMerge(DEFAULT_CONFIG, adminConfig);
  } else {
    activeConfig = structuredClone(DEFAULT_CONFIG);
  }

  // Apply rule changes via dynamic DNR rules
  await applyRuleChanges();

  // Broadcast config update to all content scripts
  broadcastConfigUpdate();

  console.log('[CONFIG] Active config applied');
}

// Chrome compiles each DNR regexFilter under a 2KB memory cap and silently
// skips any rule over it. Rules whose pattern could not fit were split in
// 3.2.4 into several rules; the first piece keeps the original id. Managed
// config written against an original id ("rules": { "1051": ... }) must keep
// governing every piece, so toggles are expanded through this map.
const RULE_SPLIT_SIBLINGS = {"1046": [1057], "1047": [1058], "1051": [1059, 1060], "1052": [1061], "1053": [1072], "1054": [1062, 1063], "1073": [1077, 1078]};

function expandRuleIds(id) {
  return [id, ...(RULE_SPLIT_SIBLINGS[id] || [])];
}

// Fixed id for the classroom-control dynamic rule (admin domain lists start
// at 5001, so this never collides).
const YOUTUBE_IN_DOCS_RULE_ID = 4001;
const YOUTUBE_IN_SEARCH_RULE_ID = 4002;

// Hosts whose result pages play YouTube in place. Listed by exact host on
// purpose: initiatorDomains also matches subdomains, so 'google.com' would
// sweep in classroom.google.com, docs.google.com and sites.google.com, where
// teacher-assigned video must keep working. 'www.google.com' is Search only.
const SEARCH_ENGINE_INITIATORS = [
  'www.google.com',
  'bing.com',
  'duckduckgo.com',
  'search.yahoo.com',
  'search.brave.com',
  'startpage.com',
  'yandex.com',
  'ecosia.org'
];

async function applyRuleChanges() {
  try {
    // Toggle individual static rules using updateStaticRules (Chrome 111+)
    const disableRuleIds = [];
    const enableRuleIds = [];

    for (const [ruleId, ruleConfig] of Object.entries(activeConfig.rules)) {
      const id = parseInt(ruleId, 10);
      if (isNaN(id)) continue;

      if (ruleConfig.enabled === false) {
        disableRuleIds.push(...expandRuleIds(id));
      } else {
        enableRuleIds.push(...expandRuleIds(id));
      }
    }

    if (disableRuleIds.length > 0 || enableRuleIds.length > 0) {
      await chrome.declarativeNetRequest.updateStaticRules({
        rulesetId: 'blocking_rules',
        disableRuleIds,
        enableRuleIds
      });
      console.log(`[CONFIG] Static rules — disabled: [${disableRuleIds}], re-enabled: [${enableRuleIds}]`);
    }

    // Handle dynamic rules for additional blacklist/whitelist domains
    const existingDynamic = await chrome.declarativeNetRequest.getDynamicRules();
    const removeIds = existingDynamic.map(r => r.id);
    const addRules = [];
    let dynamicId = 5001;

    const allResourceTypes = ['main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other'];

    // Classroom control: block YouTube inside Google Docs/Sheets/Slides. The
    // rule exists ONLY while the option is on (all dynamic rules are removed
    // and rebuilt on every config load), so "off" leaves no footprint. Scoped
    // by initiator, so youtube.com itself keeps working. Priority 11 so this
    // explicit opt-in beats a district's general additionalWhitelist entry for
    // youtube.com (priority 10) rather than being silently cancelled by it.
    if (activeConfig.classroomControls && activeConfig.classroomControls.blockYouTubeInDocs === true) {
      addRules.push({
        id: YOUTUBE_IN_DOCS_RULE_ID,
        priority: 11,
        action: { type: 'block' },
        condition: {
          requestDomains: ['youtube.com', 'youtube-nocookie.com', 'youtu.be', 'ytimg.com', 'googlevideo.com', 'youtubeembeddedplayer.googleapis.com'],
          // Google sign-in status checks ride on accounts.youtube.com; it serves
          // no video, so it is never part of the block.
          excludedRequestDomains: ['accounts.youtube.com'],
          initiatorDomains: ['docs.google.com'],
          resourceTypes: ['sub_frame', 'media', 'image', 'xmlhttprequest', 'ping', 'websocket', 'other']
        }
      });
    }

    // Classroom control: block YouTube players embedded in search results.
    // Same shape as the Docs rule, different initiators. Frames and media only:
    // the in-place player is an embed iframe, and result thumbnails (images)
    // are left alone so the results page still looks normal. A top-level click
    // through to youtube.com is a main_frame request and is not touched.
    if (activeConfig.classroomControls && activeConfig.classroomControls.blockYouTubeInSearch === true) {
      addRules.push({
        id: YOUTUBE_IN_SEARCH_RULE_ID,
        priority: 11,
        action: { type: 'block' },
        condition: {
          requestDomains: ['youtube.com', 'youtube-nocookie.com', 'youtu.be', 'googlevideo.com', 'youtubeembeddedplayer.googleapis.com'],
          excludedRequestDomains: ['accounts.youtube.com'],
          initiatorDomains: SEARCH_ENGINE_INITIATORS,
          resourceTypes: ['sub_frame', 'media']
        }
      });
    }

    // Additional blacklist domains → dynamic block rules
    for (const domain of activeConfig.domains.additionalBlacklist) {
      addRules.push({
        id: dynamicId++,
        priority: 3,
        action: { type: 'block' },
        condition: {
          requestDomains: [domain],
          resourceTypes: allResourceTypes
        }
      });
    }

    // Additional whitelist domains → dynamic allow rules (higher priority)
    for (const domain of activeConfig.domains.additionalWhitelist) {
      addRules.push({
        id: dynamicId++,
        priority: 10,
        action: { type: 'allow' },
        condition: {
          requestDomains: [domain],
          resourceTypes: allResourceTypes
        }
      });
    }

    // Additional urlFilter patterns → dynamic block rules.
    // Limited to main_frame + sub_frame so we don't nuke legitimate
    // script/image/font subresources that happen to share a URL prefix
    // with a blocked path.
    const urlFilterResourceTypes = ['main_frame', 'sub_frame'];
    for (const pattern of activeConfig.domains.additionalUrlFilters || []) {
      if (typeof pattern !== 'string' || !pattern) continue;
      addRules.push({
        id: dynamicId++,
        priority: 3,
        action: { type: 'block' },
        condition: {
          urlFilter: pattern,
          resourceTypes: urlFilterResourceTypes
        }
      });
    }

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: removeIds,
      addRules: addRules
    });

    console.log(`[CONFIG] Dynamic rules — added: ${addRules.length}, removed: ${removeIds.length}`);

  } catch (error) {
    console.error('[CONFIG] Failed to apply rule changes:', error);
  }
}

// The educational allowlist plus the district's additionalWhitelist, handed
// to content scripts so the content-side checks stand down on trusted vendor
// domains the same way the network rules do.
function trustedDomainList() {
  const extra = (activeConfig.domains && Array.isArray(activeConfig.domains.additionalWhitelist))
    ? activeConfig.domains.additionalWhitelist.filter(d => typeof d === 'string' && d)
    : [];
  return EXCLUDED_DOMAINS.concat(extra);
}

function broadcastConfigUpdate() {
  // Send updated config to all connected content scripts
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      if (tab.id) {
        chrome.tabs.sendMessage(tab.id, {
          type: 'CONFIG_UPDATED',
          config: {
            contentGuard: activeConfig.contentGuard,
            googleSitesInspector: activeConfig.googleSitesInspector,
            appsScriptInspector: activeConfig.appsScriptInspector,
            classroomControls: activeConfig.classroomControls,
            trustedDomains: trustedDomainList()
          }
        }).catch(() => {
          // Tab may not have content script loaded yet
        });
      }
    }
  });
}

// Listen for managed storage changes (admin pushes new policy)
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'managed') {
    console.log('[CONFIG] Managed storage changed, reloading config');
    loadConfig();
  }
});

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

let tabCreationEvents = [];
let connectedPorts = new Map();

// ============================================================================
// HEARTBEAT & ANTI-TAMPER SYSTEM
// ============================================================================

// Last ping timestamp per tab id — lets checkConnections distinguish a live
// content script from one that has gone silent (page tampering, forced
// content-script teardown, or the tab navigating somewhere our scripts don't
// run). A tab that is a normal web page but has no recent heartbeat is a
// signal an admin may want in the logs.
let lastHeartbeat = new Map();
let heartbeatTimer = null;

class HeartbeatMonitor {
  static startMonitoring() {
    // Idempotent: called on every service-worker start (see ensureInitialized).
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
    }
    if (!activeConfig.heartbeat.enabled) return;

    heartbeatTimer = setInterval(() => {
      this.checkConnections();
    }, activeConfig.heartbeat.interval);
  }

  static async checkConnections() {
    const tabs = await chrome.tabs.query({});
    const activePorts = connectedPorts.size;
    const now = Date.now();

    // Content scripts ping on their own ~30s cadence; flag a tab as stale
    // only well past that so we don't false-alarm on a tab mid-reconnect.
    const STALE_AFTER = 90000;
    let stale = 0;

    for (const tab of tabs) {
      if (!tab.id) continue;
      // Only expect a heartbeat from tabs whose content script has checked in
      // at least once. This deliberately does NOT read tab.url: a URL read here
      // was the only non-config use of the broad host permission, for a
      // console diagnostic. Side benefit: tabs opened before install (no
      // content script until reload) and non-web pages no longer false-alarm.
      const last = lastHeartbeat.get(tab.id);
      if (last === undefined) continue;
      if (now - last > STALE_AFTER) {
        stale++;
      }
    }

    if (stale > 0) {
      // Successful-defense logs use console.log (see 3.0.10 notes); a missing
      // heartbeat is genuinely warn-worthy — it can indicate tampering — so it
      // stays at warn for the Errors panel. The durable remedy is force-
      // installing the extension via Workspace so it cannot be disabled.
      console.warn(`[HEARTBEAT] ${stale} web tab(s) with no recent content-script heartbeat (tabs: ${tabs.length}, ports: ${activePorts})`);
    } else {
      console.log(`[HEARTBEAT] Active tabs: ${tabs.length}, Connected ports: ${activePorts}`);
    }
  }

  static recordPing(tabId) {
    if (tabId) lastHeartbeat.set(tabId, Date.now());
  }

  static registerPort(port) {
    const tabId = port.sender?.tab?.id;
    if (tabId) {
      connectedPorts.set(tabId, port);
      lastHeartbeat.set(tabId, Date.now());

      port.onDisconnect.addListener(() => {
        connectedPorts.delete(tabId);
      });
    }
  }
}

// ============================================================================
// TAB MANAGEMENT
// ============================================================================

async function enforceTabLimit() {
  try {
    const tabs = await chrome.tabs.query({});
    
    if (tabs.length > activeConfig.tabLimits.maxTabs) {
      const sortedTabs = tabs.sort((a, b) => {
        const timeA = a.lastAccessed || 0;
        const timeB = b.lastAccessed || 0;
        return timeA - timeB;
      });
      
      const tabsToClose = tabs.length - activeConfig.tabLimits.maxTabs;
      let closedCount = 0;
      
      for (const tab of sortedTabs) {
        if (closedCount >= tabsToClose) break;
        if (!tab.active && tab.id) {
          try {
            await chrome.tabs.remove(tab.id);
            closedCount++;
          } catch (error) {
            console.log(`Could not close tab ${tab.id}:`, error);
          }
        }
      }
    }
  } catch (error) {
    console.error('Error enforcing tab limit:', error);
  }
}

// ============================================================================
// SPAM DETECTION
// ============================================================================

function detectTabSpam() {
  const now = Date.now();
  
  // Remove old events
  while (tabCreationEvents.length > 0 && 
         tabCreationEvents[0] < now - activeConfig.tabLimits.tabCreationWindow) {
    tabCreationEvents.shift();
  }
  
  tabCreationEvents.push(now);
  
  if (tabCreationEvents.length > activeConfig.tabLimits.maxTabsInWindow) {
    return true;
  }
  
  return false;
}

async function handleBulkTabCreation(tabCount) {
  if (tabCount > 20) {
    
    const tabs = await chrome.tabs.query({});
    const sortedTabs = tabs.sort((a, b) => (b.id || 0) - (a.id || 0));
    
    let keepCount = 0;
    const tabsToKeep = new Set();
    
    for (const tab of tabs) {
      if (tab.active) {
        tabsToKeep.add(tab.id);
      }
    }
    
    for (const tab of sortedTabs) {
      if (keepCount < activeConfig.tabLimits.maxTabs && !tabsToKeep.has(tab.id)) {
        tabsToKeep.add(tab.id);
        keepCount++;
      }
    }
    
    for (const tab of tabs) {
      if (!tabsToKeep.has(tab.id) && tab.id) {
        try {
          await chrome.tabs.remove(tab.id);
        } catch (error) {
          // Tab might be already closed
        }
      }
    }
  }
}

// ============================================================================
// SERVICE WORKER DETECTION
// ============================================================================

const EXCLUDED_DOMAINS = [
  // Reference / encyclopedias
  'wikipedia.org',
  'britannica.com',
  'worldbookonline.com',

  // Curriculum & assignments
  'ixl.com',
  'khanacademy.org',
  'edpuzzle.com',
  'newsela.com',
  'commonlit.org',
  'brainpop.com',
  'readworks.org',
  'nearpod.com',
  'peardeck.com',
  'quizlet.com',
  'quizizz.com',
  'kahoot.it',
  'blooket.com',
  'gimkit.com',
  'formative.com',
  'kami.app',
  'flipgrid.com',
  'seesaw.me',
  'discoveryeducation.com',
  'scholastic.com',

  // Curriculum publishers (Pearson, McGraw Hill, HMH)
  'savvasrealize.com',
  'pearsonrealize.com',
  'mheducation.com',
  'hmhco.com',
  'my.hrw.com',
  'thinkcentral.com',

  // LMS platforms
  'schoology.com',
  'instructure.com',
  'blackboard.com',
  'powerschool.com',
  'google.com',
  'gstatic.com',
  'microsoftonline.com',
  'office.com',
  'office365.com',
  'sharepoint.com',
  'onenote.com',
  'clever.com',
  'classdojo.com',
  'remind.com',

  // Math & science
  'desmos.com',
  'geogebra.org',
  'wolframalpha.com',
  'mathway.com',
  'photomath.com',
  'phet.colorado.edu',
  'prodigygame.com',
  'zearn.org',
  'deltamath.com',
  'mathletics.com',
  'mysteryscience.com',
  'generationgenius.com',

  // Language & reading
  'duolingo.com',
  'getepic.com',
  'raz-kids.com',
  'starfall.com',
  'abcya.com',
  'lexialearning.com',
  'noredink.com',
  'achieve3000.com',
  'imaginelearning.com',
  'mobymax.com',
  'readingplus.com',
  'readinga-z.com',
  'myon.com',
  'quill.org',
  'membean.com',

  // Higher ed / MOOCs
  'coursera.org',
  'edx.org',
  'udemy.com',

  // Online programs / counseling
  'edmentum.com',
  'study-island.com',
  'apexlearning.com',
  'edgenuity.com',
  'naviance.com',
  'commonapp.org',

  // Research & media
  'pbslearningmedia.org',
  'pbs.org',
  'nationalgeographic.com',
  'nasa.gov',
  'smithsonianmag.com',
  'loc.gov',
  'archives.gov',

  // Civics / government data
  'usa.gov',
  'census.gov',
  'congress.gov',
  'whitehouse.gov',

  // Coding education
  'code.org',
  'scratch.mit.edu',
  'codecademy.com',
  'tynker.com',
  'codehs.com',
  'codecombat.com',
  'tinkercad.com',

  // Testing & assessment
  'collegeboard.org',
  'act.org',
  'nwea.org',
  'amplify.com',
  'renaissance.com',
  'iready.com',

  // Study & productivity
  'quizlet.live',
  'studystack.com',
  'cram.com',
  'anki.net',
  'ankiweb.net',
  'memrise.com',
  'vocabulary.com',
  'spellingcity.com',
  'turnitin.com',
  'grammarly.com',
  'canva.com',
  'prezi.com',
  'lucidchart.com',
  'diagrams.net',
  'notion.so',
  'wordwall.net',
  'mentimeter.com',
  'bookcreator.com',
  'pixton.com',
  'wakelet.com',
  'adobe.com',

  // Research & writing
  'scholar.google.com',
  'jstor.org',
  'easybib.com',
  'bibme.org',
  'citationmachine.net',
  'noodletools.com',
  'zotero.org',

  // Library & research databases
  'gale.com',
  'proquest.com',
  'ebsco.com',
  'ebscohost.com',
  'destinydiscover.com',
  'soraapp.com',
  'overdrive.com',
  'bookshare.org',
  'learningally.org',

  // Accessibility
  'texthelp.com',

  // Video & media education
  'ted.com',
  'edtechmagazine.com',
  'screencastify.com',
  'loom.com',
  'animoto.com',
  'powtoon.com',
  'book-creator.com',
  'storyboardthat.com',

  // District / custom
  'jaraty.com',
  'tapspeak.org',
  'lucidread.org',

  // ---- 3.0.9 ADDITIONS ----

  // State testing platforms (high-stakes — tab closure during a state test
  // is the worst-case false positive; expanded coverage prioritizes these)
  'testnav.com',                   // Pearson — PARCC, M-STEP, FSA, others
  'pearsonaccess.com',             // Pearson testing admin
  'pearsonaccessnext.com',         // Pearson testing admin (newer)
  'cambiumassessment.com',         // Cambium Learning (AIR successor)
  'cambiumlearning.com',
  'cambiumtds.com',                // Cambium Test Delivery System
  'airast.org',                    // American Institutes for Research (legacy)
  'drcedirect.com',                // DRC Insight (Data Recognition Corp)
  'smarterbalanced.org',           // Multi-state consortium
  'ets.org',                       // Educational Testing Service (covers all subdomains: HiSET, CAASPP, ELPAC, GRE, etc.)
  'texasassessment.gov',           // Texas STAAR
  'fastbridge.org',                // FAST screening (Renaissance)
  'dibels.uoregon.edu',            // DIBELS reading assessment
  'acadiencelearning.org',         // Acadience (DIBELS successor)
  'masteryconnect.com',            // District assessment platform
  'edulastic.com',                 // District assessment platform
  'usatestprep.com',               // Test prep
  'wida.us',                       // WIDA ELL assessment
  'wida.wisc.edu',                 // WIDA at UW-Madison
  'avantassessment.com',           // STAMP ELL placement
  'ged.com',                       // GED testing
  'ibo.org',                       // International Baccalaureate
  'hiset.ets.org',                 // HiSET (covered by ets.org but explicit for clarity)

  // Student information systems & district admin platforms
  'infinitecampus.com',
  'skyward.com',
  'aeries.com',
  'edupoint.com',                  // Synergy / ParentVUE / StudentVUE
  'classlink.com',                 // SSO portal — many districts route everything through this
  'tylertech.com',                 // Tyler Technologies (Munis, Versatrans, etc.)
  'renweb.com',                    // RenWeb (parochial schools)
  'factsmgt.com',                  // FACTS (parochial schools)
  'frontlineeducation.com',        // Frontline (substitutes, IEP, payroll)
  'frontlineks12.com',

  // Special education, IEP platforms, and assistive tech (IEP-student
  // tooling — false positives here are especially costly)
  'goalbookapp.com',               // Goalbook IEP goals
  'pcgeducation.com',              // PCG Education / EdPlan IEP
  'semstracker.com',               // Special Ed Medical Service tracker
  'centralreach.com',              // CentralReach ABA platform
  'tobiidynavox.com',              // AAC devices/software
  'mytobiidynavox.com',
  'boardmaker.com',                // Boardmaker symbol communication
  'assistiveware.com',             // Proloquo2Go AAC
  'prc-saltillo.com',              // PRC-Saltillo AAC devices
  'donjohnston.com',               // Co:Writer, Snap&Read
  'naturalreader.com',             // Text-to-speech
  'voicedream.com',                // Voice Dream Reader
  'clarosoftware.com',             // Claro reading/writing AT
  'gingersoftware.com',            // Ginger writing AT
  'nvaccess.org',                  // NVDA screen reader
  'freedomscientific.com',         // JAWS, ZoomText
  'humanware.com',                 // BrailleNote, Victor Reader

  // Parent communication
  'parentsquare.com',
  'bloomz.com',
  'talkingpoints.org',

  // Video conferencing (school-licensed)
  'zoom.us',
  'webex.com',

  // Additional curriculum & learning platforms
  'ck12.org',                      // CK-12 (free OER flexbooks)
  'pltw.org',                      // Project Lead the Way STEM
  'stmath.com',                    // ST Math (JiJi)
  'dreambox.com',                  // DreamBox math
  'splashlearn.com',               // SplashLearn K-5
  'abcmouse.com',                  // ABCmouse early learning
  'adventureacademy.com',          // ABCmouse for older grades
  'aleks.com',                     // ALEKS adaptive math
  'studysync.com',                 // StudySync ELA curriculum
  'wonderopolis.org',              // Wonder of the Day
  'studiesweekly.com',             // Studies Weekly social studies
  'timeforkids.com',               // Time for Kids
  'juniorachievement.org',         // Junior Achievement
  'mysterydoug.com',               // Mystery Doug (Mystery Science sibling)
  'definedlearning.com',           // Defined Learning STEM
  'unrealengine.com',              // Unreal Engine (used in game-design and CTE programs)

  // Additional library, database, and reading platforms
  'worldcat.org',
  'learningexpresslibrary.com',    // EBSCO LearningExpress
  'culturegrams.com',              // ProQuest CultureGrams
  'encyclopedia.com',
  'pebblego.com',                  // Capstone PebbleGo (early-reader nonfiction)
  'bookflix.com',                  // Scholastic BookFlix
  'trueflix.com',                  // Scholastic TrueFlix
  'abdodigital.com',
  'infobaselearning.com',
  'factsforme.com',                // Cherry Lake

  // Federal & state government education
  'ed.gov',                        // US Department of Education
  'house.gov',
  'senate.gov',
  'supremecourt.gov',
  'fldoe.org',                     // Florida DOE
  'nysed.gov',                     // New York State Ed Dept
  'cde.ca.gov',                    // California Dept of Education
  'tea.texas.gov',                 // Texas Education Agency

  // ---- 3.2.2 ADDITIONS ----

  // Web-filtering vendor infrastructure. These are the SCHOOL'S OWN filter and
  // its block pages — they must never be interfered with. iBoss (and several
  // other vendors) redirect a blocked request to a block page whose URL embeds
  // the originally-requested address as a parameter; when that blocked address
  // contains an evasion keyword (e.g. "...unblocked-games..."), the block-page
  // redirect itself matched rule 1003 (.*unblock.*(game|site|web).*) and YSNP
  // blocked the filter's own block page. Allowlisting the vendor domains exempts
  // the block page even when its URL carries the trigger words. Students cannot
  // host content on these vendor-controlled domains, so there is no bypass risk.
  'ibosscloud.com',                // iBoss cloud SWG (block pages)
  'iboss.com',                     // iBoss
  'lightspeedsystems.com',         // Lightspeed Filter / Relay
  'securly.com',                   // Securly
  'goguardian.com',                // GoGuardian (the vendor; "goguardian-bypass" tooling is matched separately and is not hosted here)
  'contentkeeper.com',             // ContentKeeper
  'linewize.com',                  // Linewize
  'linewize.net',
  'familyzone.com',                // Family Zone / Linewize
  'zscaler.com',                   // Zscaler
  'zscaler.net',
  'opendns.com',                   // Cisco Umbrella / OpenDNS
  'umbrella.com',
  'fortiguard.com',                // Fortinet FortiGuard
  'blocksi.net',                   // Blocksi
  'deledao.com',                   // Deledao
  'barracuda.com',                 // Barracuda Web Security
  // googleapis.com was previously allowlisted as an apex, which shielded storage.googleapis.com
  // (a hub host) from every check. Only the API subdomains pages actually need are exempt now.
  'fonts.googleapis.com',
  'ajax.googleapis.com',
  'maps.googleapis.com',
  'www.googleapis.com',
  'apis.googleapis.com',
  'youtubeembeddedplayer.googleapis.com',
  'translate.googleapis.com',
  'content.googleapis.com',
  'oauth2.googleapis.com',
  'securetoken.googleapis.com',
  'identitytoolkit.googleapis.com',
  'firestore.googleapis.com',
  'firebaseinstallations.googleapis.com',
  'firebaseremoteconfig.googleapis.com',
  'people.googleapis.com',
  'docs.googleapis.com',
  'sheets.googleapis.com',
  'drive.googleapis.com',
  'classroom.googleapis.com',
  'generativelanguage.googleapis.com',
  'speech.googleapis.com',
  'texttospeech.googleapis.com',
  // 3.3.0 allowlist expansion — vendor-controlled K-12 domains only (no user-published content)
  // ebooks, libraries, publishers
  'cengage.com',
  'vitalsource.com',
  'redshelf.com',
  'kortext.com',
  'perusall.com',
  'activelylearn.com',
  'mackinvia.com',
  'mackin.com',
  'follett.com',
  'follettdestiny.com',
  'follettsoftware.com',
  'libbyapp.com',
  'hoopladigital.com',
  'baker-taylor.com',
  'kidsa-z.com',
  'learninga-z.com',
  'readtheory.org',
  'tumblebooks.com',
  'tumblebooklibrary.com',
  'capstonepub.com',
  'rosendigital.com',
  'salempress.com',
  'storylineonline.net',
  'uniteforliteracy.com',
  'gutenberg.org',
  'openlibrary.org',
  'hathitrust.org',
  'oercommons.org',
  'openstax.org',
  'libretexts.org',
  'pearson.com',
  'savvas.com',
  'mcgraw-hill.com',
  // curriculum and practice platforms
  'greatminds.org',
  'illustrativemathematics.org',
  'kiddom.co',
  'carnegielearning.com',
  'mathnation.com',
  'stemscopes.com',
  'acceleratelearning.com',
  'explorelearning.com',
  'legendsoflearning.com',
  'flocabulary.com',
  'lexiacore5.com',
  'curriculumassociates.com',
  'i-ready.com',
  'freckle.com',
  'readingeggs.com',
  'mathseeds.com',
  'boddlelearning.com',
  'happynumbers.com',
  'typing.com',
  'typingclub.com',
  'nitrotype.com',
  'typingagent.com',
  'icivics.org',
  'pbskids.org',
  'kahoot.com',
  'wayground.com',
  'socrative.com',
  'plickers.com',
  'classkick.com',
  'baamboozle.com',
  'flippity.net',
  'jeopardylabs.com',
  'gradescope.com',
  'otus.com',
  'edsby.com',
  'w3schools.com',
  'developer.mozilla.org',
  'makecode.com',
  'minecraft.net',
  'wevideo.com',
  'flip.com',
  // assessment
  'istation.com',
  'pearsonassessments.com',
  'illuminateed.com',
  'linkit.com',
  'caaspp.org',
  // accessibility
  'kurzweiledu.com',
  'kurzweil3000.com',
  'speechify.com',
  'ablenetinc.com',
  'readspeaker.com',
  // platforms, SSO, LMS
  'd2l.com',
  'brightspace.com',
  'microsoft.com',
  'live.com',
  'msftauth.net',
  'msauth.net',
  'office.net',
  'sharepointonline.com',
  'apple.com',
  'gg4l.com',
  'rapididentity.com',
  // reference and government
  'noaa.gov',
  'nih.gov',
  'cdc.gov',
  'usgs.gov',
  'nps.gov',
  'si.edu',
  'c-span.org',
  'merriam-webster.com',
  'thesaurus.com',
  'purdue.edu',
  // college and career
  'xello.com',
  'studentaid.gov',
  'scoir.com',
  'parchment.com',
  // SEL, safety and classroom management
  'secondstep.org',
  'characterstrong.com',
  'gaggle.net',
  'bark.us',
  'hapara.com',
  'dyknow.com',
  'lanschool.com',
  'managedmethods.com',
  // web-filter vendors (block pages must never be interfered with)
  'paloaltonetworks.com',
  'fortinet.com',
  'sophos.com',
  'watchguard.com',
  'sonicwall.com',
  'smoothwall.com',
  'netsweeper.com',
  'webtitan.com',
  'dnsfilter.com',
  'cleanbrowsing.org',
  'safedns.com'
];

async function detectServiceWorkerProxy(details) {
  // Only act on top-frame navigations. This function's only action is closing
  // the entire tab, so matching on a subframe URL (an ad/embed/widget) would
  // let a stray match take down the student's whole tab. Sub-frame proxy
  // resources are covered by the DNR rules (which target sub_frame) and by the
  // Google Sites inspector instead.
  if (details.frameId !== 0) return;

  // Check for known proxy Service Worker patterns
  const suspiciousPatterns = [
    // Proxies (established)
    /ultraviolet.*(proxy|unblo|bypass)/i,
    /rammerhead/i,
    // "scramjet" alone false-positives on legitimate aerospace content
    // (NASA's X-43 scramjet research articles, etc.) — same class of bug
    // as the old bare /ultraviolet/i pattern that hit Wikipedia. Require
    // a proxy-context suffix to match.
    /\bscramjet[-_.]*(proxy|unblock|bypass|client|worker|bundle|js)\b/i,
    // Scramjet is now the FLAGSHIP TitaniumNetwork/Mercury Workshop proxy
    // (Ultraviolet is deprecated/unmaintained as of 2026). Its shipped
    // bundle/WASM filenames and global symbols are highly specific and
    // essentially never appear outside a Scramjet deployment, so we match
    // them bare — this catches a hub that renames the loader to defeat the
    // keyword pattern above but still ships the stock runtime.
    /scramjet\.(all|sync|wasm|worker|shared|controller)\.(?:js|wasm)/i,
    /\$scramjetLoad(?:Controller|Worker)\b/,
    /\bScramjet(?:ServiceWorker|Controller)\b/,
    /mercurywork/i,
    /holy[-_.]?unblocker/i,
    /corrosion[-_.]?proxy/i,
    /stomp[-_.]?(bootstrap|rewrite)/i,

    // Newer proxy frameworks (2025-2026 sweep)
    // - Interstellar: actively maintained, GitHub UseInterstellar/Interstellar.
    //   Tightened from .* to a short separator so we don't match IMDB or
    //   film-studies URLs about the Christopher Nolan movie that happen to
    //   contain "proxy" elsewhere in the path.
    /\binterstellar[-_.]*(proxy|unblock|bypass|ub|client|worker)\b/i,
    // - Doge Unblocker family: dogenetwork/, DogeNetwork/dogeub, the-V01D/voiddoge, etc.
    /\bdoge[-_.]?(unblocker|proxy|network)\b/i,
    /\bdogeub\b/i,
    // - Womginx: wombat + nginx-based proxy (binary-person/womginx)
    /\bwomginx\b/i,
    // - Alloy / AlloyProxy: Titanium Network's web proxy, foundation for many forks
    /\balloy[-_.]?proxy\b/i,
    // - TacoProxy: Alloy frontend
    /\btaco[-_.]?proxy\b/i,
    // - InvisiProxy: Scramjet + Ultraviolet wrapper with Wisp/Bare-Mux
    /\binvisi[-_.]?proxy\b/i,
    // - Nebula Proxy / Nebula-X
    /\bnebula[-_.]?proxy\b/i,
    // - GoGuardian-Bypass (AroriaNetwork): iframe-based GoGuardian bypass
    /\bgoguardian[-_.]?bypass\b/i,
    // - Project group identifiers that appear in their distribution URLs
    /\btitanium[-_.]?network\b/i,
    /\baroria[-_.]?network\b/i,

    // Newer proxy frameworks / forks that have appeared or risen to
    // prominence since the 3.0.9 sweep (2026 roster). Generic dictionary
    // words (bolt, galaxy, shadow, saturn, utopia, incognito, emerald,
    // rosin, strawberry, sapphire, chemical, selenite, kpx, jupiter) are
    // anchored to a proxy-context suffix to keep false positives low;
    // distinctive coined names (petezah, kazwire, hydrovolter, womginx,
    // daydreamx, hypersonic) are matched bare.
    // NOTE: "chemical" is intentionally NOT matched here — "chemical proxy" is
    // a legitimate earth-science term (geochemical/paleoclimate proxies), and
    // this function closes the whole tab on a match. The Chemical proxy is
    // still covered by DNR rule 1046, which is frame/script-scoped and carries
    // the educational allowlist.
    /\bbolt[-_.]?(proxy|unblocker)\b/i,
    /\bsapphire[-_.]?(proxy|unblock|launcher)\b/i,
    /\bhypers?0?nic[-_.]?(proxy|unblock)\b/i,   // Hypersonic / Hypers0nic (Scramjet frontend)
    /\bdaydream[-_.]?(x|proxy|unblock)\b/i,     // DaydreamX (Night Network tabbed proxy)
    /\bnight[-_.]?(network|proxy)\b/i,
    /\bspace[-_.]?proxy\b/i,
    /\buntitled[-_.]?proxy\b/i,
    /\bkpx[-_.]?(proxy|unblock)\b/i,
    /\butopia[-_.]?(proxy|unblock)\b/i,
    /\bsat(?:u|)rn[-_.]?(proxy|unblock)\b/i,    // Saturn / Satrun
    /\bgalaxy[-_.]?(proxy|unblock)\b/i,
    /\bshadow[-_.]?(proxy|unblock)\b/i,
    /\bincognito[-_.]?(proxy|unblock)\b/i,
    /\bemerald[-_.]?(proxy|unblock)\b/i,
    /\bselenite[-_.]?(proxy|unblock)\b/i,
    /\brosin[-_.]?(proxy|unblock)\b/i,
    /\bstrawberry[-_.]?(proxy|unblock)\b/i,
    /\bradon[-_.]?(games?|proxy|unblock)\b/i,
    /\bjup(?:i|1)t[e3]?r[-_.]?proxy\b/i,        // Jupiter / Jup1tR proxy
    /\bjup1tr\b/i,
    /\bnode[-_.]?unblocker\b/i,
    /\bpetezah\b/i,
    /\bkazwire\b/i,
    /\bhydrovolter\b/i,

    // Transport & protocol layers.
    // Ultraviolet/Scramjet now tunnel over the Wisp protocol via Bare-Mux
    // with an Epoxy or libcurl.js transport (TLS-in-WASM over a WebSocket).
    // We match the loader/transport names AND their shipped global symbols
    // and worker paths so renaming the frontend doesn't help — the stock
    // transport runtime still has to load.
    /uv\.bundle/i,
    /bare[-_.]?client/i,
    /bare[-_.]?mux/i,
    /\bBareMux(?:Connection)?\b/,               // BareMux / BareMux.BareMuxConnection global
    /\/baremux\/worker\.js/i,
    /epoxy[-_.]?(transport|client|worker)/i,
    /\bEpoxyClient\b/,
    /\bEpxMod\b/,
    /epoxy[-_.]?tls/i,
    /epoxy\.wasm/i,
    /wisp[-_.]?(client|server|transport)/i,
    /libcurl[-_.]?(transport|worker)/i,
    /tomphttp/i,
    // Bare *server* endpoints (the server-side half of the transport).
    // The bare protocol exposes versioned /bare/v{N}/ paths, and the
    // reference implementation ships as @tomphttp/bare-server-node.
    /bare[-_.]?server/i,
    /@tomphttp\/bare-server-node/i,
    /\/bare\/v\d/i,

    // Client-side URL rewriters used by proxy projects
    // Wombat (webrecorder/wombat) is the rewriter that Womginx and several
    // others depend on. Match the characteristic global symbol and the
    // canonical script filename rather than the bare word "wombat".
    /\bwbWombat\b/,
    /\/wombat\.js\b/i,

    // Generic proxy service worker patterns
    /service[-_.]?worker[-_.]?proxy/i
  ];

  const url = details.url || '';

  // Skip excluded curriculum/educational domains.
  // Dot-anchored suffix match: 'ets.org' matches ets.org and *.ets.org, but
  // NOT 'darknets.org'. A bare endsWith() would let a student register a
  // domain ending in an allowlisted substring (e.g. '...nets.org',
  // '...hosted.com') to bypass proxy detection. Mirrors the anchored logic
  // already used in content_guard.js (currentPageIsHistoryMonitorExempt).
  try {
    const hostname = new URL(url).hostname;
    if (EXCLUDED_DOMAINS.some(domain => hostname === domain || hostname.endsWith('.' + domain))) {
      return;
    }
  } catch (e) {
    // Invalid URL, continue with detection
  }

  const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(url));

  if (isSuspicious) {
    // Attempt to close the tab
    if (details.tabId) {
      try {
        await chrome.tabs.remove(details.tabId);
      } catch (error) {
        console.error('Failed to close proxy tab:', error);
      }
    }
  }
}

// ============================================================================
// DATA: URL GAME / PROXY DETECTION
// ============================================================================

// High-confidence signatures for game/proxy content smuggled into a
// `data:text/html` top-level navigation. This is the data: analogue of the
// about:blank vector closed in 3.0.12: the same launcher templates do
//   window.open('data:text/html,<full game HTML>')
// and the game runs in a tab that NEITHER the content-script inspectors
// (Chrome does not inject content scripts into data: URLs) NOR declarativeNet-
// Request (data: is not a network request) can see. So we inspect the URL the
// navigation committed to, in the background, and close the tab on a match.
//
// Patterns mirror apps_script_inspector.js's HIGH_CONFIDENCE set — any single
// match is conclusive, so the false-positive risk is low (and data:text/html
// top-level navigations are themselves vanishingly rare in legitimate K-12
// use). Kept in sync intentionally; if you add a brand/engine there, add it
// here.
//
// Limitation: a launcher that opens a *minimal* data: page and injects the
// game later via document.write leaves no signature in the committed URL.
// The dominant template embeds the whole document inline, which this catches.
const DATA_URL_GAME_PATTERNS = [
  // Game engines
  /createUnityInstance\s*\(/,
  /\bunity-canvas\b/i,
  /\bc3runtime\b/i,
  /\bruntimeScriptList\s*:/i,
  // Ad-fraud distribution networks
  /\b(api\.)?gamemonetize\.com\b/i,
  /\b(ads\.)?gamedistribution\.com\b/i,
  // Consumer game portals that hubs proxy/embed content from
  /\b(?:www\.)?poki\.com\b/i,
  /\b(?:www\.)?crazygames\.com\b/i,
  /\by8\.com\b/i,
  /\barmorgames\.com\b/i,
  /\baddictinggames\.com\b/i,
  /\bnewgrounds\.com\b/i,
  // Flash / base64 game payloads
  /\bswfToBlobUrl\b/,
  /application\/x-shockwave-flash/,
  /data:@file\/(xml|html);base64/i,
  // Ad-fraud / launcher fingerprints
  /google\.ima\.AdsRequest/,
  /Object\.defineProperty\s*\(\s*document\s*,\s*['"]referrer['"]/i,
  /\bgameXmlUrl\b/,
  /\bgoogleScriptUrl\b/,
  /id\s*=\s*["']free-game-grid["']/i,
  // Commercial game brand names that essentially only appear on hubs
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
  // 2026 brand-list additions
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

async function detectDataUrlGame(details) {
  const url = details.url || '';
  if (!/^data:text\/html/i.test(url)) return;

  // Decode the payload so signatures match the rendered source, not the
  // percent-/base64-encoded transport form. Fall back to the raw URL string
  // if decoding fails (a partial match on the encoded form is still useful).
  let haystack = url;
  try {
    const comma = url.indexOf(',');
    if (comma !== -1) {
      const meta = url.slice(5, comma); // between "data:" and ","
      const payload = url.slice(comma + 1);
      haystack = /;base64/i.test(meta) ? atob(payload) : decodeURIComponent(payload);
    }
  } catch (e) {
    // Malformed encoding — scan the raw URL string instead.
  }

  if (DATA_URL_GAME_PATTERNS.some(p => p.test(haystack))) {
    console.log(`[SECURITY] data: URL game blocked on tab ${details.tabId}`);
    if (details.tabId) {
      try {
        await chrome.tabs.remove(details.tabId);
      } catch (error) {
        console.error('Failed to close data: URL game tab:', error);
      }
    }
  }
}

// ============================================================================
// MESSAGE HANDLING
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only accept messages from this extension's own content scripts.
  // sender.id must match our extension ID, and content scripts always
  // carry a tab context (sender.tab). Rejecting anything else blocks
  // stray messages from other extensions or future externally_connectable
  // configurations from reading config.
  if (sender.id !== chrome.runtime.id || !sender.tab) {
    return;
  }

  switch (message.type) {
    case 'HEARTBEAT':
      sendResponse({ status: 'alive', timestamp: Date.now() });
      break;

    case 'GET_CONFIG':
      // Wait for the admin config to be loaded before replying. A content
      // script's GET_CONFIG can be the very event that wakes a dormant
      // service worker; answering immediately would hand it DEFAULT_CONFIG
      // (kill switches ignored, Strict Sites mode off).
      ensureInitialized().catch(() => {}).then(() => {
        sendResponse({
          contentGuard: activeConfig.contentGuard,
          googleSitesInspector: activeConfig.googleSitesInspector,
          appsScriptInspector: activeConfig.appsScriptInspector,
          classroomControls: activeConfig.classroomControls,
          trustedDomains: trustedDomainList()
        });
      });
      return true; // async sendResponse
  }
});

// ============================================================================
// PORT CONNECTIONS (HEARTBEAT)
// ============================================================================

chrome.runtime.onConnect.addListener((port) => {
  // Only accept connections from our own extension's content scripts.
  if (port.sender?.id !== chrome.runtime.id || !port.sender?.tab) {
    try { port.disconnect(); } catch (e) {}
    return;
  }

  if (port.name === 'heartbeat') {
    HeartbeatMonitor.registerPort(port);

    port.onDisconnect.addListener(() => {
      // Read lastError to suppress the bfcache "channel is closed" warning
      void chrome.runtime.lastError;
    });

    port.onMessage.addListener((msg) => {
      if (msg.type === 'ping') {
        HeartbeatMonitor.recordPing(port.sender?.tab?.id);
        try {
          port.postMessage({ type: 'pong', timestamp: Date.now() });
        } catch (e) {
          // Port closed (page entered bfcache), ignore
        }
      }
    });
  }
});

// ============================================================================
// TAB EVENT LISTENERS
// ============================================================================

chrome.tabs.onCreated.addListener(async (tab) => {
  const isSpam = detectTabSpam();

  if (isSpam && tab.id) {
    // Close the spam tab regardless of whether it grabbed focus. Earlier
    // builds only closed background spam tabs (!tab.active), which let a
    // launcher that calls window.open with focus (or a foreground
    // window.open loop) survive by keeping each burst tab active. The spam
    // threshold (>maxTabsInWindow created within tabCreationWindow) only
    // trips on genuine flooding, so closing the focused tab is safe;
    // focus falls back to a prior tab, and enforceTabLimit cleans the rest.
    try {
      await chrome.tabs.remove(tab.id);
      return;
    } catch (error) {
      console.log('Could not close spam tab:', error);
    }
  }

  await enforceTabLimit();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  connectedPorts.delete(tabId);
  lastHeartbeat.delete(tabId);
});

// ============================================================================
// WEB NAVIGATION MONITORING
// ============================================================================

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.url) {
    // Detect Service Worker proxies (URL keyword match)
    await detectServiceWorkerProxy(details);
    // Detect games smuggled into a data:text/html top-level navigation —
    // invisible to both content scripts and DNR. Only inspect the top frame;
    // a data: subframe can't be a free-standing launched game tab.
    if (details.frameId === 0) {
      await detectDataUrlGame(details);
    }
  }
});

// ============================================================================
// INITIALIZATION
// ============================================================================

// activeConfig lives in service-worker memory, and an MV3 worker can be torn
// down and respawned at any time (idle kill, crash, memory pressure) WITHOUT
// firing onInstalled/onStartup. Initialization therefore runs on every worker
// start — from top level below — not just from those two events; otherwise a
// respawned worker silently reverts to DEFAULT_CONFIG and stops the heartbeat
// monitor. Memoized so concurrent callers share one load.
let initPromise = null;

function ensureInitialized() {
  if (!initPromise) {
    initPromise = loadConfig().then(() => {
      HeartbeatMonitor.startMonitoring();
    });
  }
  return initPromise;
}

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('You Shall Not Pass Enterprise v3.3.0 installed');

  // Load admin config before anything else
  await ensureInitialized();

  await enforceTabLimit();

  const tabs = await chrome.tabs.query({});
  await handleBulkTabCreation(tabs.length);
});

chrome.runtime.onStartup.addListener(async () => {
  console.log('You Shall Not Pass Enterprise v3.3.0 started');

  // Load admin config before anything else
  await ensureInitialized();

  const tabs = await chrome.tabs.query({});
  await handleBulkTabCreation(tabs.length);
});

ensureInitialized();

// ============================================================================
// PERIODIC ENFORCEMENT
// ============================================================================

setInterval(async () => {
  await enforceTabLimit();
}, 10000);

// ============================================================================
// SERVICE WORKER KEEPALIVE
// ============================================================================

// Prevent service worker from going dormant during active violations
let keepAliveInterval;

function startKeepAlive() {
  if (!keepAliveInterval) {
    keepAliveInterval = setInterval(() => {
      chrome.runtime.getPlatformInfo(() => {
        // Just accessing an API keeps the service worker alive
      });
    }, 20000); // Every 20 seconds
  }
}

function stopKeepAlive() {
  if (keepAliveInterval) {
    clearInterval(keepAliveInterval);
    keepAliveInterval = null;
  }
}

// Start keepalive
startKeepAlive();

console.log('You Shall Not Pass Enterprise v3.3.0 - Background worker initialized');
// Maintained by TeacherMagic.org