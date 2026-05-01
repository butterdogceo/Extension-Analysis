// You Shall Not Pass - Enterprise Hardened v3.0.5
// Written by Jim Tyler, Microsoft MVP
// Visit my Github for project notes: https://github.com/jimrtyler/youshallnotpass
// Background Service Worker
// Comprehensive defense against K-12 filter evasion ecosystem

// ============================================================================
// CONFIGURATION
// ============================================================================

const DEFAULT_CONFIG = {
  version: 1,
  rules: {},
  tabLimits: {
    maxTabs: 15,
    tabCreationWindow: 2000,
    maxTabsInWindow: 5
  },
  contentGuard: {
    enabled: true,
    maxHistoryPushesPerSecond: 50,
    enableLTBEEFDetection: true
  },
  googleSitesInspector: {
    enableBlobBlocking: true,
    enableGameDetection: true,
    enableWorkerDetection: true,
    enableBase64Detection: true,
    scanInterval: 2000,
    minSuspiciousFrameSize: 400
  },
  heartbeat: {
    enabled: true,
    interval: 5000
  },
  domains: {
    additionalWhitelist: [],
    additionalBlacklist: []
  }
};

// Active config starts as defaults, updated by loadConfig()
let activeConfig = structuredClone(DEFAULT_CONFIG);

// Config refresh interval (60 minutes) for URL-based configs
const CONFIG_REFRESH_INTERVAL = 60 * 60 * 1000;
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
        const response = await fetch(managed.configUrl, { cache: 'no-cache' });
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
        console.warn('[CONFIG] Failed to fetch config URL, using cache:', fetchError.message);
        // Fall back to cached version
        const cached = await chrome.storage.local.get(['_cachedConfig']);
        if (cached._cachedConfig) {
          adminConfig = cached._cachedConfig;
          console.log('[CONFIG] Using cached config');
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

async function applyRuleChanges() {
  try {
    // Toggle individual static rules using updateStaticRules (Chrome 111+)
    const disableRuleIds = [];
    const enableRuleIds = [];

    for (const [ruleId, ruleConfig] of Object.entries(activeConfig.rules)) {
      const id = parseInt(ruleId, 10);
      if (isNaN(id)) continue;

      if (ruleConfig.enabled === false) {
        disableRuleIds.push(id);
      } else {
        enableRuleIds.push(id);
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

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: removeIds,
      addRules: addRules
    });

    console.log(`[CONFIG] Dynamic rules — added: ${addRules.length}, removed: ${removeIds.length}`);

  } catch (error) {
    console.error('[CONFIG] Failed to apply rule changes:', error);
  }
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
            googleSitesInspector: activeConfig.googleSitesInspector
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

class HeartbeatMonitor {
  static startMonitoring() {
    if (!activeConfig.heartbeat.enabled) return;

    setInterval(() => {
      this.checkConnections();
    }, activeConfig.heartbeat.interval);
  }
  
  static async checkConnections() {
    const tabs = await chrome.tabs.query({});
    const activePorts = connectedPorts.size;
    
    console.log(`[HEARTBEAT] Active tabs: ${tabs.length}, Connected ports: ${activePorts}`);
  }
  
  static registerPort(port) {
    const tabId = port.sender?.tab?.id;
    if (tabId) {
      connectedPorts.set(tabId, port);
      
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
  'padlet.com',
  'seesaw.me',

  // LMS platforms
  'schoology.com',
  'instructure.com',
  'blackboard.com',
  'powerschool.com',
  'google.com',
  'googleapis.com',
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

  // Language & reading
  'duolingo.com',
  'epic.com',
  'getepic.com',
  'raz-kids.com',
  'starfall.com',
  'abcya.com',
  'lexialearning.com',
  'noredink.com',

  // Higher ed / MOOCs
  'coursera.org',
  'edx.org',
  'udemy.com',

  // Research & media
  'pbslearningmedia.org',
  'pbs.org',
  'nationalgeographic.com',
  'nasa.gov',
  'smithsonianmag.com',
  'loc.gov',
  'archives.gov',

  // Coding education
  'code.org',
  'scratch.mit.edu',
  'codecademy.com',
  'replit.com',

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
  'notion.site',

  // Research & writing
  'scholar.google.com',
  'jstor.org',
  'cite.com',
  'easybib.com',
  'bibme.org',
  'citationmachine.net',
  'noodletools.com',
  'zotero.org',

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
  'lucidread.org'
];

async function detectServiceWorkerProxy(details) {
  // Check for known proxy Service Worker patterns
  const suspiciousPatterns = [
    // Proxies
    /ultraviolet.*(proxy|unblo|bypass)/i,
    /rammerhead/i,
    /scramjet/i,
    /mercurywork/i,
    /holy[-_.]?unblocker/i,
    /corrosion[-_.]?proxy/i,
    /stomp[-_.]?(bootstrap|rewrite)/i,

    // Transport & protocol layers
    /uv\.bundle/i,
    /bare[-_.]?client/i,
    /bare[-_.]?mux/i,
    /epoxy[-_.]?(transport|client|worker)/i,
    /wisp[-_.]?(client|server|transport)/i,
    /libcurl[-_.]?(transport|worker)/i,
    /tomphttp/i,

    // Generic proxy service worker patterns
    /service[-_.]?worker[-_.]?proxy/i
  ];

  const url = details.url || '';

  // Skip excluded curriculum/educational domains
  try {
    const hostname = new URL(url).hostname;
    if (EXCLUDED_DOMAINS.some(domain => hostname.endsWith(domain))) {
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
// MESSAGE HANDLING
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case 'HEARTBEAT':
      sendResponse({ status: 'alive', timestamp: Date.now() });
      break;

    case 'GET_CONFIG':
      sendResponse({
        contentGuard: activeConfig.contentGuard,
        googleSitesInspector: activeConfig.googleSitesInspector
      });
      break;
  }
});

// ============================================================================
// PORT CONNECTIONS (HEARTBEAT)
// ============================================================================

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'heartbeat') {
    HeartbeatMonitor.registerPort(port);

    port.onDisconnect.addListener(() => {
      // Read lastError to suppress the bfcache "channel is closed" warning
      void chrome.runtime.lastError;
    });

    port.onMessage.addListener((msg) => {
      if (msg.type === 'ping') {
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
  
  if (isSpam) {
    if (!tab.active && tab.id) {
      try {
        await chrome.tabs.remove(tab.id);
        return;
      } catch (error) {
        console.log('Could not close spam tab:', error);
      }
    }
  }
  
  await enforceTabLimit();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  connectedPorts.delete(tabId);
});

// ============================================================================
// WEB NAVIGATION MONITORING
// ============================================================================

chrome.webNavigation.onCommitted.addListener(async (details) => {
  // Detect Service Worker proxies
  if (details.url) {
    await detectServiceWorkerProxy(details);
  }
});

// ============================================================================
// INITIALIZATION
// ============================================================================

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('You Shall Not Pass Enterprise v3.0.5 installed');

  // Load admin config before anything else
  await loadConfig();

  await enforceTabLimit();

  const tabs = await chrome.tabs.query({});
  await handleBulkTabCreation(tabs.length);

  // Start heartbeat monitoring
  HeartbeatMonitor.startMonitoring();
});

chrome.runtime.onStartup.addListener(async () => {
  console.log('You Shall Not Pass Enterprise v3.0.5 started');

  // Load admin config before anything else
  await loadConfig();

  const tabs = await chrome.tabs.query({});
  await handleBulkTabCreation(tabs.length);

  // Start heartbeat monitoring
  HeartbeatMonitor.startMonitoring();
});

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

console.log('You Shall Not Pass Enterprise v3.0.5 - Background worker initialized');
// Written by Jim Tyler, Microsoft MVP
// Visit my Github for project notes: https://github.com/jimrtyler/youshallnotpass