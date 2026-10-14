// You Shall Not Pass - Enterprise Hardened v3.3.0
// Content Guard Script
// Maintained by TeacherMagic.org
// Runs in all frames to detect and mitigate attacks in real-time

(function() {
  'use strict';
  
  // ============================================================================
  // CONFIGURATION
  // ============================================================================
  
  // Defaults matching the original hardcoded values
  let CONFIG = {
    MAX_HISTORY_PUSHES_PER_SECOND: 50,
    HEARTBEAT_INTERVAL: 30000, // 30 seconds
    MONITORING_ENABLED: true,
    ENABLE_LTBEEF_DETECTION: true,
    ENABLE_ANTI_EXTENSION_HEURISTICS: true,
    ENABLE_BLOB_GUARD: true,
    ENABLE_HUB_SHELL_DETECTION: true,
    ENABLE_SERVICE_WORKER_SCAN: true
  };

  // Load config from background service worker
  function loadConfigFromBackground() {
    try {
      chrome.runtime.sendMessage({ type: 'GET_CONFIG' }, (response) => {
        if (chrome.runtime.lastError || !response) return;
        if (response.contentGuard) {
          CONFIG.MONITORING_ENABLED = response.contentGuard.enabled !== false;
          if (typeof response.contentGuard.maxHistoryPushesPerSecond === 'number') {
            CONFIG.MAX_HISTORY_PUSHES_PER_SECOND = response.contentGuard.maxHistoryPushesPerSecond;
          }
          CONFIG.ENABLE_LTBEEF_DETECTION = response.contentGuard.enableLTBEEFDetection !== false;
          CONFIG.ENABLE_ANTI_EXTENSION_HEURISTICS = response.contentGuard.enableAntiExtensionHeuristics !== false;
          CONFIG.ENABLE_BLOB_GUARD = response.contentGuard.enableBlobGuard !== false;
          CONFIG.ENABLE_HUB_SHELL_DETECTION = response.contentGuard.enableHubShellDetection !== false;
          CONFIG.ENABLE_SERVICE_WORKER_SCAN = response.contentGuard.enableServiceWorkerScan !== false;
          applyTrustedDomains(response.trustedDomains);
          // Forward enabled/threshold to the MAIN-world history guard.
          sendHistoryGuardConfig();
        }
      });
    } catch (e) {
      // Extension context may not be available yet
    }
  }

  // Listen for config updates from background.
  // Only accept messages from our own extension's service worker:
  // sender.id must match, and background has no sender.tab.
  chrome.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== chrome.runtime.id || sender.tab) return;
    if (message.type === 'CONFIG_UPDATED' && message.config?.contentGuard) {
      const cg = message.config.contentGuard;
      CONFIG.MONITORING_ENABLED = cg.enabled !== false;
      if (typeof cg.maxHistoryPushesPerSecond === 'number') {
        CONFIG.MAX_HISTORY_PUSHES_PER_SECOND = cg.maxHistoryPushesPerSecond;
      }
      CONFIG.ENABLE_LTBEEF_DETECTION = cg.enableLTBEEFDetection !== false;
      CONFIG.ENABLE_ANTI_EXTENSION_HEURISTICS = cg.enableAntiExtensionHeuristics !== false;
      CONFIG.ENABLE_BLOB_GUARD = cg.enableBlobGuard !== false;
      CONFIG.ENABLE_HUB_SHELL_DETECTION = cg.enableHubShellDetection !== false;
      CONFIG.ENABLE_SERVICE_WORKER_SCAN = cg.enableServiceWorkerScan !== false;
      applyTrustedDomains(message.config.trustedDomains);
      sendHistoryGuardConfig();
    }
  });

  // ============================================================================
  // STATE
  // ============================================================================

  let historyMonitor = {
    count: 0,
    lastReset: Date.now(),
    violationTriggered: false
  };

  let heartbeatPort = null;
  let initialized = false;

  // Trusted domains: the educational allowlist plus the district's
  // additionalWhitelist, pushed by the background. On these pages every
  // content-side detector stands down (the heartbeat keeps running). Vendor
  // single-page apps — ebook readers, LMS editors — write to history dozens
  // of times a second and register service workers, and none of them are
  // trying to evade a filter.
  // STATIC copy of background.js EXCLUDED_DOMAINS (= the rules.json
  // allowlist). It has to be available synchronously at document_start: a
  // reader that writes history 800 times a second trips the flood defense
  // within ~60 ms, long before the first GET_CONFIG reply. The three copies
  // (rules.json, background.js, here) must stay identical — regenerate this
  // block from background.js whenever the allowlist changes.
  const TRUSTED_DOMAINS_STATIC = [
    'wikipedia.org', 'britannica.com', 'worldbookonline.com', 'ixl.com', 'khanacademy.org', 'edpuzzle.com',
    'newsela.com', 'commonlit.org', 'brainpop.com', 'readworks.org', 'nearpod.com', 'peardeck.com',
    'quizlet.com', 'quizizz.com', 'kahoot.it', 'blooket.com', 'gimkit.com', 'formative.com',
    'kami.app', 'flipgrid.com', 'seesaw.me', 'discoveryeducation.com', 'scholastic.com', 'savvasrealize.com',
    'pearsonrealize.com', 'mheducation.com', 'hmhco.com', 'my.hrw.com', 'thinkcentral.com', 'schoology.com',
    'instructure.com', 'blackboard.com', 'powerschool.com', 'google.com', 'gstatic.com', 'microsoftonline.com',
    'office.com', 'office365.com', 'sharepoint.com', 'onenote.com', 'clever.com', 'classdojo.com',
    'remind.com', 'desmos.com', 'geogebra.org', 'wolframalpha.com', 'mathway.com', 'photomath.com',
    'phet.colorado.edu', 'prodigygame.com', 'zearn.org', 'deltamath.com', 'mathletics.com', 'mysteryscience.com',
    'generationgenius.com', 'duolingo.com', 'getepic.com', 'raz-kids.com', 'starfall.com', 'abcya.com',
    'lexialearning.com', 'noredink.com', 'achieve3000.com', 'imaginelearning.com', 'mobymax.com', 'readingplus.com',
    'readinga-z.com', 'myon.com', 'quill.org', 'membean.com', 'coursera.org', 'edx.org',
    'udemy.com', 'edmentum.com', 'study-island.com', 'apexlearning.com', 'edgenuity.com', 'naviance.com',
    'commonapp.org', 'pbslearningmedia.org', 'pbs.org', 'nationalgeographic.com', 'nasa.gov', 'smithsonianmag.com',
    'loc.gov', 'archives.gov', 'usa.gov', 'census.gov', 'congress.gov', 'whitehouse.gov',
    'code.org', 'scratch.mit.edu', 'codecademy.com', 'tynker.com', 'codehs.com', 'codecombat.com',
    'tinkercad.com', 'collegeboard.org', 'act.org', 'nwea.org', 'amplify.com', 'renaissance.com',
    'iready.com', 'quizlet.live', 'studystack.com', 'cram.com', 'anki.net', 'ankiweb.net',
    'memrise.com', 'vocabulary.com', 'spellingcity.com', 'turnitin.com', 'grammarly.com', 'canva.com',
    'prezi.com', 'lucidchart.com', 'diagrams.net', 'notion.so', 'wordwall.net', 'mentimeter.com',
    'bookcreator.com', 'pixton.com', 'wakelet.com', 'adobe.com', 'scholar.google.com', 'jstor.org',
    'easybib.com', 'bibme.org', 'citationmachine.net', 'noodletools.com', 'zotero.org', 'gale.com',
    'proquest.com', 'ebsco.com', 'ebscohost.com', 'destinydiscover.com', 'soraapp.com', 'overdrive.com',
    'bookshare.org', 'learningally.org', 'texthelp.com', 'ted.com', 'edtechmagazine.com', 'screencastify.com',
    'loom.com', 'animoto.com', 'powtoon.com', 'book-creator.com', 'storyboardthat.com', 'jaraty.com',
    'tapspeak.org', 'lucidread.org', 'testnav.com', 'pearsonaccess.com', 'pearsonaccessnext.com', 'cambiumassessment.com',
    'cambiumlearning.com', 'cambiumtds.com', 'airast.org', 'drcedirect.com', 'smarterbalanced.org', 'ets.org',
    'texasassessment.gov', 'fastbridge.org', 'dibels.uoregon.edu', 'acadiencelearning.org', 'masteryconnect.com', 'edulastic.com',
    'usatestprep.com', 'wida.us', 'wida.wisc.edu', 'avantassessment.com', 'ged.com', 'ibo.org',
    'hiset.ets.org', 'infinitecampus.com', 'skyward.com', 'aeries.com', 'edupoint.com', 'classlink.com',
    'tylertech.com', 'renweb.com', 'factsmgt.com', 'frontlineeducation.com', 'frontlineks12.com', 'goalbookapp.com',
    'pcgeducation.com', 'semstracker.com', 'centralreach.com', 'tobiidynavox.com', 'mytobiidynavox.com', 'boardmaker.com',
    'assistiveware.com', 'prc-saltillo.com', 'donjohnston.com', 'naturalreader.com', 'voicedream.com', 'clarosoftware.com',
    'gingersoftware.com', 'nvaccess.org', 'freedomscientific.com', 'humanware.com', 'parentsquare.com', 'bloomz.com',
    'talkingpoints.org', 'zoom.us', 'webex.com', 'ck12.org', 'pltw.org', 'stmath.com',
    'dreambox.com', 'splashlearn.com', 'abcmouse.com', 'adventureacademy.com', 'aleks.com', 'studysync.com',
    'wonderopolis.org', 'studiesweekly.com', 'timeforkids.com', 'juniorachievement.org', 'mysterydoug.com', 'definedlearning.com',
    'unrealengine.com', 'worldcat.org', 'learningexpresslibrary.com', 'culturegrams.com', 'encyclopedia.com', 'pebblego.com',
    'bookflix.com', 'trueflix.com', 'abdodigital.com', 'infobaselearning.com', 'factsforme.com', 'ed.gov',
    'house.gov', 'senate.gov', 'supremecourt.gov', 'fldoe.org', 'nysed.gov', 'cde.ca.gov',
    'tea.texas.gov', 'ibosscloud.com', 'iboss.com', 'lightspeedsystems.com', 'securly.com', 'goguardian.com',
    'contentkeeper.com', 'linewize.com', 'linewize.net', 'familyzone.com', 'zscaler.com', 'zscaler.net',
    'opendns.com', 'umbrella.com', 'fortiguard.com', 'blocksi.net', 'deledao.com', 'barracuda.com',
    'fonts.googleapis.com', 'ajax.googleapis.com', 'maps.googleapis.com', 'www.googleapis.com', 'apis.googleapis.com', 'youtubeembeddedplayer.googleapis.com',
    'translate.googleapis.com', 'content.googleapis.com', 'oauth2.googleapis.com', 'securetoken.googleapis.com', 'identitytoolkit.googleapis.com', 'firestore.googleapis.com',
    'firebaseinstallations.googleapis.com', 'firebaseremoteconfig.googleapis.com', 'people.googleapis.com', 'docs.googleapis.com', 'sheets.googleapis.com', 'drive.googleapis.com',
    'classroom.googleapis.com', 'generativelanguage.googleapis.com', 'speech.googleapis.com', 'texttospeech.googleapis.com', 'cengage.com', 'vitalsource.com',
    'redshelf.com', 'kortext.com', 'perusall.com', 'activelylearn.com', 'mackinvia.com', 'mackin.com',
    'follett.com', 'follettdestiny.com', 'follettsoftware.com', 'libbyapp.com', 'hoopladigital.com', 'baker-taylor.com',
    'kidsa-z.com', 'learninga-z.com', 'readtheory.org', 'tumblebooks.com', 'tumblebooklibrary.com', 'capstonepub.com',
    'rosendigital.com', 'salempress.com', 'storylineonline.net', 'uniteforliteracy.com', 'gutenberg.org', 'openlibrary.org',
    'hathitrust.org', 'oercommons.org', 'openstax.org', 'libretexts.org', 'pearson.com', 'savvas.com',
    'mcgraw-hill.com', 'greatminds.org', 'illustrativemathematics.org', 'kiddom.co', 'carnegielearning.com', 'mathnation.com',
    'stemscopes.com', 'acceleratelearning.com', 'explorelearning.com', 'legendsoflearning.com', 'flocabulary.com', 'lexiacore5.com',
    'curriculumassociates.com', 'i-ready.com', 'freckle.com', 'readingeggs.com', 'mathseeds.com', 'boddlelearning.com',
    'happynumbers.com', 'typing.com', 'typingclub.com', 'nitrotype.com', 'typingagent.com', 'icivics.org',
    'pbskids.org', 'kahoot.com', 'wayground.com', 'socrative.com', 'plickers.com', 'classkick.com',
    'baamboozle.com', 'flippity.net', 'jeopardylabs.com', 'gradescope.com', 'otus.com', 'edsby.com',
    'w3schools.com', 'developer.mozilla.org', 'makecode.com', 'minecraft.net', 'wevideo.com', 'flip.com',
    'istation.com', 'pearsonassessments.com', 'illuminateed.com', 'linkit.com', 'caaspp.org', 'kurzweiledu.com',
    'kurzweil3000.com', 'speechify.com', 'ablenetinc.com', 'readspeaker.com', 'd2l.com', 'brightspace.com',
    'microsoft.com', 'live.com', 'msftauth.net', 'msauth.net', 'office.net', 'sharepointonline.com',
    'apple.com', 'gg4l.com', 'rapididentity.com', 'noaa.gov', 'nih.gov', 'cdc.gov',
    'usgs.gov', 'nps.gov', 'si.edu', 'c-span.org', 'merriam-webster.com', 'thesaurus.com',
    'purdue.edu', 'xello.com', 'studentaid.gov', 'scoir.com', 'parchment.com', 'secondstep.org',
    'characterstrong.com', 'gaggle.net', 'bark.us', 'hapara.com', 'dyknow.com', 'lanschool.com',
    'managedmethods.com', 'paloaltonetworks.com', 'fortinet.com', 'sophos.com', 'watchguard.com', 'sonicwall.com',
    'smoothwall.com', 'netsweeper.com', 'webtitan.com', 'dnsfilter.com', 'cleanbrowsing.org', 'safedns.com'
  ];
  let trustedDomains = TRUSTED_DOMAINS_STATIC.slice();
  function applyTrustedDomains(list) {
    // Background sends the static list plus the district's additionalWhitelist;
    // union so a late or missing reply can only add, never remove.
    if (Array.isArray(list)) {
      const merged = new Set(trustedDomains);
      for (const d of list) if (typeof d === 'string' && d) merged.add(d);
      trustedDomains = Array.from(merged);
    }
    sendHistoryGuardConfig();
  }
  function currentPageIsTrusted() {
    const host = location.hostname || '';
    if (!host) return false;
    return trustedDomains.some(d => host === d || host.endsWith('.' + d));
  }
  
  // ============================================================================
  // HEARTBEAT SYSTEM
  // ============================================================================
  
  let heartbeatInterval = null;

  function initializeHeartbeat() {
    try {
      heartbeatPort = chrome.runtime.connect({ name: 'heartbeat' });

      heartbeatPort.onMessage.addListener((msg) => {
        if (msg.type === 'pong') {
          console.log('[HEARTBEAT] Received pong from background');
        }
      });

      heartbeatPort.onDisconnect.addListener(() => {
        heartbeatPort = null;
        // Clear ping interval to avoid sending on a dead port
        if (heartbeatInterval) {
          clearInterval(heartbeatInterval);
          heartbeatInterval = null;
        }
        // Check lastError to suppress the bfcache console warning
        void chrome.runtime.lastError;
        // Only reconnect if the page is still visible
        if (document.visibilityState === 'visible') {
          setTimeout(initializeHeartbeat, 5000);
        }
      });

      // Clear any previous interval before creating a new one
      if (heartbeatInterval) {
        clearInterval(heartbeatInterval);
      }
      // Send periodic pings
      heartbeatInterval = setInterval(() => {
        if (heartbeatPort) {
          try {
            heartbeatPort.postMessage({ type: 'ping' });
          } catch (error) {
            // Port closed, clean up
            heartbeatPort = null;
            if (heartbeatInterval) {
              clearInterval(heartbeatInterval);
              heartbeatInterval = null;
            }
          }
        }
      }, CONFIG.HEARTBEAT_INTERVAL);

    } catch (error) {
      heartbeatPort = null;
    }
  }
  
  // ============================================================================
  // HISTORY FLOODING DETECTION (Point-Blank Defense)
  // ============================================================================

  // Hostname suffixes exempt from the history-flood monitor. Google's own
  // UIs (Sites Share dialog, Drive Share dialog, Docs collaboration UI,
  // Classroom navigation, etc.) can legitimately burn through pushState
  // calls fast enough to trip the threshold during normal operation —
  // the Share button on Google Sites is the canonical case that prompted
  // this exemption.
  //
  // The threat model for the history-flood defense is attacker-controlled
  // pages doing it deliberately to overload filtering extensions; Google
  // surfaces are not that. We give them a pass.
  //
  // Suffix match: 'google.com' matches google.com, sites.google.com,
  // drive.google.com, etc.
  const HISTORY_MONITOR_EXEMPT_SUFFIXES = [
    'google.com',
    'googleusercontent.com',
    'gstatic.com',
    'googleapis.com',
    'youtube.com',
    'youtube-nocookie.com'
  ];

  function currentPageIsHistoryMonitorExempt() {
    const host = location.hostname || '';
    if (currentPageIsTrusted()) return true;
    return HISTORY_MONITOR_EXEMPT_SUFFIXES.some(
      suffix => host === suffix || host.endsWith('.' + suffix)
    );
  }

  // Unified block notice. Message is intentionally generic — matches the
  // text used by google_sites_inspector.js — so the page author cannot tell
  // from the visible output which defense fired. Detection details go to the
  // console for admin/dev visibility. Safe DOM construction (no innerHTML).
  function renderBlockNotice() {
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
      // Can fire before <body> exists (we run at document_start).
      (document.body || document.documentElement).replaceChildren(container);
    } catch (error) {
      console.error('Failed to replace page content:', error);
    }
  }

  function handleHistoryFlood() {
    if (historyMonitor.violationTriggered) return;
    historyMonitor.violationTriggered = true;
    
    // Use console.log so Chrome's Errors panel doesn't aggregate this as
    // a failure — this is a successful defensive block, not an error.
    console.log(`[SECURITY] History flood blocked: ${historyMonitor.count}/sec on ${window.location.href}`);
    
    // Stop all loading
    try {
      window.stop();
    } catch (error) {
      console.error('Failed to stop window loading:', error);
    }
    
    renderBlockNotice();
  }
  
  // The pushState/replaceState wrap itself lives in history_guard_main.js
  // ("world": "MAIN"). A content script runs in an isolated world, so wrapping
  // window.history here — as builds before 3.2.3 did — is invisible to page
  // scripts and never counted a single page call. This side owns what the MAIN
  // world can't be trusted with: the config (chrome.runtime is only available
  // here) and the block notice (DOM constructors the page can't tamper with).
  //
  // Channel: CustomEvents on window, authenticated by a per-document nonce.
  // The first config message is dispatched synchronously at document_start —
  // before any page script exists — and the MAIN-world listener swallows every
  // config event (stopImmediatePropagation), so the page never learns the
  // nonce and cannot forge a "disable" message.
  const HG_EVT_READY = '__ysnp_hg_ready';
  const HG_EVT_CONFIG = '__ysnp_hg_config';
  const HG_EVT_FLOOD = '__ysnp_hg_flood';

  let historyGuardNonce = null;
  let historyGuardReadyAnswered = false;

  function makeNonce() {
    try {
      const bytes = new Uint8Array(16);
      crypto.getRandomValues(bytes);
      return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
      return String(Math.random()).slice(2) + String(Math.random()).slice(2);
    }
  }

  function sendHistoryGuardConfig() {
    if (!historyGuardNonce) return;
    // Google's own surfaces use rapid pushState legitimately (Sites Share
    // dialog being the known regression) — see HISTORY_MONITOR_EXEMPT_SUFFIXES.
    const enabled = CONFIG.MONITORING_ENABLED && !currentPageIsHistoryMonitorExempt();
    try {
      window.dispatchEvent(new CustomEvent(HG_EVT_CONFIG, {
        // String detail: primitives cross the world boundary intact.
        detail: JSON.stringify({
          nonce: historyGuardNonce,
          enabled: enabled,
          max: CONFIG.MAX_HISTORY_PUSHES_PER_SECOND
        })
      }));
    } catch (e) {}
  }

  function initializeHistoryMonitor() {
    historyGuardNonce = makeNonce();

    window.addEventListener(HG_EVT_FLOOD, (event) => {
      // Spoofable by the page, but the only effect is blocking itself.
      if (!CONFIG.MONITORING_ENABLED || currentPageIsHistoryMonitorExempt()) return;
      historyMonitor.count = parseInt(event.detail, 10) || historyMonitor.count;
      handleHistoryFlood();
    }, true);

    // If this script was injected before history_guard_main.js, the config
    // sent below is missed; the guard announces itself and we answer (once).
    window.addEventListener(HG_EVT_READY, () => {
      if (historyGuardReadyAnswered) return;
      historyGuardReadyAnswered = true;
      sendHistoryGuardConfig();
    }, true);

    if (currentPageIsHistoryMonitorExempt()) {
      console.log('[CONTENT GUARD] History monitor exempt on Google surface:', location.hostname);
    }
    sendHistoryGuardConfig();
  }
  
  // ============================================================================
  // SYMBALOO EVASION-HUB SCANNER
  // ============================================================================

  // Symbaloo is a legitimate webmix/bookmarking tool widely used by teachers,
  // but is also routinely abused as a hub for "unblocked games" link
  // collections. DNR rule 1035 already blocks URLs containing "unblocked" on
  // symbaloo.com at the network layer; this content-script check catches the
  // residual case where the URL is a hash/ID but the webmix TITLE contains
  // evasion keywords ("Unblocked Games 2026", etc.). Districts can disable
  // via managed config: rules: { "1035": { "enabled": false } } and/or
  // wrapping a flag around this function (TODO if FP complaints arrive).
  function currentPageIsSymbaloo() {
    const host = location.hostname || '';
    return host === 'symbaloo.com' || host.endsWith('.symbaloo.com');
  }

  function symbalooLooksLikeEvasion() {
    // URL check — defense in depth in case rule 1035 was disabled
    if (/\bunblock(ed|er|ing)?\b/i.test(location.href)) return true;

    // Title check — the residual case the DNR rule can't catch
    if (/\bunblock(ed|er|ing)?\b/i.test(document.title || '')) return true;

    // Heading / webmix-name text check
    const headings = document.querySelectorAll(
      'h1, h2, .mix-name, .webmix-title, [class*="title"], [class*="Title"]'
    );
    for (const h of headings) {
      if (/\bunblock(ed|er|ing)?\b/i.test(h.textContent || '')) return true;
    }
    return false;
  }

  function checkSymbalooPage() {
    if (!currentPageIsSymbaloo()) return;
    if (!symbalooLooksLikeEvasion()) return;

    console.log(`[CONTENT GUARD] Symbaloo hub blocked: ${location.href} (title: ${document.title})`);

    // Replace page with the same neutral block notice used by the
    // history-flood handler. Safe DOM construction (no innerHTML) so
    // attacker-controlled values can't inject markup.
    try {
      window.stop();
    } catch (e) {}

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
      document.body.replaceChildren(container);
    } catch (error) {
      console.error('Failed to replace page content:', error);
    }
  }

  // ============================================================================
  // ANTI-EXTENSION-TAMPER DOM MONITORING
  // ============================================================================

  // NOTE on scope (see README "Threat model"): The original LTBEEF / Ingot
  // extension-disable exploits were patched in Chrome 106, and this extension's
  // manifest requires Chrome 111+ — so the LTBEEF/Ingot-named GUIs cannot run
  // on any supported browser, and detecting them by name was dead weight.
  // Those name-specific selectors (.ingot-overlay, #ltbeef-ui,
  // [data-exploit="ltbeef"], .spork-gui, and the "ltbeef" substring match) were
  // REMOVED in 3.2.0.
  //
  // What remains targets the CURRENT tooling by BEHAVIOR, not by name: a
  // control-panel overlay that tries to disable/sideload extensions
  // (the Web Store's private install-API name, "disable extensions",
  // Point-Blank swap, noguardian). Behavioral text tells survive a rename;
  // dictionary-word tells were deliberately excluded to avoid FP reload loops.

  // Coined-token substring selectors — safe because "noguardian" is not an
  // ordinary word or common class fragment. Gated under
  // ENABLE_ANTI_EXTENSION_HEURISTICS.
  const ANTI_EXT_HEURISTIC_SELECTORS = [
    '[id*="noguardian" i]',
    '[class*="noguardian" i]'
  ];

  // HARD text signatures: strings that essentially only appear in extension-
  // tampering UIs. A match inside an injected overlay is conclusive on its own.
  // Dictionary words ("ingot", "point blank") are intentionally NOT here — they
  // false-positive on legitimate high-z-index overlays (cookie banners,
  // paywalls) and would loop the page reload.
  const ANTI_EXT_TEXT_SIGNATURES = [
    /\bnoguardian\b/i,
    /extension\s+launcher/i,
    /swap\s+launcher/i,
    /disable\s+(all\s+)?extensions?/i,
    /kill\s+extensions?/i,
    /beginInstallWithManifest3/i,
    /webstorePrivate/i,
    /goguardian\s*(bypass|remover|killer|disabler|off)/i
  ];

  function looksLikeInjectedOverlay(el) {
    try {
      const s = getComputedStyle(el);
      if (s.position !== 'fixed' && s.position !== 'absolute') return false;
      const z = parseInt(s.zIndex, 10);
      return !isNaN(z) && z >= 9999;
    } catch (e) {
      return false;
    }
  }

  // Per-tab reload cap so a mistaken (or genuinely re-injecting) detection
  // can't loop-reload the page forever. sessionStorage persists across same-tab
  // reloads; if it's unavailable (opaque origin / sandboxed frame) we fall back
  // to a single reload per script instance.
  const RELOAD_GUARD_KEY = '__ysnp_ax_reloads';
  const MAX_ANTI_EXT_RELOADS = 2;
  let reloadedThisInstance = false;

  function safeReloadForAntiExtension() {
    let count = null;
    try {
      count = parseInt(sessionStorage.getItem(RELOAD_GUARD_KEY) || '0', 10) || 0;
    } catch (e) {
      count = null; // sessionStorage not accessible here
    }

    if (count !== null) {
      if (count >= MAX_ANTI_EXT_RELOADS) {
        console.warn('[SECURITY] Anti-extension reload cap reached; leaving page as-is');
        return;
      }
      try { sessionStorage.setItem(RELOAD_GUARD_KEY, String(count + 1)); } catch (e) {}
    } else {
      if (reloadedThisInstance) return;
      reloadedThisInstance = true;
    }

    setTimeout(() => {
      try { window.location.reload(); } catch (e) {}
    }, 100);
  }

  function neutralizeAntiExtensionElement(element, why) {
    console.log(`[SECURITY] Anti-extension GUI removed: ${why} on ${window.location.href}`);
    try {
      element.remove();
    } catch (error) {
      console.error('Failed to remove anti-extension GUI element:', error);
    }
    // Reload to disrupt the exploit's page-context state (rate-capped).
    safeReloadForAntiExtension();
  }

  function safeQuery(selector) {
    try {
      return document.querySelector(selector);
    } catch (e) {
      // Older engines may not support the case-insensitive attribute flag.
      return null;
    }
  }

  function detectAntiExtensionGUI() {
    if (!CONFIG.ENABLE_LTBEEF_DETECTION) return false;
    // All remaining detection is heuristic (behavioral / coined-token). Gated
    // by its own kill switch so an admin hitting a false positive can disable
    // it via managed config.
    if (!CONFIG.ENABLE_ANTI_EXTENSION_HEURISTICS) return false;

    // Coined-token substring selectors (safe — not real words).
    for (const selector of ANTI_EXT_HEURISTIC_SELECTORS) {
      const element = safeQuery(selector);
      if (element) {
        neutralizeAntiExtensionElement(element, `selector=${selector}`);
        return true;
      }
    }

    // An injected high-z-index overlay whose text matches a HARD tampering
    // signature. Scanning body's direct children (the standard injection point
    // for these panels) keeps this cheap on large pages.
    const body = document.body;
    if (!body) return false;
    for (const el of body.children) {
      if (el.nodeType !== 1) continue;
      if (!looksLikeInjectedOverlay(el)) continue;
      const text = el.textContent || '';
      if (text.length > 6000) continue; // real tooling panels are small
      if (ANTI_EXT_TEXT_SIGNATURES.some(p => p.test(text))) {
        neutralizeAntiExtensionElement(el, 'heuristic overlay text match');
        return true;
      }
    }

    return false;
  }

  // ============================================================================
  // CROSS-ORIGIN BLOB / SRCDOC / javascript: GAME-IFRAME GUARD
  // ============================================================================

  // google_sites_inspector.js handles these vectors on sites.google.com. This
  // lighter guard runs on ALL pages (content_guard's scope) to close the
  // "spawn the game from a blob on a cheap domain / file: URL" bypass. To keep
  // false positives near zero on the open web, it uses only HIGH-confidence
  // signatures (specific launcher fingerprints, engine loaders, ad-fraud hosts,
  // brand names) — NOT the broad "emulator"/"unblocked"/"/rom/" terms the Sites
  // inspector can afford on its scoped surface.
  // CONCLUSIVE on a single match — hub/launcher/ad-fraud fingerprints that do
  // not appear in legitimate content. Engine loaders (createUnityInstance,
  // UnityLoader, c2/c3runtime) are DELIBERATELY EXCLUDED here: the Sites
  // inspector rates them medium-confidence because they appear in legitimate
  // K-12 game-design coursework and student portfolios, and this guard runs on
  // the whole open web — so treating them as conclusive would contradict that
  // and risk a false positive on a legit WebGL/Construct embed.
  const CG_CONCLUSIVE_SIGNATURES = [
    /\bgameXmlUrl\b/,
    /\bgoogleScriptUrl\b/,
    /\bswfToBlobUrl\b/,
    /google\.ima\.AdsRequest/,
    /Object\.defineProperty\s*\(\s*document\s*,\s*['"]referrer['"]/i,
    /\b(api\.)?gamemonetize\.com\b/i,
    /\b(ads\.)?gamedistribution\.com\b/i,
    /id\s*=\s*["']free-game-grid["']/i
  ];

  // Brand names — a single title could be an offhand mention, so (mirroring the
  // Sites page-body catalog scan) TWO or more distinct matches are required.
  const CG_BRAND_SIGNATURES = [
    /\bRetro\s*Bowl\b/i,
    /\bSubway\s*Surfers\b/i,
    /\bFriday\s*Night\s*Funkin/i,
    /\b1v1\.lol\b/i,
    /\bEaglercraft\b/i,
    /\bDrift\s*Hunters\b/i,
    /\bSlope\s*(?:Game|Ball|3D|Tunnel|Run)\b/i,
    /\bBitLife\b/i,
    /\bSnow\s*Rider\s*3D\b/i,
    /\bBloxd\.io\b/i,
    /\bSmash\s*Karts\b/i
  ];

  function neutralizeGameIframe(iframe, why) {
    console.log(`[CONTENT GUARD] Game iframe neutralized: ${why} on ${window.location.href}`);
    try { iframe.removeAttribute('srcdoc'); } catch (e) {}
    try { iframe.removeAttribute('src'); } catch (e) {}
    try { iframe.src = 'about:blank'; } catch (e) {}
    try { iframe.style.display = 'none'; } catch (e) {}
  }

  function contentMatchesGameSignature(html) {
    if (!html) return false;
    if (CG_CONCLUSIVE_SIGNATURES.some(p => p.test(html))) return true;
    if (CONFIG.ENABLE_HUB_SHELL_DETECTION && hubShellSignatureHit(html)) return true;
    // Brand path: require >=2 distinct brand titles.
    let brandHits = 0;
    for (const p of CG_BRAND_SIGNATURES) {
      if (p.test(html) && ++brandHits >= 2) return true;
    }
    return false;
  }

  function inspectIframeForGame(iframe) {
    if (!CONFIG.ENABLE_BLOB_GUARD) return false;
    let src = '';
    try { src = iframe.src || iframe.getAttribute('src') || ''; } catch (e) {}

    // javascript:/vbscript: iframe src executes script in the frame — always
    // neutralize (legitimate embeds never use these).
    if (/^\s*(javascript|vbscript):/i.test(src)) {
      neutralizeGameIframe(iframe, 'dangerous scheme');
      return true;
    }

    // srcdoc — inline document, readable directly.
    let srcdoc = null;
    try { srcdoc = iframe.getAttribute('srcdoc'); } catch (e) {}
    if (srcdoc && contentMatchesGameSignature(srcdoc)) {
      neutralizeGameIframe(iframe, 'srcdoc game');
      return true;
    }

    // blob: — the blob inherits the creator origin, so if it's same-origin we
    // can read its rendered document. Cross-origin/opaque blobs are skipped
    // (we don't guess without a signal, to avoid FP on the open web).
    if (src.startsWith('blob:')) {
      try {
        const doc = iframe.contentDocument || (iframe.contentWindow && iframe.contentWindow.document);
        if (doc && contentMatchesGameSignature(doc.documentElement.outerHTML)) {
          neutralizeGameIframe(iframe, 'blob game');
          return true;
        }
      } catch (e) {
        // Cross-origin blob — can't inspect; leave it (DNR/host rules cover known bad hosts).
      }
    }

    return false;
  }

  // The dedicated inspectors own these surfaces (more thorough, with block
  // notices); skip them here to avoid redundant work and double-neutralization.
  const BLOB_GUARD_SKIP_HOSTS = ['sites.google.com', 'script.googleusercontent.com'];

  function blobGuardAppliesToThisFrame() {
    const host = location.hostname || '';
    return !BLOB_GUARD_SKIP_HOSTS.some(h => host === h || host.endsWith('.' + h));
  }

  function scanForGameIframes() {
    if (!CONFIG.ENABLE_BLOB_GUARD) return;
    if (!blobGuardAppliesToThisFrame()) return;
    let iframes;
    try { iframes = document.querySelectorAll('iframe[srcdoc], iframe[src^="blob:"], iframe[src^="javascript:"]'); }
    catch (e) { return; }
    iframes.forEach(inspectIframeForGame);
  }

  // ============================================================================
  // HUB-SHELL / INLINE-SCRIPT SIGNATURE DETECTOR (3.2.4)
  // ============================================================================

  // The 2026 "cherri"/"Fern" hub family (and the renamed-Scramjet/Sapphire
  // builds it ships) is a BARE SHELL: one empty <div>, no text, no brand
  // names, every filename randomized per build, and a service worker that
  // takes over the origin before anything renders. Nothing the blob guard or
  // the brand catalog reads exists on such a page. What DOES survive the
  // randomization is the inline bootstrap code in <head>: the service-worker
  // takeover snippet, the hub's own globals, the renamed runtime's internal
  // symbol names, and the ad-fraud popunder call that pays for it. Inline
  // scripts are readable from the isolated world, so we fingerprint those.
  //
  // Every signature here is CONCLUSIVE on its own: coined tokens and vendor
  // API calls that do not occur in legitimate curriculum pages. Dictionary
  // words are deliberately absent. Rate: each inline script is tested once.
  const HUB_SHELL_INLINE_SIGNATURES = [
    // Service-worker takeover bootstrap (cherri/Fern): unregisters every other
    // SW, registers its own, force-reloads until it controls the page.
    { test: t => /\b__SW_FILE__\b/.test(t) && /\b__sw_reload\b/.test(t), why: 'sw-takeover bootstrap' },
    // Hub globals / storage keys
    { test: t => /\b__cherri(?:Hs|Assets|Navigate|Host|Sapphire|Audio)\b/.test(t) || /\bcherri_cdn_down\b/.test(t), why: 'cherri globals' },
    // Adcash popunder invocation (ad-fraud monetization of hubs; loaded via
    // a blob SharedWorker to dodge ad blockers). Vendor API, never on
    // legitimate K-12 content.
    { test: t => /\.runPop\s*\(\s*\{\s*zoneId\b/.test(t), why: 'popunder ad loader' },
    // Proxy runtime internals that survive filename renaming. The stock
    // Scramjet/Ultraviolet/Sapphire/Bare-Mux symbol names are compiled into
    // the bundles; a hub that inlines its bootstrap exposes them here.
    { test: t => /\bScramjet(?:Wasm|Version|ServiceWorker|Controller)\b/.test(t) || /\$scramjetLoad(?:Controller|Worker)\b/.test(t), why: 'scramjet runtime symbol' },
    { test: t => /\b__uv\$config\b/.test(t) || /\bUVServiceWorker\b/.test(t), why: 'ultraviolet runtime symbol' },
    { test: t => /\bsapphire_extensions\b/.test(t) || /\bSAPPHIRE_PREFIX\b/.test(t), why: 'sapphire runtime symbol' },
    { test: t => /\bsw\$initRemoteTransport\b/.test(t) || /\bBareMux\b/.test(t), why: 'bare-mux transport symbol' },
    // Decoy-page loaders that pull a proxy bundle from a GitHub account via
    // CDN mirrors (opium/"APStudy" template). The loader obfuscates the URL
    // by string reversal, so both orientations of the account path are
    // matched.
    { test: t => /TongSherbet\/storage/i.test(t) || /egarots\/tebrehSgnoT/i.test(t) || /apple-bonkers\/67/i.test(t), why: 'known hub CDN account path' },
    // "Totally Science" mirror template: inline code that renames the page
    // per serving hostname and injects noindex on CloudFront mirrors to stay
    // out of search indexes (and so out of filter vendors' crawlers).
    { test: t => /\bpageTitleNewName\b/.test(t) || /\baddMetaNoIndexNoFollow\b/.test(t), why: 'mirror-template title/noindex code' },
    // PeteZah "pz" decoy gate (HypeStudy, Rosin/ScholarNest): coined global
    // in the gate's inline bootstrap.
    { test: t => /\b__PZ_EG__\b/.test(t), why: 'pz decoy-gate bootstrap' },
    // Loaders that hide their URLs by writing every string backwards and
    // reversing it at runtime (the "APStudy"/opium decoy template does this 17
    // times on one page). "https://" backwards never appears in legitimate
    // inline script.
    // rawOnly: this one is meaningful only on the text as written — testing
    // it against the reversed variant would match every script that contains
    // a normal "https://".
    { test: t => /\/\/:s?ptth/.test(t), why: 'reversed-URL loader', rawOnly: true },
    // Nexora games hub (served through Bunny CDN pull zones fronting GitHub
    // Pages; decoy "Learning Hub" description). Coined globals from its inline
    // bootstrap.
    { test: t => /\bNexora(?:Auth|Boot|MouseTracking|PanicButton)\b/.test(t), why: 'nexora hub bootstrap' }
  ];

  // Signatures are tested against the script text as written AND against two
  // normalized forms: percent-decoded (an account path written as
  // "%54ongSherbet" decodes to the real name) and reversed (loaders that store
  // strings backwards). This closes the two cheap obfuscations seen in the
  // field without adding any new tokens.
  function hubShellTextVariants(text) {
    const variants = [text];
    try {
      const decoded = text.replace(/%([0-9a-fA-F]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16)));
      if (decoded !== text) variants.push(decoded);
    } catch (e) {}
    try {
      // Reversing even a 2.5 MB string is cheap; only inline scripts reach here.
      variants.push(text.split('').reverse().join(''));
    } catch (e) {}
    // Base64 literals (the obvious next step after reversal): decode any
    // base64-looking run of 24+ chars and append the decoded text as one
    // more variant. Binary-looking output is kept too; the regexes are cheap.
    try {
      const runs = text.match(/[A-Za-z0-9+/]{24,}={0,2}/g);
      if (runs && runs.length <= 500) {
        const decoded = [];
        for (const run of runs) {
          try { decoded.push(atob(run)); } catch (e) {}
        }
        if (decoded.length) variants.push(decoded.join('\n'));
      }
    } catch (e) {}
    return variants;
  }

  function hubShellSignatureHit(text) {
    const variants = hubShellTextVariants(text);
    for (let v = 0; v < variants.length; v++) {
      for (const sig of HUB_SHELL_INLINE_SIGNATURES) {
        if (sig.rawOnly && v > 0) continue;
        let hit = false;
        try { hit = sig.test(variants[v]); } catch (e) {}
        if (hit) return sig.why;
      }
    }
    return null;
  }

  // DOM markers: coined element ids from hub templates. Checked alongside the
  // inline scripts; a single match is conclusive.
  const HUB_SHELL_DOM_MARKERS = [
    { selector: '#category-Panic-Key', why: 'hub panic-key menu' },
    // PeteZah "pz" decoy gate: a study-site front ("HypeStudy", "ScholarNest")
    // with EducationalOrganization structured data and a proof-of-work CAPTCHA
    // in front of the hub, built to be categorized as Education by filter
    // crawlers. Its coined element id and script path survive rehosting.
    { selector: '#pz-seo-ld', why: 'pz decoy-gate structured data' },
    { selector: 'script[src$="pz-vanta.js"]', why: 'pz decoy-gate script' }
  ];

  let hubShellTriggered = false;
  const hubShellScannedScripts = new WeakSet();

  function handleHubShell(why) {
    if (hubShellTriggered) return;
    hubShellTriggered = true;
    console.log(`[SECURITY] Hub shell blocked: ${why} on ${window.location.href}`);
    try { window.stop(); } catch (e) {}
    // The shell's whole point is a service worker that owns the origin from
    // now on. Tear down every registration on this scope so a reload lands
    // on the network (where DNR sees it) rather than in the proxy's SW.
    try {
      if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {
        navigator.serviceWorker.getRegistrations().then(regs => {
          regs.forEach(r => { try { r.unregister(); } catch (e) {} });
        }).catch(() => {});
      }
    } catch (e) {}
    renderBlockNotice();
  }

  function scanInlineScriptsForHubShell() {
    if (!CONFIG.ENABLE_HUB_SHELL_DETECTION || hubShellTriggered) return;
    if (currentPageIsTrusted()) return;
    let scripts;
    // querySelectorAll (not document.scripts) so this also works in the
    // SVG-foreignObject launcher variant, where the document is not an
    // HTMLDocument.
    for (const m of HUB_SHELL_DOM_MARKERS) {
      let el = null;
      try { el = document.querySelector(m.selector); } catch (e) {}
      if (el) { handleHubShell(m.why); return; }
    }
    try { scripts = document.querySelectorAll('script:not([src])'); } catch (e) { return; }
    for (const el of scripts) {
      if (hubShellScannedScripts.has(el)) continue;
      hubShellScannedScripts.add(el);
      let text = '';
      try { text = el.textContent || ''; } catch (e) { continue; }
      if (!text || text.length > 2500000) continue; // 2.5 MB: inlining the whole bundle no longer hides the bootstrap
      const why = hubShellSignatureHit(text);
      if (why) { handleHubShell(why); return; }
    }
  }

  // ============================================================================
  // SERVICE-WORKER SOURCE SCAN (obfuscation-resistant)
  // ============================================================================

  // A service-worker proxy must register a worker on the page's origin, and
  // the page can fetch that worker's source (same origin). The proxy
  // frameworks' internal symbols are compiled into those files; a hub can
  // rename every file and every page global for free, but renaming these
  // means rebuilding the framework. Legitimate PWAs never contain them.
  //
  // Only the registered worker and the files it importScripts() are read
  // (depth 1, at most 6 files, 3 MB each). Google surfaces are skipped — they
  // register workers everywhere and never run a proxy.
  const SW_RUNTIME_SIGNATURES = [
    [/\bScramjet(?:Wasm|Version|ServiceWorker|Controller)\b/, 'scramjet'],
    [/\$scramjetLoad(?:Controller|Worker)\b|\bsw\$initRemoteTransport\b|\bsw\$setCookieDone\b|\bcontroller\$init\b/, 'scramjet'],
    [/\b__uv\$(?:config|referrer|cookies|location)\b|\bUVServiceWorker\b|\buv\.rewriteImport\b/, 'ultraviolet'],
    [/\bBareMux(?:Connection)?\b|\bbare-mux\b/, 'bare-mux'],
    [/\bsapphire_extensions\b|\bSAPPHIRE_PREFIX\b/, 'sapphire'],
    [/\brammerhead\b/i, 'rammerhead'],
    [/\bEpoxyClient\b|\bepoxy[-_.]?tls\b/, 'epoxy']
  ];
  const SW_SCAN_SKIP_SUFFIXES = ['google.com', 'googleusercontent.com', 'gstatic.com', 'youtube.com', 'googleapis.com'];
  let swScanDone = false;
  let swScanFoundRegistration = false;

  function swScanAppliesHere() {
    const host = location.hostname || '';
    if (!host) return false;
    return !SW_SCAN_SKIP_SUFFIXES.some(sfx => host === sfx || host.endsWith('.' + sfx));
  }

  function swSourceLooksLikeProxy(text) {
    for (const [re, why] of SW_RUNTIME_SIGNATURES) {
      if (re.test(text)) return why;
    }
    return null;
  }

  async function fetchSameOriginText(url, maxBytes) {
    const u = new URL(url, location.href);
    if (u.origin !== location.origin) return null; // never reach outside the page's own origin
    const res = await fetch(u.href, { cache: 'force-cache', credentials: 'omit' });
    if (!res.ok) return null;
    const text = await res.text();
    return text.length > maxBytes ? text.slice(0, maxBytes) : text;
  }

  async function scanServiceWorkers() {
    if (swScanDone || hubShellTriggered) return;
    if (currentPageIsTrusted()) return;
    if (!CONFIG.ENABLE_HUB_SHELL_DETECTION || !CONFIG.ENABLE_SERVICE_WORKER_SCAN) return;
    if (!swScanAppliesHere()) return;
    if (!navigator.serviceWorker || !navigator.serviceWorker.getRegistrations) return;
    swScanDone = true;
    let regs = [];
    try { regs = await navigator.serviceWorker.getRegistrations(); } catch (e) { return; }
    if (regs.length > 0) swScanFoundRegistration = true;
    const seen = new Set();
    const queue = [];
    for (const reg of regs) {
      const w = reg.active || reg.waiting || reg.installing;
      if (w && w.scriptURL) queue.push(w.scriptURL);
    }
    let budget = 6;
    while (queue.length && budget-- > 0) {
      const url = queue.shift();
      if (seen.has(url)) continue;
      seen.add(url);
      let text = null;
      try { text = await fetchSameOriginText(url, 3000000); } catch (e) {}
      if (!text) continue;
      // Same normalization as the inline-script signatures: as written,
      // percent-decoded, reversed, base64-decoded.
      let why = null;
      for (const variant of hubShellTextVariants(text)) {
        why = swSourceLooksLikeProxy(variant);
        if (why) break;
      }
      if (why) {
        handleHubShell('service worker contains ' + why + ' runtime (' + url.split('/').pop() + ')');
        return;
      }
      // Follow imports one level down. Static importScripts("a.js") arguments
      // first; then any string literal in the worker that, as written OR
      // reversed, looks like a relative script path — hubs hide the import
      // target as a reversed string and build it at runtime. Only same-origin
      // URLs are ever fetched, so a wrong guess costs one cached request.
      const re = /importScripts\s*\(([^)]*)\)/g;
      let m;
      while ((m = re.exec(text)) !== null) {
        for (const arg of m[1].split(',')) {
          const lit = arg.trim().replace(/^["'`]|["'`]$/g, '');
          // Only plain path/URL literals; a computed argument is handled by
          // the literal scan below.
          if (lit && /^[A-Za-z0-9_./:%-]+$/.test(lit)) {
            try { queue.push(new URL(lit, url).href); } catch (e) {}
          }
        }
      }
      const litRe = /["']([A-Za-z0-9_./-]{4,80})["']/g;
      let lm;
      let candidates = 0;
      while ((lm = litRe.exec(text)) !== null && candidates < 40) {
        for (const cand of [lm[1], lm[1].split('').reverse().join('')]) {
          if (/^[A-Za-z0-9_./-]+\.m?js$/.test(cand)) {
            candidates++;
            try { queue.push(new URL(cand, url).href); } catch (e) {}
          }
        }
      }
    }
  }

  // ============================================================================
  // EVENT-DRIVEN SCAN SCHEDULER
  // ============================================================================

  // Replaces the old setInterval(5000) poll that ran forever on every page.
  // A single debounced MutationObserver drives both the anti-extension check
  // and the blob/srcdoc game guard: idle pages cost nothing, and bursts of DOM
  // churn are coalesced into at most one pass per debounce window.
  let scanScheduled = false;
  let lastScanAt = 0;
  let domObserver = null;

  function runScans() {
    scanScheduled = false;
    lastScanAt = Date.now();
    if (currentPageIsTrusted()) return;
    try { scanInlineScriptsForHubShell(); } catch (e) {}
    try { detectAntiExtensionGUI(); } catch (e) {}
    try { scanForGameIframes(); } catch (e) {}
  }

  function scheduleScan() {
    if (scanScheduled) return;
    scanScheduled = true;
    // Debounce + a 2s minimum spacing. On a continuously-mutating page (chat,
    // infinite scroll, live dashboard) a fresh mutation arrives the instant
    // runScans finishes, so a plain debounce would settle into a sustained
    // ~1 Hz scan (getComputedStyle on positioned body children forces a style
    // recalc — measurable on low-end Chromebooks). Enforcing ≥2s between passes
    // bounds the steady-state cost; overlay/game injection doesn't need faster
    // response, and the load-time one-shots cover startup content.
    const sinceLast = Date.now() - lastScanAt;
    const delay = Math.max(1000, 2000 - sinceLast);
    setTimeout(runScans, delay);
  }

  function startEventDrivenScanning() {
    // A few one-shot passes to catch content present shortly after load,
    // without committing to a perpetual timer.
    setTimeout(runScans, 300);
    setTimeout(runScans, 1500);
    setTimeout(runScans, 4000);
    // Hub-shell bootstraps live in <head>; catch them the moment parsing ends.
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => { try { scanInlineScriptsForHubShell(); } catch (e) {} });
    }
    // Service-worker source scan: once the page has settled, with two retries
    // while no registration has been seen yet (registration is asynchronous
    // and a slow worker script can still be installing at 2.5 s), and again
    // if a worker takes control later (proxies register, then claim).
    for (const ms of [2500, 6000, 12000]) {
      setTimeout(() => {
        if (!swScanFoundRegistration) swScanDone = false;
        scanServiceWorkers().catch(() => {});
      }, ms);
    }
    try {
      if (navigator.serviceWorker) {
        navigator.serviceWorker.addEventListener('controllerchange', () => {
          swScanDone = false;
          setTimeout(() => { scanServiceWorkers().catch(() => {}); }, 500);
        });
      }
    } catch (e) {}

    try {
      domObserver = new MutationObserver(() => scheduleScan());
      const target = document.body || document.documentElement;
      if (target) {
        domObserver.observe(target, { childList: true, subtree: true });
      } else {
        document.addEventListener('DOMContentLoaded', () => {
          const t = document.body || document.documentElement;
          if (t && domObserver) domObserver.observe(t, { childList: true, subtree: true });
        });
      }
    } catch (e) {
      // MutationObserver unavailable — fall back to a low-frequency safety net.
      setInterval(runScans, 15000);
    }
  }

  // ============================================================================
  // INITIALIZATION
  // ============================================================================
  
  function initialize() {
    if (initialized) return;
    initialized = true;

    console.log('[CONTENT GUARD] Initializing protection...');

    try {
      loadConfigFromBackground();
      initializeHeartbeat();
      initializeHistoryMonitor();

      // Symbaloo title-based evasion check. Run now (URL is available
      // immediately) and re-run on DOMContentLoaded / load in case the
      // webmix title is set after initial render.
      checkSymbalooPage();
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', checkSymbalooPage);
      }
      window.addEventListener('load', checkSymbalooPage);

      // Event-driven anti-extension + blob/srcdoc game guard (no perpetual
      // poll — see startEventDrivenScanning).
      startEventDrivenScanning();

      console.log('[CONTENT GUARD] Protection active');
    } catch (error) {
      console.error('[CONTENT GUARD] Initialization error:', error);
    }
  }
  
  // Run immediately. The content script is injected at document_start,
  // so we must wrap history.pushState before any page script can call it —
  // waiting for DOMContentLoaded would be too late for the Point-Blank
  // defense. initialize() is idempotent.
  initialize();

})();
// Maintained by TeacherMagic.org