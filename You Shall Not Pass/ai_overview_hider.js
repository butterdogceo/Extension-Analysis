// You Shall Not Pass - Enterprise Hardened v3.3.0
// Classroom Controls
// Hide Google AI Overview (optional, OFF by default)
// Maintained by TeacherMagic.org
//
// Ported from the standalone "Hide AI Overview" extension. Removes the AI
// Overview block and the AI Mode entry points from Google Search so students
// engage with primary sources. Runs only on google.com, and does nothing
// unless an admin sets classroomControls.hideGoogleAiOverview to true in
// managed config. The stylesheet is injected by this script (not declared in
// the manifest) so that "off" means no page is touched at all.

(function() {
  'use strict';

  const FLAG = 'hideGoogleAiOverview';
  const STYLE_ID = 'ysnp-hide-ai-overview';
  const HIDDEN_ATTR = 'data-ysnp-ai-hidden';
  const HIDE_CSS = 'display: none !important; visibility: hidden !important; height: 0 !important; overflow: hidden !important; margin: 0 !important; padding: 0 !important;';

  // Precise selectors for AI Overview only
  const AI_SELECTORS = [
    'div#eKIzJc',
    'div[id="eKIzJc"]',
    'div.YzCcne[data-mcpr]',
    'div[data-mcp="18"]',
    'div[data-attrid="AIOverview"]',
    'div[data-async-type="aiOverview"]',
    'div[aria-label="AI Overview"]'
  ];

  // Selectors for AI Mode in navigation and on the homepage
  const AI_MODE_SELECTORS = [
    'div.olrp5b',
    'a.XVMlrc[href*="udm=50"]',
    'a[href*="udm=50"]',
    'button.plR5qb',
    'button[jsname="B6rgad"]'
  ];

  const STYLESHEET =
    AI_SELECTORS.join(',\n') + ' {\n  ' + HIDE_CSS.replace(/; /g, ';\n  ') + '\n}\n' +
    'div.olrp5b,\n' +
    'div[role="listitem"]:has(a[href*="udm=50"]),\n' +
    'a.XVMlrc[href*="udm=50"],\n' +
    'button.plR5qb,\n' +
    'button[jsname="B6rgad"] {\n  display: none !important;\n}\n';

  let active = false;
  let observer = null;
  let timers = [];
  // Previous inline style of each element we hide, so "off" can restore it.
  const previousStyle = new WeakMap();

  function hideElement(el) {
    if (!el || el.hasAttribute(HIDDEN_ATTR)) return;
    previousStyle.set(el, el.getAttribute('style'));
    el.style.cssText = HIDE_CSS;
    el.setAttribute(HIDDEN_ATTR, 'true');
  }

  function findAndHideAIOverview() {
    if (!active) return;

    // Method 1: direct selector matching for AI Overview
    AI_SELECTORS.forEach(selector => {
      try {
        document.querySelectorAll(selector).forEach(hideElement);
      } catch (e) {}
    });

    // Method 2: AI Mode nav button and homepage button
    AI_MODE_SELECTORS.forEach(selector => {
      try {
        document.querySelectorAll(selector).forEach(el => {
          // For links, hide the parent list item
          if (el.tagName === 'A') {
            const listItem = el.closest('div[role="listitem"]');
            if (listItem) hideElement(listItem);
            else hideElement(el);
          } else {
            hideElement(el);
          }
        });
      } catch (e) {}
    });

    // Method 3: the h1 containing "AI Overview" → hide its container
    document.querySelectorAll('h1').forEach(h1 => {
      if (h1.textContent && h1.textContent.trim() === 'AI Overview') {
        const container = h1.closest('div[data-mcpr]') ||
                          h1.closest('div.YzCcne') ||
                          h1.closest('div#eKIzJc');
        if (container) hideElement(container);
      }
    });

    // Method 4: the "AI Overview" label
    document.querySelectorAll('div.Fzsovc').forEach(el => {
      if (el.textContent && el.textContent.trim() === 'AI Overview') {
        const container = el.closest('div[data-mcpr]') ||
                          el.closest('div.YzCcne') ||
                          el.closest('div#eKIzJc');
        if (container) hideElement(container);
      }
    });

    // Method 5: "AI Mode" text in the nav → hide its list item
    document.querySelectorAll('span.R1QWuf').forEach(span => {
      if (span.textContent && span.textContent.trim() === 'AI Mode') {
        const listItem = span.closest('div[role="listitem"]');
        if (listItem) hideElement(listItem);
      }
    });
  }

  function injectStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = STYLESHEET;
    // At document_start <head> may not exist yet; the root element does.
    (document.head || document.documentElement).appendChild(style);
  }

  function startObserver() {
    if (!active || observer) return;
    if (!document.body) {
      requestAnimationFrame(startObserver);
      return;
    }
    observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
          findAndHideAIOverview();
          return;
        }
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  function start() {
    if (active) return;
    active = true;
    injectStyle();
    findAndHideAIOverview();
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', findAndHideAIOverview);
    }
    startObserver();
    // Follow-up passes for the first few seconds (catches async loading)
    timers = [500, 1000, 2000].map(ms => setTimeout(findAndHideAIOverview, ms));
    console.log('[CLASSROOM CONTROLS] Hiding Google AI Overview');
  }

  function stop() {
    if (!active) return;
    active = false;
    timers.forEach(clearTimeout);
    timers = [];
    if (observer) {
      try { observer.disconnect(); } catch (e) {}
      observer = null;
    }
    const style = document.getElementById(STYLE_ID);
    if (style) style.remove();
    document.querySelectorAll('[' + HIDDEN_ATTR + ']').forEach(el => {
      const prev = previousStyle.get(el);
      if (prev === null || prev === undefined) el.removeAttribute('style');
      else el.setAttribute('style', prev);
      el.removeAttribute(HIDDEN_ATTR);
    });
  }

  // OFF unless the admin explicitly sets the flag to true.
  function applyConfig(classroomControls) {
    if (classroomControls && classroomControls[FLAG] === true) start();
    else stop();
  }

  try {
    chrome.runtime.sendMessage({ type: 'GET_CONFIG' }, (response) => {
      if (chrome.runtime.lastError || !response) return;
      applyConfig(response.classroomControls);
    });
  } catch (e) {
    // Extension context may not be available yet
  }

  // Only accept config pushes from our own extension's service worker.
  chrome.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== chrome.runtime.id || sender.tab) return;
    if (message.type === 'CONFIG_UPDATED' && message.config) {
      applyConfig(message.config.classroomControls);
    }
  });
})();
// Maintained by TeacherMagic.org
