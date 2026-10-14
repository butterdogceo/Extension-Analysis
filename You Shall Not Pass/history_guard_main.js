// You Shall Not Pass - Enterprise Hardened v3.3.0
// History Guard (MAIN world)
// Maintained by TeacherMagic.org
//
// The Point-Blank history-flood defense has to wrap the pushState/replaceState
// that PAGE scripts call. Content scripts run in an isolated world with their
// own JS wrappers for DOM objects, so the wrap content_guard.js installed
// before 3.2.3 was only ever visible to content_guard.js itself — page code
// kept calling the native functions. This file is registered with
// "world": "MAIN" so the wrap lands in the page's own world.
//
// MAIN-world scripts have no chrome.* APIs and share their world with the
// (hostile) page, so this file is deliberately tiny:
//   - it only counts calls and refuses them past the threshold;
//   - config (enabled / threshold) is pushed in by content_guard.js over a
//     nonce-authenticated CustomEvent channel (see below);
//   - the block notice is rendered by content_guard.js in the isolated world,
//     where the page cannot tamper with the DOM constructors we use.
//
// Known limit (consistent with README "Threat model"): a page can still obtain
// a pristine History.prototype from a freshly created same-origin iframe
// before our script is injected into it. This raises the bar; it is not a wall.

(function() {
  'use strict';

  const EVT_READY = '__ysnp_hg_ready';
  const EVT_CONFIG = '__ysnp_hg_config';
  const EVT_FLOOD = '__ysnp_hg_flood';

  // Capture natives now, at document_start, before any page script can
  // replace them.
  const NativeCustomEvent = window.CustomEvent;
  const dispatch = window.dispatchEvent.bind(window);
  const now = Date.now.bind(Date);
  const parse = JSON.parse;

  let enabled = true;
  let maxPerSecond = 50;
  let nonce = null;

  let count = 0;
  let lastReset = now();
  let tripped = false;

  // Config channel. content_guard.js picks a random nonce and sends it with the
  // first config message, which is delivered synchronously during
  // document_start injection — before any page script exists. Later messages
  // must carry the same nonce. This listener is the first one registered on
  // window (capture), and it stops propagation, so page listeners never see
  // the nonce and cannot forge a "disable" message.
  window.addEventListener(EVT_CONFIG, (event) => {
    event.stopImmediatePropagation();
    let msg;
    try { msg = parse(event.detail); } catch (e) { return; }
    if (!msg || typeof msg.nonce !== 'string' || !msg.nonce) return;
    if (nonce === null) {
      nonce = msg.nonce;
    } else if (msg.nonce !== nonce) {
      return;
    }
    enabled = msg.enabled !== false;
    if (typeof msg.max === 'number' && msg.max > 0) maxPerSecond = msg.max;
  }, true);

  function allow() {
    if (!enabled) return true;
    if (tripped) return false;

    const t = now();
    if (t - lastReset > 1000) {
      count = 0;
      lastReset = t;
    }
    count++;

    if (count > maxPerSecond) {
      tripped = true; // latch: the page is about to be replaced
      try { dispatch(new NativeCustomEvent(EVT_FLOOD, { detail: String(count) })); } catch (e) {}
      return false;
    }
    return true;
  }

  // Wrap on the prototype (not the instance) so
  // History.prototype.pushState.call(history, …) is covered too.
  function wrap(name) {
    const original = History.prototype[name];
    if (typeof original !== 'function') return;
    const wrapped = function(...args) {
      if (!allow()) return;
      return original.apply(this, args);
    };
    try {
      Object.defineProperty(History.prototype, name, {
        value: wrapped,
        writable: true,
        configurable: true
      });
    } catch (e) {}
  }

  wrap('pushState');
  wrap('replaceState');

  // If content_guard.js was injected before us, it missed nothing yet — ask it
  // to send config now. (If it runs after us, it sends unprompted.)
  try { dispatch(new NativeCustomEvent(EVT_READY)); } catch (e) {}
})();
// Maintained by TeacherMagic.org
