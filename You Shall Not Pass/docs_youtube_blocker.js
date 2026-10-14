// You Shall Not Pass - Enterprise Hardened v3.3.0
// Classroom Controls
// Block YouTube previews in Google Docs / Sheets / Slides (optional, OFF by default)
// Maintained by TeacherMagic.org
//
// Ported from the standalone "Block YouTube Previews in Google Docs/Sheets/
// Slides" extension. Students use the YouTube preview popup, link-preview
// hover card, smart chip and embedded player inside Docs editors to watch
// video past the filter. Two layers, both controlled by
// classroomControls.blockYouTubeInDocs in managed config:
//   1. background.js adds a dynamic DNR rule that blocks YouTube requests
//      initiated by docs.google.com (player frame, stream, thumbnails).
//   2. This content script removes the leftover preview UI so there is
//      nothing left to click.
// Browsing youtube.com directly is not affected. Does nothing unless the flag
// is true; the stylesheet is injected here (not declared in the manifest) so
// "off" means no page is touched at all.

(function() {
  'use strict';

  const FLAG = 'blockYouTubeInDocs';
  const STYLE_ID = 'ysnp-docs-youtube-block';
  const BLOCKED_ATTR = 'data-ysnp-yt-blocked';
  const NOTICE_CLASS = 'ysnp-yt-blocked-notice';

  const STYLESHEET =
    '.' + NOTICE_CLASS + ' {\n' +
    '  display: inline-flex;\n  align-items: center;\n  gap: 6px;\n  padding: 6px 10px;\n  margin: 2px;\n' +
    '  font: 12px/1.4 "Google Sans", Roboto, Arial, sans-serif;\n  color: #b00020;\n  background: #fdecea;\n' +
    '  border: 1px solid #f5c6cb;\n  border-radius: 6px;\n  vertical-align: middle;\n  user-select: none;\n}\n' +
    // Hide any YouTube iframe that slips past the script before it can be
    // replaced, so a video can never flash on screen.
    'iframe[src*="youtube.com"],\niframe[src*="youtu.be"],\niframe[src*="youtube-nocookie.com"],\niframe[src*="ytimg.com"] {\n' +
    '  display: none !important;\n}\n';

  // Hostnames that mark an element as YouTube-related.
  const YT_HOSTS = [
    'youtube.com',
    'youtu.be',
    'youtube-nocookie.com',
    'ytimg.com',
    'googlevideo.com'
  ];

  let active = false;
  let observer = null;

  function isYouTubeUrl(url) {
    if (!url) return false;
    url = String(url).toLowerCase();
    for (let i = 0; i < YT_HOSTS.length; i++) {
      if (url.indexOf(YT_HOSTS[i]) !== -1) return true;
    }
    return false;
  }

  // Replace a blocked node with a small inline notice instead of leaving a
  // blank hole, so the user understands the block is intentional.
  function makeNotice() {
    const note = document.createElement('div');
    note.className = NOTICE_CLASS;
    note.textContent = '🚫 YouTube video blocked';
    note.setAttribute(BLOCKED_ATTR, '1');
    return note;
  }

  function replaceWithNotice(el) {
    if (!el || el.getAttribute(BLOCKED_ATTR) === '1') return;
    if (!el.parentNode) {
      el.remove();
      return;
    }
    try {
      el.parentNode.replaceChild(makeNotice(), el);
    } catch (e) {
      el.remove();
    }
  }

  // Walk up to a likely popup / hover-card / preview container so we hide the
  // entire card rather than a single child element.
  function closestPopup(el) {
    let depth = 0;
    let node = el;
    while (node && node !== document.body && depth < 8) {
      const role = (node.getAttribute && node.getAttribute('role')) || '';
      let cls = (node.className && node.className.baseVal) // svg-safe
        ? node.className.baseVal
        : (typeof node.className === 'string' ? node.className : '');
      cls = cls.toLowerCase();
      if (
        role === 'dialog' ||
        role === 'tooltip' ||
        cls.indexOf('linkpreview') !== -1 ||
        cls.indexOf('link-preview') !== -1 ||
        cls.indexOf('preview') !== -1 ||
        cls.indexOf('hovercard') !== -1 ||
        cls.indexOf('smart-chip') !== -1 ||
        cls.indexOf('smartchip') !== -1 ||
        cls.indexOf('bubble') !== -1 ||
        cls.indexOf('popup') !== -1
      ) {
        return node;
      }
      node = node.parentElement;
      depth++;
    }
    return null;
  }

  function hideCard(card) {
    card.setAttribute(BLOCKED_ATTR, '1');
    card.style.setProperty('display', 'none', 'important');
  }

  // 1. <iframe> embeds (Slides "Insert video", Docs preview player).
  function scrubIframes(root) {
    const frames = root.querySelectorAll ? root.querySelectorAll('iframe') : [];
    for (const f of frames) {
      if (isYouTubeUrl(f.src) || isYouTubeUrl(f.getAttribute('data-src'))) {
        replaceWithNotice(f);
      }
    }
  }

  // 2. <img> thumbnails inside preview/hover cards.
  function scrubImages(root) {
    const imgs = root.querySelectorAll ? root.querySelectorAll('img') : [];
    for (const img of imgs) {
      if (isYouTubeUrl(img.src) || isYouTubeUrl(img.getAttribute('data-src'))) {
        // Hide the whole preview card the thumbnail lives in, if we can find
        // a popup-like ancestor; otherwise just remove the image.
        const card = closestPopup(img);
        if (card) hideCard(card);
        else img.remove();
      }
    }
  }

  // 3. Anything carrying a YouTube URL in an attribute (link previews, chips).
  function scrubAttributes(root) {
    const sel =
      '[href*="youtube"],[href*="youtu.be"],[data-url*="youtube"],' +
      '[data-url*="youtu.be"],[style*="ytimg"],[style*="youtube"]';
    const nodes = root.querySelectorAll ? root.querySelectorAll(sel) : [];
    for (const n of nodes) {
      const href = n.getAttribute('href') || n.getAttribute('data-url') || '';
      const style = n.getAttribute('style') || '';
      if (isYouTubeUrl(href) || isYouTubeUrl(style)) {
        const card = closestPopup(n);
        if (card) hideCard(card);
      }
    }
  }

  function scrub(root) {
    if (!active || !root) return;
    scrubIframes(root);
    scrubImages(root);
    scrubAttributes(root);
  }

  function injectStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = STYLESHEET;
    // At document_start <head> may not exist yet; the root element does.
    (document.head || document.documentElement).appendChild(style);
  }

  function start() {
    if (active) return;
    active = true;
    injectStyle();
    scrub(document);
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => scrub(document));
    }

    observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (node.nodeType === 1) {
            // Element node: scrub it and its subtree, then its parent in case
            // the added node itself is a target.
            scrub(node);
            scrub(node.parentNode || document);
          }
        }
        // Attribute changes can swap a placeholder src into a YouTube URL.
        if (m.type === 'attributes' && m.target && m.target.nodeType === 1) {
          scrub(m.target.parentNode || document);
        }
      }
    });
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['src', 'data-src', 'href', 'data-url', 'style']
    });
    console.log('[CLASSROOM CONTROLS] Blocking YouTube previews in Google Docs/Sheets/Slides');
  }

  // Turning the flag off stops further blocking. Previews already removed in
  // this tab stay removed until the page is reloaded.
  function stop() {
    if (!active) return;
    active = false;
    if (observer) {
      try { observer.disconnect(); } catch (e) {}
      observer = null;
    }
    const style = document.getElementById(STYLE_ID);
    if (style) style.remove();
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
