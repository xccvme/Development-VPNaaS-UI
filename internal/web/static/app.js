// VPNaaS console helpers: CSRF header for HTMX, modal close, sidebar, toasts.
// Dynamic text is only ever assigned via textContent.
(function () {
  'use strict';
  const meta = document.querySelector('meta[name="csrf-token"]');
  const toast = () => document.getElementById('toast');
  function showToast(message, ok) {
    const t = toast();
    if (!t) return;
    t.textContent = message;
    t.className = 'mb-4 rounded-lg border px-4 py-3 text-sm ' + (ok ? 'border-[#BADBCC] bg-[#E6F4EA] text-[#1E7B34]' : 'border-[#F5C2C7] bg-[#FDECEA] text-[#B3261E]');
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => { t.className = 'hidden'; }, ok ? 4000 : 10000);
  }
  function closeModal() {
    const m = document.getElementById('modal');
    if (m) m.replaceChildren();
  }
  document.addEventListener('htmx:configRequest', (e) => {
    if (meta) e.detail.headers['X-CSRF-Token'] = meta.content;
  });
  document.addEventListener('htmx:responseError', (e) => {
    const xhr = e.detail.xhr;
    let message = 'Permintaan gagal (HTTP ' + xhr.status + ')';
    try {
      const data = JSON.parse(xhr.responseText);
      if (data && typeof data.detail === 'string') message = data.detail;
    } catch (_) {
      if (xhr.responseText && xhr.responseText.length < 300 && !/</.test(xhr.responseText)) message = xhr.responseText.trim();
    }
    showToast(message, false);
  });
  document.addEventListener('htmx:sendError', () => showToast('Server dashboard tidak dapat dihubungi.', false));
  document.body.addEventListener('vpnaas:close', () => setTimeout(closeModal, 0));
  document.body.addEventListener('vpnaas:toast', (e) => showToast(String(e.detail.value || ''), true));
  document.addEventListener('click', (e) => {
    const target = e.target;
    if (!(target instanceof Element)) return;
    if (target.closest('[data-modal-close]') || target.matches('[data-modal]')) closeModal();
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('backdrop');
    if (target.closest('[data-sidebar-toggle]')) {
      sidebar.classList.toggle('-translate-x-full');
      backdrop.classList.toggle('hidden');
    } else if (target.closest('[data-sidebar-close]')) {
      sidebar.classList.add('-translate-x-full');
      backdrop.classList.add('hidden');
    }
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

  // Row action menus (/akun, /koneksi): click-only. Native popover top-layer
  // avoids clipping by the horizontally scrolling table. Closes on outside
  // click, Escape, item selection, scroll/resize and HTMX swaps.
  let actions = null;
  function menuOf(root) { return root.querySelector('[role="menu"]'); }
  function closeActions(restore) {
    if (!actions) return;
    const root = actions, button = root.querySelector('[data-actions-toggle]'), menu = menuOf(root);
    actions = null;
    button.setAttribute('aria-expanded', 'false');
    if (menu.matches(':popover-open')) menu.hidePopover();
    if (restore && button.isConnected) button.focus();
  }
  function positionActions() {
    if (!actions || !actions.isConnected) { closeActions(false); return; }
    const button = actions.querySelector('[data-actions-toggle]'), menu = menuOf(actions);
    const r = button.getBoundingClientRect(), w = menu.offsetWidth, h = menu.offsetHeight;
    menu.style.left = Math.max(8, Math.min(r.right - w, window.innerWidth - w - 8)) + 'px';
    const below = r.bottom + 2;
    menu.style.top = Math.max(8, below + h <= window.innerHeight - 8 ? below : r.top - h - 2) + 'px';
  }
  function openActions(root, focusFirst) {
    closeActions(false);
    actions = root;
    const button = root.querySelector('[data-actions-toggle]'), menu = menuOf(root);
    if (!menu.matches(':popover-open')) menu.showPopover();
    button.setAttribute('aria-expanded', 'true');
    positionActions();
    if (focusFirst) { const first = menu.querySelector('[role="menuitem"]'); if (first) first.focus(); }
  }
  document.addEventListener('click', (e) => {
    if (!(e.target instanceof Element)) return;
    const toggle = e.target.closest('[data-actions-toggle]');
    if (toggle) {
      const root = toggle.closest('[data-row-actions]');
      if (actions === root) closeActions(false); else openActions(root, e.detail === 0);
      return;
    }
    if (!actions) return;
    if (!actions.contains(e.target) || e.target.closest('[role="menuitem"]')) closeActions(false);
  });
  document.addEventListener('keydown', (e) => {
    if (!actions) return;
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeActions(true); return; }
    if (e.key === 'Tab') { closeActions(false); return; }
    const items = Array.from(menuOf(actions).querySelectorAll('[role="menuitem"]'));
    const index = items.indexOf(document.activeElement);
    if (['ArrowDown','ArrowUp','Home','End'].includes(e.key)) {
      e.preventDefault();
      const next = e.key === 'Home' ? 0 : e.key === 'End' ? items.length - 1 : (index + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length;
      items[next].focus();
    }
  }, true);
  window.addEventListener('resize', () => closeActions(false));
  document.addEventListener('scroll', (e) => { if (!actions || !menuOf(actions).contains(e.target)) closeActions(false); }, true);
  document.addEventListener('htmx:beforeSwap', () => closeActions(false));

  // Pause hx-trigger="every 30s" table polling while the tab is hidden; polls
  // carry no triggering event, user actions (Muat ulang, search) always do.
  // On return, refresh once so the table is not stale.
  document.addEventListener('htmx:beforeRequest', (e) => {
    if (document.visibilityState === 'hidden' && !(e.detail.requestConfig && e.detail.requestConfig.triggeringEvent)) e.preventDefault();
  });
  let hiddenSince = 0;
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') { hiddenSince = Date.now(); return; }
    if (hiddenSince && Date.now() - hiddenSince > 30000 && window.htmx && !document.querySelector('#modal > *')) htmx.trigger(document.body, 'vpnaas:changed');
    hiddenSince = 0;
  });
})();
