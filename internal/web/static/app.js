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

  // Native popover top-layer avoids clipping by the horizontally scrolling table.
  let actions = null, pinned = false, closeTimer = null, suppressFocus = false;
  function menuOf(root) { return root.querySelector('[role="menu"]'); }
  function closeActions(restore) {
    clearTimeout(closeTimer);
    if (!actions) return;
    const root = actions, button = root.querySelector('[data-actions-toggle]'), menu = menuOf(root);
    actions = null; pinned = false;
    button.setAttribute('aria-expanded', 'false');
    if (menu.matches(':popover-open')) menu.hidePopover();
    if (restore) { suppressFocus = true; button.focus(); suppressFocus = false; }
  }
  function positionActions() {
    if (!actions || !actions.isConnected) { closeActions(false); return; }
    const button = actions.querySelector('[data-actions-toggle]'), menu = menuOf(actions);
    const r = button.getBoundingClientRect(), w = menu.offsetWidth, h = menu.offsetHeight;
    menu.style.left = Math.max(8, Math.min(r.right - w, window.innerWidth - w - 8)) + 'px';
    const below = r.bottom + 2;
    menu.style.top = Math.max(8, below + h <= window.innerHeight - 8 ? below : r.top - h - 2) + 'px';
  }
  function openActions(root) {
    clearTimeout(closeTimer);
    if (actions !== root) { closeActions(false); actions = root; }
    const button = root.querySelector('[data-actions-toggle]'), menu = menuOf(root);
    if (!menu.matches(':popover-open')) menu.showPopover();
    button.setAttribute('aria-expanded', 'true');
    positionActions();
  }
  document.addEventListener('pointerover', (e) => {
    if (e.pointerType !== 'mouse') return;
    const root = e.target.closest('[data-account-actions]');
    if (root) openActions(root);
  });
  document.addEventListener('pointerout', (e) => {
    const root = e.target.closest('[data-account-actions]');
    if (root && !root.contains(e.relatedTarget) && !pinned && !root.contains(document.activeElement)) {
      closeTimer = setTimeout(() => closeActions(false), 180);
    }
  });
  document.addEventListener('focusin', (e) => {
    const root = e.target.closest('[data-account-actions]');
    if (root && !suppressFocus) openActions(root);
    else if (!root) closeActions(false);
  });
  document.addEventListener('click', (e) => {
    const root = e.target.closest('[data-account-actions]');
    if (e.target.closest('[data-actions-toggle]')) {
      if (actions === root && pinned) closeActions(false);
      else { openActions(root); pinned = true; }
    } else if (!root || e.target.closest('[role="menuitem"]')) closeActions(false);
  });
  document.addEventListener('keydown', (e) => {
    if (!actions) return;
    if (e.key === 'Escape') { e.preventDefault(); closeActions(true); return; }
    const items = Array.from(menuOf(actions).querySelectorAll('[role="menuitem"]'));
    const index = items.indexOf(document.activeElement);
    if (['ArrowDown','ArrowUp','Home','End'].includes(e.key)) {
      e.preventDefault(); pinned = true;
      const next = e.key === 'Home' ? 0 : e.key === 'End' ? items.length - 1 : (index + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length;
      items[next].focus();
    }
  });
  // Scrolling / resizing closes the menu rather than leaving it detached from its row.
  window.addEventListener('resize', () => closeActions(false));
  document.addEventListener('scroll', () => closeActions(false), true);
  document.addEventListener('htmx:beforeSwap', () => closeActions(false));
})();
