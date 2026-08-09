function isUsableTab(tabEl) {
  return tabEl && !tabEl.disabled && tabEl.getAttribute('aria-disabled') !== 'true';
}

export function initRovingTablist({ tabIds, panelByTabId, onActivate = null }) {
  const orderedTabs = tabIds
    .map((tabId) => document.getElementById(tabId))
    .filter(isUsableTab);

  if (orderedTabs.length === 0) return null;

  const orderedTabIds = orderedTabs.map((tabEl) => tabEl.id);

  function resolvePanels(panelRef) {
    const refs = Array.isArray(panelRef) ? panelRef : [panelRef];
    return refs
      .map((ref) => (typeof ref === 'string' ? document.getElementById(ref) : ref))
      .filter(Boolean);
  }

  function activateTab(tabId, { focus = false } = {}) {
    const requestedTab = document.getElementById(tabId);
    if (!orderedTabIds.includes(tabId) || !isUsableTab(requestedTab)) return;

    orderedTabIds.forEach((currentTabId) => {
      const tabEl = document.getElementById(currentTabId);
      const panelEls = resolvePanels(panelByTabId[currentTabId]);
      const active = currentTabId === tabId;

      if (tabEl) {
        tabEl.classList.toggle('active', active);
        tabEl.setAttribute('aria-selected', String(active));
        tabEl.tabIndex = active ? 0 : -1;
        if (active && focus) tabEl.focus({ preventScroll: true });
      }

      for (const panelEl of panelEls) {
        panelEl.classList.toggle('active', active);
        panelEl.hidden = !active;
        panelEl.style.display = active ? 'block' : 'none';
      }
    });

    if (typeof onActivate === 'function') onActivate(tabId);
  }

  function activateByOffset(currentTabId, offset) {
    const currentIndex = orderedTabIds.indexOf(currentTabId);
    if (currentIndex < 0) return;
    for (let distance = 1; distance <= orderedTabIds.length; distance += 1) {
      const nextIndex = (
        currentIndex + (offset * distance) + (orderedTabIds.length * distance)
      ) % orderedTabIds.length;
      const nextTabId = orderedTabIds[nextIndex];
      if (isUsableTab(document.getElementById(nextTabId))) {
        activateTab(nextTabId, { focus: true });
        return;
      }
    }
  }

  function activateBoundaryTab(fromEnd) {
    const candidates = fromEnd ? [...orderedTabIds].reverse() : orderedTabIds;
    const target = candidates.find((tabId) => isUsableTab(document.getElementById(tabId)));
    if (target) activateTab(target, { focus: true });
  }

  orderedTabIds.forEach((tabId) => {
    const tabEl = document.getElementById(tabId);
    if (!tabEl) return;

    tabEl.addEventListener('click', () => {
      activateTab(tabId);
    });

    tabEl.addEventListener('keydown', (event) => {
      if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
        event.preventDefault();
        activateByOffset(tabId, 1);
      } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
        event.preventDefault();
        activateByOffset(tabId, -1);
      } else if (event.key === 'Home') {
        event.preventDefault();
        activateBoundaryTab(false);
      } else if (event.key === 'End') {
        event.preventDefault();
        activateBoundaryTab(true);
      } else if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        activateTab(tabId, { focus: true });
      }
    });
  });

  const initiallySelected = orderedTabIds.find((tabId) => {
    const tabEl = document.getElementById(tabId);
    return tabEl?.getAttribute('aria-selected') === 'true' || tabEl?.classList.contains('active');
  }) || orderedTabIds[0];

  activateTab(initiallySelected);

  return { activateTab };
}
