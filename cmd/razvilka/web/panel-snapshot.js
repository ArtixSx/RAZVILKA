'use strict';

// This fallback contains saved choices, never a route recommendation or proof.
function validSavedPanel(value) {
  return value?.schema === 1 && value.dataplane === 'not-checked'
    && ['empty', 'available', 'retained', 'expired'].includes(value.state)
    && Number.isSafeInteger(value.revision) && value.revision >= 0
    && Number.isFinite(value.data_age_ms) && value.data_age_ms >= 0
    && Number.isFinite(value.max_age_seconds) && value.max_age_seconds > 0
    && value.max_age_seconds <= 900
    && (!value.data || (typeof value.instance_id === 'string' && value.instance_id.length === 32
      && Number.isSafeInteger(value.data.config?.revision)
      && Array.isArray(value.data.services) && value.data.services.length <= 512
      && value.data.services.every(s => typeof s.id === 'string' && typeof s.name === 'string'
        && typeof s.desired?.enabled === 'boolean' && typeof s.applied?.enabled === 'boolean'
        && typeof s.desired.route === 'string' && typeof s.applied.route === 'string'
        && (s.sources == null || Array.isArray(s.sources) && s.sources.every(x => typeof x === 'string'))
        && (s.applied_sources == null || Array.isArray(s.applied_sources) && s.applied_sources.every(x => typeof x === 'string')))));
}

async function loadSavedPanelSnapshot(generation, options) {
  try {
    const value = await api('/api/v1/panel/snapshot', { ...options, readTimeoutMs: 3000 });
    if (!panelSnapshotCurrent(generation) || !state.authenticated || !validSavedPanel(value)) return;
    const previous = state.savedPanel?.value;
    if (previous?.instance_id === value.instance_id && previous.revision > value.revision) return;
    state.savedPanel = { value, receivedAt: Date.now() };
    if (state.dataLoad?.metrics?.phase !== 'ready' && Number.isFinite(Date.parse(value.metrics?.timestamp))) {
      state.metrics = { ...(state.metrics || {}), latest: value.metrics };
      state.dataLoad.metrics = { loaded: true, phase: 'busy', message: 'Последнее измерение роутера' };
      try { renderMetrics(); } catch (_) { /* A chart cannot gate navigation. */ }
    }
    renderPanelLoad();
  } catch (error) {
    if (!panelSnapshotCurrent(generation)) return;
    if (error.status === 401) {
      cancelPanelRefresh();
      showAuth({ authenticated: false }, 'Сессия завершилась. Войдите снова.');
    }
    // No replacement with empty configuration after a timeout or mixed version.
  }
}

function renderSavedPanelSnapshot() {
  const saved = state.savedPanel;
  const banner = $('#panelSavedNotice');
  if (!state.authenticated || !saved) { if (banner) banner.hidden = true; return; }
  const value = saved.value;
  const age = value.data_age_ms + Math.max(0, Date.now() - saved.receivedAt);
  const usable = value.data && age < value.max_age_seconds * 1000
    && ['available', 'retained'].includes(value.state);
  const load = state.dataLoad?.services;
  const mayReplace = !load?.loaded || ['busy', 'error'].includes(load.phase);
  if (usable && mayReplace && (load?.savedRevision !== value.revision || load?.savedInstance !== value.instance_id)) {
    state.services = value.data.services.map(s => ({
      id: s.id, name: s.name, category: s.category, custom: s.custom,
      enabled: s.desired.enabled, applied_enabled: s.applied.enabled,
      route: s.desired.route, mode: s.desired.route, applied_route: s.applied.route,
      sources: s.sources || [], applied_sources: s.applied_sources || [],
      desired_state: s.desired, applied_state: s.applied,
      dirty: s.route_dirty || s.sources_dirty, route_dirty: s.route_dirty, sources_dirty: s.sources_dirty,
      evidence_level: 'none', evidence_status: 'unknown', presentation_only: true,
    }));
    state.dataLoad.services = { loaded: true, phase: 'busy', savedRevision: value.revision,
      savedInstance: value.instance_id, updatedAt: Date.parse(value.generated_at),
      message: 'Показаны сохранённые настройки. Текущее подключение ещё проверяется.' };
  } else if (!usable && (load?.savedInstance || state.services?.some(s => s.presentation_only))) {
    // An expired image is unavailable, not evidence of removed services.
    state.services = [];
    state.dataLoad.services = { loaded: false, phase: 'error', message: 'Сохранённые данные устарели. Обновите состояние.' };
  }
  const showing = !!state.dataLoad?.services?.savedInstance;
  if (banner) {
    banner.hidden = !showing && (usable || state.dataLoad?.services?.loaded === true);
    banner.textContent = showing
      ? `Сохранённые настройки · ${Math.floor(age / 1000)} сек назад. Просмотр доступен; управление вернётся после обновления состояния. Это не результат проверки подключения.`
      : !usable ? 'Свежий снимок настроек пока недоступен. Это не означает, что сервисы удалены.' : '';
  }
}

document.addEventListener('razvilka:auth-required', () => {
  state.savedPanel = null;
  state.inventoryObservation = null; state.inventoryInvalidatedAt = 0;
  state.inventoryUnsupported = false;
  if (typeof cancelPanelInventoryRefresh === 'function') cancelPanelInventoryRefresh();
  state.components = []; state.engines = []; state.engineConfigs = []; state.system = {};
  // Clear protected presentation and freshness markers before the next login.
  state.services = []; state.sources = []; state.devices = [];
  state.nodes = { available: false, nodes: [], sources: [], counts: {} };
  state.dataLoad = {};
  const banner = $('#panelSavedNotice');
  if (banner) { banner.hidden = true; banner.textContent = ''; }
  for (const id of ['ui3ServiceCatalog', 'ui3HomeServices', 'serviceList', 'ui3InspectorContent']) {
    const element = document.getElementById(id);
    if (element) element.textContent = '';
  }
});
