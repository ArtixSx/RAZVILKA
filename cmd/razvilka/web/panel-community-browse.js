'use strict';

// Historical display definitions never enter state.community or its previews.
const communityBrowse = { saved: null, live: false, showing: false, loading: false, epoch: 0, request: 0, action: 0, invalidatedAt: 0, instance: '', revision: -1, timer: null };

function validSavedCommunityBrowse(value) {
  if (value?.schema !== 1 || value.dataplane !== 'not-checked' || value.max_age_seconds !== 900
    || !Number.isSafeInteger(value.revision) || value.revision < 0
    || !Number.isFinite(value.data_age_ms) || value.data_age_ms < 0
    || typeof value.observed_at !== 'string' || !Number.isFinite(Date.parse(value.observed_at))
    || !['empty', 'available', 'retained', 'expired'].includes(value.state)
    || typeof value.instance_id !== 'string'
    || !(/^[a-f0-9]{32}$/.test(value.instance_id) || value.state === 'empty' && value.instance_id === '' && value.revision === 0 && value.generated_at === null)) return false;
  if (['empty', 'expired'].includes(value.state)) return value.data == null;
  const generated = Date.parse(value.generated_at), observed = Date.parse(value.observed_at);
  return typeof value.generated_at === 'string' && Number.isFinite(generated) && generated <= observed + 1000 && value.data_age_ms < 900000
    && Math.abs(Math.max(0, observed - generated) - value.data_age_ms) <= 1000
    && Array.isArray(value.data?.entries) && value.data.entries.length <= 1128 && JSON.stringify(value.data).length <= 262144
    && value.data.entries.every(entry => entry && Object.keys(entry).every(key => ['id', 'name', 'category', 'description'].includes(key))
      && typeof entry.id === 'string' && /^[a-z0-9][a-z0-9-]{0,63}$/.test(entry.id)
      && typeof entry.name === 'string' && entry.name.length > 0 && entry.name.length <= 512
      && typeof entry.category === 'string' && entry.category.length <= 256
      && typeof entry.description === 'string' && entry.description.length <= 4096);
}

function communityBrowseActionsAllowed() {
  return state.authenticated && communityBrowse.live && !communityBrowse.showing && $('#communityCatalogDialog').open;
}

function communityBrowseActionToken() { return { action: communityBrowse.action, auth: state.authGeneration || 0 }; }
function communityBrowseActionCurrent(token) {
  return token && communityBrowseActionsAllowed() && token.action === communityBrowse.action && token.auth === (state.authGeneration || 0);
}

function communityBrowseSetControls(readOnly) {
  const form = $('#communityOwnForm');
  if (form) {
    form.hidden = readOnly;
    const section = form.closest?.('details');
    if (section) section.hidden = readOnly;
  }
  for (const button of document.querySelectorAll('[data-community-import],[data-community-refresh]')) button.disabled = readOnly;
  const refresh = $('#communityBrowseRefresh');
  refresh.disabled = communityBrowse.loading;
  refresh.textContent = communityBrowse.loading ? 'Читаем каталог…' : 'Повторить чтение каталога';
}

function communityBrowseSearchStarted() {
  communityBrowse.action++;
  communityBrowse.live = false;
  communityBrowse.loading = true;
  communityBrowseSetControls(true);
  if (communityBrowse.showing) renderSavedCommunityBrowse();
}

function communityBrowseLiveAccepted() {
  const wasShowingSaved = communityBrowse.showing;
  communityBrowse.live = true;
  communityBrowse.loading = false;
  communityBrowse.showing = false;
  clearTimeout(communityBrowse.timer);
  communityBrowseSetControls(false);
  $('#communityBrowseNotice').hidden = true;
  $('#communityBrowseRefresh').hidden = true;
  // Only replace the empty historical placeholder. A selected preview belongs
  // to its existing request/action generation and must survive list refreshes.
  if (wasShowingSaved && !state.communityPreview) $('#communityPreview').innerHTML = '<div class="community-empty">Выберите сервис. Загрузим его домены и покажем изменения до импорта.</div>';
}

function invalidateSavedCommunityBrowse(mutation = false) {
  communityBrowse.epoch++;
  communityBrowse.request++;
  communityBrowse.saved = null;
  communityBrowse.invalidatedAt = mutation === true ? Date.now() : 0;
  clearTimeout(communityBrowse.timer);
  if (mutation !== true) {
    communityBrowse.instance = ''; communityBrowse.revision = -1;
    communityBrowse.live = false; communityBrowse.showing = false; communityBrowse.loading = false; communityBrowse.action++;
    state.community = []; state.communityPreview = null;
    for (const id of ['communityResults', 'communityPreview', 'communityBrowseNotice']) { const element = $('#' + id); if (element) element.textContent = ''; }
    $('#communityBrowseNotice').hidden = true;
    $('#communityBrowseRefresh').hidden = true;
  } else if (communityBrowse.showing) renderSavedCommunityBrowse();
}

async function loadSavedCommunityBrowse(seq, epoch) {
  const ticket = ++communityBrowse.request, savedEpoch = communityBrowse.epoch, auth = state.authGeneration || 0, started = Date.now();
  const current = () => ticket === communityBrowse.request && savedEpoch === communityBrowse.epoch && auth === (state.authGeneration || 0)
    && workflowSession(epoch) && seq === workflowState.communitySeq && $('#communityCatalogDialog').open;
  try {
    const value = await api('/api/v1/panel/community', { readTimeoutMs: 3000 });
    if (!current() || !validSavedCommunityBrowse(value)) return;
    if (communityBrowse.instance === value.instance_id && communityBrowse.revision > value.revision) return;
    if (started - value.data_age_ms < communityBrowse.invalidatedAt) return;
    if (communityBrowse.instance && communityBrowse.instance !== value.instance_id) {
      communityBrowse.action++; state.communityPreview = null;
      $('#communityPreview').textContent = 'Приложение перезапущено. Откройте новый предпросмотр перед импортом.';
      if (typeof cancelCustomSource === 'function') cancelCustomSource();
    }
    communityBrowse.instance = value.instance_id; communityBrowse.revision = value.revision;
    communityBrowse.saved = { value, receivedAt: Date.now() };
    if (!communityBrowse.live) renderSavedCommunityBrowse();
  } catch (error) {
    if (!current()) return;
    if (error.status === 401 || error.status === 403) showAuth({ authenticated: false }, 'Сессия завершилась. Войдите снова.');
  }
}

function renderSavedCommunityBrowse() {
  if (communityBrowse.live || !$('#communityCatalogDialog').open || !state.authenticated) return false;
  clearTimeout(communityBrowse.timer);
  if (!communityBrowse.showing) {
    communityBrowse.showing = true; communityBrowse.action++;
    state.communityPreview = null;
    if (typeof cancelCustomSource === 'function') cancelCustomSource();
  }
  communityBrowseSetControls(true);
  $('#communityPreview').textContent = communityBrowse.loading
    ? 'Сохранённые определения доступны для просмотра, пока читаем актуальный каталог. После загрузки можно будет открыть состав доменов и предпросмотр импорта.'
    : 'Сохранённые определения доступны только для просмотра. Состав доменов, предпросмотр и импорт требуют нового чтения каталога.';
  const saved = communityBrowse.saved, value = saved?.value, elapsed = saved ? Date.now() - saved.receivedAt : -1;
  const age = value && elapsed >= 0 ? value.data_age_ms + elapsed : Infinity;
  const usable = value?.data && ['available', 'retained'].includes(value.state) && age < 900000;
  if (saved && !usable) communityBrowse.saved = null;
  const query = $('#communitySearch').value.trim().toLowerCase();
  const entries = usable ? value.data.entries.filter(entry => [entry.id, entry.name, entry.category, entry.description].join(' ').toLowerCase().includes(query)) : [];
  const notice = $('#communityBrowseNotice'); notice.hidden = false;
  notice.textContent = usable
    ? `Снимок каталога в памяти · создан ${Math.floor(age / 1000)} сек назад. Это время снимка, а не обновления источника. ${communityBrowse.loading ? 'Читаем актуальный каталог… Пока доступен только просмотр снимка; импорт появится после загрузки.' : 'Только просмотр; доступность сервисов не проверена.'}`
    : `Сохранённый каталог сейчас недоступен или устарел. Это не означает, что определения удалены. ${communityBrowse.loading ? 'Читаем актуальный каталог…' : 'Повторите чтение позже.'}`;
  $('#communityBrowseRefresh').hidden = false;
  $('#communityResults').innerHTML = entries.map(entry => `<article class="community-result community-saved-entry"><div><b>${esc(entry.name)}</b><small>${esc(entry.category)}</small><p>${esc(entry.description)}</p></div></article>`).join('')
    || `<div class="community-empty">${usable ? 'Ничего не найдено в сохранённых определениях.' : 'Снимок каталога пока недоступен.'}</div>`;
  if (usable && !document.hidden) communityBrowse.timer = setTimeout(renderSavedCommunityBrowse, Math.min(1000, 900000 - age));
  return true;
}

function communityBrowseUnavailable(error) {
  communityBrowse.loading = false;
  if (error.status === 401 || error.status === 403) { showAuth({ authenticated: false }, 'Сессия завершилась. Войдите снова.'); return true; }
  communityBrowse.live = false;
  return renderSavedCommunityBrowse();
}

document.addEventListener('submit', event => {
  if (event.target?.id === 'communityOwnForm' && !communityBrowseActionsAllowed()) { event.preventDefault(); event.stopImmediatePropagation(); }
}, true);
document.addEventListener('click', event => {
  if (event.target?.id === 'communityBrowseRefresh') void searchCommunityCatalog(true);
});
document.addEventListener('razvilka:auth-required', invalidateSavedCommunityBrowse);
document.addEventListener('visibilitychange', () => {
  if (communityBrowse.showing && $('#communityCatalogDialog').open) renderSavedCommunityBrowse();
});
