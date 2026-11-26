'use strict';

// Saved device names and addresses are historical presentation, never live
// membership or input to a device/service mutation. Keep this DTO out of state.devices.
const deviceBrowseRuntime = { saved: null, epoch: 0, formEpoch: 0, request: 0, invalidatedAt: 0, timer: null, showing: false, liveReadable: false, instance: null, revision: -1 };

function validSavedDeviceBrowse(value) {
  if (value?.schema !== 1 || value.dataplane !== 'not-checked'
    || !(/^[a-f0-9]{32}$/.test(value.instance_id || '') || value.state === 'empty' && value.instance_id === '' && value.revision === 0 && value.generated_at === null)
    || !Number.isSafeInteger(value.revision) || value.revision < 0
    || !['empty', 'available', 'retained', 'expired'].includes(value.state)
    || value.max_age_seconds !== 900 || !Number.isFinite(value.data_age_ms) || value.data_age_ms < 0
    || !Number.isFinite(Date.parse(value.observed_at))) return false;
  if (['empty', 'expired'].includes(value.state)) return value.data == null;
  const generated = Date.parse(value.generated_at), observed = Date.parse(value.observed_at);
  const fields = ['id', 'name', 'group', 'hostname', 'known_addresses', 'interface', 'last_seen_at'];
  return Number.isFinite(generated) && generated <= observed + 1000 && value.data_age_ms < 900000
    && Math.abs(Math.max(0, observed - generated) - value.data_age_ms) <= 1000
    && Array.isArray(value.data?.devices) && value.data.devices.length <= 512
    && JSON.stringify(value.data).length <= 262144
    && value.data.devices.every(row => row && Object.keys(row).every(key => fields.includes(key))
      && /^[a-z0-9][a-z0-9-]{2,95}$/.test(row.id || '')
      && ['name', 'group', 'hostname', 'interface'].every(key => row[key] == null || typeof row[key] === 'string' && row[key].length <= 512)
      && (row.last_seen_at == null || typeof row.last_seen_at === 'string' && Number.isFinite(Date.parse(row.last_seen_at)))
      && Array.isArray(row.known_addresses) && row.known_addresses.length <= 32768
      && row.known_addresses.every(address => typeof address === 'string' && address.length > 0 && address.length <= 128));
}

function deviceBrowseMutationAllowed() {
  return state.authenticated === true && state.dataLoad?.devices?.phase === 'ready' && !deviceBrowseRuntime.showing;
}

function deviceBrowseMutationToken() {
  return deviceBrowseMutationAllowed() ? { epoch: deviceBrowseRuntime.formEpoch, auth: state.authGeneration || 0 } : null;
}

function deviceBrowseMutationCurrent(token) {
  return token && deviceBrowseMutationAllowed() && token.epoch === deviceBrowseRuntime.formEpoch
    && token.auth === (state.authGeneration || 0);
}

function closeDeviceBrowseEditors() {
  deviceBrowseRuntime.formEpoch++;
  for (const id of ['deviceEditDialog', 'devicePolicyDialog']) {
    const dialog = $('#' + id);
    if (dialog?.open) dialog.close();
  }
  for (const id of ['deviceEditID', 'devicePolicyID', 'deviceEditName', 'deviceEditGroup']) { const field = $('#' + id); if (field) field.value = ''; }
  for (const id of ['deviceEditTitle', 'deviceEditIdentity', 'devicePolicyTitle', 'devicePolicyIdentity', 'devicePolicyWarning']) {
    const field = $('#' + id); if (field) field.textContent = '';
  }
}

function deviceBrowseSectionChanged(phase) {
  if (phase === 'loading') deviceBrowseRuntime.formEpoch++;
  else if (phase !== 'ready') { deviceBrowseRuntime.liveReadable = false; closeDeviceBrowseEditors(); }
  else { deviceBrowseRuntime.liveReadable = true; deviceBrowseRuntime.showing = false; }
  for (const id of ['deviceEditForm', 'devicePolicyForm']) {
    const submit = $('#' + id)?.querySelector?.('button[type="submit"]');
    if (submit) submit.disabled = phase !== 'ready';
  }
}

function invalidateSavedDeviceBrowse(mutation = false) {
  deviceBrowseRuntime.epoch++;
  deviceBrowseRuntime.request++;
  deviceBrowseRuntime.saved = null;
  deviceBrowseRuntime.invalidatedAt = mutation === true ? Date.now() : 0;
  if (mutation !== true) { deviceBrowseRuntime.instance = null; deviceBrowseRuntime.revision = -1; }
  deviceBrowseRuntime.showing = false;
  deviceBrowseRuntime.liveReadable = false;
  clearTimeout(deviceBrowseRuntime.timer);
  closeDeviceBrowseEditors();
  const notice = $('#deviceBrowseNotice');
  if (notice) { notice.hidden = true; notice.textContent = ''; }
  // A pending/uncertain write cannot leave old live cards actionable either.
  if (state.dataLoad?.devices) state.dataLoad.devices = { ...state.dataLoad.devices, phase: 'loading' };
  if (state.currentView === 'devices' && state.authenticated && typeof renderDevices === 'function') renderDevices();
}

async function loadSavedDeviceBrowse(generation, options = {}) {
  if (!state.authenticated) return;
  const ticket = ++deviceBrowseRuntime.request, epoch = deviceBrowseRuntime.epoch, auth = state.authGeneration || 0;
  const started = Date.now();
  const current = () => ticket === deviceBrowseRuntime.request && epoch === deviceBrowseRuntime.epoch
    && auth === (state.authGeneration || 0) && state.authenticated && panelSnapshotCurrent(generation);
  try {
    const value = await api('/api/v1/panel/devices', { ...options, readTimeoutMs: 3000 });
    if (!current() || !validSavedDeviceBrowse(value)) return;
    if (deviceBrowseRuntime.instance === value.instance_id && deviceBrowseRuntime.revision > value.revision) return;
    if (deviceBrowseRuntime.instance && deviceBrowseRuntime.instance !== value.instance_id) closeDeviceBrowseEditors();
    // Do not resurrect a pre-mutation publication after the write settled.
    if (started - value.data_age_ms < deviceBrowseRuntime.invalidatedAt) return;
    deviceBrowseRuntime.instance = value.instance_id;
    deviceBrowseRuntime.revision = value.revision;
    deviceBrowseRuntime.saved = { value, receivedAt: Date.now() };
    if (state.currentView === 'devices') renderDevices();
  } catch (error) {
    if (!current()) return;
    if (error.status === 401 || error.status === 403) {
      invalidateSavedDeviceBrowse();
      cancelPanelRefresh();
      showAuth({ authenticated: false }, 'Сессия завершилась. Войдите снова.');
    }
    // Timeout, mixed server version and malformed responses grant no live state.
  }
}

function renderSavedDeviceBrowse() {
  const notice = $('#deviceBrowseNotice');
  clearTimeout(deviceBrowseRuntime.timer);
  const phase = state.dataLoad?.devices?.phase;
  if (state.authenticated && (phase === 'ready' || phase === 'loading' && deviceBrowseRuntime.liveReadable)) {
    if (phase === 'ready') deviceBrowseRuntime.liveReadable = true;
    deviceBrowseRuntime.showing = false;
    if (notice) {
      notice.hidden = phase === 'ready';
      notice.textContent = phase === 'loading' ? 'Обновляем список устройств. Изменения временно недоступны.' : '';
    }
    return false;
  }
  if (!deviceBrowseRuntime.showing) closeDeviceBrowseEditors();
  deviceBrowseRuntime.showing = true;
  const saved = deviceBrowseRuntime.saved, value = saved?.value;
  const elapsed = saved ? Date.now() - saved.receivedAt : -1;
  const age = value && elapsed >= 0 ? value.data_age_ms + elapsed : Infinity;
  const usable = state.authenticated && value?.data && ['available', 'retained'].includes(value.state) && age < 900000;
  if (saved && !usable) deviceBrowseRuntime.saved = null;
  const query = ($('#deviceSearch')?.value || '').trim().toLowerCase();
  const rows = usable ? value.data.devices.filter(row => [row.name, row.hostname, row.group, row.interface, ...row.known_addresses].join(' ').toLowerCase().includes(query)) : [];
  if (notice) {
    notice.hidden = !state.authenticated;
    notice.textContent = usable
      ? `Снимок сохранённых данных · создан ${Math.floor(age / 1000)} сек назад. Только просмотр. Адреса относятся к прошлым данным; подключение сейчас не проверено.`
      : 'Свежие данные об устройствах пока недоступны. Это не означает, что устройства удалены. Поиск можно повторить.';
  }
  const warning = $('#devicePersistenceWarning');
  if (warning) { warning.hidden = true; warning.textContent = ''; }
  $('#deviceGrid').innerHTML = rows.map(row => `<article class="device-card device-saved-card">
    <div class="device-card-head"><div><h3>${esc(row.name || row.hostname || row.id)}</h3><p>${esc(row.hostname || '')}</p></div><span class="device-state">СОХРАНЕНО</span></div>
    <p>Известные ранее адреса</p><div class="device-addresses">${deviceAddressesHTML(row.known_addresses)}</div>
    <div class="device-meta"><span>Интерфейс <b>${esc(row.interface || '—')}</b></span><span>Группа <b>${esc(row.group || 'без группы')}</b></span></div>
    <p>Последнее обнаружение (из сохранённых данных): ${row.last_seen_at ? esc(new Date(row.last_seen_at).toLocaleString('ru-RU')) : 'время неизвестно'}. Текущее подключение не проверено.</p>
  </article>`).join('');
  const empty = $('#deviceEmpty');
  empty.style.display = rows.length ? 'none' : 'grid';
  const title = empty.querySelector?.('strong'), text = empty.querySelector?.('span');
  if (title) title.textContent = usable && query ? 'Ничего не найдено в сохранённых данных' : 'Список устройств ещё не обновлён';
  if (text) text.textContent = usable && query ? 'Попробуйте другое имя или известный ранее адрес.' : 'Сохранённый список сейчас недоступен. Нажмите «Найти заново» чуть позже.';
  $('#deviceGroupSuggestions').innerHTML = '';
  if (usable && state.currentView === 'devices' && !document.hidden) deviceBrowseRuntime.timer = setTimeout(renderDevices, Math.min(1000, 900000 - age));
  return true;
}

document.addEventListener('razvilka:auth-required', invalidateSavedDeviceBrowse);
document.addEventListener('visibilitychange', () => {
  if (state.currentView === 'devices' && typeof renderDevices === 'function') renderDevices();
});
document.addEventListener('razvilka:view-change', event => {
  clearTimeout(deviceBrowseRuntime.timer);
  if (event.detail !== 'devices') closeDeviceBrowseEditors();
});
