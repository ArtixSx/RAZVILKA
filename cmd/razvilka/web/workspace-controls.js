'use strict';

const workspaceControl = { generation: 0, busy: false, readBusy: false, pending: null, timer: null, expanded: false, authenticated: false };

function workspaceControlVisible() { return workspaceControl.authenticated && $('#authScreen').hidden && !document.hidden; }

function acceptWorkspaceControl(control) {
  if (!control || !Number.isSafeInteger(control.config_revision)) return false;
  const current = state.serviceControl;
  if (current && control.config_revision < current.config_revision) return false;
  state.serviceControl = control;
  workspaceControl.readBusy = false;
  renderWorkspaceControls();
  return true;
}

function renderWorkspaceControls() {
  const control = state.serviceControl;
  const ready = workspaceControl.authenticated && !!control && Number.isSafeInteger(control.config_revision);
  for (const [id, mode] of [['#projectModeAuto', 'auto'], ['#projectModeManual', 'manual']]) {
    const button = $(id);
    button.disabled = !ready || workspaceControl.busy || workspaceControl.readBusy;
    button.setAttribute('aria-pressed', String(ready && control.mode === mode));
  }
  const power = $('#projectPower');
  const running = ready && control.running === true;
  const canStop = ready && (running || control.can_stop === true);
  power.disabled = !ready || workspaceControl.busy || workspaceControl.readBusy || (control.runtime_state === 'unknown' && !canStop);
  power.setAttribute('aria-checked', String(canStop));
  power.classList.toggle('running', running);
  power.classList.toggle('unknown', !ready || control.runtime_state === 'unknown');
  $('#projectPowerLabel').textContent = workspaceControl.busy ? 'Выполняется…' : !ready ? 'Нет данных' : control.runtime_state === 'unknown' ? 'Нужна проверка' : running ? 'Работает' : 'Не работает';
  $('#projectPowerHint').textContent = workspaceControl.readBusy ? 'Дождитесь завершения проверки' : canStop ? 'Нажмите, чтобы остановить' : control?.resume_available ? 'Нажмите, чтобы включить' : 'Выбрать и включить сервисы';
  power.setAttribute('aria-label', canStop ? 'Остановить маршруты RAZVILKA' : 'Включить маршруты RAZVILKA');
  if (ready) $('#systemText').textContent = workspaceControl.readBusy ? 'Выполняется проверка или изменение' : control.safe_mode ? 'Применение заблокировано в настройках' : control.mode === 'manual' ? 'Подключения меняете вы' : 'Автозамена по правилам сервисов';
}

async function refreshWorkspaceControl() {
  if (!workspaceControlVisible()) return false;
  if (workspaceControl.pending) return workspaceControl.pending;
  const generation = workspaceControl.generation;
  const pending = api('/api/v1/service-control').then(control => {
    if (generation !== workspaceControl.generation || !workspaceControlVisible()) return false;
    return acceptWorkspaceControl(control);
  }).catch(error => {
    if (error.status === 409 && generation === workspaceControl.generation && workspaceControlVisible()) {
      workspaceControl.readBusy = true; renderWorkspaceControls(); return false;
    }
    throw error;
  });
  workspaceControl.pending = pending;
  try { return await pending; }
  finally { if (workspaceControl.pending === pending) workspaceControl.pending = null; }
}

function scheduleWorkspaceControl(delay = 15000) {
  clearTimeout(workspaceControl.timer);
  workspaceControl.timer = null;
  if (!workspaceControlVisible()) return;
  workspaceControl.timer = setTimeout(async () => {
    const generation = workspaceControl.generation;
    try { await refreshWorkspaceControl(); }
    catch (_) { if (generation === workspaceControl.generation) { state.serviceControl = null; renderWorkspaceControls(); } }
    finally { if (generation === workspaceControl.generation) scheduleWorkspaceControl(workspaceControl.readBusy ? 3000 : 15000); }
  }, delay);
}

async function changeWorkspaceMode(mode) {
  const control = state.serviceControl;
  if (!workspaceControlVisible() || workspaceControl.busy || workspaceControl.readBusy || !control || !['auto', 'manual'].includes(mode) || control.mode === mode) return;
  const generation = workspaceControl.generation;
  workspaceControl.busy = true; renderWorkspaceControls();
  try {
    const result = await api('/api/v1/service-control', { method: 'PUT', body: JSON.stringify({ expected_revision: control.config_revision, mode, confirm: 'SAVE_SERVICE_CONTROL' }) });
    if (generation !== workspaceControl.generation) return;
    if (!acceptWorkspaceControl(result.control || result)) await refreshWorkspaceControl();
    await refreshAfterMutation();
    if (generation !== workspaceControl.generation) return;
    showNotice('success', mode === 'auto' ? 'Автопилот включён' : 'Ручная настройка', mode === 'auto' ? 'Автоматическая замена разрешена только для настроенных сервисов и выбранного резерва. Правила доступны в карточке сервиса.' : 'Автоматическая замена отключена. Действующие подключения сохранены.');
  } catch (error) {
    if (generation === workspaceControl.generation) { showNotice('error', 'Режим не изменён', error.message); await refreshWorkspaceControl().catch(() => {}); }
  } finally { if (generation === workspaceControl.generation) { workspaceControl.busy = false; renderWorkspaceControls(); } }
}

async function toggleWorkspaceRuntime() {
  const control = state.serviceControl;
  if (!workspaceControlVisible() || workspaceControl.busy || workspaceControl.readBusy || !control || (control.runtime_state === 'unknown' && !control.can_stop)) return;
  if (!control.running && !control.can_stop && !control.resume_available) {
    setView('services');
    showNotice('review', 'Выберите сервис для подключения', 'Запустите «Автоподбор» или выберите подключение вручную, укажите устройства и нажмите «Проверить и применить».');
    return;
  }
  const generation = workspaceControl.generation;
  const action = control.running || control.can_stop ? 'stop' : 'resume';
  workspaceControl.busy = true; renderWorkspaceControls();
  try {
    const result = await api('/api/v1/service-control/runtime', { method: 'POST', body: JSON.stringify({ expected_revision: control.config_revision, action, confirm: action === 'stop' ? 'STOP_OWNED_ROUTES' : 'RESUME_OWNED_ROUTES' }) });
    if (generation !== workspaceControl.generation) return;
    if (!result.ok) throw new Error(result.error || 'Изменение не подтверждено. Обновите состояние.');
    acceptWorkspaceControl(result.control);
    await refreshAfterMutation();
    if (generation !== workspaceControl.generation) return;
    showNotice('success', action === 'stop' ? 'Маршруты RAZVILKA остановлены' : 'Маршруты RAZVILKA включены', action === 'stop' ? 'Ваши настройки сохранены. Панель остаётся доступна.' : 'Предыдущие сервисы и устройства восстановлены после проверки.');
  } catch (error) {
    if (generation === workspaceControl.generation) { showNotice('error', 'Переключение не завершено', error.message); await refreshWorkspaceControl().catch(() => {}); }
  } finally { if (generation === workspaceControl.generation) { workspaceControl.busy = false; renderWorkspaceControls(); } }
}

function engineVersionHTML(engine) {
  const component = (state.components || []).find(item => item.id === engine.id);
  const version = component?.installed_version;
  if (!engine.installed && !component?.installed) return '<span class="engine-inline-version">Не установлен</span>';
  const installed = version || 'Версия не определена';
  const update = component?.update_available && component.available_version;
  return `<span class="engine-inline-version ${update ? 'has-update' : ''}">${esc(installed)}${update ? ` <span aria-label="Доступна новая версия">→ ${esc(component.available_version)}</span>` : ''}</span>`;
}

function renderEngineUpdateAction(engine) {
  const component = (state.components || []).find(item => item.id === engine.id);
  if (!component?.update_available) return '';
  const reason = component.external_owner ? 'Установлен вне RAZVILKA. Подробности — в разделе «Установка и обновления».' : 'Обновление пока недоступно. Проверьте состояние компонента в разделе «Установка и обновления».';
  return `<button class="secondary engine-update-action" type="button" data-engine-update="${esc(engine.id)}" ${component.can_update ? '' : `disabled title="${esc(reason)}"`}>Обновить до ${esc(component.available_version)}</button>${component.can_update ? '' : `<small class="engine-update-reason">${esc(reason)}</small>`}`;
}

function bindWorkspaceControls() {
  $('#projectModeAuto').addEventListener('click', () => changeWorkspaceMode('auto'));
  $('#projectModeManual').addEventListener('click', () => changeWorkspaceMode('manual'));
  $('#projectPower').addEventListener('click', toggleWorkspaceRuntime);
  $('#overviewExpandServices').addEventListener('click', () => {
    workspaceControl.expanded = !workspaceControl.expanded;
    $('#overviewExpandServices').setAttribute('aria-expanded', String(workspaceControl.expanded));
    $('#overviewExpandServices').textContent = workspaceControl.expanded ? 'Свернуть' : 'Развернуть';
    renderOverviewQuickServices();
  });
  $('#overviewFindWebsite').addEventListener('click', () => { setView('services'); if (typeof openServiceWebsiteDiscovery === 'function') openServiceWebsiteDiscovery(); });
  $('#engineSelectedHead').addEventListener('click', event => { const update = event.target.closest('[data-engine-update]'); if (update) manageComponent(update.dataset.engineUpdate, 'update'); });
  $('#checkEngineVersions').addEventListener('click', async () => {
    const button = $('#checkEngineVersions'); if (button.disabled) return;
    button.disabled = true; button.textContent = 'Проверяем версии…';
    try { await refreshComponents(true); }
    finally { button.disabled = false; button.textContent = 'Проверить версии'; }
  });
  document.addEventListener('razvilka:auth-required', () => {
    workspaceControl.authenticated = false; workspaceControl.generation++; workspaceControl.busy = false; workspaceControl.readBusy = false;
    clearTimeout(workspaceControl.timer); workspaceControl.pending = null; state.serviceControl = null; renderWorkspaceControls();
  });
  document.addEventListener('razvilka:auth-restored', () => { if (!workspaceControl.authenticated) { workspaceControl.authenticated = true; scheduleWorkspaceControl(0); } });
  document.addEventListener('visibilitychange', () => { if (document.hidden) clearTimeout(workspaceControl.timer); else scheduleWorkspaceControl(0); });
}
