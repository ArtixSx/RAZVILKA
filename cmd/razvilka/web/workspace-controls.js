'use strict';

const workspaceControl = { generation: 0, busy: false, readBusy: false, pending: null, timer: null, expanded: false, authenticated: false, lastError: '', runtimeJob: null, runtimeRequest: null, stopReceipt: null };

// The workspace control and the service dashboard poll service-control on
// their own timers. A read already in flight serves both; a finished read is
// never reused, so an operation gate (HTTP 409) is seen at once.
const serviceControlReads = { promise: null };
function readServiceControl() {
  if (serviceControlReads.promise) return serviceControlReads.promise;
  const read = typeof readPanelResource === 'function' ? readPanelResource : api;
  const promise = read('/api/v1/service-control').finally(() => { if (serviceControlReads.promise === promise) serviceControlReads.promise = null; });
  serviceControlReads.promise = promise;
  return promise;
}
// A read started before a mutation must not answer for the state after it.
function forgetServiceControlRead() { serviceControlReads.promise = null; }

function workspaceRuntimeToken(intent) {
  const signature = JSON.stringify(intent);
  let saved = workspaceControl.runtimeRequest;
  try { saved ||= JSON.parse(sessionStorage.getItem('razvilka.runtime-request') || 'null'); } catch (_) {}
  if (!saved || saved.signature !== signature || !/^[a-f0-9]{32}$/.test(saved.key) || !Number.isFinite(saved.at) || Date.now() < saved.at || Date.now() - saved.at >= 86400000) {
    const bytes = new Uint8Array(16); globalThis.crypto.getRandomValues(bytes);
    saved = { signature, key: Array.from(bytes, x => x.toString(16).padStart(2, '0')).join(''), at: Date.now() };
  }
  workspaceControl.runtimeRequest = saved;
  try { sessionStorage.setItem('razvilka.runtime-request', JSON.stringify(saved)); } catch (_) {}
  return saved.key;
}

function clearWorkspaceRuntimeToken() {
  workspaceControl.runtimeRequest = null;
  try { sessionStorage.removeItem('razvilka.runtime-request'); } catch (_) {}
}

function acceptWorkspaceRuntimeJobs(control) {
  const comparingDNS = typeof acceptDNSLabJobs === 'function' && acceptDNSLabJobs(control);
  const applyingDNS = typeof acceptDNSApplyJobs === 'function' && acceptDNSApplyJobs(control);
  workspaceControl.dnsJobPending = comparingDNS || applyingDNS;
  const jobs = (control?.durable_jobs || []).filter(job => ['service-stop', 'service-resume'].includes(job.mode));
  const active = jobs.find(job => ['queued', 'running', 'canceling', 'interrupted'].includes(job.state));
  const previous = workspaceControl.runtimeJob;
  const finished = previous && jobs.find(job => job.id === previous.id && ['completed', 'failed', 'canceled'].includes(job.state));
  workspaceControl.runtimeJob = active || null;
  if (finished) {
    workspaceControl.lastError = finished.state === 'failed' ? finished.message : '';
    showNotice(finished.state === 'completed' ? 'success' : 'review', finished.state === 'completed' ? 'Переключение завершено' : 'Проверьте состояние проекта', finished.message);
    if (typeof refreshScopedDNS === 'function') refreshScopedDNS();
  }
  return !!active || workspaceControl.dnsJobPending;
}

function workspaceControlVisible() { return workspaceControl.authenticated && $('#authScreen').hidden && !document.hidden; }

function acceptWorkspaceControl(control) {
  if (!control || !Number.isSafeInteger(control.config_revision)) return false;
  const current = state.serviceControl;
  if (current && control.config_revision < current.config_revision) return false;
  state.serviceControl = control;
  // Revoked update authority is an accepted Stop intent, not a cleanup proof.
  // Only a fresh full control observation can confirm the stopped routes.
  if (control.runtime_state === 'stopped' && control.running === false) workspaceControl.stopReceipt = null;
  acceptWorkspaceRuntimeJobs(control);
  workspaceControl.readBusy = false;
  renderWorkspaceControls();
  return true;
}

function workspaceRuntimeControl() {
  if (state.serviceControl) return state.serviceControl;
  // A retained settings image cannot authorize Resume or prove a live path.
  // It can supply Stop's CAS revision; the server still rechecks that revision
  // and owns cancellation, cleanup and the final stopped state.
  const saved = state.savedPanel, value = saved?.value, cfg = value?.data?.config;
  const age = value?.data_age_ms + Math.max(0, Date.now() - saved?.receivedAt);
  if (!workspaceControlVisible() || value?.schema !== 1 || value.dataplane !== 'not-checked'
    || !['available', 'retained'].includes(value.state) || !Number.isFinite(age) || age < 0
    || !Number.isFinite(value.max_age_seconds) || value.max_age_seconds <= 0 || value.max_age_seconds > 900
    || age >= value.max_age_seconds * 1000 || !Number.isSafeInteger(cfg?.revision) || cfg.revision < 1
    || cfg.stopped !== false || !Array.isArray(value.data?.services)
    || !value.data.services.some(s => s.applied?.enabled === true)) return null;
  return { config_revision: cfg.revision, mode: cfg.mode, safe_mode: cfg.safe_mode === true,
    runtime_state: 'unknown', running: false, can_stop: true, resume_available: false, presentation_only: true };
}

function renderWorkspaceControls() {
  const control = workspaceRuntimeControl();
  const stopPending = !!workspaceControl.stopReceipt;
  const ready = workspaceControl.authenticated && !!control && Number.isSafeInteger(control.config_revision);
  for (const [id, mode] of [['#projectModeAuto', 'auto'], ['#projectModeManual', 'manual']]) {
    const button = $(id);
    button.disabled = !ready || control.presentation_only || workspaceControl.busy || workspaceControl.readBusy || !!workspaceControl.runtimeJob || stopPending;
    button.setAttribute('aria-pressed', String(ready && control.mode === mode));
  }
  const power = $('#projectPower');
  const running = ready && control.running === true;
  const canStop = ready && (running || control.can_stop === true);
  power.disabled = !ready || workspaceControl.busy || !!workspaceControl.runtimeJob || stopPending || (workspaceControl.readBusy && !canStop) || (control.runtime_state === 'unknown' && !canStop);
  power.setAttribute('aria-checked', String(canStop));
  power.classList.toggle('running', running && !stopPending);
  power.classList.toggle('unknown', stopPending || !ready || control.runtime_state === 'unknown');
  $('#projectPowerLabel').textContent = workspaceControl.runtimeJob ? (workspaceControl.runtimeJob.mode === 'service-stop' ? 'Останавливаем…' : 'Включаем…') : workspaceControl.busy ? 'Выполняется…' : !ready ? 'Состояние не получено' : control.runtime_state === 'unknown' ? (canStop ? 'Включён · маршруты не подтверждены' : 'Включён · ждёт применения') : running ? 'Проект включён' : control.runtime_state === 'stopped' ? 'Проект выключен' : 'Нужна настройка';
  $('#projectPowerHint').textContent = workspaceControl.runtimeJob ? 'Задание сохранено на роутере' : workspaceControl.readBusy && canStop ? 'Можно поставить остановку в очередь' : workspaceControl.readBusy ? 'Дождитесь завершения проверки' : !ready ? 'Откройте лог или обновите' : control.safe_mode ? 'Безопасный режим · открыть настройки' : canStop ? 'Нажмите, чтобы выключить' : control.runtime_state === 'unknown' ? 'Примените изменения, чтобы подтвердить' : control?.resume_available ? 'Нажмите, чтобы включить' : 'Выбрать и включить сервисы';
  // Simple mode names the switch by what the owner gets: the bypass.
  if (globalThis.document?.body?.classList?.contains?.('rz-simple') && ready && !workspaceControl.runtimeJob && !workspaceControl.busy && !stopPending) {
    if (running) { $('#projectPowerLabel').textContent = 'Обход включён'; $('#projectPowerHint').textContent = 'Нажмите, чтобы выключить всё'; }
    else if (canStop) { $('#projectPowerLabel').textContent = 'Работа обхода не подтверждена'; $('#projectPowerHint').textContent = 'Можно остановить маршруты · откройте лог'; }
    else if (control.runtime_state === 'stopped') { $('#projectPowerLabel').textContent = 'Обход выключен'; if (control?.resume_available) $('#projectPowerHint').textContent = 'Нажмите, чтобы включить'; }
  }
  if (stopPending) {
    $('#projectPowerLabel').textContent = 'Остановка запрошена';
    $('#projectPowerHint').textContent = 'Очистка маршрутов ещё не подтверждена · откройте лог';
  }
  power.setAttribute('aria-label', canStop ? 'Остановить маршруты RAZVILKA' : 'Включить маршруты RAZVILKA');
  if (stopPending) power.setAttribute('aria-label', 'Остановка запрошена; очистка маршрутов ещё не подтверждена');
  // The project is on; only the live routes are unconfirmed. Name the reason.
  const recovery = state.status?.node_recovery;
  const recoveryNote = ['requires-review', 'network-stale', 'revalidating'].includes(recovery?.state) ? recovery.message : '';
  power.title = ready && control.runtime_state === 'unknown' ? recoveryNote || control.runtime_issue?.message || 'Маршруты ещё не подтверждены в текущей сети.' : '';
  if (stopPending) power.title = 'Запрос остановки принят. Продолжение обновления заблокировано; очистка маршрутов ещё не подтверждена.';
  if (ready) $('#systemText').textContent = workspaceControl.readBusy ? 'Выполняется проверка или изменение' : control.safe_mode ? 'Применение заблокировано в настройках' : control.mode === 'manual' ? 'Подключения меняете вы' : 'Автозамена по правилам сервисов';
  if (stopPending) $('#systemText').textContent = 'Остановка требует подтверждения';
}

async function refreshWorkspaceControl() {
  if (!workspaceControlVisible()) return false;
  if (workspaceControl.pending) return workspaceControl.pending;
  const generation = workspaceControl.generation;
  const context = typeof panelReadContext === 'function' ? panelReadContext() : null;
  const current = () => generation === workspaceControl.generation && workspaceControlVisible() && (context === null || panelReadContextCurrent(context));
  const pending = (async () => {
    if (workspaceControl.runtimeJob || workspaceControl.readBusy || workspaceControl.dnsJobPending) {
      const read = typeof readPanelResource === 'function' ? readPanelResource : api;
      const memory = await read('/api/v1/service-control/current');
      if (!current()) return null;
      if (acceptWorkspaceRuntimeJobs(memory)) { renderWorkspaceControls(); return null; }
    }
    return readServiceControl();
  })().then(control => {
    if (!current()) return false;
    return acceptWorkspaceControl(control);
  }).catch(error => {
    if (!current()) return false;
    if (error.status === 409) {
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
    catch (error) { if (generation === workspaceControl.generation) { workspaceControl.lastError = error.message; state.serviceControl = null; renderWorkspaceControls(); } }
    finally { if (generation === workspaceControl.generation) scheduleWorkspaceControl(workspaceControl.readBusy || workspaceControl.runtimeJob || workspaceControl.dnsJobPending ? 3000 : 15000); }
  }, delay);
}

async function changeWorkspaceMode(mode) {
  const control = state.serviceControl;
  if (!workspaceControlVisible() || workspaceControl.busy || workspaceControl.readBusy || workspaceControl.stopReceipt || !control || !['auto', 'manual'].includes(mode) || control.mode === mode) return;
  const generation = workspaceControl.generation;
  workspaceControl.busy = true; renderWorkspaceControls();
  try {
    forgetServiceControlRead();
    const result = await api('/api/v1/service-control', { method: 'PUT', body: JSON.stringify({ expected_revision: control.config_revision, mode, confirm: 'SAVE_SERVICE_CONTROL' }) }).finally(forgetServiceControlRead);
    if (generation !== workspaceControl.generation) return;
    if (!acceptWorkspaceControl(result.control || result)) await refreshWorkspaceControl();
    await refreshAfterMutation();
    if (generation !== workspaceControl.generation) return;
    showNotice('success', mode === 'auto' ? 'Автопилот включён' : 'Ручная настройка', mode === 'auto' ? 'Автоматическая замена разрешена только для настроенных сервисов и выбранного резерва. Правила доступны в карточке сервиса.' : 'Автоматическая замена отключена. Действующие подключения сохранены.');
  } catch (error) {
    if (generation === workspaceControl.generation) { workspaceControl.lastError = error.message; showNotice('error', 'Режим не изменён', error.message); await refreshWorkspaceControl().catch(() => {}); }
  } finally { if (generation === workspaceControl.generation) { workspaceControl.busy = false; renderWorkspaceControls(); } }
}

async function toggleWorkspaceRuntime() {
  const control = workspaceRuntimeControl();
  if (!workspaceControlVisible() || workspaceControl.busy || workspaceControl.runtimeJob || workspaceControl.stopReceipt || !control || (workspaceControl.readBusy && !control.running && !control.can_stop) || (control.runtime_state === 'unknown' && !control.can_stop)) return;
  if (control.safe_mode && !control.running && !control.can_stop) {
    setView('settings');
    showNotice('review', 'Включён безопасный режим', 'Отключите безопасный режим в настройках, затем включите проект. Сохранённые маршруты пройдут проверку перед запуском.');
    return;
  }
  if (!control.running && !control.can_stop && !control.resume_available) {
    setView('services');
    showNotice('review', 'Выберите сервис для подключения', 'Запустите «Автоподбор» или выберите подключение вручную, укажите устройства и нажмите «Проверить и применить».');
    return;
  }
  const generation = workspaceControl.generation;
  const action = control.running || control.can_stop ? 'stop' : 'resume';
  workspaceControl.busy = true; renderWorkspaceControls();
  try {
    if (action === 'stop') {
      const fingerprint=value=>JSON.stringify([value?.config_revision,value?.running,value?.can_stop,value?.runtime_state,value?.safe_mode,value?.resume_available]);
      const reviewed=fingerprint(control);
      if (!await askConfirmation('Выключить обход для всех сервисов?', 'Вернётся обычная маршрутизация роутера. Включить снова можно этой же кнопкой.', 'Выключить обход')) return;
      if (generation !== workspaceControl.generation || !workspaceControlVisible()) return;
      if (reviewed !== fingerprint(workspaceRuntimeControl())) {
        showNotice('review','Состояние изменилось','Обновите состояние и подтвердите остановку снова.');
        return;
      }
    }
    const intent = { expected_revision: control.config_revision, action, confirm: action === 'stop' ? 'STOP_OWNED_ROUTES' : 'RESUME_OWNED_ROUTES' };
    forgetServiceControlRead();
    const result = await api('/api/v1/service-control/runtime', { method: 'POST', body: JSON.stringify({ ...intent, idempotency_key: workspaceRuntimeToken(intent) }) }).finally(forgetServiceControlRead);
    if (generation !== workspaceControl.generation) return;
    clearWorkspaceRuntimeToken();
    if (result.persistent && result.job) {
      workspaceControl.runtimeJob = result.job;
      acceptWorkspaceRuntimeJobs({ durable_jobs: [result.job] });
      if (workspaceControl.runtimeJob) showNotice('review', 'Задание принято', result.job.message || 'Переключение сохранено на роутере. Браузер можно закрыть.');
      workspaceControl.lastError = '';
      scheduleWorkspaceControl(1000);
      return;
    }
    if (action === 'stop' && result.stop_requested === true && result.authority_revoked === true && result.stopped_confirmed === false && result.cleanup_pending === true) {
      workspaceControl.stopReceipt = { stop_requested: true, authority_revoked: true, stopped_confirmed: false, cleanup_pending: true };
      workspaceControl.lastError = '';
      showNotice('review', 'Остановка запрошена', 'Запрос сохранён на роутере. Продолжение обновления заблокировано; очистка маршрутов ещё не подтверждена. Откройте лог проекта для проверки.');
      scheduleWorkspaceControl(1000);
      return;
    }
    if (!result.ok) throw new Error(result.error || 'Изменение не подтверждено. Обновите состояние.');
    workspaceControl.lastError = '';
    acceptWorkspaceControl(result.control);
    await refreshAfterMutation();
    if (generation !== workspaceControl.generation) return;
    showNotice('success', action === 'stop' ? 'Маршруты RAZVILKA остановлены' : 'Маршруты RAZVILKA включены', action === 'stop' ? 'Ваши настройки сохранены. Панель остаётся доступна.' : 'Предыдущие сервисы и устройства восстановлены после проверки.');
  } catch (error) {
    if (generation === workspaceControl.generation) { if (error.status >= 400 && error.status < 500) clearWorkspaceRuntimeToken(); workspaceControl.lastError = error.message; showNotice('error', 'Переключение не завершено', error.message); await refreshWorkspaceControl().catch(() => {}); }
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

async function openWorkspaceLog() {
  if (!workspaceControlVisible()) return;
  const generation = workspaceControl.generation;
  const context = typeof panelReadContext === 'function' ? panelReadContext() : null;
  const current = () => generation === workspaceControl.generation && workspaceControlVisible() && (context === null || panelReadContextCurrent(context));
  let jobs = null, jobsError = '', nodeJob = null, nodeJobError = '', autonomy = null, autonomyError = '';
  try {
    const [audit, memory, checks, automatic] = await Promise.allSettled([api('/api/v1/audit/current?limit=40'), api('/api/v1/service-control/current'), api('/api/v1/node-checks/current'), api('/api/v1/panel/autonomy')]);
    if (!current()) return;
    if (memory.status === 'fulfilled') jobs = memory.value.durable_jobs || [];
    else jobsError = memory.reason?.message || 'Не удалось получить очередь заданий.';
    if (checks.status === 'fulfilled' && checks.value && Object.hasOwn(checks.value, 'job') && (checks.value.job === null || typeof checks.value.job === 'object' && !Array.isArray(checks.value.job))) nodeJob = checks.value.job;
    else nodeJobError = 'Не удалось прочитать последнюю проверку подключений. Обновите журнал, чтобы повторить чтение.';
    if (automatic.status === 'fulfilled') autonomy = automatic.value;
    else autonomyError = 'Не удалось получить состояние Автопилота. Обновите лог, чтобы повторить чтение.';
    if (audit.status !== 'fulfilled') throw audit.reason;
    state.audit = audit.value;
    renderAudit();
  } catch (error) {
    if (!current()) return;
    workspaceControl.lastError = error.message;
    showNotice('error', 'Журнал не обновлён', error.message);
  }
  if (!current()) return;
  showDetails({
    detail_kind: 'project-log',
    control: state.serviceControl,
    stop_receipt: workspaceControl.stopReceipt,
    jobs, jobs_error: jobsError,
    node_job: nodeJob, node_job_error: nodeJobError,
    autonomy, autonomy_error: autonomyError,
    load_issues: (state.loadIssues || []).map(issue => ({section: issue.section, message: issue.message || 'Не удалось получить данные'})),
    audit: state.audit,
    component_issues: (state.components || []).filter(item => item.update_check_error || item.inventory_error).map(item => ({id:item.name || item.id, message:item.inventory_error || item.update_check_error})),
    last_action_error: workspaceControl.lastError,
  }, 'Лог проекта');
}

function bindWorkspaceControls() {
  $('#projectModeAuto').addEventListener('click', () => changeWorkspaceMode('auto'));
  $('#projectModeManual').addEventListener('click', () => changeWorkspaceMode('manual'));
  $('#projectPower').addEventListener('click', toggleWorkspaceRuntime);
  $('#projectLog').addEventListener('click', openWorkspaceLog);
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
    forgetServiceControlRead();
    workspaceControl.authenticated = false; workspaceControl.generation++; workspaceControl.busy = false; workspaceControl.readBusy = false; workspaceControl.lastError = '';
    workspaceControl.runtimeJob = null; workspaceControl.stopReceipt = null; workspaceControl.dnsJobPending = false; clearWorkspaceRuntimeToken();
    clearTimeout(workspaceControl.timer); workspaceControl.pending = null; state.serviceControl = null; state.savedPanel = null; renderWorkspaceControls();
  });
  document.addEventListener('razvilka:auth-restored', () => { if (!workspaceControl.authenticated) { workspaceControl.authenticated = true; scheduleWorkspaceControl(0); } });
  document.addEventListener('visibilitychange', () => { if (document.hidden) clearTimeout(workspaceControl.timer); else scheduleWorkspaceControl(0); });
}
