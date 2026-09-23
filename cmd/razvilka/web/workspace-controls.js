'use strict';

const workspaceControl = { generation: 0, busy: false, readBusy: false, pending: null, timer: null, expanded: false, authenticated: false, lastError: '', runtimeJob: null, runtimeRequest: null };

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
  workspaceControl.dnsJobPending = typeof acceptDNSLabJobs === 'function' && acceptDNSLabJobs(control);
  const jobs = (control?.durable_jobs || []).filter(job => ['service-stop', 'service-resume'].includes(job.mode));
  const active = jobs.find(job => ['queued', 'running', 'canceling', 'interrupted'].includes(job.state));
  const previous = workspaceControl.runtimeJob;
  const finished = previous && jobs.find(job => job.id === previous.id && ['completed', 'failed', 'canceled'].includes(job.state));
  workspaceControl.runtimeJob = active || null;
  if (finished) {
    workspaceControl.lastError = finished.state === 'failed' ? finished.message : '';
    showNotice(finished.state === 'completed' ? 'success' : 'review', finished.state === 'completed' ? 'Переключение завершено' : 'Проверьте состояние проекта', finished.message);
  }
  return !!active || workspaceControl.dnsJobPending;
}

function workspaceControlVisible() { return workspaceControl.authenticated && $('#authScreen').hidden && !document.hidden; }

function acceptWorkspaceControl(control) {
  if (!control || !Number.isSafeInteger(control.config_revision)) return false;
  const current = state.serviceControl;
  if (current && control.config_revision < current.config_revision) return false;
  state.serviceControl = control;
  acceptWorkspaceRuntimeJobs(control);
  workspaceControl.readBusy = false;
  renderWorkspaceControls();
  return true;
}

function renderWorkspaceControls() {
  const control = state.serviceControl;
  const ready = workspaceControl.authenticated && !!control && Number.isSafeInteger(control.config_revision);
  for (const [id, mode] of [['#projectModeAuto', 'auto'], ['#projectModeManual', 'manual']]) {
    const button = $(id);
    button.disabled = !ready || workspaceControl.busy || workspaceControl.readBusy || !!workspaceControl.runtimeJob;
    button.setAttribute('aria-pressed', String(ready && control.mode === mode));
  }
  const power = $('#projectPower');
  const running = ready && control.running === true;
  const canStop = ready && (running || control.can_stop === true);
  power.disabled = !ready || workspaceControl.busy || !!workspaceControl.runtimeJob || (workspaceControl.readBusy && !canStop) || (control.runtime_state === 'unknown' && !canStop);
  power.setAttribute('aria-checked', String(canStop));
  power.classList.toggle('running', running);
  power.classList.toggle('unknown', !ready || control.runtime_state === 'unknown');
  $('#projectPowerLabel').textContent = workspaceControl.runtimeJob ? (workspaceControl.runtimeJob.mode === 'service-stop' ? 'Останавливаем…' : 'Включаем…') : workspaceControl.busy ? 'Выполняется…' : !ready ? 'Состояние не получено' : control.runtime_state === 'unknown' ? 'Нужна проверка' : running ? 'Проект включён' : control.runtime_state === 'stopped' ? 'Проект выключен' : 'Нужна настройка';
  $('#projectPowerHint').textContent = workspaceControl.runtimeJob ? 'Задание сохранено на роутере' : workspaceControl.readBusy && canStop ? 'Можно поставить остановку в очередь' : workspaceControl.readBusy ? 'Дождитесь завершения проверки' : !ready ? 'Откройте лог или обновите' : control.safe_mode ? 'Безопасный режим · открыть настройки' : canStop ? 'Нажмите, чтобы выключить' : control?.resume_available ? 'Нажмите, чтобы включить' : 'Выбрать и включить сервисы';
  power.setAttribute('aria-label', canStop ? 'Остановить маршруты RAZVILKA' : 'Включить маршруты RAZVILKA');
  if (ready) $('#systemText').textContent = workspaceControl.readBusy ? 'Выполняется проверка или изменение' : control.safe_mode ? 'Применение заблокировано в настройках' : control.mode === 'manual' ? 'Подключения меняете вы' : 'Автозамена по правилам сервисов';
}

async function refreshWorkspaceControl() {
  if (!workspaceControlVisible()) return false;
  if (workspaceControl.pending) return workspaceControl.pending;
  const generation = workspaceControl.generation;
  const pending = (async () => {
    if (workspaceControl.runtimeJob || workspaceControl.readBusy || workspaceControl.dnsJobPending) {
      const memory = await api('/api/v1/service-control/current');
      if (generation !== workspaceControl.generation || !workspaceControlVisible()) return null;
      if (acceptWorkspaceRuntimeJobs(memory)) { renderWorkspaceControls(); return null; }
    }
    return api('/api/v1/service-control');
  })().then(control => {
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
    catch (error) { if (generation === workspaceControl.generation) { workspaceControl.lastError = error.message; state.serviceControl = null; renderWorkspaceControls(); } }
    finally { if (generation === workspaceControl.generation) scheduleWorkspaceControl(workspaceControl.readBusy || workspaceControl.runtimeJob || workspaceControl.dnsJobPending ? 3000 : 15000); }
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
    if (generation === workspaceControl.generation) { workspaceControl.lastError = error.message; showNotice('error', 'Режим не изменён', error.message); await refreshWorkspaceControl().catch(() => {}); }
  } finally { if (generation === workspaceControl.generation) { workspaceControl.busy = false; renderWorkspaceControls(); } }
}

async function toggleWorkspaceRuntime() {
  const control = state.serviceControl;
  if (!workspaceControlVisible() || workspaceControl.busy || workspaceControl.runtimeJob || !control || (workspaceControl.readBusy && !control.running && !control.can_stop) || (control.runtime_state === 'unknown' && !control.can_stop)) return;
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
    const intent = { expected_revision: control.config_revision, action, confirm: action === 'stop' ? 'STOP_OWNED_ROUTES' : 'RESUME_OWNED_ROUTES' };
    const result = await api('/api/v1/service-control/runtime', { method: 'POST', body: JSON.stringify({ ...intent, idempotency_key: workspaceRuntimeToken(intent) }) });
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
  setView('activity');
  let jobs = null, jobsError = '';
  try {
    const [audit, memory] = await Promise.allSettled([api('/api/v1/audit/current?limit=40'), api('/api/v1/service-control/current')]);
    if (generation !== workspaceControl.generation || !workspaceControlVisible()) return;
    if (memory.status === 'fulfilled') jobs = memory.value.durable_jobs || [];
    else jobsError = memory.reason?.message || 'Не удалось получить очередь заданий.';
    if (audit.status !== 'fulfilled') throw audit.reason;
    state.audit = audit.value;
    renderAudit();
  } catch (error) {
    if (generation !== workspaceControl.generation) return;
    workspaceControl.lastError = error.message;
    showNotice('error', 'Журнал не обновлён', error.message);
  }
  if (generation !== workspaceControl.generation || !workspaceControlVisible()) return;
  showDetails({
    detail_kind: 'project-log',
    control: state.serviceControl,
    jobs, jobs_error: jobsError,
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
    workspaceControl.authenticated = false; workspaceControl.generation++; workspaceControl.busy = false; workspaceControl.readBusy = false; workspaceControl.lastError = '';
    workspaceControl.runtimeJob = null; workspaceControl.dnsJobPending = false; clearWorkspaceRuntimeToken();
    clearTimeout(workspaceControl.timer); workspaceControl.pending = null; state.serviceControl = null; renderWorkspaceControls();
  });
  document.addEventListener('razvilka:auth-restored', () => { if (!workspaceControl.authenticated) { workspaceControl.authenticated = true; scheduleWorkspaceControl(0); } });
  document.addEventListener('visibilitychange', () => { if (document.hidden) clearTimeout(workspaceControl.timer); else scheduleWorkspaceControl(0); });
}
