'use strict';

// Dashboard state is presentation only. Checks never assign a route; a found
// node goes through the existing service/scope review before it can be applied.
const serviceDashboard = {
  control: null, expanded: new Set(), epoch: 0, read: null, poll: null,
  operation: null, edit: null, scheduleDirty: false, scheduleRevision: null, scheduleServiceIDs: [],
  lookup: null, lookupResults: [], authenticated: true, message: '',
  pendingRequest: null,
};

function serviceDashboardApplied(service) {
  return service.applied_state || { enabled: !!service.applied_enabled, route: service.applied_route };
}

function serviceDashboardResult(service) {
  return (serviceDashboard.control?.results || []).find(result => result.service_id === service.id);
}

function serviceDashboardFresh(result) {
  if (!result || result.stale === true || result.freshness_verified !== true) return false;
  const currentRevision = Math.max(state.status?.revision || 0, state.serviceControl?.config_revision || serviceDashboard.control?.config_revision || 0);
  if (result.config_revision !== currentRevision) return false;
  const until = Date.parse(result.valid_until || result.fresh_until || '');
  const checked = Date.parse(result.checked_at || '');
  return Number.isFinite(checked) && checked <= Date.now() && Number.isFinite(until) && checked < until && until > Date.now();
}

// Shared with the home page: a calculated AUTO candidate is never an observed
// route. TCP reachability alone never becomes a service PASS.
function serviceDashboardSummary(service) {
  const applied = serviceDashboardApplied(service);
  const result = serviceDashboardResult(service);
  const directResult = !applied.enabled && serviceDashboardFresh(result) && result.kind === 'check'
    && result.checked_route === 'direct' && !result.applied_route && !result.recommended_node_id;
  if (state.serviceControl?.runtime_state === 'stopped' && !directResult) return { route: '', label: 'Остановлен', kind: 'unknown', detail: 'Маршруты RAZVILKA остановлены. Сохранённые настройки можно включить общей кнопкой.', pingLabel: 'Пинг: —' };
  const route = applied.enabled ? applied.route : '';
  const observed = service.observed_state || {};
  const currentResult = applied.enabled && serviceDashboardFresh(result) && result.kind !== 'select'
    && !result.recommended_node_id && (result.checked_route || result.applied_route) === route;
  const freshObserved = applied.enabled && observed.route === route
    && observed.status !== 'stale' && Number.isFinite(Date.parse(observed.checked_at || ''))
    && Date.parse(observed.checked_at) <= Date.now() && Date.parse(observed.checked_at) < Date.parse(observed.fresh_until || '')
    && Date.parse(observed.fresh_until || '') > Date.now();
  let label = applied.enabled ? 'Не проверен' : 'Не включён';
  let kind = 'unknown';
  let detail = applied.enabled ? 'Маршрут применён; доступ к сервису ещё не подтверждён.' : 'Для сервиса пока нет применённого маршрута.';
  if (directResult) {
    label = result.status === 'pass' && result.available === true ? 'Напрямую: доступен' : result.status === 'fail' ? 'Напрямую: недоступен' : 'Напрямую: результат неясен';
    kind = result.status === 'pass' && result.available === true ? 'good' : result.status === 'fail' ? 'bad' : 'warn';
    detail = 'Проверка прямого веб-доступа выполнена с роутера. Обход не включён; неприменённые настройки эта проверка не подтверждает.';
  } else if (currentResult) {
    if (result.status === 'pass' && result.available === true) {
      label = 'Сервис доступен'; kind = 'good';
    } else if (result.status === 'fail') {
      label = 'Проверка не пройдена'; kind = 'bad';
    } else {
      label = result.status === 'not-ready' ? 'Нужна настройка' : 'Результат неясен'; kind = 'warn';
    }
    detail = result.message || detail;
  } else if (freshObserved && observed.level === 'service-confirmed' && observed.outcome === 'service_accepted') {
    label = 'Сервис доступен'; kind = 'good'; detail = 'Есть свежая проверка сервиса через применённый маршрут.';
  } else if (applied.enabled && (result || observed.checked_at)) {
    label = 'Нужна новая проверка';
  }
  const ping = route?.startsWith('sing-box:node-') && typeof nodePassivePing === 'function' ? nodePassivePing(route.slice('sing-box:'.length)) : null;
  const latency = ping?.reachable && Number.isFinite(ping.latency_ms) ? ping.latency_ms : null;
  return { route, label, kind, detail, pingLabel: latency !== null ? `Пинг TCP: ${Math.round(latency)} мс` : ping && !ping.reachable ? 'Пинг TCP: нет ответа' : 'Пинг: —' };
}

function serviceDashboardPingNode(service) {
  const applied = serviceDashboardApplied(service);
  if (!applied.enabled || !applied.route?.startsWith('sing-box:node-')) return null;
  const node = (state.nodes?.nodes || []).find(item => `sing-box:${item.id}` === applied.route);
  return node && typeof nodeCanCheck === 'function' && nodeCanCheck(node) && typeof nodeSupportsTCPPing === 'function' && nodeSupportsTCPPing(node) ? node : null;
}

function serviceDashboardRouteSelect(service) {
  const options = (state.routeOptions || []).filter(option => !option.services?.length || option.services.includes(service.id));
  if (service.route && !options.some(option => option.id === service.route)) {
    options.push({ id: service.route, name: routeLabel(service.route), selectable: false });
  }
  return `<select data-sd-route="${esc(service.id)}" data-sd-focus="route-${esc(service.id)}" aria-label="Выбранный маршрут: ${esc(service.name)}" ${serviceDashboard.edit ? 'disabled' : ''}>${options.map(option => `<option value="${esc(option.id)}" ${option.id === service.route ? 'selected' : ''} ${option.selectable === false ? 'disabled' : ''}>${esc(option.id === 'auto' ? 'Автоматически по правилам' : option.id === 'direct' ? 'Напрямую' : option.name || routeLabel(option.id))}${option.selectable === false ? ' · недоступен' : ''}</option>`).join('')}</select>`;
}

function serviceDashboardRecommendation(service) {
  const result = serviceDashboardResult(service);
  if (result?.recommended_node_id && result.available === true && result.status === 'pass' && serviceDashboardFresh(result)) {
    const node = (state.nodes?.nodes || []).find(item => item.id === result.recommended_node_id && !item.disabled && item.state !== 'expired');
    if (node) return `<div class="sd-recommendation good"><b>Найдено проверенное подключение</b><span>${esc(nodeDisplayName(node))}. Оно ещё не назначено сервису.</span><button class="primary" type="button" data-sd-use="${esc(node.id)}" data-sd-service="${esc(service.id)}" data-sd-focus="use-${esc(service.id)}">Выбрать устройства и применить</button></div>`;
  }
  if (result?.kind === 'select') return `<div class="sd-recommendation"><b>Автоподбор</b><span>${esc(result.message || 'Рабочее подключение пока не найдено. Обновите подключения и повторите подбор.')}</span></div>`;
  return '<div class="sd-recommendation"><b>Рекомендация пока не проверена</b><span>Автоподбор проверит до трёх сохранённых подключений за один подбор и предложит подходящее для этого сервиса.</span></div>';
}

function serviceDashboardCard(service) {
  const summary = serviceDashboardSummary(service);
  const applied = serviceDashboardApplied(service);
  const open = serviceDashboard.expanded.has(service.id);
  const result = serviceDashboardResult(service);
  const busy = !!serviceDashboard.operation || serviceDashboardJobActive();
  const scope = applied.enabled ? nodeScopeText(service.applied_sources || []) : 'Ещё не назначены';
  const pending = service.dirty || service.enabled !== applied.enabled;
  const timing = serviceDashboardFresh(result) && Number.isFinite(result.latency_ms) ? `Время проверки: ${Math.round(result.latency_ms)} мс` : '';
  const pingNode = serviceDashboardPingNode(service);
  const id = esc(service.id);
  return `<article class="sd-card ${pending ? 'pending' : ''} ${open ? 'is-expanded' : ''}" data-sd-card="${id}">
    <div class="sd-card-head"><button class="sd-summary" type="button" data-sd-expand="${id}" data-sd-focus="expand-${id}" aria-expanded="${open}" aria-controls="sd-details-${id}">
      <span class="sd-name"><span class="service-badge">${typeof consoleServiceIcon==='function'?consoleServiceIcon(service):esc(service.icon || '•')}</span><span><b>${esc(service.name)}</b><small>${pending ? 'Есть неприменённые изменения' : esc(service.category || '')}</small></span></span>
      <span class="sd-current"><small>Применённый маршрут</small><b>${esc(summary.route ? routeLabel(summary.route) : 'Не включён')}</b></span>
      <span class="sd-health ${summary.kind}">${summary.label === 'Не включён' ? '' : `<b>${esc(summary.label)}</b>`}<small title="TCP-пинг измеряет соединение с сервером. Доступ к сайту проверяется отдельно.">${esc(summary.pingLabel)}</small></span>
      <span class="sd-chevron" aria-hidden="true"><span class="r41-expand-label">${open ? 'Свернуть' : 'Подробнее'}</span>${open ? '−' : '+'}</span>
    </button><div class="sd-switch"><button type="button" class="toggle ${service.enabled ? 'on' : ''}" role="switch" aria-checked="${!!service.enabled}" aria-label="${service.enabled ? 'Выключить' : 'Включить'} ${esc(service.name)} после применения" data-sd-toggle="${id}" data-sd-focus="toggle-${id}" ${serviceDashboard.edit ? 'disabled' : ''}><i></i></button><small>${service.enabled ? 'Выбрано: вкл.' : 'Выбрано: выкл.'}</small></div></div>
    <div class="sd-details" id="sd-details-${id}" ${open ? '' : 'hidden'}>
      <p class="sd-description">${esc(service.description || '')}</p>
      <div class="sd-detail-grid"><div class="sd-setting"><label><span>Изменить маршрут</span>${serviceDashboardRouteSelect(service)}</label><small>${service.route === 'auto' ? 'Автоматический расчёт не доказывает, что выбранный обход уже работает.' : 'Выбор вступит в силу после проверки и применения.'}</small>${service.route_available === false ? `<p class="sd-warning">${esc(service.route_issue || 'Выбранный маршрут недоступен.')}</p>` : ''}</div>
      <div class="sd-setting"><span>Устройства действующего маршрута</span><b>${esc(scope)}</b>${service.sources_dirty ? `<small>После применения: ${esc(nodeScopeText(service.sources || []))}</small>` : ''}<button class="secondary" type="button" data-sd-scope="${id}" data-sd-focus="scope-${id}" ${serviceDashboard.edit ? 'disabled' : ''}>Изменить устройства</button></div>
      <div class="sd-setting"><span>Последняя проверка</span><b class="${summary.kind}">${esc(summary.label)}</b><small>${esc(summary.detail)}</small>${timing ? `<small>${esc(timing)} · это не пинг</small>` : ''}${result?.checked_at ? `<small>${esc(new Date(result.checked_at).toLocaleString('ru-RU'))}</small>` : ''}</div></div>
      ${serviceDashboardRecommendation(service)}
      <div class="sd-card-actions"><button class="secondary" type="button" data-sd-check="${id}" data-sd-focus="check-${id}" ${busy ? 'disabled' : ''}>Проверить сервис</button>${pingNode ? `<button class="secondary" type="button" data-sd-ping="${id}" data-sd-focus="ping-${id}" ${busy ? 'disabled' : ''}>Пинг сервера</button>` : ''}<button class="secondary" type="button" data-sd-select="${id}" data-sd-focus="select-${id}" ${busy ? 'disabled' : ''}>Подобрать подключение</button><button class="secondary" type="button" data-sd-lists="${id}" data-sd-focus="lists-${id}">Домены и IP (${(service.domains || []).length})</button>${service.route_available === false ? `<button class="secondary" type="button" data-sd-setup="${esc(service.route)}">Настроить обход</button>` : ''}${service.nfqws2?.relevant ? `<button class="secondary" type="button" data-sd-nfqws="${id}">Проверка NFQWS2</button>` : ''}${service.custom ? `<button class="secondary" type="button" data-sd-custom="${id}">Изменить сервис</button><button class="secondary" type="button" data-sd-delete="${id}">Удалить сервис</button>` : ''}</div>
    </div></article>`;
}

function renderServiceDashboard() {
  const list = $('#serviceList');
  if (!list) return;
  if (state.serviceControl && (!serviceDashboard.control || state.serviceControl.config_revision >= serviceDashboard.control.config_revision)) serviceDashboard.control = state.serviceControl;
  populateServiceCategories();
  const focus = document.activeElement;
  // Keep an open native select intact during background refreshes. Its change
  // or blur renders again; the user's option is never silently reset by a poll.
  if (!list.contains?.(focus) || !focus?.matches?.('[data-sd-route]')) {
    const key = list.contains?.(focus) ? focus?.dataset?.sdFocus : '';
    list.innerHTML = state.services.filter(serviceMatches).map(serviceDashboardCard).join('') || '<p class="empty-inline">Сервис не найден. Попробуйте найти его по адресу сайта.</p>';
    if (key) [...list.querySelectorAll('[data-sd-focus]')].find(element => element.dataset.sdFocus === key)?.focus({ preventScroll: true });
  }
  renderServiceDashboardControl();
  if(typeof renderInterface==='function')renderInterface();
}

function serviceDashboardJobActive() {
  return ['queued', 'running', 'canceling', 'cancelling', 'interrupted'].includes(serviceDashboard.control?.job?.state);
}

function serviceDashboardServiceIDs() {
  return state.services.map(service => service.id);
}

function renderServiceDashboardControl() {
  const control = serviceDashboard.control;
  const job = control?.job;
  const busy = !!serviceDashboard.operation || serviceDashboardJobActive();
  const ready = Number.isSafeInteger(control?.config_revision) && serviceDashboard.authenticated;
  $('#serviceCheckAll').disabled = busy || !ready;
  $('#serviceSelectAll').disabled = busy || !ready;
  $('#serviceCancelCheck').hidden = !serviceDashboardJobActive() || !job?.mode?.startsWith('service-');
  $('#serviceCancelCheck').disabled = !!serviceDashboard.operation;
  const stoppedNote = state.serviceControl?.runtime_state === 'stopped' ? 'Маршруты остановлены. Проверка не включает их; применение включит выбранные сервисы после проверки. ' : '';
  $('#serviceCheckStatus').textContent = stoppedNote + (serviceDashboard.message || (serviceDashboardJobActive()
    ? (['service-node-apply', 'service-stop', 'service-resume'].includes(job.mode) ? job.message || 'Выполняется переключение маршрутов.' : `Идёт ${job.mode === 'service-select' ? 'подбор подключений' : 'проверка'}${Number.isFinite(job.completed) && Number.isFinite(job.total) ? `: ${job.completed} из ${job.total}` : ''}. Маршруты не изменяются.`)
    : control ? 'Проверка подтверждает веб-доступ. Подбор предлагает подключение; применение и устройства вы выбираете отдельно.' : 'Получаем состояние проверок…'));
  const schedule = control?.schedule;
  if (schedule && !serviceDashboard.scheduleDirty) {
    $('#serviceScheduleEnabled').checked = !!schedule.enabled;
    const seconds = String(schedule.interval_seconds || 900);
    const select = $('#serviceScheduleInterval');
    if (![...select.options].some(option => option.value === seconds)) select.add(new Option(`Каждые ${seconds} сек`, seconds));
    select.value = seconds;
    const savedIDs = schedule.service_ids || [];
    const allIDs = serviceDashboardServiceIDs();
    $('#serviceScheduleAll').checked = false;
    serviceDashboard.scheduleServiceIDs = savedIDs.length ? [...savedIDs] : allIDs;
  }
  for (const id of ['serviceScheduleEnabled', 'serviceScheduleInterval', 'serviceScheduleAll']) $(`#${id}`).disabled = !ready || !!serviceDashboard.operation;
  $('#serviceScheduleSave').disabled = !ready || !serviceDashboard.scheduleDirty || !!serviceDashboard.operation;
  const next = Date.parse(schedule?.next_check_at || '');
  $('#serviceScheduleNext').textContent = schedule?.enabled ? `Следующая проверка: ${Number.isFinite(next) && next > Date.now() ? new Date(next).toLocaleString('ru-RU') : 'по очереди после текущих операций'}.` : 'Автоматическая проверка выключена.';
  $('#serviceScheduleSelection').textContent = `Сервисы расписания (${serviceDashboard.scheduleServiceIDs.length}): ${serviceDashboard.scheduleServiceIDs.map(id => state.services.find(service => service.id === id)?.name || id).join(', ')}.`;
  const visible = state.services.filter(serviceMatches);
  $('#serviceExpandAll').textContent = visible.length && visible.every(service => serviceDashboard.expanded.has(service.id)) ? 'Свернуть все' : 'Развернуть все';
  const select = $('#serviceAutoPickTarget');
  if (document.activeElement !== select) {
    const selected = select.value;
    select.innerHTML = state.services.map(service => `<option value="${esc(service.id)}">${esc(service.name)}</option>`).join('');
    select.value = state.services.some(service => service.id === selected) ? selected : (state.services.find(service => service.applied_enabled)?.id || state.services[0]?.id || '');
  }
  select.disabled = busy;
}

function serviceDashboardCurrent(operation) {
  return serviceDashboard.operation === operation && operation.epoch === serviceDashboard.epoch && !operation.controller.signal.aborted && serviceDashboard.authenticated;
}

async function refreshServiceControl() {
  if (!serviceDashboard.authenticated || serviceDashboard.read) return;
  const controller = new AbortController();
  const epoch = serviceDashboard.epoch;
  serviceDashboard.read = controller;
  try {
    const memory = await api('/api/v1/service-control/current', { signal: controller.signal });
    if (controller.signal.aborted || epoch !== serviceDashboard.epoch) return;
    const priorJob = serviceDashboard.control?.job;
    serviceDashboard.control = { ...serviceDashboard.control, job: memory.job || null };
    if (state.serviceControl) state.serviceControl = { ...state.serviceControl, job: memory.job || null };
    if (typeof nodeBrowser !== 'undefined' && Array.isArray(memory.pings)) nodeBrowser.pings = memory.pings;
    if (serviceDashboardJobActive()) { renderServiceDashboard(); return; }
    const control = await api('/api/v1/service-control', { signal: controller.signal });
    if (controller.signal.aborted || epoch !== serviceDashboard.epoch) return;
    if (typeof acceptWorkspaceControl === 'function') acceptWorkspaceControl(control);
    else state.serviceControl = control;
    serviceDashboard.control = state.serviceControl || control;
    if (priorJob?.state === 'running' || priorJob?.state === 'canceling') {
      // A checked candidate must exist in the current inventory before its
      // explicit review action is offered. These reads happen after cleanup.
      const nodes = await api('/api/v1/nodes', { signal: controller.signal });
      if (controller.signal.aborted || epoch !== serviceDashboard.epoch) return;
      state.nodes = nodes;
    }
    if (serviceDashboard.message.startsWith('Не удалось получить состояние:')) serviceDashboard.message = '';
    renderServiceDashboard();
  } catch (error) {
    if (!controller.signal.aborted && epoch === serviceDashboard.epoch) {
      serviceDashboard.message = `Не удалось получить состояние: ${error.message}`;
      renderServiceDashboardControl();
    }
  } finally { if (serviceDashboard.read === controller) serviceDashboard.read = null; }
}

// Retain one uncertain request across a lost response/reload. Only references
// and a random token are stored locally; the server remains the authority.
function serviceDashboardRequestToken(signature) {
  let pending = serviceDashboard.pendingRequest;
  try { pending ||= JSON.parse(sessionStorage.getItem('razvilka.service-job-request') || 'null'); } catch (_) {}
  if (!pending || pending.signature !== signature || !/^[a-f0-9]{32}$/.test(pending.key) || !Number.isFinite(pending.at) || Date.now() - pending.at >= 86400000 || Date.now() < pending.at) {
    const bytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(bytes);
    pending = { signature, key: Array.from(bytes, x => x.toString(16).padStart(2, '0')).join(''), at: Date.now() };
  }
  serviceDashboard.pendingRequest = pending;
  try { sessionStorage.setItem('razvilka.service-job-request', JSON.stringify(pending)); } catch (_) {}
  return pending.key;
}

function clearServiceDashboardRequestToken() {
  serviceDashboard.pendingRequest = null;
  try { sessionStorage.removeItem('razvilka.service-job-request'); } catch (_) {}
}

async function serviceDashboardStart(kind, serviceIDs) {
  if (serviceDashboard.operation || serviceDashboardJobActive() || !serviceDashboard.authenticated) return;
  const ids = [...new Set(serviceIDs)].filter(id => state.services.some(service => service.id === id));
  const revision = serviceDashboard.control?.config_revision;
  if (!ids.length || !Number.isSafeInteger(revision)) return;
  if (ids.length > (kind === 'select' ? 12 : 64)) { serviceDashboard.message = 'За один запуск доступны до 64 сервисов для проверки и до 12 для подбора. Запустите отдельные сервисы из карточек.'; renderServiceDashboardControl(); return; }
  const operation = { epoch: serviceDashboard.epoch, controller: new AbortController() };
  serviceDashboard.operation = operation;
  serviceDashboard.message = 'Запускаем проверку…';
  renderServiceDashboard();
  try {
    const intent = { kind, service_ids: ids, expected_revision: revision };
    const idempotency_key = serviceDashboardRequestToken(JSON.stringify(intent));
    const response = await api('/api/v1/service-control/jobs', { method: 'POST', signal: operation.controller.signal, body: JSON.stringify({ ...intent, idempotency_key }) });
    if (!serviceDashboardCurrent(operation)) return;
    clearServiceDashboardRequestToken();
    const job = response.job || response;
    serviceDashboard.control = { ...serviceDashboard.control, job };
    if (state.serviceControl) state.serviceControl = { ...state.serviceControl, job };
    serviceDashboard.message = '';
  } catch (error) {
    if (serviceDashboardCurrent(operation)) {
      if (error.status >= 400 && error.status < 500) clearServiceDashboardRequestToken();
      serviceDashboard.message = error.message;
    }
  } finally {
    if (serviceDashboard.operation === operation) { serviceDashboard.operation = null; renderServiceDashboard(); }
  }
}

async function serviceDashboardPing(serviceID) {
  const service = state.services.find(item => item.id === serviceID);
  const node = service && serviceDashboardPingNode(service);
  if (!node || serviceDashboard.operation || serviceDashboardJobActive() || !serviceDashboard.authenticated) return;
  const operation = { epoch: serviceDashboard.epoch, controller: new AbortController() };
  serviceDashboard.operation = operation;
  serviceDashboard.message = 'Измеряем TCP-пинг сервера. Это отдельная проверка соединения, без смены маршрута.';
  renderServiceDashboard();
  try {
    const response = await submitSelectedNodeCheck({ node_ids: [node.id], mode: 'tcp' }, { signal: operation.controller.signal });
    if (!serviceDashboardCurrent(operation)) return;
    serviceDashboard.control = { ...serviceDashboard.control, job: response.job };
    if (state.serviceControl) state.serviceControl = { ...state.serviceControl, job: response.job };
    serviceDashboard.message = '';
  } catch (error) {
    if (serviceDashboardCurrent(operation)) serviceDashboard.message = error.message;
  } finally {
    if (serviceDashboard.operation === operation) { serviceDashboard.operation = null; renderServiceDashboard(); }
  }
}

async function serviceDashboardCancel() {
  const job = serviceDashboard.control?.job;
  if (!job?.id || !job.mode?.startsWith('service-') || serviceDashboard.operation || !serviceDashboardJobActive()) return;
  const operation = { epoch: serviceDashboard.epoch, controller: new AbortController() };
  serviceDashboard.operation = operation;
  renderServiceDashboardControl();
  try {
    await api(`/api/v1/service-control/current?job_id=${encodeURIComponent(job.id)}`, { method: 'DELETE', signal: operation.controller.signal });
    if (serviceDashboardCurrent(operation)) serviceDashboard.message = 'Останавливаем проверку. Дождитесь завершения очистки.';
  } catch (error) {
    if (serviceDashboardCurrent(operation)) serviceDashboard.message = error.message;
  } finally {
    if (serviceDashboard.operation === operation) { serviceDashboard.operation = null; await refreshServiceControl(); }
  }
}

async function serviceDashboardSaveSchedule(event) {
  event?.preventDefault();
  if (serviceDashboard.operation || !serviceDashboard.scheduleDirty || !Number.isSafeInteger(serviceDashboard.scheduleRevision)) return;
  const schedule = { enabled: $('#serviceScheduleEnabled').checked, interval_seconds: Number($('#serviceScheduleInterval').value), service_ids: [...serviceDashboard.scheduleServiceIDs] };
  if (!Number.isInteger(schedule.interval_seconds) || schedule.interval_seconds < 60 || schedule.interval_seconds > 86400) return;
  if (schedule.service_ids.length > 64 || schedule.enabled && !schedule.service_ids.length) { serviceDashboard.message = 'В расписании должно быть от 1 до 64 сервисов.'; renderServiceDashboardControl(); return; }
  const operation = { epoch: serviceDashboard.epoch, controller: new AbortController() };
  serviceDashboard.operation = operation;
  renderServiceDashboardControl();
  try {
    const control = await api('/api/v1/service-control', { method: 'PUT', signal: operation.controller.signal, body: JSON.stringify({ expected_revision: serviceDashboard.scheduleRevision, schedule, confirm: 'SAVE_SERVICE_CONTROL' }) });
    if (!serviceDashboardCurrent(operation)) return;
    if (typeof acceptWorkspaceControl === 'function') acceptWorkspaceControl(control);
    else state.serviceControl = control;
    serviceDashboard.control = state.serviceControl || control;
    serviceDashboard.scheduleDirty = false;
    serviceDashboard.message = 'Расписание сохранено. Оно запускает только проверки доступности.';
  } catch (error) {
    if (serviceDashboardCurrent(operation)) {
      serviceDashboard.message = error.message;
      if (error.status === 409) { serviceDashboard.scheduleDirty = false; await refreshServiceControl(); }
    }
  } finally {
    if (serviceDashboard.operation === operation) { serviceDashboard.operation = null; renderServiceDashboardControl(); }
  }
}

async function serviceDashboardEdit(serviceID, changes) {
  const service = state.services.find(item => item.id === serviceID);
  if (!service || serviceDashboard.edit || !serviceDashboard.authenticated) return;
  const snapshot = { enabled: !!service.enabled, route: service.route, sources: [...(service.sources || [])], ...changes };
  const edit = { epoch: serviceDashboard.epoch, controller: new AbortController() };
  serviceDashboard.edit = edit;
  renderServiceDashboard();
  try {
    const result = await api(`/api/v1/services/${encodeURIComponent(serviceID)}`, { method: 'PUT', signal: edit.controller.signal, body: JSON.stringify(snapshot) });
    if (serviceDashboard.edit !== edit || edit.epoch !== serviceDashboard.epoch || edit.controller.signal.aborted) return;
    if (result.id !== serviceID || result.ok !== true) throw new Error('Не удалось подтвердить изменение сервиса. Обновите страницу.');
    serviceDashboard.message = 'Выбор сохранён. Нажмите «Проверить и применить», чтобы изменить действующий маршрут.';
    const [status, services] = await Promise.all([api('/api/v1/status', { signal: edit.controller.signal }), api('/api/v1/services', { signal: edit.controller.signal })]);
    if (serviceDashboard.edit !== edit || edit.epoch !== serviceDashboard.epoch || edit.controller.signal.aborted) return;
    state.status = status; state.services = services;
    renderStatus(); renderOverviewQuickServices(); renderOverviewServices(); renderReadiness(); renderSettings();
  } catch (error) {
    if (serviceDashboard.edit === edit && edit.epoch === serviceDashboard.epoch && !edit.controller.signal.aborted) serviceDashboard.message = error.message;
  } finally {
    if (serviceDashboard.edit === edit) { serviceDashboard.edit = null; renderServiceDashboard(); }
  }
}

function serviceWebsiteHosts(input) {
  const tokens = String(input).trim().split(/[\s,]+/).filter(Boolean);
  if (!tokens.length || tokens.length > 12) throw new Error('Введите от 1 до 12 адресов сайтов, каждый с новой строки.');
  return [...new Set(tokens.map(token => {
    if (token.length > 2048 || /[\u0000-\u001f\u007f]/.test(token)) throw new Error('Адрес сайта слишком длинный или содержит недопустимые символы.');
    let url;
    try { url = new URL(token.includes('://') ? token : `https://${token}`); } catch (_) { throw new Error('Не удалось прочитать адрес сайта. Пример: youtube.com'); }
    const host = url.hostname.toLowerCase().replace(/\.$/, '');
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || host.length > 253 || !host.includes('.') || !/^[a-z0-9.-]+$/.test(host) || /^\d+(\.\d+){3}$/.test(host) || host.split('.').some(label => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) throw new Error('Введите имя сайта без пароля, локального адреса или IP. Пример: youtube.com');
    return host;
  }))];
}

function openServiceWebsiteDiscovery() {
  setView('services');
  $('#serviceWebsiteDiscovery').open = true;
  $('#serviceWebsiteInput').focus();
}

function renderServiceWebsiteResults() {
  $('#serviceWebsiteResults').innerHTML = serviceDashboard.lookupResults.map((entry, index) => `<div class="sd-website-result"><b>${esc(entry.host)}</b>${entry.error ? `<p>${esc(entry.error)}</p>` : entry.matches.length ? `<p>${entry.matches.length > 1 ? 'Адрес входит в несколько сервисов. Выберите нужный:' : 'Найден в каталоге:'}</p><div>${entry.matches.map(match => `<button class="secondary" type="button" data-sd-match="${esc(match.service_id)}">${esc(match.service_name)} · ${esc(match.matched_rule)}</button>`).join('')}</div>` : `<p>В каталоге нет совпадений. Можно подготовить свой сервис и проверить настройки перед добавлением.</p><button class="secondary" type="button" data-sd-create="${index}">Создать сервис для этого сайта…</button>`}</div>`).join('');
}

async function discoverServiceWebsites(event) {
  event?.preventDefault();
  let hosts;
  try { hosts = serviceWebsiteHosts($('#serviceWebsiteInput').value); } catch (error) { $('#serviceWebsiteStatus').textContent = error.message; return; }
  serviceDashboard.lookup?.controller.abort();
  const lookup = { controller: new AbortController(), epoch: serviceDashboard.epoch };
  serviceDashboard.lookup = lookup;
  serviceDashboard.lookupResults = [];
  $('#serviceWebsiteFind').disabled = true;
  $('#serviceWebsiteCancel').hidden = false;
  $('#serviceWebsiteStatus').textContent = 'Сопоставляем адреса с локальным каталогом…';
  renderServiceWebsiteResults();
  const current = () => serviceDashboard.lookup === lookup && lookup.epoch === serviceDashboard.epoch && !lookup.controller.signal.aborted;
  try {
    for (const host of hosts) {
      const result = await api(`/api/v1/diagnostics/domain?q=${encodeURIComponent(host)}`, { signal: lookup.controller.signal });
      if (!current()) return;
      serviceDashboard.lookupResults.push({ host, matches: (result.matches || []).filter(match => state.services.some(service => service.id === match.service_id)) });
      renderServiceWebsiteResults();
    }
    if (current()) $('#serviceWebsiteStatus').textContent = 'Поиск завершён. Нажмите на найденный сервис, чтобы открыть его настройки. Маршруты не изменены.';
  } catch (error) {
    if (current()) $('#serviceWebsiteStatus').textContent = error.message;
  } finally {
    if (serviceDashboard.lookup === lookup) { serviceDashboard.lookup = null; $('#serviceWebsiteFind').disabled = false; $('#serviceWebsiteCancel').hidden = true; }
  }
}

function cancelServiceWebsiteDiscovery() {
  const searching = !!serviceDashboard.lookup;
  serviceDashboard.lookup?.controller.abort();
  serviceDashboard.lookup = null;
  $('#serviceWebsiteFind').disabled = false;
  $('#serviceWebsiteCancel').hidden = true;
  if (searching) $('#serviceWebsiteStatus').textContent = 'Поиск остановлен.';
}

function serviceDashboardLifecycle(clear = false) {
  serviceDashboard.epoch++;
  serviceDashboard.read?.abort(); serviceDashboard.read = null;
  serviceDashboard.operation?.controller.abort(); serviceDashboard.operation = null;
  serviceDashboard.edit?.controller.abort(); serviceDashboard.edit = null;
  clearTimeout(serviceDashboard.poll); serviceDashboard.poll = null;
  cancelServiceWebsiteDiscovery();
  if (clear) {
    serviceDashboard.control = null; serviceDashboard.lookupResults = [];
    serviceDashboard.scheduleDirty = false; serviceDashboard.message = '';
    $('#serviceWebsiteStatus').textContent = '';
    $('#serviceWebsiteInput').value = ''; renderServiceWebsiteResults();
  }
}

function startServiceDashboardPolling() {
  clearTimeout(serviceDashboard.poll);
  if (!serviceDashboard.authenticated) return;
  refreshServiceControl();
  const tick = async () => {
    if (!serviceDashboard.authenticated || state.currentView !== 'services') return;
    const epoch = serviceDashboard.epoch;
    await refreshServiceControl();
    if (epoch === serviceDashboard.epoch && serviceDashboard.authenticated && state.currentView === 'services') serviceDashboard.poll = setTimeout(tick, serviceDashboardJobActive() ? 1500 : 10000);
  };
  serviceDashboard.poll = setTimeout(tick, 1500);
}

function bindServiceDashboard() {
  $('#serviceList').addEventListener('click', event => {
    const button = event.target.closest('button');
    if (!button || button.disabled) return;
    const data = button.dataset;
    if (data.sdExpand) { serviceDashboard.expanded.has(data.sdExpand) ? serviceDashboard.expanded.delete(data.sdExpand) : serviceDashboard.expanded.add(data.sdExpand); renderServiceDashboard(); }
    if (data.sdToggle) { const service = state.services.find(item => item.id === data.sdToggle); if (service) serviceDashboardEdit(service.id, { enabled: !service.enabled }); }
    if (data.sdScope) openServiceScope(data.sdScope);
    if (data.sdLists) showServiceDetails(data.sdLists);
    if (data.sdCustom) openCustomServiceDialog(data.sdCustom);
    if (data.sdDelete) deleteCustomService(data.sdDelete);
    if (data.sdSetup) openRouteInstallation(data.sdSetup);
    if (data.sdNfqws) showNFQWS2Details(data.sdNfqws);
    if (data.sdCheck) serviceDashboardStart('check', [data.sdCheck]);
    if (data.sdPing) serviceDashboardPing(data.sdPing);
    if (data.sdSelect) serviceDashboardStart('select', [data.sdSelect]);
    if (data.sdUse) {
      const service = state.services.find(item => item.id === data.sdService);
      const result = service && serviceDashboardResult(service);
      if (result?.recommended_node_id === data.sdUse && serviceDashboardFresh(result) && result.available === true && result.status === 'pass') openNodeCheck(data.sdUse, data.sdService);
    }
  });
  $('#serviceList').addEventListener('change', event => {
    const select = event.target.closest('[data-sd-route]');
    if (select) serviceDashboardEdit(select.dataset.sdRoute, { route: select.value });
  });
  $('#serviceList').addEventListener('focusout', event => { if (event.target.matches?.('[data-sd-route]')) queueMicrotask(renderServiceDashboard); });
  $('#serviceExpandAll').addEventListener('click', () => {
    const visible = state.services.filter(serviceMatches);
    const collapse = visible.every(service => serviceDashboard.expanded.has(service.id));
    visible.forEach(service => collapse ? serviceDashboard.expanded.delete(service.id) : serviceDashboard.expanded.add(service.id));
    renderServiceDashboard();
  });
  $('#serviceCheckAll').addEventListener('click', () => serviceDashboardStart('check', serviceDashboardServiceIDs()));
  $('#serviceSelectAll').addEventListener('click', () => serviceDashboardStart('select', [$('#serviceAutoPickTarget').value]));
  $('#serviceCancelCheck').addEventListener('click', serviceDashboardCancel);
  $('#serviceScheduleForm').addEventListener('submit', serviceDashboardSaveSchedule);
  for (const id of ['serviceScheduleEnabled', 'serviceScheduleInterval', 'serviceScheduleAll']) $(`#${id}`).addEventListener('change', () => {
    if (!serviceDashboard.scheduleDirty) serviceDashboard.scheduleRevision = serviceDashboard.control?.config_revision;
    if (id === 'serviceScheduleAll') serviceDashboard.scheduleServiceIDs = $('#serviceScheduleAll').checked ? serviceDashboardServiceIDs() : [...(serviceDashboard.control?.schedule?.service_ids?.length ? serviceDashboard.control.schedule.service_ids : serviceDashboardServiceIDs())];
    serviceDashboard.scheduleDirty = true; renderServiceDashboardControl();
  });
  $('#serviceWebsiteForm').addEventListener('submit', discoverServiceWebsites);
  $('#serviceWebsiteCancel').addEventListener('click', cancelServiceWebsiteDiscovery);
  $('#serviceWebsiteInput').addEventListener('input', () => { if (serviceDashboard.lookup) cancelServiceWebsiteDiscovery(); });
  $('#serviceWebsiteResults').addEventListener('click', event => {
    const match = event.target.closest('[data-sd-match]');
    const create = event.target.closest('[data-sd-create]');
    if (match) {
      const service = state.services.find(item => item.id === match.dataset.sdMatch);
      if (!service) return;
      $('#serviceSearch').value = service.name; $('#serviceCategory').value = '';
      serviceDashboard.expanded.add(service.id); renderServiceDashboard();
      [...$('#serviceList').querySelectorAll('[data-sd-expand]')].find(button => button.dataset.sdExpand === service.id)?.focus();
    }
    if (create) {
      const result = serviceDashboard.lookupResults[Number(create.dataset.sdCreate)];
      if (!result || result.matches.length || !serviceDashboard.authenticated) return;
      openCustomServiceDialog();
      $('#customServiceName').value = result.host;
      $('#customServiceDomains').value = result.host;
      $('#customServiceProbe').value = `https://${result.host}/`;
    }
  });
  document.addEventListener('razvilka:view-change', event => { serviceDashboardLifecycle(); if (event.detail === 'services') startServiceDashboardPolling(); });
  document.addEventListener('razvilka:auth-required', () => { serviceDashboard.authenticated = false; clearServiceDashboardRequestToken(); serviceDashboardLifecycle(true); });
  document.addEventListener('razvilka:auth-restored', () => { serviceDashboard.authenticated = true; if (state.currentView === 'services') startServiceDashboardPolling(); });
}
