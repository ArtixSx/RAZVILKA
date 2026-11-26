/* Liveness is independent from route health. No secrets or policy are persisted. */
'use strict';
(function (root) {
  const phases = Object.freeze({
    preparing: 'Подготовка проверки', maintenance: 'Обслуживание приложения и компонентов',
    subscriptions: 'Подготовка подписок', selecting: 'Выбор сервиса',
    activating: 'Подготовка выбранных сервисов', checking: 'Проверка и применение сервиса',
    reserves: 'Подготовка пополнения резервов', cleanup: 'Завершение операции и очистка',
    'update-handoff': 'Передача управления обновлению',
  });
  const maxProgressSeconds = 7 * 24 * 60 * 60;
  const progressSeconds = value => Number.isSafeInteger(value) && value >= 0 && value <= maxProgressSeconds;
  const progressTime = value => typeof value === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
    && Number.isFinite(Date.parse(value));
  function duration(seconds) {
    if (seconds < 60) return `${seconds} с`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} мин ${seconds % 60} с`;
    return `${Math.floor(seconds / 3600)} ч ${Math.floor(seconds % 3600 / 60)} мин`;
  }

  // Progress is a separate observation of the current gate holder. It never
  // refreshes a settings snapshot or grants permission to change a route.
  // An unknown/new/malformed DTO falls back to the existing busy explanation.
  function progressView(admission, services = []) {
    const p = admission?.progress;
    if (admission?.state !== 'busy' || admission.active !== 1 || admission.exclusive !== true || admission.fenced !== false
      || !p || Array.isArray(p) || !Number.isSafeInteger(p.id) || p.id < 1 || p.kind !== 'autonomy'
      || !Object.prototype.hasOwnProperty.call(phases, p.phase)
      || !progressTime(p.started_at) || !progressTime(p.phase_started_at)
      || Date.parse(p.phase_started_at) < Date.parse(p.started_at)
      || !progressSeconds(p.elapsed_seconds) || !progressSeconds(p.phase_seconds) || p.phase_seconds > p.elapsed_seconds
      || Date.parse(p.phase_started_at) > Date.parse(p.started_at) + (p.elapsed_seconds + 1) * 1000
      || typeof p.deadline_exceeded !== 'boolean'
      || p.service_id !== undefined && (typeof p.service_id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(p.service_id))) return null;
    const deadline = p.deadline_at !== undefined && p.deadline_at !== null;
    const remaining = p.remaining_seconds !== undefined && p.remaining_seconds !== null;
    if (deadline && (!progressTime(p.deadline_at) || Date.parse(p.deadline_at) < Date.parse(p.started_at))
      || remaining && (!deadline || !progressSeconds(p.remaining_seconds))
      || p.deadline_exceeded && (!deadline || remaining && p.remaining_seconds !== 0)) return null;
    const service = p.service_id && Array.isArray(services) ? services.find(s => s?.id === p.service_id) : null;
    const name = typeof service?.name === 'string' && service.name.length > 0 && service.name.length <= 120 ? service.name : '';
    const activity = phases[p.phase] + (name ? ` · ${name}` : '');
    const timing = p.deadline_exceeded
      ? `Прошло ${duration(p.elapsed_seconds)}. Лимит времени истёк; ожидаем завершения и очистки.`
      : `Прошло ${duration(p.elapsed_seconds)} · На этапе ${duration(p.phase_seconds)}`
        + (remaining ? ` · До лимита ${duration(p.remaining_seconds)}` : '');
    return { activity, timing, deadlineExceeded: p.deadline_exceeded };
  }

  function validSnapshot(value) {
    const a = value?.admission;
    if (value?.schema !== 1 || value?.name !== 'RAZVILKA' || value?.panel !== 'responding' || value?.dataplane !== 'not-checked') return false;
    if (!a || !['idle', 'shared', 'busy', 'recovery-required'].includes(a.state)) return false;
    if (!Number.isSafeInteger(a.active) || a.active < 0 || typeof a.exclusive !== 'boolean' || typeof a.fenced !== 'boolean') return false;
    const expected = a.fenced ? 'recovery-required' : a.exclusive ? 'busy' : a.active ? 'shared' : 'idle';
    return a.state === expected && (!a.exclusive || a.active === 1);
  }

  function describe(value, services = []) {
    if (!value) return '';
    if (value.kind === 'unsupported') return 'Быстрая диагностика недоступна. Сервер и интерфейс должны быть обновлены вместе.';
    if (value.kind === 'unreachable') return 'Панель не ответила на быструю проверку. Последние данные сохранены; это не доказывает остановку обходов.';
    if (value.admission?.state === 'recovery-required') return 'Панель отвечает. Изменения приостановлены до восстановления журнала; обычное применение не снимет эту защиту.';
    if (value.admission?.state === 'busy') {
      const progress = progressView(value.admission, services);
      if (progress) return `Панель отвечает. Сейчас: ${progress.activity}. ` + (progress.deadlineExceeded
        ? 'Лимит времени истёк; операция остаётся занятой до завершения и очистки.'
        : 'Можно переходить между разделами; действия подождут завершения операции.');
      // The server names the running operation in fixed words; no timer text,
      // so the live region does not change on every heartbeat.
      const operation = typeof value.admission.operation === 'string' && value.admission.operation ? `Сейчас выполняется: ${value.admission.operation}.` : 'Выполняется операция.';
      return `Панель отвечает. ${operation} Можно переходить между разделами; действия подождут её завершения.`;
    }
    return 'Панель отвечает. Доступность сервисов и работа обходов проверяются отдельно.';
  }

  function createController(options) {
    if (typeof options?.request !== 'function' || typeof options?.publish !== 'function') throw new TypeError('request and publish are required');
    const isVisible = options.isVisible || (() => true);
    const later = options.setTimeout || root.setTimeout.bind(root);
    const clear = options.clearTimeout || root.clearTimeout.bind(root);
    const now = options.now || Date.now;
    let enabled = false, epoch = 0, timer = null, inFlight = null, failures = 0, lastSuccess = null;
    const current = (ticket) => enabled && ticket.epoch === epoch && isVisible();
    const emit = (value) => { try { options.publish(value); } catch (_) { /* A view error must not wedge the polling lifecycle. */ } };
    function schedule(delay) {
      if (timer !== null) clear(timer);
      timer = null;
      if (!enabled || !isVisible()) return;
      timer = later(() => { timer = null; void refresh(); }, delay);
    }
    function stop() {
      enabled = false; epoch++; lastSuccess = null;
      if (timer !== null) clear(timer);
      timer = null;
      inFlight?.controller.abort();
      inFlight = null;
    }
    function start() {
      if (enabled) return;
      enabled = true;
      failures = 0;
      schedule(0);
    }
    function refresh() {
      if (!enabled || !isVisible()) return Promise.resolve(false);
      if (inFlight) return inFlight.promise;
      if (timer !== null) clear(timer);
      timer = null;
      const ticket = { epoch, controller: new AbortController(), promise: null };
      inFlight = ticket;
      let nextDelay = 15000;
      ticket.promise = Promise.resolve().then(async () => {
        if (!current(ticket)) return false;
        try {
          const value = await options.request({ signal: ticket.controller.signal, readTimeoutMs: 3000 });
          if (!current(ticket)) return false;
          if (!validSnapshot(value)) throw new Error('Incomplete liveness response');
          lastSuccess = now(); failures = 0;
          nextDelay = value.admission.state === 'busy' ? 5000 : 15000;
          emit({ kind: 'responding', admission: value.admission, receivedAt: lastSuccess, dataplane: 'not-checked' });
          return true;
        } catch (error) {
          if (!current(ticket)) return false;
          if (error?.status === 401) {
            stop(); lastSuccess = null;
            emit(null);
            try { options.onAuthRequired?.(); } catch (_) { /* No stale response is published. */ }
            return false;
          }
          if (error?.status === 404) {
            // Avoid an endless retry storm when a browser/server pair is mixed.
            emit({ kind: 'unsupported', receivedAt: lastSuccess });
            stop();
            return false;
          }
          failures = Math.min(failures + 1, 5);
          nextDelay = Math.min(60000, 5000 * (2 ** (failures - 1)));
          emit({ kind: 'unreachable', receivedAt: lastSuccess });
          return false;
        } finally {
          if (inFlight === ticket) inFlight = null;
          if (current(ticket)) schedule(nextDelay);
        }
      });
      return ticket.promise;
    }
    return Object.freeze({ start, stop, refresh });
  }

  function needsAttention(value) {
    return !!value && (value.kind !== 'responding' || ['busy', 'recovery-required'].includes(value.admission?.state));
  }
  root.RazvilkaPanelAvailability = Object.freeze({ createController, describe, validSnapshot, needsAttention, progressView });
  if (typeof document === 'undefined' || typeof api !== 'function' || typeof state === 'undefined') return;

  let panel = null, text = null, progress = null, timestamp = null, retry = null;
  const visible = () => state.authenticated === true && !document.hidden;
  const render = (value) => {
    state.panelAvailability = visible() ? value : null;
    document.dispatchEvent(new Event('razvilka:panel-availability'));
    if (!needsAttention(value) || !visible()) { if (panel) panel.hidden = true; return; }
    if (!panel) {
      const notice = document.getElementById('notice');
      if (!notice?.parentNode) return;
      panel = document.createElement('section'); panel.id = 'panelAvailability'; panel.className = 'panel-availability';
      const copy = document.createElement('div');
      text = document.createElement('span'); progress = document.createElement('small'); timestamp = document.createElement('small');
      // Announce phase/deadline changes, not every elapsed-time heartbeat.
      text.setAttribute('role', 'status'); text.setAttribute('aria-live', 'polite'); text.setAttribute('aria-atomic', 'true');
      copy.append(text, progress, timestamp);
      retry = document.createElement('button'); retry.type = 'button'; retry.textContent = 'Обновить';
      retry.addEventListener('click', () => { monitor.start(); void monitor.refresh(); });
      panel.append(copy, retry); notice.parentNode.insertBefore(panel, notice);
    }
    panel.hidden = false;
    panel.dataset.state = value.kind === 'responding' ? value.admission.state : value.kind;
    const message = describe(value, state.services);
    if (text.textContent !== message) text.textContent = message;
    const progressText = progressView(value.admission, state.services)?.timing || '';
    progress.hidden = !progressText;
    if (progress.textContent !== progressText) progress.textContent = progressText;
    // Do not churn the live region every heartbeat. Update the timestamp only
    // when the status message changes or the minute changes.
    const checked = value.receivedAt == null ? 'Успешной проверки ещё не было.'
      : `Последний ответ панели: ${new Date(value.receivedAt).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}`;
    if (timestamp.textContent !== checked) timestamp.textContent = checked;
    retry.hidden = value.kind === 'responding';
    retry.textContent = value.kind === 'unreachable' || value.kind === 'unsupported' ? 'Повторить' : 'Обновить';
  };
  const monitor = createController({
    request: (options) => api('/api/v1/panel/availability', options),
    isVisible: visible,
    publish: (value) => {
      render(value);
      // Reuse this bounded, visibility-aware heartbeat; no second timer.
      if (value?.kind === 'responding' && typeof refreshPanelInventory === 'function') void refreshPanelInventory();
    },
    onAuthRequired: () => showAuth({ auth_required: true, authenticated: false }, 'Сессия завершилась. Войдите снова.'),
  });
  document.addEventListener('razvilka:auth-restored', monitor.start);
  document.addEventListener('razvilka:auth-required', () => { monitor.stop(); render(null); });
  document.addEventListener('visibilitychange', () => { if (visible()) monitor.start(); else monitor.stop(); });
  if (visible()) monitor.start();
})(globalThis);
