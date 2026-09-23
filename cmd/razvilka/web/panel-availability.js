/* Liveness is independent from route health. No secrets or policy are persisted. */
'use strict';
(function (root) {
  function validSnapshot(value) {
    const a = value?.admission;
    if (value?.schema !== 1 || value?.name !== 'RAZVILKA' || value?.panel !== 'responding' || value?.dataplane !== 'not-checked') return false;
    if (!a || !['idle', 'shared', 'busy', 'recovery-required'].includes(a.state)) return false;
    if (!Number.isSafeInteger(a.active) || a.active < 0 || typeof a.exclusive !== 'boolean' || typeof a.fenced !== 'boolean') return false;
    const expected = a.fenced ? 'recovery-required' : a.exclusive ? 'busy' : a.active ? 'shared' : 'idle';
    return a.state === expected && (!a.exclusive || a.active === 1);
  }

  function describe(value) {
    if (!value) return '';
    if (value.kind === 'unsupported') return 'Быстрая диагностика недоступна. Сервер и интерфейс должны быть обновлены вместе.';
    if (value.kind === 'unreachable') return 'Панель не ответила на быструю проверку. Последние данные сохранены; это не доказывает остановку обходов.';
    if (value.admission?.state === 'recovery-required') return 'Панель отвечает. Изменения приостановлены до восстановления журнала; обычное применение не снимет эту защиту.';
    if (value.admission?.state === 'busy') return 'Панель отвечает. Выполняется операция; можно переходить между разделами. Изменение маршрутов временно занято.';
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
  root.RazvilkaPanelAvailability = Object.freeze({ createController, describe, validSnapshot, needsAttention });
  if (typeof document === 'undefined' || typeof api !== 'function' || typeof state === 'undefined') return;

  let panel = null, text = null, timestamp = null, retry = null;
  const visible = () => state.authenticated === true && !document.hidden;
  const render = (value) => {
    state.panelAvailability = visible() ? value : null;
    if (!needsAttention(value) || !visible()) { if (panel) panel.hidden = true; return; }
    if (!panel) {
      const notice = document.getElementById('notice');
      if (!notice?.parentNode) return;
      panel = document.createElement('section'); panel.id = 'panelAvailability'; panel.className = 'panel-availability';
      panel.setAttribute('role', 'status'); panel.setAttribute('aria-live', 'polite'); panel.setAttribute('aria-atomic', 'true');
      const copy = document.createElement('div');
      text = document.createElement('span'); timestamp = document.createElement('small');
      copy.append(text, timestamp);
      retry = document.createElement('button'); retry.type = 'button'; retry.textContent = 'Обновить';
      retry.addEventListener('click', () => { monitor.start(); void monitor.refresh(); });
      panel.append(copy, retry); notice.parentNode.insertBefore(panel, notice);
    }
    panel.hidden = false;
    panel.dataset.state = value.kind === 'responding' ? value.admission.state : value.kind;
    const message = describe(value);
    if (text.textContent !== message) text.textContent = message;
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
    publish: render,
    onAuthRequired: () => showAuth({ auth_required: true, authenticated: false }, 'Сессия завершилась. Войдите снова.'),
  });
  document.addEventListener('razvilka:auth-restored', monitor.start);
  document.addEventListener('razvilka:auth-required', () => { monitor.stop(); render(null); });
  document.addEventListener('visibilitychange', () => { if (visible()) monitor.start(); else monitor.stop(); });
  if (visible()) monitor.start();
})(globalThis);
