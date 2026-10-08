/* The managed bundle has its own source reader and installer. Package inventory
 * and saved compatibility checks never stand in for its current installed GET. */
(function (root) {
  'use strict';
  const base = '/api/v1/components/nfqws2/managed-bundle';
  const text = (value, limit = 256) => typeof value === 'string' && value.length > 0 && value.length <= limit;
  const identity = value => text(value?.provider_id) && text(value.flavor) && /^[a-f0-9]{64}$/.test(value.manifest_sha256 || '');
  function validPlan(value) {
    return Number.isSafeInteger(value?.revision) && value.revision >= 0 && typeof value.ready === 'boolean'
      && typeof value.code === 'string' && value.code.length <= 128 && typeof value.reason === 'string' && value.reason.length <= 4096
      && identity(value.bundle) && text(value.bundle.architecture) && typeof value.installed_idle === 'boolean'
      && typeof value.compatibility_ready === 'boolean' && value.working_routes_changed === false;
  }
  function validInstalled(value) {
    return value?.installed_idle === true && identity(value) && text(value.receipt_id) && value.working_routes_changed === false;
  }
  function matches(plan, installed) {
    return validPlan(plan) && validInstalled(installed) && ['provider_id', 'flavor', 'manifest_sha256'].every(key => plan.bundle[key] === installed[key]);
  }
  function validReceipt(value) {
    return value?.schema === 1 && value.state === 'ready-idle' && identity(value) && text(value.transaction_id) && text(value.generation_path, 4096);
  }
  function receiptMatches(receipt, observation) {
    return validReceipt(receipt) && validInstalled(observation) && receipt.transaction_id === observation.receipt_id
      && ['provider_id', 'flavor', 'manifest_sha256'].every(key => receipt[key] === observation[key]);
  }
  root.RazvilkaManagedNFQBundle = Object.freeze({ validPlan, validInstalled, matches, validReceipt, receiptMatches });
  if (typeof document === 'undefined') return;

  const views = new Set(['engines', 'engineconfig', 'updates']);
  const managed = { epoch: 0, read: null, action: null, plan: null, installed: null, revision: null, received: 0, error: '', unknownWrite: false };
  const active = () => state.authenticated && views.has(state.currentView) && !document.hidden;
  const fresh = () => validPlan(managed.plan) && managed.received > 0 && Date.now() - managed.received < 60000 && !managed.error;
  const busy = () => !!managed.read || !!managed.action || !!state.componentOperation || !!state.componentRefreshRequest;
  const currentRevision = () => managed.revision === managed.plan?.revision && !(Number.isSafeInteger(state.status?.revision) && state.status.revision > managed.plan.revision);
  const installed = () => fresh() && matches(managed.plan, managed.installed);
  const allowed = () => active() && fresh() && currentRevision() && managed.plan.ready && !installed() && !busy() && !managed.unknownWrite
    && !(typeof componentRecoveryFence === 'function' && componentRecoveryFence());

  function card(id) {
    if (id !== 'nfqws2') return '';
    const ready = fresh(), present = installed();
    const note = managed.unknownWrite ? [managed.error, 'Исход установки ещё не подтверждён. Прочитайте состояние и журнал восстановления; повторная установка заблокирована.'].filter(Boolean).join(' ')
      : managed.error || (present ? 'Управляемый пакет установлен и сейчас не используется для рабочих маршрутов.'
        : !ready ? 'Прочитайте план и текущее состояние управляемого пакета.'
          : !currentRevision() ? 'Настройки изменились. Прочитайте новый план перед установкой.'
            : managed.plan.reason || (managed.plan.ready ? 'План готов. Установку нужно запустить отдельно.' : 'Установка сейчас недоступна.'));
    const bundle = ready ? `<small>Пакет: ${esc(managed.plan.bundle.flavor)} · ${esc(managed.plan.bundle.architecture)}</small>` : '';
    return `<section data-managed-nfq-panel aria-label="Управляемый пакет NFQWS2"><b>Управляемый пакет NFQWS2</b><p role="status">${esc(note)}</p>${bundle}<small>Установка файлов не включает обход. Совместимость и соединение проверяются отдельно.</small><div class="ui3-engine-actions"><button type="button" class="secondary" data-managed-nfq-read data-rz-focus="managed-nfq-read" ${busy() ? 'disabled' : ''}>${managed.read ? 'Читаем…' : 'Прочитать план и состояние'}</button><button type="button" class="primary" data-managed-nfq-install data-rz-focus="managed-nfq-install" ${allowed() ? '' : 'disabled'}>${managed.action ? 'Устанавливаем…' : 'Установить управляемый пакет'}</button></div></section>`;
  }
  function render() {
    if (typeof renderComponents === 'function') renderComponents();
    if (typeof renderInterfaceEngines === 'function' && views.has(state.currentView)) renderInterfaceEngines();
  }
  function expire() { managed.received = 0; managed.installed = null; }
  async function read(force = false) {
    if (!active() || managed.action && !force) return false;
    if (managed.read) return managed.read.promise;
    const ticket = { epoch: managed.epoch, controller: new AbortController(), promise: null };
    managed.read = ticket;
    ticket.promise = Promise.resolve().then(async () => {
      try {
        const options = { signal: ticket.controller.signal, readTimeoutMs: 20000, cache: 'no-store' };
        const results = await Promise.allSettled([api(base + '/plan', options), api(base + '/installed', options), api('/api/v1/status', options)]);
        if (ticket.epoch !== managed.epoch || managed.read !== ticket || !active()) return false;
        const unauthorized = results.find(result => result.status === 'rejected' && result.reason?.status === 401);
        if (unauthorized) throw unauthorized.reason;
        const [planResult, installedResult, statusResult] = results;
        if (planResult.status === 'rejected') throw planResult.reason;
        if (!validPlan(planResult.value)) throw new Error('Получен неполный план управляемого пакета. Установка заблокирована.');
        if (statusResult.status === 'rejected') throw statusResult.reason;
        if (!Number.isSafeInteger(statusResult.value?.revision) || statusResult.value.revision < 0) throw new Error('Текущая ревизия настроек не прочитана. Установка заблокирована.');
        let observation = null;
        if (installedResult.status === 'fulfilled') {
          if (!validInstalled(installedResult.value)) throw new Error('Установка управляемого пакета ещё не подтверждена.');
          observation = installedResult.value;
        } else if (installedResult.reason?.status !== 503 || installedResult.reason?.payload?.code !== 'MANAGED_NFQWS_SOURCE_UNAVAILABLE'
          || installedResult.reason?.payload?.installed_idle !== false) throw installedResult.reason;
        managed.plan = planResult.value; managed.installed = observation; managed.revision = statusResult.value.revision;
        managed.received = Date.now(); managed.error = '';
        if (matches(managed.plan, observation)) managed.unknownWrite = false;
        return true;
      } catch (error) {
        if (ticket.epoch !== managed.epoch || managed.read !== ticket) return false;
        expire(); managed.error = error?.message || 'План и состояние не прочитаны.';
        if (error.status === 401) showAuth({ ...state.status, authenticated: false }, error.message);
        return false;
      } finally {
        if (managed.read === ticket) { managed.read = null; render(); }
      }
    });
    render();
    return ticket.promise;
  }
  async function install() {
    if (!allowed()) return false;
    const ticket = { id: 'nfqws2', action: 'managed-bundle-install', epoch: managed.epoch, plan: managed.plan, sent: false, controller: new AbortController() };
    managed.action = ticket; state.componentOperation = ticket;
    const current = () => ticket.epoch === managed.epoch && managed.action === ticket && state.authenticated;
    const timer = setTimeout(() => ticket.controller.abort(), 120000);
    render();
    try {
      managed.unknownWrite = true; ticket.sent = true;
      const result = await api(base + '/install', { method: 'POST', signal: ticket.controller.signal, body: JSON.stringify({ expected_revision: ticket.plan.revision }) });
      if (!current()) return false;
      if (result?.ok !== true || result.installed_idle !== true || typeof result.compatibility_ready !== 'boolean'
        || result.working_routes_changed !== false || !validReceipt(result.receipt)) throw new Error('Сервер не подтвердил установку управляемого пакета. Повторная установка не отправляется.');
      if (!await read(true) || !current() || !matches(ticket.plan, managed.installed) || !receiptMatches(result.receipt, managed.installed)) throw new Error('Установка отправлена, но независимое чтение ещё не подтвердило этот пакет и квитанцию.');
      managed.unknownWrite = false;
      state.inventoryInvalidatedAt = Date.now();
      if (typeof refreshComponents === 'function') await refreshComponents(false);
      if (!current()) return false;
      showNotice('review', 'Управляемый пакет установлен без запуска маршрутов', 'Текущее состояние прочитано отдельно. Проверку совместимости и доступности сервиса выполните отдельно.');
      return true;
    } catch (error) {
      if (!current()) return false;
      expire(); managed.unknownWrite = true; managed.error = error.message || 'Исход установки ещё не подтверждён.';
      if (error.status === 409 && error.payload?.code === 'MANAGED_NFQWS_INSTALL_REFUSED') {
        managed.unknownWrite = false;
        managed.error = 'Установка отклонена. Прочитайте новый план и причину отказа перед следующим действием.';
      } else if (error.status === 503 && error.payload?.code === 'MANAGED_NFQWS_RECOVERY_REQUIRED') {
        managed.error = 'Установка требует восстановления. Прочитайте журнал обновления; установку не повторяйте.';
        if (typeof componentUpdatePending === 'function') componentUpdatePending();
      }
      if (error.status === 401) showAuth({ ...state.status, authenticated: false }, error.message);
      return false;
    } finally {
      clearTimeout(timer);
      if (state.componentOperation === ticket) state.componentOperation = null;
      if (managed.action === ticket) { managed.action = null; render(); }
    }
  }
  root.managedNFQBundleCard = card;
  root.refreshManagedNFQBundle = async journal => {
    const epoch = managed.epoch, transaction = journal?.transaction;
    const settled = typeof RazvilkaComponentRecovery !== 'undefined' && RazvilkaComponentRecovery.valid(journal)
      && journal.recovery_required === false && transaction?.schema_version === 3 && transaction.component === 'nfqws2'
      && ['accepted-installed-idle', 'rolled-back', 'abandoned'].includes(transaction.phase);
    const observed = await read();
    if (observed && epoch === managed.epoch && settled && currentRevision() && journal.revision === managed.plan.revision
      && (installed() || ['rolled-back', 'abandoned'].includes(transaction.phase))) {
      managed.unknownWrite = false; render();
    }
    return observed;
  };
  document.addEventListener('click', event => {
    if (event.target.closest?.('[data-managed-nfq-read]') && !busy()) void read();
    const button = event.target.closest?.('[data-managed-nfq-install]');
    if (button && !button.disabled) void install();
  });
  document.addEventListener('razvilka:auth-required', () => {
    managed.epoch++; managed.read?.controller.abort(); managed.action?.controller.abort();
    if (state.componentOperation === managed.action) state.componentOperation = null;
    managed.read = null; managed.action = null; managed.plan = null; managed.revision = null; managed.error = ''; managed.unknownWrite = false; expire(); render();
  });
  document.addEventListener('razvilka:view-change', event => {
    if (!views.has(event.detail)) {
      managed.epoch++; managed.read?.controller.abort(); managed.read = null;
      if (managed.action?.sent) { managed.unknownWrite = true; managed.error = 'Исход установки ещё не прочитан. Прочитайте состояние без повторной установки.'; }
      if (state.componentOperation === managed.action) state.componentOperation = null;
      managed.action = null; expire();
    }
  });
})(typeof globalThis === 'undefined' ? window : globalThis);
