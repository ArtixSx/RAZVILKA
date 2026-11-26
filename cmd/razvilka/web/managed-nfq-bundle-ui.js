/* The managed bundle has its own source reader and installer. Package inventory
 * and saved compatibility checks never stand in for its current installed GET. */
(function (root) {
  'use strict';
  const base = '/api/v1/components/nfqws2/managed-bundle';
  const text = (value, limit = 256) => typeof value === 'string' && value.length > 0 && value.length <= limit;
  const identity = value => text(value?.provider_id) && text(value.flavor) && /^[a-f0-9]{64}$/.test(value.manifest_sha256 || '');
  function validPlan(value) {
    const bundle = identity(value?.bundle) && text(value.bundle.architecture);
    const unreviewed = value?.ready === false && value.code === 'MANAGED_NFQWS_PLATFORM_UNREVIEWED' && value.bundle == null;
    return Number.isSafeInteger(value?.revision) && value.revision >= 0 && typeof value.ready === 'boolean'
      && typeof value.code === 'string' && value.code.length <= 128 && typeof value.reason === 'string' && value.reason.length <= 4096
      && (bundle || unreviewed) && typeof value.installed_idle === 'boolean'
      && typeof value.compatibility_ready === 'boolean' && value.working_routes_changed === false;
  }
  function validInstalled(value) {
    return value?.installed_idle === true && identity(value) && text(value.receipt_id) && value.working_routes_changed === false;
  }
  function matches(plan, installed) {
    return validPlan(plan) && identity(plan.bundle) && validInstalled(installed) && ['provider_id', 'flavor', 'manifest_sha256'].every(key => plan.bundle[key] === installed[key]);
  }
  function validReceipt(value) {
    return value?.schema === 1 && value.state === 'ready-idle' && identity(value) && text(value.transaction_id) && text(value.generation_path, 4096);
  }
  function receiptMatches(receipt, observation) {
    return validReceipt(receipt) && validInstalled(observation) && receipt.transaction_id === observation.receipt_id
      && ['provider_id', 'flavor', 'manifest_sha256'].every(key => receipt[key] === observation[key]);
  }
  function writeAction(plan, observation) {
    if (!validPlan(plan) || !plan.ready || matches(plan, observation)) return null;
    if (plan.action === 'update') {
      return plan.installed_idle === true && plan.update_available === true && validInstalled(plan.installed) && validInstalled(observation)
        && ['provider_id', 'flavor', 'manifest_sha256', 'receipt_id'].every(key => plan.installed[key] === observation[key]) ? 'update' : null;
    }
    return (plan.action === undefined || plan.action === 'install') && plan.installed_idle === false && observation === null ? 'install' : null;
  }
  root.RazvilkaManagedNFQBundle = Object.freeze({ validPlan, validInstalled, matches, validReceipt, receiptMatches, writeAction });
  if (typeof document === 'undefined') return;

  const views = new Set(['engines', 'engineconfig', 'updates', 'onboard']);
  const managed = { epoch: 0, read: null, action: null, plan: null, installed: null, revision: null, received: 0, error: '', unknownWrite: false };
  const active = () => state.authenticated && views.has(state.currentView) && !document.hidden;
  const fresh = () => validPlan(managed.plan) && managed.received > 0 && Date.now() - managed.received < 60000 && !managed.error;
  const busy = () => !!managed.read || !!managed.action || !!state.componentOperation || !!state.componentRefreshRequest;
  const currentRevision = () => managed.revision === managed.plan?.revision && !(Number.isSafeInteger(state.status?.revision) && state.status.revision > managed.plan.revision);
  const installed = () => fresh() && matches(managed.plan, managed.installed);
  const allowed = () => active() && fresh() && currentRevision() && writeAction(managed.plan, managed.installed) !== null && !busy() && !managed.unknownWrite
    && !(typeof componentRecoveryFence === 'function' && componentRecoveryFence());

  // Home only needs the installed receipt. Reading it must never enable an
  // install/update, which continues to need its own plan and revision.
  let summary = null, summaryRequest = null;
  const summaryVisible = () => state.authenticated && !document.hidden &&
    ['overview', 'engines', 'engineconfig', 'updates'].includes(state.currentView);
  function forgetSummary() {
    summary = null;
    summaryRequest?.abort();
    summaryRequest = null;
  }
  function recordSummary(value, started) {
    summary = {installed:validInstalled(value) && value.provider_id === 'managed-nfqws-payload', started, session:state.authGeneration};
  }
  function recentSummary() {
    const age = Date.now() - summary?.started;
    return summary && summary.session === state.authGeneration && age >= 0 && age < 60000 &&
      !(state.inventoryInvalidatedAt > summary.started);
  }
  root.managedNFQInstallState = () => state.authenticated && state.componentOperation?.id !== 'nfqws2' &&
    recentSummary() && summary.installed ? 'installed' : 'unknown';
  root.observeManagedNFQInstall = async () => {
    if (!summaryVisible() || recentSummary() || summaryRequest || managed.read || state.componentOperation) return;
    const controller = new AbortController(), session = state.authGeneration, started = Date.now();
    summaryRequest = controller;
    let value = null;
    try {
      value = await api(base + '/installed', {signal:controller.signal, cache:'no-store', readTimeoutMs:20000});
    } catch (error) {
      if (summaryRequest === controller && session === state.authGeneration && error?.status === 401) showAuth({...state.status, authenticated:false}, error.message);
    } finally {
      if (summaryRequest === controller) {
        summaryRequest = null;
        if (session === state.authGeneration && summaryVisible()) {
          // A later, independent observation cannot refresh the old write plan.
          // A change in receipt (including loss of readback) revokes that plan.
          if (fresh() && (value?.receipt_id !== managed.installed?.receipt_id ||
            value?.manifest_sha256 !== managed.installed?.manifest_sha256)) expire();
          recordSummary(value, started);
          if (state.currentView === 'overview' && typeof refreshHomeEngineSummary === 'function') refreshHomeEngineSummary();
          else render();
        }
      }
    }
  };

  function card(id) {
    if (id !== 'nfqws2') return '';
    const ready = fresh(), present = installed() || root.managedNFQInstallState() === 'installed', updating = managed.plan?.action === 'update';
    const canWrite = allowed();
    const note = managed.unknownWrite ? [managed.error, 'Исход установки ещё не подтверждён. Прочитайте состояние и журнал восстановления; повторная установка заблокирована.'].filter(Boolean).join(' ')
      : managed.error || (typeof componentRecoveryFence === 'function' && componentRecoveryFence() ? 'Сначала завершите восстановление на странице обновлений.' : present && !updating ? 'Управляемый пакет установлен. Работа маршрутов проверяется отдельно.'
        : !ready ? 'Проверьте, есть ли пакет NFQWS2 для вашего роутера.'
          : !currentRevision() ? 'Настройки изменились. Проверьте доступность пакета ещё раз.'
            : managed.plan.reason || (managed.plan.ready ? 'План готов. Установку нужно запустить отдельно.' : 'Установка сейчас недоступна.'));
    const bundle = ready && managed.plan.bundle ? `<small>Пакет: ${esc(managed.plan.bundle.flavor)} · ${esc(managed.plan.bundle.architecture)}</small>` : '';
    return `<section data-managed-nfq-panel aria-label="Управляемый пакет NFQWS2"><b>Установка NFQWS2</b><p role="status">${esc(note)}</p>${bundle}<small>Установка файлов не включает обход. Совместимость и соединение проверяются отдельно.</small><div class="ui3-engine-actions"><button type="button" class="${canWrite ? 'secondary' : 'primary'}" data-managed-nfq-read data-rz-focus="managed-nfq-read" ${busy() ? 'disabled' : ''}>${managed.read ? 'Читаем…' : ready ? 'Проверить ещё раз' : 'Проверить доступность пакета'}</button><button type="button" class="primary" data-managed-nfq-install data-rz-focus="managed-nfq-install" ${canWrite ? '' : managed.action ? 'disabled' : 'disabled hidden'}>${managed.action ? 'Выполняем…' : updating ? 'Обновить управляемый пакет' : 'Установить NFQWS2'}</button></div></section>`;
  }
  function render() {
    if (typeof renderComponents === 'function') renderComponents();
    if (typeof renderInterfaceEngines === 'function' && views.has(state.currentView)) renderInterfaceEngines();
  }
  function expire() { managed.received = 0; managed.installed = null; }
  async function read(force = false) {
    if (!active() || managed.action && !force) return false;
    if (managed.read) return managed.read.promise;
    forgetSummary();
    const ticket = { epoch: managed.epoch, controller: new AbortController(), promise: null, started:Date.now() };
    managed.read = ticket;
    const current = () => ticket.epoch === managed.epoch && managed.read === ticket && active();
    ticket.promise = Promise.resolve().then(async () => {
      try {
        const options = { signal: ticket.controller.signal, readTimeoutMs: 20000, cache: 'no-store' };
        // The plan's retained-controller review can occupy the metadata gate.
        // Read the independent lease and status after it has returned.
        const plan = await api(base + '/plan', options);
        if (!current()) return false;
        if (!validPlan(plan)) throw new Error('Получен неполный план управляемого пакета. Установка заблокирована.');
        let observation = null;
        try {
          observation = await api(base + '/installed', options);
          if (!validInstalled(observation)) throw new Error('Установка управляемого пакета ещё не подтверждена.');
        } catch (error) {
          if (error?.status !== 503 || error.payload?.code !== 'MANAGED_NFQWS_SOURCE_UNAVAILABLE' || error.payload.installed_idle !== false) throw error;
        }
        if (!current()) return false;
        const status = await api('/api/v1/status', options);
        if (!current()) return false;
        if (!Number.isSafeInteger(status?.revision) || status.revision < 0) throw new Error('Текущая ревизия настроек не прочитана. Установка заблокирована.');
        managed.plan = plan; managed.installed = observation; managed.revision = status.revision;
        managed.received = Date.now(); managed.error = '';
        recordSummary(observation, ticket.started);
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
    forgetSummary();
    const operation = writeAction(managed.plan, managed.installed);
    const ticket = { id: 'nfqws2', action: 'managed-bundle-' + operation, epoch: managed.epoch, plan: managed.plan, sent: false, controller: new AbortController() };
    managed.action = ticket; state.componentOperation = ticket;
    const current = () => ticket.epoch === managed.epoch && managed.action === ticket && state.authenticated;
    const log = operation === 'install' ? root.RazvilkaInstallLog?.begin('NFQWS2', 'План проверен. Готовим установку NFQWS2…') : null;
    const timer = setTimeout(() => ticket.controller.abort(), 370000);
    render();
    try {
      managed.unknownWrite = true; ticket.sent = true;
      log?.sent();
      const result = await api(base + '/' + operation, { method: 'POST', ...(log ? { headers: log.headers } : {}), signal: ticket.controller.signal, body: JSON.stringify({ expected_revision: ticket.plan.revision }) });
      if (!current()) return false;
      if (result?.ok !== true || result.installed_idle !== true || typeof result.compatibility_ready !== 'boolean'
        || result.working_routes_changed !== false || !validReceipt(result.receipt)) throw new Error('Сервер не подтвердил установку управляемого пакета. Повторная установка не отправляется.');
      log?.note('Проверяем установленный пакет на роутере…');
      if (!await read(true) || !current() || !matches(ticket.plan, managed.installed) || !receiptMatches(result.receipt, managed.installed)) throw new Error('Установка отправлена, но независимое чтение ещё не подтвердило этот пакет и квитанцию.');
      managed.unknownWrite = false;
      state.inventoryInvalidatedAt = Date.now();
      if (typeof refreshComponents === 'function') await refreshComponents(false);
      if (!current()) return false;
      log?.finish('NFQWS2 установлен. Маршруты сервисов пока выключены.');
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
      log?.finish(managed.unknownWrite ? 'Исход установки неизвестен. Откройте журнал в разделе «Обновления».' : managed.error);
      return false;
    } finally {
      log?.finish('Установка отправлена. Проверьте состояние пакета в разделе «Обходы».');
      clearTimeout(timer);
      if (state.componentOperation === ticket) state.componentOperation = null;
      if (managed.action === ticket) { managed.action = null; render(); }
    }
  }
  root.managedNFQBundleCard = card;
  root.wizardManagedNFQ = {
    refresh: read,
    status() {
      return { installed: fresh() && validInstalled(managed.installed),
        canInstall: allowed() && writeAction(managed.plan, managed.installed) === 'install',
        reason: managed.error || managed.plan?.reason || 'Сначала проверьте доступность пакета.' };
    },
    async install(stillRequested) {
      if (state.currentView !== 'onboard' || !await read() || !stillRequested() || writeAction(managed.plan, managed.installed) !== 'install') return false;
      return install();
    }
  };
  root.refreshManagedNFQBundle = async (journal, receipt = null) => {
    const epoch = managed.epoch, transaction = journal?.transaction;
    const settled = typeof RazvilkaComponentRecovery !== 'undefined' && RazvilkaComponentRecovery.valid(journal)
      && journal.recovery_required === false && transaction?.schema_version === 3 && transaction.component === 'nfqws2'
      && ['accepted-installed-idle', 'rolled-back', 'abandoned'].includes(transaction.phase);
    const observed = await read();
    const matching = observed && epoch === managed.epoch && settled && currentRevision() && journal.revision === managed.plan.revision
      && (receipt ? validInstalled(managed.installed) && receiptMatches(receipt, managed.installed)
        : ['rolled-back', 'abandoned'].includes(transaction.phase) && managed.installed === null);
    if (matching) { managed.unknownWrite = false; render(); }
    return matching;
  };
  document.addEventListener('click', event => {
    if (event.target.closest?.('[data-managed-nfq-read]') && !busy()) void read();
    const button = event.target.closest?.('[data-managed-nfq-install]');
    if (button && !button.disabled) void install();
  });
  document.addEventListener('razvilka:auth-required', () => {
    forgetSummary();
    managed.epoch++; managed.read?.controller.abort(); managed.action?.controller.abort();
    if (state.componentOperation === managed.action) state.componentOperation = null;
    managed.read = null; managed.action = null; managed.plan = null; managed.revision = null; managed.error = ''; managed.unknownWrite = false; expire(); render();
  });
  document.addEventListener('razvilka:view-change', event => {
    if (!summaryVisible()) forgetSummary();
    if (!views.has(event.detail)) {
      managed.epoch++; managed.read?.controller.abort(); managed.read = null;
      if (managed.action?.sent) { managed.unknownWrite = true; managed.error = 'Исход установки ещё не прочитан. Прочитайте состояние без повторной установки.'; }
      if (state.componentOperation === managed.action) state.componentOperation = null;
      managed.action = null; expire();
    }
  });
})(typeof globalThis === 'undefined' ? window : globalThis);
