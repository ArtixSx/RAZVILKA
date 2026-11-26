'use strict';

// Opening the panel only reads status. Download and installation each require
// their own click; the final click is bound to the reviewed server job.
let appUpdateView = null;
let appUpdateRead = null;
let appUpdateReadAt = 0;
let appUpdateSession = 0;

function appUpdateBadge(update) {
  const unchecked = {label:'Не проверено', kind:'', note:'Проверьте версию, чтобы узнать, доступно ли обновление.'};
  if (!update) return unchecked;
  if (update.state === 'check-failed' || update.metadata_stale) return { label: 'Ошибка проверки', kind: '', note: 'Сведения о выпусках получить не удалось. Повторите проверку позже.' };
  const checked = Date.parse(update.checked_at || '');
  if (!Number.isFinite(checked) || checked > Date.now() || Date.now() - checked > 45 * 60 * 1000) return unchecked;
  if (update.update_available && update.can_prepare) return { label: `Доступна ${update.latest_version}`, kind: 'update', note: 'Подготовьте пакет для вашего роутера. Установку можно запустить после проверки пакета.' };
  if (update.state === 'development') return { label: 'Тестовая сборка', kind: '', note: 'Установлена сборка для разработки. В выбранном канале сейчас нет подходящего обновления.' };
  if (update.state === 'ahead') return { label: 'Новее релиза', kind: '', note: 'Установленная версия новее последнего выпуска выбранного канала.' };
  if (update.state === 'unrecognized') return { label: 'Версия не распознана', kind: '', note: 'Сравнить установленную версию с опубликованным выпуском не удалось.' };
  if (update.state === 'current') return { label: 'Актуальная', kind: 'current', note: 'Установлена последняя проверенная версия выбранного канала.' };
  return unchecked;
}

function renderAppVersionStatus() {
  const badge = appUpdateBadge(state.appUpdate);
  const button = $('#appVersionAction'), label = $('#appVersionStatus');
  const update = badge.kind === 'update';
  // A released update reads "v0.20.0 → v0.20.1" beside a pulsing dot.
  if (label) label.textContent = update ? `→ v${state.appUpdate.latest_version} · обновить` : badge.label;
  if (button) {
    button.classList.toggle('update', update); button.classList.toggle('current', badge.kind === 'current');
    button.title = update ? `Вышло обновление ${state.appUpdate.latest_version}. Нажмите, чтобы открыть.` : 'Проверка и обновление RAZVILKA';
  }
  if (typeof window !== 'undefined' && typeof CustomEvent === 'function') window.dispatchEvent(new CustomEvent('razvilka:app-update', { detail: update ? { version: state.appUpdate.latest_version } : null }));
}

async function refreshAppUpdate(force = false) {
  if (appUpdateRead) return appUpdateRead;
  if (!force && appUpdateReadAt && Date.now() - appUpdateReadAt < 30 * 60 * 1000) return;
  const generation = appUpdateSession;
  const controller = new AbortController();
  const request = (async () => {
    const button = $('#checkAppUpdate'); if (button) { button.disabled = true; button.textContent = 'Проверяем…'; }
    try {
      const update = await api(`/api/v1/update${force ? '?refresh=true' : ''}`, { signal: controller.signal });
      if (generation !== appUpdateSession) return;
      state.appUpdate = update; appUpdateReadAt = Date.now();
    } catch (error) {
      if (generation !== appUpdateSession) return;
      state.appUpdate = { state: 'check-failed', checked_at: new Date().toISOString() }; appUpdateReadAt = Date.now();
    } finally {
      if (generation === appUpdateSession) { renderAppUpdatePanel(); if (button) { button.disabled = false; button.textContent = 'Проверить снова'; } }
    }
  })();
  appUpdateRead = request;
  request.controller = controller;
  try { await request; } finally { if (appUpdateRead === request) appUpdateRead = null; }
}

function appUpdateSummaryHTML() {
  const update = state.appUpdate, badge = appUpdateBadge(update);
  const installed = update?.installed_version || state.status?.version || '—';
  const available = badge.kind === 'update';
  const channel = {stable:'Стабильные', preview:'Предварительные и стабильные'}[update?.channel];
  const checked = Date.parse(update?.checked_at || '');
  const checkedLabel = update?.state === 'check-failed' || update?.metadata_stale ? 'Последняя попытка' : 'Последняя проверка';
  return `<div class="app-update-result"><p><b>Канал выпусков</b> · ${esc(channel || 'нет данных')}</p>${update?.retry_at?`<p>Источник запросил паузу до ${esc(new Date(update.retry_at).toLocaleString('ru-RU'))}. Повтор не обходит это ограничение.</p>`:''}<div class="app-update-summary"><div><h3>RAZVILKA ${esc(installed)}</h3><p>${esc(badge.label)}</p></div><span class="app-update-badge ${available ? 'update' : ''}">${esc(available ? update.latest_version : installed)}</span></div><p>${esc(badge.note)}</p>${Number.isFinite(checked) ? `<small>${checkedLabel} · ${esc(new Date(checked).toLocaleString('ru-RU'))}</small>` : ''}</div>`;
}

function renderAppUpdatePanel() {
  renderAppVersionStatus();
  renderMaintenanceAddresses();
  const settings = $('#appUpdateState');
  if (settings) { settings.innerHTML = `${appUpdateSummaryHTML()}<button class="secondary" type="button" data-open-app-update>Подробности обновления</button>`; settings.querySelector('[data-open-app-update]')?.addEventListener('click', openAppUpdate); }
  renderAppUpdateDialog();
}

function ensureAppUpdateDialog() {
  let dialog = $('#appUpdateDialog');
  if (dialog) return dialog;
  dialog = document.createElement('dialog'); dialog.id = 'appUpdateDialog'; dialog.className = 'form-dialog'; dialog.setAttribute('aria-label','Обновление приложения');
  dialog.innerHTML = '<div class="auth-form"><div class="dialog-head"><div><h2>Обновление приложения</h2></div><button class="dialog-close" type="button" data-update-close aria-label="Закрыть">×</button></div><div data-update-summary></div><p data-update-progress role="status" aria-live="polite"></p><div data-update-proof></div><div class="dialog-actions"><button class="secondary" type="button" data-update-refresh>Проверить снова</button><button class="secondary" type="button" data-update-cancel hidden>Остановить загрузку</button><button class="primary" type="button" data-update-prepare>Подготовить обновление</button><button class="primary" type="button" data-update-apply hidden>Установить и перезапустить</button></div></div>';
  document.body.appendChild(dialog);
  dialog.querySelector('[data-update-close]').addEventListener('click', closeAppUpdate);
  dialog.querySelector('[data-update-refresh]').addEventListener('click', () => refreshAppUpdate(true));
  dialog.querySelector('[data-update-prepare]').addEventListener('click', prepareAppUpdate);
  dialog.querySelector('[data-update-cancel]').addEventListener('click', cancelAppUpdatePreparation);
  dialog.querySelector('[data-update-apply]').addEventListener('click', installAppUpdate);
  dialog.addEventListener('cancel', event => { event.preventDefault(); closeAppUpdate(); });
  return dialog;
}

function renderAppUpdateDialog() {
  const view = appUpdateView; if (!view) return;
  const dialog = $('#appUpdateDialog'), job = view.job;
  dialog.querySelector('[data-update-summary]').innerHTML = appUpdateSummaryHTML();
  dialog.querySelector('[data-update-progress]').textContent = view.error || job?.message || 'Получаем состояние обновления…';
  const proof = dialog.querySelector('[data-update-proof]');
  proof.innerHTML = job?.release ? `<p>Пакет ${esc(job.release.version)} · ${esc(job.release.architecture)} · ${esc(Math.ceil(job.release.archive.size / 1048576))} МБ</p>${job.state === 'ready' ? '<p>Целостность пакета подтверждена по SHA256 официального релиза. При установке будет создана резервная копия; при ошибке проверки запуска установщик выполнит откат. Панель ненадолго перезапустится.</p>' : ''}` : '';
  const active = ['preparing', 'installing', 'restarting'].includes(job?.state);
  const prepare = dialog.querySelector('[data-update-prepare]');
  prepare.hidden = !!job?.can_apply || active; prepare.disabled = view.busy || appUpdateBadge(state.appUpdate).kind !== 'update' || job?.state === 'requires-review';
  const apply = dialog.querySelector('[data-update-apply]'); apply.hidden = !job?.can_apply; apply.disabled = view.busy;
  const cancel = dialog.querySelector('[data-update-cancel]'); cancel.hidden = !job?.can_cancel; cancel.disabled = view.busy;
  dialog.querySelector('[data-update-refresh]').disabled = view.busy || active;
}

async function openAppUpdate() {
  closeAppUpdate();
  const view = { controller: new AbortController(), job: null, busy: false, error: '', timer: null, deadline: Date.now() + 25 * 60 * 1000 };
  appUpdateView = view; ensureAppUpdateDialog().showModal(); renderAppUpdateDialog();
  await Promise.all([refreshAppUpdate(false), readAppUpdateJob(view)]);
}

function closeAppUpdate() {
  if (appUpdateView) { appUpdateView.controller.abort(); clearTimeout(appUpdateView.timer); }
  appUpdateView = null; $('#appUpdateDialog')?.close();
}

async function readAppUpdateJob(view) {
  try {
    const job = await api('/api/v1/self-update/current', { signal: view.controller.signal });
    if (appUpdateView !== view || view.controller.signal.aborted) return;
    view.job = job; view.error = '';
    if (job.state === 'completed') { appUpdateReadAt = 0; await refreshAppUpdate(true); }
  } catch (error) {
    if (appUpdateView !== view || view.controller.signal.aborted) return;
    view.error = ['installing', 'restarting'].includes(view.job?.state) ? 'Панель перезапускается. Ждём подтверждения результата…' : error.message;
  }
  if (appUpdateView !== view) return;
  renderAppUpdateDialog();
  if (['preparing', 'installing', 'restarting'].includes(view.job?.state) && Date.now() < view.deadline) view.timer = setTimeout(() => readAppUpdateJob(view), 2000);
  else if (Date.now() >= view.deadline) { view.error = 'Ожидание завершено. Откройте обновление снова, чтобы проверить результат установки.'; renderAppUpdateDialog(); }
}

async function prepareAppUpdate() {
  const view = appUpdateView;
  if (!view || view.busy || appUpdateBadge(state.appUpdate).kind !== 'update') return;
  view.busy = true; view.error = ''; renderAppUpdateDialog();
  try {
    const job = await api('/api/v1/self-update/prepare', { method: 'POST', signal: view.controller.signal, body: JSON.stringify({ confirm: 'PREPARE_APP_UPDATE' }) });
    if (appUpdateView !== view) return;
    view.job = job; view.deadline = Date.now() + 25 * 60 * 1000;
    clearTimeout(view.timer); view.timer = setTimeout(() => readAppUpdateJob(view), 1000);
  } catch (error) { if (appUpdateView === view) view.error = error.message; }
  finally { if (appUpdateView === view) { view.busy = false; renderAppUpdateDialog(); } }
}

async function cancelAppUpdatePreparation() {
  const view = appUpdateView; if (!view || view.busy || !view.job?.can_cancel) return;
  view.busy = true; renderAppUpdateDialog();
  try { const job = await api('/api/v1/self-update/current', { method: 'DELETE', signal: view.controller.signal }); if (appUpdateView === view) view.job = job; }
  catch (error) { if (appUpdateView === view) view.error = error.message; }
  finally { if (appUpdateView === view) { view.busy = false; renderAppUpdateDialog(); } }
}

async function installAppUpdate() {
  const view = appUpdateView, job = view?.job;
  if (!view || view.busy || !job?.can_apply || !job.review_token) return;
  // The visible package/version and this exact token remain fixed throughout
  // confirmation. Closing the panel or signing out revokes this continuation.
  view.busy = true; renderAppUpdateDialog();
  try {
    if (!await askConfirmation(`Установить RAZVILKA ${job.release.version}?`, 'Панель перезапустится. Установщик создаст резервную копию и проверит запуск новой версии.', 'Установить обновление')) return;
    if (appUpdateView !== view || view.controller.signal.aborted || view.job !== job) return;
    const result = await api('/api/v1/self-update/apply', { method: 'POST', signal: view.controller.signal, body: JSON.stringify({ job_id: job.id, review_token: job.review_token, config_revision: job.config_revision, confirm: 'INSTALL_APP_UPDATE' }) });
    if (appUpdateView !== view) return;
    view.job = result; view.error = ''; clearTimeout(view.timer); view.timer = setTimeout(() => readAppUpdateJob(view), 1000);
  } catch (error) {
    if (appUpdateView === view) { view.error = `${error.message} Проверяем, был ли принят запрос.`; clearTimeout(view.timer); view.timer = setTimeout(() => readAppUpdateJob(view), 1000); }
  } finally { if (appUpdateView === view) { view.busy = false; renderAppUpdateDialog(); } }
}

function bindAppUpdateUI() {
  $('#appVersionAction')?.addEventListener('click', openAppUpdate);
  document.addEventListener('razvilka:auth-restored', () => refreshAppUpdate(false));
  document.addEventListener('razvilka:auth-required', () => { appUpdateSession++; appUpdateRead?.controller?.abort(); appUpdateRead = null; appUpdateReadAt = 0; state.appUpdate = null; closeAppUpdate(); renderAppVersionStatus(); });
  renderAppVersionStatus();
}

function renderMaintenanceAddresses() {
 const el=$('#maintenanceAddressStatus'); if(!el)return;
 const refresh=typeof consoleSnapshot==='object'?consoleSnapshot?.address_refresh:null;
 const refill=typeof consoleSnapshot==='object'?consoleSnapshot?.reserve_refill:null;
 const labels={checked:'Проверка адресных правил завершена',partial:'Адресные правила обновлены частично',failed:'Обновление адресов не завершено',canceled:'Обновление адресов отменено','timed-out':'Истекло время обновления адресов','network-stale':'Сеть изменилась; адресные правила требуют новой проверки'};
 const sources={queued:'Пополнение разрешённого источника в очереди',waiting:'Пополнение ожидает паузу источника','no-enabled-source':'Нет включённого разрешённого источника для пополнения'};
 const when=refresh?.checked_at&&Number.isFinite(Date.parse(refresh.checked_at))?new Date(refresh.checked_at).toLocaleString('ru-RU'):'';
 el.textContent=(labels[refresh?.state]||'Свежего результата обновления адресных правил ещё нет')+(when?' · '+when:'')+(sources[refill?.state]?' · '+sources[refill.state]:'')+'. Это не подтверждение работы всех сайтов и не обновление ключей.';
}
