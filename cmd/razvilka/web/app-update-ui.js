'use strict';

// Opening the panel only reads status. Download and installation each require
// their own click; the final click is bound to the reviewed server job.
let appUpdateView = null;
let appUpdateRead = null;
let appUpdateReadAt = 0;
let appUpdateSession = 0;

function appUpdateBadge(update) {
  if (!update) return { label: 'Не проверено', kind: '' };
  if (update.state === 'check-failed') return { label: 'Ошибка проверки', kind: '' };
  const checked = Date.parse(update.checked_at || '');
  if (!Number.isFinite(checked) || Date.now() - checked > 45 * 60 * 1000) return { label: 'Не проверено', kind: '' };
  if (update.update_available && update.can_prepare) return { label: `Доступна ${update.latest_version}`, kind: 'update' };
  if (update.state === 'development') return { label: 'Тестовая сборка', kind: '' };
  if (update.state === 'ahead') return { label: 'Новее релиза', kind: '' };
  if (update.state === 'current') return { label: 'Актуальная', kind: 'current' };
  return { label: 'Не проверено', kind: '' };
}

function renderAppVersionStatus() {
  const badge = appUpdateBadge(state.appUpdate);
  const button = $('#appVersionAction'), label = $('#appVersionStatus');
  if (label) label.textContent = badge.label;
  if (button) { button.classList.toggle('update', badge.kind === 'update'); button.classList.toggle('current', badge.kind === 'current'); button.title = 'Проверка и обновление RAZVILKA'; }
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
  let note = 'Проверяем официальный стабильный релиз. Загрузка начинается по кнопке.';
  if (update?.state === 'check-failed') note = 'Связаться с официальным каталогом релизов не удалось. Установленная версия сохранена.';
  else if (update?.state === 'development' || update?.state === 'ahead') note = 'Ваша сборка новее опубликованного стабильного релиза. Более старая версия не будет установлена.';
  else if (available) note = 'Сначала скачаем пакет для вашего роутера и проверим возможность установки.';
  else if (badge.kind === 'current') note = 'Установлен последний проверенный стабильный релиз.';
  return `<div class="app-update-result"><div class="app-update-summary"><div><h3>RAZVILKA ${esc(installed)}</h3><p>${esc(badge.label)}</p></div><span class="app-update-badge ${available ? 'update' : ''}">${esc(available ? update.latest_version : installed)}</span></div><p>${esc(note)}</p>${update?.checked_at ? `<small>Проверено ${esc(new Date(update.checked_at).toLocaleString('ru-RU'))}</small>` : ''}</div>`;
}

function renderAppUpdatePanel() {
  renderAppVersionStatus();
  const settings = $('#appUpdateState');
  if (settings) { settings.innerHTML = `${appUpdateSummaryHTML()}<button class="secondary" type="button" data-open-app-update>Открыть обновление</button>`; settings.querySelector('[data-open-app-update]')?.addEventListener('click', openAppUpdate); }
  renderAppUpdateDialog();
}

function ensureAppUpdateDialog() {
  let dialog = $('#appUpdateDialog');
  if (dialog) return dialog;
  dialog = document.createElement('dialog'); dialog.id = 'appUpdateDialog'; dialog.className = 'form-dialog';
  dialog.innerHTML = '<div class="auth-form"><div class="dialog-head"><div><h2>Обновление приложения</h2><p>Официальные стабильные версии RAZVILKA</p></div><button class="dialog-close" type="button" data-update-close aria-label="Закрыть">×</button></div><div data-update-summary></div><p data-update-progress role="status" aria-live="polite"></p><div data-update-proof></div><div class="dialog-actions"><button class="secondary" type="button" data-update-refresh>Проверить снова</button><button class="secondary" type="button" data-update-cancel hidden>Остановить загрузку</button><button class="primary" type="button" data-update-prepare>Подготовить обновление</button><button class="primary" type="button" data-update-apply hidden>Установить и перезапустить</button></div></div>';
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
