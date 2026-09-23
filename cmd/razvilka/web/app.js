'use strict';

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const plural = (value, one, few, many) => {
  const number = Math.abs(Number(value)) % 100;
  const last = number % 10;
  if (number > 10 && number < 20) return many;
  if (last === 1) return one;
  if (last >= 2 && last <= 4) return few;
  return many;
};

const state = {
  authenticated: false,
  status: {},
  system: {},
  metrics: { latest: {}, history: [], capacity: {} },
  services: [],
  engines: [],
  components: [],
  componentFilter: 'all',
  serviceMode: 'lite',
  warp: {},
  warpPolicyDirty: false,
  engineConfigs: [],
  selectedEngine: 'nfqws2',
  selectedEngineFile: 'main',
  engineMode: 'guided',
  engineEditorDirty: false,
  engineEditorVersion: 0,
  engineEditorEpoch: 0,
  engineIntent: null,
  engineLoaded: null,
  engineGuided: null,
  engineGuidedLoading: false,
  engineValidation: null,
  engineTab: 'config',
  testlab: { current: [], matrix: [] },
  engineLab: { engines: [], conflicts: [] },
  audit: { events: [], available: false },
  strategyLab: { pools: [], candidates: [], summaries: [], selections: [] },
  z2kPreview: { found: false, read_only: true },
  smartRoute: { services: {} },
  dns: { profiles: [], providers: [], draft: { profile_id: 'automatic' }, applied: { profile_id: 'automatic' }, plan: null },
  sessions: [],
  sources: [],
  nodes: { available: false, generation: 0, nodes: [], sources: [], counts: {}, note: '' },
  routeOptions: [],
  connections: { connections: [], active: 0, closed: 0, live: false },
  devices: [],
  community: [],
  communityPreview: null,
  profileBundle: null,
  profilePreview: null,
  remoteProfilePreview: null,
  remoteProfileReviewedInput: '',
  remoteProfileBusy: false,
  remoteProfileSelectedIndex: 0,
  privateBackupEnvelope: null,
  privateBackupPreview: null,
  appUpdate: null,
  serviceControl: null,
  scopeService: null,
  noticeDetails: null,
  stream: null,
  onboardingStep: 0,
  onboardingAutoEvaluated: false,
  loadIssues: [],
  dataLoad: {},
  currentView: 'overview',
};

const panelLoad = { generation: 0, request: null, controller: null, retryTimer: null, retryCount: 0 };
let inventoryRead = null;

const viewMeta = {
  overview: ['Главная', 'Сервисы, подключения и состояние вашей сети'],
  services: ['Сервисы', 'Проверьте доступ, выберите подключение и устройства'],
  connections: ['Соединения', 'Подтверждённый путь реального сетевого трафика'],
  engines: ['Установка и обновления', 'Версии и обслуживание компонентов обхода'],
  nodes: ['Подключения', 'VLESS и VPN: серверы, подписки и проверка доступа'],
  engineconfig: ['Обходы', 'Активные обходы, версии и настройки подключения'],
  devices: ['Устройства', 'Назначьте сервисы конкретным клиентам или группам'],
  dns: ['DNS', 'Выберите DNS-серверы и проверьте их доступность'],
  sources: ['Источники', 'Списки доменов и адресов для автоматического распознавания сервисов'],
  testlab: ['Тест обходов', 'Сравните доступность сервиса через установленные обходы'],
  strategylab: ['Подбор NFQWS2', 'Расширенная проверка стратегий для опытных пользователей'],
  diagnostics: ['Диагностика', 'Проверка роутера и причин, мешающих применению'],
  settings: ['Настройки', 'Режим применения, резервные копии и учётная запись'],
};

const fallbackLabels = {
  auto: 'Автопилот',
  direct: 'DIRECT',
  nfqws2: 'NFQWS2',
  usque: 'WARP · MASQUE',
  'warp-wg': 'WARP · WireGuard',
  'sing-box': 'Sing-box',
  xray: 'Xray',
  amneziawg: 'AmneziaWG',
};

const ADMIN_TOKEN_KEY = 'razvilka.adminToken';
const ONBOARDING_KEY = 'razvilka.onboarding.v011';
const SERVICE_MODE_KEY = 'razvilka.services.mode.v1';

try {
  state.serviceMode = localStorage.getItem(SERVICE_MODE_KEY) === 'pro' ? 'pro' : 'lite';
} catch (_) {
  state.serviceMode = 'lite';
}

async function api(url, options = {}) {
  const { readTimeoutMs, ...fetchOptions } = options;
  const method = String(options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && !headers.has('content-type')) {
    headers.set('content-type', 'application/json');
  }

  const token = sessionStorage.getItem(ADMIN_TOKEN_KEY);
  if (token) headers.set('authorization', `Bearer ${token}`);

  // A slow read must not leave the panel or an editor loading indefinitely.
  // Mutations retain their caller's deadline: a timeout must not replay Apply.
  const controller = method === 'GET' ? new AbortController() : null;
  let timedOut = false;
  const abort = () => controller?.abort();
  if (options.signal?.aborted) abort();
  options.signal?.addEventListener('abort', abort, { once: true });
  const readTimeout = Number.isSafeInteger(readTimeoutMs) ? Math.max(250, Math.min(110000, readTimeoutMs)) : 20000;
  const timer = controller ? setTimeout(() => { timedOut = true; controller.abort(); }, readTimeout) : null;
  try {
  const response = await fetch(url, { ...fetchOptions, method, headers, signal: controller?.signal || options.signal, credentials: 'same-origin' });
  if (!response.ok) {
	const text = (await response.text()).trim();
	let payload = null;
	try { payload = text ? JSON.parse(text) : null; } catch (_) { /* plain-text API error */ }
	const rawError = payload?.error || text || `HTTP ${response.status}`;
	const error = new Error(friendlyErrorMessage(rawError, response.status));
	error.technicalMessage = rawError;
	error.payload = payload || { error: rawError };
	error.status = response.status;
	throw error;
  }
  return await response.json();
  } catch (error) {
    if (timedOut) throw Object.assign(new Error('Ответ задерживается. Последние полученные данные сохранены; повторите обновление.'), { code: 'READ_TIMEOUT' });
    throw error;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', abort);
  }
}

function friendlyErrorMessage(value, status = 0) {
  const text = String(value || '').trim();
  const lower = text.toLowerCase();
  if (lower.includes('administrator login is required')) return 'Сессия завершилась. Войдите снова.';
  if (lower === 'password must not be empty') return 'Введите пароль.';
  if (lower === 'password must not exceed 256 bytes') return 'Пароль слишком длинный: максимум 256 байт в UTF-8.';
  if (lower.includes('failed to fetch') || lower.includes('networkerror') || lower.includes('load failed')) return 'Не удалось связаться с RAZVILKA. Проверьте, что служба запущена, и повторите попытку.';
  if (lower === 'engine is not installed') return 'Этот обход не установлен.';
  if (lower === 'engine is installed but not running') return 'Обход установлен, но сейчас не запущен.';
  if (lower.includes('state file changed since it was read')) return 'Настройки изменились в другой операции. Запись остановлена, чтобы не затереть новые данные. Требуется повторная загрузка настроек службой.';
  if (lower.includes('private restore journal is locked')) return 'Настройки сейчас заняты другой операцией. Дождитесь её завершения. Если сообщение остаётся, откройте технические детали.';
  if (lower.includes('private restore result requires recovery review')) return 'Результат записи настроек не подтверждён. Проверьте состояние настроек перед повторным сохранением; при необходимости выполните восстановление.';
  if (lower.includes('engine draft rollback incomplete')) return 'Часть черновиков не удалось восстановить. Рабочие файлы обходов не менялись. Проверьте черновики перед применением.';
  if (lower.includes('engine draft import failed; original draft files preserved')) return 'Черновики не сохранены. Прежние файлы черновиков сохранены; рабочие настройки обходов не менялись.';
  if (lower.includes('engine config written, but draft cleanup was not confirmed')) return 'Рабочий файл обхода записан, но удаление его черновика не подтверждено. Проверьте состояние перед повторным применением.';
  if (/[Ѐ-ӿ]/.test(text)) return text;
  if (status === 401) return 'Нужно снова войти в RAZVILKA.';
  if (status === 403) return 'Недостаточно прав для этого действия.';
  if (status === 404) return 'Нужный объект не найден. Обновите страницу и повторите.';
  if (status === 409) return 'Действие пока невозможно из-за текущего состояния. Откройте технические детали.';
  return 'Операция не выполнена. Откройте технические детали и повторите попытку.';
}

function captureSetupKey() {
  const match = location.hash.match(/^#(?:setup|recovery)=([A-Za-z0-9_-]{32,})$/);
  if (!match) return;
  sessionStorage.setItem(ADMIN_TOKEN_KEY, match[1]);
  history.replaceState(null, '', `${location.pathname}${location.search}`);
}

function showAuth(status, message = '') {
  state.authenticated = false;
  document.dispatchEvent(new Event('razvilka:auth-required'));
  state.status = status || state.status || {};
  $('#authScreen').hidden = false;
  $('.app-shell').setAttribute('aria-hidden', 'true');
  const setup = !!state.status.setup_required;
  $('#authSetupPanel').hidden = !setup;
  $('#authLoginPanel').hidden = setup;
  $('#authMessage').textContent = message;
  if (setup) $('#setupToken').value = sessionStorage.getItem(ADMIN_TOKEN_KEY) || '';
  else $('#loginUsername').value = state.status.username || 'admin';
}

function hideAuth() {
  // A saved cookie can authenticate the first load without ever showing the
  // login screen. Visibility is not an authentication lifecycle signal.
  const restored = state.authenticated !== true;
  state.authenticated = true;
  $('#authScreen').hidden = true;
  $('.app-shell').removeAttribute('aria-hidden');
  $('#authMessage').textContent = '';
  if (restored) {
    $('#detailsPanel').classList.remove('open');
    document.dispatchEvent(new Event('razvilka:auth-restored'));
  }
}

async function submitSetup(event) {
  event.preventDefault();
  const token = $('#setupToken').value.trim();
  const username = $('#setupUsername').value.trim();
  const password = $('#setupPassword').value;
  if (password !== $('#setupPasswordRepeat').value) { $('#authMessage').textContent = 'Пароли не совпадают.'; return; }
  sessionStorage.setItem(ADMIN_TOKEN_KEY, token);
  try {
    await api('/api/v1/auth/setup', { method: 'POST', body: JSON.stringify({ username, password }) });
    sessionStorage.removeItem(ADMIN_TOKEN_KEY);
    $('#setupPassword').value = ''; $('#setupPasswordRepeat').value = '';
    hideAuth(); await refreshAll(); await showPlan(); startConnectionStream();
  } catch (error) { $('#authMessage').textContent = error.message; }
}

async function submitLogin(event) {
  event.preventDefault();
  sessionStorage.removeItem(ADMIN_TOKEN_KEY);
  try {
    await api('/api/v1/auth/login', { method: 'POST', body: JSON.stringify({ username: $('#loginUsername').value.trim(), password: $('#loginPassword').value }) });
    $('#loginPassword').value = ''; hideAuth(); await refreshAll(); await showPlan(); startConnectionStream();
  } catch (error) { $('#authMessage').textContent = 'Неверный логин или пароль.'; }
}

async function recoverAccount(event) {
  event.preventDefault();
  const token = $('#recoveryToken').value.trim();
  const username = $('#recoveryUsername').value.trim();
  const password = $('#recoveryPassword').value;
  if (!token) { $('#authMessage').textContent = 'Введите recovery key.'; return; }
  if (password !== $('#recoveryPasswordRepeat').value) { $('#authMessage').textContent = 'Новые пароли не совпадают.'; return; }
  sessionStorage.setItem(ADMIN_TOKEN_KEY, token);
  try {
    await api('/api/v1/auth/recover', { method: 'POST', body: JSON.stringify({ username, new_password: password }) });
    sessionStorage.removeItem(ADMIN_TOKEN_KEY);
    $('#recoveryToken').value = ''; $('#recoveryPassword').value = ''; $('#recoveryPasswordRepeat').value = '';
    hideAuth(); await refreshAll(); await showPlan(); startConnectionStream();
  } catch (error) { $('#authMessage').textContent = error.message; }
}

async function logout() {
  document.dispatchEvent(new Event('razvilka:auth-required'));
  try { await api('/api/v1/auth/logout', { method: 'POST' }); } catch (_) { /* session may already be gone */ }
  sessionStorage.removeItem(ADMIN_TOKEN_KEY);
  if (state.stream) { state.stream.close(); state.stream = null; }
  const status = await api('/api/v1/auth/status');
  showAuth(status);
}

function askConfirmation(title, text, action = 'Продолжить') {
  const dialog = $('#actionDialog');
  // Do not attach two approvals to the same close event. A second click is
  // declined, not queued: its context may be stale when the first action ends.
  if (!dialog || dialog.open || askConfirmation.pending) return Promise.resolve(false);
  askConfirmation.pending = true;
  return new Promise((resolve) => {
    let settled = false;
    const finish = (approved) => {
      if (settled) return;
      settled = true;
      dialog.removeEventListener('close', onClose);
      dialog.removeEventListener('cancel', onCancel);
      document.removeEventListener('razvilka:auth-required', onAuthRequired);
      askConfirmation.pending = false;
      resolve(approved);
    };
    const onClose = () => finish(dialog.returnValue === 'confirm');
    const onCancel = () => finish(false);
    const onAuthRequired = () => {
      dialog.returnValue = '';
      if (dialog.open) dialog.close('');
      finish(false);
    };
    dialog.addEventListener('close', onClose);
    dialog.addEventListener('cancel', onCancel);
    document.addEventListener('razvilka:auth-required', onAuthRequired);
    try {
      $('#actionDialogTitle').textContent = title;
      $('#actionDialogText').textContent = text;
      $('#actionDialogConfirm').textContent = action;
      dialog.returnValue = '';
      dialog.showModal();
    } catch (_) { finish(false); }
  });
}

function applyStateText(enabled, route) {
  return enabled ? routeLabel(route || 'auto') : 'выключен';
}

function reviewApplyPlan(preview) {
  const dialog = $('#applyReviewDialog');
  const summary = preview.change_summary || {};
  const tx = preview.transaction || {};
  const included = summary.included || [];
  const deferred = summary.deferred || [];
  const services = summary.services || [];
  const devices = summary.devices || [];
  const blockers = (tx.blockers || []).filter((item) => item.code !== 'SAFE_MODE');
  const scopeNames = { all: 'общих изменений', routing: 'маршрутов и политик', services: 'маршрутов сервисов', devices: 'областей устройств', engine: 'конфигурации обхода' };
  $('#applyReviewTitle').textContent = `Проверка ${scopeNames[summary.scope] || 'изменений'}`;
  $('#applyReviewSubtitle').textContent = summary.working_change
    ? 'После подтверждения рабочая сеть изменится только по этому плану.'
    : preview.safe_mode && summary.network_change
    ? 'Безопасный режим проверит план и не изменит рабочую сеть.'
    : summary.network_change
    ? 'План пока не готов к рабочему применению.'
    : 'Сетевые правила не изменятся.';
  const includedHTML = included.length
    ? included.map((item) => `<div><b>${Number(item.count) || 0}</b><span>${esc(item.label)}</span></div>`).join('')
    : '<div class="empty"><b>0</b><span>новых сетевых изменений</span></div>';
  const servicesHTML = services.slice(0, 8).map((item) => `<div class="apply-review-change"><b>${esc(item.name)}</b><span>${esc(applyStateText(item.before_enabled, item.before_route))}</span><i>→</i><strong>${esc(applyStateText(item.after_enabled, item.after_route))}</strong></div>`).join('');
  const devicesHTML = devices.slice(0, 8).map((item) => `<div class="apply-review-change"><b>${esc(item.name)}</b><span>${Number(item.before_count) ? `${Number(item.before_count)} адресов` : 'вся сеть'}</span><i>→</i><strong>${Number(item.after_count) ? `${Number(item.after_count)} адресов` : 'вся сеть'}</strong></div>`).join('');
  const deferredHTML = deferred.length ? `<section class="apply-review-deferred"><h4>Останется на других вкладках</h4><div>${deferred.map((item) => `<span><b>${Number(item.count) || 0}</b>${esc(item.label)}</span>`).join('')}</div><p>${esc(summary.independent_notice || '')}</p></section>` : '';
  const blockersHTML = blockers.length ? `<section class="apply-review-blockers"><h4>Сначала исправьте</h4>${blockers.map((item) => `<div><b>${esc(item.message)}</b><span>${esc(item.resolution || 'Откройте технический план для подробностей.')}</span></div>`).join('')}</section>` : '';
  const blocked = !preview.safe_mode && !tx.ready && !tx.noop;
  const impactLabel = blocked ? 'ПРИМЕНЕНИЕ ЗАБЛОКИРОВАНО' : summary.working_change ? 'РАБОЧАЯ СЕТЬ ИЗМЕНИТСЯ' : preview.safe_mode && summary.network_change ? 'ТОЛЬКО ПРОВЕРКА' : 'БЕЗ ИЗМЕНЕНИЯ СЕТИ';
  const impactText = blocked ? 'Ничего не изменится до устранения причин' : summary.working_change ? 'Применение с автоматическим откатом' : preview.safe_mode && summary.network_change ? 'Черновик останется неподтверждённым' : 'Сохраняется только выбранное состояние';
  $('#applyReviewContent').innerHTML = `<section class="apply-review-impact ${summary.working_change ? 'working' : ''} ${blocked ? 'blocked' : ''}"><div><span>${impactLabel}</span><b>${impactText}</b></div></section><section class="apply-review-areas">${includedHTML}</section>${servicesHTML ? `<section class="apply-review-list"><h4>Сервисы</h4>${servicesHTML}${services.length > 8 ? `<small>И ещё ${services.length - 8}</small>` : ''}</section>` : ''}${devicesHTML ? `<section class="apply-review-list"><h4>Устройства</h4>${devicesHTML}${devices.length > 8 ? `<small>И ещё ${devices.length - 8}</small>` : ''}</section>` : ''}<section class="apply-review-safety"><div><b>Как проверяем</b><span>${esc(summary.verification || 'Сначала проверяется план.')}</span></div><div><b>Если проверка не пройдёт</b><span>${esc(summary.rollback || 'Рабочее состояние не изменится.')}</span></div></section>${deferredHTML}${blockersHTML}`;
  const confirm = $('#applyReviewConfirm');
  const canContinue = !!preview.safe_mode || !!tx.ready || !!tx.noop;
  confirm.disabled = !canContinue;
  confirm.textContent = !canContinue ? 'Сначала исправьте причины' : preview.safe_mode && summary.network_change ? 'Проверить без применения' : summary.working_change ? 'Применить и проверить' : 'Сохранить';
  dialog.returnValue = '';
  dialog.showModal();
  return new Promise((resolve) => dialog.addEventListener('close', () => resolve(dialog.returnValue === 'confirm'), { once: true }));
}

function needsApplyReview(preview) {
  const summary = preview.change_summary || {};
  const transaction = preview.transaction || {};
  const blockers = (transaction.blockers || []).filter((item) => item.code !== 'SAFE_MODE');
  if (blockers.length) return true;
  // The section button is already explicit consent. The server still performs
  // stage -> validate -> health -> rollback, so a second click for a small
  // service-only change adds ceremony rather than safety.
  if (summary.scope === 'services' || summary.scope === 'routing') {
    return (summary.services || []).length > 8 || (summary.devices || []).length > 0;
  }
  return !!summary.network_change || !!summary.working_change;
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function routeOption(id) {
  return state.routeOptions.find((o) => o.id === id);
}

function routeLabel(id) {
  if (id === 'auto') return 'Автопилот';
  if (typeof id === 'string' && id.startsWith('sing-box:node-')) {
    const nodeId = id.slice('sing-box:'.length);
    const node = (state.nodes?.nodes || []).find((item) => item.id === nodeId);
    return node ? nodeDisplayName(node) : 'Подключение недоступно';
  }
  if (typeof id === 'string' && id.startsWith('sing-box:group-')) {
    const groupId = id.slice('sing-box:'.length);
    const group = (state.nodes?.groups || []).find((item) => item.id === groupId);
    return group?.name || `Группа ${groupId.slice('group-'.length, 'group-'.length + 6)}`;
  }
  return routeOption(id)?.name || fallbackLabels[id] || id || '—';
}

function routeAvailable(id) {
  if (id === 'auto' || id === 'direct') return true;
  const option = routeOption(id);
  return !!(option && option.selectable);
}

function setView(name) {
  if (typeof name !== 'string' || !document.getElementById(`view-${name}`)) name = 'overview';
  // Navigation is local. A broken status/engine widget must not strand the
  // user on its page, submit a write, or silently discard an editor's draft.
  state.uiRenderIssues ||= {};
  const render = (key, action) => {
    try { action(); delete state.uiRenderIssues[key]; }
    catch (_) { state.uiRenderIssues[key] = 'Не удалось обновить виджет. Остальные разделы доступны.'; }
  };
  render('navigation-event', () => document.dispatchEvent(new CustomEvent('razvilka:view-change', { detail: name })));
  state.currentView = name;
  $$('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${name}`));
  $$('.nav[data-view]').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  const meta = viewMeta[name] || [name, ''];
  $('#pageTitle').textContent = meta[0];
  $('#pageSubtitle').textContent = meta[1];
  render('navigation-console', () => { if (typeof consoleViewChanged === 'function') consoleViewChanged(name); });
  render('navigation-workspace', () => renderWorkspaceNavigation(name));
  render('navigation-scroll', () => {
    const activeNav = $(`.nav[data-view="${CSS.escape(name)}"]`);
    if (activeNav && window.matchMedia('(max-width: 760px)').matches) activeNav.scrollIntoView({ block: 'nearest', inline: 'center' });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
  render('navigation-status', () => { if (state.status && Object.keys(state.status).length) renderStatus(); });
  render('navigation-tabs', () => { if (typeof renderInterfaceNavigation === 'function') renderInterfaceNavigation(name); });
  render('navigation-interface', () => { if (typeof renderInterface === 'function') renderInterface(); });
  if (name === 'engineconfig') render('navigation-engine', () => {
    if (state.engineGuidedRequest && state.engineGuidedRequest.view !== name && !state.engineIntent) invalidateEngineEditorContext();
    renderEngineControl();
  });
}

const detailStatusLabels = {
  pass: 'Доступен', partial: 'Доступен частично', fail: 'Недоступен', timeout: 'Тайм-аут',
  'not-ready': 'Не проверен', ready: 'Готов', running: 'Работает', stopped: 'Остановлен',
};

const detailReasonLabels = {
  'current-route-remains-best': 'Текущий обход остаётся лучшим по подтверждённым результатам.',
  'selected-first-confirmed-route': 'Выбран первый обход с подтверждённой доступностью.',
  'selected-faster-confirmed-route': 'Выбран более быстрый подтверждённый обход.',
  'no-confirmed-route': 'Подтверждённый рабочий обход пока не найден.',
};

function friendlyDetail(value) {
  const text = String(value || '').trim();
  if (!text) return 'Дополнительных пояснений нет.';
  if (text === 'engine is not installed') return 'Этот обход не установлен.';
  if (text === 'engine is installed but not running') return 'Обход установлен, но сейчас не запущен.';
  if (text === 'WAN interface was not detected') return 'WAN-интерфейс не определён, поэтому честно изолировать прямой маршрут пока нельзя.';
  if (text === 'DIRECT needs an isolated bypass-free socket before it can be compared fairly') return 'Для честного сравнения DIRECT нужен отдельный сокет без влияния других обходов.';
  if (text.startsWith('DIRECT isolation refused while external tunnels are present:')) {
    const tunnels = text.split(':').slice(1).join(':').trim();
    return `Прямой маршрут не проверялся: обнаружен внешний туннель ${tunnels}. Это защищает результат от ложного подтверждения.`;
  }
  if (text === 'service endpoint reachable through isolated nfqws2 adapter') return 'Сервис ответил через изолированный NFQWS2.';
  if (text === 'service endpoint reachable through current route') return 'Сервис ответил через уже применённый маршрут.';
  if (text.includes('i/o timeout') || text.includes('context deadline exceeded') || text.includes('Client.Timeout exceeded')) {
    return 'Сервис не ответил за отведённое время. Сам путь трафика проверяется отдельно — это ещё не означает, что сервис доступен.';
  }
  return text;
}

function technicalDetails(value) {
  const raw = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return `<details class="technical-details"><summary>Показать технические данные</summary><pre>${esc(raw)}</pre></details>`;
}

function evidenceLevelLabel(level) {
  return ({
    none: 'нет доказательств',
    catalog: 'только каталог',
    configured: 'конфигурация сохранена',
    runtime: 'обход запущен, маршрут не доказан',
    'route-confirmed': 'маршрут подтверждён',
    'service-confirmed': 'сервис и маршрут подтверждены',
  })[String(level || 'none')] || 'уровень не определён';
}

function evidenceAtLeast(actual, required) {
  const rank = { none: 0, catalog: 1, configured: 2, runtime: 3, 'route-confirmed': 4, 'service-confirmed': 5 };
  return (rank[String(actual || 'none')] || 0) >= (rank[String(required || 'none')] || 0);
}

function evidenceOutcomeLabel(outcome) {
  return ({
    transport_reachable: 'транспорт доступен',
    tls_valid: 'TLS корректен',
    service_accepted: 'сервис принял запрос',
    service_blocked: 'сервис вернул блокирующий ответ',
    content_mismatch: 'TLS или содержимое не совпало',
    edge_unsuitable: 'точка выхода не подходит',
    unknown: 'результат не определён',
  })[String(outcome || 'unknown')] || 'результат не определён';
}

function probeVerdict(result) {
  const status = String(result?.status || 'not-ready');
  const routeConfirmed = !!result?.route_confirmed;
  const verdict = String(result?.verdict || result?.evidence_v2?.verdict || '');
  const errorCode = String(result?.error_code || result?.evidence_v2?.error_code || '');
  if (result?.route_proof_error || result?.evidence_v2?.route_proof_error) return { tone: 'warn', text: 'Путь через выбранный обход не подтверждён — это не означает, что сервис не работает' };
  if (verdict === 'MISROUTED') return { tone: 'fail', text: 'Ответ пришёл через другой маршрут — обход не подтверждён' };
  if (verdict === 'BLOCKED' && errorCode === 'timeout') return { tone: 'warn', text: 'Проверка не дождалась ответа; это ещё не доказывает блокировку' };
  if (verdict === 'BLOCKED' && errorCode.includes('tls')) return { tone: 'warn', text: 'Безопасное TLS-соединение не подтверждено' };
  if (verdict === 'BLOCKED') return { tone: 'warn', text: 'Получен блокирующий ответ, работа сервиса не подтверждена' };
  if (verdict === 'INCONCLUSIVE') return { tone: 'warn', text: 'Недостаточно данных для вывода о работе сервиса' };
  if (verdict === 'ERROR') return { tone: 'warn', text: 'Ошибка проверки — это не доказательство неработающего обхода' };
  if (verdict === 'PARTIAL') return { tone: 'warn', text: 'Доступ подтверждён лишь частично' };
  if (status === 'pass' && routeConfirmed && evidenceAtLeast(result?.evidence_level, 'service-confirmed')) return { tone: 'pass', text: 'Сервис работает через этот маршрут' };
  if (status === 'pass') return { tone: 'warn', text: 'Сервис ответил, но путь трафика не доказан' };
  if (routeConfirmed) return { tone: 'fail', text: 'Маршрут использован, сервис не ответил' };
  if (status === 'not-ready') return { tone: 'muted', text: 'Проверка маршрута недоступна' };
  return { tone: 'fail', text: 'Доступ через маршрут не подтверждён' };
}

function probeStatusLabel(result) {
  if (result?.route_proof_error || result?.evidence_v2?.route_proof_error) return 'Путь не подтверждён';
  const errorCode = String(result?.error_code || result?.evidence_v2?.error_code || '');
  if (result?.verdict === 'BLOCKED' && errorCode === 'timeout') return 'Нет ответа';
  if (result?.verdict === 'BLOCKED' && errorCode.includes('tls')) return 'TLS не подтверждён';
  return ({ PASS: 'Проверено', PARTIAL: 'Частично', BLOCKED: 'Блокирующий ответ', MISROUTED: 'Другой маршрут', INCONCLUSIVE: 'Не подтверждено', ERROR: 'Ошибка проверки' })[result?.verdict] || testStatusLabel(result?.status);
}

function evidenceBadgeHTML(item, compact = false) {
  const level = String(item?.evidence_level || 'none');
  const label = evidenceLevelLabel(level);
  const route = item?.evidence_route ? routeLabel(item.evidence_route) : '';
  const checked = item?.evidence_checked_at ? new Date(item.evidence_checked_at).toLocaleString('ru-RU') : '';
  const stale = item?.evidence_fresh_until && new Date(item.evidence_fresh_until).getTime() <= Date.now();
  const outcome = item?.evidence_outcome ? evidenceOutcomeLabel(item.evidence_outcome) : '';
  const title = [`Уровень подтверждения: ${label}`, outcome ? `итог: ${outcome}` : '', route ? `обход: ${route}` : '', checked ? `проверено: ${checked}` : '', item?.evidence_source ? `источник: ${item.evidence_source}` : '', item?.evidence_probe_id ? `probe: ${item.evidence_probe_id}` : ''].filter(Boolean).join(' · ');
  const text = stale ? 'Данные устарели' : compact ? label : `Подтверждение: ${label}`;
  return `<em class="evidence-badge evidence-${esc(level)} ${stale ? 'evidence-stale' : ''}" title="${esc(title)}">${esc(text)}</em>`;
}

function renderRouteComparisonDetails(value) {
  const results = Array.isArray(value.results) ? value.results : [];
  const decisions = Array.isArray(value.decisions) ? value.decisions : [];
  const assessments = Array.isArray(value.assessments) ? value.assessments : [];
  const serviceName = results.find((item) => item?.service_name)?.service_name || decisions[0]?.service_id || 'Сервис';
  const confirmed = results.filter((item) => item?.route_confirmed && item?.status === 'pass' && evidenceAtLeast(item?.evidence_level, 'service-confirmed') && (!item?.verdict || item.verdict === 'PASS'));
  const assessment = assessments[0] || null;
  const selected = assessment?.recommended_route || decisions[0]?.selected || confirmed[0]?.route || '';
  const summary = selected ? `${serviceName} → ${routeLabel(selected)}` : `${serviceName}: рабочий обход не подтверждён`;
  const assessmentTone = ({ 'direct-sufficient': 'pass', 'bypass-required': 'pass', 'bypass-improves-access': 'warn', 'direct-partial': 'warn', 'control-unavailable': 'warn', 'control-not-run': 'warn', 'no-working-route': 'fail' })[assessment?.conclusion] || (confirmed.length ? 'pass' : 'warn');
  const assessmentTitle = ({
    'direct-sufficient': 'Обход не требуется',
    'bypass-required': 'Обход действительно нужен',
    'bypass-improves-access': 'Обход улучшает доступ',
    'direct-partial': 'DIRECT работает частично',
    'control-unavailable': 'DIRECT-контроль недоступен',
    'control-not-run': 'DIRECT-контроль не запускался',
    'no-working-route': 'Рабочий маршрут не найден',
  })[assessment?.conclusion] || 'Итог сравнения';
  const decisionCards = decisions.map((decision) => {
    const reason = detailReasonLabels[decision.reason] || decision.reason || 'Решение принято по результатам проверки.';
    const changeText = decision.changed ? `Маршрут изменён: ${routeLabel(decision.previous)} → ${routeLabel(decision.selected)}` : `Оставлен ${routeLabel(decision.selected)}`;
    return `<div class="detail-decision"><span>${esc(decision.service_id || serviceName)}</span><strong>${esc(changeText)}</strong><p>${esc(reason)}</p></div>`;
  }).join('');
  const resultCards = results.map((result) => {
    const status = String(result.status || 'not-ready');
    const verdict = probeVerdict(result);
    const metrics = [
      result.http_status ? `HTTP ${result.http_status}` : '',
      Number.isFinite(Number(result.latency_ms)) && Number(result.latency_ms) > 0 ? `${Number(result.latency_ms)} мс` : '',
      result.evidence_level ? evidenceLevelLabel(result.evidence_level) : (result.route_confirmed ? 'маршрут подтверждён' : ''),
      result.outcome ? evidenceOutcomeLabel(result.outcome) : '',
      result.evidence_v2?.finished_at ? `факт: ${timeAgo(result.evidence_v2.finished_at)}` : '',
    ].filter(Boolean);
    const scenario = result.scenario_label ? `<small>${esc(result.scenario_label)}${result.scenario_required ? ' · обязательный' : ''}</small>` : '';
    return `<article class="route-result-card status-${esc(status)}"><div class="route-result-head"><strong>${esc(routeLabel(result.route))}${scenario}</strong><span>${esc(probeStatusLabel(result))}</span></div><div class="probe-verdict ${esc(verdict.tone)}">${esc(verdict.text)}</div>${metrics.length ? `<div class="route-result-metrics">${metrics.map((metric) => `<b>${esc(metric)}</b>`).join('')}</div>` : ''}<p>${esc(friendlyDetail(result.detail))}</p></article>`;
  }).join('');
  return `<div class="detail-hero ${esc(assessmentTone)}"><span>${esc(assessmentTitle)}</span><h4>${esc(summary)}</h4><p>${esc(assessment?.message || (confirmed.length ? `Подтверждено рабочих вариантов: ${confirmed.length}.` : 'Ни один выбранный вариант пока не дал подтверждённый ответ.'))}</p></div>${value.control_added ? '<div class="detail-note"><b>Контроль добавлен автоматически</b><p>RAZVILKA проверила DIRECT вместе с выбранными обходами, чтобы не назначать обход без необходимости.</p></div>' : ''}${decisionCards ? `<section class="detail-section"><h4>Решение Smart Route</h4>${decisionCards}</section>` : ''}<section class="detail-section"><h4>Проверенные маршруты</h4><div class="route-result-list">${resultCards || '<div class="detail-empty">Результаты проверки отсутствуют.</div>'}</div></section>${value.note ? `<div class="detail-note"><b>Как выполнялся тест</b><p>${esc(value.note)}</p></div>` : ''}${technicalDetails(value)}`;
}

function renderGenericDetails(value) {
  if (typeof value === 'string') return `<div class="detail-hero"><span>Сообщение</span><p>${esc(value)}</p></div>${technicalDetails(value)}`;
  if (!value || typeof value !== 'object') return `<div class="detail-empty">Нет дополнительных данных.</div>${technicalDetails(value)}`;
  if (value.detail_kind === 'panel-load' && Array.isArray(value.issues)) {
    const busy = value.issues.length > 0 && value.issues.every(issue => issue.busy);
    const sections = { inventory: 'Компоненты', services: 'Сервисы', engineConfigs: 'Настройки обходов', nodes: 'Подключения', dns: 'DNS', status: 'Состояние проекта' };
    return `<div class="detail-hero warn"><span>Загрузка данных</span><h4>${busy ? 'Ожидаем свежие сведения' : 'Часть данных не загрузилась'}</h4><p>Последние полученные данные сохранены. Состояние подключения проверяется отдельно.</p></div><div class="detail-section">${value.issues.map(issue => `<div class="detail-note"><b>${esc(sections[issue.section] || issue.section || 'Раздел панели')}</b><p>${esc(issue.message || 'Повторите чтение данных.')}</p></div>`).join('')}</div>${technicalDetails(value)}`;
  }
  const headline = value.error || value.message || value.note || (value.ok === false ? 'Действие не выполнено' : 'Операция завершена');
  const primitive = Object.entries(value).filter(([, item]) => item == null || ['string', 'number', 'boolean'].includes(typeof item)).slice(0, 10);
  return `<div class="detail-hero ${value.error || value.ok === false ? 'fail' : 'pass'}"><span>${value.error ? 'Ошибка' : 'Результат'}</span><h4>${esc(headline)}</h4></div>${primitive.length ? `<dl class="detail-kv">${primitive.map(([key, item]) => `<div><dt>${esc(key.replaceAll('_', ' '))}</dt><dd>${esc(typeof item === 'boolean' ? (item ? 'да' : 'нет') : item)}</dd></div>`).join('')}</dl>` : ''}${technicalDetails(value)}`;
}

function renderServiceListsDetails(value) {
  const domains = Array.isArray(value.domains) ? value.domains : [];
  const cidrs = Array.isArray(value.ip_and_cidr) ? value.ip_and_cidr : [];
  const sources = Array.isArray(value.source_updates) ? value.source_updates : [];
  const list = (items, empty) => items.length
    ? `<pre>${items.slice(0, 120).map(esc).join('\n')}</pre>${items.length > 120 ? `<small>Показаны первые 120 из ${items.length} записей.</small>` : ''}`
    : `<div class="detail-empty">${esc(empty)}</div>`;
  const sourceRows = sources.length
    ? sources.map((source) => `<div><b>${esc(source.id)}</b><span>${esc(source.status || 'статус неизвестен')}</span><small>${esc(source.updated_at || 'время обновления не указано')}</small></div>`).join('')
    : '<div><b>Встроенный каталог</b><span>поставляется вместе с этой версией RAZVILKA</span><small>Обновляется при обновлении приложения</small></div>';
  return `<div class="detail-hero"><span>Списки маршрутизации</span><h4>${esc(value.summary || 'Домены и IP-сети сервиса')}</h4><p>Это адреса, которыми RAZVILKA распознаёт сервис. Они не доказывают, что маршрут уже работает: доступ подтверждается отдельной проверкой.</p></div><section class="detail-section service-list-details"><h4>Домены (${domains.length})</h4>${list(domains, 'Для этого сервиса доменные правила не заданы.')}<h4>IP и CIDR (${cidrs.length})</h4>${list(cidrs, 'IP-сети не заданы: сейчас сервис распознаётся только по доменам. Для полной IP-блокировки понадобится актуальный IP-источник или туннель.')}</section><section class="detail-section"><h4>Актуальность списков</h4><div class="service-source-status">${sourceRows}</div><p class="detail-footnote">${esc(value.list_status || '')}</p></section>${technicalDetails(value)}`;
}

function renderNFQWS2ServiceDetails(value) {
  const nfq = value.nfqws2 || {};
  const ownerTone = nfq.owner === 'external' ? 'fail' : nfq.owner === 'razvilka' ? 'pass' : 'warn';
  const ownerText = nfq.owner === 'external'
    ? `${nfq.owner_name || 'Внешний процесс'} управляет NFQUEUE`
    : nfq.owner === 'razvilka'
      ? 'RAZVILKA управляет этим экземпляром'
      : 'Владелец NFQUEUE пока не подтверждён';
  const unknown = (value) => value && value !== 'unknown' ? value : 'не определено';
  const recommendation = nfq.recommendation_only
    ? '<div class="detail-note"><b>Это рекомендация</b><p>Сервис выключен. NFQWS2 не активирован и трафик через него не направляется.</p></div>'
    : '';
  const stale = nfq.stale
    ? '<div class="detail-note warn"><b>Расчёт устарел</b><p>Черновик отличается от применённого состояния. Сначала сохраните и проверьте изменения либо отмените их.</p></div>'
    : '';
  return `<div class="detail-hero ${ownerTone}"><span>NFQWS2 · ${esc(value.service_name || '')}</span><h4>${esc(ownerText)}</h4><p>Здесь отдельно показаны выбор, профиль, стратегия и фактическое подтверждение. Расчёт не выдаётся за работающий маршрут.</p></div>${recommendation}${stale}<dl class="detail-kv"><div><dt>Движок</dt><dd>${esc(unknown(nfq.engine))} · ${esc(unknown(nfq.engine_state))}</dd></div><div><dt>Профиль</dt><dd>${esc(unknown(nfq.profile))}</dd></div><div><dt>Стратегия</dt><dd>${esc(unknown(nfq.strategy))}</dd></div><div><dt>Результат выбора</dt><dd>${esc(unknown(nfq.selection_status))}</dd></div><div><dt>Подтверждение</dt><dd>${esc(evidenceLevelLabel(nfq.evidence || 'none'))}${nfq.evidence_status ? ` · ${esc(nfq.evidence_status)}` : ''}</dd></div><div><dt>Владелец</dt><dd>${esc(unknown(nfq.owner_name))} · ${esc(unknown(nfq.ownership_state))}</dd></div></dl>${nfq.owner === 'external' ? '<div class="detail-note warn"><b>Внешний владелец</b><p>RAZVILKA не будет запускать второй NFQWS2 поверх работающего z2k. Импортируйте совместимые стратегии или остановите внешний стек вручную.</p></div>' : ''}<div class="detail-actions"><button class="primary" type="button" data-open-strategy-lab="1">Открыть подбор NFQWS2</button></div>${technicalDetails(value)}`;
}

function showDetails(value, title = 'Детали') {
  $('#detailsPanel').classList.add('open');
  $('#details').innerHTML = value?.detail_kind === 'project-log'
    ? renderProjectLogDetails(value)
    : value?.detail_kind === 'nfqws2-service'
    ? renderNFQWS2ServiceDetails(value)
    : value?.detail_kind === 'service-lists'
      ? renderServiceListsDetails(value)
    : value && typeof value === 'object' && Array.isArray(value.results) && Array.isArray(value.decisions)
      ? renderRouteComparisonDetails(value)
      : renderGenericDetails(value);
  $('.drawer-head h3').textContent = title;
  $('#detailsSubtitle').textContent = value?.detail_kind === 'project-log' ? 'Текущее состояние · причины ошибок · последние действия' : 'Краткий итог · технические данные доступны ниже';
  $('#details [data-open-strategy-lab]')?.addEventListener('click', () => {
    $('#detailsPanel').classList.remove('open');
    setView('strategylab');
  });
}

function showNotice(kind, title, message, details = null, settings = false) {
  const notice = $('#notice');
  notice.hidden = false;
  notice.className = `notice ${kind || 'success'}`;
  $('#noticeTitle').textContent = title;
  $('#noticeText').textContent = message;
  state.noticeDetails = details;
  $('#noticeDetails').hidden = details == null;
  $('#noticeSettings').hidden = !settings;
}

function hideNotice() {
  $('#notice').hidden = true;
  state.noticeDetails = null;
}

function onboardingDone() {
  try { return localStorage.getItem(ONBOARDING_KEY) === 'done'; } catch (_) { return false; }
}

function setOnboardingDone() {
  try { localStorage.setItem(ONBOARDING_KEY, 'done'); } catch (_) { /* private browser storage may be unavailable */ }
}

function onboardingNeeded() {
  const managed = new Set(['nfqws2', 'usque', 'warp-wg', 'sing-box', 'xray', 'amneziawg']);
  const hasBypass = state.components.some((component) => managed.has(component.id) && component.installed);
  const hasServices = state.services.some((service) => service.enabled);
  return !hasBypass && !hasServices;
}

function openOnboarding(force = false) {
  if (!force && (state.onboardingDeferred || onboardingDone() || !onboardingNeeded())) return;
  state.onboardingDeferred = false;
  state.onboardingStep = Math.max(0, Math.min(3, state.onboardingStep || 0));
  renderOnboarding();
  if (!$('#onboardingDialog').open) $('#onboardingDialog').showModal();
}

function closeOnboarding(done = true) {
  if (done) setOnboardingDone();
  else state.onboardingDeferred = true;
  if ($('#onboardingDialog').open) $('#onboardingDialog').close();
}

function renderOnboarding() {
  const step = state.onboardingStep;
  const labels = ['Проверка роутера', 'Выбор обхода', 'Выбор сервисов', 'План и запуск'];
  $('#onboardingSteps').innerHTML = labels.map((label, index) => `<li class="${index === step ? 'active' : ''} ${index < step ? 'done' : ''}"><i>${index < step ? '✓' : index + 1}</i><span>${esc(label)}</span></li>`).join('');
  const components = ['sing-box', 'nfqws2', 'usque', 'warp-wg'].map((id) => state.components.find((item) => item.id === id)).filter(Boolean);
  const preferredIDs = ['youtube', 'discord', 'telegram', 'chatgpt', 'claude', 'gemini', 'twitch', 'instagram', 'facebook', 'reddit', 'tiktok', 'x-twitter'];
  const preferred = preferredIDs.map((id) => state.services.find((item) => item.id === id)).filter(Boolean);
  const services = preferred.length >= 6 ? preferred : state.services.filter((item) => !item.custom).slice(0, 12);
  const installed = state.components.filter((item) => item.installed && item.provider !== 'external');
  const enabled = state.services.filter((item) => item.enabled);
  let content = '';
  if (step === 0) {
    const capacity = state.metrics.capacity || {};
    content = `<span class="eyebrow">ШАГ 1 ИЗ 4</span><h2>Сначала — безопасная база</h2><p class="onboarding-lead">Панель уже работает, но обходы не устанавливаются скрытно. Проверим, что роутер готов, и сохраним рабочий интернет без изменений.</p><div class="onboarding-checks"><div><i>✓</i><span><b>RAZVILKA запущена</b><small>${esc(state.status.listen || ':8787')} · ${esc(state.system.architecture || state.system.arch || 'архитектура определяется')}</small></span></div><div><i>✓</i><span><b>${state.status.safe_mode ? 'Изменения маршрутов заблокированы' : 'Изменение маршрутов разрешено'}</b><small>${state.status.safe_mode ? 'Проверки доступны; применить маршрут можно после снятия блокировки в настройках.' : 'Уже применённые маршруты продолжают работать.'}</small></span></div><div><i>${capacity.level && capacity.level !== 'critical' ? '✓' : '·'}</i><span><b>Ресурсы роутера</b><small>${esc((capacity.reasons || []).join(' · ') || 'замеры появятся после нескольких секунд работы')}</small></span></div></div><div class="onboarding-note">Если интернет сейчас работает, мастер не должен его прервать: установка обхода и применение маршрута — разные подтверждаемые операции.</div>`;
  } else if (step === 1) {
    const unavailable = components.some((component) => !component.installed && !component.available);
    content = `<span class="eyebrow">ШАГ 2 ИЗ 4</span><h2>Выберите первый обход</h2><p class="onboarding-lead">Для VLESS добавьте свои ссылки или подписку, затем выберите сервис и устройства. Другие компоненты доступны в «Настройки → Компоненты».</p>${unavailable ? '<div class="onboarding-repository"><span><b>Список пакетов ещё не проверен</b><small>RAZVILKA добавит только известные feed NFQWS2/Usque и выполнит opkg update. Обходы при этом не устанавливаются.</small></span><button class="secondary" data-onboarding-refresh>Проверить доступность</button></div>' : ''}<div class="onboarding-note"><b>VLESS и публичные каталоги</b><p>Добавьте подключение и проверьте его на своём роутере.</p><button class="primary" type="button" data-onboarding-nodes>Открыть подключения</button></div><div class="onboarding-components">${components.map((component) => { const installedText = component.installed ? `Установлен ${component.installed_version || ''}` : (component.available ? `Доступен ${component.available_version || ''}` : 'Сначала проверьте список пакетов'); const action = component.installed ? '<span class="engine-state installed">ГОТОВ</span>' : `<button class="secondary" data-onboarding-component="${esc(component.id)}" ${component.available ? '' : 'disabled'}>Установить</button>`; return `<article class="${component.id === 'nfqws2' ? 'recommended' : ''}">${component.id === 'nfqws2' ? '<em>РЕКОМЕНДУЕМ НАЧАТЬ</em>' : ''}<b>${esc(component.name)}</b><p>${esc(component.description || '')}</p><small>${esc(installedText)}</small>${action}</article>`; }).join('')}</div><div class="onboarding-note">Созданный профиль WARP или добавленная VLESS-ссылка ещё требуют проверки доступа. Установка компонента сама по себе не включает маршрут.</div>`;
  } else if (step === 2) {
    content = `<span class="eyebrow">ШАГ 3 ИЗ 4</span><h2>Отметьте нужные сервисы</h2><p class="onboarding-lead">Сейчас создаётся только черновик с автоматическим выбором обхода. RAZVILKA ещё ничего не применяет в систему.</p><div class="onboarding-services">${services.map((service) => `<button class="${service.enabled ? 'selected' : ''}" data-onboarding-service="${esc(service.id)}"><span>${esc(service.icon || '◇')}</span><b>${esc(service.name)}</b><i>${service.enabled ? '✓' : '+'}</i></button>`).join('')}</div><div class="onboarding-selection"><b>${enabled.length}</b><span>сервисов выбрано</span></div>`;
  } else {
    content = `<span class="eyebrow">ШАГ 4 ИЗ 4</span><h2>Проверьте план перед запуском</h2><p class="onboarding-lead">Выбор сохранён в черновике. Сначала RAZVILKA покажет препятствия и создаваемые правила, затем сделает резервную копию. Рабочее применение включается отдельно.</p><div class="onboarding-summary"><div><span>Установленные обходы</span><b>${installed.length ? installed.map((item) => item.name).join(', ') : 'пока нет'}</b></div><div><span>Выбранные сервисы</span><b>${enabled.length ? enabled.map((item) => item.name).slice(0, 6).join(', ') + (enabled.length > 6 ? ` +${enabled.length - 6}` : '') : 'пока нет'}</b></div><div><span>Текущее состояние</span><b>${state.status.safe_mode ? 'Изменения маршрутов заблокированы' : 'Рабочее применение разрешено'}</b></div></div><div class="onboarding-note success">Мастер не обещает доступ без теста: после установки обхода откройте план, затем выполните проверку маршрутов.</div>`;
  }
  $('#onboardingContent').innerHTML = content;
  $('#onboardingBack').disabled = step === 0;
  $('#onboardingNext').textContent = step === 3 ? 'Открыть план' : 'Далее';
}

async function onboardingNext() {
  if (state.onboardingStep < 3) {
    state.onboardingStep += 1;
    renderOnboarding();
    return;
  }
  closeOnboarding(true);
  setView('diagnostics');
  await showPlan();
}

async function onboardingAction(event) {
  if (event.target.closest('[data-onboarding-nodes]')) { closeOnboarding(false); setView('nodes'); setNodeBrowserTab('all'); return; }
  const componentButton = event.target.closest('[data-onboarding-component]');
  const serviceButton = event.target.closest('[data-onboarding-service]');
  const refreshButton = event.target.closest('[data-onboarding-refresh]');
  if (refreshButton) {
    refreshButton.disabled = true;
    refreshButton.textContent = 'Проверка…';
    await refreshComponents(true);
    renderOnboarding();
    return;
  }
  if (componentButton) {
    const id = componentButton.dataset.onboardingComponent;
    closeOnboarding(false);
    const completed = await manageComponent(id, 'install');
    if (completed) state.onboardingStep = 2;
    openOnboarding(true);
  }
  if (serviceButton) {
    serviceButton.disabled = true;
    await toggleService(serviceButton.dataset.onboardingService);
    renderOnboarding();
  }
}

function formatBytes(n) {
  const value = Number(n || 0);
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 ** 3) return `${(value / (1024 ** 2)).toFixed(1)} MB`;
  return `${(value / (1024 ** 3)).toFixed(2)} GB`;
}

function formatRate(value) {
  return `${formatBytes(Number(value) || 0)}/с`;
}

function formatMemory(kb) {
  if (!kb) return '—';
  return `${Math.round(Number(kb) / 1024)} MB`;
}

function formatUptime(seconds) {
  const total = Math.max(0, Number(seconds) || 0);
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  return [days ? `${days}д` : '', `${hours}ч`, `${minutes}м`].filter(Boolean).join(' ');
}

function timeAgo(value) {
  if (!value) return '—';
  const ts = new Date(value).getTime();
  if (!Number.isFinite(ts)) return '—';
  const seconds = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (seconds < 5) return 'сейчас';
  if (seconds < 60) return `${seconds} сек`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} мин`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} ч`;
  return `${Math.floor(seconds / 86400)} д`;
}

function yesNo(v) {
  return v ? ['есть', 'probe-ok'] : ['нет', 'probe-no'];
}

function panelSectionState(key, phase, error = null) {
  state.dataLoad ||= {};
  const previous = state.dataLoad[key] || {};
  state.dataLoad[key] = { loaded: previous.loaded === true || phase === 'ready', phase,
    message: error?.message || '', updatedAt: phase === 'ready' ? Date.now() : previous.updatedAt };
}

function panelBusy(error) {
  return error?.status === 409 && (error.payload?.code === 'RESTORE_OPERATION_BUSY' || error.payload?.node_recovery?.state === 'revalidating');
}

function refreshPanelLoadNotice(show = false) {
  const owned = state.noticeDetails?.detail_kind === 'panel-load';
  const issues = (state.loadIssues || []).filter(issue => state.dataLoad?.[issue.section]?.phase !== 'ready');
  state.loadIssues = issues;
  if (!issues.length) { if (owned) hideNotice(); return; }
  if (!show && !owned) return;
  const busy = issues.every(issue => issue.busy);
  if (busy && state.dataLoad.services?.savedInstance) { if (owned) hideNotice(); return; }
  const retry = busy || panelLoad.retryCount < 3;
  showNotice('review', busy ? 'Сведения обновляются' : 'Часть данных временно недоступна',
    retry ? 'Загруженные разделы доступны. Последние полученные данные сохранены; повторим чтение автоматически.'
      : 'Загруженные разделы доступны. Автоматические попытки закончились; нажмите «Обновить», чтобы повторить.',
    { detail_kind: 'panel-load', issues });
}

function panelSnapshotCurrent(generation) {
  return generation === panelLoad.generation && !panelLoad.controller?.signal.aborted;
}

function schedulePanelRetry(busy = false) {
  clearTimeout(panelLoad.retryTimer);
  panelLoad.retryTimer = null;
  if (document.hidden || $('#authScreen')?.hidden === false || (!busy && panelLoad.retryCount >= 3)) return;
  if (!busy) panelLoad.retryCount++;
  panelLoad.retryTimer = setTimeout(() => { panelLoad.retryTimer = null; void refreshAll(true); }, busy ? 5000 : 10000);
}

function cancelPanelRefresh() {
  panelLoad.generation++;
  panelLoad.controller?.abort();
  panelLoad.controller = null;
  panelLoad.request = null;
  clearTimeout(panelLoad.retryTimer);
  panelLoad.retryTimer = null;
}

function renderPanelLoad() {
  state.uiRenderIssues ||= {};
  const render = (key, action) => {
    try { action(); delete state.uiRenderIssues[key]; }
    catch (_) { state.uiRenderIssues[key] = 'Не удалось обновить виджет. Последние данные сохранены.'; }
  };
  render('panel-snapshot', () => { if (typeof renderSavedPanelSnapshot === 'function') renderSavedPanelSnapshot(); });
  render('panel-settings-mode', () => { if (typeof renderSettingsMode === 'function') renderSettingsMode(); });
  const values = Object.values(state.dataLoad || {});
  render('panel-interface', () => { if (typeof renderInterface === 'function') renderInterface(); });
  render('panel-engine', () => {
    if (!state.dataLoad?.engineConfigs?.loaded && typeof renderEngineControl === 'function') renderEngineControl();
  });
  const text = values.some(value => value.phase === 'busy') ? 'Выполняется операция. Разделы можно открывать; данные обновятся автоматически.'
    : values.some(value => value.phase === 'error') ? 'Часть данных не обновилась. Последние полученные данные сохранены.'
    : Object.keys(state.uiRenderIssues).length ? 'Один из виджетов не обновился. Навигация и остальные разделы доступны.'
    : values.some(value => value.phase === 'loading') ? 'Загружаем данные разделов…' : '';
  if ($('#systemText') && text) $('#systemText').textContent = text;
  refreshPanelLoadNotice();
}

function renderPanelSection(key) {
  // Publish independent read results immediately, without an all-endpoints barrier.
  const renderers = {
    status: () => { renderStatus(); renderSettings(); },
    system: renderSystem, metrics: renderMetrics,
    inventory: () => { renderSystem(); renderEngines(); renderComponents(); },
    services: () => {
      renderServices(); renderOverviewQuickServices(); renderOverviewServices(); renderReadiness();
      if (state.dataLoad.testlab?.loaded) renderTestLab();
      if (state.dataLoad.warp?.loaded) renderWarpManager();
      if (state.dataLoad.strategyLab?.loaded) renderStrategyLab();
      if (state.dataLoad.engineConfigs?.loaded) renderEngineControl();
      if (state.dataLoad.dns?.loaded) renderDNSServiceBindings();
    },
    engines: renderEngines, engineConfigs: renderEngineControl, components: renderComponents,
    warp: renderWarpManager, sources: renderSources, nodes: renderNodes,
    nodeFeeds: renderNodes, nodeAutofallback: renderNodes,
    routeOptions: () => { renderServices(); if (state.dataLoad.testlab?.loaded) renderTestLab(); },
    connections: renderConnections, devices: renderDevices, testlab: renderTestLab,
    engineLab: renderEngineLab, audit: renderAudit, strategyLab: renderStrategyLab,
    z2kPreview: renderStrategyLab, smartRoute: renderStrategyLab,
    serviceControl: () => { if (typeof renderWorkspaceControls === 'function') renderWorkspaceControls(); },
    dns: renderDNS, dnsPlan: renderDNSPlan, sessions: renderSettings,
  };
  renderers[key]?.();
  if (typeof renderConsole === 'function') renderConsole();
  renderPanelLoad();
}

function acceptPanelSection(key, value, requestStartedAt) {
  if (key === 'inventory') { acceptPanelInventory(value, requestStartedAt); return; }
  const arrays = ['services', 'engines', 'engineConfigs', 'components', 'sources', 'routeOptions'];
  if (arrays.includes(key) && !Array.isArray(value)) throw new Error('Получен неполный список. Последние данные сохранены.');
  if (value === null || typeof value !== 'object') throw new Error('Получен неполный ответ. Последние данные сохранены.');
  if (key === 'serviceControl') { if (typeof acceptWorkspaceControl === 'function') acceptWorkspaceControl(value); else state.serviceControl = value; }
  else if (key === 'devices') acceptDeviceList(value);
  else state[key] = key === 'sessions' ? (value.sessions || []) : value;
  panelSectionState(key, 'ready');
}

function acceptPanelInventory(value, requestStartedAt = Date.now()) {
  if (value?.schema !== 1 || value.dataplane !== 'not-checked'
    || !['empty', 'available', 'retained', 'expired'].includes(value.state)
    || !Number.isSafeInteger(value.revision) || value.revision < 0
    || !Number.isFinite(value.data_age_ms) || value.data_age_ms < 0
    || value.max_age_seconds !== 300) throw new Error('Сведения о компонентах получены не полностью.');
  const previous = state.inventoryObservation;
  if (previous?.instance === value.instance_id && previous.revision > value.revision) return;
  const observed = Date.parse(value.observed_at);
  if (!value.data || !Number.isFinite(observed) || value.data_age_ms >= 300000
    || !['available', 'retained'].includes(value.state)
    || requestStartedAt - value.data_age_ms < (state.inventoryInvalidatedAt || 0)) {
    throw Object.assign(new Error('Новые сведения о компонентах ещё собираются. Последние данные сохранены.'), { status: 409, payload: { code: 'RESTORE_OPERATION_BUSY' } });
  }
  if (typeof value.instance_id !== 'string' || value.instance_id.length !== 32
    || !Array.isArray(value.data.components) || value.data.components.length > 64
    || !Array.isArray(value.data.engines) || value.data.engines.length > 64
    || !value.data.system || typeof value.data.system !== 'object'
    || value.data.components.some(c => typeof c.id !== 'string' || typeof c.installed !== 'boolean')
    || value.data.engines.some(c => typeof c.id !== 'string' || typeof c.installed !== 'boolean')) {
    throw new Error('Сведения о компонентах получены не полностью.');
  }
  state.inventoryObservation = { instance: value.instance_id, revision: value.revision,
    observedAt: value.observed_at, receivedAt: Date.now(), ageMS: value.data_age_ms,
    localObservedBefore: requestStartedAt - value.data_age_ms, retained: value.state === 'retained' };
  state.components = value.data.components;
  state.engines = value.data.engines;
  state.system = value.data.system;
  for (const key of ['components', 'engines', 'system', 'inventory']) panelSectionState(key, 'ready');
}

function inventoryObservationStale() {
  const value = state.inventoryObservation;
  return !!value && (value.retained || value.localObservedBefore < (state.inventoryInvalidatedAt || 0)
    || value.ageMS + Math.max(0, Date.now() - value.receivedAt) >= 60000);
}

function cancelPanelInventoryRefresh() {
  inventoryRead?.controller.abort();
  inventoryRead = null;
}

function refreshPanelInventory() {
  if (!state.authenticated || document.hidden || state.inventoryUnsupported || panelLoad.request) return Promise.resolve(false);
  if (inventoryRead) return inventoryRead.promise;
  const ticket = { generation: panelLoad.generation, controller: new AbortController(), promise: null };
  inventoryRead = ticket;
  const current = () => inventoryRead === ticket && state.authenticated && !document.hidden && panelSnapshotCurrent(ticket.generation);
  ticket.promise = Promise.resolve().then(async () => {
    try {
      const started = Date.now();
      const value = await api('/api/v1/panel/inventory', { signal: ticket.controller.signal, readTimeoutMs: 3000 });
      if (!current()) return false;
      acceptPanelInventory(value, started);
      return true;
    } catch (error) {
      if (!current()) return false;
      if (error.status === 401) { cancelPanelRefresh(); showAuth({ authenticated: false }, 'Сессия завершилась. Войдите снова.'); return false; }
      if (error.status === 404) state.inventoryUnsupported = true;
      panelSectionState('inventory', panelBusy(error) ? 'busy' : 'error', error);
      return false;
    } finally {
      if (current()) {
        // Metadata-only renderers: periodic observation must not redraw forms
        // or lose a partially edited profile/service/DNS field.
        try { renderComponents(); renderEngines(); renderSystem(); if (typeof renderInterfaceEngines === 'function') renderInterfaceEngines(); } catch (_) { /* Independent from polling lifetime. */ }
        refreshPanelLoadNotice();
      }
      if (inventoryRead === ticket) inventoryRead = null;
    }
  });
  return ticket.promise;
}

async function settlePanelReads(requests, read) {
  let next = 0;
  await Promise.allSettled(Array.from({ length: Math.min(4, requests.length) }, async () => {
    while (next < requests.length) await read(requests[next++]);
  }));
}

async function refreshAll(retryFailed = false) {
  if (panelLoad.request) return panelLoad.request;
  if (!retryFailed) panelLoad.retryCount = 0;
  clearTimeout(panelLoad.retryTimer);
  panelLoad.retryTimer = null;
  const generation = ++panelLoad.generation;
  panelLoad.controller = new AbortController();
  const pending = loadPanelSnapshot(generation, retryFailed);
  panelLoad.request = pending;
  try { return await pending; }
  finally { if (panelLoad.request === pending) { panelLoad.request = null; panelLoad.controller = null; } }
}

async function refreshAfterMutation() {
  // Readback cannot join a snapshot admitted before the completed write.
  // Abort transport and fence late bodies even when cancellation is ignored.
  cancelPanelRefresh();
  state.inventoryInvalidatedAt = Date.now();
  if ($('#authScreen')?.hidden === false) return false;
  return refreshAll();
}

async function loadPanelSnapshot(generation, retryFailed = false) {
  const issues = [];
  const options = { signal: panelLoad.controller.signal };
  const retryKeys = new Set(Object.entries(state.dataLoad || {}).filter(([, value]) => !value.loaded || ['error', 'busy'].includes(value.phase)).map(([key]) => key));
  for (const key of ['status', 'services', 'engineConfigs']) {
    if (key === 'status' || !retryFailed || retryKeys.has(key)) panelSectionState(key, 'loading');
  }
  renderPanelLoad();
  try {
    // Authentication is the only prerequisite. A runtime status or a probe
    // job is not an authentication decision and must not gate the whole UI.
    const authentication = await api('/api/v1/auth/status', options);
    if (!panelSnapshotCurrent(generation)) return false;
    if (authentication.setup_required || !authentication.authenticated) {
      const status = await api('/api/v1/status', options).catch(() => authentication);
      if (!panelSnapshotCurrent(generation)) return false;
      state.status = status;
      try { renderStatus(); } catch (_) { /* Login must survive a failed widget. */ }
      showAuth(status); $('#systemText').textContent = 'Требуется вход'; return false;
    }
    hideAuth();
    if (typeof loadSavedPanelSnapshot === 'function') void loadSavedPanelSnapshot(generation, options);
    // This already has its own single-flight scheduler and auth epoch.
    // Never await it here: a slow job-status endpoint is an isolated failure.
    scheduleNodeActivity(0);
    const requests = [
      ['status', '/api/v1/status'],
      ['inventory', '/api/v1/panel/inventory'],
      ['metrics', '/api/v1/metrics?limit=120'],
      ['services', '/api/v1/services'],
      ['engineConfigs', '/api/v1/engine-configs'],
      ['warp', '/api/v1/warp'],
      ['sources', '/api/v1/sources'],
      ['nodes', '/api/v1/nodes'],
      ['nodeFeeds', '/api/v1/node-feeds'],
      ['nodeAutofallback', '/api/v1/node-autofallback'],
      ['routeOptions', '/api/v1/routes/options'],
      ['connections', '/api/v1/connections?include_closed=true'],
      ['devices', '/api/v1/devices?view=status'],
      ['testlab', '/api/v1/testlab'],
      ['engineLab', '/api/v1/engine-lab'],
      ['audit', '/api/v1/audit/current?limit=40'],
      ['strategyLab', '/api/v1/strategy-lab'],
      ['z2kPreview', '/api/v1/migrations/z2k/preview'],
      ['smartRoute', '/api/v1/smart-route'],
      ['serviceControl', '/api/v1/service-control'],
      ['dns', '/api/v1/dns'],
      ['dnsPlan', '/api/v1/dns/plan'],
      ['sessions', '/api/v1/auth/sessions'],
    ].filter(([key]) => key === 'status' || !retryFailed || retryKeys.has(key) || !state.dataLoad[key]?.loaded);
    requests.forEach(([key]) => panelSectionState(key, 'loading'));
    renderPanelLoad();
    await settlePanelReads(requests, async ([key, url]) => {
      if (!panelSnapshotCurrent(generation)) return;
      try {
        const requestStartedAt = Date.now();
        const value = await api(url, options);
        if (!panelSnapshotCurrent(generation)) return;
        if (key === 'status' && (value?.setup_required || (value?.auth_required && !value?.authenticated))) {
          cancelPanelRefresh();
          showAuth(value); $('#systemText').textContent = 'Требуется вход'; return;
        }
        acceptPanelSection(key, value, requestStartedAt);
        renderPanelSection(key);
      } catch (error) {
        if (!panelSnapshotCurrent(generation)) return;
        if (error.status === 401) {
          cancelPanelRefresh();
          showAuth({ ...state.status, authenticated: false }, 'Сессия завершилась. Войдите снова.');
          return;
        }
        if (error.payload?.node_recovery?.state === 'revalidating') {
          state.status = { ...state.status, node_recovery: error.payload.node_recovery, live_active: false, dataplane_recovery_state: 'network-stale' };
        }
        panelSectionState(key, panelBusy(error) ? 'busy' : 'error', error);
        issues.push({ section: key, url, busy: panelBusy(error), message: error.message || 'Раздел временно недоступен', technical: error.technicalMessage || '' });
        renderPanelLoad();
      }
    });
    if (!panelSnapshotCurrent(generation)) return false;
    state.loadIssues = issues;
    renderPanelLoad();
    if (issues.length) {
      const busy = Object.values(state.dataLoad).some(value => value.phase === 'busy');
      // Availability and the saved-image notice already explain an operation
      // in progress. Keep a separate warning only for additional failures.
      refreshPanelLoadNotice(true);
      schedulePanelRetry(busy);
    } else { panelLoad.retryCount = 0; }
    if (!state.onboardingAutoEvaluated && state.dataLoad.services?.loaded && state.dataLoad.engineConfigs?.loaded) {
      state.onboardingAutoEvaluated = true;
      if(typeof consoleInitialSetup==='function')consoleInitialSetup();else setTimeout(() => openOnboarding(false), 0);
    }
    return true;
  } catch (error) {
    if (!panelSnapshotCurrent(generation)) return false;
    // This is an authentication/bootstrap failure, NOT a failed service list.
    // Keep independent snapshots and never fabricate empty configuration.
    const busy = panelBusy(error);
    for (const key of ['status', 'services', 'engineConfigs']) {
      if (state.dataLoad[key]?.phase === 'loading') panelSectionState(key, busy ? 'busy' : 'error', error);
    }
    state.loadIssues = [{ section: 'authentication', message: error.message }];
    renderPanelLoad();
    if (error.status === 401) showAuth({ ...state.status, authenticated: false }, 'Сессия завершилась. Войдите снова.');
    else {
      showNotice('review', 'Данные пока не обновились', error.message, { response: error.payload });
      schedulePanelRetry(busy);
    }
    return false;
  }
}

function renderAll() {
  renderStatus();
  renderSystem();
  renderMetrics();
  renderServices();
  renderOverviewQuickServices();
  renderOverviewServices();
  renderReadiness();
  renderEngines();
  renderComponents();
  renderWarpManager();
  renderEngineControl();
  renderSources();
  renderNodes();
  renderConnections();
  renderDevices();
  renderTestLab();
  renderEngineLab();
  renderAudit();
  renderStrategyLab();
  renderDNS();
  renderSettings();
  if(typeof renderConsole==='function')renderConsole();
}

function renderComponents() {
  const counts = {
    all: state.components.length,
    installed: state.components.filter((c) => c.installed).length,
    available: state.components.filter((c) => !c.installed && c.available).length,
    updates: state.components.filter((c) => c.update_available).length,
  };
  $('#componentSummary').innerHTML = `<div><span>Установлено</span><b>${counts.installed}</b></div><div><span>Можно установить</span><b>${counts.available}</b></div><div class="${counts.updates ? 'attention' : ''}"><span>Обновления</span><b>${counts.updates}</b></div><div><span>Всего компонентов</span><b>${counts.all}</b></div>`;
  $$('#componentFilters [data-component-filter]').forEach((button) => {
    const filter = button.dataset.componentFilter;
    button.classList.toggle('active', filter === state.componentFilter);
    const count = counts[filter] ?? 0;
    button.textContent = `${{ all: 'Все', installed: 'Установлены', available: 'Можно установить', updates: 'Есть обновления' }[filter]} · ${count}`;
  });
  const visible = state.components.filter((component) => {
    if (state.componentFilter === 'installed') return component.installed;
    if (state.componentFilter === 'available') return !component.installed && component.available;
    if (state.componentFilter === 'updates') return component.update_available;
    return true;
  });
  $('#componentEmpty').hidden = visible.length > 0;
  $('#componentStrip').hidden = visible.length === 0;
  $('#componentStrip').innerHTML = visible.map((c) => {
    let version = 'нет в подключённых репозиториях';
    let actions = '';
    const info = typeof consoleEngineState === 'function' ? consoleEngineState(c.id) : null;
    const update = info ? consoleEngineUpdateState(info) : null;
    const stale = c.catalog_stale || c.update_check_error || c.inventory_error || state.componentCatalogError || update?.kind === 'failed';
    const busy = !!state.componentOperation || !!state.componentRefreshRequest || c.operation_status === 'running';
    const unavailable = busy || c.running || c.external_owner || inventoryObservationStale();
    if (c.update_available) {
      version = info ? consoleEngineVersionLabel(info) : `${c.installed_version || 'Версия неизвестна'}${c.available_version ? ` → ${c.available_version}` : ''}`;
      actions += `<button class="primary component-action" data-component="${esc(c.id)}" data-component-action="update" ${c.can_update && !stale && !unavailable ? '' : 'disabled'}>Обновить</button>`;
    } else if (c.installed) {
      version = `установлена ${c.installed_version || '—'}`;
      actions += `<span class="engine-state installed">${update?.kind === 'current' ? 'АКТУАЛЬНО' : 'УСТАНОВЛЕН'}</span>`;
    } else if (c.available) {
      version = `доступна ${c.available_version || '—'}`;
      actions += `<button class="primary component-action" data-component="${esc(c.id)}" data-component-action="install" ${c.can_install && !stale && !unavailable ? '' : 'disabled'}>Установить</button>`;
    }
    if (c.installed && state.engineConfigs.some((engine) => engine.id === c.id)) actions += `<button class="mini-button component-config" data-engine-config="${esc(c.id)}">Настроить</button>`;
    if (c.can_remove && !c.external_owner) actions += `<button class="component-remove component-action" data-component="${esc(c.id)}" data-component-action="remove" ${unavailable || c.inventory_error ? 'disabled' : ''}>Удалить</button>`;
    if (c.external_owner) actions = '<span class="external-owner-tag">ВНЕШНЕЕ УПРАВЛЕНИЕ</span>';
    const budget = c.resource_budget || {};
    const budgetText = [budget.ram_mib ? `${budget.ram_mib} МиБ RAM` : '', budget.flash_mib ? `${budget.flash_mib} МиБ flash` : '', budget.cpu_class || ''].filter(Boolean).join(' · ');
    const statusClass = c.update_available ? 'has-update' : c.installed ? 'is-installed' : c.available ? 'is-available' : 'is-unavailable';
    const verification = c.verification === 'verified'
      ? ['verified', `УСТАНОВКА ПРОВЕРЕНА${c.verified_version ? ` · ${c.verified_version}` : ''}`]
      : c.verification === 'verified-removed'
      ? ['verified', 'УДАЛЕНИЕ ПРОВЕРЕНО']
      : c.verification === 'changed-after-verification'
      ? ['warning', 'СОСТОЯНИЕ ИЗМЕНИЛОСЬ ПОСЛЕ ПРОВЕРКИ']
      : c.verification === 'receipt-error'
      ? ['failed', 'ОШИБКА ЧТЕНИЯ РЕЗУЛЬТАТА УСТАНОВКИ']
      : c.installed
      ? ['unverified', 'УСТАНОВЛЕН ВНЕ RAZVILKA ИЛИ ЕЩЁ НЕ ПРОВЕРЕН']
      : ['', ''];
    const runtime = c.running ? '<span class="component-runtime running">ЗАПУЩЕН</span>' : c.configured ? '<span class="component-runtime configured">НАСТРОЕН · НЕ ЗАПУЩЕН</span>' : c.installed ? '<span class="component-runtime">НЕ НАСТРОЕН</span>' : '';
    const verificationHTML = verification[1] ? `<span class="component-verification ${verification[0]}">${verification[1]}${c.last_action_at ? ` · ${esc(timeAgo(c.last_action_at))} назад` : ''}</span>` : '';
    const operationName = ({ install: 'УСТАНОВКА', update: 'ОБНОВЛЕНИЕ', remove: 'УДАЛЕНИЕ' })[c.operation_action] || 'ОПЕРАЦИЯ';
    const operationLabels = {
      running: ['running', `${operationName} ВЫПОЛНЯЕТСЯ`],
      succeeded: ['', `${operationName} ЗАВЕРШЕНО`],
      failed: ['failed', `${operationName} ЗАВЕРШИЛОСЬ ОШИБКОЙ`],
      interrupted: ['failed', `${operationName} БЫЛО ПРЕРВАНО`],
      'receipt-error': ['failed', 'РЕЗУЛЬТАТ ОПЕРАЦИИ НЕ ЧИТАЕТСЯ'],
    };
    const operation = operationLabels[c.operation_status];
    const operationHTML = operation
      ? `<span class="component-operation ${operation[0]}" title="${esc(c.operation_message || '')}">${operation[1]}${c.operation_at ? ` · ${esc(timeAgo(c.operation_at))} назад` : ''}</span>`
      : '';
    const operationDetail = ['failed', 'interrupted', 'receipt-error'].includes(c.operation_status) && c.operation_message
      ? `<small class="component-operation-message">${esc(friendlyDetail(c.operation_message))}</small>`
      : '';
    return `<div class="component-item ${statusClass} ${c.external_owner ? 'external' : ''}"><div><b>${esc(c.name)}</b><small>${esc(c.description || '')}</small>${c.use_case ? `<small class="component-purpose"><strong>Подходит:</strong> ${esc(c.use_case)}</small>` : ''}${c.requirement ? `<small class="component-requirement"><strong>Нужно:</strong> ${esc(c.requirement)}</small>` : ''}<small class="component-budget">${esc(budgetText)}</small><small class="component-version ${c.update_available ? 'update' : ''}">${esc(version)}</small><div class="component-health-line">${verificationHTML}${runtime}${operationHTML}</div>${operationDetail}</div><div class="component-actions">${actions}</div></div>`;
  }).join('');
}

async function refreshComponents(refresh = true) {
  if (state.componentRefreshRequest) return state.componentRefreshRequest;
  const epoch = workflowState.epoch;
  if (!workflowSession(epoch)) return false;
  const button = $('#refreshComponents');
  button.disabled = true; button.textContent = 'Проверка…';
  const request = Promise.resolve().then(async () => {
    try {
      if (!refresh) {
        const requestStartedAt = Date.now();
        const observation = await api('/api/v1/panel/inventory');
        if (!workflowSession(epoch)) return false;
        acceptPanelInventory(observation, requestStartedAt);
        return true;
      }
      const components = await api('/api/v1/components?refresh=true', { readTimeoutMs: 110000 });
      if (!workflowSession(epoch)) return false;
      if (!Array.isArray(components)) throw new Error('Получен неполный каталог. Последние данные сохранены.');
      state.components = components;
      state.inventoryInvalidatedAt = Date.now();
      if (refresh) state.componentCatalogError = '';
      panelSectionState('components', 'ready');
      return true;
    } catch (error) {
      if (!workflowSession(epoch)) return false;
      state.componentCatalogError = error.message;
      panelSectionState('components', panelBusy(error) ? 'busy' : 'error', error);
      showNotice('error', 'Обновления не проверены', 'Последние сведения об установленных компонентах сохранены. Проверьте доступ к источникам и повторите запрос.', { error: error.message });
      return false;
    } finally {
      if (state.componentRefreshRequest === request) state.componentRefreshRequest = null;
      if (workflowSession(epoch)) {
        button.disabled = false; button.textContent = 'Проверить обновления';
        renderComponents(); renderEngineControl();
        if (typeof renderConsole === 'function') renderConsole();
        if (typeof renderInterfaceEngines === 'function') renderInterfaceEngines();
      }
    }
  });
  state.componentRefreshRequest = request;
  if (typeof renderInterfaceEngines === 'function') renderInterfaceEngines();
  return request;
}

async function manageComponent(id, requestedAction) {
  if (state.componentOperation || state.componentRefreshRequest || !workflowSession(workflowState.epoch)) return false;
  const component = state.components.find(c => c.id === id);
  if (!component) return false;
  const action = requestedAction || (component.update_available ? 'update' : 'install');
  if (!['install', 'update', 'remove'].includes(action)) return false;
  const operation = { id, action, epoch: workflowState.epoch };
  state.componentOperation = operation;
  $$('.component-action').forEach(button => { button.disabled = true; });
  if (typeof renderInterfaceEngines === 'function') renderInterfaceEngines();
  try { return await manageComponentReviewed(id, action); }
  finally {
    if (state.componentOperation === operation) state.componentOperation = null;
    if (workflowSession(operation.epoch)) {
      renderComponents();
      if (typeof renderInterfaceEngines === 'function') renderInterfaceEngines();
    }
  }
}

async function manageComponentReviewed(id, requestedAction) {
  const epoch=workflowState.epoch;
  const component = state.components.find((c) => c.id === id);
  if (!component) return false;
  const action = requestedAction || (component.update_available ? 'update' : 'install');
  const verbs = { install: 'Установить', update: 'Обновить', remove: 'Удалить' };
  const verb = verbs[action] || 'Выполнить';
  const source = component.provider === 'opkg'
    ? 'официальный/подключённый Entware feed'
    : 'официальный GitHub release с обязательной проверкой checksums.txt';
  let plan;
  try {
    plan = await api(`/api/v1/components/${encodeURIComponent(id)}/plan?action=${encodeURIComponent(action)}`, { readTimeoutMs: 110000 });
  } catch (error) {
    if(!workflowSession(epoch))return false;
    showDetails({ error: error.message, response: error.payload }, `${component.name}: план недоступен`);
    return false;
  }
  if(!workflowSession(epoch))return false;
  if (!plan.ready) {
    showDetails(plan, `${component.name}: действие заблокировано`);
    return false;
  }
  const operation = action === 'remove'
    ? 'Будет удалён только пакет/файл, принадлежащий RAZVILKA. Конфликты, активный процесс или зависимые сервисы блокируют действие.'
    : `Источник: ${source}. После установки обход останется выключенным, пока вы явно не назначите сервисы и не выполните общий Apply.`;
  if (!await askConfirmation(`${verb} ${component.name}`, `${operation} План содержит ${plan.steps?.length || 0} проверяемых этапов, фиксирует версии до/после и не включает маршруты автоматически.`, verb)) return false;
  if(!workflowSession(epoch))return false;
  const buttons = $$(`.component-action[data-component="${CSS.escape(id)}"]`);
  buttons.forEach((button) => { button.disabled = true; button.textContent = 'Выполняется…'; });
  try {
    const result = await api(`/api/v1/components/${encodeURIComponent(id)}/${encodeURIComponent(action)}`, { method: 'POST' });
    if(!workflowSession(epoch))return false;
    if (result?.ok !== true) throw new Error('Сервер не подтвердил завершение операции с компонентом.');
    if (!await refreshComponents(false)) throw new Error('Операция отправлена, но повторная проверка состояния не завершена.');
    if(!workflowSession(epoch))return false;
    const [engines, engineConfigs] = await Promise.all([api('/api/v1/engines'), api('/api/v1/engine-configs')]);
    if(!workflowSession(epoch))return false;
    Object.assign(state, { engines, engineConfigs });
    renderEngines(); renderEngineControl();
    showNotice('success', `${component.name}: ${action === 'remove' ? 'удаление завершено' : 'установка проверена'}`, action === 'remove' ? 'Компонент удалён и повторная проверка подтвердила результат.' : 'Версия повторно прочитана с роутера, контрольный результат сохранён. Маршруты сервисов пока не менялись.', { plan, result });
    showDetails({ plan, result }, `${component.name}: готово`);
    return true;
  } catch (error) {
    if(!workflowSession(epoch))return false;
    await refreshComponents(false);
    if(!workflowSession(epoch))return false;
    showNotice('error', `${component.name}: ${action === 'remove' ? 'удаление' : action === 'update' ? 'обновление' : 'установка'} не завершено`, 'RAZVILKA не подтвердила итоговое состояние. Причина сохранена в карточке компонента; устраните её и повторите операцию. Маршруты автоматически не включались.', { error: error.message, response: error.payload, plan });
    showDetails({ error: error.message, response: error.payload, plan }, `${component.name}: ошибка`);
    return false;
  }
}

function renderStatus() {
  const s = state.status;
  const engineDrafts = Number(s.engine_config_drafts || 0);
  $('#version').textContent = `v${s.version || '—'}`;
  $('#footerVersion').textContent = `v${s.version || '—'}`;
  const buildCommit = s.build_commit && s.build_commit !== 'unknown' ? String(s.build_commit).slice(0, 10) : 'commit неизвестен';
  const buildState = s.build_dirty_known ? (s.build_dirty ? 'есть локальные изменения' : 'чистая сборка') : 'состояние исходников неизвестно';
  const buildTime = s.build_time && s.build_time !== 'unknown' ? new Date(s.build_time).toLocaleString('ru-RU') : 'дата сборки неизвестна';
  $('#settingBuild').textContent = `v${s.version || '—'} · ${buildCommit}`;
  $('#settingBuild').title = `${buildState} · ${buildTime}`;
  $('#settingBuildDetails').textContent = `${buildTime} · ${buildState}`;
  $('#listenChip').textContent = s.listen || ':8787';
  $('#systemText').textContent = s.safe_mode ? 'Изменения заблокированы' : (s.live_active ? 'Маршруты активны' : 'Маршруты не включены');
  if (typeof renderWorkspaceControls === 'function') renderWorkspaceControls();
  if (typeof renderAppVersionStatus === 'function') renderAppVersionStatus();
  $('#topUptime').textContent = formatUptime(s.uptime_seconds);
  $('#kpiState').textContent = s.live_active ? 'Активна' : (s.safe_mode ? 'Безопасный режим' : 'Не применено');
  $('#kpiStateSub').textContent = s.live_active ? 'конфигурация применена' : (s.safe_mode ? 'рабочие маршруты не изменяются' : 'нет подтверждённого применения');
  $('#kpiEngines').textContent = `${s.engines_running ?? '—'} / ${s.engines_installed ?? '—'}`;
  $('#kpiServices').textContent = `${s.enabled_services ?? '—'} / ${s.catalog_services ?? '—'}`;
  $('#kpiConnections').textContent = s.active_connections ?? '—';
  $('#connectionCounter').textContent = s.active_connections ?? '—';
  $('#serviceNavCount').textContent = s.enabled_services ?? '—';
  $('#serviceDraftBar').classList.toggle('show', !!s.services_pending_changes);
  $('#serviceDraftBar').classList.toggle('safe-review', !!s.safe_mode);
  renderPendingServiceChanges();
  $('#applyServiceChanges').textContent = s.safe_mode ? 'Проверить изменения' : 'Проверить и применить';
  $('#deviceDraftBar').classList.toggle('show', !!s.devices_pending_changes);
  $('#deviceDraftBar').classList.toggle('safe-review', !!s.safe_mode);
  $('#sourceDraftBar').classList.toggle('show', !!s.sources_pending_changes);
  $('#sourceDraftBar').classList.toggle('safe-review', !!s.safe_mode);
  $('#applyDeviceChanges').textContent = s.safe_mode ? 'Проверить изменения' : 'Проверить и применить';
  const pendingViews = pendingChangeViews(s);
  $('#draftBar').classList.toggle('show', pendingViews.some(view => view !== state.currentView));
  $('#draftBar').classList.toggle('safe-review', !!s.safe_mode);
  const failedApply = !s.safe_mode && !!s.pending_changes && !!s.last_apply_failure;
  $('#draftBar').classList.toggle('apply-failed', failedApply);
  $('#draftTitle').textContent = failedApply
    ? 'Применение не завершено'
    : 'Изменения ожидают применения';
  $('#draftHint').textContent = failedApply && s.last_apply_failure === 'WARP_WIREGUARD_HANDSHAKE'
    ? 'WARP WireGuard не получил ответ ни на одном резервном UDP-порту. Проверьте Cloudflare и используйте WARP · MASQUE по TCP/443 либо свой сервер.'
    : failedApply && s.last_apply_failure === 'WARP_MASQUE_SERVICE_TIMEOUT'
    ? 'Cloudflare принял MASQUE-сессию, но сервис не ответил через туннель. После одной смены сессии выберите Sing-box/VLESS или AmneziaWG со своим сервером.'
    : failedApply && s.last_apply_failure === 'SING_BOX_NODE_UNREACHABLE'
    ? 'Публичный ключ прошёл проверку формата, но не реальное подключение. Импортируйте несколько свежих ключей одним списком для автоматического локального выбора.'
    : failedApply
    ? 'Новый маршрут не прошёл проверку. Откройте изменённый раздел и проверьте состояние.'
    : engineDrafts > 0
    ? 'Откройте настройки нужного подключения, чтобы проверить и применить его изменения.'
    : 'Откройте изменённый раздел. Применение затронет только выбранную область.';
  $('#applyChanges').textContent = 'Открыть изменения';
  $('#applySettings').textContent = s.safe_mode ? 'Проверить изменения' : (failedApply ? 'Повторить проверку' : 'Проверить и применить');
  $('#discardChanges').hidden = true;
}

function openPendingChanges() {
  const views = pendingChangeViews(state.status || {});
  const view = views.find(name => name !== state.currentView) || views[0];
  if (!view) {
    showNotice('info', 'Изменений для применения нет', 'Все полученные настройки уже применены.');
    return;
  }
  if (view === 'services' && typeof interfaceOpenServiceChanges === 'function') {
    interfaceOpenServiceChanges();
    return;
  }
  if (view === 'engineconfig') {
    void openPendingEngineChanges().catch(error => showNotice('error', 'Не удалось открыть изменения', error.message));
    return;
  }
  setView(view);
  const target = $({ devices: '#deviceDraftBar', sources: '#sourceDraftBar', dns: '#view-dns', engineconfig: '#view-engineconfig' }[view]);
  target?.scrollIntoView({ block: 'center', behavior: 'smooth' });
}

async function openPendingEngineChanges() {
  const changed = (state.engineConfigs || []).filter(engine => (engine.files || []).some(file => file.staged));
  const engine = changed.find(item => item.id === state.selectedEngine) || changed[0];
  if (!engine) {
    setView('engineconfig');
    showNotice('info', 'Получаем состав изменений', 'Обновите состояние панели, чтобы открыть изменённый файл.');
    return;
  }
  if (state.engineIntent) {
    showNotice('info', 'Настройки проверяются', 'Дождитесь завершения текущей операции.');
    return;
  }
  const file = engine.files.find(item => item.staged);
  if (state.selectedEngine !== engine.id) {
    await selectEngine(engine.id);
    if (state.selectedEngine !== engine.id) return; // The user kept an unsaved editor.
  }
  if (state.selectedEngineFile !== file.id) {
    await selectEngineFile(file.id);
    if (state.selectedEngineFile !== file.id) return;
  }
  setView('engineconfig');
  switchEngineTab('config');
  $('#engineFileSelect')?.focus();
  $('#view-engineconfig')?.scrollIntoView({ block: 'start', behavior: 'smooth' });
}

function pendingChangeViews(status) {
  const views = [];
  if (status.services_pending_changes) views.push('services');
  if (status.devices_pending_changes) views.push('devices');
  if (status.sources_pending_changes) views.push('sources');
  if (status.dns_pending_changes) views.push('dns');
  if (status.engine_pending_changes || Number(status.engine_config_drafts || 0) > 0) views.push('engineconfig');
  return views;
}

function renderPendingServiceChanges() {
  const changed = (state.services || []).filter(service => service.route_dirty || service.enabled !== !!service.applied_enabled);
  $('#serviceChangeSummary').textContent = changed.length ? changed.map(service => {
    const before = service.applied_enabled ? routeLabel(service.applied_route) : 'Выключен';
    const after = service.enabled ? routeLabel(service.route) : 'Выключен';
    return `${service.name}: ${before} → ${after}${!service.enabled && !service.applied_enabled ? `; сохранённый маршрут: ${routeLabel(service.route)}` : ''}`;
  }).join('\n') : 'Получаем состав изменений сервисов…';
}

function renderSystem() {
  const s = state.system || {};
  $('#kpiWan').textContent = s.wan_interface || '—';
  $('#kpiArch').textContent = [s.architecture, s.kernel].filter(Boolean).join(' · ') || 'не определено';

  const values = [
    ['Архитектура', s.architecture || '—', true],
    ['Ядро системы', s.kernel || '—', !!s.kernel],
    ['Имя роутера', s.hostname || '—', !!s.hostname],
    ['WAN', s.wan_interface || '—', !!s.wan_interface],
    ['RAM', `${formatMemory(s.mem_available_kb)} свободно / ${formatMemory(s.mem_total_kb)}`, !!s.mem_total_kb],
    ['/opt', ...yesNo(s.opt_ready)],
    ['opkg', ...yesNo(s.opkg)],
    ['Управление маршрутами', ...yesNo(s.ip_command)],
    ['/dev/net/tun', ...yesNo(s.tun)],
    ['iptables', ...yesNo(s.iptables)],
    ['ip6tables', ...yesNo(s.ip6tables)],
    ['nftables', ...yesNo(s.nftables)],
    ['NFQUEUE', ...yesNo(s.nfqueue)],
		['ipset', s.ipset ? 'есть' : 'не установлен', s.ipset ? 'probe-ok' : 'probe-warn'],
		['TProxy · TCP/UDP', s.tproxy ? 'поддерживается' : 'модуль не обнаружен', s.tproxy ? 'probe-ok' : 'probe-warn'],
		['Socket match · быстрый путь', s.socket_match ? 'поддерживается' : 'модуль не обнаружен', s.socket_match ? 'probe-ok' : 'probe-warn'],
		['Conntrack · активность', s.conntrack ? 'доступен' : 'ограничено', s.conntrack ? 'probe-ok' : 'probe-warn'],
    ['Внешние туннели', s.route_contamination ? (s.external_tunnels || []).join(', ') || 'обнаружены' : 'не обнаружены', s.route_contamination ? 'probe-warn' : 'probe-ok'],
  ];
  $('#systemProbe').innerHTML = values.map(([name, value, okOrClass]) => {
    const cls = typeof okOrClass === 'string' ? okOrClass : (okOrClass ? 'probe-ok' : 'probe-no');
    return `<div class="probe-row"><span>${esc(name)}</span><b class="${cls}">${esc(value)}</b></div>`;
  }).join('');
}

function metricPolyline(history, key, width = 360, height = 76) {
  const values = history.map((item) => Number(item[key]) || 0);
  const ceiling = Math.max(...values, 1);
  if (values.length < 2) return '';
  return values.map((value, index) => {
    const x = (index / (values.length - 1)) * width;
    const y = height - ((value / ceiling) * (height - 6)) - 3;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
}

function renderMetrics() {
  const metrics = state.metrics || {};
  const latest = metrics.latest || {};
  const history = metrics.history || [];
  const capacity = metrics.capacity || {};
  const labels = { high: 'Хороший запас', medium: 'Умеренный запас', low: 'Мало ресурсов', critical: 'Критично', unknown: 'Нет данных' };
  $('#routerCapacity').textContent = labels[capacity.level] || labels.unknown;
  $('#routerCapacity').className = `capacity-value ${esc(capacity.level || 'unknown')}`;
  $('#routerCapacityHint').textContent = (capacity.reasons || []).join(' · ') || 'Ожидаем системные счётчики';
  $('#metricCPU').textContent = latest.cpu_ready ? `${Number(latest.cpu_percent || 0).toFixed(0)}%` : 'сбор…';
  $('#metricRAM').textContent = latest.memory_total_bytes ? `${Number(latest.memory_used_percent || 0).toFixed(0)}%` : '—';
  $('#metricDisk').textContent = latest.disk_total_bytes ? `${Number(latest.disk_used_percent || 0).toFixed(0)}%` : '—';
  $('#metricTemp').textContent = latest.temperature_c ? `${Number(latest.temperature_c).toFixed(0)} °C` : '—';
  $('#topCPU').textContent = latest.cpu_ready ? `${Number(latest.cpu_percent || 0).toFixed(0)}%` : '—';
  $('#topRAM').textContent = latest.memory_total_bytes ? `${Number(latest.memory_used_percent || 0).toFixed(0)}%` : '—';
  $('#metricDownload').textContent = latest.traffic_ready ? formatRate(latest.rx_bytes_per_second) : 'сбор…';
  $('#metricUpload').textContent = latest.traffic_ready ? formatRate(latest.tx_bytes_per_second) : 'сбор…';
  $('#trafficWAN').textContent = latest.wan_interface || 'WAN не определён';
  const periods = metrics.traffic_periods || [];
  $('#trafficPeriods').innerHTML = periods.map((period) => {
    const ready = Number(period.samples || 0) >= 2;
    const approximate = !period.complete || Number(period.discontinuities || 0) > 0;
    const hint = Number(period.discontinuities || 0) > 0 ? `Есть разрывов: ${period.discontinuities}` : (period.complete ? 'Период покрыт сохранённой историей' : 'История периода ещё накапливается');
    return `<div title="${esc(hint)}"><span>${esc(period.label)}${approximate ? ' ≈' : ''}</span><b>${ready ? `↓ ${formatBytes(period.rx_bytes)}` : 'сбор…'}</b><small>${ready ? `↑ ${formatBytes(period.tx_bytes)}` : 'нет полного интервала'}</small></div>`;
  }).join('');
  $('#trafficChart').innerHTML = `<polyline class="traffic-download" points="${metricPolyline(history, 'rx_bytes_per_second')}"/><polyline class="traffic-upload" points="${metricPolyline(history, 'tx_bytes_per_second')}"/>`;
}

function renderEngineLab() {
  const report = state.engineLab || {};
  const conflicts = report.conflicts || [];
  $('#engineLabSummary').innerHTML = `<div class="engine-lab-kpi ${report.ready_for_isolated_probes ? 'pass' : 'warn'}"><strong>${report.ready_for_isolated_probes ? 'ГОТОВО' : 'ТРЕБУЕТ ВНИМАНИЯ'}</strong><span>изолированные проверки</span></div><div class="engine-lab-kpi ${conflicts.length ? 'warn' : 'pass'}"><strong>${conflicts.length}</strong><span>конфликтов ресурсов</span></div><div class="engine-lab-kpi"><strong>${(report.engines || []).filter((engine) => engine.installed).length}</strong><span>обходов установлено</span></div><div class="engine-lab-kpi"><strong>${report.generated_at ? timeAgo(report.generated_at) : '—'}</strong><span>последняя проверка</span></div>`;
  $('#engineLabRows').innerHTML = (report.engines || []).map((engine) => {
    const checks = (engine.checks || []).map((check) => `<span class="lab-check ${esc(check.status)}" title="${esc(check.detail)}"><i></i>${esc(check.id)}</span>`).join('');
    const resources = (engine.resources || []).map((resource) => `${resource.kind}:${resource.value}`).join(' · ') || 'ресурсы не объявлены';
    return `<div class="engine-lab-row ${engine.external ? 'external' : ''}"><div><b>${esc(engine.name || engine.id)}${engine.external ? '<span class="external-owner-tag">ВНЕШНЕЕ УПРАВЛЕНИЕ</span>' : ''}</b><small>${esc(engine.version_number || engine.version || 'версия не определена')} · ${esc(engine.schema_level || '—')}</small></div><div class="lab-checks">${checks}</div><div><span class="probe-mode">${esc(engine.probe_mode || '—')}</span><small>${esc(resources)}</small></div></div>`;
  }).join('');
  if (conflicts.length) {
    $('#engineLabRows').insertAdjacentHTML('beforeend', `<div class="engine-conflicts"><b>Блокирующие конфликты</b>${conflicts.map((conflict) => `<span>${esc(conflict.kind)} <code>${esc(conflict.value)}</code>: ${esc((conflict.engines || []).join(', '))}${conflict.system_use ? ` · занято системой: ${esc(conflict.system_use)}` : ''}</span>`).join('')}</div>`);
  }
}

function renderAudit() {
  const target = $('#auditRows');
  if (!target) return;
  const events = state.audit?.events || [];
  target.innerHTML = events.map(renderProjectAuditRow).join('') || `<div class="community-empty">${state.audit?.available === false && state.audit?.last_error ? esc(state.audit.last_error) : 'Действий пока нет.'}</div>`;
}

function renderStrategyLab() {
  const lab = state.strategyLab || {};
  const pools = lab.pools || [];
  const candidates = lab.candidates || [];
  const summaries = lab.summaries || [];
  const selections = lab.selections || [];
  const migration = state.z2kPreview || {};
	const budget = lab.safety?.probe_budget || {};
	const budgetNode = $('#strategyResourceBudget');
	if (budgetNode) {
		budgetNode.classList.toggle('blocked', budget.allowed === false);
		const memory = budget.memory_total_kb ? `${Math.round((budget.memory_available_kb || 0) / 1024)} МиБ свободно · ${budget.memory_available_percent || 0}%` : 'RAM не определена';
		const load = budget.cpu_count ? `load ${Number(budget.load_1 || 0).toFixed(2)} / ${budget.cpu_count} CPU` : 'нагрузка не определена';
		budgetNode.innerHTML = `<b>${budget.allowed === false ? 'ТЕСТ ОТЛОЖЕН' : 'РЕСУРСЫ ТЕСТА'}</b><span>${esc(budget.reason || 'Проверяем RAM и нагрузку роутера…')} ${esc(memory)} · ${esc(load)} · лимит ${Math.round((budget.timeout_ms || 15000) / 1000)} с.</span>`;
	}
	const target = $('#strategyTarget').value;
	const probeServices = (state.services || []).filter((service) => service.probe_url);
  $('#strategyTarget').innerHTML = probeServices.map((service) => `<option value="${esc(service.id)}">${esc(service.name)}</option>`).join('') || '<option value="">Нет сервисов с адресом проверки</option>';
	if (probeServices.some((service) => service.id === target)) $('#strategyTarget').value = target;
  $('#z2kMigration').innerHTML = migration.found
    ? `<div><span class="external-owner-tag">ТОЛЬКО ИМПОРТ</span><b>Найдена внешняя конфигурация NFQWS2 ${esc(migration.version || '')}</b><small>${migration.files?.length || 0} файлов · ${migration.strategies?.length || 0} стратегий · ${(migration.extra_domains?.length || 0) + (migration.auto_domains?.length || 0)} доменов. Сам z2k не устанавливается и не становится обходом RAZVILKA.</small></div><div class="z2k-migration-actions"><button class="secondary" id="showZ2KPreview" type="button">Показать источник</button><button class="primary" id="importZ2KStrategies" type="button">Импортировать в черновик NFQWS2</button></div>`
    : '<div><b>Внешняя конфигурация NFQWS2 не обнаружена</b><small>Подбор стратегий работает с обычным NFQWS2. Отдельный сервис z2k не требуется и не устанавливается.</small></div>';
  $('#showZ2KPreview')?.addEventListener('click', () => showDetails(migration, 'Внешний источник NFQWS2 · только чтение'));
  $('#importZ2KStrategies')?.addEventListener('click', importZ2KStrategies);
  const currentPool = $('#strategyPool').value;
  $('#strategyPool').innerHTML = pools.map((pool) => `<option value="${esc(pool.id)}">${esc(pool.name)}</option>`).join('');
  if (pools.some((pool) => pool.id === currentPool)) $('#strategyPool').value = currentPool;
  $('#strategyPools').innerHTML = pools.map((pool) => {
    const count = candidates.filter((candidate) => candidate.pool_id === pool.id).length;
    const validated = candidates.filter((candidate) => candidate.pool_id === pool.id && candidate.validation?.ok && candidate.validation?.native).length;
    return `<div class="strategy-pool"><span>${esc(pool.protocol.toUpperCase())}</span><b>${esc(pool.name)}</b><small>${esc(pool.description)}</small><em>${validated} проверено · ${count} всего</em></div>`;
  }).join('');
  $('#strategyCandidates').innerHTML = candidates.map((candidate) => {
    const validation = candidate.validation || {};
		const pool = pools.find((item) => item.id === candidate.pool_id);
    const cls = validation.ok && validation.native ? 'pass' : validation.native ? 'fail' : 'warn';
    const label = validation.ok && validation.native ? 'ПРОВЕРЕНО' : validation.native ? 'ОТКЛОНЕНО' : 'НУЖНА ПРОВЕРКА';
		const probe = validation.ok && validation.native
			? ['tcp', 'quic'].includes(pool?.protocol) ? `<button class="primary" data-strategy-probe="${esc(candidate.id)}">${pool?.protocol === 'quic' ? 'Тест HTTP/3' : 'Тест маршрута'}</button>` : '<button class="secondary" disabled title="Для голосового UDP нужен сервисный handshake">UDP сервиса</button>'
			: '';
    return `<div class="strategy-candidate"><div><b>${esc(candidate.name)}</b><small>${esc(candidate.pool_id)} · ${esc(candidate.origin || 'вручную')}</small></div><code>${esc(candidate.arguments)}</code><span class="strategy-validation ${cls}" title="${esc(validation.output || '')}">${label}</span><div class="strategy-candidate-actions"><button class="secondary" data-strategy-validate="${esc(candidate.id)}">Проверить</button>${probe}<button class="danger" data-strategy-delete="${esc(candidate.id)}">Удалить</button></div></div>`;
  }).join('') || '<div class="strategy-empty">Добавьте кандидата вручную или позже импортируйте совместимые данные. Ничего не применяется автоматически.</div>';
	const evidence = lab.evidence || [];
  $('#strategyEvidence').innerHTML = summaries.map((summary) => {
		const latest = [...evidence].reverse().find((item) => item.candidate_id === summary.candidate_id && item.service_id === summary.service_id && item.protocol === summary.protocol && item.ip_family === summary.ip_family);
		const quality = summary.passes > 0 ? `TTFB ≈ ${Math.round(summary.average_ttfb_ms || summary.average_latency_ms || 0)} мс` : 'нет успешного замера';
		return `<button class="strategy-summary ${summary.eligible ? 'eligible' : ''}" data-strategy-evidence="${esc(latest ? evidence.indexOf(latest) : '')}"><div><b>${esc(serviceName(summary.service_id))}</b><small>${esc(summary.protocol.toUpperCase())} · ${esc(summary.ip_family)}</small></div><span>${summary.fresh_passes || 0} свежих успеха / ${summary.fresh_failures || 0} ошибок · ${esc(quality)}</span><em>${Math.round((summary.confidence || 0) * 100)}% доверия</em><small>${esc(summary.reason)}</small></button>`;
	}).join('') || '<div class="strategy-empty">Результаты появятся после изолированных проверок DNS → TCP → TLS → HTTP и подтверждения счётчика NFQUEUE.</div>';
	const selectionKey = (item) => `${item.service_id}|${item.protocol}|${item.ip_family}`;
	const currentByKey = new Map(selections.map((selection) => [selectionKey(selection), selection.candidate_id]));
	const statusLabels = { healthy: 'РАБОТАЕТ', 'frozen-healthy': 'ЗАКРЕПЛЕНО', degraded: 'НУЖНА ПРОВЕРКА', 'frozen-degraded': 'ЗАКРЕПЛЕНО · ЕСТЬ ОШИБКИ' };
	const remembered = selections.map((selection) => {
		const candidate = candidates.find((item) => item.id === selection.candidate_id);
		return `<article class="strategy-memory-card ${selection.healthy ? 'healthy' : 'degraded'}"><div><span>${esc(statusLabels[selection.status] || selection.status || 'СОСТОЯНИЕ НЕИЗВЕСТНО')}</span><b>${esc(serviceName(selection.service_id))} · ${esc(selection.protocol.toUpperCase())} · ${esc(selection.ip_family)}</b><small>${esc(candidate?.name || selection.candidate_id)} · ${Math.round((selection.confidence || 0) * 100)}% доверия</small></div><p>${esc(selection.rollback_reason || selection.reason || 'Ожидаются новые проверки')}</p><button class="secondary" data-strategy-reset="1" data-service="${esc(selection.service_id)}" data-protocol="${esc(selection.protocol)}" data-family="${esc(selection.ip_family)}">Не запоминать</button></article>`;
	});
	const available = summaries.filter((summary) => summary.eligible && currentByKey.get(selectionKey(summary)) !== summary.candidate_id).map((summary) => {
		const candidate = candidates.find((item) => item.id === summary.candidate_id);
		return `<article class="strategy-memory-card available"><div><span>ГОТОВ К ПАМЯТИ</span><b>${esc(serviceName(summary.service_id))} · ${esc(summary.protocol.toUpperCase())} · ${esc(summary.ip_family)}</b><small>${esc(candidate?.name || summary.candidate_id)} · ${Math.round((summary.confidence || 0) * 100)}% доверия</small></div><p>Автовозврат сработает только после ${lab.safety?.automatic_rollback_failures || 3} последовательных изолированных отказов.</p><button class="primary" data-strategy-select="${esc(summary.candidate_id)}" data-service="${esc(summary.service_id)}" data-protocol="${esc(summary.protocol)}" data-family="${esc(summary.ip_family)}">Запомнить</button></article>`;
	});
	$('#strategyMemory').innerHTML = [...remembered, ...available].join('') || '<div class="strategy-empty">Сначала получите три свежих подтверждённых результата для одного кандидата.</div>';
}

async function updateStrategyMemory(button, reset = false) {
	button.disabled = true;
	try {
		const body = { action: reset ? 'reset' : 'select', service_id: button.dataset.service, protocol: button.dataset.protocol, ip_family: button.dataset.family, candidate_id: button.dataset.strategySelect || '', frozen: false };
		await api('/api/v1/strategy-lab/selections', { method: 'POST', body: JSON.stringify(body) });
		state.strategyLab = await api('/api/v1/strategy-lab');
		renderStrategyLab();
	} catch (error) {
		showDetails({ error: error.message, response: error.payload }, reset ? 'Память стратегии не сброшена' : 'Стратегия не запомнена');
	} finally {
		button.disabled = false;
	}
}

async function importZ2KStrategies() {
  // The explicit import button is sufficient for staging unverified candidates.
  // Server validation and the separate live-apply boundary are unchanged.
  const button = $('#importZ2KStrategies');
  button.disabled = true; button.textContent = 'Импорт…';
  try {
    const result = await api('/api/v1/migrations/z2k/import-strategies', { method: 'POST', body: JSON.stringify({ confirm: 'IMPORT_Z2K_STRATEGIES' }) });
    state.strategyLab = await api('/api/v1/strategy-lab');
    renderStrategyLab();
    showDetails(result, 'Внешние стратегии импортированы в черновик NFQWS2');
  } catch (error) {
    showDetails({ error: error.message, response: error.payload }, 'Импорт внешних стратегий не выполнен');
  }
}

async function addStrategyCandidate(event) {
  event.preventDefault();
  const button = $('#addStrategyCandidate');
  button.disabled = true; button.textContent = 'Сохранение…';
  try {
    const candidate = await api('/api/v1/strategy-lab/candidates', { method: 'POST', body: JSON.stringify({ pool_id: $('#strategyPool').value, name: $('#strategyName').value.trim(), arguments: $('#strategyArguments').value.trim() }) });
    state.strategyLab = await api('/api/v1/strategy-lab');
    $('#strategyName').value = ''; $('#strategyArguments').value = '';
    renderStrategyLab();
    showDetails(candidate, 'Кандидат сохранён без применения');
  } catch (error) { showDetails({ error: error.message }, 'Стратегия не принята'); }
  finally { button.disabled = false; button.textContent = 'Добавить кандидата'; }
}

async function validateStrategyCandidate(id) {
  try {
    const candidate = await api(`/api/v1/strategy-lab/candidates/${encodeURIComponent(id)}/validate`, { method: 'POST' });
    state.strategyLab = await api('/api/v1/strategy-lab');
    renderStrategyLab();
    showDetails(candidate.validation, candidate.validation?.ok ? 'Нативная проверка пройдена' : 'NFQWS2 отклонил стратегию');
  } catch (error) { showDetails({ error: error.message }, 'Проверка не выполнена'); }
}

async function probeStrategyCandidate(id) {
	const serviceID = $('#strategyTarget').value;
	if (!serviceID) return showDetails({ error: 'В каталоге нет сервиса с адресом проверки' }, 'Тест не запущен');
	if (!await askConfirmation('Запустить изолированный тест NFQWS2?', `RAZVILKA временно направит только одно соединение к ${serviceName(serviceID)} в отдельную NFQUEUE. Основной маршрут и рабочий конфиг не меняются; временное правило удалится даже при тайм-ауте.`, 'Запустить тест')) return;
	try {
		const evidence = await api(`/api/v1/strategy-lab/candidates/${encodeURIComponent(id)}/probe`, { method: 'POST', body: JSON.stringify({ service_id: serviceID, ip_family: $('#strategyFamily').value }) });
		state.strategyLab = await api('/api/v1/strategy-lab');
		renderStrategyLab();
		showDetails(evidence, evidence.success ? 'Изолированный маршрут подтверждён' : 'Стратегия не прошла тест');
	} catch (error) {
		showDetails({ error: error.message, response: error.payload }, 'Тест не выполнен');
	}
}

async function deleteStrategyCandidate(id) {
	const candidate = (state.strategyLab?.candidates || []).find((item) => item.id === id);
	if (!await askConfirmation('Удалить кандидата?', `Будут удалены только черновик «${candidate?.name || id}», его результаты тестов и выборы. Рабочий конфиг NFQWS2 не изменится.`, 'Удалить')) return;
	try {
		await api(`/api/v1/strategy-lab/candidates/${encodeURIComponent(id)}`, { method: 'DELETE', body: JSON.stringify({}) });
		state.strategyLab = await api('/api/v1/strategy-lab');
		renderStrategyLab();
	} catch (error) {
		showDetails({ error: error.message }, 'Кандидат не удалён');
	}
}

async function refreshEngineLab() {
  const button = $('#refreshEngineLab');
  button.disabled = true; button.textContent = 'Проверка…';
  try {
    state.engineLab = await api('/api/v1/engine-lab');
    renderEngineLab();
  } catch (error) {
    showDetails({ error: error.message }, 'Лаборатория обходов');
  } finally {
    button.disabled = false; button.textContent = 'Перепроверить';
  }
}

function routeSelectHTML(service) {
  if (state.serviceMode === 'lite' && !['auto', 'direct'].includes(service.route)) {
    return `<div class="forced-route-summary"><span>${esc(routeLabel(service.route))}</span><button class="secondary" type="button" data-switch-pro="1">Изменить в расширенном режиме</button></div>`;
  }
  const options = state.routeOptions.filter((option) => {
    if (state.serviceMode === 'lite' && !['auto', 'direct'].includes(option.id)) return false;
    return !Array.isArray(option.services) || !option.services.length || option.services.includes(service.id);
  });
  if (service.route && !options.some((o) => o.id === service.route)) {
    options.push({ id: service.route, name: service.route, installed: true, selectable: true, kind: 'custom' });
  }
  return `<select class="route-select" data-route-id="${esc(service.id)}" aria-label="Маршрут для ${esc(service.name)}">${options.map((o) => {
    const selected = o.id === service.route ? 'selected' : '';
    const disabled = !o.selectable ? 'disabled' : '';
    const suffix = !o.selectable && o.id !== 'auto' && o.id !== 'direct'
      ? !o.installed
        ? ' · компонент не установлен'
        : !o.configured
        ? ' · сначала создайте или импортируйте профиль'
        : ' · конфигурация не готова'
      : '';
    const label = o.id === 'auto' ? 'Автопилот (AUTO)' : (o.name || routeLabel(o.id));
    return `<option value="${esc(o.id)}" ${selected} ${disabled}>${esc(label)}${suffix}</option>`;
  }).join('')}</select>`;
}

function setServiceMode(mode) {
  state.serviceMode = mode === 'pro' ? 'pro' : 'lite';
  try { localStorage.setItem(SERVICE_MODE_KEY, state.serviceMode); } catch (_) { /* optional preference */ }
  renderServices();
}

function serviceStateRoute(entry, fallback, disabledText = 'выключен') {
  if (!entry?.enabled) return disabledText;
  return routeLabel(entry.route || fallback || 'auto');
}

function serviceObservedLabel(service) {
  const observed = service.observed_state || {};
  if (!service.applied_state?.enabled && !service.applied_enabled) return 'нет активного маршрута';
  if (observed.status === 'stale') return 'данные устарели';
  if (!observed.route) return evidenceLevelLabel(observed.level || service.evidence_level || 'catalog');
  return `${routeLabel(observed.route)} · ${evidenceLevelLabel(observed.level || service.evidence_level || 'none')}`;
}

function showNFQWS2Details(id) {
  const service = state.services.find((item) => item.id === id);
  if (!service) return;
  showDetails({ detail_kind: 'nfqws2-service', service_id: service.id, service_name: service.name, nfqws2: service.nfqws2 || {} }, `NFQWS2 · ${service.name}`);
}

function populateServiceCategories() {
  const select = $('#serviceCategory');
  const current = select.value;
  const categories = [...new Set(state.services.map((s) => s.category).filter(Boolean))].sort();
  select.innerHTML = '<option value="">Все категории</option>' + categories.map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
  if (categories.includes(current)) select.value = current;
}

function serviceMatches(service) {
  const filter=window.RazvilkaConsoleFilters?.service;
  if(filter==='mine'&&!service.enabled&&!service.applied_enabled)return false;
  if(filter==='custom'&&!service.custom)return false;
  const q = $('#serviceSearch').value.trim().toLowerCase();
  const category = $('#serviceCategory').value;
  if (category && service.category !== category) return false;
  if (!q) return true;
  return [service.name, service.description, service.category, ...(service.domains || [])].join(' ').toLowerCase().includes(q);
}

function renderServices() {
  renderPendingServiceChanges();
  renderServiceDashboard();
}

function renderOverviewServices() {
  const chosen = state.services.filter(service => service.enabled || service.applied_enabled || service.route_dirty || service.sources_dirty).sort((a, b) => Number(b.applied_enabled) - Number(a.applied_enabled) || a.name.localeCompare(b.name, 'ru')).slice(0, 7);
  $('#overviewServices').innerHTML = chosen.map((s) => {
    const desired = s.enabled ? routeLabel(s.route) : 'Выключить';
    const summary = serviceDashboardSummary(s);
    const applied = summary.route ? routeLabel(summary.route) : summary.label;
    const pending = s.route_dirty || s.sources_dirty || s.enabled !== s.applied_enabled;
    return `<div class="overview-service">
      <div class="service-name"><div class="service-badge">${typeof consoleServiceIcon==='function'?consoleServiceIcon(s):esc(s.icon || 'AF')}</div><div><b>${esc(s.name)}</b><small>${esc(s.category || '')}${pending ? ' · Ожидают применения' : ''}</small></div></div>
      <span class="overview-selection">${pending ? `Выбрано: ${esc(desired)}` : ''}</span>
      <span class="overview-applied" title="${esc(summary.detail)}"><small>Сейчас</small><span class="route-pill ${summary.kind} applied-route">${esc(applied)}</span>${summary.route ? `<small>${esc(summary.label)} · ${esc(summary.pingLabel)}</small>` : ''}</span>
    </div>`;
  }).join('');
}

function renderOverviewQuickServices() {
  const container = $('#overviewQuickServices');
  if (!container) return;
  const chosen = [...state.services].sort((a, b) => Number(b.enabled) - Number(a.enabled) || a.name.localeCompare(b.name, 'ru')).slice(0, typeof workspaceControl !== 'undefined' && workspaceControl.expanded ? state.services.length : 6);
  container.innerHTML = chosen.map((service) => `<button class="quick-service ${service.enabled ? 'enabled' : ''}" data-overview-toggle="${esc(service.id)}"><span class="service-badge">${typeof consoleServiceIcon==='function'?consoleServiceIcon(service):esc(service.icon || '+')}</span><b>${esc(service.name)}</b><span class="quick-switch ${service.enabled ? 'on' : ''}"><i></i></span></button>`).join('');
  $$('[data-overview-toggle]').forEach((button) => button.addEventListener('click', () => toggleService(button.dataset.overviewToggle)));
}

function renderReadiness() {
  const sys = state.system || {};
  const installed = state.engines.filter((e) => e.installed).length;
  const operationalSources = state.sources.filter((s) => s.kind !== 'reference' && s.enabled);
  const sourceReady = operationalSources.filter((s) => s.ready).length;
  const rows = [
    ['Entware', sys.opt_ready && sys.opkg, sys.opt_ready && sys.opkg ? 'готов' : 'нужно проверить /opt и opkg'],
    ['Интернет-интерфейс', !!sys.wan_interface, sys.wan_interface || 'не определён'],
    ['NFQUEUE', !!sys.nfqueue, sys.nfqueue ? 'готов для NFQWS2' : 'нужен для NFQWS2'],
    ['Туннельный интерфейс', !!sys.tun, sys.tun ? 'доступен' : 'может понадобиться туннельным обходам'],
    ['Внешние туннели', !sys.route_contamination, sys.route_contamination ? `обнаружены: ${(sys.external_tunnels || []).join(', ') || 'неизвестный туннель'}` : 'не обнаружены'],
    ['Обходы', installed > 0, installed ? `${installed} установлено` : 'пока чистая среда'],
    ['Источники', operationalSources.length > 0 && sourceReady === operationalSources.length, `${sourceReady} / ${operationalSources.length} включённых списков готовы`],
    ['Ожидают применения', !state.status.pending_changes, state.status.pending_changes ? 'есть изменения' : 'нет'],
  ];
  $('#readinessMini').innerHTML = rows.map(([name, ok, detail]) => `<div class="readiness-row"><div><b>${esc(name)}</b><small>${esc(detail)}</small></div><span class="ready-state ${ok ? '' : 'warn'}">${ok ? 'ГОТОВО' : 'ПРОВЕРИТЬ'}</span></div>`).join('');
}

function renderEngines() {
  const cards = state.engines.map((e) => {
    const cls = e.running ? 'running' : e.installed ? 'installed' : '';
    const text = e.running ? 'РАБОТАЕТ' : e.installed ? 'УСТАНОВЛЕН' : 'НЕ УСТАНОВЛЕН';
    const kind = e.kind === 'local' ? 'Локальный' : e.kind === 'tunnel' ? 'Туннель' : (e.kind || 'Обход');
    const guide = engineRoleGuide(e.id);
    return `<button class="concept-engine-row" data-engine-open="${esc(e.id)}"><div><b>${esc(e.name)}</b><small>${esc(kind)}${guide ? ` · ${esc(guide.short)}` : ''}</small></div><span class="engine-state ${cls}">${text}</span><span class="engine-config-link">Настроить →</span></button>`;
  }).join('');
  $('#engineCards').innerHTML = cards;
  $$('[data-engine-open]').forEach((button) => button.addEventListener('click', async () => { await openEngineConfiguration(button.dataset.engineOpen); }));
}

function engineRoleGuide(id) {
  return ({
    nfqws2: { short: 'без сервера', title: 'Локальный обход DPI', text: 'Меняет вид DPI-трафика прямо на роутере. Подходит, когда домен доступен по IP, но провайдер вмешивается в TCP, TLS или QUIC.', need: 'Удалённый сервер не нужен.' },
    usque: { short: 'Cloudflare MASQUE', title: 'Туннель WARP через MASQUE', text: 'Отправляет выбранные сервисы через Cloudflare по QUIC/HTTP2. Полезен при полной IP-блокировке, когда одного NFQWS2 недостаточно.', need: 'Нужен доступ к Cloudflare; свой сервер не нужен.' },
    'warp-wg': { short: 'Cloudflare WireGuard', title: 'Туннель WARP WireGuard', text: 'Отправляет выбранные IP-сети через профиль Cloudflare WARP. Работает только если провайдер пропускает WireGuard-handshake.', need: 'Нужен созданный или импортированный WARP-профиль.' },
    'sing-box': { short: 'нужен удалённый профиль', title: 'Универсальный клиент для своего сервера', text: 'Подключает VLESS/Reality, Hysteria2, TUIC или Shadowsocks и ведёт выбранные сервисы через удалённый узел. Это вариант для полной блокировки, TCP, UDP и IP-сетей.', need: 'Одна установка ничего не разблокирует: нужен рабочий профиль своего или доверенного сервера.' },
    xray: { short: 'нужен VLESS-профиль', title: 'Альтернативный VLESS/Reality-клиент', text: 'Подключает удалённый Xray/VLESS-узел и используется как туннельный маршрут для выбранных сервисов.', need: 'Нужны адрес, UUID/ключи и доступный удалённый сервер.' },
    amneziawg: { short: 'нужен AWG-сервер', title: 'Устойчивый туннель AmneziaWG', text: 'Ведёт выбранные сервисы через сервер с поддержкой AmneziaWG и помогает там, где обычный WireGuard фильтруется.', need: 'Нужен собственный или доверенный сервер AmneziaWG; профиль WARP сюда не подходит.' },
  })[String(id || '')] || null;
}

async function openEngineConfiguration(id = '') {
  if (id && state.engineConfigs.some((engine) => engine.id === id)) await selectEngine(id);
  setView('engineconfig');
}

function openRouteInstallation(id = '') {
  setView('engines');
  const component = state.components.find((item) => item.id === id);
  const name = component?.name || routeLabel(id);
  const message = component?.available
    ? 'Компонент доступен для установки. Нажмите «Установить»; после проверки вернитесь к сервису и выберите маршрут снова.'
    : 'Компонент не найден в подключённых источниках для этой архитектуры. Обновите каталог и откройте технические детали компонента.';
  showNotice(component?.available ? 'review' : 'error', `${name}: требуется установка`, message, component || { component: id }, false);
  requestAnimationFrame(() => document.querySelector(`.component-action[data-component="${CSS.escape(id)}"]`)?.focus());
}


function selectedEngineView() {
  return state.engineConfigs.find((e) => e.id === state.selectedEngine) || state.engineConfigs[0] || null;
}

function selectedEngineFile() {
  const engine = selectedEngineView();
  if (!engine) return null;
  return engine.files.find((f) => f.id === state.selectedEngineFile) || engine.files[0] || null;
}

function engineStatusText(engine) {
  if (!engine) return ['НЕИЗВЕСТНО', ''];
  if (engine.running) return ['РАБОТАЕТ', 'running'];
  if (engine.installed) return ['УСТАНОВЛЕН', 'installed'];
  return ['НЕ УСТАНОВЛЕН', ''];
}

function renderEngineControl() {
  if (!state.engineConfigs.length) {
    const load = state.dataLoad?.engineConfigs;
    const message = load?.loaded ? 'Нет описаний обходов' : load?.phase === 'busy' ? 'Настройки временно заняты. Повторим загрузку.' : load?.phase === 'error' ? 'Не удалось загрузить настройки. Нажмите «Обновить».' : 'Загружаем настройки обходов…';
    $('#engineControlList').innerHTML = `<div class="empty-inline">${esc(message)}</div>`;
    $('#engineSelectedHead').innerHTML = '';
    $('#guidedEditor').innerHTML = `<div class="guided-empty">${esc(message)}</div>`;
    $('#engineEditorMessage').textContent = message;
    $('#engineDraftDependency').hidden = true;
    return;
  }
  if (!state.engineConfigs.some((e) => e.id === state.selectedEngine)) state.selectedEngine = state.engineConfigs[0].id;
  const engine = selectedEngineView();
  if (!engine.files.some((f) => f.id === state.selectedEngineFile)) state.selectedEngineFile = engine.files[0]?.id || 'main';
  const file = selectedEngineFile();
  if(typeof renderAWGWorkspace==='function')renderAWGWorkspace();
  renderWarpManager();
  if(typeof renderConsoleEngine==='function')renderConsoleEngine();

  $('#engineSafeBadge').textContent = state.status.safe_mode ? 'БЕЗОПАСНЫЙ РЕЖИМ · ЗАПИСЬ ВЫКЛЮЧЕНА' : 'РАБОЧИЙ РЕЖИМ';
  $('#engineSafeBadge').classList.toggle('active-apply', !state.status.safe_mode);
  $('#engineControlList').innerHTML = [...state.engineConfigs].sort((a, b) => Number(b.running) - Number(a.running) || Number(b.installed) - Number(a.installed)).map((e) => {
    const [text, cls] = engineStatusText(e);
    const drafts = (e.files || []).filter((f) => f.staged).length;
    return `<button class="engine-control-item ${e.id === state.selectedEngine ? 'active' : ''}" data-engine-id="${esc(e.id)}">
      <div><b>${esc(e.name)}</b>${typeof engineVersionHTML === 'function' ? engineVersionHTML(e) : ''}<small>${esc(e.description || '')}</small></div>
      <div class="engine-control-meta"><span class="engine-state ${cls}">${text}</span>${drafts ? `<span class="draft-count">Есть изменения: ${drafts}</span>` : ''}</div>
    </button>`;
  }).join('');
  $$('[data-engine-id]').forEach((b) => b.addEventListener('click', () => selectEngine(b.dataset.engineId)));

  const [statusText, statusClass] = engineStatusText(engine);
  const role = engineRoleGuide(engine.id);
  $('#engineSelectedHead').innerHTML = `<div><h3>${esc(engine.name)} ${typeof engineVersionHTML === 'function' ? engineVersionHTML(engine) : ''}</h3><p>${esc(engine.description || '')}</p>${role ? `<div class="engine-role-guide"><span>ЗАЧЕМ НУЖЕН</span><b>${esc(role.title)}</b><p>${esc(role.text)}</p><small>${esc(role.need)}</small></div>` : ''}</div><div class="engine-selected-meta"><span class="engine-state ${statusClass}">${statusText}</span><span>${(engine.files || []).length} файлов</span>${typeof renderEngineUpdateAction === 'function' ? renderEngineUpdateAction(engine) : ''}</div>`;

  const stagedFiles = (engine.files || []).filter((item) => item.staged);
  const assignedServices = state.services.filter((service) => service.enabled && (service.route === engine.id || service.planned_engine === engine.id));
  const dependency = $('#engineDraftDependency');
  dependency.hidden = stagedFiles.length === 0 || assignedServices.length > 0;
  if (!dependency.hidden) {
    $('#engineDraftDependencyTitle').textContent = `${engine.name}: выберите сервис`;
    $('#engineDraftDependencyText').textContent = 'Настройки готовы к проверке. Выберите, для какого сервиса и устройств использовать этот обход.';
  }

  $('#engineFileSelect').innerHTML = (engine.files || []).map((f) => `<option value="${esc(f.id)}" ${f.id === state.selectedEngineFile ? 'selected' : ''}>${esc(f.name)}${f.staged ? ' · есть изменения' : ''}${f.sensitive ? ' · секретный' : ''}</option>`).join('');
  $('#engineFilesTable').innerHTML = (engine.files || []).map((f) => `<div class="engine-file-row ${f.id === state.selectedEngineFile ? 'active' : ''}" data-engine-file-row="${esc(f.id)}"><div><b>${esc(f.name)}</b><small>${esc(f.description || '')}</small></div><div class="engine-file-meta"><span>${esc(f.syntax)}</span><span>${f.exists ? formatBytes(f.size) : 'нет рабочего файла'}</span>${f.staged ? '<span class="draft-count">ЕСТЬ ИЗМЕНЕНИЯ</span>' : ''}${f.sensitive ? '<span class="secret-tag">СЕКРЕТНЫЙ</span>' : ''}</div><code>${esc(f.path || '—')}</code></div>`).join('');
  $$('[data-engine-file-row]').forEach((row) => row.addEventListener('click', () => selectEngineFile(row.dataset.engineFileRow)));

  $('#engineCheckRunning').textContent = engine.running ? 'да' : engine.installed ? 'установлен, но остановлен' : 'нет';
  $('#engineCheckApply').textContent = state.status.safe_mode ? 'Safe Mode: изменения запрещены' : 'Проверка не применяет маршрут';

  const loadedSame = state.engineLoaded && state.engineLoaded.engine_id === engine.id && state.engineLoaded.file_id === file?.id;
  const guidedSame = state.engineGuided && state.engineGuided.engine_id === engine.id && state.engineGuided.file_id === file?.id;
  const editor = $('#engineEditor');
  const expert = state.engineMode === 'expert';
  $('#engineModeGuided').classList.toggle('active', !expert);
  $('#engineModeExpert').classList.toggle('active', expert);
  $('#guidedEditor').hidden = expert;
  $('#expertEditor').hidden = !expert;
  editor.disabled = !file;
  $('#engineSaveDraft').disabled = !file;
  $('#engineImport').disabled = !file;
  $('#engineExport').disabled = !file;
  $('#remoteProfileImport').hidden = engine.id !== 'sing-box' || file?.id !== 'main';
  updateEngineEditorActions();

  if (!file) {
    editor.value = '';
    editor.disabled = true;
    $('#engineFileState').textContent = 'Нет файлов';
    $('#engineEditorMessage').textContent = '';
    return;
  }

  const fileState = [file.exists ? 'НАСТРОЕН' : 'НОВЫЕ НАСТРОЙКИ', file.staged ? 'ЕСТЬ ИЗМЕНЕНИЯ' : '', file.sensitive ? 'СЕКРЕТНЫЙ' : '', file.modified_at ? `изменён ${timeAgo(file.modified_at)} назад` : ''].filter(Boolean).join(' · ');
  $('#engineFileState').textContent = fileState;

  if (!expert) {
    if (guidedSame && !state.engineEditorDirty) renderGuidedEditor();
    else if (!state.engineIntent && !state.engineGuidedLoading && !state.engineEditorDirty && !state.engineReadError) void loadEngineGuided();
    if (!state.engineIntent) $('#engineEditorMessage').textContent = state.engineEditorDirty ? 'Есть изменения. Нажмите «Проверить и применить».' : guidedSame ? (file.staged ? 'Есть изменения, ожидающие применения.' : 'Показаны текущие настройки.') : 'Загрузка параметров…';
  } else {
    editor.placeholder = file.sensitive ? 'Секретный конфиг: не копируйте ключи в чужие сервисы.' : 'Конфигурация / список';
    if (loadedSame && !state.engineEditorDirty) editor.value = state.engineLoaded.content || '';
    if (!state.engineIntent) $('#engineEditorMessage').textContent = state.engineEditorDirty ? 'Есть изменения. Нажмите «Проверить и применить».' : loadedSame ? (file.staged ? 'Есть изменения, ожидающие применения.' : 'Показаны текущие настройки.') : 'Загрузка…';
    if (!state.engineIntent && !loadedSame && !state.engineEditorDirty && !state.engineReadError) void loadEngineFile();
  }
  if (state.engineReadError && !state.engineIntent) $('#engineEditorMessage').textContent = state.engineReadError + ' Нажмите «Перечитать», чтобы повторить.';

  const v = state.engineValidation;
  if (v && v.engine_id === engine.id && v.file_id === file.id) {
    $('#engineCheckBasic').textContent = v.ok ? 'ПРОЙДЕНА' : 'ОШИБКА';
    $('#engineCheckBasic').className = v.ok ? 'probe-ok' : 'probe-no';
    $('#engineCheckNative').textContent = v.native ? 'да' : 'нет / только базовая';
    $('#engineCheckOutput').textContent = v.output || '—';
  } else {
    $('#engineCheckBasic').textContent = 'не запускалась';
    $('#engineCheckBasic').className = '';
    $('#engineCheckNative').textContent = '—';
    $('#engineCheckOutput').textContent = 'Здесь появится результат проверки выбранного файла. Нажмите «Проверить конфигурацию».';
  }
  updateEngineEditorActions();
  if(typeof renderWorkflowControls==='function')renderWorkflowControls();
  if(typeof renderSetupRepairControls==='function')renderSetupRepairControls();
}

function renderWarpManager() {
  const panel = $('#warpManager');
  if (!panel) return;
  const visible = state.selectedEngine === 'warp-wg';
  panel.hidden = !visible;
  if (!visible) return;
  const w = state.warp || {};
  const component = state.components.find((item) => item.id === 'warp-wg');
  const installed = !!component?.installed;
  $('#warpInstallHint').hidden = installed;
  $('#warpGeneratorState').textContent = w.generator_installed ? (w.generator_version || 'Генератор доступен') : 'Генератор недоступен';
  const registrationPending = w.registration_state === 'pending-review';
  const registrationInvalid = w.registration_state === 'local-state-invalid';
  $('#warpAccountState').textContent = registrationInvalid ? 'Нужна проверка сохранённых данных' : registrationPending ? (w.recovery_available ? 'Есть ответ для восстановления' : 'Исход регистрации не определён') : w.account_registered ? 'зарегистрирован' : 'нет аккаунта';
  $('#warpLiveState').textContent = w.live_profile ? (w.valid ? 'валиден' : 'ошибка профиля') : 'нет';
  $('#warpCandidateState').textContent = w.candidate_staged ? 'черновик готов' : 'нет черновика';
  const badge = $('#warpStateBadge');
  badge.textContent = w.live_profile && w.valid ? 'ФОРМАТ ПРОФИЛЯ КОРРЕКТЕН' : w.candidate_staged ? 'ЧЕРНОВИК ГОТОВ' : 'НЕ НАСТРОЕН';
  badge.className = `engine-state ${w.live_profile && w.valid ? 'running' : w.candidate_staged ? 'installed' : ''}`;
  $('#warpNote').textContent = w.validation_error || w.note || '';
  $('#warpGenerate').disabled = !w.generator_installed || registrationInvalid || (registrationPending && !w.recovery_available);
  $('#warpGenerate').textContent = registrationPending && w.recovery_available ? 'Восстановить профиль' : 'Создать профиль';
  $('#warpRotate').disabled = !w.generator_installed || registrationPending || registrationInvalid;
  $('#warpCheck').disabled = !installed || (!w.candidate_staged && !w.live_profile);
  const canarySelect = $('#warpCanaryService');
  const selectedCanaryService = canarySelect.value || 'telegram';
  canarySelect.innerHTML = state.services.filter((service) => service.probe_url || (service.probes || []).some((probe) => probe.required && probe.url)).map((service) => `<option value="${esc(service.id)}">${esc(service.name)}</option>`).join('');
  if ([...canarySelect.options].some((option) => option.value === selectedCanaryService)) canarySelect.value = selectedCanaryService;
  else if ([...canarySelect.options].some((option) => option.value === 'telegram')) canarySelect.value = 'telegram';
  $('#warpCanary').disabled = !installed || (!w.candidate_staged && !w.live_profile) || !canarySelect.value;
  $('#warpDelete').disabled = !!state.status.safe_mode || !w.live_profile;
  const health = w.health || {};
  const policy = health.policy || {};
  const healthState = health.state || {};
  if (!state.warpPolicyDirty) {
    $('#warpHealthInterval').value = policy.check_interval_seconds || 180;
    $('#warpAllowAccountRefresh').checked = !!policy.allow_account_refresh;
    $('#warpHealthEnabled').value = String(!!policy.enabled);
    $('#warpFailureThreshold').value = policy.failure_threshold || 3;
    $('#warpMinFailedServices').value = policy.min_failed_services || 2;
    $('#warpCooldownHours').value = policy.cooldown_hours || 24;
    $('#warpMaxRotations').value = policy.max_rotations_per_day || 1;
    $('#warpAutoCandidate').checked = !!policy.auto_generate_candidate;
    $('#warpAutoApply').checked = !!policy.auto_apply_candidate;
    $('#warpHealthAcceptTOS').checked = !!policy.accept_tos;
  }
  $('#warpPolicyFeedback').textContent = state.warpPolicyDirty ? 'Есть несохранённые изменения' : '';
  const warpAssigned = state.services.some((service) => service.enabled && (service.resolved_route === 'warp-wg' || service.route === 'warp-wg'));
  $('#warpApplyHint').classList.toggle('ready', warpAssigned);
  $('#warpApplyHint').textContent = warpAssigned
    ? 'WARP назначен включённому сервису. После проверки общее применение сможет активировать профиль с резервной копией и автоматическим возвратом при ошибке.'
    : 'Профиль-кандидат не меняет интернет сам по себе. Для применения назначьте WARP хотя бы одному включённому сервису.';
  $('#warpHealthBadge').textContent = policy.enabled ? (health.eligible ? 'ГОТОВА К КАНДИДАТУ' : 'НАБЛЮДЕНИЕ') : 'ВЫКЛЮЧЕНА';
  $('#warpHealthBadge').className = health.eligible ? 'ready' : '';
  const healthReasons = {
    'policy-disabled': 'Политика выключена',
    'terms-not-accepted': 'Нужно принять условия Cloudflare',
    'waiting-for-confirmed-warp-route-evidence': 'Ожидание изолированного подтверждения маршрута WARP',
    'healthy-or-insufficient-failures': 'Маршрут работает или ошибок недостаточно',
    'candidate-already-staged': 'Кандидат уже ожидает проверки',
    'daily-rotation-limit-reached': 'Достигнут суточный лимит ротаций',
    'rotation-cooldown-active': 'Ещё не закончилась пауза после ротации',
    'eligible-to-stage-fresh-candidate': 'Порог достигнут — можно создать нового кандидата',
    'candidate-staged-awaiting-isolated-validation': 'Кандидат создан и ждёт изолированной проверки',
    'fresh-candidate-staged-awaiting-transactional-apply': 'Новый кандидат готов и ждёт ручного применения',
    'fresh-candidate-staged-safe-mode-blocked-auto-apply': 'Кандидат готов, но безопасный режим запрещает автоматическое применение',
    'fresh-candidate-staged-route-draft-blocked-auto-apply': 'Кандидат готов; автоматическое применение остановлено из-за изменений маршрутов',
    'fresh-candidate-staged-other-engine-drafts-blocked-auto-apply': 'Кандидат готов; автоматическое применение остановлено из-за других черновиков обходов',
    'fresh-candidate-staged-dataplane-unavailable': 'Кандидат готов, но управление маршрутами недоступно',
    'fresh-candidate-staged-transaction-blocked': 'Кандидат готов, но проверка перед применением не пройдена',
    'fresh-profile-activated': 'Новый WARP-профиль применён и проверен',
    'fresh-profile-activation-failed': 'Новый профиль не прошёл проверку; восстановлен предыдущий',
  };
  Object.assign(healthReasons, {
 'daily-attempt-limit-reached':'Суточный лимит попыток регистрации исчерпан — рабочие ключи сохранены',
 'attempt-cooldown-active':'Пауза после попытки регистрации; перезапуск не сбрасывает лимит',
 'transport-exhausted-refresh-disabled':'Прежний транспорт не подтверждён; новая регистрация не разрешена',
 'tunnel-works-service-specific-failure':'Туннель работает для другого сервиса — аккаунт не меняется',
 'service-failed-account-kept':'Отказ веб-сценария, а не подтверждённый отказ аккаунта',
 'waiting-for-independent-failure-round':'Повторная проверка слишком близко к предыдущей',
 'control-path-unavailable':'Не подтверждён независимый доступ к API; генерация отложена',
 'candidate-repair-staged':'Подготовлен кандидат с прежними ключами',
 'candidate-repair-activated':'Туннель восстановлен с прежними ключами',
 'registration-pending-or-failed':'Регистрация не подтверждена; слепой повтор запрещён',
 'safe-mode-blocked-recovery':'Безопасный режим запрещает восстановление с сетевыми изменениями'
 });
  $('#warpRecoveryBudget').textContent = `Попыток за сохранённое окно: ${(healthState.registration_attempts||[]).length} · интервал ${policy.check_interval_seconds||180} с · новое устройство ${policy.allow_account_refresh?'разрешено после проверок':'не разрешено'}`;
  const reason = health.reason || healthState.last_decision || 'policy-disabled';
  const assurance = healthState.evidence_level && healthState.evidence_level !== 'none' ? ` · ${evidenceLevelLabel(healthState.evidence_level)}` : '';
  $('#warpHealthReason').textContent = `${healthReasons[reason] || reason.replaceAll('-', ' ')}${assurance}`;
  $('#warpHealthRounds').textContent = `${healthState.consecutive_failed_rounds || 0} / ${policy.failure_threshold || 3}`;
}

async function refreshWarp() {
  state.warp = await api('/api/v1/warp');
  renderWarpManager();
}

async function generateWarp(fresh) {
  const recovering = state.warp.registration_state === 'pending-review' && state.warp.recovery_available;
  const needsAcceptance = !recovering && (fresh || !state.warp.account_registered);
  if (needsAcceptance && !$('#warpAcceptTOS').checked) { showDetails({ message: 'Для нового аккаунта отметьте принятие условий Cloudflare.' }, 'Нужно подтверждение'); return; }
  const title = recovering ? 'Восстановить профиль WARP' : fresh ? 'Создать новый аккаунт WARP' : 'Создать профиль WARP';
  const message = recovering ? 'Приложение восстановит профиль из сохранённого ответа Cloudflare без нового запроса регистрации.' : fresh ? 'Предыдущие аккаунты и рабочий профиль сохранятся. Новый аккаунт будет зарегистрирован один раз, а профиль попадёт в черновик для проверки.' : 'Приложение использует сохранённый аккаунт или зарегистрирует новый один раз. Профиль попадёт в черновик для проверки.';
  if (!await askConfirmation(title, message, 'Создать')) return;
  const button = fresh ? $('#warpRotate') : $('#warpGenerate'); button.disabled = true; button.textContent = 'Генерация…';
  try {
    const result = await api('/api/v1/warp/generate', { method: 'POST', body: JSON.stringify({ fresh, accept_tos: needsAcceptance && $('#warpAcceptTOS').checked }) });
    state.engineLoaded = null; state.engineGuided = null; state.engineValidation = null;
    await refreshEngineConfigs(); await refreshWarp();
    showNotice('success', 'Профиль WARP готов', result.message || 'Профиль сохранён как черновик и ещё не меняет рабочий маршрут.', result);
  } catch (error) {
    const payload = error.payload || {};
    if (payload.code === 'WARP_REGISTRATION_PENDING') {
      await refreshWarp();
      showNotice('error', 'Регистрацию нужно восстановить', payload.hint || error.message, payload);
    } else if (payload.code === 'WARP_REGISTRATION_UNAVAILABLE') {
      showNotice('error', 'Cloudflare временно не отвечает', payload.hint || error.message, payload);
    } else {
      showNotice('error', 'Не удалось создать WARP', error.message, { ...payload, technical: error.technicalMessage || '' });
    }
  }
  finally { button.textContent = fresh ? 'Новый аккаунт + профиль' : 'Создать профиль'; renderWarpManager(); }
}

async function importWarpFile(event) {
  const file = event.target.files?.[0]; event.target.value = '';
  if (!file) return;
  if (file.size > 256 * 1024) { showDetails({ error: 'Профиль больше 256 КБ' }, 'Импорт отклонён'); return; }
  try {
    const result = await api('/api/v1/warp/import', { method: 'POST', body: JSON.stringify({ content: await file.text() }) });
    state.engineLoaded = null; state.engineGuided = null; state.engineValidation = null;
    await refreshEngineConfigs(); await refreshWarp(); showDetails(result, 'WARP-профиль загружен');
  } catch (error) { showDetails({ error: error.message, technical: error.technicalMessage || '', response: error.payload }, 'Профиль не принят'); }
}

async function checkWarp() {
  try { showDetails(await api('/api/v1/warp/check', { method: 'POST' }), 'Проверка WARP'); }
  catch (error) { showDetails({ error: error.message, technical: error.technicalMessage || '', response: error.payload }, 'WARP не прошёл проверку'); }
}

async function checkWarpCanary() {
  const serviceID = $('#warpCanaryService').value;
  const service = state.services.find((item) => item.id === serviceID);
  if (!serviceID) return;
  if (!await askConfirmation('Проверить WARP без применения?', `RAZVILKA временно поднимет отдельный WARP-интерфейс, проверит Cloudflare и ${service?.name || serviceID}, затем удалит интерфейс и правила. Рабочие маршруты не изменятся.`, 'Запустить проверку')) return;
  const button = $('#warpCanary');
  button.disabled = true; button.textContent = 'Проверяем…';
  try {
    const result = await api('/api/v1/warp/canary', { method: 'POST', body: JSON.stringify({ service_id: serviceID }) });
    showNotice('success', 'WARP готов к применению', result.message, result);
  } catch (error) {
    const payload = error.payload || {};
    const raw = payload.error || error.message || '';
    const message = /handshake was not confirmed/i.test(raw)
      ? 'Провайдер не пропустил WARP WireGuard ни на UDP 2408, 500, 1701 или 4500. Профиль сохранён как черновик, рабочие маршруты не изменены. Используйте WARP · MASQUE либо другой установленный обход.'
      : /canary probe.*deadline|context deadline|timeout/i.test(raw)
        ? `WARP-туннель поднялся, но ${service?.name || serviceID} через него не ответил вовремя. Такой профиль не следует применять для этого сервиса.`
        : 'Безопасная проверка не пройдена. Профиль оставлен черновиком, рабочие маршруты не изменены.';
    showNotice('error', 'WARP не прошёл безопасную проверку', message, { ...payload, technical: raw || error.technicalMessage || '' });
  } finally {
    button.textContent = 'Проверить без применения';
    renderWarpManager();
  }
}

async function checkWarpConnectivity() {
  const button = $('#warpConnectivity');
  button.disabled = true; button.textContent = 'Проверяем…';
  try {
    const result = await api('/api/v1/warp/connectivity', { method: 'POST' });
    const rows = [
      { name: 'Регистрация профиля', status: result.registration?.ready ? 'ДОСТУПНА' : 'НЕДОСТУПНА', detail: result.registration?.message, latency_ms: result.registration?.latency_ms },
      { name: 'MASQUE по TCP/443', status: result.masque_http2?.ready ? 'ДОСТУПЕН' : 'НЕДОСТУПЕН', detail: result.masque_http2?.message, latency_ms: result.masque_http2?.latency_ms },
      { name: 'WARP WireGuard', status: 'НУЖНА БЕЗОПАСНАЯ ПРОВЕРКА', detail: `Создайте профиль и нажмите «Проверить без применения». UDP-порты: ${(result.wireguard_ports || []).join(', ')}` },
    ];
    showDetails({ result: result.ok ? 'Есть доступный транспорт Cloudflare' : 'Cloudflare не подтверждён', checks: rows, recommendation: result.recommendation, note: result.note }, 'Какой WARP использовать');
  } catch (error) {
    showDetails({ error: error.message, response: error.payload }, 'Проверка Cloudflare не выполнена');
  } finally {
    button.disabled = false; button.textContent = 'Проверить Cloudflare';
  }
}

async function deleteWarp() {
  if (!await askConfirmation('Удалить рабочий WARP', 'Перед удалением будет создана резервная копия. Аккаунт wgcf останется, чтобы профиль можно было создать снова.', 'Удалить')) return;
  try { const result = await api('/api/v1/warp/profile', { method: 'DELETE' }); await refreshEngineConfigs(); await refreshWarp(); showDetails(result, 'WARP удалён'); }
  catch (error) { showDetails({ error: error.message }, 'Удаление заблокировано'); }
}

async function saveWarpHealthPolicy() {
  const policy = {
    enabled: $('#warpHealthEnabled').value === 'true',
    accept_tos: $('#warpHealthAcceptTOS').checked,
    auto_generate_candidate: $('#warpAutoCandidate').checked,
    auto_apply_candidate: $('#warpAutoApply').checked,
    failure_threshold: Number($('#warpFailureThreshold').value),
    min_failed_services: Number($('#warpMinFailedServices').value),
    cooldown_hours: Number($('#warpCooldownHours').value),
    max_rotations_per_day: Number($('#warpMaxRotations').value),
    check_interval_seconds: Number($('#warpHealthInterval').value),
    allow_account_refresh: $('#warpAllowAccountRefresh').checked,
  };
  if(!Number.isInteger(policy.check_interval_seconds)||policy.check_interval_seconds<60||policy.check_interval_seconds>3600){showDetails({message:'Интервал — от 60 до 3600 секунд.'},'Политика не сохранена');return;}
  if(policy.allow_account_refresh && !policy.auto_generate_candidate){showDetails({message:'Новая регистрация требует включённого восстановления профиля.'},'Политика не сохранена');return;}
  if (policy.auto_generate_candidate && (!policy.enabled || !policy.accept_tos)) {
    showDetails({ message: 'Автогенерация требует включённой политики и отдельного принятия условий Cloudflare.' }, 'Политика не сохранена');
    return;
  }
  if (policy.auto_apply_candidate && !policy.auto_generate_candidate) {
    showDetails({ message: 'Автоматическое применение требует включённой автогенерации профиля-кандидата.' }, 'Политика не сохранена');
    return;
  }
  const button = $('#warpSaveHealth'); button.disabled = true; button.textContent = 'Сохранение…';
  try {
    await api('/api/v1/warp/health/policy', { method: 'PUT', body: JSON.stringify(policy) });
    state.warpPolicyDirty = false;
    await refreshWarp();
    $('#warpPolicyFeedback').textContent = 'Сохранено';
    showNotice('success', 'Автоконтроль WARP сохранён', policy.enabled ? 'Политика включена. Замена профиля произойдёт только после заданного числа подтверждённых сбоев.' : 'Политика выключена. Профиль WARP не будет заменяться автоматически.');
  } catch (error) { showDetails({ error: error.message, technical: error.technicalMessage || '', response: error.payload }, 'Политика не сохранена'); }
  finally { button.disabled = false; button.textContent = 'Сохранить автоконтроль'; }
}

async function runWarpHealthCheck() {
  const button = $('#warpRunHealth'); button.disabled = true; button.textContent = 'Проверка…';
  try {
    const result = await api('/api/v1/warp/health/check', { method: 'POST' });
    await refreshWarp();
    showDetails(result, 'Проверка WARP-сервисов');
  } catch (error) { showDetails({ error: error.message, technical: error.technicalMessage || '', response: error.payload }, 'Проверка WARP недоступна'); }
  finally { button.disabled = false; button.textContent = 'Проверить WARP-сервисы'; }
}

function captureEngineEditorContext() {
  return { engineID: state.selectedEngine, fileID: state.selectedEngineFile, mode: state.engineMode, version: state.engineEditorVersion || 0, epoch: state.engineEditorEpoch || 0, view: state.currentView };
}

function engineEditorContextCurrent(context) {
  return context.engineID === state.selectedEngine && context.fileID === state.selectedEngineFile && context.mode === state.engineMode && context.version === (state.engineEditorVersion || 0) && context.epoch === (state.engineEditorEpoch || 0) && context.view === state.currentView && $('#authScreen')?.hidden !== false;
}

function engineIntentCurrent(intent) {
  return state.engineIntent === intent && !intent.controller.signal.aborted && engineEditorContextCurrent(intent);
}

function updateEngineEditorActions() {
  const file = selectedEngineFile();
  const busy = !!state.engineIntent;
  $('#engineApplyConfig').disabled = busy || !file || (!state.engineEditorDirty && !file.staged);
  $('#engineDiscardDraft').disabled = busy || !file || (!state.engineEditorDirty && !file.staged);
  $('#engineCancelOperation').hidden = !busy;
  $('#engineCancelOperation').disabled = !!state.engineIntent?.controller.signal.aborted;
  for (const id of ['r4Validate', 'engineFileSelect', 'engineModeGuided', 'engineModeExpert', 'engineEditor', 'engineSaveDraft', 'engineValidate', 'engineImport', 'engineReload', 'engineAssignService', 'engineDiscardAllDrafts']) $(`#${id}`).disabled = busy || !file;
  for (const input of $$('[data-guided-field], [data-engine-id]')) input.disabled = busy;
}

function markEngineEditorDirty() {
  if (state.engineIntent) return;
  state.engineEditorDirty = true;
  state.engineEditorVersion = (state.engineEditorVersion || 0) + 1;
  state.engineValidation = null;
  $('#engineEditorMessage').textContent = 'Есть изменения. Нажмите «Проверить и применить».';
  updateEngineEditorActions();
}

function invalidateEngineEditorContext() {
  state.engineEditorEpoch = (state.engineEditorEpoch || 0) + 1;
  state.engineGuidedRequest = null;
  state.engineGuidedLoading = false;
  state.engineReadError = '';
}

function beginEngineIntent() {
  if (state.engineIntent || !selectedEngineView() || !selectedEngineFile() || $('#authScreen')?.hidden === false) return null;
  invalidateEngineEditorContext();
  const intent = { ...captureEngineEditorContext(), controller: new AbortController(), dirty: !!state.engineEditorDirty };
  intent.body = intent.mode === 'guided' ? { values: Object.fromEntries($$('[data-guided-field]').map(input => [input.dataset.guidedField, input.value])) } : { content: $('#engineEditor').value };
  state.engineIntent = intent;
  updateEngineEditorActions();
  return intent;
}

function finishEngineIntent(intent) {
  if (state.engineIntent !== intent) return;
  state.engineIntent = null;
  // Release private buffers after completion/cancellation; the editor owns its
  // current visible values and the backend owns any confirmed staging image.
  intent.body = null;
  updateEngineEditorActions();
  if (engineEditorContextCurrent(intent)) renderEngineControl();
}

function cancelEngineIntent(clearPrivate = false) {
  state.engineIntent?.controller.abort();
  invalidateEngineEditorContext();
  if (clearPrivate) {
    if (state.engineIntent) state.engineIntent.body = null;
    state.engineLoaded = null; state.engineGuided = null; state.engineEditorDirty = false;
    $('#engineEditor').value = ''; $('#guidedEditor').innerHTML = '';
  } else if (state.engineIntent) {
    $('#engineEditorMessage').textContent = 'Останавливаем операцию. Дождитесь завершения проверки или возврата прежних настроек.';
  }
  updateEngineEditorActions();
}

function handleEngineEditorLifecycle(event) {
  if (event.type === 'razvilka:auth-required') cancelEngineIntent(true);
  else if (event.detail !== 'engineconfig') cancelEngineIntent();
}

function renderGuidedEditor() {
  const view = state.engineGuided;
  const container = $('#guidedEditor');
  if (!view?.supported) {
    container.innerHTML = `<div class="guided-empty"><b>Для этого файла подходит редактор списка или экспертный режим</b><span>${esc(view?.message || 'Понятные поля для этого формата ещё не описаны.')}</span><button class="secondary" id="guidedOpenExpert" type="button">Открыть экспертный режим</button></div>`;
    $('#engineSaveDraft').disabled = true;
    $('#guidedOpenExpert').addEventListener('click', () => switchEngineMode('expert'));
    return;
  }
  const groups = new Map();
  (view.fields || []).forEach((field) => {
    const group = field.group || 'Основное';
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(field);
  });
  container.innerHTML = [...groups].map(([group, fields]) => `<section class="guided-group"><div class="guided-group-title"><h4>${esc(group)}</h4></div><div class="guided-fields">${fields.map((field) => {
    const value = view.values?.[field.id] ?? '';
    let control;
    if ((field.options || []).length) {
      const current = field.options.some(option => option.value === value) ? '' : `<option value="${esc(value)}" selected>${value === '' ? 'Не задано' : `Текущее значение: ${esc(value)}`}</option>`;
      control = `<select data-guided-field="${esc(field.id)}">${current}${field.options.map((option) => `<option value="${esc(option.value)}" ${option.value === value ? 'selected' : ''}>${esc(option.label)}</option>`).join('')}</select>`;
    } else if (field.type === 'boolean') {
      control = `<select data-guided-field="${esc(field.id)}"><option value="true" ${value === 'true' ? 'selected' : ''}>Включено</option><option value="false" ${value !== 'true' ? 'selected' : ''}>Выключено</option></select>`;
    } else if (field.type === 'arguments') {
      // HTML consumes the first newline after <textarea>; supply that newline
      // separately so leading newlines in the actual strategy remain intact.
      control = `<textarea data-guided-field="${esc(field.id)}" rows="6" spellcheck="false" placeholder="${esc(field.placeholder || '')}" ${field.required ? 'required' : ''}>\n${esc(value)}</textarea>`;
    } else {
      const type = field.type === 'number' ? 'number' : 'text';
      control = `<input data-guided-field="${esc(field.id)}" type="${type}" value="${esc(value)}" placeholder="${esc(field.placeholder || '')}" ${field.min ? `min="${field.min}"` : ''} ${field.max ? `max="${field.max}"` : ''} ${field.required ? 'required' : ''}>`;
    }
    return `<label class="guided-field"><span>${esc(field.label)}${field.required ? ' *' : ''}</span>${control}${field.description ? `<small>${esc(field.description)}</small>` : ''}</label>`;
  }).join('')}</div></section>`).join('');
  $$('[data-guided-field]').forEach((input) => {
    input.addEventListener('input', markEngineEditorDirty); input.addEventListener('change', markEngineEditorDirty);
  });
  $('#engineSaveDraft').disabled = false;
}

async function loadEngineGuided(force = false) {
  const engine = selectedEngineView(); const file = selectedEngineFile();
  if (!engine || !file || state.engineIntent || (!force && state.engineEditorDirty) || state.engineGuidedLoading) return;
  const context = captureEngineEditorContext();
  state.engineGuidedRequest = context;
  state.engineGuidedLoading = true;
  try {
    const guided = await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/guided?file=${encodeURIComponent(file.id)}`);
    if (!engineEditorContextCurrent(context) || state.engineGuidedRequest !== context) return;
    if (guided.engine_id !== engine.id || guided.file_id !== file.id) throw new Error('Ответ относится к другому файлу. Откройте настройки заново.');
    state.engineGuided = guided;
    state.engineReadError = '';
    state.engineEditorDirty = false;
    renderGuidedEditor();
    $('#engineEditorMessage').textContent = state.engineGuided.source === 'missing' ? 'Заполните параметры и нажмите «Проверить и применить».' : state.engineGuided.source === 'staged' ? 'Есть изменения, ожидающие применения.' : 'Показаны текущие настройки.';
  } catch (error) {
    if (!engineEditorContextCurrent(context)) return;
    state.engineReadError = error.message;
    $('#guidedEditor').innerHTML = `<div class="guided-empty"><b>Не удалось прочитать параметры</b><span>${esc(error.message)}</span></div>`;
    $('#engineEditorMessage').textContent = `Ошибка: ${error.message}`;
  } finally { if (state.engineGuidedRequest === context) { state.engineGuidedLoading = false; state.engineGuidedRequest = null; updateEngineEditorActions(); } }
}

async function switchEngineMode(mode) {
  if (mode === state.engineMode || state.engineIntent) return;
  if (state.engineEditorDirty && !await askConfirmation('Несохранённые изменения', 'Сменить режим и потерять локальные изменения?', 'Сменить режим')) return;
  state.engineMode = mode;
  invalidateEngineEditorContext();
  state.engineEditorDirty = false;
  state.engineLoaded = null;
  state.engineGuided = null;
  renderEngineControl();
}

function noticeBelongsOnlyToEngine(details, id) {
  if(!details||!id)return false;
  if(details.engine_id===id)return true;
  const blockers=details.transaction?.blockers;
  return Array.isArray(blockers)&&blockers.length>0&&blockers.every(b=>b.code==='ENGINE_DRAFT_UNUSED'&&b.adapter===id);
}

async function selectEngine(id) {
  if (state.engineIntent) return;
  if (state.engineEditorDirty && !await askConfirmation('Несохранённые изменения', 'Переключить обход и потерять локальные изменения редактора?', 'Переключить')) return;
  if(state.selectedEngine!==id && noticeBelongsOnlyToEngine(state.noticeDetails,state.selectedEngine))hideNotice();
  state.selectedEngine = id;
  invalidateEngineEditorContext();
  const engine = selectedEngineView();
  state.selectedEngineFile = engine?.files?.[0]?.id || 'main';
  state.engineEditorDirty = false;
  state.engineLoaded = null;
  state.engineGuided = null;
  state.engineValidation = null;
  state.engineMode = 'guided';
  renderEngineControl();
  if (typeof renderInterfaceEngines === 'function') renderInterfaceEngines();
}

async function selectEngineFile(id) {
  if (state.engineIntent) { $('#engineFileSelect').value = state.selectedEngineFile; return; }
  if (state.engineEditorDirty && !await askConfirmation('Несохранённые изменения', 'Переключить файл и потерять локальные изменения редактора?', 'Переключить')) {
    $('#engineFileSelect').value = state.selectedEngineFile;
    return;
  }
  state.selectedEngineFile = id;
  invalidateEngineEditorContext();
  state.engineEditorDirty = false;
  state.engineLoaded = null;
  state.engineGuided = null;
  state.engineValidation = null;
  state.engineMode = id === 'main' ? 'guided' : 'expert';
  renderEngineControl();
}

async function loadEngineFile(force = false) {
  const engine = selectedEngineView();
  const file = selectedEngineFile();
  if (!engine || !file || state.engineIntent) return;
  if (!force && state.engineEditorDirty) return;
  const context = captureEngineEditorContext();
  try {
    const content = await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/file?file=${encodeURIComponent(file.id)}&expert=true`);
    if (!engineEditorContextCurrent(context)) return;
    if (content.engine_id !== engine.id || content.file_id !== file.id) throw new Error('Ответ относится к другому файлу. Откройте настройки заново.');
    state.engineLoaded = content;
    state.engineReadError = '';
    state.engineEditorDirty = false;
    $('#engineEditor').value = content.content || '';
    $('#engineEditorMessage').textContent = content.source === 'missing' ? 'Введите или загрузите настройки и нажмите «Проверить и применить».' : content.source === 'staged' ? 'Есть изменения, ожидающие применения.' : 'Показаны текущие настройки.';
  } catch (error) {
    if (!engineEditorContextCurrent(context)) return;
    state.engineReadError = error.message;
    $('#engineEditorMessage').textContent = `Ошибка чтения: ${error.message}`;
  }
}

async function refreshEngineConfigs(intent = null) {
  const context = intent || captureEngineEditorContext();
  const [configs, status] = await Promise.all([api('/api/v1/engine-configs', { signal: intent?.controller.signal }), api('/api/v1/status', { signal: intent?.controller.signal })]);
  if (!engineEditorContextCurrent(context) || intent && !engineIntentCurrent(intent)) return false;
  state.engineConfigs = configs;
  state.status = status;
  renderStatus();
  renderEngineControl();
  return true;
}

async function saveEngineDraft(existingIntent = null) {
  const intent = existingIntent || beginEngineIntent();
  if (!intent || !engineIntentCurrent(intent)) return null;
  try {
    const action = intent.mode === 'guided' ? 'guided' : 'file';
    const staged = await api(`/api/v1/engine-configs/${encodeURIComponent(intent.engineID)}/${action}?file=${encodeURIComponent(intent.fileID)}`, { method: 'PUT', signal: intent.controller.signal, body: JSON.stringify(intent.body) });
    if (!engineIntentCurrent(intent)) return null;
    if (staged.engine_id !== intent.engineID || staged.file_id !== intent.fileID || staged.source !== 'staged') throw new Error('Сохранение выбранного файла не подтверждено. Применение остановлено.');
    if (intent.mode === 'guided') state.engineGuided = null;
    state.engineLoaded = staged;
    state.engineEditorDirty = false;
    state.engineValidation = null;
    if (!await refreshEngineConfigs(intent) || !engineIntentCurrent(intent)) return null;
    $('#engineEditorMessage').textContent = 'Изменения подготовлены для проверки. Рабочие настройки пока прежние.';
    return staged;
  } catch (error) {
    if (engineIntentCurrent(intent)) showDetails({ error: error.message }, 'Изменения не подготовлены — применение остановлено');
    return null;
  } finally { if (!existingIntent) finishEngineIntent(intent); }
}

async function validateEngineFile() {
  const intent = beginEngineIntent();
  if (!intent) return;
  try {
    if (intent.dirty && !await saveEngineDraft(intent)) return;
    if (!engineIntentCurrent(intent)) return;
    const validation = await api(`/api/v1/engine-configs/${encodeURIComponent(intent.engineID)}/validate?file=${encodeURIComponent(intent.fileID)}`, { method: 'POST', signal: intent.controller.signal });
    if (!engineIntentCurrent(intent)) return;
    if (validation.engine_id !== intent.engineID || validation.file_id !== intent.fileID) throw new Error('Проверен другой файл. Повторите выбор.');
    state.engineValidation = validation;
    renderEngineControl();
    switchEngineTab('check');
  } catch (error) { if (engineIntentCurrent(intent)) showDetails({ error: error.message }, 'Ошибка проверки конфигурации'); }
  finally { finishEngineIntent(intent); }
}

async function discardEngineConfigDraft() {
  const engine = selectedEngineView(); const file = selectedEngineFile();
  if (!engine || !file || state.engineIntent) return;
  const intent = beginEngineIntent();
  if (!intent) return;
  try {
    if (file.staged) await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/discard?file=${encodeURIComponent(file.id)}`, { method: 'POST', signal: intent.controller.signal });
    if (!engineIntentCurrent(intent)) return;
    state.engineLoaded = null; state.engineGuided = null; state.engineEditorDirty = false; state.engineValidation = null;
    $('#engineEditor').value = '';
    await refreshEngineConfigs(intent);
  } catch (error) { if (engineIntentCurrent(intent)) showDetails({ error: error.message }, 'Не удалось отменить изменения'); }
  finally { finishEngineIntent(intent); }
}

async function discardSelectedEngineDrafts() {
  const engine = selectedEngineView();
  if (state.engineIntent || !engine || !(engine.files || []).some((file) => file.staged)) return;
  if (!await askConfirmation('Отменить изменения обхода?', `${engine.name}: будут отменены только изменения настроек. Рабочая конфигурация останется прежней.`, 'Отменить изменения')) return;
  await discardDraft('engine', engine.id);
}

function assignSelectedEngineToService() {
  if (state.engineIntent) return;
  const engine = selectedEngineView();
  if (!engine) return;
  setView('services');
  $('#serviceSearch').value = '';
  $('#serviceCategory').value = '';
  renderServices();
  showNotice('review', `Назначьте сервис обходу ${engine.name}`, `В карточке нужного сервиса включите его и выберите «${engine.name}» в поле «Желаемый маршрут». Затем примените изменения этой вкладки.`, { engine: engine.id, action: 'assign-service' });
  requestAnimationFrame(() => $('#serviceSearch')?.focus());
}

async function applyEngineConfig() {
  const engine = selectedEngineView();
  const intent = beginEngineIntent();
  if (!intent) return;
  try {
    $('#engineEditorMessage').textContent = 'Подготавливаем выбранные настройки и проверяем их…';
    if (intent.dirty && !await saveEngineDraft(intent)) return;
    if (!engineIntentCurrent(intent)) return;
    const validation = await api(`/api/v1/engine-configs/${encodeURIComponent(intent.engineID)}/validate?file=${encodeURIComponent(intent.fileID)}`, { method: 'POST', signal: intent.controller.signal });
    if (!engineIntentCurrent(intent)) return;
    if (validation.engine_id !== intent.engineID || validation.file_id !== intent.fileID) throw new Error('Проверен другой файл. Применение остановлено.');
    state.engineValidation = validation;
    if (!state.engineValidation.ok) throw new Error(state.engineValidation.output || 'Конфигурация не прошла проверку');
    if (!await refreshEngineConfigs(intent) || !engineIntentCurrent(intent)) return;
    const plan = await api(`/api/v1/plan?scope=engine&engine=${encodeURIComponent(intent.engineID)}`, { signal: intent.controller.signal });
    if (!engineIntentCurrent(intent)) return;
    const unused = (plan.transaction?.blockers || []).find((blocker) => blocker.code === 'ENGINE_DRAFT_UNUSED' && blocker.adapter === engine.id);
    if (unused) {
      showNotice('review', `Выберите сервис для ${engine.name}`, unused.resolution || 'Откройте «Сервисы», выберите этот обход и устройства, затем нажмите «Проверить и применить».', plan, true);
      return;
    }
    await applyDraft('engine', intent.engineID, { signal: intent.controller.signal, isCurrent: () => engineIntentCurrent(intent), preview: plan, engineIntent: intent });
  } catch (error) { if (engineIntentCurrent(intent)) showDetails({ error: error.message }, 'Настройки не применены'); }
  finally { finishEngineIntent(intent); }
}

async function importEngineFile() { const f = selectedEngineFile(); if (!f || state.engineIntent) return; if (state.engineMode !== 'expert') await switchEngineMode('expert'); if (state.engineMode === 'expert' && !state.engineIntent) $('#engineImportInput').click(); }

async function reloadEngineEditor() {
  if (state.engineIntent) return;
  const context = captureEngineEditorContext();
  if (state.engineEditorDirty && !await askConfirmation('Перечитать настройки', 'Отменить изменения в редакторе и перечитать настройки?', 'Перечитать')) return;
  if (!engineEditorContextCurrent(context) || state.engineIntent) return;
  invalidateEngineEditorContext();
  state.engineEditorDirty = false;
  if (state.engineMode === 'guided') await loadEngineGuided(true); else await loadEngineFile(true);
  renderEngineControl();
}

async function handleEngineImport(event) {
  const picked = event.target.files?.[0]; event.target.value = '';
  const engine = selectedEngineView(); const file = selectedEngineFile();
  if (!picked || !engine || !file || state.engineIntent) return;
  const context = captureEngineEditorContext();
  if (picked.size > 2 * 1024 * 1024) { showDetails({ error: 'Файл больше 2 МБ' }, 'Импорт отклонён'); return; }
  try {
    const text = await picked.text();
    if (!engineEditorContextCurrent(context) || state.engineIntent) return;
    $('#engineEditor').value = text; markEngineEditorDirty(); switchEngineTab('config'); renderEngineControl();
    $('#engineEditor').value = text; // render keeps loaded text, so restore imported local buffer explicitly.
    $('#engineEditorMessage').textContent = `Файл ${picked.name} открыт. Нажмите «Проверить и применить».`;
  } catch (error) { showDetails({ error: error.message }, 'Ошибка импорта'); }
}

function renderRemoteProfilePreview() {
  const container = $('#remoteProfilePreview');
  const preview = state.remoteProfilePreview?.preview;
  const importButton = $('#remoteProfileImportButton');
  const storeButton = $('#remoteProfileStoreButton');
  importButton.disabled = state.remoteProfileBusy || !preview?.node_count || state.remoteProfileReviewedInput !== $('#remoteProfileURI').value.trim();
  storeButton.disabled = importButton.disabled;
  if (!state.remoteProfileBusy) {
    importButton.textContent = preview?.node_count ? `Черновик Sing-box: 1 выбранный` : 'Создать черновик Sing-box';
    storeButton.textContent = preview?.node_count ? `Сохранить принятые: ${Number(preview.node_count)}` : 'Сохранить в узлы';
  }
  if (!preview) {
    container.innerHTML = '<span>Обработка локальная. Из JSON/YAML берутся только поддерживаемые узлы; чужие DNS, маршруты, скрипты и панели удаляются. Вставляйте сам ключ vless://… — не адрес страницы сайта.</span>';
    return;
  }
  const nodes = preview.nodes || [];
	if (state.remoteProfileSelectedIndex >= nodes.length) state.remoteProfileSelectedIndex = 0;
  const visible = nodes.slice(0, 6).map((node, index) => `<li class="${state.remoteProfileSelectedIndex === index ? 'selected' : ''}"><button type="button" data-provider-node="${index}" aria-pressed="${state.remoteProfileSelectedIndex === index}"><i>${state.remoteProfileSelectedIndex === index ? 'ВЫБРАН' : 'ВЫБРАТЬ'}</i><b>${esc(node.name || `Узел ${index + 1}`)}</b><span>${esc(node.protocol)} · ${esc(node.server)}:${Number(node.port) || '—'}${node.transport ? ` · ${esc(node.transport)}` : ''}</span></button></li>`).join('');
  const hidden = nodes.length > 6 ? `<li><b>Ещё ${nodes.length - 6}</b><span>доступны для сохранения во вкладке «Узлы»</span></li>` : '';
  const warnings = [...(preview.warnings || []), ...nodes.flatMap((node) => node.warnings || [])].map((warning) => `<small>${esc(warning)}</small>`).join('');
	const selector = nodes.length ? `<label class="provider-node-select"><span>Начальный узел</span><select id="remoteProfileNode">${nodes.map((node, index) => `<option value="${index}" ${state.remoteProfileSelectedIndex === index ? 'selected' : ''}>${esc(node.name || `Узел ${index + 1}`)} · ${esc(node.protocol)}</option>`).join('')}</select></label>` : '';
  const issues = [['Отклонено', preview.rejected || []], ['Пропущено', preview.skipped || []]].filter(([, entries]) => entries.length).map(([label, entries]) => `<details><summary>${label}: ${entries.length} — причины</summary><ul>${entries.map((entry) => `<li><b>Запись ${Number(entry.index)} · ${esc(entry.code)}</b><span>${esc(entry.reason)}</span></li>`).join('')}</ul></details>`).join('');
  const explanation = nodes.length ? 'Формат принят, но доступность ещё не доказана. Проверка списка не подключает узлы и не меняет маршруты. Доступность нужно проверить из вашей сети перед применением.' : 'Нет подходящих узлов. Черновик не изменён; исправьте отклонённые записи или выберите другой список.';
  container.innerHTML = `<div class="remote-profile-summary"><b>Принято: ${Number(preview.node_count) || 0} · ${esc(preview.format || 'профиль')}</b><span>${explanation}</span>${selector}${warnings}</div><ul>${visible}${hidden}</ul>${issues}`;
	$$('[data-provider-node]').forEach((button) => button.addEventListener('click', () => { state.remoteProfileSelectedIndex = Number(button.dataset.providerNode) || 0; renderRemoteProfilePreview(); }));
	$('#remoteProfileNode')?.addEventListener('change', (event) => { state.remoteProfileSelectedIndex = Number(event.target.value) || 0; renderRemoteProfilePreview(); });
}

async function previewRemoteProfile() {
  if (state.remoteProfileBusy) return;
  const uri = $('#remoteProfileURI').value.trim();
  state.remoteProfilePreview = null;
  state.remoteProfileReviewedInput = '';
	state.remoteProfileSelectedIndex = 0;
  renderRemoteProfilePreview();
  if (!uri) return;
  state.remoteProfileBusy = true;
  const button = $('#remoteProfilePreviewButton');
  button.disabled = true; button.textContent = 'Проверяем…';
  try {
    const result = await api('/api/v1/provider-profiles/preview', { method: 'POST', body: JSON.stringify({ profile: uri }) });
    if ($('#remoteProfileURI').value.trim() !== uri) return;
    state.remoteProfilePreview = result;
    state.remoteProfileReviewedInput = uri;
    renderRemoteProfilePreview();
  } catch (error) {
    if ($('#remoteProfileURI').value.trim() !== uri) return;
    if (error.payload?.preview) state.remoteProfilePreview = { preview: error.payload.preview };
    showDetails({ error: error.message, resolution: 'Поддерживаются URI, текстовые/Base64-подписки, JSON Sing-box и YAML Clash/Mihomo. Проверьте формат, адрес, порт и обязательные ключи.' }, 'Пакет профилей не принят');
  } finally { state.remoteProfileBusy = false; button.disabled = false; button.textContent = 'Проверить пакет'; renderRemoteProfilePreview(); }
}

async function importRemoteProfile() {
  const uri = $('#remoteProfileURI').value.trim();
  const preview = state.remoteProfilePreview?.preview;
  if (state.remoteProfileBusy || !uri || !preview?.node_count || state.remoteProfileReviewedInput !== uri) return;
  state.remoteProfileBusy = true;
  const button = $('#remoteProfileImportButton');
  button.disabled = true; button.textContent = 'Создаём…';
  try {
    const result = await api('/api/v1/provider-profiles/import', { method: 'POST', body: JSON.stringify({ profile: uri, selected_index: state.remoteProfileSelectedIndex, accept_partial: !!preview.rejected?.length, confirm: 'IMPORT_REMOTE_PROFILE' }) });
    if ($('#remoteProfileURI').value.trim() === uri) $('#remoteProfileURI').value = '';
    state.remoteProfilePreview = null;
    state.remoteProfileReviewedInput = '';
		state.remoteProfileSelectedIndex = 0;
    state.engineValidation = result.validation || null;
    await refreshEngineConfigs();
    renderRemoteProfilePreview();
    switchEngineTab('check');
    showNotice(result.ok ? 'success' : 'review', result.ok ? 'Черновик Sing-box готов' : 'Черновик создан, нужна проверка', result.note, result, true);
  } catch (error) {
    showDetails({ error: error.message, response: error.payload }, 'Профиль не импортирован');
  } finally { state.remoteProfileBusy = false; renderRemoteProfilePreview(); }
}

async function storeRemoteNodes() {
  const profile = $('#remoteProfileURI').value.trim();
  const preview = state.remoteProfilePreview?.preview;
  if (state.remoteProfileBusy || !profile || !preview?.node_count || state.remoteProfileReviewedInput !== profile) return;
  state.remoteProfileBusy = true;
  const button = $('#remoteProfileStoreButton');
  button.disabled = true;
  button.textContent = 'Сохраняем…';
  try {
    const result = await api('/api/v1/nodes/import', { method: 'POST', body: JSON.stringify({ profile, accept_partial: !!preview.rejected?.length, confirm: 'STORE_REMOTE_NODES' }) });
    await refreshNodes();
    showNotice('success', 'Узлы сохранены локально', `${Number(result.accepted_nodes || 0)} ${plural(result.accepted_nodes || 0, 'узел принят', 'узла приняты', 'узлов приняты')}. Всего в хранилище: ${Number(result.total_nodes || 0)}. Они ожидают точной проверки; маршруты не изменены.`, result, true);
  } catch (error) {
    showDetails({ error: error.message, response: error.payload }, 'Узлы не сохранены');
  } finally { state.remoteProfileBusy = false; renderRemoteProfilePreview(); }
}

async function selectRemoteProfileFile(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  if (file.size > 256 * 1024) {
    showDetails({ error: 'Файл больше 256 КБ.' }, 'Пакет профилей не принят');
    return;
  }
  try {
    $('#remoteProfileURI').value = await file.text();
    state.remoteProfilePreview = null;
		state.remoteProfileSelectedIndex = 0;
    renderRemoteProfilePreview();
    await previewRemoteProfile();
  } catch (error) {
    showDetails({ error: error.message }, 'Не удалось прочитать файл');
  }
}

function toggleRemoteProfileVisibility() {
  const input = $('#remoteProfileURI');
  const button = $('#remoteProfileReveal');
  const visible = input.classList.toggle('revealed');
  button.textContent = visible ? 'Скрыть' : 'Показать';
  button.setAttribute('aria-pressed', String(visible));
}

async function exportEngineFile() {
  const engine = selectedEngineView(); const file = selectedEngineFile();
  if (!engine || !file) return;
  try {
    if (file.sensitive && !await askConfirmation('Экспорт секретного конфига', 'Файл может содержать приватные ключи, UUID и пароли. Скачать его на это устройство?', 'Скачать')) return;
    const content = await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/file?file=${encodeURIComponent(file.id)}&expert=true`);
    const blob = new Blob([content.content || ''], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob); const a = document.createElement('a');
    a.href = url; a.download = file.name || `${engine.id}-${file.id}.conf`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  } catch (error) { showDetails({ error: error.message }, 'Ошибка экспорта'); }
}

function switchEngineTab(name) {
  state.engineTab = name;
  $$('.engine-tab').forEach((b) => b.classList.toggle('active', b.dataset.engineTab === name));
  $$('.engine-tab-panel').forEach((p) => p.classList.toggle('active', p.id === `engine-tab-${name}`));
}

function testStatusLabel(status) {
  return ({ pass: 'РАБОТАЕТ', partial: 'ЧАСТИЧНО', fail: 'ОШИБКА', 'not-ready': 'НЕ ГОТОВ', 'adapter-pending': 'НУЖЕН АДАПТЕР', pending: 'ОЖИДАНИЕ' })[status] || String(status || '—').toUpperCase();
}

function streamStatusLabel(status) {
  return ({ complete: 'прочитан', sampled: '32 КБ проверено', empty: 'без тела', interrupted: 'оборван' })[status] || 'не измерен';
}

function probeTiming(result) {
  const ttfb = Number(result?.ttfb_ms);
  const total = Number(result?.latency_ms);
  if (Number.isFinite(ttfb) && ttfb >= 0) return `TTFB ${ttfb} мс${Number.isFinite(total) && total > ttfb ? ` · всего ${total} мс` : ''}`;
  return Number.isFinite(total) ? `${total} мс` : '—';
}

function probeStream(result) {
  const bytes = Number(result?.bytes_read);
  const size = Number.isFinite(bytes) && bytes > 0 ? formatBytes(bytes) : '';
  return [streamStatusLabel(result?.stream_status), size].filter(Boolean).join(' · ');
}

function renderTestLab() {
  const current = state.testlab?.current || [];
  const counts = { pass: 0, partial: 0, fail: 0, 'not-ready': 0 };
  current.forEach((r) => { counts[r.status] = (counts[r.status] || 0) + 1; });
  $('#testSummary').innerHTML = [
    ['Работает', counts.pass, 'pass'], ['Частично', counts.partial, 'partial'], ['Ошибок', counts.fail, 'fail'], ['Проверено', current.length, ''],
  ].map(([label, n, cls]) => `<div class="test-stat ${cls}"><strong>${n}</strong><span>${label}</span></div>`).join('');
  $('#testCurrentRows').innerHTML = current.map((r) => { const verdict = probeVerdict(r); return `<tr><td><b>${esc(r.service_name)}</b><small>${esc(r.scenario_label || 'Основной доступ')}${r.scenario_required ? ' · обязательный' : ''}</small><small>${esc(r.probe_url || '')}</small></td><td><span class="test-status ${esc(r.status)}">${esc(probeStatusLabel(r))}</span><small>${esc(evidenceOutcomeLabel(r.outcome))}</small></td><td>${r.http_status || '—'}</td><td>${esc(probeTiming(r))}</td><td><span class="stream-status ${esc(r.stream_status || '')}">${esc(probeStream(r))}</span></td><td>${r.route === 'current' ? 'ТЕКУЩИЙ<small>применённый маршрут</small>' : esc(routeLabel(r.route))}<span class="probe-verdict ${esc(verdict.tone)}">${esc(verdict.text)}</span><small>${esc(evidenceLevelLabel(r.evidence_level))}</small><small>${r.evidence_v2?.finished_at ? esc(`факт: ${timeAgo(r.evidence_v2.finished_at)}`) : ''}</small></td><td>${esc(friendlyDetail(r.detail || '—'))}</td></tr>`; }).join('') || '<tr><td colspan="7"><div class="empty-inline">Проверки ещё не запускались</div></td></tr>';

  const routes = state.routeOptions.filter((o) => o.id !== 'auto');
  const cells = state.testlab?.matrix || [];
  const by = new Map(cells.map((c) => [`${c.service_id}\x00${c.route}`, c]));
  const latest = new Map(current.filter((r) => r.route === 'current').map((r) => [r.service_id, r]));
  $('#testMatrix').innerHTML = `<table class="matrix-table"><thead><tr><th>Сервис</th><th>Текущий</th>${routes.map((r) => `<th>${esc(r.name || routeLabel(r.id))}</th>`).join('')}</tr></thead><tbody>${state.services.map((s) => {
    const cur = latest.get(s.id);
    return `<tr><td><b>${esc(s.name)}</b></td><td>${cur ? `<span class="matrix-cell ${esc(cur.status)}" title="${esc(cur.detail || '')}">${testStatusLabel(cur.status)}</span>` : '<span class="matrix-cell pending">—</span>'}</td>${routes.map((route) => {
      const c = by.get(`${s.id}\x00${route.id}`);
      const status = c?.status || 'pending';
      return `<td><span class="matrix-cell ${esc(status)}" title="${esc(c?.reason || '')}">${testStatusLabel(status)}</span></td>`;
    }).join('')}</tr>`;
  }).join('')}</tbody></table>`;

  const serviceSelect = $('#isolatedService');
  const selectedService = serviceSelect.value;
  serviceSelect.innerHTML = state.services.map((service) => `<option value="${esc(service.id)}">${esc(service.name)}</option>`).join('');
  if (state.services.some((service) => service.id === selectedService)) serviceSelect.value = selectedService;
  const selectedRoutes = new Set($$('#isolatedRoutes input:checked').map((input) => input.value));
  $('#isolatedRoutes').innerHTML = routes.map((route) => {
    const available = route.id === 'direct' || !!route.selectable;
    const stateText = available ? 'готов к проверке' : !route.installed ? 'компонент не установлен' : !route.configured ? 'сначала создайте или импортируйте профиль' : 'конфигурация не готова';
    return `<label class="route-test-choice ${available ? '' : 'unavailable'}"><input type="checkbox" value="${esc(route.id)}" ${(available && (selectedRoutes.has(route.id) || (selectedRoutes.size === 0 && route.id === 'direct'))) ? 'checked' : ''} ${available ? '' : 'disabled'}><span>${esc(route.name || routeLabel(route.id))}</span><small>${esc(stateText)}</small></label>`;
  }).join('');
  renderSmartRoute();
}

function renderSmartRoute() {
  const services = state.smartRoute?.services || {};
  const rows = Object.entries(services).filter(([, item]) => item.selected_route);
  $('#smartRouteSummary').innerHTML = rows.map(([id, item]) => {
    const service = state.services.find((candidate) => candidate.id === id);
    const evidence = item.evidence?.[item.selected_route];
    return `<div class="smart-route-row"><span><b>${esc(service?.name || id)}</b><small>${esc(detailReasonLabels[item.reason] || item.reason || 'подтверждено')}</small></span><i>→</i><strong>${esc(routeLabel(item.selected_route))}</strong><em>${evidence ? `${esc(testStatusLabel(evidence.status))} · ${evidence.latency_ms || 0} мс · ${esc(evidenceOutcomeLabel(evidence.outcome))} · ${esc(evidenceLevelLabel(evidence.evidence_level))}` : '—'}</em></div>`;
  }).join('') || '<div class="empty-inline">Автопилот начнёт с безопасного порядка каталога и будет учитывать только локально подтверждённые проверки.</div>';
}

function dnsProfileByID(id) {
  return (state.dns?.profiles || []).find((profile) => profile.id === id);
}

function dnsProviderByID(id) {
  return (state.dns?.providers || []).find((provider) => provider.id === id);
}

function dnsEndpointLabel(endpoint) {
  const transport = String(endpoint.transport || 'dns').toUpperCase();
  const target = endpoint.url || (endpoint.address ? `${endpoint.address.includes(':') ? `[${endpoint.address}]` : endpoint.address}:${Number(endpoint.port || 0)}` : 'адрес не указан');
  const scope = endpoint.scope && endpoint.scope !== 'production' ? ` · ${endpoint.scope}` : '';
  return `${transport} · ${target}${scope}`;
}

function dnsProviderConfigMarkup(provider, dns) {
  if (provider.id === 'nextdns') {
    return `<div class="dns-provider-config"><label><span>ID профиля NextDNS</span><input id="dnsNextDNSID" maxlength="6" inputmode="text" autocomplete="off" spellcheck="false" placeholder="abc123" value="${esc(dns.nextdns_profile_id || '')}"><small>${esc(provider.configuration_hint || 'ID находится в кабинете NextDNS.')}</small></label><div class="dns-provider-config-actions"><button class="secondary" id="dnsSaveNextDNS" type="button">Сохранить ID</button>${dns.nextdns_profile_id ? '<button class="text-danger" id="dnsClearNextDNS" type="button">Удалить ID</button>' : ''}</div></div>`;
  }
  if (provider.id === 'custom') {
    return `<div class="dns-custom-config"><label><span>Название</span><input id="dnsCustomName" maxlength="80" placeholder="Домашний DNS" value="${esc(provider.configured ? provider.name : '')}"></label><label><span>Обычный DNS · по одному на строку</span><textarea id="dnsCustomServers" maxlength="1200" placeholder="9.9.9.9&#10;149.112.112.112">${esc((provider.servers || []).join('\n'))}</textarea></label><label><span>DoH · только HTTPS URL</span><input id="dnsCustomDoH" maxlength="512" placeholder="https://dns.example/dns-query" value="${esc(provider.doh || '')}"></label><label><span>DoT · имя или IP, порт 853 добавится автоматически</span><input id="dnsCustomDoT" maxlength="255" placeholder="dns.example:853" value="${esc(provider.dot || '')}"></label><label class="dns-trusted-local"><input id="dnsCustomTrustedLocal" type="checkbox" ${provider.trusted_local ? 'checked' : ''}><span><b>Это мой DNS в локальной сети</b><small>Разрешает частные IP только по явному выбору. Не включайте для чужого endpoint.</small></span></label><small>Endpoint сохраняются только на роутере. Переадресация DoH ограничена HTTPS и исходным сайтом.</small><div class="dns-provider-config-actions"><button class="secondary" id="dnsSaveCustom" type="button">Сохранить провайдер</button>${provider.configured ? '<button class="text-danger" id="dnsClearCustom" type="button">Удалить</button>' : ''}</div></div>`;
  }
  return '';
}

function renderDNS() {
  const dns = state.dns || {};
  const selectedID = dns.draft?.profile_id || 'automatic';
  const appliedID = dns.applied?.profile_id || 'automatic';
  $('#dnsProfiles').innerHTML = (dns.profiles || []).map((profile) => {
    const provider = dnsProviderByID(profile.provider_id);
    const selected = profile.id === selectedID;
    const applied = profile.id === appliedID;
    return `<button class="dns-profile-card ${selected ? 'selected' : ''}" type="button" data-dns-profile="${esc(profile.id)}" aria-pressed="${selected}">
      <span class="dns-profile-icon"><svg><use href="#i-dns"/></svg></span>
      <span><b>${esc(profile.name)}</b><small>${esc(profile.description)}</small><em>${esc(provider?.name || profile.provider_id)}${provider?.requires_configuration && !provider?.configured ? ' · НУЖНА НАСТРОЙКА' : ''}</em></span>
      <i>${applied ? 'ТЕКУЩИЙ' : (selected ? 'ЧЕРНОВИК' : '')}</i>
    </button>`;
  }).join('') || '<div class="community-empty">DNS-профили временно недоступны.</div>';
  const profile = dnsProfileByID(selectedID);
  const provider = dnsProviderByID(profile?.provider_id);
  $('#dnsProvider').innerHTML = provider ? `<div class="dns-provider-name"><span class="dns-profile-icon"><svg><use href="#i-dns"/></svg></span><div><b>${esc(provider.name)}</b><small>${esc(provider.description)}</small></div></div>
    <div class="dns-provider-rows"><div><span>Обычный DNS</span><b>${esc((provider.servers || []).join(' · ') || (provider.id === 'system' ? 'управляет система' : 'не используется'))}</b></div><div><span>DoH</span><b>${esc(provider.doh || 'не указан')}</b></div><div><span>DoT</span><b>${esc(provider.dot || 'не указан')}</b></div>${(provider.endpoints || []).length ? `<div><span>Проверяемые endpoint</span><b>${(provider.endpoints || []).map((endpoint) => esc(dnsEndpointLabel(endpoint))).join('<br>')}</b></div>` : ''}</div>
    <div class="outbound-tags"><span>${esc(provider.scope === 'negative-control' ? 'только лаборатория' : provider.scope === 'lab' ? 'лабораторный' : provider.scope === 'trusted-local' ? 'доверенный LAN' : provider.scope === 'production' ? 'обычное использование' : provider.scope === 'custom' ? 'пользовательский' : 'системный')}</span>${provider.encrypted_only ? '<span>только DoH/DoT</span>' : ''}${(provider.filters || []).map((filter) => `<span>${esc(filter)}</span>`).join('')}</div>
    ${(provider.recommended_for || []).length ? `<div class="dns-recommended"><b>Подходит для</b><span>${esc(provider.recommended_for.join(' · '))}</span></div>` : ''}
    ${(provider.warnings || []).map((warning) => `<div class="dns-provider-warning"><b>Важно</b><span>${esc(warning)}</span></div>`).join('')}
    ${provider.usque_registration === 'blocked' || provider.allowed_for_usque_bootstrap === false ? '<div class="dns-provider-warning danger"><b>USQUE</b><span>Этот DNS не будет автоматически использован для регистрации USQUE.</span></div>' : ''}
    ${(dns.migration_warnings || []).map((warning) => `<div class="dns-provider-warning"><b>Обновление</b><span>${esc(warning)}</span></div>`).join('')}
    ${dnsProviderConfigMarkup(provider, dns)}` : '<div class="community-empty">Провайдер не найден.</div>';
  $('#dnsSaveNextDNS')?.addEventListener('click', saveNextDNSProfile);
  $('#dnsClearNextDNS')?.addEventListener('click', clearNextDNSProfile);
  $('#dnsSaveCustom')?.addEventListener('click', saveCustomDNSProvider);
  $('#dnsClearCustom')?.addEventListener('click', clearCustomDNSProvider);
  renderDNSServiceBindings();
  $('#dnsProbeResults').innerHTML = (dns.last_probe || []).map((result) => `<div class="dns-probe-row"><span class="state-dot ${result.status === 'pass' ? 'good' : 'bad'}"></span><div><b><span class="dns-transport">${esc(result.transport || 'DNS')}</span>${esc(result.server)}</b><small>${result.status === 'pass' ? `${Number(result.latency_ms || 0)} мс · адресов: ${Number(result.addresses || 0)} · ${result.dnssec === 'resolver-reported-ad' || result.dnssec === 'confirmed' ? 'резолвер сообщил AD-флаг' : result.dnssec === 'not-reported' || result.dnssec === 'not-confirmed' ? 'AD-флаг не сообщён' : 'AD-флаг не проверялся'}` : esc(result.error || 'нет ответа')}</small></div></div>`).join('') || '<div class="community-empty">Проверка ещё не запускалась.</div>';
  renderDNSPlan();
}

function renderDNSServiceBindings() {
  const dns = state.dns || {};
  const serviceProfiles = (dns.profiles || []).filter((item) => {
    const itemProvider = dnsProviderByID(item.provider_id);
    return item.id !== 'automatic' && (!itemProvider?.requires_configuration || itemProvider?.configured);
  });
  const serviceDrafts = dns.service_drafts || {};
  const services = [...(state.services || [])].sort((left, right) => Number(right.enabled) - Number(left.enabled) || left.name.localeCompare(right.name, 'ru'));
  $('#dnsServiceBindings').innerHTML = services.map((service) => {
    const selectedProfile = serviceDrafts[service.id] || 'inherit';
    return `<label class="dns-service-binding ${selectedProfile !== 'inherit' ? 'changed' : ''}"><span><b>${esc(service.name)}</b><small>${service.enabled ? 'Сервис включён' : 'Сервис выключен'} · рабочий DNS не изменён</small></span><select data-dns-service="${esc(service.id)}" aria-label="DNS для ${esc(service.name)}"><option value="inherit">Наследовать общий DNS</option>${serviceProfiles.map((item) => `<option value="${esc(item.id)}" ${item.id === selectedProfile ? 'selected' : ''}>${esc(item.name)}</option>`).join('')}</select></label>`;
  }).join('') || '<div class="community-empty">Каталог сервисов временно недоступен.</div>';
}

function renderDNSPlan() {
  const dns = state.dns || {};
	const plan = state.dnsPlan || dns.plan;
	$('#dnsPlan').innerHTML = plan ? `<div class="dns-plan-summary ${plan.ready ? 'ready' : 'blocked'}"><div><span>${plan.ready ? 'ГОТОВО' : 'ПРЕДПРОСМОТР'}</span><b>${esc(plan.profile?.name || 'DNS')}</b></div><p>${esc(plan.recommendation || '')}</p></div><div class="dns-plan-checks">${(plan.checks || []).map((check) => `<div class="dns-plan-check ${esc(check.status)}"><i>${check.status === 'pass' ? '✓' : check.status === 'warn' ? '!' : '×'}</i><span><b>${esc(check.id === 'probe' ? 'Доступность' : check.id === 'ownership' ? 'Владелец DNS' : check.id === 'adapter' ? 'Применение' : check.id === 'configuration' ? 'Настройка' : check.id === 'dnssec' ? 'DNSSEC' : check.id === 'service-bindings' ? 'Привязки сервисов' : 'Профиль')}</b><small>${esc(check.message)}</small></span></div>`).join('')}</div><details class="dns-plan-steps"><summary>Показать этапы безопасного Apply</summary>${(plan.steps || []).map((step) => `<div><i>${Number(step.order)}</i><span><b>${esc(step.name)}</b><small>${esc(step.summary)}</small></span></div>`).join('')}</details>` : '<div class="community-empty">DNS-план временно недоступен.</div>';
  $('#dnsDiscard').disabled = !dns.dirty;
  const apply = $('#dnsApply');
  const canApply = !!dns.dirty && !!plan?.ready;
  apply.disabled = !canApply;
  apply.textContent = !dns.dirty ? 'Нет изменений' : plan?.ready ? 'Подтвердить DNS' : 'Применение недоступно';
  apply.title = plan?.recommendation || '';
  $('#dnsApplyHint').classList.toggle('ready', canApply);
  $('#dnsApplyHint').textContent = !dns.dirty
    ? 'DNS-черновиков нет. Рабочие настройки роутера не менялись.'
    : plan?.ready
    ? 'Этот профиль не требует изменения сети и может быть подтверждён отдельно.'
    : (plan?.recommendation || 'Live-применение заблокировано; черновик сохранён, проверка серверов доступна.');
}

async function selectServiceDNSProfile(serviceID, profileID) {
  try {
    state.dns = await api('/api/v1/dns/service-draft', { method: 'PUT', body: JSON.stringify({ service_id: serviceID, profile_id: profileID }) });
    state.dnsPlan = await api('/api/v1/dns/plan');
    state.status = await api('/api/v1/status');
    renderDNS();
    renderStatus();
    const service = state.services.find((item) => item.id === serviceID);
    showNotice('review', 'DNS для сервиса сохранён', `${service?.name || serviceID}: ${profileID === 'inherit' ? 'общий DNS' : dnsProfileByID(profileID)?.name || profileID}. Это черновик, сеть не изменена.`, state.dns);
  } catch (error) {
    showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Привязка DNS не сохранена');
  }
}

async function selectDNSProfile(profileID) {
  try {
    state.dns = await api('/api/v1/dns/draft', { method: 'PUT', body: JSON.stringify({ profile_id: profileID }) });
	state.dnsPlan = await api('/api/v1/dns/plan');
    state.status = await api('/api/v1/status');
    renderDNS();
    renderStatus();
    showNotice('review', 'DNS-профиль сохранён как черновик', 'Рабочий DNS роутера не изменён. Сначала проверьте доступность выбранных серверов.', state.dns);
  } catch (error) {
    showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'DNS-профиль не сохранён');
  }
}

async function saveNextDNSProfile() {
  const profileID = ($('#dnsNextDNSID')?.value || '').trim().toLowerCase();
  if (!profileID) {
    showDetails({ message: 'Введите шестизначный ID из кабинета NextDNS. Для удаления сохранённого ID используйте отдельную кнопку.' }, 'ID NextDNS не указан');
    return;
  }
  try {
    state.dns = await api('/api/v1/dns/nextdns', { method: 'PUT', body: JSON.stringify({ profile_id: profileID }) });
    state.dnsPlan = await api('/api/v1/dns/plan');
    renderDNS();
    showNotice('review', 'Профиль NextDNS настроен', 'ID сохранён только на роутере. Теперь можно проверить DoH и DoT; рабочий DNS ещё не изменён.', state.dns);
  } catch (error) {
    showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'ID NextDNS не сохранён');
  }
}

async function clearNextDNSProfile() {
  try {
    state.dns = await api('/api/v1/dns/nextdns', { method: 'PUT', body: JSON.stringify({ profile_id: '' }) });
    state.dnsPlan = await api('/api/v1/dns/plan');
    renderDNS();
    showNotice('review', 'ID NextDNS удалён', 'Персональный endpoint больше не используется. Рабочий DNS роутера не менялся.', state.dns);
  } catch (error) {
    showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'ID NextDNS не удалён');
  }
}

async function saveCustomDNSProvider() {
  const servers = ($('#dnsCustomServers')?.value || '').split(/[\n,;]+/).map((value) => value.trim()).filter(Boolean);
  const input = { name: ($('#dnsCustomName')?.value || '').trim(), servers, doh: ($('#dnsCustomDoH')?.value || '').trim(), dot: ($('#dnsCustomDoT')?.value || '').trim(), trusted_local: !!$('#dnsCustomTrustedLocal')?.checked };
  try {
    state.dns = await api('/api/v1/dns/custom', { method: 'PUT', body: JSON.stringify(input) });
    state.dnsPlan = await api('/api/v1/dns/plan');
    renderDNS();
    showNotice('review', 'Свой DNS сохранён', 'Endpoint нормализованы и сохранены локально. Перед использованием запустите проверку транспортов.', state.dns);
  } catch (error) {
    showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Свой DNS не сохранён');
  }
}

async function clearCustomDNSProvider() {
  try {
    state.dns = await api('/api/v1/dns/custom', { method: 'DELETE' });
    state.dnsPlan = await api('/api/v1/dns/plan');
    renderDNS();
    showNotice('review', 'Свой DNS удалён', 'Пользовательские endpoint удалены. Рабочий DNS роутера не менялся.', state.dns);
  } catch (error) {
    showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Свой DNS не удалён');
  }
}

async function testDNSProfile() {
  const button = $('#dnsTest');
  const profileID = state.dns?.draft?.profile_id || 'automatic';
  button.disabled = true; button.textContent = 'Проверка…';
  try {
    const result = await api('/api/v1/dns/test', { method: 'POST', body: JSON.stringify({ profile_id: profileID }) });
    state.dns = await api('/api/v1/dns');
	state.dnsPlan = await api('/api/v1/dns/plan');
    renderDNS();
    const passed = (result.results || []).filter((item) => item.status === 'pass').length;
    showDetails({ result: passed ? `Доступны транспорты: ${passed} из ${(result.results || []).length}` : 'Ни один DNS-транспорт не ответил', checks: result.results, note: result.note }, 'Проверка DNS');
  } catch (error) {
    showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Проверка DNS не выполнена');
  } finally {
    button.disabled = false; button.textContent = 'Проверить выбранный';
  }
}

async function discardDNSDraft() {
  try {
    state.dns = await api('/api/v1/dns/discard', { method: 'POST', body: '{}' });
	state.dnsPlan = await api('/api/v1/dns/plan');
    state.status = await api('/api/v1/status');
    renderDNS();
    renderStatus();
  } catch (error) {
    showDetails({ error: error.message }, 'DNS-черновик не сброшен');
  }
}

async function applyDNSDraft() {
  const button = $('#dnsApply');
  button.disabled = true;
  button.textContent = 'Проверка…';
  try {
    const result = await api('/api/v1/dns/apply', { method: 'POST', body: '{}' });
    [state.dns, state.dnsPlan, state.status] = await Promise.all([api('/api/v1/dns'), api('/api/v1/dns/plan'), api('/api/v1/status')]);
    renderDNS();
    renderStatus();
    showNotice('success', 'DNS-раздел подтверждён', result.note || 'Действие завершено без изменения сети.', result);
  } catch (error) {
    showNotice('review', 'DNS пока нельзя применить', error.payload?.resolution || error.message, error.payload || { error: error.message }, true);
  } finally {
    renderDNS();
  }
}

async function refreshTestLab() {
  try { [state.testlab, state.smartRoute] = await Promise.all([api('/api/v1/testlab'), api('/api/v1/smart-route')]); renderTestLab(); } catch (error) { showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Тесты не обновлены'); }
}

async function runCurrentTests() {
  const button = $('#runCurrentTests'); button.disabled = true; button.textContent = 'Проверка…';
  const enabledOnly = $('#testScope').value === 'enabled';
  const ids = enabledOnly ? state.services.filter((s) => s.applied_enabled).map((s) => s.id) : [];
  if (enabledOnly && ids.length === 0) {
    button.disabled = false; button.textContent = 'Проверить текущую конфигурацию';
    showDetails({ message: 'Нет применённых включённых сервисов. Выберите «Все сервисы» или сначала примените черновик сервисов.' }, 'Нечего проверять');
    return;
  }
  try {
    const result = await api('/api/v1/testlab/current', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ services: ids }) });
    await refreshTestLab();
    showDetails(result, 'Проверка текущей конфигурации');
  } catch (error) { showDetails({ error: error.message }, 'Тест завершился ошибкой'); }
  finally { button.disabled = false; button.textContent = 'Проверить текущую конфигурацию'; }
}

async function runIsolatedTests() {
  const button = $('#runIsolatedTests');
  const service = $('#isolatedService').value;
  const routes = $$('#isolatedRoutes input:checked').map((input) => input.value);
  if (!service || routes.length === 0) {
    showDetails({ message: 'Выберите сервис и хотя бы один маршрут.' }, 'Нечего сравнивать');
    return;
  }
  button.disabled = true; button.textContent = 'Сравнение…';
  try {
    const result = await api('/api/v1/testlab/routes', { method: 'POST', body: JSON.stringify({ services: [service], routes }) });
    [state.testlab, state.smartRoute] = await Promise.all([api('/api/v1/testlab'), api('/api/v1/smart-route')]);
    renderTestLab();
    showDetails(result, 'Изолированное сравнение маршрутов');
  } catch (error) {
    showDetails({ error: error.message }, 'Изолированный тест завершился ошибкой');
  } finally {
    button.disabled = false; button.textContent = 'Запустить сравнение';
  }
}

function sourceStateText(s) {
  if (s.kind === 'reference') return ['справочник', ''];
  if (!s.enabled) return ['выключен', ''];
  if (s.cache_status === 'stale') return ['нужно обновить', 'warn'];
  if (s.last_known_good && s.ready) return ['предыдущая копия', 'warn'];
  if (s.legacy_cache && s.ready) return ['нужна сверка', 'warn'];
  if (s.cache_status === 'quarantined') return ['обновление отклонено', 'warn'];
  if (s.last_error) return ['ошибка', 'bad'];
  if (s.ready) return ['актуален', 'good'];
  return ['не загружен', ''];
}

function sourceFreshnessText(s) {
  if (s.kind === 'reference') return '';
  if (s.cache_status === 'stale') return 'Срок актуальности истёк. Обновите список перед новой настройкой маршрутов.';
  if (s.last_known_good && s.ready) return 'Новую загрузку отклонили. Используется предыдущая проверенная копия.';
  if (s.legacy_cache && s.ready) return 'Список из предыдущей версии. Обновите, чтобы подтвердить источник и срок актуальности.';
  const expires = new Date(s.expires_at);
  return s.ready && Number.isFinite(expires.getTime()) && expires.getFullYear() > 2000 ? `Актуален до ${expires.toLocaleString('ru-RU')}` : '';
}

function sourceKindText(kind) {
  return ({ reference: 'справочный источник', domains: 'доменные имена', cidrs: 'IP-сети', downloadable: 'загружаемый список', local: 'локальный список', community: 'каталог сообщества' })[kind] || kind || 'справочник';
}

function sourceDiffText(s) {
  if (s.legacy_cache || !s.diff || s.kind === 'reference') return '';
  const { added, removed, previous_sha256: previous } = s.diff;
  if (!Number.isSafeInteger(added) || !Number.isSafeInteger(removed) || added < 0 || removed < 0) return '';
  if (!previous) return `Первая загрузка: ${added.toLocaleString('ru-RU')} записей`;
  if (!added && !removed) return 'Состав списка не изменился';
  return `Изменения списка: +${added.toLocaleString('ru-RU')} / −${removed.toLocaleString('ru-RU')}. Рабочие маршруты автоматически не меняются.`;
}

function renderSources() {
  const operational = state.sources.filter((s) => s.kind !== 'reference' && s.applied_enabled);
  const ready = operational.filter((s) => s.ready).length;
  const references = state.sources.filter((s) => s.kind === 'reference').length;
  $('#sourceOverview').innerHTML = `<div class="source-stat"><strong>${ready}</strong><span>из ${operational.length} используемых списков готовы · ${references} справочных источников</span></div><div class="source-mini-list">${state.sources.slice(0, 8).map((s) => `<span class="source-mini">${esc(s.name)}</span>`).join('')}</div>`;
  $('#sourceRows').innerHTML = state.sources.map((s) => {
    const [text, cls] = sourceStateText(s);
    const control = s.kind === 'reference'
      ? '<span class="source-reference-mark">справочно</span>'
      : `<button class="toggle ${s.enabled ? 'on' : ''}" data-source-toggle="${esc(s.id)}" aria-pressed="${s.enabled ? 'true' : 'false'}" aria-label="${s.enabled ? 'Не использовать' : 'Использовать'} ${esc(s.name)}"><i></i></button><small class="source-applied-state">${s.dirty ? `черновик · сейчас ${s.applied_enabled ? 'включён' : 'выключен'}` : s.applied_enabled ? 'используется' : 'выключен'}</small>`;
    const stateText = s.dirty ? `${text} · выбор изменён` : text;
    return `<tr class="${s.dirty ? 'source-dirty-row' : ''}"><td><b>${esc(s.name)}</b><div class="source-role">${esc(s.description || 'Проверяемый внешний источник данных.')}</div>${String(s.url || '').startsWith('https://') ? `<a class="source-url" href="${esc(s.url)}" target="_blank" rel="noreferrer">Сайт источника ↗</a>` : ''}</td><td><div class="source-choice">${control}</div></td><td>${esc(sourceKindText(s.kind))}</td><td><span class="source-state"><i class="state-dot ${s.dirty ? 'warn' : cls}"></i>${esc(stateText)}</span></td><td>${s.entries ? Number(s.entries).toLocaleString('ru-RU') : '—'}</td><td>${esc(sourceFreshnessText(s) || s.last_error || '—')}<div class="source-role">${esc(sourceDiffText(s))}</div></td></tr>`;
  }).join('');
  $$('[data-source-toggle]').forEach((button) => button.addEventListener('click', () => setSourceDraft(button.dataset.sourceToggle, button.getAttribute('aria-pressed') !== 'true')));
}

function nodeSourceLabel(node) {
  const kinds = new Set();
  for (const origin of node?.origins || []) {
    const source = (state.nodes?.sources || []).find((item) => item.id === origin.source_id);
    if (source?.kind) kinds.add(({ manual: 'ручной импорт', file: 'локальный файл', subscription: 'подписка', community: 'внешний каталог', legacy: 'перенос старых данных' })[source.kind] || 'локальный источник');
  }
  return [...kinds].join(', ') || 'источник не указан';
}

function nodeExpiryText(node) {
  const values = (node?.origins || []).map((origin) => new Date(origin.expires_at)).filter((date) => Number.isFinite(date.getTime()) && date.getFullYear() > 2000);
  if (!values.length) return 'срок не указан';
  const expiry = new Date(Math.max(...values.map((date) => date.getTime())));
  return expiry.getTime() <= Date.now() ? `истёк ${expiry.toLocaleString('ru-RU')}` : `актуален до ${expiry.toLocaleString('ru-RU')}`;
}

function nodeRecoveryBanner(recovery) {
  // A successful recovery is historical: routes may have been stopped since.
  // Current running state belongs to the global status, not this alert.
  const labels = { revalidating: 'Повторная проверка применённого маршрута', 'network-stale': 'Маршрут ожидает повторной проверки', 'requires-review': 'Восстановление требует вашего внимания' };
  const label = labels[recovery?.state];
  return label ? `<b>${esc(label)}</b><span>${esc(recovery.message || '')}</span>` : '';
}

function renderNodes() {
  renderNodeBrowser();
}

function renderNodeGroups(groups, nodes) {
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const optionMap = new Map((state.routeOptions || []).map((option) => [option.id, option]));
  $('#nodeGroupList').innerHTML = groups.map((group) => {
    const members = (group.node_ids || []).map((id) => nodeMap.has(id) ? nodeDisplayName(nodeMap.get(id)) : 'Удалённый узел');
    const services = optionMap.get(`sing-box:${group.id}`)?.services || [];
    const serviceNames = services.map((id) => state.services.find((service) => service.id === id)?.name || id);
    const assigned = state.services.filter((service) => service.enabled && service.route === `sing-box:${group.id}`).map((service) => service.name);
    const hint = assigned.length ? `Назначено: ${assigned.join(', ')}` : (serviceNames.length ? `Можно назначить: ${serviceNames.join(', ')}` : 'Сначала проверьте хотя бы один узел для нужного сервиса');
    return `<article class="node-group-card"><div><span class="node-protocol">${group.mode === 'manual' ? 'Ручной выбор' : 'Автоматическая замена при отказе'}</span><h3>${esc(group.name)}</h3><p>${members.map(esc).join(' · ')}</p><small>${esc(hint)}</small></div><div class="node-actions"><button class="secondary" type="button" data-node-group-check="${esc(group.id)}">Проверить группу</button><button class="primary" type="button" data-node-group-use="${esc(group.id)}" ${services.length ? '' : 'disabled'}>Выбрать для сервиса</button><button class="secondary" type="button" data-node-group-edit="${esc(group.id)}">Изменить</button><button class="danger-button" type="button" data-node-group-delete="${esc(group.id)}">Удалить</button></div></article>`;
  }).join('');
  $$('[data-node-group-edit]').forEach((button) => button.addEventListener('click', () => openNodeGroup(button.dataset.nodeGroupEdit)));
  $$('[data-node-group-delete]').forEach((button) => button.addEventListener('click', () => deleteNodeGroup(button.dataset.nodeGroupDelete)));
}

function openNodeGroup(id = '') {
  const nodes = (state.nodes?.nodes || []).filter((node) => !node.disabled);
  if (!nodes.length) return showDetails({ error: 'Сначала добавьте и включите хотя бы один узел.' }, 'Группа не создана');
  const group = (state.nodes?.groups || []).find((item) => item.id === id);
  const requested = [...nodeBrowser.selected];
  if (!group && requested.length > 32) return showDetails({ error: 'В резервной группе может быть до 32 подключений. Уменьшите выборку.' }, 'Создание группы');
  const selected = new Set(group?.node_ids || (requested.length ? requested : nodes.slice(0, 1).map((node) => node.id)));
  $('#nodeGroupID').value = group?.id || '';
  $('#nodeGroupTitle').textContent = group ? `Изменить: ${group.name}` : 'Новая группа';
  $('#nodeGroupName').value = group?.name || '';
  $('#nodeGroupMode').value = group?.mode || 'fallback';
  $('#nodeGroupHold').value = String(group?.hold_down_seconds || 1800);
  $('#nodeGroupMembers').innerHTML = nodes.map((node) => `<label><input type="checkbox" value="${esc(node.id)}" ${selected.has(node.id) ? 'checked' : ''}><span>${esc(nodeDisplayName(node))} · ${esc(node.protocol || '')}</span></label>`).join('');
  $('#nodeGroupPreferred').innerHTML = nodes.map((node) => `<option value="${esc(node.id)}" ${node.id === (group?.preferred_node_id || [...selected][0]) ? 'selected' : ''}>${esc(nodeDisplayName(node))}</option>`).join('');
  $('#nodeGroupDialog').showModal();
}

async function saveNodeGroup(event) {
  event.preventDefault();
  const id = $('#nodeGroupID').value;
  const nodeIDs = $$('#nodeGroupMembers input:checked').map((input) => input.value);
  if (!nodeIDs.length) return showDetails({ error: 'Выберите хотя бы один узел.' }, 'Группа не сохранена');
  if (nodeIDs.length > 32) return showDetails({ error: 'В группе может быть до 32 подключений.' }, 'Группа не сохранена');
  const preferred = nodeIDs.includes($('#nodeGroupPreferred').value) ? $('#nodeGroupPreferred').value : nodeIDs[0];
  const body = { name: $('#nodeGroupName').value.trim(), mode: $('#nodeGroupMode').value, node_ids: nodeIDs, preferred_node_id: preferred, hold_down_seconds: Number($('#nodeGroupHold').value), confirm: id ? 'UPDATE_NODE_GROUP' : 'CREATE_NODE_GROUP' };
  try {
    await api(id ? `/api/v1/node-groups/${encodeURIComponent(id)}` : '/api/v1/node-groups', { method: id ? 'PUT' : 'POST', body: JSON.stringify(body) });
    $('#nodeGroupDialog').close();
    state.routeOptions = await api('/api/v1/routes/options');
    await refreshNodes();
  } catch (error) { showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Группа не сохранена'); }
}

async function deleteNodeGroup(id) {
  const group = (state.nodes?.groups || []).find((item) => item.id === id);
  if (!group || !await askConfirmation('Удалить группу узлов?', 'Сами узлы останутся. Если группа назначена сервису, сначала выберите для него другой маршрут.', 'Удалить')) return;
  try {
    await api(`/api/v1/node-groups/${encodeURIComponent(id)}`, { method: 'DELETE', body: JSON.stringify({ confirm: 'DELETE_NODE_GROUP' }) });
    state.routeOptions = await api('/api/v1/routes/options');
    await refreshNodes();
  } catch (error) { showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Группа не удалена'); }
}

async function refreshNodes() {
  const button = $('#refreshNodes');
  button.disabled = true;
  button.textContent = 'Обновление…';
  try {
    [state.nodes, state.routeOptions] = await Promise.all([api('/api/v1/nodes'), api('/api/v1/routes/options')]);
    renderNodes();
  } catch (error) {
    showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Узлы не обновлены');
  } finally {
    button.disabled = false;
    button.textContent = 'Обновить';
  }
}

function nodeByID(id) {
  return (state.nodes?.nodes || []).find((node) => node.id === id);
}

function openNodeEdit(id) {
  const node = nodeByID(id);
  if (!node) return;
  $('#nodeEditID').value = id;
  $('#nodeEditTitle').textContent = nodeDisplayName(node);
  $('#nodeEditAlias').value = node.name?.startsWith('Узел ') ? '' : node.name || '';
  $('#nodeEditDialog').showModal();
  setTimeout(() => $('#nodeEditAlias').focus(), 0);
}

function openNodeCheck(id, serviceHint) {
  const node = nodeByID(id);
  if (!node || node.disabled || node.state === 'expired') return;
  closeNodeCheck();
  state.nodeFlow = { id, busy: false, controller: null };
  const services = state.services.filter((service) => service.probe_url || (Array.isArray(service.probes) && service.probes.some((probe) => probe.required && probe.url)));
  $('#nodeCheckID').value = id;
  $('#nodeCheckTitle').textContent = nodeDisplayName(node);
  $('#nodeCheckService').innerHTML = services.map((service) => `<option value="${esc(service.id)}">${esc(nodeServiceScenario(service))}</option>`).join('');
  const browserService = $('#nodeBrowserService')?.value;
  const preferredService = services.some(service => service.id === serviceHint) ? serviceHint : services.some(service => service.id === browserService) ? browserService : node.health?.service_id;
  if (services.some(service => service.id === preferredService)) $('#nodeCheckService').value = preferredService;
  $('#nodeCheckRun').disabled = services.length === 0;
  $('#nodeCheckRun').textContent = services.length ? 'Проверить узел' : 'Нет доступных сценариев';
  updateNodeCheckSelection();
  $('#nodeCheckDialog').showModal();
}

function updateNodeCheckSelection() {
  const serviceID = $('#nodeCheckService').value;
  const id = $('#nodeCheckID').value;
  const available = (state.routeOptions || []).some((option) => option.id === `sing-box:${id}` && option.selectable && (option.services || []).includes(serviceID));
  $('#nodeCheckPreview').hidden = !available;
  $('#nodeCheckPreview').disabled = false;
  $('#nodeCheckResult').textContent = available ? 'Для этого сервиса уже есть свежая проверка. Можно повторить её или просмотреть маршрут.' : 'Выберите сервис и запустите проверку.';
  if (typeof renderNodeIntentScope === 'function') renderNodeIntentScope(true);
}

function closeNodeCheck() {
  state.nodeFlow?.controller?.abort();
  state.nodeFlow = null;
  $('#nodeCheckDialog').close();
  $('#nodeCheckService').disabled = false;
  $('#nodeCheckPreview').hidden = true;
  $('#nodeCheckResult').textContent = '';
  if (typeof setNodeIntentBusy === 'function') setNodeIntentBusy(false);
}

async function runNodeCheck(event) {
  event.preventDefault();
  const button = $('#nodeCheckRun');
  const id = $('#nodeCheckID').value;
  const serviceID = $('#nodeCheckService').value;
  const flow = state.nodeFlow;
  if (!id || !serviceID || !flow || flow.busy) return;
  flow.busy = true;
  flow.controller = new AbortController();
  $('#nodeCheckService').disabled = true;
  $('#nodeCheckPreview').hidden = true;
  $('#nodeCheckResult').textContent = 'Проверяем этот узел для выбранного сервиса…';
  button.disabled = true;
  button.textContent = 'Проверяем до 45 секунд…';
  try {
    const response = await api(`/api/v1/nodes/${encodeURIComponent(id)}/check`, { method: 'POST', signal: flow.controller.signal, body: JSON.stringify({ service_id: serviceID, confirm: 'CHECK_NODE' }) });
    if (state.nodeFlow !== flow || $('#nodeCheckService').value !== serviceID || $('#nodeCheckID').value !== id) return;
    const passed = response.ok === true && response.result?.available === true && response.result?.service_id === serviceID && response.result?.node_id === id;
    $('#nodeCheckResult').textContent = passed ? 'Сервис доступен через этот узел. Просмотрите маршрут перед применением.' : (response.result?.message || 'Узел не прошёл проверку выбранного сервиса. Можно проверить другой узел.');
    $('#nodeCheckPreview').hidden = !passed;
    await refreshNodes();
  } catch (error) {
    if (state.nodeFlow === flow) $('#nodeCheckResult').textContent = error.name === 'AbortError' ? 'Проверка отменена. Дождитесь очистки временного процесса перед повтором.' : error.message;
  } finally {
    if (state.nodeFlow === flow) {
      flow.busy = false;
      flow.controller = null;
      $('#nodeCheckService').disabled = false;
      button.disabled = false;
      button.textContent = 'Повторить проверку';
    }
  }
}

async function previewNodeRoute() {
  const flow = state.nodeFlow;
  const id = $('#nodeCheckID').value;
  const serviceID = $('#nodeCheckService').value;
  if (!flow || flow.busy || !id || !serviceID || state.nodeRouteReview?.busy) return;
  flow.busy = true;
  flow.controller = new AbortController();
  $('#nodeCheckPreview').disabled = true;
  $('#nodeCheckRun').disabled = true;
  $('#nodeCheckService').disabled = true;
  try {
    const scope = typeof nodeIntentScopeValue === 'function' ? nodeIntentScopeValue() : { mode: 'applied' };
    if (!scope.mode || scope.mode === 'selected' && !scope.sources?.length) throw new Error('Сначала выберите устройства для подключения.');
    const response = await api(`/api/v1/nodes/${encodeURIComponent(id)}/preview`, { method: 'POST', signal: flow.controller.signal, body: JSON.stringify({ service_id: serviceID, scope, expected_revision: state.status?.revision }) });
    if (state.nodeFlow !== flow || $('#nodeCheckService').value !== serviceID || $('#nodeCheckID').value !== id) return;
    if (response.review?.node_id !== id || response.review?.service_id !== serviceID) throw new Error('Ответ относится к другому выбору. Откройте новый план.');
    closeNodeRoute();
    closeNodeCheck();
    state.nodeRouteReview = { ...response, id, serviceID, busy: false, controller: null };
    const blockers = (response.transaction?.blockers || []).map((blocker) => `<li>${esc(blocker.message)} ${esc(blocker.resolution || '')}</li>`).join('');
    $('#nodeRouteSummary').innerHTML = `<dl><div><dt>Сервис</dt><dd>${esc(nodeServiceScenario(state.services.find(service => service.id === serviceID)))}</dd></div><div><dt>Подключение</dt><dd>${esc(nodeByID(id) ? nodeDisplayName(nodeByID(id)) : response.node_name || 'Выбранный узел')}</dd></div><div><dt>Устройства</dt><dd>${esc(response.effective_scope?.summary || 'Обновите просмотр, чтобы получить область устройств')}</dd></div></dl><p>${esc(response.scope_notice || response.note || '')}</p><p>${esc(response.verification || '')}</p>${blockers ? `<ul>${blockers}</ul>` : ''}`;
    $('#nodeRouteStatus').textContent = response.safe_mode ? 'Включён безопасный режим. Разрешите рабочее применение в настройках, затем откройте новый план.' : response.ready ? 'План готов. Подтверждение действует не более двух минут и только в текущей сети.' : 'Применение пока заблокировано. Устраните причины выше и повторите просмотр.';
    $('#nodeRouteApply').disabled = !response.ready || !response.review?.review_token;
    $('#nodeRouteApply').textContent = 'Применить маршрут';
    $('#nodeRouteCancel').textContent = 'Вернуться';
    $('#nodeRouteDialog').showModal();
    const review = state.nodeRouteReview;
    state.nodeReviewTimer = setTimeout(() => {
      if (state.nodeRouteReview === review && !review.busy) {
        $('#nodeRouteApply').disabled = true;
        $('#nodeRouteStatus').textContent = 'Подтверждение истекло. Вернитесь к узлу и откройте новый план.';
      }
    }, Math.max(0, new Date(response.review?.expires_at).getTime() - Date.now()));
  } catch (error) {
    if (state.nodeFlow === flow) $('#nodeCheckResult').textContent = error.name === 'AbortError' ? 'Просмотр отменён.' : error.message;
  } finally {
    if (state.nodeFlow === flow) {
      flow.busy = false;
      flow.controller = null;
      $('#nodeCheckPreview').disabled = false;
      $('#nodeCheckRun').disabled = false;
      $('#nodeCheckService').disabled = false;
    }
  }
}

function closeNodeRoute() {
  const review = state.nodeRouteReview;
  if (review?.busy) {
    review.controller?.abort();
    review.review = null;
    $('#nodeRouteApply').disabled = true;
  }
  clearTimeout(state.nodeReviewTimer);
  state.nodeRouteReview = null;
  $('#nodeRouteDialog').close();
  $('#nodeRouteSummary').textContent = '';
}

async function applyNodeRoute() {
  const current = state.nodeRouteReview;
  const review = current?.review;
  if (!current || current.busy || !current.ready || !review?.review_token || Date.now() >= new Date(review.expires_at).getTime()) return;
  current.busy = true;
  current.controller = new AbortController();
  current.review = null; // One use, including failures and disconnected clients.
  $('#nodeRouteApply').disabled = true;
  $('#nodeRouteApply').textContent = 'Проверяем и применяем…';
  $('#nodeRouteCancel').textContent = 'Закрыть';
  $('#nodeRouteStatus').textContent = 'Сохраняем применение на роутере. Закрытие окна не отменяет принятое задание; отмена доступна в разделе «Сервисы».';
  try {
    let response = await api(`/api/v1/nodes/${encodeURIComponent(current.id)}/apply`, { method: 'POST', signal: current.controller.signal, body: JSON.stringify({ service_id: current.serviceID, review_token: review.review_token, reviewed_digest: review.reviewed_digest, revision: review.revision, generation: review.generation, confirm: 'APPLY_NODE_ROUTE', idempotency_key: `node-apply-${review.review_token}` }) });
    if (state.nodeRouteReview !== current || current.controller.signal.aborted) return;
    response = await waitNodeApplyJob(response, current.controller.signal, message => { if (state.nodeRouteReview === current) $('#nodeRouteStatus').textContent = message; });
    if (state.nodeRouteReview !== current || current.controller.signal.aborted) return;
    $('#nodeRouteStatus').textContent = response.live_applied === true ? 'Маршрут применён и прошёл проверки. Проверьте сервис на выбранном устройстве.' : 'Применение не подтверждено. Обновите панель перед новым действием.';
    await refreshAfterMutation();
  } catch (error) {
    if (state.nodeRouteReview === current) $('#nodeRouteStatus').textContent = `${error.message} Проверьте задание в разделе «Сервисы» или откройте лог перед повторным применением.`;
  } finally {
    if (state.nodeRouteReview === current) {
      current.busy = false;
      current.controller = null;
      $('#nodeRouteApply').textContent = 'Нужен новый просмотр';
      $('#nodeRouteCancel').textContent = 'Закрыть';
    }
  }
}

// Poll only the accepted identity. Closing/logging out stops observation, not
// the server-owned transaction. Canceling a job remains an explicit DELETE.
async function waitNodeApplyJob(response, signal, progress) {
  if (response.persistent !== true) return response; // Older server compatibility.
  const id = response.job?.id;
  if (!Number.isSafeInteger(id) || response.job.mode !== 'service-node-apply') throw new Error('Сохранение применения не подтверждено.');
  let job = response.job;
  const deadline = Date.now() + 6 * 60 * 1000;
  while (!signal.aborted) {
    progress(job.message || 'Применение выполняется на роутере. Окно можно закрыть.');
    if (job.state === 'completed') return { live_applied: true };
    if (['failed', 'canceled'].includes(job.state)) throw new Error(job.message || 'Применение не завершено.');
    if (Date.now() >= deadline) throw new Error('Задание ещё выполняется; его состояние доступно в разделе «Сервисы».');
    await new Promise(resolve => {
      const done = () => { clearTimeout(timer); signal.removeEventListener('abort', done); resolve(); };
      const timer = setTimeout(done, 1000);
      signal.addEventListener('abort', done, { once: true });
    });
    if (signal.aborted) break;
    const control = await api('/api/v1/service-control/current', { signal });
    if (signal.aborted) break;
    job = (control.durable_jobs || []).find(item => item.id === id);
    if (!job || job.mode !== 'service-node-apply') throw new Error('Результат задания сейчас недоступен. Откройте лог и обновите состояние.');
  }
  return { live_applied: false };
}

function renderNodeFeeds() {
  renderNodeSubscriptions();
}

async function syncNodeFeed(event) {
  await saveNodeSubscription(event);
}

async function saveNodeAlias(event) {
  event.preventDefault();
  const id = $('#nodeEditID').value;
  try {
    await api(`/api/v1/nodes/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify({ alias: $('#nodeEditAlias').value.trim() }) });
    $('#nodeEditDialog').close();
    await refreshNodes();
  } catch (error) { showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Название не сохранено'); }
}

async function toggleNodeDisabled(id, disabled) {
  const node = nodeByID(id);
  const next = !disabled;
  const verb = next ? 'Отключить' : 'Включить';
  if (!node || !await askConfirmation(`${verb} узел?`, next ? 'Узел останется в локальном хранилище, но будущий подбор не сможет его использовать. Рабочие маршруты сейчас не изменятся.' : 'Узел вернётся только в очередь проверки. Он не станет рабочим и не будет назначен сервисам автоматически.', verb)) return;
  try {
    await api(`/api/v1/nodes/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify({ disabled: next }) });
    await refreshNodes();
  } catch (error) { showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Состояние узла не изменено'); }
}

function clearNodeReveal() {
  $('#nodeRevealContent').value = '';
  $('#nodeRevealFeedback').textContent = '';
  if ($('#nodeRevealDialog').open) $('#nodeRevealDialog').close();
}

async function revealNode(id) {
  const node = nodeByID(id);
  if (!node || !await askConfirmation('Показать приватную конфигурацию?', 'Она может содержать UUID, пароль и адрес сервера. Показывайте её только на доверенном устройстве; данные не будут записаны в журнал панели.', 'Показать')) return;
  try {
    const result = await api(`/api/v1/nodes/${encodeURIComponent(id)}/reveal`, { method: 'POST', body: JSON.stringify({ confirm: 'REVEAL_NODE' }) });
    $('#nodeRevealTitle').textContent = nodeDisplayName(node);
    $('#nodeRevealContent').value = JSON.stringify(result.config, null, 2);
    $('#nodeRevealDialog').showModal();
  } catch (error) { showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Конфигурация не показана'); }
}

async function copyRevealedNode() {
  const field = $('#nodeRevealContent');
  if (!field.value) return;
  try {
    await navigator.clipboard.writeText(field.value);
    $('#nodeRevealFeedback').textContent = 'Скопировано';
  } catch (_) {
    field.select();
    document.execCommand('copy');
    $('#nodeRevealFeedback').textContent = 'Скопировано';
  }
}

async function deleteNode(id) {
  if(typeof workflowDelete==='function')return workflowDelete([id],'selected');
  const node = nodeByID(id);
  if (!node || !await askConfirmation('Удалить сохранённый узел?', 'Будут удалены локальная копия и её секрет. Черновик Sing-box и рабочие маршруты не меняются; при повторном импорте узел появится снова.', 'Удалить')) return;
  try {
    await api(`/api/v1/nodes/${encodeURIComponent(id)}`, { method: 'DELETE', body: JSON.stringify({ confirm: 'DELETE_NODE' }) });
    await refreshNodes();
  } catch (error) { showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Узел не удалён'); }
}

function renderConnections() {
  const payload = state.connections || {};
  const rows = payload.connections || [];
  const includeClosed = $('#showClosed').checked;
  const q = $('#connectionFilter').value.trim().toLowerCase();
  const filtered = rows.filter((c) => {
    if (!includeClosed && !c.active) return false;
    if (!q) return true;
    return [c.service_name, c.host, c.destination_ip, c.source_name, c.source_ip, c.route, ...(c.chain || [])].join(' ').toLowerCase().includes(q);
  });

  $('#activeConn').textContent = payload.live ? payload.active || 0 : '—';
  $('#closedConn').textContent = payload.live ? payload.closed || 0 : '—';
  $('#connectionCounter').textContent = payload.live ? payload.active || 0 : '—';
  $('#kpiConnections').textContent = payload.live ? payload.active || 0 : '—';
  $('#telemetryState').textContent = payload.live
    ? ((payload.active || 0) > 0 ? 'данные о маршрутах поступают' : 'источник подключён · активных соединений нет')
    : 'Наблюдение соединений недоступно. Это не означает отказ обходов.';
  $('#connectionRows').innerHTML = filtered.map((c) => {
    const chainData = c.chain && c.chain.length ? c.chain : [c.service_name || 'Unknown', routeLabel(c.route)];
    const chain = chainData.map((part) => `<span class="chain-node">${esc(part)}</span>`).join('<b class="chain-arrow">→</b>');
    const host = c.host || c.destination_ip || '—';
    const source = c.source_name || c.source_ip || '—';
    return `<tr class="${c.active ? '' : 'closed-row'}"><td><div class="chain">${chain}</div><small class="evidence">${esc(c.evidence || '')}</small></td><td><b>${esc(host)}</b>${c.destination_port ? `<small>:${esc(c.destination_port)}</small>` : ''}</td><td><span class="protocol">${esc((c.protocol || '—').toUpperCase())}</span></td><td>${esc(source)}</td><td><span class="traffic">↑ ${formatBytes(c.upload)} &nbsp; ↓ ${formatBytes(c.download)}</span></td><td>${timeAgo(c.updated_at || c.started_at)}</td></tr>`;
  }).join('');
  $('#connectionEmpty').style.display = filtered.length ? 'none' : 'grid';
  $('#connectionEmpty').querySelector('strong').textContent = !payload.live ? 'Источник наблюдения недоступен' : rows.length ? 'Нет совпадений с фильтром' : 'Сейчас нет наблюдаемых соединений';
  $('#connectionEmpty').querySelector('span').textContent = !payload.live ? 'Роутер не передаёт данные о потоках. Проверить доступ к сервису можно независимо. Подробная причина — в диагностике.' : rows.length ? 'Измените поиск или включите завершённые соединения.' : 'Источник работает. Строки появятся, когда будет наблюдаемый трафик.';
}

function deviceDisplayName(device) {
  return device.name || device.hostname || device.ips?.[0] || device.id;
}

function acceptDeviceList(payload) {
  // Array fallback keeps the panel compatible while a server is being upgraded.
  state.devices = Array.isArray(payload) ? payload : (payload.devices || []);
  state.devicePersistenceWarning = Array.isArray(payload) ? '' : (payload.persistence_warning || '');
}

function renderDevices() {
  const warning = $('#devicePersistenceWarning');
  warning.textContent = state.devicePersistenceWarning || '';
  warning.hidden = !state.devicePersistenceWarning;
  const query = ($('#deviceSearch')?.value || '').trim().toLowerCase();
  const devices = (state.devices || []).filter((device) => {
    if (!query) return true;
    return [device.name, device.hostname, device.mac, device.group, device.interface, ...(device.ips || [])].join(' ').toLowerCase().includes(query);
  });
  $('#deviceGrid').innerHTML = devices.map((device) => {
    const policies = device.policies || [];
    const selected = policies.filter((policy) => policy.scope === 'selected-device');
    const global = policies.filter((policy) => policy.scope === 'all-devices');
    const policyPreview = selected.slice(0, 4).map((policy) => `<span>${esc(policy.service_name)} → ${esc(routeLabel(policy.route))}</span>`).join('');
    return `<article class="device-card ${device.discovered ? 'online' : 'offline'}">
      <div class="device-card-head"><div class="device-icon">${esc((deviceDisplayName(device)[0] || '?').toUpperCase())}</div><div><h3>${esc(deviceDisplayName(device))}</h3><p>${esc(device.hostname && device.name ? device.hostname : device.mac || 'MAC не определён')}</p></div><span class="device-state"><i></i>${device.discovered ? 'В СЕТИ' : 'ОФЛАЙН'}</span></div>
      <div class="device-addresses">${(device.ips || []).map((ip) => `<code>${esc(ip)}</code>`).join('') || '<span>IP пока неизвестен</span>'}</div>
      <div class="device-meta"><span>Интерфейс <b>${esc(device.interface || '—')}</b></span><span>Группа <b>${esc(device.group || 'без группы')}</b></span><span>Свои политики <b>${selected.length}</b></span><span>Общие сервисы <b>${global.length}</b></span></div>
      <div class="device-policy-preview">${policyPreview || '<span>Индивидуальных областей пока нет</span>'}${selected.length > 4 ? `<small>+ ещё ${selected.length - 4}</small>` : ''}</div>
      <div class="device-actions"><button class="secondary device-edit" data-device-id="${esc(device.id)}" type="button">Имя и группа</button><button class="primary device-policy" data-device-id="${esc(device.id)}" type="button" ${(device.ips || []).length ? '' : 'disabled'}>Назначить сервис</button></div>
    </article>`;
  }).join('');
  $('#deviceEmpty').style.display = devices.length ? 'none' : 'grid';
  const groups = [...new Set((state.devices || []).map((device) => device.group).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'ru'));
  $('#deviceGroupSuggestions').innerHTML = groups.map((group) => `<option value="${esc(group)}"></option>`).join('');
}

async function refreshDevices() {
  const button = $('#refreshDevices');
  button.disabled = true; button.textContent = 'Поиск…';
  try {
    acceptDeviceList(await api('/api/v1/devices?view=status'));
    renderDevices();
  } catch (error) { showDetails({ error: error.message }, 'Устройства не обновлены'); }
  finally { button.disabled = false; button.textContent = 'Найти заново'; }
}

function openDeviceEdit(id) {
  const device = state.devices.find((item) => item.id === id);
  if (!device) return;
  $('#deviceEditID').value = device.id;
  $('#deviceEditName').value = device.name || '';
  $('#deviceEditGroup').value = device.group || '';
  $('#deviceEditTitle').textContent = deviceDisplayName(device);
  $('#deviceEditIdentity').textContent = [...(device.ips || []), device.mac].filter(Boolean).join(' · ');
  $('#deviceEditDialog').showModal();
  setTimeout(() => $('#deviceEditName').focus(), 0);
}

async function saveDeviceEdit(event) {
  event.preventDefault();
  const id = $('#deviceEditID').value;
  try {
    await api(`/api/v1/devices/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify({ name: $('#deviceEditName').value.trim(), group: $('#deviceEditGroup').value.trim() }) });
    $('#deviceEditDialog').close();
    await refreshDevices();
  } catch (error) { showDetails({ error: error.message }, 'Устройство не сохранено'); }
}

function openDevicePolicy(id) {
  const device = state.devices.find((item) => item.id === id);
  if (!device || !(device.ips || []).length) return;
  $('#devicePolicyID').value = device.id;
  $('#devicePolicyTitle').textContent = deviceDisplayName(device);
  $('#devicePolicyIdentity').textContent = (device.ips || []).join(' · ');
  $('#devicePolicyService').innerHTML = (state.services || []).map((service) => `<option value="${esc(service.id)}">${esc(service.name)}</option>`).join('');
  $('#devicePolicyScope').value = device.group ? 'group' : 'device';
  $('#devicePolicyScope').querySelector('option[value="group"]').disabled = !device.group;
  updateDevicePolicyForm();
  $('#devicePolicyDialog').showModal();
}

function updateDevicePolicyForm() {
  const device = state.devices.find((item) => item.id === $('#devicePolicyID').value);
  const service = state.services.find((item) => item.id === $('#devicePolicyService').value);
  if (!device || !service) return;
  $('#devicePolicyRoute').innerHTML = `<option value="${esc(service.route || 'auto')}">${esc(routeLabel(service.route || 'auto'))}</option>`;
  const scope = $('#devicePolicyScope').value;
  const count = scope === 'group' ? state.devices.filter((item) => item.group && item.group === device.group).length : 1;
  const globalWarning = !service.enabled
    ? 'Сервис сейчас выключен. Область сохранится отдельно и начнёт действовать только после включения сервиса на вкладке «Сервисы».'
    : service.enabled && !(service.sources || []).length
    ? 'Сейчас сервис действует на все устройства. После сохранения он будет ограничен выбранной областью.'
    : 'Существующая область этого сервиса будет заменена выбранным устройством или группой.';
  $('#devicePolicyWarning').textContent = `${globalWarning} Клиентов в новой области: ${count}. Один сервис использует один маршрут для всей своей области.`;
}

async function saveDevicePolicy(event) {
  event.preventDefault();
  const device = state.devices.find((item) => item.id === $('#devicePolicyID').value);
  const service = state.services.find((item) => item.id === $('#devicePolicyService').value);
  if (!device || !service) return;
  const members = $('#devicePolicyScope').value === 'group'
    ? state.devices.filter((item) => item.group && item.group === device.group)
    : [device];
  const sources = [...new Set(members.flatMap((item) => item.ips || []))].sort();
  if (!sources.length) { showDetails({ error: 'У выбранной области нет известных IP.' }, 'Политика не сохранена'); return; }
  const route = service.route || 'auto';
  if (!await askConfirmation('Сохранить область сервиса?', `${service.name}: область будет ограничена ${sources.length} адресом(ами). Маршрут ${routeLabel(route)} и состояние сервиса эта вкладка не изменяет.`, 'Сохранить в черновик')) return;
  try {
    await api(`/api/v1/services/${encodeURIComponent(service.id)}`, { method: 'PUT', body: JSON.stringify({ enabled: service.enabled, route, sources }) });
    $('#devicePolicyDialog').close();
    await refreshCoreAfterEdit();
    await refreshDevices();
    await showPlan();
  } catch (error) { showDetails({ error: error.message }, 'Политика не сохранена'); }
}

function renderSettingsMode() {
  const s = state.status || {};
  const known = typeof s.safe_mode === 'boolean' && !['loading', 'busy', 'error'].includes(state.dataLoad?.status?.phase);
  $('#settingSafeMode').textContent = !known ? 'Состояние уточняется' : s.safe_mode ? 'Безопасный' : 'Рабочий';
  $('#settingSafeMode').className = known && !s.safe_mode ? 'active-apply' : '';
  $('#toggleSafeMode').disabled = !known;
  $('#toggleSafeMode').textContent = !known ? 'Ожидаем состояние' : s.safe_mode ? 'Перейти в рабочий режим' : 'Включить безопасный режим';
  $('#settingPending').textContent = !known ? '—' : s.pending_changes ? 'есть' : 'нет';
  $('#settingEngineDrafts').textContent = known ? s.engine_config_drafts ?? '—' : '—';
  $('#settingApplied').textContent = known && s.last_applied_at ? new Date(s.last_applied_at).toLocaleString('ru-RU') : '—';
  $('#settingRevision').textContent = known ? `${s.revision ?? '—'} / ${s.applied_revision ?? '—'}` : '—';
}

function renderSettings() {
  const s = state.status || {};
  renderSettingsMode();
	$('#settingsUsername').textContent = s.username || 'admin';
	$('#sessionList').innerHTML = (state.sessions || []).map((session) => `<div class="session-row ${session.current ? 'current' : ''}"><div><b>${session.current ? 'Текущий браузер' : esc(session.remote_ip || 'Неизвестный адрес')}</b><span>${esc(session.user_agent || 'Клиент API')}</span><small>Активность: ${timeAgo(session.last_seen_at)} · до ${session.expires_at ? new Date(session.expires_at).toLocaleString('ru-RU') : '—'}</small></div>${session.current ? '<em>ТЕКУЩИЙ</em>' : `<button class="secondary revoke-session" data-session-id="${esc(session.id)}">Завершить</button>`}</div>`).join('') || '<div class="empty-inline">Нет активных сеансов</div>';
	$$('.revoke-session').forEach((button) => button.addEventListener('click', () => revokeSession(button.dataset.sessionId)));
}

async function toggleSafeMode() {
  if (typeof state.status?.safe_mode !== 'boolean' || ['loading', 'busy', 'error'].includes(state.dataLoad?.status?.phase)) return;
  const enable = !state.status.safe_mode;
  const title = enable ? 'Включить безопасный режим' : 'Перейти в рабочий режим';
  const message = enable
    ? 'Новые применения будут только проверяться. Уже работающие маршруты останутся без изменений.'
    : 'Следующее применение сможет изменить правила сети и маршруты. Перед записью RAZVILKA создаст снимок, проверит конфигурацию и вернёт прежнее состояние при ошибке.';
  if (!await askConfirmation(title, message, enable ? 'Включить' : 'Разрешить')) return;
  const controls = [$('#toggleSafeMode')];
  controls.forEach((button) => { button.disabled = true; });
  try {
    await api('/api/v1/settings/safe-mode', { method: 'PUT', body: JSON.stringify({ enabled: enable }) });
    await refreshCoreAfterEdit();
  } catch (error) { showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Режим не изменён'); }
  finally { renderSettingsMode(); }
}

async function refreshSessions() {
	const payload = await api('/api/v1/auth/sessions');
	state.sessions = payload.sessions || [];
	renderSettings();
}

async function changePassword(event) {
	event.preventDefault();
	const current = $('#currentPassword').value;
	const password = $('#newPassword').value;
	const repeat = $('#newPasswordRepeat').value;
	const message = $('#passwordChangeMessage');
	if (password !== repeat) { message.textContent = 'Новые пароли не совпадают.'; return; }
	message.textContent = 'Сохранение…';
	try {
		await api('/api/v1/auth/password', { method: 'PUT', body: JSON.stringify({ current_password: current, new_password: password }) });
		$('#currentPassword').value = ''; $('#newPassword').value = ''; $('#newPasswordRepeat').value = '';
		message.textContent = 'Пароль изменён. Все прежние сеансы завершены.';
		await refreshSessions();
	} catch (error) { message.textContent = error.message; }
}

async function rotateRecoveryKey(event) {
  event.preventDefault();
  const button = $('#recoveryRotateForm button[type="submit"]');
  button.disabled = true; button.textContent = 'Создание…';
  try {
    const result = await api('/api/v1/auth/recovery-key/rotate', { method: 'POST', body: JSON.stringify({ current_password: $('#recoveryRotatePassword').value }) });
    $('#recoveryRotatePassword').value = '';
    $('#recoveryKeyValue').textContent = result.recovery_key;
    $('#recoveryURLValue').textContent = result.recovery_url;
    $('#recoveryKeyResult').hidden = false;
  } catch (error) { showDetails({ error: error.message }, 'Recovery key не изменён'); }
  finally { button.disabled = false; button.textContent = 'Перевыпустить и показать'; }
}

async function copyRecoveryURL() {
  const value = $('#recoveryURLValue').textContent;
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    $('#copyRecoveryURL').textContent = 'Скопировано';
    setTimeout(() => { $('#copyRecoveryURL').textContent = 'Скопировать ссылку'; }, 1600);
  } catch (_) { showDetails(value, 'Ссылка восстановления'); }
}

async function revokeSession(id) {
	try {
		await api(`/api/v1/auth/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' });
		await refreshSessions();
	} catch (error) { showDetails({ error: error.message }, 'Завершение сеанса'); }
}

async function revokeOtherSessions() {
	try {
		const result = await api('/api/v1/auth/sessions/revoke-others', { method: 'POST', body: '{}' });
		await refreshSessions();
		showDetails(result, 'Остальные сеансы завершены');
	} catch (error) { showDetails({ error: error.message }, 'Завершение сеансов'); }
}

async function refreshCoreAfterEdit() {
  // A write can invalidate other sections of an in-flight initial snapshot.
  // Complete a fresh panel read instead of stranding those canceled sections.
  return refreshAfterMutation();
}

function openCustomServiceDialog(id = '') {
  const service = id ? state.services.find((item) => item.id === id && item.custom) : null;
  $('#customServiceEditing').value = service?.id || '';
  $('#customServiceTitle').textContent = service ? `Изменить ${service.name}` : 'Новый сервис';
  $('#customServiceName').value = service?.name || '';
  $('#customServiceID').value = service?.id?.replace(/^custom-/, '') || '';
  $('#customServiceID').disabled = !!service;
  $('#customServiceCategory').value = service?.category || 'Пользовательские';
  $('#customServiceProbe').value = service?.probe_url || '';
  $('#customServiceDescription').value = service?.description || '';
  $('#customServiceDomains').value = (service?.domains || []).join('\n');
  $('#customServiceCIDRs').value = (service?.cidrs || []).join('\n');
  $('#customServiceDialog').showModal();
  setTimeout(() => $('#customServiceName').focus(), 0);
}

function closeCustomServiceDialog() { $('#customServiceDialog').close(); }

async function openCommunityCatalog() {
  if(workflowState.communityImport){interfaceToast('Дождитесь завершения импорта.');return;}
  state.communityPreview = null;
  $('#communityPreview').innerHTML='<div class="community-empty">Выберите сервис. Загрузим его домены и покажем изменения до импорта.</div>';
  $('#r4CommunityStatus').textContent='';
  $('#communityCatalogDialog').showModal();
  $('#communitySearch').value = '';
  await searchCommunityCatalog();
  setTimeout(() => $('#communitySearch').focus(), 0);
}

function closeCommunityCatalog() { $('#communityCatalogDialog').close();workflowState.communitySeq++; }

async function searchCommunityCatalog() {
  const query=$('#communitySearch').value.trim(),seq=++workflowState.communitySeq,epoch=workflowState.epoch;
  $('#communityResults').innerHTML='<div class="community-empty">Читаем поддерживаемый каталог…</div>';
  try{
    const results=await workflowRequest(`/api/v1/community/services?q=${encodeURIComponent(query)}`);
    if(!workflowSession(epoch)||seq!==workflowState.communitySeq||!$('#communityCatalogDialog').open)return;
    state.community=Array.isArray(results)?results:[];renderCommunityResults();
  }catch(error){if(workflowSession(epoch)&&seq===workflowState.communitySeq)$('#communityResults').innerHTML=`<div class="community-empty error">${esc(workflowError(error))}</div>`;}
}

function renderCommunityResults() {
  $('#communityResults').innerHTML = state.community.map((entry) => `<button class="community-result ${state.communityPreview?.entry?.id === entry.id ? 'active' : ''}" data-community-id="${esc(entry.id)}" type="button">
    <span class="service-badge">${esc(entry.icon || '+')}</span><span><b>${esc(entry.name)}</b><small>${esc(entry.category)} · ${esc(accessLabel(entry.access?.status))}</small></span><i class="${entry.imported ? 'imported' : ''}">${entry.imported ? 'ДОБАВЛЕН' : 'PREVIEW'}</i>
  </button>`).join('') || '<div class="community-empty">Ничего не найдено. Можно добавить сервис вручную.</div>';
}

function accessLabel(status) {
  return ({ blocked: 'ограничен', throttled: 'замедляется', partial: 'частично ограничен', 'provider-limited': 'ограничен провайдером', variable: 'зависит от сети', catalog: 'по запросу' })[status] || 'статус не указан';
}

async function previewCommunityService(id, refresh = false) {
  const seq=++workflowState.communitySeq,epoch=workflowState.epoch;
  state.communityPreview=null;$('#r4CommunityStatus').textContent='';
  $('#communityPreview').innerHTML='<div class="community-empty">Получаем и разбираем доменный список. Это не проверка доступности сервиса…</div>';
  try{
    const preview=await workflowRequest(`/api/v1/community/services/${encodeURIComponent(id)}/preview${refresh?'?refresh=true':''}`,{},50000);
    if(!workflowSession(epoch)||seq!==workflowState.communitySeq||!$('#communityCatalogDialog').open)return;
    state.communityPreview=preview;renderCommunityResults();renderCommunityPreview();
  }catch(error){if(workflowSession(epoch)&&seq===workflowState.communitySeq)$('#communityPreview').innerHTML=`<div class="community-empty error"><p>Список не загружен: ${esc(workflowError(error))}</p><button class="secondary" data-community-refresh="${esc(id)}" type="button">Повторить загрузку</button></div>`;}
}

function renderCommunityPreview() {
  const preview = state.communityPreview;
  if (!preview) return;
  const service = preview.service || {};
  const entry = preview.entry || {};
  const domains = service.domains || [];
  const cidrs = service.cidrs || [];
  const conflicts = preview.conflicts || [];
  const imported = state.community.find((item) => item.id === entry.id)?.imported;
  const conflictRows = conflicts.slice(0, 12).map((item) => `<li><code>${esc(item.value)}</code><span>${esc(item.service_name)}</span></li>`).join('');
  const sourceURL = /^https:\/\//.test(entry.source_page || '') ? entry.source_page : '#';
  const evidenceURL = /^https:\/\//.test(entry.access?.evidence_url || '') ? entry.access.evidence_url : '';
  $('#communityPreview').innerHTML = `<div class="community-preview-head"><div class="service-badge">${esc(entry.icon || '+')}</div><div><h4>${esc(entry.name)}</h4><p>${esc(entry.description || '')}</p></div></div>
    <div class="community-access access-${esc(entry.access?.status || 'catalog')}"><b>${esc(accessLabel(entry.access?.status))}</b><span>${esc(entry.access?.note || 'Доступность необходимо проверить у своего провайдера.')}</span>${evidenceURL ? `<a href="${esc(evidenceURL)}" target="_blank" rel="noreferrer">Основание статуса ↗</a>` : ''}<small>Сведения каталога от ${esc(entry.access?.verified_at || 'не указано')} · регион RU</small></div>
    <div class="community-metrics"><div><b>${domains.length}</b><span>доменов</span></div><div><b>${cidrs.length}</b><span>IP/CIDR</span></div><div><b>${preview.skipped || 0}</b><span>пропущено</span></div><div class="${conflicts.length ? 'warn' : ''}"><b>${conflicts.length}</b><span>конфликтов</span></div></div>
    <div class="community-source"><span>Источник</span><b>${esc(entry.provider || '—')}</b><small>Лицензия: ${esc(entry.license || 'не указана')}</small><small>SHA-256: ${esc((preview.source_sha256 || '').slice(0, 16))}… · ${preview.from_cache ? 'cache' : 'загружено сейчас'}</small><a href="${esc(sourceURL)}" target="_blank" rel="noreferrer">Открыть страницу источника ↗</a></div>
    ${conflicts.length ? `<div class="community-conflicts"><b>Совпадения с существующими правилами</b><ul>${conflictRows}</ul>${conflicts.length > 12 ? `<small>И ещё ${conflicts.length - 12}. Импорт возможен только после подтверждения.</small>` : ''}</div>` : '<div class="community-clean">Конфликтов с текущим каталогом не найдено.</div>'}
    <details class="community-data"><summary>Показать данные (${domains.length + cidrs.length})</summary><div><b>Домены</b><pre>${esc(domains.slice(0, 80).join('\n') || '—')}</pre>${domains.length > 80 ? `<small>Показаны первые 80 из ${domains.length}</small>` : ''}<b>IP/CIDR</b><pre>${esc(cidrs.slice(0, 80).join('\n') || '—')}</pre>${cidrs.length > 80 ? `<small>Показаны первые 80 из ${cidrs.length}</small>` : ''}</div></details>
    ${consoleSnapshot?.policy?.setup_complete&&!imported?'<label class="r4-check"><input type="checkbox" id="r4CommunityManage" checked/><span>После импорта передать сервис Автопилоту с устройствами и разрешениями из мастера. Это отдельная задача проверки и применения.</span></label>':'<p class="r4-note">Импортирует только определение сервиса. Автопилот настраивается отдельно; существующий маршрут не изменяется.</p>'}
    <div class="community-preview-actions"><button class="secondary" data-community-refresh="${esc(entry.id)}" type="button">Обновить список</button><button class="primary" data-community-import="${esc(entry.id)}" type="button">${imported ? 'Обновить из источника' : 'Добавить в мои сервисы'}</button></div>`;
}

async function importCommunityService(id) {
  const preview=state.communityPreview;if(!preview||preview.entry?.id!==id||workflowState.communityImport)return;
  if(preview.import_guard!=='source-sha256'){$('#r4CommunityStatus').textContent='Сервер не подтвердил защиту импорта. Обновите приложение целиком; показанный список ещё не сохранён.';return;}
  if(!/^[a-f0-9]{64}$/.test(preview.source_sha256||'')){$('#r4CommunityStatus').textContent='Не получен отпечаток показанного источника. Повторите предпросмотр.';return;}
  const epoch=workflowState.epoch,imported=state.community.find(e=>e.id===id)?.imported,manage=$('#r4CommunityManage')?.checked===true;
  const conflicts=preview.conflicts||[];workflowState.communityImport=true;
  let saved=null;
  try{
    if(conflicts.length&&!await askConfirmation('Импортировать пересекающиеся списки?', `${conflicts.length} записей пересекаются с другими сервисами. Их маршруты не будут заменены.`, 'Импортировать'))return;
    if(imported&&!await askConfirmation('Обновить определение сервиса?','Показанные домены заменят предыдущую версию. Настройки маршрута сохраняются.','Обновить'))return;
    if(!workflowSession(epoch)||state.communityPreview!==preview||!$('#communityCatalogDialog').open)return;
    $('#r4CommunityStatus').textContent='Импортируем показанную редакцию списка…';
    $$('[data-community-import],[data-community-refresh]').forEach(b=>b.disabled=true);
    saved=await workflowRequest(`/api/v1/community/services/${encodeURIComponent(id)}/import`,{method:'POST',body:JSON.stringify({allow_conflicts:conflicts.length>0,refresh:false,expected_source_sha256:preview.source_sha256})},50000);
    if(!saved.service?.id)throw new Error('Backend не подтвердил идентификатор импортированного сервиса.');
    await refreshCoreAfterEdit();if(!workflowSession(epoch))return;
    if(manage)await interfaceManage(saved.service.id,true);
    if(!workflowSession(epoch))return;
    $('#r4CommunityStatus').textContent=manage?'Определение импортировано. Сервис передан Автопилоту; ожидается реальная проверка, маршрут ещё не подтверждён.':'Определение импортировано. Доступность и маршрут не изменялись.';
    interfaceToast(manage?'Сервис добавлен и ожидает проверки.':'Сервис добавлен в каталог.');
    // Keep the preview visible with its immutable digest and disable duplicate import.
    const entry=state.community.find(e=>e.id===id);if(entry)entry.imported=true;renderCommunityResults();
  }catch(error){if(workflowSession(epoch))$('#r4CommunityStatus').textContent=(saved?.service?.id?'Сервис уже импортирован, но дальнейшее действие не завершено. ':'Импорт не подтверждён. ')+workflowError(error);}
  finally{if(workflowSession(epoch)){workflowState.communityImport=false;$$('[data-community-refresh]').forEach(b=>b.disabled=false);if(!saved)$$('[data-community-import]').forEach(b=>b.disabled=false);}}
}

function splitResourceList(value) {
  return [...new Set(String(value || '').split(/[\s,]+/).map((item) => item.trim()).filter(Boolean))];
}

async function saveCustomService(event) {
  event.preventDefault();
  const editing = $('#customServiceEditing').value;
  const payload = {
    id: $('#customServiceID').value.trim(),
    name: $('#customServiceName').value.trim(),
    category: $('#customServiceCategory').value.trim() || 'Пользовательские',
    icon: '+',
    description: $('#customServiceDescription').value.trim(),
    domains: splitResourceList($('#customServiceDomains').value),
    cidrs: splitResourceList($('#customServiceCIDRs').value),
    strategy: ['auto'],
    probe_url: $('#customServiceProbe').value.trim(),
  };
  const submit = $('#customServiceForm button[type="submit"]'); submit.disabled = true; submit.textContent = 'Сохранение…';
  try {
    await api(editing ? `/api/v1/custom-services/${encodeURIComponent(editing)}` : '/api/v1/custom-services', { method: editing ? 'PUT' : 'POST', body: JSON.stringify(payload) });
    closeCustomServiceDialog();
    await refreshCoreAfterEdit();
  } catch (error) { showDetails({ error: error.message }, 'Сервис не сохранён'); }
  finally { submit.disabled = false; submit.textContent = 'Сохранить в каталог'; }
}

async function deleteCustomService(id) {
  const service = state.services.find((item) => item.id === id && item.custom);
  if (!service || !await askConfirmation('Удалить пользовательский сервис', `${service.name} и его желаемый маршрут будут удалены. Встроенные сервисы удалить нельзя.`, 'Удалить')) return;
  try {
    await api(`/api/v1/custom-services/${encodeURIComponent(id)}`, { method: 'DELETE' });
    await refreshCoreAfterEdit();
  } catch (error) { showDetails({ error: error.message }, 'Не удалось удалить сервис'); }
}

async function saveService(service) {
  return api(`/api/v1/services/${encodeURIComponent(service.id)}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ enabled: service.enabled, route: service.route, sources: service.sources || [] }),
  });
}

function closeServiceScope() {
  state.scopeService = null;
  $('#serviceScopeDialog').close();
}

function openServiceScope(id) {
  const service = state.services.find((item) => item.id === id);
  if (!service) return;
  state.scopeService = id;
  $('#serviceScopeTitle').textContent = `${service.name}: устройства`;
  $('#serviceScopeSources').value = (service.sources || []).join('\n');
  $('#serviceScopeMode').value = service.sources?.length ? 'selected' : 'all';
  renderServiceScopeDevices();
  $('#serviceScopeDialog').showModal();
}

function renderServiceScopeDevices() {
  const sources = $('#serviceScopeSources').value.split(/[\n,]/).map(value => value.trim()).filter(Boolean);
  const all = $('#serviceScopeMode').value === 'all';
  $('#serviceScopeDevices').hidden = all;
  $('#serviceScopeSources').disabled = all;
  $('#serviceScopeDevices').innerHTML = (state.devices || []).filter(device => device.ips?.length).map(device => {
    const checked = device.ips.every(ip => sources.includes(ip) || sources.includes(`${ip}/${ip.includes(':') ? 128 : 32}`));
    return `<label><input type="checkbox" data-service-scope-device="${esc(device.id)}" ${checked ? 'checked' : ''}><span>${esc(deviceDisplayName(device))}<small>${esc([device.group, ...device.ips].filter(Boolean).join(' · '))}</small></span></label>`;
  }).join('') || '<p>Устройства ещё не обнаружены. Можно ввести адрес вручную.</p>';
  $('#serviceScopeSummary').textContent = all ? 'После применения будет выбрана вся локальная сеть.' : sources.length ? `После применения будут выбраны: ${nodeScopeText(sources)}.` : 'Отметьте устройство или введите адрес. Пустой выбор не включает всю сеть.';
}

function changeServiceScopeDevice(event) {
  const input = event.target.closest('[data-service-scope-device]');
  const device = input && (state.devices || []).find(item => item.id === input.dataset.serviceScopeDevice);
  if (!device) return;
  let sources = $('#serviceScopeSources').value.split(/[\n,]/).map(value => value.trim()).filter(Boolean);
  for (const ip of device.ips || []) {
    const canonical = `${ip}/${ip.includes(':') ? 128 : 32}`;
    if (input.checked) { if (!sources.includes(ip) && !sources.includes(canonical)) sources.push(canonical); }
    else sources = sources.filter(source => source !== ip && source !== canonical);
  }
  $('#serviceScopeSources').value = sources.join('\n');
  renderServiceScopeDevices();
}

async function saveServiceScope(event) {
  event.preventDefault();
  const service = state.services.find((item) => item.id === state.scopeService);
  if (!service) return closeServiceScope();
  const previous = [...(service.sources || [])];
  const sources = $('#serviceScopeMode').value === 'all' ? [] : $('#serviceScopeSources').value.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
  if ($('#serviceScopeMode').value !== 'all' && !sources.length) { $('#serviceScopeSummary').textContent = 'Выберите хотя бы одно устройство или явно укажите всю локальную сеть.'; return; }
  service.sources = sources;
  const button = $('#serviceScopeForm button[type="submit"]');
  button.disabled = true; button.textContent = 'Сохранение…';
  try {
    const result = await saveService(service);
    service.sources = result.state?.sources || service.sources;
    closeServiceScope();
    await refreshCoreAfterEdit();
  } catch (error) {
    service.sources = previous;
    $('#serviceScopeSummary').textContent = error.message;
  } finally {
    button.disabled = false; button.textContent = 'Готово';
  }
}

async function toggleService(id) {
  const service = state.services.find((s) => s.id === id);
  if (!service) return;
  const previous = service.enabled;
  service.enabled = !service.enabled;
  renderServices();
  try {
    await saveService(service);
    await refreshCoreAfterEdit();
  } catch (error) {
    service.enabled = previous;
    renderServices();
    showDetails(error.payload || { error: error.message }, 'Не удалось изменить сервис');
  }
}

async function changeRoute(id, route) {
  const service = state.services.find((s) => s.id === id);
  if (!service) return;
  const previous = service.route;
  service.route = route;
  service.mode = route;
  renderServices();
  try {
    await saveService(service);
    await refreshCoreAfterEdit();
  } catch (error) {
    service.route = previous;
    service.mode = previous;
    renderServices();
    showDetails(error.payload || { error: error.message }, 'Не удалось изменить маршрут');
  }
}

function showServiceDetails(id) {
  const service = state.services.find((s) => s.id === id);
  if (service) {
    const domains = service.domains || [];
    const cidrs = service.cidrs || [];
    const sourceRefs = service.source_refs || [];
    const sourceFreshness = sourceRefs.map((sourceID) => {
      const source = (state.sources || []).find((item) => item.id === sourceID);
      const rawUpdatedAt = source?.updated_at || source?.checked_at || source?.last_success_at || '';
      const updatedAt = rawUpdatedAt && Date.parse(rawUpdatedAt) > Date.parse('2000-01-01T00:00:00Z')
        ? new Date(rawUpdatedAt).toLocaleString('ru-RU')
        : 'ещё не обновлялся';
      return {
        id: sourceID,
        status: source?.ready ? 'готов' : source ? 'требует проверки' : 'встроенный список',
        updated_at: updatedAt,
      };
    });
    showDetails({
      detail_kind: 'service-lists',
      summary: cidrs.length
        ? `Полное покрытие: ${domains.length} доменов и ${cidrs.length} IP/CIDR. Для полной IP-блокировки назначьте туннель (MASQUE, Sing-box или AmneziaWG).`
        : `Покрытие по доменам: ${domains.length}. Если приложение использует прямые IP-адреса, добавьте CIDR или назначьте туннель.`,
      desired_route: service.enabled ? routeLabel(service.route) : 'Выключен',
      planned_route: service.enabled ? routeLabel(service.planned_engine) : '—',
      applied_route: service.applied_enabled ? routeLabel(service.applied_route) : 'Выключен',
      evidence: evidenceLevelLabel(service.evidence_level),
      evidence_route: service.evidence_route ? routeLabel(service.evidence_route) : 'не определён',
      evidence_status: service.evidence_status || 'нет проверки',
      evidence_source: service.evidence_source || 'нет',
      evidence_checked_at: service.evidence_checked_at || 'не проверялось',
      domains,
      ip_and_cidr: cidrs,
      list_status: service.custom
        ? 'Пользовательский список: актуальность проверяет владелец.'
        : sourceRefs.length
          ? 'Базовые правила встроены в RAZVILKA; подключённые источники обновляются отдельно во вкладке «Источники».'
          : 'Список встроен в текущую версию RAZVILKA и обновляется вместе с приложением.',
      source_updates: sourceFreshness,
      source_refs: sourceRefs,
      devices_and_groups: service.sources || [],
    }, service.name);
  }
}

async function showServicePlan(id) {
  try {
    const plan = await api('/api/v1/plan');
    const row = (plan.routes || []).find((r) => r.service_id === id);
    showDetails(row || { service: id, note: 'Сервис выключен. Включите его для появления в предварительной проверке.' }, 'Предварительная проверка сервиса');
  } catch (error) {
    showDetails({ error: error.message }, 'Предварительная проверка завершилась ошибкой');
  }
}

async function applyDraft(scope = 'all', engineID = '', options = {}) {
  const current = () => !options.signal?.aborted && (!options.isCurrent || options.isCurrent());
  if (!current()) return null;
  let awaitingReview = false;
  const closeCanceledReview = () => { if (awaitingReview && $('#applyReviewDialog').open) $('#applyReviewDialog').close(); };
  options.signal?.addEventListener('abort', closeCanceledReview, { once: true });
  const buttons = scope === 'routing'
    ? [$('#applyChanges'), $('#applyServiceChanges'), $('#applyDeviceChanges')]
    : scope === 'services'
    ? [$('#applyServiceChanges')]
    : scope === 'devices'
    ? [$('#applyDeviceChanges')]
    : scope === 'engine'
    ? [$('#engineApplyConfig')]
    : [$('#applyChanges'), $('#applySettings')];
  const query = scope === 'all' ? '' : `?scope=${encodeURIComponent(scope)}${engineID ? `&engine=${encodeURIComponent(engineID)}` : ''}`;
  buttons.forEach((b) => { b.disabled = true; b.textContent = 'Проверка…'; });
  try {
    const preview = options.preview || await api(`/api/v1/plan${query}`, { signal: options.signal });
    if (!current()) return null;
    const review = preview.review;
    if (!Number.isSafeInteger(review?.expected_revision) || typeof review?.reviewed_digest !== 'string' || !review.reviewed_digest) throw new Error('Откройте новый просмотр изменений: подтверждение плана отсутствует.');
    const unusedDrafts = (preview.transaction?.blockers || []).filter((blocker) => blocker.code === 'ENGINE_DRAFT_UNUSED');
    if (unusedDrafts.length) {
      const names = unusedDrafts.map((blocker) => fallbackLabels[blocker.adapter] || blocker.adapter).join(', ');
      showNotice('review', 'Выберите сервис для подключения', `${names}: выберите хотя бы один включённый сервис для этого обхода либо отмените изменения. Рабочие настройки прежние.`, preview, true);
      return;
    }
    if (needsApplyReview(preview)) {
      awaitingReview = true;
      const accepted = await reviewApplyPlan(preview);
      awaitingReview = false;
      if (!accepted || !current()) return null;
    }
    if (!current()) return null;
    buttons.forEach((b) => { b.textContent = 'Применение…'; });
    const result = await api(`/api/v1/apply${query}`, { method: 'POST', signal: options.signal, body: JSON.stringify({ expected_revision: review.expected_revision, reviewed_digest: review.reviewed_digest }) });
    if (!current()) return null;
    await refreshCoreAfterEdit();
    if (!current()) return null;
    await refreshEngineConfigs(options.engineIntent || null);
    if (!current()) return null;
    await showPlan();
    if (!current()) return null;
    if (result.safe_mode && result.reviewed && !result.live_applied) {
      showNotice('review', 'План проверен — рабочие маршруты не изменены', 'Изменения подготовлены. Чтобы включить их, разрешите применение в настройках и повторите проверку.', result, true);
    } else if (result.live_applied && !result.scope_pending_changes) {
      showNotice('success', 'Настройки применены', result.note || 'Маршруты активированы, проверены и зафиксированы.', result);
    } else if (result.scope_pending_changes) {
      showNotice('review', 'Часть изменений ещё ждёт применения', 'Проверьте, что для каждого изменённого обхода выбран хотя бы один сервис.', result, true);
    } else if (result.pending_changes) {
      showNotice('success', 'Изменения этого раздела применены', 'В другом разделе остались отдельные изменения. Текущие маршруты работают.', result);
    } else {
      showNotice('success', 'Изменения обработаны', result.note || 'Операция завершена.', result);
    }
    return result;
  } catch (error) {
	if (!current()) return null;
	await showPlan();
	if (!current()) return null;
	const unused = (error.payload?.transaction?.blockers || []).filter((blocker) => blocker.code === 'ENGINE_DRAFT_UNUSED');
	if (unused.length) {
	  const names = unused.map((blocker) => fallbackLabels[blocker.adapter] || blocker.adapter).join(', ');
	  showNotice('review', 'Выберите сервис для подключения', `${names}: выберите хотя бы один сервис для этого обхода либо отмените изменения. Рабочие настройки прежние.`, error.payload, true);
	} else {
	  const failure = error.payload?.failure;
	  if (failure) {
	    showNotice('error', failure.title || 'Изменения не применены', `${failure.message || error.message} ${failure.resolution || ''}`.trim(), error.payload, true);
	  } else {
	    showNotice('error', 'Применение заблокировано', error.payload?.note || error.message, error.payload || { error: error.message }, true);
	  }
	}
  } finally {
    options.signal?.removeEventListener('abort', closeCanceledReview);
    if (current()) {
      buttons.forEach((button) => { button.disabled = false; });
      renderStatus();
      if (scope === 'engine') $('#engineApplyConfig').textContent = 'Проверить и применить';
      if (scope === 'routing' || scope === 'services') $('#applyServiceChanges').textContent = state.status.safe_mode ? 'Проверить без применения' : 'Проверить и применить';
      if (scope === 'routing' || scope === 'devices') $('#applyDeviceChanges').textContent = state.status.safe_mode ? 'Проверить без применения' : 'Проверить и применить';
    }
  }
}

async function discardDraft(scope = 'all', engineID = '') {
  const query = scope === 'all' ? '' : `?scope=${encodeURIComponent(scope)}${engineID ? `&engine=${encodeURIComponent(engineID)}` : ''}`;
  try {
    const result = await api(`/api/v1/discard${query}`, { method: 'POST' });
    await refreshCoreAfterEdit();
    if (scope !== 'routing') await refreshEngineConfigs();
    const title = scope === 'services' ? 'Изменения сервисов отменены' : scope === 'devices' ? 'Изменения областей отменены' : scope === 'routing' ? 'Изменения маршрутов отменены' : scope === 'engine' ? 'Черновик обхода удалён' : 'Черновики отменены';
    showNotice('success', title, result.discarded_engine_drafts ? `Отменено конфигураций обходов: ${result.discarded_engine_drafts}. Рабочие файлы не менялись.` : 'Желаемые маршруты возвращены к последнему применённому состоянию.', result);
  } catch (error) {
    showDetails({ error: error.message }, 'Не удалось отменить черновик');
  }
}

async function refreshSources() {
  const button = $('#refreshSources');
  button.disabled = true;
  button.textContent = 'Проверка…';
  try {
    state.sources = await api('/api/v1/sources/refresh', { method: 'POST' });
    state.status = await api('/api/v1/status');
    renderSources();
    renderStatus();
    renderReadiness();
    showDetails({ message: 'Сохранённые как используемые источники обновлены и проверены.', sources: state.sources }, 'Источники обновлены');
  } catch (error) {
    showDetails({ error: error.message }, 'Ошибка источников');
  } finally {
    button.disabled = false;
    button.textContent = 'Обновить используемые';
  }
}

async function setSourceDraft(id, enabled) {
  try {
    state.sources = await api(`/api/v1/sources/${encodeURIComponent(id)}/draft`, { method: 'POST', body: JSON.stringify({ enabled }) });
    state.status = await api('/api/v1/status');
    renderSources();
    renderStatus();
  } catch (error) {
    showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Выбор источника не сохранён');
  }
}

async function applySourceDraft() {
  const button = $('#applySourceChanges');
  button.disabled = true;
  button.textContent = 'Сохранение…';
  try {
    const result = await api('/api/v1/sources/apply', { method: 'POST', body: '{}' });
    state.sources = result.sources || await api('/api/v1/sources');
    state.status = await api('/api/v1/status');
    renderSources();
    renderStatus();
    renderReadiness();
    showNotice('success', 'Выбор источников сохранён', result.note || 'Маршруты и обходы не менялись.', result);
  } catch (error) {
    showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Источники не сохранены');
  } finally {
    button.disabled = false;
    button.textContent = 'Сохранить выбор';
  }
}

async function discardSourceDraft() {
  try {
    state.sources = await api('/api/v1/sources/discard', { method: 'POST', body: '{}' });
    state.status = await api('/api/v1/status');
    renderSources();
    renderStatus();
  } catch (error) {
    showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Изменения источников не отменены');
  }
}

async function refreshSystem() {
  try {
    state.system = await api('/api/v1/system');
    renderSystem();
    renderReadiness();
  } catch (error) {
    showDetails({ error: error.message }, 'Проверка роутера завершилась ошибкой');
  }
}

async function checkUsqueDoctor() {
  const button = $('#checkUsqueDoctor');
  button.disabled = true; button.textContent = 'Проверяем…';
  $('#usqueDoctorResult').innerHTML = '<div class="community-empty">Читаем только безопасные метаданные и проверяем доступность Cloudflare…</div>';
  try {
    const report = await api('/api/v1/diagnostics/usque', { method: 'POST', body: '{}' });
    const checks = report.checks || [];
    const readiness = report.readiness || (report.state === 'ready' ? 'READY' : report.state === 'attention' ? 'DEGRADED' : 'BLOCKED');
    const stateLabel = { READY: 'ГОТОВО', DEGRADED: 'НУЖНО ВНИМАНИЕ', BLOCKED: 'ПРОВЕРКА ЗАБЛОКИРОВАНА', UNKNOWN: 'НЕДОСТАТОЧНО ДАННЫХ' }[readiness] || 'СОСТОЯНИЕ НЕИЗВЕСТНО';
    const stateClass = readiness === 'READY' ? 'running' : readiness === 'DEGRADED' ? 'installed' : readiness === 'UNKNOWN' ? 'unknown' : '';
    const config = report.config || {};
    const versions = report.versions || {};
    const environment = report.environment || {};
    const ownership = report.ownership || {};
    const repair = report.ndmc_repair_preview || {};
    const bootstrap = report.bootstrap_readiness || {};
    const files = report.files || {};
    const lastBackup = report.last_backup || {};
    const endpoints = report.endpoints || {};
    const evidence = report.canary_evidence || {};
    const routeMatrix = report.endpoint_routes || [];
    const publicEndpoints = [endpoints.ipv4, endpoints.http2_ipv4, endpoints.ipv6, endpoints.http2_ipv6].filter(Boolean);
    const evidenceTime = evidence.checked_at ? new Date(evidence.checked_at).toLocaleString('ru-RU') : 'ещё не проверялся';
    const confirmedServices = (evidence.confirmed_routes || []).join(', ') || 'не подтверждены';
    const evidencePanel = `<div class="usque-evidence"><div><span>Технический WARP</span><b>${evidence.warp === 'on' || evidence.warp === 'plus' ? `warp=${esc(evidence.warp)}` : 'нет подтверждения'}</b><small>${esc(evidence.transport || 'транспорт не выбран')} · ${esc(evidenceTime)}</small></div><div><span>Выход Cloudflare</span><b>${esc(evidence.colo || 'POP неизвестен')}${evidence.loc ? ` · ${esc(evidence.loc)}` : ''}</b><small>${esc(evidence.egress_ip || 'IP не сохранён')}</small></div><div><span>Выбранный сервис</span><b>${esc(confirmedServices)}</b><small>Проверяется отдельно после WARP</small></div></div>`;
    const routesPanel = routeMatrix.length ? `<div class="usque-route-matrix">${routeMatrix.map((route) => `<span class="${route.dependency_loop ? 'loop' : route.expected ? 'available' : ''}"><b>${esc(route.family)}</b><small>${route.dependency_loop ? `петля через ${esc(route.interface || 'TUN')}` : route.available ? `через ${esc(route.interface || 'системный маршрут')}` : 'маршрут не найден'}</small></span>`).join('')}</div>` : '';
    const metadataPanel = `<div class="usque-metadata"><div><span>Версия пакета</span><b>${esc(versions.package || 'не определена')}</b><small>ядро: ${esc(versions.core || 'отдельно не опубликовано')} · конфиг: ${esc(versions.config || 'не указан')}</small></div><div><span>Окружение</span><b>${esc(environment.architecture || 'архитектура неизвестна')}</b><small>маршруты: ${esc(environment.route_tool || 'утилита не найдена')} · ndmc: ${esc(environment.ndmc_mode || 'не проверен')}</small></div><div><span>Владелец TUN</span><b>${ownership.runtime_owner === 'consistent-with-usque-init' ? 'согласуется со службой USQUE' : 'не подтверждён'}</b><small>${esc(ownership.interface || 'IFACE не задан')} · источник: ${esc(ownership.claimed_by || 'нет')}</small></div></div>`;
    const dnsFamilies = [bootstrap.dns_ipv4 ? 'IPv4' : '', bootstrap.dns_ipv6 ? 'IPv6' : ''].filter(Boolean).join(' + ');
    const bootstrapPanel = `<div class="usque-metadata"><div><span>До регистрации · время</span><b>${bootstrap.clock_sane ? 'готово' : 'нужно исправить'}</b><small>${esc(bootstrap.clock_utc ? new Date(bootstrap.clock_utc).toLocaleString('ru-RU') : 'не проверено')}</small></div><div><span>Корневые сертификаты</span><b>${bootstrap.ca_bundle ? 'найдены' : 'не подтверждены'}</b><small>${esc(bootstrap.ca_bundle_name || 'ca-certificates не найден')}</small></div><div><span>DNS Cloudflare</span><b>${bootstrap.dns_public_only ? 'публичные ответы' : 'не подтверждён'}</b><small>${bootstrap.dns_public_only ? `${esc(bootstrap.dns_answers || 0)} ответа · ${esc(dnsFamilies || 'семейство неизвестно')}` : esc(bootstrap.registration_host || 'API не задан')}</small></div></div>`;
    const dnsProviders = Object.fromEntries((state.dns?.providers || []).map((provider) => [provider.id, provider]));
    const candidateProfiles = (state.dns?.profiles || []).filter((profile) => {
      const provider = dnsProviders[profile.provider_id];
      return provider?.configured && provider?.allowed_for_usque_bootstrap && provider?.scope !== 'negative-control' && !provider?.trusted_local;
    });
    const preferredCandidate = candidateProfiles.find((profile) => profile.id === 'quad9-unfiltered')?.id || candidateProfiles[0]?.id || '';
    const candidateDNSPanel = candidateProfiles.length ? `<details class="transaction-details usque-repair-preview"><summary>Проверить другой DNS без применения</summary><div class="usque-doctor-note"><b>Изолированный DNS-кандидат</b><p>Проверит только имя API Cloudflare через выбранный профиль. DNS роутера, службы и черновики не изменятся.</p><div class="usque-repair-actions"><select id="usqueDNSCandidateProfile">${candidateProfiles.map((profile) => `<option value="${esc(profile.id)}" ${profile.id === preferredCandidate ? 'selected' : ''}>${esc(profile.name)}</option>`).join('')}</select><button class="secondary" id="checkUsqueDNSCandidate" type="button">Проверить DNS</button></div><div id="usqueDNSCandidateResult" class="dns-probe-results"><div class="community-empty">Проверка ещё не запускалась.</div></div><small>Публичный DNS-ответ — только первый этап. Он не доказывает TLS, регистрацию, WARP или доступность Telegram.</small></div></details>` : '';
    const repairAction = repair.needed && repair.eligible ? '<div class="usque-repair-actions"><button class="secondary" id="repairUsqueNDMC" type="button">Безопасно исправить ndmc</button><small>USQUE не будет перезапущен автоматически.</small></div>' : '';
    const repairPanel = repair.summary ? `<details class="transaction-details usque-repair-preview" ${repair.needed ? 'open' : ''}><summary>Ремонт связи с Keenetic · ${esc(repair.status || 'неизвестно')}</summary><div class="usque-doctor-note"><b>${esc(repair.needed ? 'Нужен точечный ремонт' : repair.eligible ? 'Изменения не требуются' : 'Ремонт заблокирован')}</b><p>${esc(repair.summary)}</p><small>Вызовы ndmc: ${esc(repair.ndmc_invocations ?? 0)} · уже изолированы: ${esc(repair.scoped_invocations ?? 0)}. До нажатия кнопки это только просмотр: файлы и службы не изменены.</small>${(repair.steps || []).length ? `<ol>${repair.steps.map((step) => `<li>${esc(step)}</li>`).join('')}</ol>` : ''}${(repair.blockers || []).length ? `<p class="danger-text">${repair.blockers.map(esc).join(' · ')}</p>` : ''}${repairAction}</div></details>` : '';
    const fileRows = Object.entries(files).map(([kind, file]) => `<div><b>${esc({ config: 'Конфигурация', session: 'Сессия', binary: 'Бинарник', init: 'Запуск' }[kind] || kind)}</b><span>${file.present ? `${esc(file.name || 'файл')} · права ${esc(file.mode || 'неизвестны')}${file.owner_uid ? ` · UID ${esc(file.owner_uid)}` : ''}` : 'не найден'}</span><small>${file.modified_at ? new Date(file.modified_at).toLocaleString('ru-RU') : 'дата неизвестна'}${file.sha256 ? ` · SHA-256 ${esc(file.sha256.slice(0, 12))}…` : ''}</small></div>`).join('');
    const filesPanel = `<details class="transaction-details usque-file-facts"><summary>Файлы и резервная копия</summary><div class="usque-file-grid">${fileRows || '<span>Метаданные файлов недоступны.</span>'}${lastBackup.present ? `<div><b>Последняя резервная копия</b><span>${esc(lastBackup.name || 'backup')} · права ${esc(lastBackup.mode || 'неизвестны')}</span><small>${esc(lastBackup.modified_at ? new Date(lastBackup.modified_at).toLocaleString('ru-RU') : '')}${lastBackup.sha256 ? ` · SHA-256 ${esc(lastBackup.sha256.slice(0, 12))}…` : ''}</small></div>` : '<div><b>Резервная копия</b><span>не найдена в известных каталогах</span><small>Doctor ничего не создаёт автоматически</small></div>'}</div></details>`;
    $('#usqueDoctorResult').innerHTML = `<div class="usque-doctor-head"><div><span class="engine-state ${stateClass}">${esc(stateLabel)}</span><h3>${esc(config.transport || 'USQUE')} · ${esc(config.sni || 'SNI по умолчанию')}</h3><p>${esc(config.interface || 'интерфейс не определён')}${report.endpoint_route_interface ? ` · IPv4 endpoint через ${esc(report.endpoint_route_interface)}` : ''}</p></div><small>${esc(report.checked_at ? new Date(report.checked_at).toLocaleString('ru-RU') : '')}</small></div>${bootstrapPanel}${candidateDNSPanel}${metadataPanel}${evidencePanel}${routesPanel}<div class="usque-check-grid">${checks.map((check) => `<div class="usque-check ${esc(check.status)}"><span>${check.status === 'pass' ? '✓' : check.status === 'warning' ? '!' : check.status === 'skipped' ? '–' : '×'}</span><div><b>${esc(check.label)}</b><p>${esc(check.message)}</p>${check.action ? `<small>${esc(check.action)}</small>` : ''}</div></div>`).join('')}</div>${repairPanel}${publicEndpoints.length ? `<details class="transaction-details"><summary>Публичные endpoints (${publicEndpoints.length})</summary><code>${publicEndpoints.map(esc).join('\n')}</code></details>` : ''}${filesPanel}<div class="usque-doctor-note">${esc(report.note || '')} Совпадение init-скрипта и TUN — полезный признак, но не доказательство владельца процесса. Исправный WARP также не считается доказательством доступности Telegram: эти результаты показаны отдельно.</div>`;
    $('#repairUsqueNDMC')?.addEventListener('click', repairUsqueNDMC);
    $('#checkUsqueDNSCandidate')?.addEventListener('click', checkUsqueDNSCandidate);
    $('#usqueDNSCandidateProfile')?.setAttribute('aria-label', 'DNS для отдельной проверки регистрации USQUE');
    $('#usqueDNSCandidateResult')?.setAttribute('aria-live', 'polite');
  } catch (error) {
    $('#usqueDoctorResult').innerHTML = `<div class="community-empty error">Проверка USQUE не выполнена: ${esc(error.message)}</div>`;
  } finally {
    button.disabled = false; button.textContent = 'Проверить снова';
  }
}

async function checkUsqueDNSCandidate(event) {
  const button = event.currentTarget;
  if (button.disabled) return;
  const selector = $('#usqueDNSCandidateProfile');
  const profileID = selector?.value || '';
  const target = $('#usqueDNSCandidateResult');
  if (!profileID || !target) return;
  button.disabled = true;
  selector.disabled = true;
  button.textContent = 'Проверяем…';
  target.innerHTML = '<div class="community-empty">Запрашиваем имя Cloudflare только через выбранный DNS…</div>';
  try {
    const result = await api('/api/v1/diagnostics/usque/dns-candidate', { method: 'POST', body: JSON.stringify({ profile_id: profileID }) });
    target.innerHTML = (result.results || []).map((item) => `<div class="dns-probe-row"><span class="state-dot ${item.status === 'pass' ? 'good' : 'bad'}"></span><div><b><span class="dns-transport">${esc(item.transport || 'DNS')}</span>${esc(item.server || '')}</b><small>${item.status === 'pass' ? `${Number(item.latency_ms || 0)} мс · публичных адресов: ${Number(item.addresses || 0)} · ${item.ipv4 ? 'IPv4' : ''}${item.ipv4 && item.ipv6 ? ' + ' : ''}${item.ipv6 ? 'IPv6' : ''}` : esc(item.error || 'нет ответа')}</small></div></div>`).join('') || '<div class="community-empty">DNS-профиль не вернул проверяемых результатов.</div>';
  } catch (error) {
    target.innerHTML = `<div class="community-empty error">${esc(error.message)}</div>`;
  } finally {
    button.disabled = false;
    selector.disabled = false;
    button.textContent = 'Проверить DNS';
  }
}

async function repairUsqueNDMC(event) {
  const button = event.currentTarget;
  const confirmed = await askConfirmation(
    'Исправить связь USQUE с Keenetic?',
    'RAZVILKA создаст закрытую резервную копию и изменит только однозначные вызовы ndmc. Затем проверит синтаксис и связь с Keenetic; при любой ошибке исходный файл вернётся автоматически. Служба USQUE не перезапускается.',
    'Создать копию и исправить',
  );
  if (!confirmed) return;
  button.disabled = true;
  button.textContent = 'Проверяем и исправляем…';
  try {
    const result = await api('/api/v1/diagnostics/usque/repair', {
      method: 'POST',
      body: JSON.stringify({ confirm: 'REPAIR_USQUE_NDMC' }),
    });
    showNotice('success', 'Ремонт USQUE завершён', result.message || 'Изменение проверено; служба USQUE не перезапускалась.', result);
    await checkUsqueDoctor();
  } catch (error) {
    showDetails({ error: error.message, technical: error.technicalMessage || '', note: 'Рабочая служба USQUE не перезапускалась. При ошибке применяется автоматический откат.' }, 'Ремонт USQUE не выполнен');
    await checkUsqueDoctor();
  }
}

async function inspectDomain() {
  const query = $('#domainInspectorInput').value.trim();
  if (!query) return;
  const button = $('#inspectDomain'); button.disabled = true; button.textContent = 'Разбор…';
  $('#domainInspectorResult').innerHTML = '<div class="community-empty">Поиск точного домена, суффикса и CIDR во всех каталогах…</div>';
  try {
    const result = await api(`/api/v1/diagnostics/domain?q=${encodeURIComponent(query)}`);
    const matches = result.matches || [];
    if (!matches.length) {
      $('#domainInspectorResult').innerHTML = `<div class="community-empty">Для <b>${esc(result.normalized)}</b> правило не найдено. Добавьте сервис вручную или через Community-каталог.</div>`;
      return;
    }
    $('#domainInspectorResult').innerHTML = `<div class="domain-inspector-summary ${result.conflict ? 'conflict' : ''}"><div><span>Проверенный адрес</span><b>${esc(result.normalized)}</b></div><div><span>Совпадений</span><b>${matches.length}</b></div><div><span>Конфликт</span><b>${result.conflict ? 'ДА — проверьте приоритет' : 'нет'}</b></div><div><span>Фактический маршрут</span><b>${result.live_route_confirmed ? 'подтверждён' : 'не подтверждён'}</b></div></div><div class="domain-match-list">${matches.map((match, index) => `<div class="domain-match ${index === 0 ? 'candidate' : ''}"><span class="service-badge">${index + 1}</span><div><b>${esc(match.service_name)}</b><small>${esc(match.service_id)} · правило <code>${esc(match.matched_rule)}</code>${match.custom ? ' · пользовательский' : ''}</small></div><div><span>${match.enabled ? 'ВКЛЮЧЁН' : 'ВЫКЛЮЧЕН'}</span><b>${esc(match.selected_route)} → ${esc(match.resolved_route)}</b><small>применён: ${match.applied_enabled ? esc(match.applied_route) : 'выключен'}</small></div></div>`).join('')}</div><small class="domain-note">${esc(result.note)}</small>`;
  } catch (error) { $('#domainInspectorResult').innerHTML = `<div class="community-empty error">${esc(error.message)}</div>`; }
  finally { button.disabled = false; button.textContent = 'Разобрать'; }
}

async function showPlan() {
  if (nodeActivityActive()) return;
  try {
    const plan = await api('/api/v1/plan');
    const tx = plan.transaction || {};
    const blockers = tx.blockers || [];
    const warnings = tx.warnings || [];
    const actions = tx.actions || [];
    const routes = tx.routes || [];
    const routeEvidence = tx.route_evidence || [];
    const stateLabel = tx.noop ? 'ИЗМЕНЕНИЯ НЕ НУЖНЫ' : tx.ready ? 'ГОТОВО К ПРИМЕНЕНИЮ' : 'ПРИМЕНЕНИЕ ЗАБЛОКИРОВАНО';
    const stateClass = tx.noop || tx.ready ? 'ready' : 'blocked';
    const phaseLabels = { snapshot: 'Снимок', stage: 'Подготовка', validate: 'Проверка', canary: 'Пробный запуск', activate: 'Активация', health: 'Проверка доступности', commit: 'Сохранение' };
    const planState = tx.safe_mode ? 'БЕЗОПАСНЫЙ РЕЖИМ' : ({ planned: 'ПЛАН', reviewed: 'ПРОВЕРЕНО', ready: 'ГОТОВО', committed: 'ПРИМЕНЕНО', 'canary-failed': 'ПРОБНЫЙ ЗАПУСК НЕ ПРОЙДЕН' }[tx.state] || tx.state || 'ПЛАН');
    const requiredEvidence = String(tx.required_evidence || 'none');
    const observedEvidence = String(tx.observed_evidence || 'none');
    const evidenceReady = evidenceAtLeast(observedEvidence, requiredEvidence);
    const evidencePanel = `<div class="transaction-evidence ${evidenceReady ? 'confirmed' : ''}"><div><span>Нужно для подтверждения</span><b>${esc(evidenceLevelLabel(requiredEvidence))}</b></div><i>→</i><div><span>Наблюдается сейчас</span><b>${esc(evidenceLevelLabel(observedEvidence))}</b></div><p>${esc(tx.evidence_note || 'План не является доказательством работы маршрута.')}</p></div>`;
    $('#planBox').innerHTML = `<div class="transaction-head"><div><span class="eyebrow">ПЛАН ${esc(tx.plan_id || '—')}</span><h3>${esc(stateLabel)}</h3><p>${esc(tx.note || plan.note || '')}</p></div><span class="transaction-state ${stateClass}">${esc(planState)}</span></div><div class="transaction-metrics"><div><b>${routes.length}</b><span>маршрутов</span></div><div><b>${(tx.adapters || []).length}</b><span>обходов</span></div><div><b>${actions.length}</b><span>шагов</span></div><div><b>${blockers.length}</b><span>проблем</span></div></div>${evidencePanel}${blockers.length ? `<div class="transaction-blockers"><h4>Что мешает применению</h4>${blockers.map((item) => `<div class="transaction-blocker"><span>${esc(item.code)}</span><div><b>${item.adapter ? `${esc(item.adapter)} · ` : ''}${esc(item.message)}</b>${item.resolution ? `<small>${esc(item.resolution)}</small>` : ''}</div></div>`).join('')}</div>` : '<div class="transaction-clean">Все обязательные проверки конфигурации пройдены. Доступ подтверждается отдельным health-check.</div>'}${warnings.length ? `<details class="transaction-details"><summary>Предупреждения (${warnings.length})</summary>${warnings.map((item) => `<div class="transaction-warning"><b>${item.adapter ? `${esc(item.adapter)} · ` : ''}${esc(item.code)}</b><span>${esc(item.message)}</span></div>`).join('')}</details>` : ''}<div class="transaction-flow">${actions.map((item) => `<div class="transaction-step"><span>${item.order}</span><div><b>${esc(phaseLabels[item.phase] || item.phase)} · ${esc(item.adapter)}</b><small>${esc(item.summary)}</small><code>${esc(item.target)}</code></div><i class="${item.razvilka_owned ? 'owned' : ''}">${item.razvilka_owned ? 'RAZVILKA' : 'ВНЕШНИЙ'}</i></div>`).join('') || '<div class="transaction-clean">Прямые маршруты не требуют изменения сетевых правил.</div>'}</div><details class="transaction-details"><summary>Маршруты (${routes.length}) и контрольная сумма</summary><div class="transaction-routes">${routes.map((route) => { const proof = routeEvidence.find((item) => item.service_id === route.service_id && item.route === route.resolved_route); return `<div><b>${esc(route.service_name)}</b><span>${esc(route.selected_route)} → ${esc(route.resolved_route)} · ${esc(evidenceLevelLabel(proof?.observed_evidence))}</span></div>`; }).join('') || '<span>Нет включённых сервисов.</span>'}</div><code class="transaction-digest">${esc(tx.digest || '—')}</code></details>`;
  } catch (error) {
    $('#planBox').innerHTML = `<div class="transaction-error">План не построен: ${esc(error.message)}</div>`;
  }
}

async function exportConfig() {
  try {
    const data = await api('/api/v1/config/export');
    downloadJSON(data, `razvilka-config-${timestampName()}.json`);
  } catch (error) {
    showDetails({ error: error.message }, 'Ошибка экспорта');
  }
}

async function downloadDiagnostics() {
  try {
    const report = await api('/api/v1/diagnostics/report');
    downloadJSON(report, `razvilka-diagnostic-${timestampName()}.json`);
    showDetails({ digest: report.digest, version: report.app_version, privacy_omissions: report.privacy_omissions }, 'Диагностический отчёт создан');
  } catch (error) {
    showDetails({ error: error.message }, 'Отчёт не создан');
  }
}

async function checkAppUpdate() { return refreshAppUpdate(true); }

function renderAppUpdate() { renderAppUpdatePanel(); }

function timestampName() { return new Date().toISOString().replace(/[:.]/g, '-'); }

function downloadJSON(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = filename;
  document.body.appendChild(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(url);
}

async function exportProfile() {
  const button = $('#exportProfile');
  button.disabled = true; button.textContent = 'Сбор профиля…';
  try {
    const query = new URLSearchParams({
      name: $('#profileName').value.trim() || 'Мой профиль RAZVILKA',
      author: $('#profileAuthor').value.trim(),
      description: $('#profileDescription').value.trim(),
    });
    const bundle = await api(`/api/v1/profiles/export?${query}`);
    downloadJSON(bundle, `razvilka-profile-${timestampName()}.json`);
    const omitted = (bundle.sensitive_omitted || []).length;
    showDetails({ profile: bundle.name, digest: bundle.digest, services: Object.keys(bundle.services || {}).length, custom_services: (bundle.custom_services || []).length, engine_files: (bundle.engine_files || []).length, sensitive_omitted: omitted, contains_secrets: bundle.contains_secrets }, 'Безопасный профиль создан');
  } catch (error) { showDetails({ error: error.message }, 'Профиль не создан'); }
  finally { button.disabled = false; button.textContent = 'Скачать безопасный профиль'; }
}

async function selectProfileFile(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  if (file.size > 8 * 1024 * 1024) { showDetails({ error: 'Файл больше 8 МБ.' }, 'Профиль не принят'); return; }
  $('#profilePreview').innerHTML = '<div class="community-empty">Проверка схемы, SHA-256, сервисов и engine-файлов…</div>';
  $('#confirmProfileImport').disabled = true;
  try {
    const bundle = JSON.parse(await file.text());
    const preview = await api('/api/v1/profiles/preview', { method: 'POST', body: JSON.stringify(bundle) });
    state.profileBundle = bundle; state.profilePreview = preview;
    renderProfilePreview();
  } catch (error) {
    state.profileBundle = null; state.profilePreview = null;
    $('#profilePreview').innerHTML = `<div class="community-empty error">Профиль отклонён: ${esc(error.message)}</div>`;
  }
}

function renderProfilePreview() {
  const preview = state.profilePreview;
  if (!preview) return;
  const changes = preview.service_changes || [];
  const changed = changes.filter((item) => item.action !== 'unchanged');
  const warnings = preview.warnings || [];
  const engines = preview.engine_files || [];
  $('#profilePreview').innerHTML = `<div class="profile-preview-head"><div><span class="eyebrow">ПРОВЕРЕНО</span><h3>${esc(preview.name)}</h3><p>${preview.author ? `Автор: ${esc(preview.author)} · ` : ''}RAZVILKA ${esc(preview.from_version || '—')}</p></div><span class="engine-state installed">SHA-256 OK</span></div><div class="community-metrics"><div><b>${changes.length}</b><span>настроек</span></div><div><b>${changed.length}</b><span>изменений</span></div><div><b>${preview.custom_added || 0}</b><span>новых сервисов</span></div><div><b>${engines.length}</b><span>engine-файлов</span></div></div>${preview.custom_updated ? `<div class="profile-warning">Будут обновлены пользовательские сервисы: ${preview.custom_updated}. Потребуется отдельное подтверждение.</div>` : ''}${warnings.map((warning) => `<div class="profile-warning">${esc(warning)}</div>`).join('')}<details><summary>Изменения сервисов (${changed.length})</summary><div class="profile-change-list">${changed.slice(0, 80).map((item) => `<div><b>${esc(item.id)}</b><span>${esc(item.enabled_before ? 'вкл' : 'выкл')} / ${esc(item.route_before)} → ${esc(item.enabled_after ? 'вкл' : 'выкл')} / ${esc(item.route_after)}</span></div>`).join('') || '<span>Состояния сервисов уже совпадают.</span>'}</div></details><small class="profile-digest">${esc(preview.digest)}</small>`;
  $('#confirmProfileImport').disabled = !preview.valid;
}

async function importProfile() {
  const bundle = state.profileBundle;
  const preview = state.profilePreview;
  if (!bundle || !preview?.valid) return;
  const allowUpdates = !!preview.requires_custom_update_approval;
  const text = `Профиль «${preview.name}» будет добавлен только в черновик. Рабочие маршруты и секретные конфиги не изменятся.${allowUpdates ? ' Существующие пользовательские сервисы будут обновлены.' : ''}`;
  if (!await askConfirmation('Импортировать проверенный профиль?', text, 'Импортировать в черновик')) return;
  const button = $('#confirmProfileImport'); button.disabled = true; button.textContent = 'Импорт…';
  try {
    const result = await api('/api/v1/profiles/import', { method: 'POST', body: JSON.stringify({ bundle, allow_custom_updates: allowUpdates }) });
    state.profileBundle = null; state.profilePreview = null;
    $('#profilePreview').innerHTML = '<div class="community-clean">Профиль импортирован в черновик. Проверьте план и файлы обходов перед применением.</div>';
    await refreshAfterMutation(); await showPlan();
    showDetails(result, 'Профиль импортирован');
  } catch (error) { showDetails({ error: error.message }, 'Импорт профиля не выполнен'); renderProfilePreview(); }
  finally { button.textContent = 'Импортировать в черновик'; button.disabled = !state.profilePreview?.valid; }
}

async function exportPrivateBackup() {
  const password = $('#privateBackupPassword').value;
  const repeat = $('#privateBackupPasswordRepeat').value;
  if (password.length < 12) { showDetails({ error: 'Пароль должен содержать минимум 12 символов.' }, 'Резервная копия не создана'); return; }
  if (password !== repeat) { showDetails({ error: 'Пароли архива не совпадают.' }, 'Резервная копия не создана'); return; }
  const button = $('#exportPrivateBackup'); button.disabled = true; button.textContent = 'Шифрование…';
  try {
    const envelope = await api('/api/v1/private-backups/export', { method: 'POST', body: JSON.stringify({ password }) });
    downloadJSON(envelope, `razvilka-private-${timestampName()}.json`);
    $('#privateBackupPassword').value = ''; $('#privateBackupPasswordRepeat').value = '';
    showDetails({ cipher: envelope.cipher, kdf: envelope.kdf, iterations: envelope.iterations, created_at: envelope.created_at }, 'Приватная резервная копия создана');
  } catch (error) {
    const sourceError = ['PRIVATE_BACKUP_ENGINE_INVALID', 'PRIVATE_BACKUP_ENGINE_UNREADABLE'].includes(error.payload?.code) && typeof error.payload?.error === 'string';
    showDetails({ error: sourceError ? error.payload.error : error.message }, 'Резервная копия не создана');
  }
  finally { button.disabled = false; button.textContent = 'Скачать зашифрованную копию'; }
}

async function selectPrivateBackupFile(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  state.privateBackupEnvelope = null; state.privateBackupPreview = null;
  $('#confirmPrivateBackup').disabled = true;
  if (!file) return;
  if (file.size > 18 * 1024 * 1024) { showDetails({ error: 'Файл больше 18 МБ.' }, 'Резервная копия не принята'); return; }
  try {
    const envelope = JSON.parse(await file.text());
    if (envelope.kind !== 'razvilka-private-backup' || !envelope.ciphertext) throw new Error('Это не приватная резервная копия RAZVILKA.');
    state.privateBackupEnvelope = envelope;
    $('#previewPrivateBackup').disabled = false;
    $('#privateBackupPreview').innerHTML = `<div class="community-empty">Выбран архив ${esc(file.name)}. Введите пароль и запустите проверку.</div>`;
  } catch (error) {
    $('#previewPrivateBackup').disabled = true;
    $('#privateBackupPreview').innerHTML = `<div class="community-empty error">${esc(error.message)}</div>`;
  }
}

async function previewPrivateBackup() {
  const envelope = state.privateBackupEnvelope;
  const password = $('#privateBackupImportPassword').value;
  if (!envelope || password.length < 12) { showDetails({ error: 'Выберите архив и введите его пароль.' }, 'Предварительный просмотр недоступен'); return; }
  const button = $('#previewPrivateBackup'); button.disabled = true; button.textContent = 'Проверка…';
  try {
    const preview = await api('/api/v1/private-backups/preview', { method: 'POST', body: JSON.stringify({ envelope, password }) });
    state.privateBackupPreview = preview;
    const warnings = preview.warnings || [];
    $('#privateBackupPreview').innerHTML = `<div class="private-backup-ok"><span class="engine-state installed">ШИФРОВАНИЕ И ЦЕЛОСТНОСТЬ ПРОВЕРЕНЫ</span><h3>Резервная копия RAZVILKA ${esc(preview.from_version)}</h3><p>${preview.created_at ? new Date(preview.created_at).toLocaleString('ru-RU') : '—'}</p><div class="private-backup-metrics"><div><b>${preview.services || 0}</b><span>сервисов</span></div><div><b>${preview.engine_files?.length || 0}</b><span>конфигов</span></div><div><b>${preview.sensitive_files || 0}</b><span>секретных</span></div><div><b>${preview.custom_services || 0}</b><span>пользовательских</span></div><div><b>${preview.devices || 0}</b><span>устройств</span></div><div><b>${preview.nodes || 0}</b><span>узлов</span></div><div><b>${preview.node_groups || 0}</b><span>групп узлов</span></div><div><b>${preview.subscriptions || 0}</b><span>подписок · на паузе</span></div><div><b>черновик</b><span>режим</span></div></div>${warnings.map((warning) => `<div class="private-backup-warning">${esc(warning)}</div>`).join('')}<details><summary>Технические сведения</summary><div class="private-backup-digest">${esc(preview.digest)}</div></details></div>`;
    $('#confirmPrivateBackup').disabled = !preview.valid;
  } catch (error) {
    state.privateBackupPreview = null;
    $('#confirmPrivateBackup').disabled = true;
    $('#privateBackupPreview').innerHTML = `<div class="community-empty error">Архив не принят: ${esc(error.message)}</div>`;
  } finally { button.disabled = false; button.textContent = 'Расшифровать и проверить'; }
}

async function importPrivateBackup() {
  if (!state.privateBackupEnvelope || !state.privateBackupPreview?.valid) return;
  if (!await askConfirmation('Импортировать приватную резервную копию?', 'Сервисы, устройства и все конфиги обходов, включая ключи, попадут только в черновик. Рабочие маршруты, пароль панели и ключ восстановления не изменятся.', 'Импортировать в черновик')) return;
  const button = $('#confirmPrivateBackup'); button.disabled = true; button.textContent = 'Импорт…';
  let committed = false;
  try {
    const result = await api('/api/v1/private-backups/import', { method: 'POST', body: JSON.stringify({ envelope: state.privateBackupEnvelope, password: $('#privateBackupImportPassword').value, confirm: 'IMPORT_PRIVATE_BACKUP' }) });
    committed = true;
    state.privateBackupEnvelope = null; state.privateBackupPreview = null;
    $('#privateBackupImportPassword').value = '';
    $('#previewPrivateBackup').disabled = true;
    $('#privateBackupPreview').innerHTML = '<div class="community-clean">Настройки восстановлены в черновик. Подписки поставлены на паузу; возобновите нужные в разделе VLESS и VPN → Подписки. Проверьте устройства и маршруты перед применением.</div>';
    await refreshAfterMutation(); await showPlan();
    showDetails(result, 'Приватная резервная копия импортирована');
  } catch (error) {
    // A failed/uncertain import invalidates the old preview. Never leave its
    // password or a one-click retry armed after an incomplete rollback.
    state.privateBackupEnvelope = null; state.privateBackupPreview = null;
    $('#privateBackupImportPassword').value = '';
    $('#previewPrivateBackup').disabled = true;
    const response = error.payload || {};
    const message = committed
      ? 'Импорт выполнен, но панель не удалось обновить. Обновите страницу перед дальнейшими действиями.'
      : response.recovery_required === true
        ? 'Восстановление остановлено. Изменения приостановлены до проверки журнала при следующем запуске приложения. Не удаляйте журнал и не применяйте черновики вручную.'
      : response.not_started === true
        ? 'Импорт не начат: операция занята, отменена или хранилища не готовы. Настройки не изменены. После устранения причины выберите и проверьте архив заново.'
        : response.rolled_back === true
          ? 'Восстановление не завершено. Изменения этой операции отменены. Для повторной попытки выберите и проверьте архив заново.'
          : 'Не удалось подтвердить результат восстановления. Обновите страницу и проверьте черновики. Не повторяйте импорт вслепую.';
    $('#privateBackupPreview').innerHTML = `<div class="community-empty error">${esc(message)}</div>`;
    showDetails({ error: message, code: response.code || '', phase: response.phase || '' }, committed ? 'Импорт выполнен — обновите панель' : 'Проверьте результат восстановления');
  }
  finally { button.textContent = 'Импортировать приватные данные в черновик'; button.disabled = !state.privateBackupPreview?.valid; }
}

async function refreshConnections() {
  try {
    state.connections = await api('/api/v1/connections?include_closed=true');
    renderConnections();
  } catch (_) {
    // SSE or next refresh will recover. Do not spam the UI on transient failures.
  }
}

function startConnectionStream() {
  if (!window.EventSource || state.stream) return;
  const stream = new EventSource('/api/v1/connections/stream');
  state.stream = stream;
  stream.addEventListener('connections', (event) => {
    try {
      const payload = JSON.parse(event.data);
      const live = Array.isArray(payload) ? payload : (payload.connections || []);
      const closed = (state.connections.connections || []).filter((c) => !c.active);
      state.connections.connections = [...live, ...closed];
      state.connections.active = live.length;
      if (!Array.isArray(payload)) {
        state.connections.live = !!payload.live;
        state.connections.producer = payload.producer || '';
        state.connections.reason = payload.reason || '';
      }
      renderConnections();
    } catch (_) {
      // Ignore malformed one-off events; REST refresh remains fallback.
    }
  });
  stream.onerror = () => {
    $('#telemetryState').textContent = 'соединение восстанавливается…';
  };
}

function bindEvents() {
  bindNodeBrowser();
  bindServiceDashboard();
  if (typeof bindWorkspaceControls === 'function') bindWorkspaceControls();
  if (typeof bindAppUpdateUI === 'function') bindAppUpdateUI();
  window.addEventListener('beforeunload', (event) => {
    if (!state.engineEditorDirty && !state.warpPolicyDirty) return;
    event.preventDefault();
    event.returnValue = '';
  });
  $$('[data-view]').forEach((button) => button.addEventListener('click', () => setView(button.dataset.view)));
  $$('[data-service-mode]').forEach((button) => button.addEventListener('click', () => setServiceMode(button.dataset.serviceMode)));
  $('#serviceSearch').addEventListener('input', renderServices);
  $('#serviceCategory').addEventListener('change', renderServices);
  $('#connectionFilter').addEventListener('input', renderConnections);
  $('#showClosed').addEventListener('change', renderConnections);
  $('#nodeSearch').addEventListener('input', renderNodes);
  $('#nodeStateFilter').addEventListener('change', renderNodes);
  $('#refreshNodes').addEventListener('click', refreshNodes);
  $('#nodeOpenImport').addEventListener('click', openQuickNodeImport);
  $('#nodeOpenGroup').addEventListener('click', () => openNodeGroup());
  $('#nodeList').addEventListener('click', (event) => {
    const check = event.target.closest('[data-node-check]');
    const edit = event.target.closest('[data-node-edit]');
    const disable = event.target.closest('[data-node-disable]');
    const reveal = event.target.closest('[data-node-reveal]');
    const remove = event.target.closest('[data-node-delete]');
    if (check) openNodeCheck(check.dataset.nodeCheck);
    else if (edit) openNodeEdit(edit.dataset.nodeEdit);
    else if (disable) toggleNodeDisabled(disable.dataset.nodeDisable, disable.dataset.disabled === 'true');
    else if (reveal) revealNode(reveal.dataset.nodeReveal);
    else if (remove) deleteNode(remove.dataset.nodeDelete);
  });
  $('#nodeEditForm').addEventListener('submit', saveNodeAlias);
  $('#nodeEditClose').addEventListener('click', () => $('#nodeEditDialog').close());
  $('#nodeEditCancel').addEventListener('click', () => $('#nodeEditDialog').close());
  $('#nodeGroupForm').addEventListener('submit', saveNodeGroup);
  $('#nodeGroupClose').addEventListener('click', () => $('#nodeGroupDialog').close());
  $('#nodeGroupCancel').addEventListener('click', () => $('#nodeGroupDialog').close());
  $('#nodeCheckForm').addEventListener('submit', runNodeCheck);
  $('#nodeCheckClose').addEventListener('click', closeNodeCheck);
  $('#nodeCheckCancel').addEventListener('click', closeNodeCheck);
  $('#nodeCheckDialog').addEventListener('cancel', (event) => { event.preventDefault(); closeNodeCheck(); });
  $('#nodeCheckService').addEventListener('change', updateNodeCheckSelection);
  $('#nodeCheckPreview').addEventListener('click', previewNodeRoute);
  $('#nodeRouteApply').addEventListener('click', applyNodeRoute);
  $('#nodeRouteClose').addEventListener('click', closeNodeRoute);
  $('#nodeRouteCancel').addEventListener('click', closeNodeRoute);
  $('#nodeRouteDialog').addEventListener('cancel', (event) => { event.preventDefault(); closeNodeRoute(); });
  $('#nodeFeedPreset').addEventListener('change', () => { $('#nodeFeedCustom').hidden = $('#nodeFeedPreset').value !== 'custom'; });
  $('#nodeFeedForm').addEventListener('submit', syncNodeFeed);
  $('#nodeFeedCancel').addEventListener('click', () => state.nodeFeedController?.abort());
  $('#nodeRevealClose').addEventListener('click', clearNodeReveal);
  $('#nodeRevealDone').addEventListener('click', clearNodeReveal);
  $('#nodeRevealCopy').addEventListener('click', copyRevealedNode);
  $('#nodeRevealDialog').addEventListener('close', () => { $('#nodeRevealContent').value = ''; $('#nodeRevealFeedback').textContent = ''; });
  $('#deviceSearch').addEventListener('input', renderDevices);
  $('#refreshDevices').addEventListener('click', refreshDevices);
  $('#deviceGrid').addEventListener('click', (event) => {
    const edit = event.target.closest('.device-edit');
    const policy = event.target.closest('.device-policy');
    if (edit) openDeviceEdit(edit.dataset.deviceId);
    if (policy) openDevicePolicy(policy.dataset.deviceId);
  });
  $('#deviceEditForm').addEventListener('submit', saveDeviceEdit);
  $('#deviceEditClose').addEventListener('click', () => $('#deviceEditDialog').close());
  $('#deviceEditCancel').addEventListener('click', () => $('#deviceEditDialog').close());
  $('#devicePolicyForm').addEventListener('submit', saveDevicePolicy);
  $('#devicePolicyClose').addEventListener('click', () => $('#devicePolicyDialog').close());
  $('#devicePolicyCancel').addEventListener('click', () => $('#devicePolicyDialog').close());
  $('#devicePolicyService').addEventListener('change', updateDevicePolicyForm);
  $('#devicePolicyScope').addEventListener('change', updateDevicePolicyForm);
  $('#refreshAll').addEventListener('click', async () => { await refreshAll(); await showPlan(); });
  $('#dnsProfiles').addEventListener('click', (event) => {
    const profile = event.target.closest('[data-dns-profile]');
    if (profile) selectDNSProfile(profile.dataset.dnsProfile);
  });
  $('#dnsServiceBindings').addEventListener('change', (event) => {
    const select = event.target.closest('[data-dns-service]');
    if (select) selectServiceDNSProfile(select.dataset.dnsService, select.value);
  });
  $('#dnsTest').addEventListener('click', testDNSProfile);
  $('#dnsApply').addEventListener('click', applyDNSDraft);
  $('#dnsDiscard').addEventListener('click', discardDNSDraft);
  $('#refreshSources').addEventListener('click', refreshSources);
  $('#applySourceChanges').addEventListener('click', applySourceDraft);
  $('#discardSourceChanges').addEventListener('click', discardSourceDraft);
  $('#refreshSystem').addEventListener('click', refreshSystem);
  $('#downloadDiagnostics').addEventListener('click', downloadDiagnostics);
	$('#checkUsqueDoctor').addEventListener('click', checkUsqueDoctor);
	$('#inspectDomain').addEventListener('click', inspectDomain);
	$('#domainInspectorInput').addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); inspectDomain(); } });
	$('#refreshEngineLab').addEventListener('click', refreshEngineLab);
  $('#strategyCandidateForm').addEventListener('submit', addStrategyCandidate);
	$('#strategyCandidates').addEventListener('click', (event) => {
		const validate = event.target.closest('[data-strategy-validate]');
		const probe = event.target.closest('[data-strategy-probe]');
		const remove = event.target.closest('[data-strategy-delete]');
		if (validate) validateStrategyCandidate(validate.dataset.strategyValidate);
		if (probe) probeStrategyCandidate(probe.dataset.strategyProbe);
		if (remove) deleteStrategyCandidate(remove.dataset.strategyDelete);
	});
	$('#strategyEvidence').addEventListener('click', (event) => {
		const row = event.target.closest('[data-strategy-evidence]');
		const index = Number(row?.dataset.strategyEvidence);
		if (row && Number.isInteger(index) && state.strategyLab?.evidence?.[index]) showDetails(state.strategyLab.evidence[index], 'Подтверждённый результат NFQWS2');
	});
	$('#strategyMemory').addEventListener('click', (event) => {
		const select = event.target.closest('[data-strategy-select]');
		const reset = event.target.closest('[data-strategy-reset]');
		if (select) updateStrategyMemory(select, false);
		if (reset) updateStrategyMemory(reset, true);
	});
  $('#refreshComponents').addEventListener('click', () => refreshComponents(true));
  $('#openEngineConfig').addEventListener('click', () => openEngineConfiguration());
  $('#openComponentCatalog').addEventListener('click', () => void openEngineInstallation(selectedEngineView()?.id));
  $('#componentFilters').addEventListener('click', (event) => {
    const button = event.target.closest('[data-component-filter]');
    if (!button) return;
    state.componentFilter = button.dataset.componentFilter;
    renderComponents();
  });
  $('#overviewRefreshComponents').addEventListener('click', () => refreshComponents(true));
  $('#overviewOnboarding').addEventListener('click', () => { state.onboardingStep = 0; openOnboarding(true); });
  $('#onboardingContent').addEventListener('click', onboardingAction);
  $('#onboardingBack').addEventListener('click', () => { state.onboardingStep = Math.max(0, state.onboardingStep - 1); renderOnboarding(); });
  $('#onboardingNext').addEventListener('click', onboardingNext);
  $('#onboardingLater').addEventListener('click', () => closeOnboarding(false));
  $('#overviewSetupResume').addEventListener('click', () => openOnboarding(true));
  $('#onboardingClose').addEventListener('click', () => closeOnboarding(true));
  $('#componentStrip').addEventListener('click', (event) => {
    const config = event.target.closest('.component-config');
    if (config) { void openEngineConfiguration(config.dataset.engineConfig); return; }
    const button = event.target.closest('.component-action');
    if (button && !button.disabled) manageComponent(button.dataset.component, button.dataset.componentAction);
  });
  document.addEventListener('razvilka:auth-required', () => { state.componentRefreshRequest = null; state.componentOperation = null; state.componentCatalogError = ''; });
  $('#showPlan').addEventListener('click', showPlan);
  $('#applyChanges').addEventListener('click', openPendingChanges);
  $('#applySettings').addEventListener('click', () => applyDraft('all'));
  $('#applyServiceChanges').addEventListener('click', () => applyDraft('services'));
  $('#applyDeviceChanges').addEventListener('click', () => applyDraft('devices'));
  $('#toggleSafeMode').addEventListener('click', toggleSafeMode);
  $('#discardChanges').addEventListener('click', () => discardDraft(state.status.routing_pending_changes ? 'routing' : 'all'));
  $('#discardSettings').addEventListener('click', () => discardDraft('all'));
  $('#discardServiceChanges').addEventListener('click', () => discardDraft('services'));
  $('#discardDeviceChanges').addEventListener('click', () => discardDraft('devices'));
  $('#exportConfig').addEventListener('click', exportConfig);
  $('#overviewExportConfig').addEventListener('click', exportConfig);
  $('#engineFileSelect').addEventListener('change', (e) => selectEngineFile(e.target.value));
  $('#engineModeGuided').addEventListener('click', () => switchEngineMode('guided'));
  $('#engineModeExpert').addEventListener('click', () => switchEngineMode('expert'));
  $('#engineEditor').addEventListener('input', markEngineEditorDirty);
  $('#engineReload').addEventListener('click', reloadEngineEditor);
  $('#engineSaveDraft').addEventListener('click', () => saveEngineDraft());
  $('#engineCancelOperation').addEventListener('click', () => cancelEngineIntent());
  document.addEventListener('razvilka:auth-required', handleEngineEditorLifecycle);
  document.addEventListener('razvilka:auth-required', cancelPanelRefresh);
  document.addEventListener('click', event => { if (event.target.closest?.('[data-panel-refresh]')) void refreshAll(); });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { clearTimeout(panelLoad.retryTimer); panelLoad.retryTimer = null; }
    else if ($('#authScreen')?.hidden && state.loadIssues.length) schedulePanelRetry(true);
  });
  document.addEventListener('razvilka:view-change', handleEngineEditorLifecycle);
  $('#engineValidate').addEventListener('click', validateEngineFile);
  $('#engineDiscardDraft').addEventListener('click', discardEngineConfigDraft);
  $('#engineDiscardAllDrafts').addEventListener('click', discardSelectedEngineDrafts);
  $('#engineAssignService').addEventListener('click', assignSelectedEngineToService);
  $('#engineApplyConfig').addEventListener('click', applyEngineConfig);
  $('#engineImport').addEventListener('click', importEngineFile);
  $('#engineImportInput').addEventListener('change', handleEngineImport);
  $('#engineExport').addEventListener('click', exportEngineFile);
  $('#remoteProfileURI').addEventListener('input', () => { state.remoteProfilePreview = null; state.remoteProfileReviewedInput = ''; state.remoteProfileSelectedIndex = 0; renderRemoteProfilePreview(); });
  $('#remoteProfileFileButton').addEventListener('click', () => $('#remoteProfileFile').click());
  $('#remoteProfileFile').addEventListener('change', selectRemoteProfileFile);
  $('#remoteProfileReveal').addEventListener('click', toggleRemoteProfileVisibility);
  $('#remoteProfilePreviewButton').addEventListener('click', previewRemoteProfile);
  $('#remoteProfileStoreButton').addEventListener('click', storeRemoteNodes);
  $('#remoteProfileImportButton').addEventListener('click', importRemoteProfile);
  $('#warpGenerate').addEventListener('click', () => generateWarp(false));
  $('#warpInstallComponent').addEventListener('click', () => void openEngineInstallation('warp-wg'));
  $('#warpRotate').addEventListener('click', () => generateWarp(true));
  $('#warpImport').addEventListener('click', () => $('#warpImportInput').click());
  $('#warpImportInput').addEventListener('change', importWarpFile);
  $('#warpCheck').addEventListener('click', checkWarp);
  $('#warpCanary').addEventListener('click', checkWarpCanary);
  $('#warpConnectivity').addEventListener('click', checkWarpConnectivity);
  $('#warpDelete').addEventListener('click', deleteWarp);
  $('#warpSaveHealth').addEventListener('click', saveWarpHealthPolicy);
  $('#warpRunHealth').addEventListener('click', runWarpHealthCheck);
  ['warpHealthInterval', 'warpAllowAccountRefresh', 'warpHealthEnabled', 'warpFailureThreshold', 'warpMinFailedServices', 'warpCooldownHours', 'warpMaxRotations', 'warpAutoCandidate', 'warpAutoApply', 'warpHealthAcceptTOS'].forEach((id) => {
    const markWarpPolicyDirty = () => {
      state.warpPolicyDirty = true;
      $('#warpPolicyFeedback').textContent = 'Есть несохранённые изменения';
    };
    $(`#${id}`).addEventListener('input', markWarpPolicyDirty);
    $(`#${id}`).addEventListener('change', markWarpPolicyDirty);
  });
  $$('.engine-tab').forEach((b) => b.addEventListener('click', () => switchEngineTab(b.dataset.engineTab)));
  $('#runCurrentTests').addEventListener('click', runCurrentTests);
	$('#runIsolatedTests').addEventListener('click', runIsolatedTests);
  $('#refreshTestLab').addEventListener('click', refreshTestLab);
	$('#passwordChangeForm').addEventListener('submit', changePassword);
	$('#recoveryRotateForm').addEventListener('submit', rotateRecoveryKey);
	$('#copyRecoveryURL').addEventListener('click', copyRecoveryURL);
	$('#revokeOtherSessions').addEventListener('click', revokeOtherSessions);
  $('#hideDetails').addEventListener('click', () => $('#detailsPanel').classList.remove('open'));
  $('#noticeClose').addEventListener('click', hideNotice);
  $('#noticeDetails').addEventListener('click', () => { if (state.noticeDetails != null) showDetails(state.noticeDetails, 'Технические детали'); });
  $('#noticeSettings').addEventListener('click', () => setView('settings'));
  $('#setupForm').addEventListener('submit', submitSetup);
  $('#loginForm').addEventListener('submit', submitLogin);
  $('#recoveryResetForm').addEventListener('submit', recoverAccount);
  $('#logoutButton').addEventListener('click', logout);
  $('#useRecovery').addEventListener('click', async () => {
    const token = $('#recoveryToken').value.trim();
    if (!token) return;
    sessionStorage.setItem(ADMIN_TOKEN_KEY, token);
    if (await refreshAll()) { hideAuth(); await showPlan(); startConnectionStream(); }
    else $('#authMessage').textContent = 'Recovery key не принят.';
  });
  $('#exportProfile').addEventListener('click', exportProfile);
  $('#selectProfileImport').addEventListener('click', () => $('#profileImportInput').click());
  $('#profileImportInput').addEventListener('change', selectProfileFile);
  $('#confirmProfileImport').addEventListener('click', importProfile);
  $('#exportPrivateBackup').addEventListener('click', exportPrivateBackup);
  $('#selectPrivateBackup').addEventListener('click', () => $('#privateBackupImportInput').click());
  $('#privateBackupImportInput').addEventListener('change', selectPrivateBackupFile);
  $('#previewPrivateBackup').addEventListener('click', previewPrivateBackup);
  $('#confirmPrivateBackup').addEventListener('click', importPrivateBackup);
  $('#checkAppUpdate').addEventListener('click', checkAppUpdate);
  $('#addCustomService').addEventListener('click', () => openCustomServiceDialog());
  $('#openBypassSetup').addEventListener('click', () => {
    $('#detailsPanel').classList.remove('open');
    setView('engines');
  });
  $('#openCommunityCatalog').addEventListener('click', openCommunityCatalog);
  $('#communityCatalogClose').addEventListener('click', closeCommunityCatalog);
  $('#communitySearchButton').addEventListener('click', searchCommunityCatalog);
  $('#communitySearch').addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); searchCommunityCatalog(); } });
  $('#communityResults').addEventListener('click', (event) => { const item = event.target.closest('[data-community-id]'); if (item) previewCommunityService(item.dataset.communityId); });
  $('#communityPreview').addEventListener('click', (event) => {
    const refresh = event.target.closest('[data-community-refresh]');
    const importButton = event.target.closest('[data-community-import]');
    if (refresh) previewCommunityService(refresh.dataset.communityRefresh, true);
    if (importButton) importCommunityService(importButton.dataset.communityImport);
  });
  $('#customServiceForm').addEventListener('submit', saveCustomService);
  $('#customServiceClose').addEventListener('click', closeCustomServiceDialog);
  $('#customServiceCancel').addEventListener('click', closeCustomServiceDialog);
  $('#serviceScopeForm').addEventListener('submit', saveServiceScope);
  $('#serviceScopeClose').addEventListener('click', closeServiceScope);
  $('#serviceScopeCancel').addEventListener('click', closeServiceScope);
}

async function boot() {
  captureSetupKey();
  bindEvents();
  if (await refreshAll()) { await showPlan(); startConnectionStream(); }
}

void boot();
setInterval(refreshConnections, 15000);
