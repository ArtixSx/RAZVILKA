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
  status: {},
  system: {},
  metrics: { latest: {}, history: [], capacity: {} },
  services: [],
  engines: [],
  components: [],
  componentFilter: 'all',
  warp: {},
  warpPolicyDirty: false,
  engineConfigs: [],
  selectedEngine: 'nfqws2',
  selectedEngineFile: 'main',
  engineMode: 'guided',
  engineEditorDirty: false,
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
  routeOptions: [],
  connections: { connections: [], active: 0, closed: 0, live: false },
  devices: [],
  community: [],
  communityPreview: null,
  profileBundle: null,
  profilePreview: null,
  remoteProfilePreview: null,
  remoteProfileSelectedIndex: 0,
  privateBackupEnvelope: null,
  privateBackupPreview: null,
  appUpdate: null,
  scopeService: null,
  noticeDetails: null,
  stream: null,
  onboardingStep: 0,
  onboardingAutoEvaluated: false,
  loadIssues: [],
};

const viewMeta = {
  overview: ['Обзор', 'Главное состояние сервисов, обходов и роутера'],
  services: ['Сервисы', 'Включите нужный сервис — режим AUTO подберёт доступный обход'],
  connections: ['Соединения', 'Подтверждённый путь реального сетевого трафика'],
  engines: ['Обходы', 'Установите только нужные обходы — маршруты от этого не изменятся'],
  engineconfig: ['Настройка обходов', 'Сохраните черновик, проверьте его и примените вместе с выбранным сервисом'],
  devices: ['Устройства', 'Назначьте сервисы конкретным клиентам или группам'],
  dns: ['DNS', 'Выберите профиль, проверьте резолверы и подготовьте безопасный черновик'],
  sources: ['Источники', 'Списки доменов и адресов для автоматического распознавания сервисов'],
  testlab: ['Тест обходов', 'Сравните доступность сервиса через установленные обходы'],
  strategylab: ['Подбор NFQWS2', 'Расширенная проверка стратегий для опытных пользователей'],
  diagnostics: ['Диагностика', 'Проверка роутера и причин, мешающих применению'],
  settings: ['Настройки', 'Режим применения, резервные копии и учётная запись'],
};

const fallbackLabels = {
  auto: 'AUTO',
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

async function api(url, options = {}) {
  const method = String(options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && !headers.has('content-type')) {
    headers.set('content-type', 'application/json');
  }

  const token = sessionStorage.getItem(ADMIN_TOKEN_KEY);
  if (token) headers.set('authorization', `Bearer ${token}`);

  const response = await fetch(url, { ...options, method, headers, credentials: 'same-origin' });
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
  return response.json();
}

function friendlyErrorMessage(value, status = 0) {
  const text = String(value || '').trim();
  const lower = text.toLowerCase();
  if (lower.includes('administrator login is required')) return 'Сессия завершилась. Войдите снова.';
  if (lower.includes('failed to fetch') || lower.includes('networkerror') || lower.includes('load failed')) return 'Не удалось связаться с RAZVILKA. Проверьте, что служба запущена, и повторите попытку.';
  if (lower === 'engine is not installed') return 'Этот обход не установлен.';
  if (lower === 'engine is installed but not running') return 'Обход установлен, но сейчас не запущен.';
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
  $('#authScreen').hidden = true;
  $('.app-shell').removeAttribute('aria-hidden');
  $('#authMessage').textContent = '';
  $('#detailsPanel').classList.remove('open');
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
  try { await api('/api/v1/auth/logout', { method: 'POST' }); } catch (_) { /* session may already be gone */ }
  sessionStorage.removeItem(ADMIN_TOKEN_KEY);
  if (state.stream) { state.stream.close(); state.stream = null; }
  const status = await api('/api/v1/status');
  showAuth(status);
}

function askConfirmation(title, text, action = 'Продолжить') {
  const dialog = $('#actionDialog');
  $('#actionDialogTitle').textContent = title;
  $('#actionDialogText').textContent = text;
  $('#actionDialogConfirm').textContent = action;
  dialog.showModal();
  return new Promise((resolve) => dialog.addEventListener('close', () => resolve(dialog.returnValue === 'confirm'), { once: true }));
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
  return routeOption(id)?.name || fallbackLabels[id] || id || '—';
}

function routeAvailable(id) {
  if (id === 'auto' || id === 'direct') return true;
  const option = routeOption(id);
  return !!(option && option.selectable);
}

function setView(name) {
  $$('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${name}`));
  $$('.nav[data-view]').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  const activeNav = $(`.nav[data-view="${CSS.escape(name)}"]`);
  if (activeNav && window.matchMedia('(max-width: 760px)').matches) activeNav.scrollIntoView({ block: 'nearest', inline: 'center' });
  const meta = viewMeta[name] || [name, ''];
  $('#pageTitle').textContent = meta[0];
  $('#pageSubtitle').textContent = meta[1];
  window.scrollTo({ top: 0, behavior: 'smooth' });
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

function evidenceBadgeHTML(item, compact = false) {
  const level = String(item?.evidence_level || 'none');
  const label = evidenceLevelLabel(level);
  const route = item?.evidence_route ? routeLabel(item.evidence_route) : '';
  const checked = item?.evidence_checked_at ? new Date(item.evidence_checked_at).toLocaleString('ru-RU') : '';
  const title = [`Уровень подтверждения: ${label}`, route ? `обход: ${route}` : '', checked ? `проверено: ${checked}` : '', item?.evidence_source ? `источник: ${item.evidence_source}` : ''].filter(Boolean).join(' · ');
  const text = compact ? label : `Подтверждение: ${label}`;
  return `<em class="evidence-badge evidence-${esc(level)}" title="${esc(title)}">${esc(text)}</em>`;
}

function renderRouteComparisonDetails(value) {
  const results = Array.isArray(value.results) ? value.results : [];
  const decisions = Array.isArray(value.decisions) ? value.decisions : [];
  const assessments = Array.isArray(value.assessments) ? value.assessments : [];
  const serviceName = results.find((item) => item?.service_name)?.service_name || decisions[0]?.service_id || 'Сервис';
  const confirmed = results.filter((item) => item?.route_confirmed && item?.status === 'pass');
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
    const metrics = [
      result.http_status ? `HTTP ${result.http_status}` : '',
      Number.isFinite(Number(result.latency_ms)) && Number(result.latency_ms) > 0 ? `${Number(result.latency_ms)} мс` : '',
      result.evidence_level ? evidenceLevelLabel(result.evidence_level) : (result.route_confirmed ? 'маршрут подтверждён' : ''),
    ].filter(Boolean);
    const scenario = result.scenario_label ? `<small>${esc(result.scenario_label)}${result.scenario_required ? ' · обязательный' : ''}</small>` : '';
    return `<article class="route-result-card status-${esc(status)}"><div class="route-result-head"><strong>${esc(routeLabel(result.route))}${scenario}</strong><span>${esc(detailStatusLabels[status] || status)}</span></div>${metrics.length ? `<div class="route-result-metrics">${metrics.map((metric) => `<b>${esc(metric)}</b>`).join('')}</div>` : ''}<p>${esc(friendlyDetail(result.detail))}</p></article>`;
  }).join('');
  return `<div class="detail-hero ${esc(assessmentTone)}"><span>${esc(assessmentTitle)}</span><h4>${esc(summary)}</h4><p>${esc(assessment?.message || (confirmed.length ? `Подтверждено рабочих вариантов: ${confirmed.length}.` : 'Ни один выбранный вариант пока не дал подтверждённый ответ.'))}</p></div>${value.control_added ? '<div class="detail-note"><b>Контроль добавлен автоматически</b><p>RAZVILKA проверила DIRECT вместе с выбранными обходами, чтобы не назначать обход без необходимости.</p></div>' : ''}${decisionCards ? `<section class="detail-section"><h4>Решение Smart Route</h4>${decisionCards}</section>` : ''}<section class="detail-section"><h4>Проверенные маршруты</h4><div class="route-result-list">${resultCards || '<div class="detail-empty">Результаты проверки отсутствуют.</div>'}</div></section>${value.note ? `<div class="detail-note"><b>Как выполнялся тест</b><p>${esc(value.note)}</p></div>` : ''}${technicalDetails(value)}`;
}

function renderGenericDetails(value) {
  if (typeof value === 'string') return `<div class="detail-hero"><span>Сообщение</span><p>${esc(value)}</p></div>${technicalDetails(value)}`;
  if (!value || typeof value !== 'object') return `<div class="detail-empty">Нет дополнительных данных.</div>${technicalDetails(value)}`;
  const headline = value.error || value.message || value.note || (value.ok === false ? 'Действие не выполнено' : 'Операция завершена');
  const primitive = Object.entries(value).filter(([, item]) => item == null || ['string', 'number', 'boolean'].includes(typeof item)).slice(0, 10);
  return `<div class="detail-hero ${value.error || value.ok === false ? 'fail' : 'pass'}"><span>${value.error ? 'Ошибка' : 'Результат'}</span><h4>${esc(headline)}</h4></div>${primitive.length ? `<dl class="detail-kv">${primitive.map(([key, item]) => `<div><dt>${esc(key.replaceAll('_', ' '))}</dt><dd>${esc(typeof item === 'boolean' ? (item ? 'да' : 'нет') : item)}</dd></div>`).join('')}</dl>` : ''}${technicalDetails(value)}`;
}

function showDetails(value, title = 'Детали') {
  $('#detailsPanel').classList.add('open');
  $('#details').innerHTML = value && typeof value === 'object' && Array.isArray(value.results) && Array.isArray(value.decisions)
    ? renderRouteComparisonDetails(value)
    : renderGenericDetails(value);
  $('.drawer-head h3').textContent = title;
  $('#detailsSubtitle').textContent = 'Краткий итог · технические данные доступны ниже';
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
  if (!force && (onboardingDone() || !onboardingNeeded())) return;
  state.onboardingStep = Math.max(0, Math.min(3, state.onboardingStep || 0));
  renderOnboarding();
  if (!$('#onboardingDialog').open) $('#onboardingDialog').showModal();
}

function closeOnboarding(done = true) {
  if (done) setOnboardingDone();
  if ($('#onboardingDialog').open) $('#onboardingDialog').close();
}

function renderOnboarding() {
  const step = state.onboardingStep;
  const labels = ['Проверка роутера', 'Выбор обхода', 'Выбор сервисов', 'План и запуск'];
  $('#onboardingSteps').innerHTML = labels.map((label, index) => `<li class="${index === step ? 'active' : ''} ${index < step ? 'done' : ''}"><i>${index < step ? '✓' : index + 1}</i><span>${esc(label)}</span></li>`).join('');
  const components = ['nfqws2', 'usque', 'warp-wg'].map((id) => state.components.find((item) => item.id === id)).filter(Boolean);
  const preferredIDs = ['youtube', 'discord', 'telegram', 'chatgpt', 'claude', 'gemini', 'twitch', 'instagram', 'facebook', 'reddit', 'tiktok', 'x-twitter'];
  const preferred = preferredIDs.map((id) => state.services.find((item) => item.id === id)).filter(Boolean);
  const services = preferred.length >= 6 ? preferred : state.services.filter((item) => !item.custom).slice(0, 12);
  const installed = state.components.filter((item) => item.installed && item.provider !== 'external');
  const enabled = state.services.filter((item) => item.enabled);
  let content = '';
  if (step === 0) {
    const capacity = state.metrics.capacity || {};
    content = `<span class="eyebrow">ШАГ 1 ИЗ 4</span><h2>Сначала — безопасная база</h2><p class="onboarding-lead">Панель уже работает, но обходы не устанавливаются скрытно. Проверим, что роутер готов, и сохраним рабочий интернет без изменений.</p><div class="onboarding-checks"><div><i>✓</i><span><b>RAZVILKA запущена</b><small>${esc(state.status.listen || ':8787')} · ${esc(state.system.architecture || state.system.arch || 'архитектура определяется')}</small></span></div><div><i>✓</i><span><b>Безопасный режим включён</b><small>правила сети, DNS, туннели и маршруты не меняются без подтверждения</small></span></div><div><i>${capacity.level && capacity.level !== 'critical' ? '✓' : '·'}</i><span><b>Ресурсы роутера</b><small>${esc((capacity.reasons || []).join(' · ') || 'замеры появятся после нескольких секунд работы')}</small></span></div></div><div class="onboarding-note">Если интернет сейчас работает, мастер не должен его прервать: установка обхода и применение маршрута — разные подтверждаемые операции.</div>`;
  } else if (step === 1) {
    const unavailable = components.some((component) => !component.installed && !component.available);
    content = `<span class="eyebrow">ШАГ 2 ИЗ 4</span><h2>Выберите первый обход</h2><p class="onboarding-lead">Начните с одного. Остальные можно установить позже во вкладке «Обходы», когда увидите нагрузку и результаты тестов.</p>${unavailable ? '<div class="onboarding-repository"><span><b>Список пакетов ещё не проверен</b><small>RAZVILKA добавит только известные feed NFQWS2/Usque и выполнит opkg update. Обходы при этом не устанавливаются.</small></span><button class="secondary" data-onboarding-refresh>Проверить доступность</button></div>' : ''}<div class="onboarding-components">${components.map((component) => { const installedText = component.installed ? `Установлен ${component.installed_version || ''}` : (component.available ? `Доступен ${component.available_version || ''}` : 'Сначала проверьте список пакетов'); const action = component.installed ? '<span class="engine-state installed">ГОТОВ</span>' : `<button class="secondary" data-onboarding-component="${esc(component.id)}" ${component.available ? '' : 'disabled'}>Установить</button>`; return `<article class="${component.id === 'nfqws2' ? 'recommended' : ''}">${component.id === 'nfqws2' ? '<em>РЕКОМЕНДУЕМ НАЧАТЬ</em>' : ''}<b>${esc(component.name)}</b><p>${esc(component.description || '')}</p><small>${esc(installedText)}</small>${action}</article>`; }).join('')}</div><div class="onboarding-note">WARP Generator ставится как зависимость только при выборе WARP WireGuard. WARP MASQUE и NFQWS2 можно устанавливать независимо.</div>`;
  } else if (step === 2) {
    content = `<span class="eyebrow">ШАГ 3 ИЗ 4</span><h2>Отметьте нужные сервисы</h2><p class="onboarding-lead">Сейчас создаётся только черновик с автоматическим выбором обхода. RAZVILKA ещё ничего не применяет в систему.</p><div class="onboarding-services">${services.map((service) => `<button class="${service.enabled ? 'selected' : ''}" data-onboarding-service="${esc(service.id)}"><span>${esc(service.icon || '◇')}</span><b>${esc(service.name)}</b><i>${service.enabled ? '✓' : '+'}</i></button>`).join('')}</div><div class="onboarding-selection"><b>${enabled.length}</b><span>сервисов выбрано</span></div>`;
  } else {
    content = `<span class="eyebrow">ШАГ 4 ИЗ 4</span><h2>Проверьте план перед запуском</h2><p class="onboarding-lead">Выбор сохранён в черновике. Сначала RAZVILKA покажет препятствия и создаваемые правила, затем сделает резервную копию. Рабочее применение включается отдельно.</p><div class="onboarding-summary"><div><span>Установленные обходы</span><b>${installed.length ? installed.map((item) => item.name).join(', ') : 'пока нет'}</b></div><div><span>Выбранные сервисы</span><b>${enabled.length ? enabled.map((item) => item.name).slice(0, 6).join(', ') + (enabled.length > 6 ? ` +${enabled.length - 6}` : '') : 'пока нет'}</b></div><div><span>Текущее состояние</span><b>${state.status.safe_mode ? 'Безопасный режим — рабочая сеть не изменена' : 'Рабочее применение разрешено'}</b></div></div><div class="onboarding-note success">Мастер не обещает доступ без теста: после установки обхода откройте план, затем выполните проверку маршрутов.</div>`;
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

async function refreshAll() {
  $('#systemText').textContent = 'Обновление…';
  try {
    const status = await api('/api/v1/status');
    state.status = status;
    if (status.setup_required || (status.auth_required && !status.authenticated)) {
      showAuth(status);
      $('#systemText').textContent = 'Требуется вход';
      return false;
    }
    hideAuth();
    const requests = [
      ['system', '/api/v1/system'],
      ['metrics', '/api/v1/metrics?limit=120'],
      ['services', '/api/v1/services'],
      ['engines', '/api/v1/engines'],
      ['engineConfigs', '/api/v1/engine-configs'],
      ['components', '/api/v1/components'],
      ['warp', '/api/v1/warp'],
      ['sources', '/api/v1/sources'],
      ['routeOptions', '/api/v1/routes/options'],
      ['connections', '/api/v1/connections?include_closed=true'],
      ['devices', '/api/v1/devices'],
      ['testlab', '/api/v1/testlab'],
      ['engineLab', '/api/v1/engine-lab'],
      ['audit', '/api/v1/audit?limit=40'],
      ['strategyLab', '/api/v1/strategy-lab'],
      ['z2kPreview', '/api/v1/migrations/z2k/preview'],
      ['smartRoute', '/api/v1/smart-route'],
      ['dns', '/api/v1/dns'],
      ['dnsPlan', '/api/v1/dns/plan'],
      ['sessions', '/api/v1/auth/sessions'],
    ];
    const settled = await Promise.allSettled(requests.map(([, url]) => api(url)));
    const issues = [];
    settled.forEach((result, index) => {
      const [key, url] = requests[index];
      if (result.status === 'fulfilled') {
        state[key] = key === 'sessions' ? (result.value.sessions || []) : result.value;
        return;
      }
      issues.push({ section: key, url, message: result.reason?.message || 'Раздел временно недоступен', technical: result.reason?.technicalMessage || '' });
    });
    state.status = status;
    state.loadIssues = issues;
    renderAll();
    $('#systemText').textContent = status.safe_mode ? 'Защита включена' : (status.live_active ? 'Маршруты активны' : 'Запись разрешена');
    if (issues.length) {
      showNotice('review', 'Часть данных временно недоступна', `${issues.length} ${issues.length === 1 ? 'раздел не загрузился' : 'раздела не загрузились'}. Остальная панель продолжает работать.`, { issues });
    }
    if (!state.onboardingAutoEvaluated) {
      state.onboardingAutoEvaluated = true;
      setTimeout(() => openOnboarding(false), 0);
    }
    return true;
  } catch (error) {
    $('#systemText').textContent = 'Ошибка связи';
    if (error.status === 401 || String(error.technicalMessage || '').includes('administrator login is required')) {
      const status = await api('/api/v1/status'); showAuth(status, 'Сессия завершилась. Войдите снова.');
    } else showDetails({ error: error.message, technical: error.technicalMessage || '', response: error.payload }, 'Не удалось обновить панель');
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
  renderConnections();
  renderDevices();
  renderTestLab();
  renderEngineLab();
  renderAudit();
  renderStrategyLab();
  renderDNS();
  renderSettings();
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
    if (c.update_available) {
      version = `${c.installed_version} → ${c.available_version}`;
      actions += `<button class="primary component-action" data-component="${esc(c.id)}" data-component-action="update">Обновить</button>`;
    } else if (c.installed) {
      version = `установлена ${c.installed_version || '—'}`;
      actions += '<span class="engine-state installed">АКТУАЛЬНО</span>';
    } else if (c.available) {
      version = `доступна ${c.available_version || '—'}`;
      actions += `<button class="primary component-action" data-component="${esc(c.id)}" data-component-action="install">Установить</button>`;
    }
    if (c.installed && state.engineConfigs.some((engine) => engine.id === c.id)) actions += `<button class="mini-button component-config" data-engine-config="${esc(c.id)}">Настроить</button>`;
    if (c.can_remove && !c.external_owner) actions += `<button class="component-remove component-action" data-component="${esc(c.id)}" data-component-action="remove">Удалить</button>`;
    if (c.external_owner) actions = '<span class="external-owner-tag">ВНЕШНЕЕ УПРАВЛЕНИЕ</span>';
    const budget = c.resource_budget || {};
    const budgetText = [budget.ram_mib ? `${budget.ram_mib} МиБ RAM` : '', budget.flash_mib ? `${budget.flash_mib} МиБ flash` : '', budget.cpu_class || ''].filter(Boolean).join(' · ');
    const statusClass = c.update_available ? 'has-update' : c.installed ? 'is-installed' : c.available ? 'is-available' : 'is-unavailable';
    return `<div class="component-item ${statusClass} ${c.external_owner ? 'external' : ''}"><div><b>${esc(c.name)}</b><small>${esc(c.description || '')}</small>${c.use_case ? `<small class="component-purpose"><strong>Подходит:</strong> ${esc(c.use_case)}</small>` : ''}${c.requirement ? `<small class="component-requirement"><strong>Нужно:</strong> ${esc(c.requirement)}</small>` : ''}<small class="component-budget">${esc(budgetText)}</small><small class="component-version ${c.update_available ? 'update' : ''}">${esc(version)}</small></div><div class="component-actions">${actions}</div></div>`;
  }).join('');
}

async function refreshComponents(refresh = true) {
  const button = $('#refreshComponents');
  button.disabled = true; button.textContent = 'Проверка…';
  try {
    state.components = await api(`/api/v1/components${refresh ? '?refresh=true' : ''}`);
    renderComponents();
  } catch (error) { showDetails({ error: error.message }, 'Проверка обновлений'); }
  finally { button.disabled = false; button.textContent = 'Проверить обновления'; }
}

async function manageComponent(id, requestedAction) {
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
    plan = await api(`/api/v1/components/${encodeURIComponent(id)}/plan?action=${encodeURIComponent(action)}`);
  } catch (error) {
    showDetails({ error: error.message, response: error.payload }, `${component.name}: план недоступен`);
    return false;
  }
  if (!plan.ready) {
    showDetails(plan, `${component.name}: действие заблокировано`);
    return false;
  }
  const operation = action === 'remove'
    ? 'Будет удалён только пакет/файл, принадлежащий RAZVILKA. Конфликты, активный процесс или зависимые сервисы блокируют действие.'
    : `Источник: ${source}. После установки обход останется выключенным, пока вы явно не назначите сервисы и не выполните общий Apply.`;
  if (!await askConfirmation(`${verb} ${component.name}`, `${operation} План содержит ${plan.steps?.length || 0} проверяемых этапов, фиксирует версии до/после и не включает маршруты автоматически.`, verb)) return false;
  const buttons = $$(`.component-action[data-component="${CSS.escape(id)}"]`);
  buttons.forEach((button) => { button.disabled = true; button.textContent = 'Выполняется…'; });
  try {
    const result = await api(`/api/v1/components/${encodeURIComponent(id)}/${encodeURIComponent(action)}`, { method: 'POST' });
    await refreshComponents(false);
    const [engines, engineConfigs] = await Promise.all([api('/api/v1/engines'), api('/api/v1/engine-configs')]);
    Object.assign(state, { engines, engineConfigs });
    renderEngines(); renderEngineControl();
    showDetails({ plan, result }, `${component.name}: готово`);
    return true;
  } catch (error) { showDetails({ error: error.message, response: error.payload, plan }, `${component.name}: ошибка`); return false; }
}

function renderStatus() {
  const s = state.status;
  const engineDrafts = Number(s.engine_config_drafts || 0);
  $('#version').textContent = `v${s.version || '—'}`;
  $('#footerVersion').textContent = `v${s.version || '—'}`;
  $('#listenChip').textContent = s.listen || ':8787';
  $('#topModeLabel').textContent = s.safe_mode ? 'Безопасный режим' : 'Рабочий режим';
  $('#systemText').textContent = s.safe_mode ? 'Защита включена' : (s.live_active ? 'Маршруты активны' : 'Запись разрешена');
  $('#topModeControl').classList.toggle('active-apply', !s.safe_mode);
  $('#topToggleSafeMode').setAttribute('aria-checked', String(!!s.safe_mode));
  const modeAction = s.safe_mode ? 'Безопасный режим включён. Перейти в рабочий режим' : 'Рабочий режим включён. Вернуться в безопасный режим';
  $('#topToggleSafeMode').setAttribute('aria-label', modeAction);
  $('#topToggleSafeMode').title = modeAction;
  $('#topUptime').textContent = formatUptime(s.uptime_seconds);
  $('#kpiState').textContent = s.live_active ? 'Активна' : (s.safe_mode ? 'Безопасный режим' : 'Не применено');
  $('#kpiStateSub').textContent = s.live_active ? 'маршруты подтверждены' : (s.safe_mode ? 'рабочие маршруты не изменяются' : 'нет подтверждённого применения');
  $('#kpiEngines').textContent = `${s.engines_running || 0} / ${s.engines_installed || 0}`;
  $('#kpiServices').textContent = `${s.enabled_services || 0} / ${s.catalog_services || 0}`;
  $('#kpiConnections').textContent = s.active_connections || 0;
  $('#connectionCounter').textContent = s.active_connections || 0;
  $('#serviceNavCount').textContent = s.enabled_services || 0;
  $('#draftBar').classList.toggle('show', !!s.pending_changes || engineDrafts > 0);
  $('#draftBar').classList.toggle('safe-review', !!s.safe_mode);
  const failedApply = !s.safe_mode && !!s.pending_changes && !!s.last_apply_failure;
  $('#draftBar').classList.toggle('apply-failed', failedApply);
  $('#draftTitle').textContent = failedApply
    ? 'Применение отменено — интернет восстановлен'
    : engineDrafts > 0
    ? `${engineDrafts} ${engineDrafts === 1 ? 'черновик обхода ждёт применения' : 'черновика обходов ждут применения'}`
    : (s.safe_mode ? 'Изменения сохранены как черновик' : 'Есть неподтверждённые изменения');
  $('#draftHint').textContent = failedApply && s.last_apply_failure === 'WARP_WIREGUARD_HANDSHAKE'
    ? 'WARP WireGuard не получил ответ ни на одном резервном UDP-порту. Проверьте Cloudflare и используйте WARP · MASQUE по TCP/443 либо свой сервер.'
    : failedApply && s.last_apply_failure === 'WARP_MASQUE_SERVICE_TIMEOUT'
    ? 'Cloudflare принял MASQUE-сессию, но сервис не ответил через туннель. После одной смены сессии выберите Sing-box/VLESS или AmneziaWG со своим сервером.'
    : failedApply
    ? 'Новый маршрут не прошёл проверку. Исправьте настройки и повторите либо отмените черновик.'
    : engineDrafts > 0
    ? 'Черновик применяется только вместе с сервисом, назначенным этому обходу'
    : (s.safe_mode ? 'Безопасный режим проверит план, но не изменит рабочие маршруты' : 'Сначала проверяем план, затем применяем всё одной операцией');
  $('#applyChanges').textContent = s.safe_mode ? 'Проверить план' : (failedApply ? 'Повторить' : 'Применить');
  $('#applySettings').textContent = s.safe_mode ? 'Проверить план' : (failedApply ? 'Повторить проверку' : 'Применить черновик');
  $('#discardChanges').textContent = failedApply ? 'Отменить черновик' : 'Отменить';
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
  const actionLabels = { POST: 'Запуск', PUT: 'Изменение', PATCH: 'Изменение', DELETE: 'Удаление' };
  const outcomeLabels = { ok: 'выполнено', failed: 'ошибка', denied: 'отклонено' };
  target.innerHTML = events.map((event) => `<div class="audit-row ${esc(event.outcome || '')}"><span class="audit-outcome">${esc(outcomeLabels[event.outcome] || event.outcome || '—')}</span><div><b>${esc(actionLabels[event.action] || event.action || 'Действие')}</b><code>${esc(event.path || '—')}</code></div><small>${esc(event.actor || 'локально')} · ${esc(event.remote_ip || '—')} · ${esc(timeAgo(event.timestamp))}</small><em>${Number(event.duration_ms || 0)} мс</em></div>`).join('') || `<div class="community-empty">${state.audit?.available === false && state.audit?.last_error ? esc(state.audit.last_error) : 'Действий пока нет.'}</div>`;
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
  if (!await askConfirmation('Импортировать совместимые внешние стратегии?', 'Источник останется только для чтения. В подбор NFQWS2 попадут непроверенные кандидаты; рабочие NFQUEUE, конфиги и маршруты не изменятся.', 'Импортировать в черновик')) return;
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
  const options = [...state.routeOptions];
  if (service.route && !options.some((o) => o.id === service.route)) {
    options.push({ id: service.route, name: service.route, installed: true, selectable: true, kind: 'custom' });
  }
  return `<select class="route-select" data-route-id="${esc(service.id)}" aria-label="Маршрут для ${esc(service.name)}">${options.map((o) => {
    const selected = o.id === service.route ? 'selected' : '';
    const disabled = (!o.selectable && o.id !== service.route) ? 'disabled' : '';
    const suffix = !o.selectable && o.id !== 'auto' && o.id !== 'direct' ? ' · не установлен' : '';
    return `<option value="${esc(o.id)}" ${selected} ${disabled}>${esc(o.name || routeLabel(o.id))}${suffix}</option>`;
  }).join('')}</select>`;
}

function populateServiceCategories() {
  const select = $('#serviceCategory');
  const current = select.value;
  const categories = [...new Set(state.services.map((s) => s.category).filter(Boolean))].sort();
  select.innerHTML = '<option value="">Все категории</option>' + categories.map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
  if (categories.includes(current)) select.value = current;
}

function serviceMatches(service) {
  const q = $('#serviceSearch').value.trim().toLowerCase();
  const category = $('#serviceCategory').value;
  if (category && service.category !== category) return false;
  if (!q) return true;
  return [service.name, service.description, service.category, ...(service.domains || [])].join(' ').toLowerCase().includes(q);
}

function renderServices() {
  populateServiceCategories();
  const visible = state.services.filter(serviceMatches);
  $('#serviceList').innerHTML = visible.map((s) => {
    const plannedAvailable = routeAvailable(s.planned_engine);
    const resolvedClass = plannedAvailable ? '' : 'off';
    const appliedText = s.applied_enabled ? routeLabel(s.applied_route) : 'выключен';
    const dirty = s.dirty ? 'dirty' : '';
    const domainCount = Number((s.domains || []).length);
    const cidrCount = Number((s.cidrs || []).length);
    const coverageClass = cidrCount > 0 ? 'full' : 'domains';
    const coverageLabel = cidrCount > 0 ? 'ДОМЕНЫ + IP' : 'ТОЛЬКО ДОМЕНЫ';
    const coverageTitle = cidrCount > 0 ? 'Учтены домены и IP-сети приложения' : 'Приложение может обращаться по IP; при полной блокировке лучше туннель';
    return `<article class="service-card ${s.enabled ? 'enabled' : ''} ${dirty}">
      <div class="service-top">
        <div class="service-id"><div class="service-badge">${esc(s.icon || 'AF')}</div><div><h3>${esc(s.name)}</h3><p>${esc(s.description || '')}</p></div></div>
        <button class="toggle ${s.enabled ? 'on' : ''}" data-toggle-id="${esc(s.id)}" aria-label="${s.enabled ? 'Выключить' : 'Включить'} ${esc(s.name)}"><i></i></button>
      </div>
      <div class="service-control-grid">
        <div><span class="control-label">Желаемый маршрут</span>${routeSelectHTML(s)}</div>
        <div><span class="control-label">AUTO / фактический план</span><div class="resolved ${resolvedClass}"><i></i><span>${esc(routeLabel(s.planned_engine))}</span></div></div>
        <div class="service-actions"><button class="mini-button ${s.sources?.length ? 'scoped' : ''}" data-scope-id="${esc(s.id)}" title="Устройства" aria-label="Устройства для ${esc(s.name)}">◎</button><button class="mini-button" data-detail-id="${esc(s.id)}" title="Технические детали" aria-label="Технические детали ${esc(s.name)}">i</button><button class="mini-button" data-test-id="${esc(s.id)}" title="Проверить маршрут" aria-label="Проверить маршрут ${esc(s.name)}">⚡</button>${s.custom ? `<button class="mini-button" data-edit-service="${esc(s.id)}" title="Изменить" aria-label="Изменить ${esc(s.name)}">✎</button><button class="mini-button danger-mini" data-delete-service="${esc(s.id)}" title="Удалить" aria-label="Удалить ${esc(s.name)}">×</button>` : ''}</div>
      </div>
      <div class="service-meta"><span>${esc(s.category || 'Без категории')} · ${domainCount.toLocaleString('ru-RU')} доменов${cidrCount ? ` · ${cidrCount.toLocaleString('ru-RU')} IP-сетей` : ''} · ${s.sources?.length ? `${s.sources.length} областей` : 'вся локальная сеть'} <em class="coverage-badge ${coverageClass}" title="${esc(coverageTitle)}">${coverageLabel}</em></span><span class="service-proof-line">${evidenceBadgeHTML(s)}<span class="${s.dirty ? 'dirty-tag' : 'applied-tag'}">${s.dirty ? `изменено · применено: ${esc(appliedText)}` : `применено: ${esc(appliedText)}`}</span></span></div>
    </article>`;
  }).join('') || '<div class="empty-inline">Ничего не найдено</div>';

  $$('[data-toggle-id]').forEach((button) => button.addEventListener('click', () => toggleService(button.dataset.toggleId)));
  $$('.route-select[data-route-id]').forEach((select) => select.addEventListener('change', () => changeRoute(select.dataset.routeId, select.value)));
  $$('[data-detail-id]').forEach((button) => button.addEventListener('click', () => showServiceDetails(button.dataset.detailId)));
  $$('[data-scope-id]').forEach((button) => button.addEventListener('click', () => openServiceScope(button.dataset.scopeId)));
  $$('[data-test-id]').forEach((button) => button.addEventListener('click', () => showServicePlan(button.dataset.testId)));
  $$('[data-edit-service]').forEach((button) => button.addEventListener('click', () => openCustomServiceDialog(button.dataset.editService)));
  $$('[data-delete-service]').forEach((button) => button.addEventListener('click', () => deleteCustomService(button.dataset.deleteService)));
}

function renderOverviewServices() {
  const chosen = [...state.services].sort((a, b) => Number(b.enabled) - Number(a.enabled) || a.name.localeCompare(b.name, 'ru')).slice(0, 7);
  $('#overviewServices').innerHTML = chosen.map((s) => {
    const desired = s.enabled ? routeLabel(s.route) : 'ВЫКЛ';
    const planned = s.enabled ? routeLabel(s.planned_engine) : '—';
    const applied = s.applied_enabled ? routeLabel(s.applied_route) : 'ВЫКЛ';
    const desiredClass = s.route === 'auto' ? 'auto' : (routeAvailable(s.route) ? 'good' : 'warn');
    const appliedClass = s.applied_enabled ? 'good' : '';
    return `<div class="overview-service">
      <div class="service-name"><div class="service-badge">${esc(s.icon || 'AF')}</div><div><b>${esc(s.name)}</b><small>${esc(s.category || '')}${s.dirty ? ' · черновик' : ''}</small></div></div>
      <span class="route-pill ${desiredClass}">${esc(desired)}${s.route === 'auto' && s.enabled ? ` → ${esc(planned)}` : ''}</span>
      <span class="overview-arrow">→</span>
      <span class="overview-applied"><span class="route-pill ${appliedClass} applied-route">${esc(applied)}</span>${evidenceBadgeHTML(s, true)}</span>
    </div>`;
  }).join('');
}

function renderOverviewQuickServices() {
  const container = $('#overviewQuickServices');
  if (!container) return;
  const chosen = [...state.services].sort((a, b) => Number(b.enabled) - Number(a.enabled) || a.name.localeCompare(b.name, 'ru')).slice(0, 12);
  container.innerHTML = chosen.map((service) => `<button class="quick-service ${service.enabled ? 'enabled' : ''}" data-overview-toggle="${esc(service.id)}"><span class="service-badge">${esc(service.icon || '+')}</span><b>${esc(service.name)}</b><span class="quick-switch ${service.enabled ? 'on' : ''}"><i></i></span></button>`).join('');
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
    ['Несохранённые изменения', !state.status.pending_changes, state.status.pending_changes ? 'есть черновик' : 'нет'],
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
    $('#engineControlList').innerHTML = '<div class="empty-inline">Нет описаний обходов</div>';
    $('#engineSelectedHead').innerHTML = '';
    return;
  }
  if (!state.engineConfigs.some((e) => e.id === state.selectedEngine)) state.selectedEngine = state.engineConfigs[0].id;
  const engine = selectedEngineView();
  if (!engine.files.some((f) => f.id === state.selectedEngineFile)) state.selectedEngineFile = engine.files[0]?.id || 'main';
  const file = selectedEngineFile();
  renderWarpManager();

  $('#engineSafeBadge').textContent = state.status.safe_mode ? 'БЕЗОПАСНЫЙ РЕЖИМ · ЗАПИСЬ ВЫКЛЮЧЕНА' : 'РАБОЧИЙ РЕЖИМ';
  $('#engineSafeBadge').classList.toggle('active-apply', !state.status.safe_mode);
  $('#engineControlList').innerHTML = state.engineConfigs.map((e) => {
    const [text, cls] = engineStatusText(e);
    const drafts = (e.files || []).filter((f) => f.staged).length;
    return `<button class="engine-control-item ${e.id === state.selectedEngine ? 'active' : ''}" data-engine-id="${esc(e.id)}">
      <div><b>${esc(e.name)}</b><small>${esc(e.description || '')}</small></div>
      <div class="engine-control-meta"><span class="engine-state ${cls}">${text}</span>${drafts ? `<span class="draft-count">${drafts} черн.</span>` : ''}</div>
    </button>`;
  }).join('');
  $$('[data-engine-id]').forEach((b) => b.addEventListener('click', () => selectEngine(b.dataset.engineId)));

  const [statusText, statusClass] = engineStatusText(engine);
  const role = engineRoleGuide(engine.id);
  $('#engineSelectedHead').innerHTML = `<div><h3>${esc(engine.name)}</h3><p>${esc(engine.description || '')}</p>${role ? `<div class="engine-role-guide"><span>ЗАЧЕМ НУЖЕН</span><b>${esc(role.title)}</b><p>${esc(role.text)}</p><small>${esc(role.need)}</small></div>` : ''}</div><div class="engine-selected-meta"><span class="engine-state ${statusClass}">${statusText}</span><span>${(engine.files || []).length} файлов</span></div>`;

  $('#engineFileSelect').innerHTML = (engine.files || []).map((f) => `<option value="${esc(f.id)}" ${f.id === state.selectedEngineFile ? 'selected' : ''}>${esc(f.name)}${f.staged ? ' · черновик' : ''}${f.sensitive ? ' · секретный' : ''}</option>`).join('');
  $('#engineFilesTable').innerHTML = (engine.files || []).map((f) => `<div class="engine-file-row ${f.id === state.selectedEngineFile ? 'active' : ''}" data-engine-file-row="${esc(f.id)}"><div><b>${esc(f.name)}</b><small>${esc(f.description || '')}</small></div><div class="engine-file-meta"><span>${esc(f.syntax)}</span><span>${f.exists ? formatBytes(f.size) : 'нет рабочего файла'}</span>${f.staged ? '<span class="draft-count">ЧЕРНОВИК</span>' : ''}${f.sensitive ? '<span class="secret-tag">СЕКРЕТНЫЙ</span>' : ''}</div><code>${esc(f.path || '—')}</code></div>`).join('');
  $$('[data-engine-file-row]').forEach((row) => row.addEventListener('click', () => selectEngineFile(row.dataset.engineFileRow)));

  $('#engineCheckRunning').textContent = engine.running ? 'да' : engine.installed ? 'установлен, но остановлен' : 'нет';
  $('#engineCheckApply').textContent = state.status.safe_mode ? 'запрещён безопасным режимом' : 'разрешён после проверки';

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
  $('#engineApplyConfig').disabled = !file?.staged;
  $('#engineDiscardDraft').disabled = !file?.staged;

  if (!file) {
    editor.value = '';
    editor.disabled = true;
    $('#engineFileState').textContent = 'Нет файлов';
    $('#engineEditorMessage').textContent = '';
    return;
  }

  const fileState = [file.exists ? 'РАБОЧИЙ' : 'РАБОЧЕГО ФАЙЛА НЕТ', file.staged ? 'ЧЕРНОВИК' : '', file.sensitive ? 'СЕКРЕТНЫЙ' : '', file.modified_at ? `изменён ${timeAgo(file.modified_at)} назад` : ''].filter(Boolean).join(' · ');
  $('#engineFileState').textContent = fileState;

  if (!expert) {
    if (guidedSame) renderGuidedEditor();
    else if (!state.engineGuidedLoading && !state.engineEditorDirty) void loadEngineGuided();
    $('#engineEditorMessage').textContent = state.engineEditorDirty ? 'Есть изменения в простых полях. Сохраните черновик.' : (guidedSame ? `Источник: ${state.engineGuided.source || '—'}` : 'Загрузка простых параметров…');
  } else {
    editor.placeholder = file.sensitive ? 'Секретный конфиг: не копируйте ключи в чужие сервисы.' : 'Конфигурация / список';
    if (loadedSame && !state.engineEditorDirty) editor.value = state.engineLoaded.content || '';
    $('#engineEditorMessage').textContent = state.engineEditorDirty ? 'Есть локальные изменения. Нажмите «Сохранить черновик».' : (loadedSame ? `Источник: ${state.engineLoaded.source || '—'}` : 'Загрузка…');
    if (!loadedSame && !state.engineEditorDirty) void loadEngineFile();
  }

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
    $('#engineCheckOutput').textContent = 'Нажмите «Проверить» во вкладке «Конфиг».';
  }
}

function renderWarpManager() {
  const panel = $('#warpManager');
  if (!panel) return;
  const visible = state.selectedEngine === 'warp-wg';
  panel.hidden = !visible;
  if (!visible) return;
  const w = state.warp || {};
  $('#warpGeneratorState').textContent = w.generator_installed ? (w.generator_version || 'wgcf установлен') : 'wgcf не установлен';
  $('#warpAccountState').textContent = w.account_registered ? 'зарегистрирован' : 'нет аккаунта';
  $('#warpLiveState').textContent = w.live_profile ? (w.valid ? 'валиден' : 'ошибка профиля') : 'нет';
  $('#warpCandidateState').textContent = w.candidate_staged ? 'черновик готов' : 'нет черновика';
  const badge = $('#warpStateBadge');
  badge.textContent = w.live_profile && w.valid ? 'РАБОЧИЙ ПРОФИЛЬ ГОТОВ' : w.candidate_staged ? 'ЧЕРНОВИК ГОТОВ' : 'НЕ НАСТРОЕН';
  badge.className = `engine-state ${w.live_profile && w.valid ? 'running' : w.candidate_staged ? 'installed' : ''}`;
  $('#warpNote').textContent = w.validation_error || w.note || '';
  $('#warpGenerate').disabled = !w.generator_installed;
  $('#warpRotate').disabled = !w.generator_installed;
  $('#warpDelete').disabled = !!state.status.safe_mode || !w.live_profile;
  const health = w.health || {};
  const policy = health.policy || {};
  const healthState = health.state || {};
  if (!state.warpPolicyDirty) {
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
  const needsAcceptance = fresh || !state.warp.account_registered;
  if (needsAcceptance && !$('#warpAcceptTOS').checked) { showDetails({ message: 'Для нового аккаунта отметьте принятие условий Cloudflare.' }, 'Нужно подтверждение'); return; }
  const title = fresh ? 'Создать новый аккаунт WARP' : 'Создать профиль WARP';
  const message = fresh ? 'Текущий аккаунт wgcf будет сохранён в резервной копии. Новый профиль попадёт в черновик и не заменит рабочий автоматически.' : 'wgcf создаст проверенный профиль-кандидат. Рабочий профиль пока не изменится.';
  if (!await askConfirmation(title, message, 'Создать')) return;
  const button = fresh ? $('#warpRotate') : $('#warpGenerate'); button.disabled = true; button.textContent = 'Генерация…';
  try {
    const result = await api('/api/v1/warp/generate', { method: 'POST', body: JSON.stringify({ fresh, accept_tos: needsAcceptance && $('#warpAcceptTOS').checked }) });
    state.engineLoaded = null; state.engineGuided = null; state.engineValidation = null;
    await refreshEngineConfigs(); await refreshWarp();
    showNotice('success', 'Профиль WARP готов', result.message || 'Профиль сохранён как черновик и ещё не меняет рабочий маршрут.', result);
  } catch (error) {
    const payload = error.payload || {};
    if (payload.code === 'WARP_REGISTRATION_UNAVAILABLE') {
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

async function checkWarpConnectivity() {
  const button = $('#warpConnectivity');
  button.disabled = true; button.textContent = 'Проверяем…';
  try {
    const result = await api('/api/v1/warp/connectivity', { method: 'POST' });
    const rows = [
      { name: 'Регистрация профиля', status: result.registration?.ready ? 'ДОСТУПНА' : 'НЕДОСТУПНА', detail: result.registration?.message, latency_ms: result.registration?.latency_ms },
      { name: 'MASQUE по TCP/443', status: result.masque_http2?.ready ? 'ДОСТУПЕН' : 'НЕДОСТУПЕН', detail: result.masque_http2?.message, latency_ms: result.masque_http2?.latency_ms },
      { name: 'WARP WireGuard', status: 'ПРОВЕРЯЕТСЯ ПРИ APPLY', detail: `UDP-порты: ${(result.wireguard_ports || []).join(', ')}` },
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
  };
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
      control = `<select data-guided-field="${esc(field.id)}">${field.options.map((option) => `<option value="${esc(option.value)}" ${option.value === value ? 'selected' : ''}>${esc(option.label)}</option>`).join('')}</select>`;
    } else if (field.type === 'boolean') {
      control = `<select data-guided-field="${esc(field.id)}"><option value="true" ${value === 'true' ? 'selected' : ''}>Включено</option><option value="false" ${value !== 'true' ? 'selected' : ''}>Выключено</option></select>`;
    } else {
      const type = field.type === 'number' ? 'number' : 'text';
      control = `<input data-guided-field="${esc(field.id)}" type="${type}" value="${esc(value)}" placeholder="${esc(field.placeholder || '')}" ${field.min ? `min="${field.min}"` : ''} ${field.max ? `max="${field.max}"` : ''} ${field.required ? 'required' : ''}>`;
    }
    return `<label class="guided-field"><span>${esc(field.label)}${field.required ? ' *' : ''}</span>${control}${field.description ? `<small>${esc(field.description)}</small>` : ''}</label>`;
  }).join('')}</div></section>`).join('');
  $$('[data-guided-field]').forEach((input) => {
    const dirty = () => { state.engineEditorDirty = true; $('#engineEditorMessage').textContent = 'Есть изменения в простых полях. Нажмите «Сохранить черновик».'; };
    input.addEventListener('input', dirty); input.addEventListener('change', dirty);
  });
  $('#engineSaveDraft').disabled = false;
}

async function loadEngineGuided(force = false) {
  const engine = selectedEngineView(); const file = selectedEngineFile();
  if (!engine || !file || (!force && state.engineEditorDirty) || state.engineGuidedLoading) return;
  state.engineGuidedLoading = true;
  try {
    state.engineGuided = await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/guided?file=${encodeURIComponent(file.id)}`);
    state.engineEditorDirty = false;
    renderGuidedEditor();
    $('#engineEditorMessage').textContent = state.engineGuided.source === 'missing' ? 'Рабочий файл отсутствует. После заполнения будет создан черновик.' : `Источник: ${state.engineGuided.source || '—'}`;
  } catch (error) {
    $('#guidedEditor').innerHTML = `<div class="guided-empty"><b>Не удалось прочитать параметры</b><span>${esc(error.message)}</span></div>`;
    $('#engineEditorMessage').textContent = `Ошибка: ${error.message}`;
  } finally { state.engineGuidedLoading = false; }
}

async function switchEngineMode(mode) {
  if (mode === state.engineMode) return;
  if (state.engineEditorDirty && !await askConfirmation('Несохранённые изменения', 'Сменить режим и потерять локальные изменения?', 'Сменить режим')) return;
  state.engineMode = mode;
  state.engineEditorDirty = false;
  state.engineLoaded = null;
  state.engineGuided = null;
  renderEngineControl();
}

async function selectEngine(id) {
  if (state.engineEditorDirty && !await askConfirmation('Несохранённые изменения', 'Переключить обход и потерять локальные изменения редактора?', 'Переключить')) return;
  state.selectedEngine = id;
  const engine = selectedEngineView();
  state.selectedEngineFile = engine?.files?.[0]?.id || 'main';
  state.engineEditorDirty = false;
  state.engineLoaded = null;
  state.engineGuided = null;
  state.engineValidation = null;
  state.engineMode = 'guided';
  renderEngineControl();
}

async function selectEngineFile(id) {
  if (state.engineEditorDirty && !await askConfirmation('Несохранённые изменения', 'Переключить файл и потерять локальные изменения редактора?', 'Переключить')) {
    $('#engineFileSelect').value = state.selectedEngineFile;
    return;
  }
  state.selectedEngineFile = id;
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
  if (!engine || !file) return;
  if (!force && state.engineEditorDirty) return;
  try {
    const content = await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/file?file=${encodeURIComponent(file.id)}&expert=true`);
    state.engineLoaded = content;
    state.engineEditorDirty = false;
    $('#engineEditor').value = content.content || '';
    $('#engineEditorMessage').textContent = content.source === 'missing' ? 'Рабочий файл отсутствует. Можно импортировать или создать черновик.' : `Источник: ${content.source}`;
  } catch (error) {
    $('#engineEditorMessage').textContent = `Ошибка чтения: ${error.message}`;
  }
}

async function refreshEngineConfigs() {
  state.engineConfigs = await api('/api/v1/engine-configs');
  state.status = await api('/api/v1/status');
  renderStatus();
  renderEngineControl();
}

async function saveEngineDraft() {
  const engine = selectedEngineView();
  const file = selectedEngineFile();
  if (!engine || !file) return;
  const button = $('#engineSaveDraft');
  button.disabled = true;
  try {
    let staged;
    if (state.engineMode === 'guided') {
      const values = Object.fromEntries($$('[data-guided-field]').map((input) => [input.dataset.guidedField, input.value]));
      staged = await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/guided?file=${encodeURIComponent(file.id)}`, { method: 'PUT', body: JSON.stringify({ values }) });
      state.engineGuided = null;
    } else {
      staged = await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/file?file=${encodeURIComponent(file.id)}`, { method: 'PUT', body: JSON.stringify({ content: $('#engineEditor').value }) });
    }
    state.engineLoaded = staged;
    state.engineEditorDirty = false;
    state.engineValidation = null;
    await refreshEngineConfigs();
    $('#engineEditorMessage').textContent = 'Черновик сохранён. Рабочая конфигурация не изменена.';
  } catch (error) {
    showDetails({ error: error.message }, 'Не удалось сохранить черновик');
  } finally { button.disabled = false; }
}

async function validateEngineFile() {
  const engine = selectedEngineView(); const file = selectedEngineFile();
  if (!engine || !file) return;
  if (state.engineEditorDirty) {
    await saveEngineDraft();
    if (state.engineEditorDirty) return;
  }
  try {
    state.engineValidation = await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/validate?file=${encodeURIComponent(file.id)}`, { method: 'POST' });
    renderEngineControl();
    switchEngineTab('check');
  } catch (error) { showDetails({ error: error.message }, 'Ошибка проверки конфигурации'); }
}

async function discardEngineConfigDraft() {
  const engine = selectedEngineView(); const file = selectedEngineFile();
  if (!engine || !file || !file.staged) return;
  try {
    await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/discard?file=${encodeURIComponent(file.id)}`, { method: 'POST' });
    state.engineLoaded = null; state.engineGuided = null; state.engineEditorDirty = false; state.engineValidation = null;
    await refreshEngineConfigs();
    if (state.engineMode === 'guided') await loadEngineGuided(true); else await loadEngineFile(true);
  } catch (error) { showDetails({ error: error.message }, 'Не удалось отменить черновик'); }
}

async function applyEngineConfig() {
  const engine = selectedEngineView(); const file = selectedEngineFile();
  if (!engine || !file) return;
  try {
    if (state.engineEditorDirty) await saveEngineDraft();
    state.engineValidation = await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/validate?file=${encodeURIComponent(file.id)}`, { method: 'POST' });
    if (!state.engineValidation.ok) throw new Error(state.engineValidation.output || 'Конфигурация не прошла проверку');
    await refreshEngineConfigs();
    const plan = await api('/api/v1/plan');
    const unused = (plan.transaction?.blockers || []).find((blocker) => blocker.code === 'ENGINE_DRAFT_UNUSED' && blocker.adapter === engine.id);
    if (unused) {
      showNotice('review', `Сначала назначьте сервис обходу ${engine.name}`, unused.resolution || 'Откройте «Сервисы», включите нужный ресурс и выберите этот обход. После этого повторите Apply.', plan, true);
      return;
    }
    await applyDraft();
  } catch (error) { showDetails({ error: error.message }, 'Конфигурация не подготовлена'); }
}

async function importEngineFile() { const f = selectedEngineFile(); if (!f) return; if (state.engineMode !== 'expert') await switchEngineMode('expert'); if (state.engineMode === 'expert') $('#engineImportInput').click(); }

async function handleEngineImport(event) {
  const picked = event.target.files?.[0]; event.target.value = '';
  const engine = selectedEngineView(); const file = selectedEngineFile();
  if (!picked || !engine || !file) return;
  if (picked.size > 2 * 1024 * 1024) { showDetails({ error: 'Файл больше 2 МБ' }, 'Импорт отклонён'); return; }
  try {
    const text = await picked.text();
    $('#engineEditor').value = text; state.engineEditorDirty = true; switchEngineTab('config'); renderEngineControl();
    $('#engineEditor').value = text; // render keeps loaded text, so restore imported local buffer explicitly.
    $('#engineEditorMessage').textContent = `Импортирован локально: ${picked.name}. Нажмите «Сохранить черновик».`;
  } catch (error) { showDetails({ error: error.message }, 'Ошибка импорта'); }
}

function renderRemoteProfilePreview() {
  const container = $('#remoteProfilePreview');
  const preview = state.remoteProfilePreview?.preview;
  $('#remoteProfileImportButton').disabled = !preview?.node_count;
  if (!preview) {
    container.innerHTML = '<span>Обработка локальная. Из JSON/YAML берутся только поддерживаемые узлы; чужие DNS, маршруты, скрипты и панели удаляются.</span>';
    return;
  }
  const nodes = preview.nodes || [];
	if (state.remoteProfileSelectedIndex >= nodes.length) state.remoteProfileSelectedIndex = 0;
  const visible = nodes.slice(0, 6).map((node, index) => `<li class="${state.remoteProfileSelectedIndex === index ? 'selected' : ''}"><button type="button" data-provider-node="${index}" aria-pressed="${state.remoteProfileSelectedIndex === index}"><i>${state.remoteProfileSelectedIndex === index ? 'ВЫБРАН' : 'ВЫБРАТЬ'}</i><b>${esc(node.name || `Узел ${index + 1}`)}</b><span>${esc(node.protocol)} · ${esc(node.server)}:${Number(node.port) || '—'}${node.transport ? ` · ${esc(node.transport)}` : ''}</span></button></li>`).join('');
  const hidden = nodes.length > 6 ? `<li><b>Ещё ${nodes.length - 6}</b><span>будут сохранены в локальном селекторе</span></li>` : '';
  const warnings = [...(preview.warnings || []), ...nodes.flatMap((node) => node.warnings || [])].map((warning) => `<small>${esc(warning)}</small>`).join('');
	const selector = `<label class="provider-node-select"><span>Начальный узел</span><select id="remoteProfileNode">${nodes.map((node, index) => `<option value="${index}" ${state.remoteProfileSelectedIndex === index ? 'selected' : ''}>${esc(node.name || `Узел ${index + 1}`)} · ${esc(node.protocol)}</option>`).join('')}</select></label>`;
  container.innerHTML = `<div class="remote-profile-summary"><b>${Number(preview.node_count)} ${plural(Number(preview.node_count), 'узел', 'узла', 'узлов')} · ${esc(preview.format || 'профиль')}</b><span>Доступы скрыты; рабочая конфигурация не изменяется</span>${selector}${warnings}</div><ul>${visible}${hidden}</ul>`;
	$$('[data-provider-node]').forEach((button) => button.addEventListener('click', () => { state.remoteProfileSelectedIndex = Number(button.dataset.providerNode) || 0; renderRemoteProfilePreview(); }));
	$('#remoteProfileNode')?.addEventListener('change', (event) => { state.remoteProfileSelectedIndex = Number(event.target.value) || 0; renderRemoteProfilePreview(); });
}

async function previewRemoteProfile() {
  const uri = $('#remoteProfileURI').value.trim();
  state.remoteProfilePreview = null;
	state.remoteProfileSelectedIndex = 0;
  renderRemoteProfilePreview();
  if (!uri) return;
  const button = $('#remoteProfilePreviewButton');
  button.disabled = true; button.textContent = 'Проверяем…';
  try {
    state.remoteProfilePreview = await api('/api/v1/provider-profiles/preview', { method: 'POST', body: JSON.stringify({ profile: uri }) });
    renderRemoteProfilePreview();
  } catch (error) {
    showDetails({ error: error.message, resolution: 'Поддерживаются URI, текстовые/Base64-подписки, JSON Sing-box и YAML Clash/Mihomo. Проверьте формат, адрес, порт и обязательные ключи.' }, 'Пакет профилей не принят');
  } finally { button.disabled = false; button.textContent = 'Проверить пакет'; }
}

async function importRemoteProfile() {
  const uri = $('#remoteProfileURI').value.trim();
  const preview = state.remoteProfilePreview?.preview;
  if (!uri || !preview) return;
	const selected = preview.nodes?.[state.remoteProfileSelectedIndex];
  if (!await askConfirmation('Создать черновик Sing-box', `${preview.node_count} ${plural(Number(preview.node_count), 'узел', 'узла', 'узлов')}. Начальным станет «${selected?.name || `Узел ${state.remoteProfileSelectedIndex + 1}`}»; рабочий профиль не изменится до общего Apply.`, 'Создать черновик')) return;
  const button = $('#remoteProfileImportButton');
  button.disabled = true; button.textContent = 'Создаём…';
  try {
    const result = await api('/api/v1/provider-profiles/import', { method: 'POST', body: JSON.stringify({ profile: uri, selected_index: state.remoteProfileSelectedIndex, confirm: 'IMPORT_REMOTE_PROFILE' }) });
    $('#remoteProfileURI').value = '';
    state.remoteProfilePreview = null;
		state.remoteProfileSelectedIndex = 0;
    state.engineValidation = result.validation || null;
    await refreshEngineConfigs();
    renderRemoteProfilePreview();
    switchEngineTab('check');
    showNotice(result.ok ? 'success' : 'review', result.ok ? 'Черновик Sing-box готов' : 'Черновик создан, нужна проверка', result.note, result, true);
  } catch (error) {
    showDetails({ error: error.message, response: error.payload }, 'Профиль не импортирован');
  } finally { button.disabled = false; button.textContent = 'Создать черновик'; }
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
  $('#testCurrentRows').innerHTML = current.map((r) => `<tr><td><b>${esc(r.service_name)}</b><small>${esc(r.scenario_label || 'Основной доступ')}${r.scenario_required ? ' · обязательный' : ''}</small><small>${esc(r.probe_url || '')}</small></td><td><span class="test-status ${esc(r.status)}">${testStatusLabel(r.status)}</span></td><td>${r.http_status || '—'}</td><td>${esc(probeTiming(r))}</td><td><span class="stream-status ${esc(r.stream_status || '')}">${esc(probeStream(r))}</span></td><td>${r.route === 'current' ? 'ТЕКУЩИЙ<small>применённый маршрут</small>' : esc(routeLabel(r.route))}<small>${esc(evidenceLevelLabel(r.evidence_level))}</small></td><td>${esc(friendlyDetail(r.detail || '—'))}</td></tr>`).join('') || '<tr><td colspan="7"><div class="empty-inline">Проверки ещё не запускались</div></td></tr>';

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
  $('#isolatedRoutes').innerHTML = routes.map((route) => `<label class="route-test-choice ${route.installed || route.id === 'direct' ? '' : 'unavailable'}"><input type="checkbox" value="${esc(route.id)}" ${(selectedRoutes.has(route.id) || (selectedRoutes.size === 0 && route.id === 'direct')) ? 'checked' : ''}><span>${esc(route.name || routeLabel(route.id))}</span><small>${route.installed || route.id === 'direct' ? 'готов к проверке' : 'не установлен'}</small></label>`).join('');
  renderSmartRoute();
}

function renderSmartRoute() {
  const services = state.smartRoute?.services || {};
  const rows = Object.entries(services).filter(([, item]) => item.selected_route);
  $('#smartRouteSummary').innerHTML = rows.map(([id, item]) => {
    const service = state.services.find((candidate) => candidate.id === id);
    const evidence = item.evidence?.[item.selected_route];
    return `<div class="smart-route-row"><span><b>${esc(service?.name || id)}</b><small>${esc(detailReasonLabels[item.reason] || item.reason || 'подтверждено')}</small></span><i>→</i><strong>${esc(routeLabel(item.selected_route))}</strong><em>${evidence ? `${esc(testStatusLabel(evidence.status))} · ${evidence.latency_ms || 0} мс · ${esc(evidenceLevelLabel(evidence.evidence_level))}` : '—'}</em></div>`;
  }).join('') || '<div class="empty-inline">Сначала запустите изолированное сравнение. AUTO пока использует порядок стратегии каталога.</div>';
}

function dnsProfileByID(id) {
  return (state.dns?.profiles || []).find((profile) => profile.id === id);
}

function dnsProviderByID(id) {
  return (state.dns?.providers || []).find((provider) => provider.id === id);
}

function dnsProviderConfigMarkup(provider, dns) {
  if (provider.id === 'nextdns') {
    return `<div class="dns-provider-config"><label><span>ID профиля NextDNS</span><input id="dnsNextDNSID" maxlength="6" inputmode="text" autocomplete="off" spellcheck="false" placeholder="abc123" value="${esc(dns.nextdns_profile_id || '')}"><small>${esc(provider.configuration_hint || 'ID находится в кабинете NextDNS.')}</small></label><div class="dns-provider-config-actions"><button class="secondary" id="dnsSaveNextDNS" type="button">Сохранить ID</button>${dns.nextdns_profile_id ? '<button class="text-danger" id="dnsClearNextDNS" type="button">Удалить ID</button>' : ''}</div></div>`;
  }
  if (provider.id === 'custom') {
    return `<div class="dns-custom-config"><label><span>Название</span><input id="dnsCustomName" maxlength="80" placeholder="Домашний DNS" value="${esc(provider.configured ? provider.name : '')}"></label><label><span>Обычный DNS · по одному на строку</span><textarea id="dnsCustomServers" maxlength="1200" placeholder="192.168.1.2:53&#10;9.9.9.9">${esc((provider.servers || []).join('\n'))}</textarea></label><label><span>DoH · только HTTPS URL</span><input id="dnsCustomDoH" maxlength="512" placeholder="https://dns.example/dns-query" value="${esc(provider.doh || '')}"></label><label><span>DoT · имя или IP, порт 853 добавится автоматически</span><input id="dnsCustomDoT" maxlength="255" placeholder="dns.example:853" value="${esc(provider.dot || '')}"></label><small>Endpoint сохраняются только на роутере. Query-параметры, логины и пароли в DoH запрещены.</small><div class="dns-provider-config-actions"><button class="secondary" id="dnsSaveCustom" type="button">Сохранить провайдер</button>${provider.configured ? '<button class="text-danger" id="dnsClearCustom" type="button">Удалить</button>' : ''}</div></div>`;
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
    <div class="dns-provider-rows"><div><span>Обычный DNS</span><b>${esc((provider.servers || []).join(' · ') || (provider.id === 'system' ? 'управляет система' : 'не указан'))}</b></div><div><span>DoH</span><b>${esc(provider.doh || 'не указан')}</b></div><div><span>DoT</span><b>${esc(provider.dot || 'не указан')}</b></div></div>
    <div class="outbound-tags">${(provider.filters || []).map((filter) => `<span>${esc(filter)}</span>`).join('')}</div>
    ${dnsProviderConfigMarkup(provider, dns)}` : '<div class="community-empty">Провайдер не найден.</div>';
  $('#dnsSaveNextDNS')?.addEventListener('click', saveNextDNSProfile);
  $('#dnsClearNextDNS')?.addEventListener('click', clearNextDNSProfile);
  $('#dnsSaveCustom')?.addEventListener('click', saveCustomDNSProvider);
  $('#dnsClearCustom')?.addEventListener('click', clearCustomDNSProvider);
  $('#dnsProbeResults').innerHTML = (dns.last_probe || []).map((result) => `<div class="dns-probe-row"><span class="state-dot ${result.status === 'pass' ? 'good' : 'bad'}"></span><div><b><span class="dns-transport">${esc(result.transport || 'DNS')}</span>${esc(result.server)}</b><small>${result.status === 'pass' ? `${Number(result.latency_ms || 0)} мс · адресов: ${Number(result.addresses || 0)} · ${result.dnssec === 'confirmed' ? 'DNSSEC подтверждён' : result.dnssec === 'not-confirmed' ? 'DNSSEC не подтверждён' : 'DNSSEC не проверялся'}` : esc(result.error || 'нет ответа')}</small></div></div>`).join('') || '<div class="community-empty">Проверка ещё не запускалась.</div>';
	const plan = state.dnsPlan || dns.plan;
	$('#dnsPlan').innerHTML = plan ? `<div class="dns-plan-summary ${plan.ready ? 'ready' : 'blocked'}"><div><span>${plan.ready ? 'ГОТОВО' : 'ПРЕДПРОСМОТР'}</span><b>${esc(plan.profile?.name || 'DNS')}</b></div><p>${esc(plan.recommendation || '')}</p></div><div class="dns-plan-checks">${(plan.checks || []).map((check) => `<div class="dns-plan-check ${esc(check.status)}"><i>${check.status === 'pass' ? '✓' : check.status === 'warn' ? '!' : '×'}</i><span><b>${esc(check.id === 'probe' ? 'Доступность' : check.id === 'ownership' ? 'Владелец DNS' : check.id === 'adapter' ? 'Применение' : check.id === 'configuration' ? 'Настройка' : check.id === 'dnssec' ? 'DNSSEC' : 'Профиль')}</b><small>${esc(check.message)}</small></span></div>`).join('')}</div><details class="dns-plan-steps"><summary>Показать этапы безопасного Apply</summary>${(plan.steps || []).map((step) => `<div><i>${Number(step.order)}</i><span><b>${esc(step.name)}</b><small>${esc(step.summary)}</small></span></div>`).join('')}</details>` : '<div class="community-empty">DNS-план временно недоступен.</div>';
  $('#dnsDiscard').disabled = !dns.dirty;
}

async function selectDNSProfile(profileID) {
  try {
    state.dns = await api('/api/v1/dns/draft', { method: 'PUT', body: JSON.stringify({ profile_id: profileID }) });
	state.dnsPlan = await api('/api/v1/dns/plan');
    renderDNS();
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
  const input = { name: ($('#dnsCustomName')?.value || '').trim(), servers, doh: ($('#dnsCustomDoH')?.value || '').trim(), dot: ($('#dnsCustomDoT')?.value || '').trim() };
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
    renderDNS();
  } catch (error) {
    showDetails({ error: error.message }, 'DNS-черновик не сброшен');
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
  if (s.last_error) return ['ошибка', 'bad'];
  if (s.ready) return ['готов', 'good'];
  return ['не загружен', ''];
}

function sourceKindText(kind) {
  return ({ reference: 'справочник', downloadable: 'загружаемый список', local: 'локальный список', community: 'каталог сообщества' })[kind] || kind || 'справочник';
}

function renderSources() {
  const operational = state.sources.filter((s) => s.kind !== 'reference' && s.enabled);
  const ready = operational.filter((s) => s.ready).length;
  const references = state.sources.filter((s) => s.kind === 'reference').length;
  $('#sourceOverview').innerHTML = `<div class="source-stat"><strong>${ready}</strong><span>из ${operational.length} включённых списков готовы · ${references} справочных источников</span></div><div class="source-mini-list">${state.sources.slice(0, 8).map((s) => `<span class="source-mini">${esc(s.name)}</span>`).join('')}</div>`;
  $('#sourceRows').innerHTML = state.sources.map((s) => {
    const [text, cls] = sourceStateText(s);
    return `<tr><td><b>${esc(s.name)}</b><div class="source-role">${esc(s.url || '')}</div></td><td>${esc(sourceKindText(s.kind))}</td><td><span class="source-state"><i class="state-dot ${cls}"></i>${esc(text)}</span></td><td>${s.entries ? Number(s.entries).toLocaleString('ru-RU') : '—'}</td><td>${esc(s.last_error || '—')}</td></tr>`;
  }).join('');
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

  $('#activeConn').textContent = payload.active || 0;
  $('#closedConn').textContent = payload.closed || 0;
  $('#connectionCounter').textContent = payload.active || 0;
  $('#kpiConnections').textContent = payload.active || 0;
  $('#telemetryState').textContent = payload.live
    ? ((payload.active || 0) > 0 ? 'данные о маршрутах поступают' : 'источник подключён · активных соединений нет')
    : friendlyDetail(payload.reason || 'телеметрия недоступна');
  $('#connectionRows').innerHTML = filtered.map((c) => {
    const chainData = c.chain && c.chain.length ? c.chain : [c.service_name || 'Unknown', routeLabel(c.route)];
    const chain = chainData.map((part) => `<span class="chain-node">${esc(part)}</span>`).join('<b class="chain-arrow">→</b>');
    const host = c.host || c.destination_ip || '—';
    const source = c.source_name || c.source_ip || '—';
    return `<tr class="${c.active ? '' : 'closed-row'}"><td><div class="chain">${chain}</div><small class="evidence">${esc(c.evidence || '')}</small></td><td><b>${esc(host)}</b>${c.destination_port ? `<small>:${esc(c.destination_port)}</small>` : ''}</td><td><span class="protocol">${esc((c.protocol || '—').toUpperCase())}</span></td><td>${esc(source)}</td><td><span class="traffic">↑ ${formatBytes(c.upload)} &nbsp; ↓ ${formatBytes(c.download)}</span></td><td>${timeAgo(c.updated_at || c.started_at)}</td></tr>`;
  }).join('');
  $('#connectionEmpty').style.display = filtered.length ? 'none' : 'grid';
}

function deviceDisplayName(device) {
  return device.name || device.hostname || device.ips?.[0] || device.id;
}

function renderDevices() {
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
    state.devices = await api('/api/v1/devices');
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
  $('#devicePolicyRoute').innerHTML = (state.routeOptions || []).filter((route) => route.selectable).map((route) => `<option value="${esc(route.id)}">${esc(route.name)}${route.ready ? '' : ' · не запущен'}</option>`).join('');
  $('#devicePolicyScope').value = device.group ? 'group' : 'device';
  $('#devicePolicyScope').querySelector('option[value="group"]').disabled = !device.group;
  updateDevicePolicyForm();
  $('#devicePolicyDialog').showModal();
}

function updateDevicePolicyForm(preserveRoute = false) {
  const device = state.devices.find((item) => item.id === $('#devicePolicyID').value);
  const service = state.services.find((item) => item.id === $('#devicePolicyService').value);
  if (!device || !service) return;
  if (!preserveRoute) $('#devicePolicyRoute').value = service.route || 'auto';
  const scope = $('#devicePolicyScope').value;
  const count = scope === 'group' ? state.devices.filter((item) => item.group && item.group === device.group).length : 1;
  const globalWarning = service.enabled && !(service.sources || []).length
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
  const route = $('#devicePolicyRoute').value;
  if (!await askConfirmation('Сохранить область сервиса?', `${service.name}: ${routeLabel(route)} будет применяться только к ${sources.length} адресу(ам). Изменение попадёт в черновик и потребует общего применения.`, 'Сохранить в черновик')) return;
  try {
    await api(`/api/v1/services/${encodeURIComponent(service.id)}`, { method: 'PUT', body: JSON.stringify({ enabled: true, route, sources }) });
    $('#devicePolicyDialog').close();
    await refreshCoreAfterEdit();
    await refreshDevices();
    await showPlan();
  } catch (error) { showDetails({ error: error.message }, 'Политика не сохранена'); }
}

function renderSettings() {
  const s = state.status || {};
  $('#settingSafeMode').textContent = s.safe_mode ? 'Безопасный' : 'Рабочий';
  $('#settingSafeMode').className = s.safe_mode ? '' : 'active-apply';
  $('#toggleSafeMode').textContent = s.safe_mode ? 'Перейти в рабочий режим' : 'Включить безопасный режим';
  $('#settingPending').textContent = s.pending_changes ? 'есть' : 'нет';
  $('#settingEngineDrafts').textContent = s.engine_config_drafts || 0;
  $('#settingApplied').textContent = s.last_applied_at ? new Date(s.last_applied_at).toLocaleString('ru-RU') : '—';
  $('#settingRevision').textContent = `${s.revision || 0} / ${s.applied_revision || 0}`;
	$('#settingsUsername').textContent = s.username || 'admin';
	$('#sessionList').innerHTML = (state.sessions || []).map((session) => `<div class="session-row ${session.current ? 'current' : ''}"><div><b>${session.current ? 'Текущий браузер' : esc(session.remote_ip || 'Неизвестный адрес')}</b><span>${esc(session.user_agent || 'Клиент API')}</span><small>Активность: ${timeAgo(session.last_seen_at)} · до ${session.expires_at ? new Date(session.expires_at).toLocaleString('ru-RU') : '—'}</small></div>${session.current ? '<em>ТЕКУЩИЙ</em>' : `<button class="secondary revoke-session" data-session-id="${esc(session.id)}">Завершить</button>`}</div>`).join('') || '<div class="empty-inline">Нет активных сеансов</div>';
	$$('.revoke-session').forEach((button) => button.addEventListener('click', () => revokeSession(button.dataset.sessionId)));
}

async function toggleSafeMode() {
  const enable = !state.status.safe_mode;
  const title = enable ? 'Включить безопасный режим' : 'Перейти в рабочий режим';
  const message = enable
    ? 'Новые применения будут только проверяться. Уже работающие маршруты останутся без изменений.'
    : 'Следующее применение сможет изменить правила сети и маршруты. Перед записью RAZVILKA создаст снимок, проверит конфигурацию и вернёт прежнее состояние при ошибке.';
  if (!await askConfirmation(title, message, enable ? 'Включить' : 'Разрешить')) return;
  const controls = [$('#toggleSafeMode'), $('#topToggleSafeMode')];
  controls.forEach((button) => { button.disabled = true; });
  try {
    await api('/api/v1/settings/safe-mode', { method: 'PUT', body: JSON.stringify({ enabled: enable }) });
    await refreshCoreAfterEdit();
  } catch (error) { showDetails({ error: error.message, technical: error.technicalMessage || '' }, 'Режим не изменён'); }
  finally { controls.forEach((button) => { button.disabled = false; }); }
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
  const [status, services] = await Promise.all([api('/api/v1/status'), api('/api/v1/services')]);
  state.status = status;
  state.services = services;
  renderStatus();
  renderServices();
  renderOverviewQuickServices();
  renderOverviewServices();
  renderReadiness();
  renderSettings();
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
  state.communityPreview = null;
  $('#communityCatalogDialog').showModal();
  $('#communitySearch').value = '';
  await searchCommunityCatalog();
  setTimeout(() => $('#communitySearch').focus(), 0);
}

function closeCommunityCatalog() { $('#communityCatalogDialog').close(); }

async function searchCommunityCatalog() {
  const query = $('#communitySearch').value.trim();
  $('#communityResults').innerHTML = '<div class="community-empty">Поиск в разрешённом каталоге…</div>';
  try {
    state.community = await api(`/api/v1/community/services?q=${encodeURIComponent(query)}`);
    renderCommunityResults();
  } catch (error) {
    $('#communityResults').innerHTML = `<div class="community-empty error">${esc(error.message)}</div>`;
  }
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
  $('#communityPreview').innerHTML = '<div class="community-empty">Загрузка и локальная проверка списков…</div>';
  try {
    state.communityPreview = await api(`/api/v1/community/services/${encodeURIComponent(id)}/preview${refresh ? '?refresh=true' : ''}`);
    renderCommunityResults();
    renderCommunityPreview();
  } catch (error) {
    $('#communityPreview').innerHTML = `<div class="community-empty error">Источник не принят: ${esc(error.message)}</div>`;
  }
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
    <div class="community-access access-${esc(entry.access?.status || 'catalog')}"><b>${esc(accessLabel(entry.access?.status))}</b><span>${esc(entry.access?.note || 'Доступность необходимо проверить у своего провайдера.')}</span>${evidenceURL ? `<a href="${esc(evidenceURL)}" target="_blank" rel="noreferrer">Основание статуса ↗</a>` : ''}<small>Проверено: ${esc(entry.access?.verified_at || 'не указано')} · регион RU</small></div>
    <div class="community-metrics"><div><b>${domains.length}</b><span>доменов</span></div><div><b>${cidrs.length}</b><span>IP/CIDR</span></div><div><b>${preview.skipped || 0}</b><span>пропущено</span></div><div class="${conflicts.length ? 'warn' : ''}"><b>${conflicts.length}</b><span>конфликтов</span></div></div>
    <div class="community-source"><span>Источник</span><b>${esc(entry.provider || '—')}</b><small>Лицензия: ${esc(entry.license || 'не указана')}</small><small>SHA-256: ${esc((preview.source_sha256 || '').slice(0, 16))}… · ${preview.from_cache ? 'cache' : 'загружено сейчас'}</small><a href="${esc(sourceURL)}" target="_blank" rel="noreferrer">Открыть страницу источника ↗</a></div>
    ${conflicts.length ? `<div class="community-conflicts"><b>Совпадения с существующими правилами</b><ul>${conflictRows}</ul>${conflicts.length > 12 ? `<small>И ещё ${conflicts.length - 12}. Импорт возможен только после подтверждения.</small>` : ''}</div>` : '<div class="community-clean">Конфликтов с текущим каталогом не найдено.</div>'}
    <details class="community-data"><summary>Показать данные (${domains.length + cidrs.length})</summary><div><b>Домены</b><pre>${esc(domains.slice(0, 80).join('\n') || '—')}</pre>${domains.length > 80 ? `<small>Показаны первые 80 из ${domains.length}</small>` : ''}<b>IP/CIDR</b><pre>${esc(cidrs.slice(0, 80).join('\n') || '—')}</pre>${cidrs.length > 80 ? `<small>Показаны первые 80 из ${cidrs.length}</small>` : ''}</div></details>
    <div class="community-preview-actions"><button class="secondary" data-community-refresh="${esc(entry.id)}" type="button">Обновить preview</button><button class="primary" data-community-import="${esc(entry.id)}" type="button">${imported ? 'Обновить из источника' : 'Добавить в мои сервисы'}</button></div>`;
}

async function importCommunityService(id) {
  const preview = state.communityPreview;
  if (!preview || preview.entry?.id !== id) return;
  const conflicts = preview.conflicts || [];
  const imported = state.community.find((item) => item.id === id)?.imported;
  let allowConflicts = false;
  if (conflicts.length) {
    allowConflicts = await askConfirmation('Импортировать с конфликтами?', `${conflicts.length} доменов или сетей уже используются другими сервисами. Они не будут удалены; при активных маршрутах потребуется выбрать приоритет.`, 'Всё равно импортировать');
    if (!allowConflicts) return;
  }
  const button = $(`[data-community-import="${CSS.escape(id)}"]`);
  if (button) { button.disabled = true; button.textContent = 'Импорт…'; }
  try {
    if (imported && !await askConfirmation('Обновить правила сервиса?', 'Домены и сети будут заново загружены из указанного источника. Желаемый маршрут и состояние включения сохранятся.', 'Обновить')) { renderCommunityPreview(); return; }
    const result = await api(`/api/v1/community/services/${encodeURIComponent(id)}/import`, { method: 'POST', body: JSON.stringify({ allow_conflicts: allowConflicts, refresh: imported }) });
    await refreshCoreAfterEdit();
    await searchCommunityCatalog();
    await previewCommunityService(id);
    showDetails(result, result.updated ? 'Community-сервис обновлён' : 'Community-сервис добавлен');
  } catch (error) {
    showDetails({ error: error.message }, 'Импорт не выполнен');
    renderCommunityPreview();
  }
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
  $('#serviceScopeSummary').textContent = service.sources?.length ? `Сейчас маршрут ограничен: ${(service.sources || []).join(', ')}` : 'Сейчас маршрут применяется ко всей локальной сети.';
  $('#serviceScopeDialog').showModal();
}

async function saveServiceScope(event) {
  event.preventDefault();
  const service = state.services.find((item) => item.id === state.scopeService);
  if (!service) return closeServiceScope();
  const previous = [...(service.sources || [])];
  service.sources = $('#serviceScopeSources').value.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
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
    button.disabled = false; button.textContent = 'Сохранить в черновик';
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
    showDetails({ error: error.message }, 'Не удалось изменить сервис');
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
    showDetails({ error: error.message }, 'Не удалось изменить маршрут');
  }
}

function showServiceDetails(id) {
  const service = state.services.find((s) => s.id === id);
  if (service) {
    const domains = service.domains || [];
    const cidrs = service.cidrs || [];
    showDetails({
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
      cidrs,
      source_refs: service.source_refs || [],
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

async function applyDraft() {
  const buttons = [$('#applyChanges'), $('#applySettings')];
  buttons.forEach((b) => { b.disabled = true; b.textContent = 'Применение…'; });
  try {
    const preview = await api('/api/v1/plan');
    const unusedDrafts = (preview.transaction?.blockers || []).filter((blocker) => blocker.code === 'ENGINE_DRAFT_UNUSED');
    if (unusedDrafts.length) {
      const names = unusedDrafts.map((blocker) => fallbackLabels[blocker.adapter] || blocker.adapter).join(', ');
      showNotice('review', 'Сначала назначьте сервис черновику', `${names}: выберите хотя бы один включённый сервис для этого обхода либо отмените черновик. Рабочие настройки не изменены.`, preview, true);
      return;
    }
    const result = await api('/api/v1/apply', { method: 'POST' });
    await refreshCoreAfterEdit();
    await showPlan();
    if (result.safe_mode && result.reviewed && !result.live_applied) {
      showNotice('review', 'План проверен — рабочие маршруты не изменены', 'Это нормальная работа безопасного режима. Черновик сохранён; откройте план или явно перейдите в рабочий режим в настройках.', result, true);
    } else if (result.live_applied && !result.pending_changes) {
      showNotice('success', 'Настройки применены', result.note || 'Маршруты активированы, проверены и зафиксированы.', result);
    } else if (result.pending_changes) {
      showNotice('review', 'Часть изменений ещё ждёт применения', 'Проверьте, что каждый черновик обхода назначен хотя бы одному включённому сервису.', result, true);
    } else {
      showNotice('success', 'Изменения обработаны', result.note || 'Операция завершена.', result);
    }
  } catch (error) {
	await showPlan();
	const unused = (error.payload?.transaction?.blockers || []).filter((blocker) => blocker.code === 'ENGINE_DRAFT_UNUSED');
	if (unused.length) {
	  const names = unused.map((blocker) => fallbackLabels[blocker.adapter] || blocker.adapter).join(', ');
	  showNotice('review', 'Сначала назначьте сервис черновику', `${names}: выберите хотя бы один сервис для этого обхода либо отмените его черновик. Рабочие настройки не изменены.`, error.payload, true);
	} else {
	  const failure = error.payload?.failure;
	  if (failure) {
	    showNotice('error', failure.title || 'Изменения не применены', `${failure.message || error.message} ${failure.resolution || ''}`.trim(), error.payload, true);
	  } else {
	    showNotice('error', 'Применение заблокировано', error.payload?.note || error.message, error.payload || { error: error.message }, true);
	  }
	}
  } finally {
    buttons.forEach((button) => { button.disabled = false; });
    renderStatus();
  }
}

async function discardDraft() {
  try {
    const result = await api('/api/v1/discard', { method: 'POST' });
    await refreshCoreAfterEdit();
    await refreshEngineConfigs();
    showNotice('success', 'Черновики отменены', result.discarded_engine_drafts ? `Отменено конфигураций обходов: ${result.discarded_engine_drafts}.` : 'Желаемые маршруты возвращены к последнему применённому состоянию.', result);
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
    showDetails({ message: 'Включённые источники обновлены и проверены.', sources: state.sources }, 'Источники обновлены');
  } catch (error) {
    showDetails({ error: error.message }, 'Ошибка источников');
  } finally {
    button.disabled = false;
    button.textContent = 'Обновить включённые';
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
    const phaseLabels = { snapshot: 'Снимок', stage: 'Подготовка', validate: 'Проверка', activate: 'Активация', health: 'Проверка доступности', commit: 'Сохранение' };
    const planState = tx.safe_mode ? 'БЕЗОПАСНЫЙ РЕЖИМ' : ({ planned: 'ПЛАН', reviewed: 'ПРОВЕРЕНО', ready: 'ГОТОВО', committed: 'ПРИМЕНЕНО' }[tx.state] || tx.state || 'ПЛАН');
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

async function checkAppUpdate() {
  const button = $('#checkAppUpdate');
  button.disabled = true; button.textContent = 'Проверяем…';
  $('#appUpdateState').innerHTML = '<div class="community-empty">Запрашиваем последний стабильный релиз…</div>';
  try {
    state.appUpdate = await api('/api/v1/update?refresh=true');
    renderAppUpdate();
  } catch (error) {
    $('#appUpdateState').innerHTML = `<div class="app-update-error">${esc(error.message)}</div>`;
  } finally {
    button.disabled = false; button.textContent = 'Проверить снова';
  }
}

function renderAppUpdate() {
  const update = state.appUpdate;
  if (!update) return;
  if (update.state === 'check-failed') {
    $('#appUpdateState').innerHTML = `<div class="app-update-error">Не удалось безопасно проверить официальный релиз: ${esc(update.error || 'неизвестная ошибка')}</div>`;
    return;
  }
  const available = Boolean(update.update_available);
  const label = available ? `Доступно ${update.installed_version} → ${update.latest_version}` : `Установлена актуальная ${update.installed_version}`;
  $('#appUpdateState').innerHTML = `<div class="app-update-result"><div class="app-update-summary"><div><h3>${esc(label)}</h3><p>Проверено ${esc(update.checked_at ? new Date(update.checked_at).toLocaleString('ru-RU') : '—')}</p></div><span class="app-update-badge ${available ? 'update' : ''}">${available ? 'ЕСТЬ ОБНОВЛЕНИЕ' : 'АКТУАЛЬНО'}</span></div>${available ? `<div class="app-update-commands"><div class="app-update-command"><span>Обновление на роутере</span><code>${esc(update.install_command)}</code><button class="secondary" type="button" data-copy-update="install">Скопировать команду</button></div><div class="app-update-command"><span>Проверка GitHub attestation на компьютере</span><code>${esc(update.verify_command)}</code><button class="secondary" type="button" data-copy-update="verify">Скопировать проверку</button></div></div><div class="app-update-note">Перед обновлением скачайте зашифрованный backup. Команда запускает штатный транзакционный installer с backup, healthcheck и rollback; автоматический запуск из UI намеренно отключён.</div><a class="secondary" href="${esc(update.release_url)}" target="_blank" rel="noopener noreferrer">Открыть официальный релиз</a>` : '<div class="app-update-note">Действий не требуется. Повторная проверка доступна вручную; результат кэшируется на роутере.</div>'}</div>`;
  $$('[data-copy-update]').forEach((item) => item.addEventListener('click', async () => {
    const value = item.dataset.copyUpdate === 'verify' ? update.verify_command : update.install_command;
    try { await navigator.clipboard.writeText(value); item.textContent = 'Скопировано'; }
    catch (_) { showDetails({ command: value }, 'Скопируйте команду'); }
  }));
}

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
    await refreshAll(); await showPlan();
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
  } catch (error) { showDetails({ error: error.message }, 'Резервная копия не создана'); }
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
    $('#privateBackupPreview').innerHTML = `<div class="private-backup-ok"><span class="engine-state installed">ШИФРОВАНИЕ И ЦЕЛОСТНОСТЬ ПРОВЕРЕНЫ</span><h3>Резервная копия RAZVILKA ${esc(preview.from_version)}</h3><p>${preview.created_at ? new Date(preview.created_at).toLocaleString('ru-RU') : '—'}</p><div class="private-backup-metrics"><div><b>${preview.services || 0}</b><span>сервисов</span></div><div><b>${preview.engine_files?.length || 0}</b><span>конфигов</span></div><div><b>${preview.sensitive_files || 0}</b><span>секретных</span></div><div><b>${preview.custom_services || 0}</b><span>пользовательских</span></div><div><b>${preview.devices || 0}</b><span>устройств</span></div><div><b>черновик</b><span>режим</span></div></div>${warnings.map((warning) => `<div class="private-backup-warning">${esc(warning)}</div>`).join('')}<div class="private-backup-digest">${esc(preview.digest)}</div></div>`;
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
  try {
    const result = await api('/api/v1/private-backups/import', { method: 'POST', body: JSON.stringify({ envelope: state.privateBackupEnvelope, password: $('#privateBackupImportPassword').value, confirm: 'IMPORT_PRIVATE_BACKUP' }) });
    state.privateBackupEnvelope = null; state.privateBackupPreview = null;
    $('#privateBackupImportPassword').value = '';
    $('#previewPrivateBackup').disabled = true;
    $('#privateBackupPreview').innerHTML = '<div class="community-clean">Приватные данные импортированы в черновик. Проверьте конфиги и общий план перед применением.</div>';
    await refreshAll(); await showPlan();
    showDetails(result, 'Приватная резервная копия импортирована');
  } catch (error) { showDetails({ error: error.message }, 'Импорт резервной копии не выполнен'); }
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
  window.addEventListener('beforeunload', (event) => {
    if (!state.engineEditorDirty && !state.warpPolicyDirty) return;
    event.preventDefault();
    event.returnValue = '';
  });
  $$('[data-view]').forEach((button) => button.addEventListener('click', () => setView(button.dataset.view)));
  $('#serviceSearch').addEventListener('input', renderServices);
  $('#serviceCategory').addEventListener('change', renderServices);
  $('#connectionFilter').addEventListener('input', renderConnections);
  $('#showClosed').addEventListener('change', renderConnections);
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
  $('#devicePolicyService').addEventListener('change', () => updateDevicePolicyForm(false));
  $('#devicePolicyScope').addEventListener('change', () => updateDevicePolicyForm(true));
  $('#refreshAll').addEventListener('click', async () => { await refreshAll(); await showPlan(); });
  $('#dnsProfiles').addEventListener('click', (event) => {
    const profile = event.target.closest('[data-dns-profile]');
    if (profile) selectDNSProfile(profile.dataset.dnsProfile);
  });
  $('#dnsTest').addEventListener('click', testDNSProfile);
  $('#dnsDiscard').addEventListener('click', discardDNSDraft);
  $('#refreshSources').addEventListener('click', refreshSources);
  $('#refreshSystem').addEventListener('click', refreshSystem);
  $('#downloadDiagnostics').addEventListener('click', downloadDiagnostics);
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
  $('#openComponentCatalog').addEventListener('click', () => setView('engines'));
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
  $('#onboardingLater').addEventListener('click', () => closeOnboarding(true));
  $('#onboardingClose').addEventListener('click', () => closeOnboarding(true));
  $('#componentStrip').addEventListener('click', (event) => {
    const config = event.target.closest('.component-config');
    if (config) { void openEngineConfiguration(config.dataset.engineConfig); return; }
    const button = event.target.closest('.component-action');
    if (button) manageComponent(button.dataset.component, button.dataset.componentAction);
  });
  $('#showPlan').addEventListener('click', showPlan);
  $('#applyChanges').addEventListener('click', applyDraft);
  $('#applySettings').addEventListener('click', applyDraft);
  $('#toggleSafeMode').addEventListener('click', toggleSafeMode);
  $('#topToggleSafeMode').addEventListener('click', toggleSafeMode);
  $('#discardChanges').addEventListener('click', discardDraft);
  $('#discardSettings').addEventListener('click', discardDraft);
  $('#exportConfig').addEventListener('click', exportConfig);
  $('#overviewExportConfig').addEventListener('click', exportConfig);
  $('#engineFileSelect').addEventListener('change', (e) => selectEngineFile(e.target.value));
  $('#engineModeGuided').addEventListener('click', () => switchEngineMode('guided'));
  $('#engineModeExpert').addEventListener('click', () => switchEngineMode('expert'));
  $('#engineEditor').addEventListener('input', () => { state.engineEditorDirty = true; $('#engineEditorMessage').textContent = 'Есть локальные изменения. Нажмите «Сохранить черновик».'; });
  $('#engineReload').addEventListener('click', async () => { if (!state.engineEditorDirty || await askConfirmation('Перечитать конфигурацию', 'Потерять локальные изменения и перечитать файл?', 'Перечитать')) { state.engineEditorDirty = false; state.engineLoaded = null; state.engineGuided = null; if (state.engineMode === 'guided') await loadEngineGuided(true); else await loadEngineFile(true); renderEngineControl(); } });
  $('#engineSaveDraft').addEventListener('click', saveEngineDraft);
  $('#engineValidate').addEventListener('click', validateEngineFile);
  $('#engineDiscardDraft').addEventListener('click', discardEngineConfigDraft);
  $('#engineApplyConfig').addEventListener('click', applyEngineConfig);
  $('#engineImport').addEventListener('click', importEngineFile);
  $('#engineImportInput').addEventListener('change', handleEngineImport);
  $('#engineExport').addEventListener('click', exportEngineFile);
  $('#remoteProfileURI').addEventListener('input', () => { state.remoteProfilePreview = null; state.remoteProfileSelectedIndex = 0; renderRemoteProfilePreview(); });
  $('#remoteProfileFileButton').addEventListener('click', () => $('#remoteProfileFile').click());
  $('#remoteProfileFile').addEventListener('change', selectRemoteProfileFile);
  $('#remoteProfileReveal').addEventListener('click', toggleRemoteProfileVisibility);
  $('#remoteProfilePreviewButton').addEventListener('click', previewRemoteProfile);
  $('#remoteProfileImportButton').addEventListener('click', importRemoteProfile);
  $('#warpGenerate').addEventListener('click', () => generateWarp(false));
  $('#warpRotate').addEventListener('click', () => generateWarp(true));
  $('#warpImport').addEventListener('click', () => $('#warpImportInput').click());
  $('#warpImportInput').addEventListener('change', importWarpFile);
  $('#warpCheck').addEventListener('click', checkWarp);
  $('#warpConnectivity').addEventListener('click', checkWarpConnectivity);
  $('#warpDelete').addEventListener('click', deleteWarp);
  $('#warpSaveHealth').addEventListener('click', saveWarpHealthPolicy);
  $('#warpRunHealth').addEventListener('click', runWarpHealthCheck);
  ['warpHealthEnabled', 'warpFailureThreshold', 'warpMinFailedServices', 'warpCooldownHours', 'warpMaxRotations', 'warpAutoCandidate', 'warpAutoApply', 'warpHealthAcceptTOS'].forEach((id) => {
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
