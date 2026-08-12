'use strict';

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const state = {
  status: {},
  system: {},
  services: [],
  engines: [],
  engineConfigs: [],
  selectedEngine: 'nfqws2',
  selectedEngineFile: 'main',
  engineEditorDirty: false,
  engineLoaded: null,
  engineValidation: null,
  engineTab: 'config',
  testlab: { current: [], matrix: [] },
  sources: [],
  routeOptions: [],
  connections: { connections: [], active: 0, closed: 0, live: false },
  stream: null,
};

const viewMeta = {
  overview: ['Обзор', 'Состояние маршрутизации и системы'],
  services: ['Сервисы', 'Выбор маршрута отдельно для каждого сервиса'],
  connections: ['Соединения', 'Фактический путь живого трафика'],
  engines: ['Движки', 'Конфиги, файлы, импорт, проверка и безопасное применение'],
  devices: ['Устройства', 'Клиенты сети и персональные политики'],
  sources: ['Источники', 'Каталоги доменов, CIDR и service manifests'],
  testlab: ['Тест обходов', 'Фактическая доступность сервисов и матрица движков'],
  diagnostics: ['Диагностика', 'Preflight, dry-run и compatibility gates'],
  settings: ['Настройки', 'Safe Apply, export и состояние конфигурации'],
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

async function api(url, options = {}, allowTokenPrompt = true) {
  const method = String(options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && !headers.has('content-type')) {
    headers.set('content-type', 'application/json');
  }

  const token = sessionStorage.getItem(ADMIN_TOKEN_KEY);
  if (token) headers.set('authorization', `Bearer ${token}`);

  const response = await fetch(url, { ...options, method, headers });
  if (response.status === 401 && allowTokenPrompt) {
    sessionStorage.removeItem(ADMIN_TOKEN_KEY);
    const entered = window.prompt(
      'Введите токен администратора RAZVILKA. Он хранится на роутере в /opt/etc/razvilka/admin.token',
    );
    if (entered?.trim()) {
      sessionStorage.setItem(ADMIN_TOKEN_KEY, entered.trim());
      return api(url, options, false);
    }
  }
  if (!response.ok) {
    const text = (await response.text()).trim();
    throw new Error(text || `HTTP ${response.status}`);
  }
  return response.json();
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
  return !!(option && option.installed);
}

function setView(name) {
  $$('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${name}`));
  $$('.nav[data-view]').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  const meta = viewMeta[name] || [name, ''];
  $('#pageTitle').textContent = meta[0];
  $('#pageSubtitle').textContent = meta[1];
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function showDetails(value, title = 'Детали') {
  $('#detailsPanel').classList.add('open');
  $('#details').textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  $('.drawer-head h3').textContent = title;
}

function formatBytes(n) {
  const value = Number(n || 0);
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 ** 3) return `${(value / (1024 ** 2)).toFixed(1)} MB`;
  return `${(value / (1024 ** 3)).toFixed(2)} GB`;
}

function formatMemory(kb) {
  if (!kb) return '—';
  return `${Math.round(Number(kb) / 1024)} MB`;
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
    const [status, system, services, engines, engineConfigs, sources, routeOptions, connections, testlab] = await Promise.all([
      api('/api/v1/status'),
      api('/api/v1/system'),
      api('/api/v1/services'),
      api('/api/v1/engines'),
      api('/api/v1/engine-configs'),
      api('/api/v1/sources'),
      api('/api/v1/routes/options'),
      api('/api/v1/connections?include_closed=true'),
      api('/api/v1/testlab'),
    ]);
    Object.assign(state, { status, system, services, engines, engineConfigs, sources, routeOptions, connections, testlab });
    renderAll();
    $('#systemText').textContent = status.safe_mode ? 'Safe Mode' : 'Система активна';
  } catch (error) {
    $('#systemText').textContent = 'Ошибка связи';
    showDetails({ error: error.message }, 'Ошибка API');
  }
}

function renderAll() {
  renderStatus();
  renderSystem();
  renderServices();
  renderOverviewServices();
  renderReadiness();
  renderEngines();
  renderEngineControl();
  renderSources();
  renderConnections();
  renderTestLab();
  renderSettings();
}

function renderStatus() {
  const s = state.status;
  $('#version').textContent = `v${s.version || '—'}`;
  $('#footerVersion').textContent = `v${s.version || '—'}`;
  $('#listenChip').textContent = s.listen || ':8787';
  $('#kpiState').textContent = s.safe_mode ? 'Safe Mode' : 'Active';
  $('#kpiStateSub').textContent = s.safe_mode ? 'dataplane не изменяется' : 'dataplane разрешён';
  $('#kpiEngines').textContent = `${s.engines_running || 0} / ${s.engines_installed || 0}`;
  $('#kpiServices').textContent = `${s.enabled_services || 0} / ${s.catalog_services || 0}`;
  $('#kpiConnections').textContent = s.active_connections || 0;
  $('#connectionCounter').textContent = s.active_connections || 0;
  $('#serviceNavCount').textContent = s.enabled_services || 0;
  $('#draftBar').classList.toggle('show', !!s.pending_changes);
}

function renderSystem() {
  const s = state.system || {};
  $('#kpiWan').textContent = s.wan_interface || '—';
  $('#kpiArch').textContent = [s.architecture, s.kernel].filter(Boolean).join(' · ') || 'не определено';

  const values = [
    ['Архитектура', s.architecture || '—', true],
    ['Kernel', s.kernel || '—', !!s.kernel],
    ['Hostname', s.hostname || '—', !!s.hostname],
    ['WAN', s.wan_interface || '—', !!s.wan_interface],
    ['RAM', `${formatMemory(s.mem_available_kb)} свободно / ${formatMemory(s.mem_total_kb)}`, !!s.mem_total_kb],
    ['/opt', ...yesNo(s.opt_ready)],
    ['opkg', ...yesNo(s.opkg)],
    ['ip command', ...yesNo(s.ip_command)],
    ['/dev/net/tun', ...yesNo(s.tun)],
    ['iptables', ...yesNo(s.iptables)],
    ['ip6tables', ...yesNo(s.ip6tables)],
    ['nftables', ...yesNo(s.nftables)],
    ['NFQUEUE', ...yesNo(s.nfqueue)],
    ['Внешние туннели', s.route_contamination ? (s.external_tunnels || []).join(', ') || 'обнаружены' : 'не обнаружены', s.route_contamination ? 'probe-warn' : 'probe-ok'],
  ];
  $('#systemProbe').innerHTML = values.map(([name, value, okOrClass]) => {
    const cls = typeof okOrClass === 'string' ? okOrClass : (okOrClass ? 'probe-ok' : 'probe-no');
    return `<div class="probe-row"><span>${esc(name)}</span><b class="${cls}">${esc(value)}</b></div>`;
  }).join('');
}

function routeSelectHTML(service) {
  const options = [...state.routeOptions];
  if (service.route && !options.some((o) => o.id === service.route)) {
    options.push({ id: service.route, name: service.route, installed: true, selectable: true, kind: 'custom' });
  }
  return `<select class="route-select" data-route-id="${esc(service.id)}">${options.map((o) => {
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
    return `<article class="service-card ${s.enabled ? 'enabled' : ''} ${dirty}">
      <div class="service-top">
        <div class="service-id"><div class="service-badge">${esc(s.icon || 'AF')}</div><div><h3>${esc(s.name)}</h3><p>${esc(s.description || '')}</p></div></div>
        <button class="toggle ${s.enabled ? 'on' : ''}" data-toggle-id="${esc(s.id)}" aria-label="${s.enabled ? 'Выключить' : 'Включить'} ${esc(s.name)}"><i></i></button>
      </div>
      <div class="service-control-grid">
        <div><span class="control-label">Желаемый маршрут</span>${routeSelectHTML(s)}</div>
        <div><span class="control-label">AUTO / фактический план</span><div class="resolved ${resolvedClass}"><i></i><span>${esc(routeLabel(s.planned_engine))}</span></div></div>
        <div class="service-actions"><button class="mini-button" data-detail-id="${esc(s.id)}" title="Технические детали">i</button><button class="mini-button" data-test-id="${esc(s.id)}" title="Dry-run маршрута">⚡</button></div>
      </div>
      <div class="service-meta"><span>${esc(s.category || 'Без категории')} · ${Number((s.domains || []).length).toLocaleString('ru-RU')} доменов</span><span class="${s.dirty ? 'dirty-tag' : 'applied-tag'}">${s.dirty ? `изменено · применено: ${esc(appliedText)}` : `применено: ${esc(appliedText)}`}</span></div>
    </article>`;
  }).join('') || '<div class="empty-inline">Ничего не найдено</div>';

  $$('[data-toggle-id]').forEach((button) => button.addEventListener('click', () => toggleService(button.dataset.toggleId)));
  $$('.route-select[data-route-id]').forEach((select) => select.addEventListener('change', () => changeRoute(select.dataset.routeId, select.value)));
  $$('[data-detail-id]').forEach((button) => button.addEventListener('click', () => showServiceDetails(button.dataset.detailId)));
  $$('[data-test-id]').forEach((button) => button.addEventListener('click', () => showServicePlan(button.dataset.testId)));
}

function renderOverviewServices() {
  const chosen = [...state.services].sort((a, b) => Number(b.enabled) - Number(a.enabled) || a.name.localeCompare(b.name, 'ru')).slice(0, 7);
  $('#overviewServices').innerHTML = chosen.map((s) => {
    const desired = s.enabled ? routeLabel(s.route) : 'OFF';
    const planned = s.enabled ? routeLabel(s.planned_engine) : '—';
    const applied = s.applied_enabled ? routeLabel(s.applied_route) : 'OFF';
    const desiredClass = s.route === 'auto' ? 'auto' : (routeAvailable(s.route) ? 'good' : 'warn');
    const appliedClass = s.applied_enabled ? 'good' : '';
    return `<div class="overview-service">
      <div class="service-name"><div class="service-badge">${esc(s.icon || 'AF')}</div><div><b>${esc(s.name)}</b><small>${esc(s.category || '')}${s.dirty ? ' · draft' : ''}</small></div></div>
      <span class="route-pill ${desiredClass}">${esc(desired)}${s.route === 'auto' && s.enabled ? ` → ${esc(planned)}` : ''}</span>
      <span class="overview-arrow">→</span>
      <span class="route-pill ${appliedClass} applied-route">${esc(applied)}</span>
    </div>`;
  }).join('');
}

function renderReadiness() {
  const sys = state.system || {};
  const installed = state.engines.filter((e) => e.installed).length;
  const sourceReady = state.sources.filter((s) => s.ready).length;
  const rows = [
    ['Entware /opt', sys.opt_ready && sys.opkg, sys.opt_ready && sys.opkg ? 'готов' : 'нужно проверить'],
    ['WAN interface', !!sys.wan_interface, sys.wan_interface || 'не определён'],
    ['Netfilter / NFQUEUE', !!sys.nfqueue, sys.nfqueue ? 'обнаружен' : 'нужен для nfqws2'],
    ['TUN', !!sys.tun, sys.tun ? 'доступен' : 'может понадобиться proxy/VPN'],
    ['Route contamination', !sys.route_contamination, sys.route_contamination ? `внешние маршруты: ${(sys.external_tunnels || []).join(', ') || 'обнаружены'}` : 'не обнаружено'],
    ['Движки', installed > 0, installed ? `${installed} установлено` : 'пока чистая среда'],
    ['Источники', sourceReady > 0, `${sourceReady} / ${state.sources.length} готовы`],
    ['Pending config', !state.status.pending_changes, state.status.pending_changes ? 'есть draft' : 'чисто'],
  ];
  $('#readinessMini').innerHTML = rows.map(([name, ok, detail]) => `<div class="readiness-row"><div><b>${esc(name)}</b><small>${esc(detail)}</small></div><span class="ready-state ${ok ? '' : 'warn'}">${ok ? 'OK' : 'CHECK'}</span></div>`).join('');
}

function renderEngines() {
  const cards = state.engines.map((e) => {
    const cls = e.running ? 'running' : e.installed ? 'installed' : '';
    const text = e.running ? 'RUNNING' : e.installed ? 'INSTALLED' : 'NOT FOUND';
    return `<article class="engine-card"><div class="engine-top"><b>${esc(e.name)}</b><span class="engine-state ${cls}">${text}</span></div><p>${esc(e.description || '')}</p></article>`;
  }).join('');
  $('#engineCards').innerHTML = cards;
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
  if (!engine) return ['UNKNOWN', ''];
  if (engine.running) return ['RUNNING', 'running'];
  if (engine.installed) return ['INSTALLED', 'installed'];
  return ['NOT FOUND', ''];
}

function renderEngineControl() {
  if (!state.engineConfigs.length) {
    $('#engineControlList').innerHTML = '<div class="empty-inline">Нет описаний движков</div>';
    $('#engineSelectedHead').innerHTML = '';
    return;
  }
  if (!state.engineConfigs.some((e) => e.id === state.selectedEngine)) state.selectedEngine = state.engineConfigs[0].id;
  const engine = selectedEngineView();
  if (!engine.files.some((f) => f.id === state.selectedEngineFile)) state.selectedEngineFile = engine.files[0]?.id || 'main';
  const file = selectedEngineFile();

  $('#engineSafeBadge').textContent = state.status.safe_mode ? 'SAFE MODE · LIVE WRITE OFF' : 'ACTIVE APPLY';
  $('#engineSafeBadge').classList.toggle('active-apply', !state.status.safe_mode);
  $('#engineControlList').innerHTML = state.engineConfigs.map((e) => {
    const [text, cls] = engineStatusText(e);
    const drafts = (e.files || []).filter((f) => f.staged).length;
    return `<button class="engine-control-item ${e.id === state.selectedEngine ? 'active' : ''}" data-engine-id="${esc(e.id)}">
      <div><b>${esc(e.name)}</b><small>${esc(e.description || '')}</small></div>
      <div class="engine-control-meta"><span class="engine-state ${cls}">${text}</span>${drafts ? `<span class="draft-count">${drafts} draft</span>` : ''}</div>
    </button>`;
  }).join('');
  $$('[data-engine-id]').forEach((b) => b.addEventListener('click', () => selectEngine(b.dataset.engineId)));

  const [statusText, statusClass] = engineStatusText(engine);
  $('#engineSelectedHead').innerHTML = `<div><h3>${esc(engine.name)}</h3><p>${esc(engine.description || '')}</p></div><div class="engine-selected-meta"><span class="engine-state ${statusClass}">${statusText}</span><span>${(engine.files || []).length} файлов</span></div>`;

  $('#engineFileSelect').innerHTML = (engine.files || []).map((f) => `<option value="${esc(f.id)}" ${f.id === state.selectedEngineFile ? 'selected' : ''}>${esc(f.name)}${f.staged ? ' · draft' : ''}${f.sensitive ? ' · secret' : ''}</option>`).join('');
  $('#engineFilesTable').innerHTML = (engine.files || []).map((f) => `<div class="engine-file-row ${f.id === state.selectedEngineFile ? 'active' : ''}" data-engine-file-row="${esc(f.id)}"><div><b>${esc(f.name)}</b><small>${esc(f.description || '')}</small></div><div class="engine-file-meta"><span>${esc(f.syntax)}</span><span>${f.exists ? formatBytes(f.size) : 'нет live-файла'}</span>${f.staged ? '<span class="draft-count">DRAFT</span>' : ''}${f.sensitive ? '<span class="secret-tag">SECRET</span>' : ''}</div><code>${esc(f.path || '—')}</code></div>`).join('');
  $$('[data-engine-file-row]').forEach((row) => row.addEventListener('click', () => selectEngineFile(row.dataset.engineFileRow)));

  $('#engineCheckRunning').textContent = engine.running ? 'да' : engine.installed ? 'установлен, но остановлен' : 'нет';
  $('#engineCheckApply').textContent = state.status.safe_mode ? 'запрещён Safe Mode' : 'разрешён после validate';

  const sensitive = !!file?.sensitive;
  const loadedSame = state.engineLoaded && state.engineLoaded.engine_id === engine.id && state.engineLoaded.file_id === file?.id;
  const editor = $('#engineEditor');
  editor.disabled = sensitive;
  $('#engineSaveDraft').disabled = sensitive;
  $('#engineImport').disabled = sensitive;
  $('#engineExport').disabled = sensitive;
  $('#engineApplyConfig').disabled = !!state.status.safe_mode || sensitive || !file?.staged;
  $('#engineDiscardDraft').disabled = !file?.staged;

  if (!file) {
    editor.value = '';
    editor.disabled = true;
    $('#engineFileState').textContent = 'Нет файлов';
    $('#engineEditorMessage').textContent = '';
    return;
  }

  const fileState = [file.exists ? 'LIVE' : 'NO LIVE', file.staged ? 'DRAFT' : '', file.sensitive ? 'SECRET' : '', file.modified_at ? `изменён ${timeAgo(file.modified_at)} назад` : ''].filter(Boolean).join(' · ');
  $('#engineFileState').textContent = fileState;

  if (sensitive) {
    editor.value = '';
    editor.placeholder = 'Содержимое скрыто: перед работой с секретами будет добавлена обязательная авторизация.';
    $('#engineEditorMessage').innerHTML = '<b class="probe-no">AUTH REQUIRED</b> · UI не читает и не экспортирует ключи/UUID/пароли в этой Lab-сборке.';
  } else {
    editor.placeholder = 'Конфигурация / список';
    if (loadedSame && !state.engineEditorDirty) editor.value = state.engineLoaded.content || '';
    $('#engineEditorMessage').textContent = state.engineEditorDirty ? 'Есть локальные изменения. Нажмите «Сохранить draft».' : (loadedSame ? `Источник: ${state.engineLoaded.source || '—'}` : 'Загрузка…');
    if (!loadedSame && !state.engineEditorDirty) void loadEngineFile();
  }

  const v = state.engineValidation;
  if (v && v.engine_id === engine.id && v.file_id === file.id) {
    $('#engineCheckBasic').textContent = v.ok ? 'PASS' : 'FAIL';
    $('#engineCheckBasic').className = v.ok ? 'probe-ok' : 'probe-no';
    $('#engineCheckNative').textContent = v.native ? 'да' : 'нет / basic';
    $('#engineCheckOutput').textContent = v.output || '—';
  } else {
    $('#engineCheckBasic').textContent = 'не запускалась';
    $('#engineCheckBasic').className = '';
    $('#engineCheckNative').textContent = '—';
    $('#engineCheckOutput').textContent = 'Нажмите «Проверить» во вкладке «Конфиг».';
  }
}

async function selectEngine(id) {
  if (state.engineEditorDirty && !confirm('Есть несохранённые локальные изменения редактора. Переключить движок и потерять их?')) return;
  state.selectedEngine = id;
  const engine = selectedEngineView();
  state.selectedEngineFile = engine?.files?.[0]?.id || 'main';
  state.engineEditorDirty = false;
  state.engineLoaded = null;
  state.engineValidation = null;
  renderEngineControl();
}

async function selectEngineFile(id) {
  if (state.engineEditorDirty && !confirm('Есть несохранённые локальные изменения редактора. Переключить файл и потерять их?')) {
    $('#engineFileSelect').value = state.selectedEngineFile;
    return;
  }
  state.selectedEngineFile = id;
  state.engineEditorDirty = false;
  state.engineLoaded = null;
  state.engineValidation = null;
  renderEngineControl();
}

async function loadEngineFile(force = false) {
  const engine = selectedEngineView();
  const file = selectedEngineFile();
  if (!engine || !file || file.sensitive) return;
  if (!force && state.engineEditorDirty) return;
  try {
    const content = await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/file?file=${encodeURIComponent(file.id)}`);
    state.engineLoaded = content;
    state.engineEditorDirty = false;
    $('#engineEditor').value = content.content || '';
    $('#engineEditorMessage').textContent = content.source === 'missing' ? 'Live-файл отсутствует. Можно импортировать или создать draft.' : `Источник: ${content.source}`;
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
  if (!engine || !file || file.sensitive) return;
  const button = $('#engineSaveDraft');
  button.disabled = true;
  try {
    const staged = await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/file?file=${encodeURIComponent(file.id)}`, {
      method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ content: $('#engineEditor').value }),
    });
    state.engineLoaded = staged;
    state.engineEditorDirty = false;
    state.engineValidation = null;
    await refreshEngineConfigs();
    $('#engineEditorMessage').textContent = 'Draft сохранён. Live-конфиг не изменён.';
  } catch (error) {
    showDetails({ error: error.message }, 'Не удалось сохранить draft');
  } finally { button.disabled = false; }
}

async function validateEngineFile() {
  const engine = selectedEngineView(); const file = selectedEngineFile();
  if (!engine || !file) return;
  if (state.engineEditorDirty && !file.sensitive) {
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
    state.engineLoaded = null; state.engineEditorDirty = false; state.engineValidation = null;
    await refreshEngineConfigs();
    await loadEngineFile(true);
  } catch (error) { showDetails({ error: error.message }, 'Не удалось отменить draft'); }
}

async function applyEngineConfig() {
  const engine = selectedEngineView(); const file = selectedEngineFile();
  if (!engine || !file) return;
  if (state.status.safe_mode) { showDetails({ message: 'Safe Mode блокирует запись в live-конфиги. Draft и validation можно тестировать безопасно.' }, 'Safe Mode'); return; }
  if (!confirm(`Применить draft ${engine.name} / ${file.name}? Перед записью будет создан backup.`)) return;
  try {
    const result = await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/apply?file=${encodeURIComponent(file.id)}`, { method: 'POST' });
    state.engineLoaded = null; state.engineValidation = null; state.engineEditorDirty = false;
    await refreshEngineConfigs();
    showDetails(result, 'Конфиг применён');
  } catch (error) { showDetails({ error: error.message }, 'Apply заблокирован'); }
}

function importEngineFile() { const f = selectedEngineFile(); if (f && !f.sensitive) $('#engineImportInput').click(); }

async function handleEngineImport(event) {
  const picked = event.target.files?.[0]; event.target.value = '';
  const engine = selectedEngineView(); const file = selectedEngineFile();
  if (!picked || !engine || !file || file.sensitive) return;
  if (picked.size > 2 * 1024 * 1024) { showDetails({ error: 'Файл больше 2 МБ' }, 'Импорт отклонён'); return; }
  try {
    const text = await picked.text();
    $('#engineEditor').value = text; state.engineEditorDirty = true; switchEngineTab('config'); renderEngineControl();
    $('#engineEditor').value = text; // render keeps loaded text, so restore imported local buffer explicitly.
    $('#engineEditorMessage').textContent = `Импортирован локально: ${picked.name}. Нажмите «Сохранить draft».`;
  } catch (error) { showDetails({ error: error.message }, 'Ошибка импорта'); }
}

async function exportEngineFile() {
  const engine = selectedEngineView(); const file = selectedEngineFile();
  if (!engine || !file || file.sensitive) return;
  try {
    const content = await api(`/api/v1/engine-configs/${encodeURIComponent(engine.id)}/file?file=${encodeURIComponent(file.id)}`);
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
  return ({ pass: 'PASS', partial: 'PARTIAL', fail: 'FAIL', 'not-ready': 'NOT READY', 'adapter-pending': 'ADAPTER', pending: 'PENDING' })[status] || String(status || '—').toUpperCase();
}

function renderTestLab() {
  const current = state.testlab?.current || [];
  const counts = { pass: 0, partial: 0, fail: 0, 'not-ready': 0 };
  current.forEach((r) => { counts[r.status] = (counts[r.status] || 0) + 1; });
  $('#testSummary').innerHTML = [
    ['PASS', counts.pass, 'pass'], ['PARTIAL', counts.partial, 'partial'], ['FAIL', counts.fail, 'fail'], ['Проверено', current.length, ''],
  ].map(([label, n, cls]) => `<div class="test-stat ${cls}"><strong>${n}</strong><span>${label}</span></div>`).join('');
  $('#testCurrentRows').innerHTML = current.map((r) => `<tr><td><b>${esc(r.service_name)}</b><small>${esc(r.probe_url || '')}</small></td><td><span class="test-status ${esc(r.status)}">${testStatusLabel(r.status)}</span></td><td>${r.http_status || '—'}</td><td>${Number.isFinite(Number(r.latency_ms)) ? `${r.latency_ms} ms` : '—'}</td><td>${r.route === 'current' ? 'CURRENT<small>текущая применённая</small>' : esc(routeLabel(r.route))}</td><td>${esc(r.detail || '—')}</td></tr>`).join('') || '<tr><td colspan="6"><div class="empty-inline">Проверки ещё не запускались</div></td></tr>';

  const routes = state.routeOptions.filter((o) => o.id !== 'auto');
  const cells = state.testlab?.matrix || [];
  const by = new Map(cells.map((c) => [`${c.service_id}\x00${c.route}`, c]));
  const latest = new Map(current.map((r) => [r.service_id, r]));
  $('#testMatrix').innerHTML = `<table class="matrix-table"><thead><tr><th>Сервис</th><th>Текущий</th>${routes.map((r) => `<th>${esc(r.name || routeLabel(r.id))}</th>`).join('')}</tr></thead><tbody>${state.services.map((s) => {
    const cur = latest.get(s.id);
    return `<tr><td><b>${esc(s.name)}</b></td><td>${cur ? `<span class="matrix-cell ${esc(cur.status)}" title="${esc(cur.detail || '')}">${testStatusLabel(cur.status)}</span>` : '<span class="matrix-cell pending">—</span>'}</td>${routes.map((route) => {
      const c = by.get(`${s.id}\x00${route.id}`);
      const status = c?.status || 'pending';
      return `<td><span class="matrix-cell ${esc(status)}" title="${esc(c?.reason || '')}">${testStatusLabel(status)}</span></td>`;
    }).join('')}</tr>`;
  }).join('')}</tbody></table>`;
}

async function refreshTestLab() {
  try { state.testlab = await api('/api/v1/testlab'); renderTestLab(); } catch (error) { showDetails({ error: error.message }, 'Ошибка Test Lab'); }
}

async function runCurrentTests() {
  const button = $('#runCurrentTests'); button.disabled = true; button.textContent = 'Проверка…';
  const enabledOnly = $('#testScope').value === 'enabled';
  const ids = enabledOnly ? state.services.filter((s) => s.applied_enabled).map((s) => s.id) : [];
  if (enabledOnly && ids.length === 0) {
    button.disabled = false; button.textContent = 'Проверить текущую конфигурацию';
    showDetails({ message: 'Нет применённых включённых сервисов. Выберите «Все сервисы» или сначала примените сервисный draft.' }, 'Нечего проверять');
    return;
  }
  try {
    const result = await api('/api/v1/testlab/current', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ services: ids }) });
    await refreshTestLab();
    showDetails(result, 'Проверка текущей конфигурации');
  } catch (error) { showDetails({ error: error.message }, 'Тест завершился ошибкой'); }
  finally { button.disabled = false; button.textContent = 'Проверить текущую конфигурацию'; }
}

function sourceStateText(s) {
  if (s.last_error) return ['ошибка', 'bad'];
  if (s.ready) return ['готов', 'good'];
  return ['не загружен', ''];
}

function renderSources() {
  const ready = state.sources.filter((s) => s.ready).length;
  const enabled = state.sources.filter((s) => s.enabled).length;
  $('#sourceOverview').innerHTML = `<div class="source-stat"><strong>${ready}</strong><span>из ${state.sources.length} источников готовы · ${enabled} включено</span></div><div class="source-mini-list">${state.sources.slice(0, 8).map((s) => `<span class="source-mini">${esc(s.name)}</span>`).join('')}</div>`;
  $('#sourceRows').innerHTML = state.sources.map((s) => {
    const [text, cls] = sourceStateText(s);
    return `<tr><td><b>${esc(s.name)}</b><div class="source-role">${esc(s.url || '')}</div></td><td>${esc(s.kind || 'reference')}</td><td><span class="source-state"><i class="state-dot ${cls}"></i>${esc(text)}</span></td><td>${s.entries ? Number(s.entries).toLocaleString('ru-RU') : '—'}</td><td>${esc(s.last_error || '—')}</td></tr>`;
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
  $('#telemetryState').textContent = (payload.active || 0) > 0 ? 'live route evidence' : 'ожидание dataplane adapter';
  $('#connectionRows').innerHTML = filtered.map((c) => {
    const chainData = c.chain && c.chain.length ? c.chain : [c.service_name || 'Unknown', routeLabel(c.route)];
    const chain = chainData.map((part) => `<span class="chain-node">${esc(part)}</span>`).join('<b class="chain-arrow">→</b>');
    const host = c.host || c.destination_ip || '—';
    const source = c.source_name || c.source_ip || '—';
    return `<tr class="${c.active ? '' : 'closed-row'}"><td><div class="chain">${chain}</div><small class="evidence">${esc(c.evidence || '')}</small></td><td><b>${esc(host)}</b>${c.destination_port ? `<small>:${esc(c.destination_port)}</small>` : ''}</td><td><span class="protocol">${esc((c.protocol || '—').toUpperCase())}</span></td><td>${esc(source)}</td><td><span class="traffic">↑ ${formatBytes(c.upload)} &nbsp; ↓ ${formatBytes(c.download)}</span></td><td>${timeAgo(c.updated_at || c.started_at)}</td></tr>`;
  }).join('');
  $('#connectionEmpty').style.display = filtered.length ? 'none' : 'grid';
}

function renderSettings() {
  const s = state.status || {};
  $('#settingSafeMode').textContent = s.safe_mode ? 'ON' : 'OFF';
  $('#settingPending').textContent = s.pending_changes ? 'есть' : 'нет';
  $('#settingEngineDrafts').textContent = s.engine_config_drafts || 0;
  $('#settingApplied').textContent = s.last_applied_at ? new Date(s.last_applied_at).toLocaleString('ru-RU') : '—';
  $('#settingRevision').textContent = `${s.revision || 0} / ${s.applied_revision || 0}`;
}

async function refreshCoreAfterEdit() {
  const [status, services] = await Promise.all([api('/api/v1/status'), api('/api/v1/services')]);
  state.status = status;
  state.services = services;
  renderStatus();
  renderServices();
  renderOverviewServices();
  renderReadiness();
  renderSettings();
}

async function saveService(service) {
  return api(`/api/v1/services/${encodeURIComponent(service.id)}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ enabled: service.enabled, route: service.route }),
  });
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
  if (service) showDetails(service, service.name);
}

async function showServicePlan(id) {
  try {
    const plan = await api('/api/v1/plan');
    const row = (plan.routes || []).find((r) => r.id === id);
    showDetails(row || { service: id, note: 'Сервис выключен. Включите его для появления в dry-run.' }, 'Dry-run сервиса');
  } catch (error) {
    showDetails({ error: error.message }, 'Ошибка dry-run');
  }
}

async function applyDraft() {
  const buttons = [$('#applyChanges'), $('#applySettings')];
  buttons.forEach((b) => { b.disabled = true; b.textContent = 'Применение…'; });
  try {
    const result = await api('/api/v1/apply', { method: 'POST' });
    await refreshCoreAfterEdit();
    showDetails(result, 'Apply завершён');
  } catch (error) {
    showDetails({ error: error.message }, 'Apply не выполнен');
  } finally {
    buttons[0].disabled = false; buttons[0].textContent = 'Применить';
    buttons[1].disabled = false; buttons[1].textContent = 'Применить draft';
  }
}

async function discardDraft() {
  try {
    const result = await api('/api/v1/discard', { method: 'POST' });
    await refreshCoreAfterEdit();
    showDetails(result, 'Draft отменён');
  } catch (error) {
    showDetails({ error: error.message }, 'Не удалось отменить draft');
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
    showDetails({ message: 'Включённые operational-источники обновлены и провалидированы.', sources: state.sources }, 'Источники обновлены');
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
    showDetails({ error: error.message }, 'Ошибка Preflight');
  }
}

async function showPlan() {
  try {
    const plan = await api('/api/v1/plan');
    $('#planBox').textContent = JSON.stringify(plan, null, 2);
  } catch (error) {
    $('#planBox').textContent = `ERROR: ${error.message}`;
  }
}

async function exportConfig() {
  try {
    const data = await api('/api/v1/config/export');
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `razvilka-config-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    showDetails({ error: error.message }, 'Ошибка экспорта');
  }
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
      const live = JSON.parse(event.data);
      const closed = (state.connections.connections || []).filter((c) => !c.active);
      state.connections.connections = [...live, ...closed];
      state.connections.active = live.length;
      renderConnections();
    } catch (_) {
      // Ignore malformed one-off events; REST refresh remains fallback.
    }
  });
  stream.onerror = () => {
    $('#telemetryState').textContent = 'SSE reconnect…';
  };
}

function bindEvents() {
  $$('[data-view]').forEach((button) => button.addEventListener('click', () => setView(button.dataset.view)));
  $('#serviceSearch').addEventListener('input', renderServices);
  $('#serviceCategory').addEventListener('change', renderServices);
  $('#connectionFilter').addEventListener('input', renderConnections);
  $('#showClosed').addEventListener('change', renderConnections);
  $('#refreshAll').addEventListener('click', async () => { await refreshAll(); await showPlan(); });
  $('#refreshSources').addEventListener('click', refreshSources);
  $('#refreshSystem').addEventListener('click', refreshSystem);
  $('#showPlan').addEventListener('click', showPlan);
  $('#applyChanges').addEventListener('click', applyDraft);
  $('#applySettings').addEventListener('click', applyDraft);
  $('#discardChanges').addEventListener('click', discardDraft);
  $('#discardSettings').addEventListener('click', discardDraft);
  $('#exportConfig').addEventListener('click', exportConfig);
  $('#engineFileSelect').addEventListener('change', (e) => selectEngineFile(e.target.value));
  $('#engineEditor').addEventListener('input', () => { state.engineEditorDirty = true; $('#engineEditorMessage').textContent = 'Есть локальные изменения. Нажмите «Сохранить draft».'; });
  $('#engineReload').addEventListener('click', async () => { if (!state.engineEditorDirty || confirm('Перечитать файл и потерять локальные изменения?')) { state.engineEditorDirty = false; state.engineLoaded = null; await loadEngineFile(true); renderEngineControl(); } });
  $('#engineSaveDraft').addEventListener('click', saveEngineDraft);
  $('#engineValidate').addEventListener('click', validateEngineFile);
  $('#engineDiscardDraft').addEventListener('click', discardEngineConfigDraft);
  $('#engineApplyConfig').addEventListener('click', applyEngineConfig);
  $('#engineImport').addEventListener('click', importEngineFile);
  $('#engineImportInput').addEventListener('change', handleEngineImport);
  $('#engineExport').addEventListener('click', exportEngineFile);
  $$('.engine-tab').forEach((b) => b.addEventListener('click', () => switchEngineTab(b.dataset.engineTab)));
  $('#runCurrentTests').addEventListener('click', runCurrentTests);
  $('#refreshTestLab').addEventListener('click', refreshTestLab);
  $('#hideDetails').addEventListener('click', () => $('#detailsPanel').classList.remove('open'));
}

bindEvents();
Promise.all([refreshAll(), showPlan()]).then(() => startConnectionStream());
setInterval(refreshConnections, 15000);
