/* Simple mode: the owner's main use is to add or remove services; the
 * autopilot does the rest. The home page shows one status line, the managed
 * services and a catalog search. Everything else stays in advanced mode.
 * Pure helpers are exported for tests; actions reuse interfaceManage. */
(function (root) {
  'use strict';
  // Runtime labels are history, not a proof bound to the current route.
  const HISTORICAL = new Set(['healthy', 'applied']);
  const RECHECK = new Set(['pending', 'checking']);
  const PROGRESS = new Set(['pending', 'checking', 'applying', 'searching', 'scope-pending', 'removal-pending', 'rate-limited']);
  // States the autopilot cannot leave on its own: the owner has to change the
  // mode, a list, the service or the journal first. They are not retried.
  const WAITS_FOR_OWNER = new Set(['capability-refused', 'excluded', 'manual-change', 'definition-changed', 'unsupported-scenario', 'requires-review', 'component-stopped', 'component-unavailable', 'domain-route-unavailable']);
  const SHORT = {
    pending: 'Ждёт проверки', checking: 'Проверяется', applying: 'Включается', searching: 'Подбирается способ обхода',
    'scope-pending': 'Применяется к устройствам', 'removal-pending': 'Убирается', 'rate-limited': 'Пауза между попытками',
    'component-stopped': 'Нужный компонент не запущен', 'component-unavailable': 'Нужный компонент не готов',
    'apply-refused': 'Не удалось включить, автопилот повторит', unconfirmed: 'Проверка не дала ответа, автопилот повторит',
    'service-unconfirmed': 'Сервис отказал через несколько узлов, автопилот повторит позже',
    'domain-route-unavailable': 'Нет подтверждённого обхода для доменного сервиса',
    'capability-refused': 'Недоступно в текущем режиме', excluded: 'Не разрешён списком или исключениями',
    'requires-review': 'Нужна проверка журнала', 'manual-change': 'Изменён вручную', paused: 'На паузе',
    'network-unknown': 'Сеть не определена', 'checker-unavailable': 'Проверка временно недоступна',
    'catalog-unavailable': 'Источник подключений недоступен', 'definition-changed': 'Состав сервиса изменился',
    'unsupported-scenario': 'Нет подходящей проверки', 'origin-expired': 'Истёк источник подключения',
    'removal-blocked': 'Снятие приостановлено'
  };

  function bucket(state) {
    if (!state || PROGRESS.has(state) || HISTORICAL.has(state)) return 'progress';
    return 'problem';
  }

  function names(catalog, snapshot) {
    const out = {};
    for (const s of snapshot?.catalog_services || []) if (s?.id) out[s.id] = s.name || s.id;
    for (const s of catalog || []) if (s?.id) out[s.id] = s.name || out[s.id] || s.id;
    return out;
  }

  // updateNotice names a released update the panel already checked for.
  function updateNotice(update) {
    if (!update?.update_available || !update.can_prepare || !/^[0-9A-Za-z.+-]{1,40}$/.test(update.latest_version || '')) return null;
    return { version: update.latest_version, text: `Вышло обновление ${update.latest_version}` };
  }

  // model turns the autopilot snapshot into what the simple home renders.
  function model(snapshot, catalog, summaries = {}, recoveryRequired = false) {
    if (recoveryRequired) return { phase: 'recovery', services: [], tone: 'problem', title: 'Нужно восстановление', text: 'Панель отвечает. Чтение состояния и изменения приостановлены до проверки журнала. Работа обходов пока не подтверждена.' };
    if (!snapshot || typeof snapshot !== 'object') return { phase: 'loading', services: [], tone: 'progress', title: 'Загружаем состояние…', text: '' };
    const policy = snapshot.policy || {};
    const retained = snapshot.observation?.state === 'retained';
    const label = names(catalog, snapshot);
    const services = Object.entries(snapshot.services || {}).filter(([, s]) => s && !s.removing).map(([id, spec]) => {
      const runtime = snapshot.runtime?.[id] || {};
      const state = runtime.state || 'pending';
      const detail = String(runtime.message || '').slice(0, 220);
      if (spec.enabled !== true) return { id, name: label[id] || id, state, bucket: 'problem', short: 'Автоподбор на паузе', detail, owner: true };
      // A waiting service says when it continues ("…через 12 мин.").
      const next = state === 'rate-limited' && /Следующая попытка[^.]*через \d+ мин/.exec(detail);
      const applied = snapshot.applied_services?.[id];
      const proof = summaries[id];
      const matched = applied?.enabled === true && proof?.route && proof.route === (applied.route || applied.mode);
      if (matched && proof.kind === 'bad') return { id, name: label[id] || id, state, bucket: 'problem', short: 'Проверка не пройдена', detail: proof.detail || detail };
      if (retained) return { id, name: label[id] || id, state, bucket: 'progress', short: 'Сохранённые настройки · нужна свежая проверка', detail: 'Показаны последние настройки. Текущее состояние автопилота ещё не подтверждено.' };
      if (HISTORICAL.has(state)) {
        const verified = matched && proof.kind === 'good';
        return { id, name: label[id] || id, state, bucket: verified ? 'ok' : 'progress', short: verified ? 'Работает' : applied?.enabled ? 'Включён · нужна свежая проверка' : 'Ожидает применения', detail: verified ? proof.detail || detail : detail };
      }
      // Retain the applied assignment during recheck without claiming access.
      if (RECHECK.has(state) && applied?.enabled) return { id, name: label[id] || id, state, bucket: 'progress', short: 'Включён · перепроверяется', detail };
      return { id, name: label[id] || id, state, bucket: bucket(state), short: next ? next[0] : SHORT[state] || 'Проверяется', detail, owner: WAITS_FOR_OWNER.has(state) };
    }).sort((a, b) => ({ problem: 0, progress: 1, ok: 2 }[a.bucket] - { problem: 0, progress: 1, ok: 2 }[b.bucket]) || a.name.localeCompare(b.name, 'ru'));
    const count = kind => services.filter(s => s.bucket === kind).length;
    const base = { services, managed: new Set(services.map(s => s.id)) };
    if (snapshot.blocked || snapshot.safe_mode) return { ...base, phase: 'recovery', tone: 'problem', title: 'Нужно восстановление', text: 'После сбоя изменения приостановлены. Проверьте восстановление; работа обхода пока не подтверждена.' };
    if (retained) return { ...base, phase: 'ready', tone: 'progress', title: 'Нет свежих данных автопилота', text: 'Показаны последние настройки. Текущее состояние обновляется; работа сервисов пока не подтверждена.' };
    if (!policy.setup_complete) return { ...base, phase: 'setup', tone: 'setup', title: 'Давайте настроим обход', text: 'Выберите сервисы и устройства. Автопилот проверит доступные способы подключения и подберёт подходящий для выбранных сервисов.' };
    if (snapshot.stopped) return { ...base, phase: 'off', tone: 'problem', title: 'Проект остановлен', text: 'Маршруты остановлены. Для включения используйте общий переключатель проекта. Настройки автопилота не снимают эту остановку.' };
    if (policy.enabled === false) return { ...base, phase: 'off', tone: 'problem', title: 'Автопилот выключен', text: 'Сервисы не проверяются и не переключаются. Включите автопилот в настройках.' };
    if (!services.length) return { ...base, phase: 'empty', tone: 'setup', title: 'Добавьте первый сервис', text: 'Нажмите «Добавить сервис» и выберите, что должно открываться.' };
    const problems = count('problem'), progress = count('progress');
    // Never promise a retry for a service that waits for the owner.
    const waiting = services.filter(s => s.bucket === 'problem' && s.owner).length;
    const problemText = !waiting ? 'Автопилот продолжает попытки. Причина указана у сервиса.'
      : waiting === problems ? 'Автопилот не может включить их сам. Причина и что сделать указаны у сервиса.'
      : 'Часть сервисов автопилот повторит сам, для остальных нужно ваше решение. Причина указана у сервиса.';
    if (problems) return { ...base, phase: 'ready', tone: 'problem', title: `${plural(problems, 'сервис пока не работает', 'сервиса пока не работают', 'сервисов пока не работают')}`, text: problemText };
    if (progress) return { ...base, phase: 'ready', tone: 'progress', title: `Настраиваю ${plural(progress, 'сервис', 'сервиса', 'сервисов')}…`, text: 'Автопилот проверяет сервисы по очереди, по одному за раз, и сам включает обход.' };
    return { ...base, phase: 'ready', tone: 'ok', title: 'Всё работает', text: `${plural(services.length, 'сервис открывается', 'сервиса открываются', 'сервисов открываются')} через проверенный обход.` };
  }

  function plural(n, one, few, many) {
    const m10 = n % 10, m100 = n % 100;
    const word = m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many;
    return `${n} ${word}`;
  }

  // available lists catalog services that are not managed yet, matching query.
  function available(catalog, managed, query, limit = 40) {
    const q = String(query || '').trim().toLocaleLowerCase('ru');
    return (catalog || []).filter(s => s?.id && !managed.has(s.id) && (!q || String(s.name || s.id).toLocaleLowerCase('ru').includes(q) || String(s.category || '').toLocaleLowerCase('ru').includes(q)))
      .sort((a, b) => String(a.name || a.id).localeCompare(String(b.name || b.id), 'ru')).slice(0, limit);
  }

  // communityAvailable lists community catalogue entries for the query that
  // are neither imported yet nor shadowed by a built-in service of that name.
  function communityAvailable(entries, catalog, limit = 20) {
    const names = new Set((catalog || []).map(s => String(s?.name || '').toLocaleLowerCase('ru')));
    return (entries || []).filter(e => e?.id && !e.imported && !names.has(String(e.name || '').toLocaleLowerCase('ru'))).slice(0, limit);
  }

  // quietEngine reports an engine row a simple home leaves out: nothing
  // assigned and the component is not installed.
  function quietEngine(assigned, label) {
    return String(assigned).trim() === '0' && /не установлен/i.test(String(label || ''));
  }

  // doctorView keeps the doctor's own wording; it only orders and labels.
  function doctorView(report) {
    if (!report || report.schema !== 1 || !Array.isArray(report.checks)) return null;
    const mark = { ok: '✓', warn: '!', fail: '✕' };
    return {
      status: ['ok', 'warn', 'fail'].includes(report.status) ? report.status : 'warn',
      summary: String(report.summary || ''),
      rows: report.checks.map(c => ({
        id: String(c.id || ''), title: String(c.title || ''), detail: String(c.detail || ''),
        status: ['ok', 'warn', 'fail'].includes(c.status) ? c.status : 'warn', mark: mark[c.status] || '!',
        items: (Array.isArray(c.items) ? c.items : []).filter(i => i && i.status !== 'ok').map(i => ({ name: String(i.name || i.id || ''), detail: String(i.detail || ''), status: i.status === 'fail' ? 'fail' : 'warn' })),
        action: c.action && /^[a-z-]{1,40}$/.test(c.action.view || '') ? { view: c.action.view, label: String(c.action.label || 'Открыть') } : null,
      })),
    };
  }

  // nightly reports whether a maintenance window installs updates itself.
  function nightly(window) { return window?.mode === 'install'; }

  // withNightly returns a policy copy whose window installs or only checks.
  function withNightly(policy, field, on) {
    const next = JSON.parse(JSON.stringify(policy));
    next[field] = { ...(next[field] || {}), mode: on ? 'install' : 'check' };
    return next;
  }

  root.RazvilkaSimpleHome = Object.freeze({ model, available, communityAvailable, updateNotice, quietEngine, doctorView, nightly, withNightly, bucket, plural });
  if (typeof document === 'undefined') return;

  const KEY = 'razvilka.simpleMode';
  const ui = { open: false, query: '', busy: '', error: '', key: '', community: [], communityQuery: null, communityState: '', note: '', doctor: '', report: null, doctorError: '', settingsBusy: '', settingsError: '', settingsKey: '' };
  let communityTimer = 0, communitySeq = 0;
  const html = value => (typeof esc === 'function' ? esc(value) : String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])));
  const snapshot = () => (typeof consoleSnapshot === 'object' ? consoleSnapshot : null);
  const catalog = () => (typeof state === 'object' && Array.isArray(state?.services) ? state.services : []);

  function enabled() {
    try { return localStorage.getItem(KEY) !== '0'; } catch (_) { return true; }
  }
  function setEnabled(on) {
    try { localStorage.setItem(KEY, on ? '1' : '0'); } catch (_) { /* per-viewer convenience only */ }
    apply();
  }
  function label() {
    const on = enabled();
    const toggle = document.getElementById('rzSimpleToggle');
    if (!toggle) return;
    toggle.setAttribute('aria-checked', String(!on));
    toggle.querySelector('b').textContent = on ? 'Простой режим' : 'Расширенный режим';
    toggle.querySelector('small').textContent = on ? 'Включить все разделы и ручные настройки' : 'Перейти к сервисам и устройствам';
  }
  function apply() {
    const on = enabled();
    document.body.classList.toggle('rz-simple', on);
    ensure();
    label();
    if (on && typeof state === 'object' && state && !['overview', 'devices', 'settings', 'onboard'].includes(state.currentView)) {
      document.querySelector('[data-main-nav="overview"]')?.click();
    }
    render(true);
    renderSettings(true);
    if (typeof renderWorkspaceControls === 'function') renderWorkspaceControls();
  }

  function ensure() {
    const view = document.getElementById('view-overview');
    if (!view) return null;
    let home = document.getElementById('rzSimpleHome');
    if (!home) {
      home = document.createElement('section');
      home.id = 'rzSimpleHome';
      home.className = 'rz-simple-home';
      home.setAttribute('aria-label', 'Мои сервисы');
      view.prepend(home);
      home.addEventListener('click', onClick);
      home.addEventListener('input', onInput);
      home.addEventListener('pointerdown', () => { ui.holding = true; });
      const release = () => { setTimeout(() => { ui.holding = false; }, 0); };
      document.addEventListener('pointerup', release, true);
      document.addEventListener('pointercancel', release, true);
    }
    if (!document.getElementById('rzSimpleToggle')) {
      const nav = document.querySelector('.nav-list');
      if (nav) {
        const toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.id = 'rzSimpleToggle';
        toggle.className = 'sidebar-foot rz-simple-toggle';
        toggle.setAttribute('role', 'switch');
        toggle.innerHTML = '<span><b></b><small></small></span><span aria-hidden="true" class="power-switch"><i></i></span>';
        toggle.addEventListener('click', () => setEnabled(!enabled()));
        nav.after(toggle);
        label();
      }
    }
    return home;
  }

  // icon reuses the panel's brand icons; a service without one gets its initials.
  function icon(service) {
    try {
      if (typeof consoleServiceIcon === 'function') return consoleServiceIcon(service);
    } catch (_) { /* fall back to initials */ }
    return html(String(service?.name || '?').slice(0, 2));
  }

  // routeName names the applied method in the panel's own words.
  function routeName(id) {
    const service = catalog().find(s => s.id === id);
    const route = service?.applied_state?.enabled ? service.applied_state.route : '';
    if (!route || route === 'auto') return '';
    try {
      if (typeof interfaceRouteName === 'function') return interfaceRouteName(route);
    } catch (_) { /* plain name below */ }
    return route.split(':')[0];
  }

  function serviceRow(s) {
    const busy = ui.busy === s.id;
    const via = s.bucket === 'ok' ? routeName(s.id) : '';
    const service = catalog().find(c => c.id === s.id) || { id: s.id, name: s.name };
    return `<li class="rz-sh-service rz-sh-${s.bucket}"><span class="rz-sh-icon" aria-hidden="true">${icon(service)}<span class="rz-sh-dot"></span></span><div><b>${html(s.name)}</b><small title="${html(s.detail)}">${html(via ? `${s.short} · ${via}` : s.short)}</small></div><button type="button" class="secondary" data-rz-sh-remove="${html(s.id)}" ${busy ? 'disabled' : ''}>${busy ? 'Убираем…' : 'Убрать'}</button></li>`;
  }

  function addPanel(m) {
    if (!ui.open) return '';
    const list = available(catalog(), m.managed, ui.query);
    const button = (attr, id) => `<button type="button" class="primary" ${attr}="${html(id)}" ${ui.busy ? 'disabled' : ''}>${ui.busy === id ? 'Добавляем…' : 'Добавить'}</button>`;
    const rows = list.map(s => `<li><span class="rz-sh-icon" aria-hidden="true">${icon(s)}</span><div><b>${html(s.name || s.id)}</b><small>${html(s.category || '')}</small></div>${button('data-rz-sh-add-id', s.id)}</li>`).join('');
    // The built-in catalogue is the starter set; the community catalogue
    // (domain lists published on GitHub) holds the rest.
    const community = communityAvailable(ui.community, catalog(), 60);
    const shared = community.map(e => `<li><span class="rz-sh-icon" aria-hidden="true">${icon({ id: String(e.id || '').replace(/^ga-/, ''), name: e.name })}</span><div><b>${html(e.name || e.id)}</b><small>${html([e.category, 'каталог сообщества'].filter(Boolean).join(' · '))}</small></div>${button('data-rz-sh-community', e.id)}</li>`).join('');
    const searching = ui.communityState === 'loading' ? '<li class="rz-sh-empty">Ищем в каталоге сообщества…</li>' : '';
    const failed = ui.communityState === 'error' ? '<li class="rz-sh-empty">Каталог сообщества сейчас недоступен; повторите поиск позже.</li>' : '';
    const empty = !catalog().length ? 'Каталог ещё загружается…' : ui.communityState !== 'ready' ? '' : 'Ничего не найдено. Попробуйте другое название или добавьте свой сайт.';
    const body = rows + shared + searching + failed || (empty ? `<li class="rz-sh-empty">${empty}</li>` : '');
    return `<div class="rz-sh-add"><label class="rz-sh-search"><span>Какой сервис должен открываться?</span><input type="search" data-rz-sh-query placeholder="Например, YouTube, Netflix или Discord" value="${html(ui.query)}" autocomplete="off"></label><ul class="rz-sh-catalog">${body}</ul>${ui.note ? `<p class="rz-sh-note" role="status">${html(ui.note)}</p>` : ''}<button type="button" class="link-button" data-rz-sh-custom>Нет в списке? Добавить свой сайт</button></div>`;
  }

  // An empty query lists the whole community catalogue, so opening "Add a
  // service" already shows what can be added without typing.
  function searchCommunity(query) {
    clearTimeout(communityTimer);
    const q = query.trim();
    if (typeof api !== 'function') { ui.community = []; ui.communityState = ''; return; }
    if (q === ui.communityQuery && ui.communityState === 'ready') return;
    ui.communityState = 'loading';
    const seq = ++communitySeq;
    communityTimer = setTimeout(async () => {
      try {
        const found = await api(`/api/v1/community/services?q=${encodeURIComponent(q)}`, { headers: { 'x-razvilka-read': 'passive' } });
        if (seq !== communitySeq) return;
        ui.community = Array.isArray(found) ? found : [];
        ui.communityQuery = q; ui.communityState = 'ready';
      } catch (_) {
        if (seq === communitySeq) { ui.community = []; ui.communityState = 'error'; }
      }
      render(true);
    }, 350);
  }

  // importCommunity previews the published list, imports exactly that
  // revision and hands the new service to the autopilot, as the community
  // dialog of advanced mode does. Overlapping entries never replace the
  // routes of other services.
  async function importCommunity(id) {
    if (typeof api !== 'function' || ui.busy) return;
    ui.busy = id; ui.error = ''; ui.note = 'Загружаем список доменов сервиса из каталога сообщества…'; render(true);
    try {
      const request = typeof workflowRequest === 'function' ? workflowRequest : (path, options) => api(path, options);
      const preview = await request(`/api/v1/community/services/${encodeURIComponent(id)}/preview`, {}, 50000);
      if (preview?.import_guard !== 'source-sha256' || !/^[a-f0-9]{64}$/.test(preview?.source_sha256 || '')) throw new Error('Сервер не подтвердил отпечаток списка. Попробуйте ещё раз.');
      if (preview.bundled_fallback === true && (typeof askConfirmation !== 'function' || !await askConfirmation('Добавить встроенный снимок Telegram?', `Официальный источник недоступен. Используется встроенный снимок от ${preview.source_date || 'не указано'}: ${preview.source_url || preview.entry?.source_page || 'источник не указан'}. Это не свежая загрузка. Проверьте ${preview.service?.cidrs?.length || 0} IP-сетей перед импортом.`, 'Добавить снимок'))) return;
      const conflicts = preview.conflicts || [];
      if (conflicts.length && (typeof askConfirmation !== 'function' || !await askConfirmation('Импортировать пересекающиеся списки?', `${conflicts.length} записей пересекаются с другими сервисами. Их маршруты не будут заменены.`, 'Импортировать'))) return;
      ui.note = 'Сохраняем сервис…'; render(true);
      const saved = await request(`/api/v1/community/services/${encodeURIComponent(id)}/import`, { method: 'POST', body: JSON.stringify({ allow_conflicts: conflicts.length > 0, refresh: false, expected_source_sha256: preview.source_sha256 }) }, 50000);
      if (!saved?.service?.id) throw new Error('Сервис не сохранён.');
      if (typeof refreshCoreAfterEdit === 'function') await refreshCoreAfterEdit();
      if(await interfaceManage(saved.service.id, true)!==true)throw new Error('Определение импортировано, но включение автоподбора не подтверждено. Обновите состояние.');
      ui.community = ui.community.filter(e => e.id !== id);
      ui.note = '';
      if (typeof interfaceToast === 'function') interfaceToast('Сервис добавлен. Автопилот проверит его — результат появится у сервиса.');
    } catch (e) {
      ui.note = '';
      ui.error = (typeof workflowError === 'function' ? workflowError(e) : e?.message) || 'Сервис не добавлен.';
    } finally {
      ui.busy = ''; ui.note = ''; render(true);
    }
  }

  function render(force = false) {
    if (!enabled()) return;
    const home = ensure();
    if (!home) return;
    const snap = snapshot();
    const summaries = typeof interfaceSummaries === 'function' ? interfaceSummaries() : {};
    // Reuse the shared TTL/revision-aware result; runtime history alone does
    // not carry the current network, route and configuration proof.
    const m = model(snap, catalog(), summaries, typeof interfaceRecoveryRequired === 'function' && interfaceRecoveryRequired());
    // The advanced home renders the engine summary; simple mode shows the same
    // block beside the services instead of its own copy of that logic. Periodic
    // inventory reads update state without rendering the hidden advanced home;
    // regenerate its summary so this copy cannot retain old runtime labels.
    if (typeof renderHomeEngineSummary === 'function' && typeof interfaceDataReady === 'function' && typeof state === 'object') {
      const ready = state.authenticated === true && !(typeof interfaceState === 'object' && interfaceState.authRevoked);
      const loaded = ready && interfaceDataReady('services');
      const fresh = loaded && !['error', 'busy'].includes(state.dataLoad?.services?.phase);
      renderHomeEngineSummary(summaries, loaded, fresh);
    }
    const engines = simpleEngines(document.getElementById('ui7HomeEngines')?.innerHTML || '');
    const notice = updateNotice(typeof state === 'object' ? state?.appUpdate : null);
    // What the router is busy with replaces the technical availability banner.
    const admission = typeof state === 'object' ? state?.panelAvailability?.admission : null;
    const activity = admission?.state === 'busy' && typeof admission.operation === 'string' ? admission.operation.replace(/^автопилот:\s*/i, '') : '';
    // A press that starts on a button must end on the same element, or the
    // browser drops the click; never replace the page under a held pointer.
    if (ui.holding && !force) return;
    const focused = document.activeElement?.matches?.('[data-rz-sh-query]');
    const action = m.phase === 'recovery' ? '<button type="button" class="primary" data-view="diagnostics">Открыть восстановление</button>' : m.phase === 'setup' ? '<button type="button" class="primary" data-view="onboard">Начать настройку</button>'
      : m.phase === 'off' ? '<button type="button" class="primary" data-view="autopilot">Открыть автопилот</button>' : '';
    const canAdd = m.phase === 'ready' || m.phase === 'empty';
    const doctor = doctorCard();
    const main = (canAdd ? `<div class="rz-sh-head"><h3>Мои сервисы</h3><button type="button" class="${ui.open ? 'secondary' : 'primary'}" data-rz-sh-toggle-add aria-expanded="${ui.open}">${ui.open ? 'Готово' : 'Добавить сервис'}</button></div>${addPanel(m)}`
        + (m.services.length ? `<ul class="rz-sh-list">${m.services.map(serviceRow).join('')}</ul>` : '') : '')
      + (ui.error ? `<p class="rz-sh-error" role="alert">${html(ui.error)}</p>` : '')
      + doctor
      + '<p class="rz-sh-foot">Автопилот сам подбирает способ обхода, проверяет доступ и переключается при сбое. Вам нужно только выбрать сервисы.</p>';
    home.classList.toggle('rz-sh-with-engines', !!engines);
    const updateRow = notice ? `<span class="rz-sh-update-dot" aria-hidden="true"></span><span>${html(notice.text)}</span><button type="button" class="secondary" data-rz-sh-update>Обновить</button>` : '';
    // Each part is replaced only when its own markup changed, so a changing
    // engine count never rebuilds the service buttons under the pointer.
    patch(home, 'status', `<span class="rz-sh-badge" aria-hidden="true"></span><div><h2>${html(m.title)}</h2><p>${html(m.text)}</p>${activity ? `<small class="rz-sh-activity">Сейчас: ${html(activity)}</small>` : ''}</div>${action}`, `rz-sh-status rz-sh-${m.tone}`, 'div');
    patch(home, 'update', updateRow, 'rz-sh-update', 'div');
    patch(home, 'main', main, 'rz-sh-main', 'div');
    patch(home, 'engines', engines, 'rz-sh-engines', 'aside');
    if (focused) {
      const input = home.querySelector('[data-rz-sh-query]');
      if (input) { input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
    }
  }

  // patch keeps one child per part in a fixed order and rewrites it only
  // when its markup or class changed. An empty part is hidden.
  function patch(home, part, markup, className, tag) {
    let node = home.querySelector(`:scope > [data-rz-part="${part}"]`);
    if (!node) {
      node = document.createElement(tag);
      node.dataset.rzPart = part;
      if (part === 'engines') node.setAttribute('aria-label', 'Обходы');
      if (part === 'update') node.setAttribute('role', 'status');
      home.append(node);
    }
    if (node.className !== className) node.className = className;
    node.hidden = !markup;
    if (node.dataset.rzHtml !== markup) { node.innerHTML = markup; node.dataset.rzHtml = markup; }
  }

  // simpleEngines keeps the engines in use or installed and folds the rest
  // into one line; the advanced home keeps the full grid.
  function simpleEngines(source) {
    if (!source) return '';
    const box = document.createElement('div');
    box.innerHTML = source;
    let hidden = 0;
    box.querySelectorAll('.ui7-engine-row').forEach(row => {
      const assigned = row.querySelector('.ui7-engine-count b')?.textContent || '';
      const label = row.querySelector('span:nth-child(2) small')?.textContent || '';
      if (quietEngine(assigned, label)) { row.remove(); hidden++; }
    });
    if (hidden) {
      const more = document.createElement('p');
      more.className = 'r5-caption rz-sh-engines-more';
      more.textContent = `Ещё ${plural(hidden, 'способ можно установить', 'способа можно установить', 'способов можно установить')} в расширенном режиме, если понадобится.`;
      (box.querySelector('.ui7-engine-summary') || box).after(more);
    }
    return box.innerHTML;
  }

  function doctorCard() {
    if (!ui.doctor) return '<button type="button" class="secondary rz-doc-open" data-rz-doc-run>Что-то не открывается? Проверить</button>';
    if (ui.doctor === 'running') return '<section class="rz-doc" aria-busy="true"><h3>Проверяем…</h3><p class="rz-sh-note">Интернет, DNS, состояние RAZVILKA, способы обхода и сервисы. Это займёт несколько секунд.</p></section>';
    const view = doctorView(ui.report);
    if (!view) return `<section class="rz-doc"><h3>Проверка не выполнена</h3><p class="rz-sh-error">${html(ui.doctorError || 'Роутер не ответил на проверку.')}</p><button type="button" class="secondary" data-rz-doc-run>Повторить</button></section>`;
    const rows = view.rows.map(r => `<li class="rz-doc-${r.status}"><span class="rz-doc-mark" aria-hidden="true">${r.mark}</span><div><b>${html(r.title)}</b><small>${html(r.detail)}</small>${r.items.length ? `<ul>${r.items.map(i => `<li class="rz-doc-${i.status}">${html(i.name)}${i.detail ? ` — ${html(i.detail)}` : ''}</li>`).join('')}</ul>` : ''}</div>${r.action ? `<button type="button" class="secondary" data-view="${html(r.action.view)}">${html(r.action.label)}</button>` : ''}</li>`).join('');
    return `<section class="rz-doc rz-doc-${view.status}"><div class="rz-sh-head"><h3>Проверка</h3><button type="button" class="secondary" data-rz-doc-close>Скрыть</button></div><p>${html(view.summary)}</p><ul class="rz-doc-list">${rows}</ul><div class="rz-doc-actions"><button type="button" class="secondary" data-rz-doc-run>Проверить ещё раз</button><button type="button" class="link-button" data-rz-doc-report>Скачать отчёт для поддержки</button></div><small class="rz-sh-note">В отчёт не попадают ключи, пароли, адреса устройств и история сайтов.</small></section>`;
  }

  async function runDoctor() {
    if (ui.doctor === 'running' || typeof api !== 'function') return;
    ui.doctor = 'running'; ui.doctorError = ''; render(true);
    try {
      ui.report = await api('/api/v1/panel/doctor', { headers: { 'x-razvilka-read': 'passive' }, readTimeoutMs: 15000 });
      ui.doctor = 'done';
    } catch (e) {
      ui.report = null; ui.doctor = 'failed'; ui.doctorError = e?.message || 'Роутер не ответил на проверку.';
    }
    render(true);
  }

  async function act(id, remove) {
    if (typeof interfaceManage !== 'function' || ui.busy) return;
    ui.busy = id; ui.error = ''; render(true);
    try {
      const accepted=await interfaceManage(id, true, remove);
      if (accepted!==true)return;
      if (typeof interfaceToast === 'function') interfaceToast(remove ? 'Сервис убирается. Его обход будет снят.' : 'Сервис добавлен. Автопилот проверит его — результат появится у сервиса.');
    } catch (e) {
      ui.error = e?.message || 'Действие не выполнено.';
    } finally {
      ui.busy = ''; render(true);
    }
  }

  function onClick(event) {
    const target = event.target.closest('button');
    if (!target) return;
    // These buttons are rendered after app.js binds its static navigation.
    // Delegate locally so opening a workspace never submits setup or Apply.
    if (target.dataset.view && typeof setView === 'function') { setView(target.dataset.view); return; }
    if (target.hasAttribute('data-rz-sh-toggle-add')) { ui.open = !ui.open; ui.error = ''; if (ui.open) searchCommunity(ui.query); render(true); if (ui.open) document.querySelector('[data-rz-sh-query]')?.focus(); return; }
    if (target.dataset.rzShAddId) { void act(target.dataset.rzShAddId, false); return; }
    if (target.dataset.rzShCommunity) { void importCommunity(target.dataset.rzShCommunity); return; }
    if (target.dataset.rzShRemove) { void act(target.dataset.rzShRemove, true); return; }
    if (target.hasAttribute('data-rz-doc-run')) { void runDoctor(); return; }
    if (target.hasAttribute('data-rz-doc-close')) { ui.doctor = ''; ui.report = null; render(true); return; }
    if (target.hasAttribute('data-rz-doc-report')) { if (typeof downloadDiagnostics === 'function') void downloadDiagnostics(); return; }
    if (target.hasAttribute('data-rz-sh-update')) { if (typeof openAppUpdate === 'function') void openAppUpdate(); return; }
    if (target.hasAttribute('data-rz-sh-custom')) {
      const dialog = document.getElementById('a1-addServiceDialog');
      if (dialog && !dialog.open) dialog.showModal();
    }
  }
  function onInput(event) {
    if (!event.target.matches('[data-rz-sh-query]')) return;
    ui.query = event.target.value; searchCommunity(ui.query); render();
  }

  function settingsSection() {
    const view = document.getElementById('view-settings');
    if (!view) return null;
    let box = document.getElementById('rzSimpleSettings');
    if (!box) {
      box = document.createElement('section');
      box.id = 'rzSimpleSettings';
      box.className = 'rz-simple-settings';
      box.setAttribute('aria-label', 'Основные настройки');
      view.prepend(box);
      box.addEventListener('click', onSettingsClick);
      box.addEventListener('change', onSettingsChange);
    }
    return box;
  }

  function renderSettings(force = false) {
    if (!enabled()) return;
    const box = settingsSection();
    if (!box) return;
    const snap = snapshot();
    const p = snap?.policy;
    const version = typeof state === 'object' ? state?.status?.version || '' : '';
    const devices = !p ? 'Загружаем…' : p.all_lan ? 'Обход действует для всех устройств домашней сети.' : `Обход действует только для выбранных устройств: ${Array.isArray(p.default_sources) ? p.default_sources.length : 0}.`;
    const key = JSON.stringify([p?.revision, p?.application?.mode, p?.components?.mode, p?.all_lan, version, ui.settingsBusy, ui.settingsError]);
    if (!force && key === ui.settingsKey) return;
    ui.settingsKey = key;
    const ready = !!p?.setup_complete && !ui.settingsBusy;
    const toggle = (field, title, detail) => `<label class="rz-set-row"><span><b>${title}</b><small>${detail}</small></span><input type="checkbox" role="switch" data-rz-set-nightly="${field}" ${nightly(p?.[field]) ? 'checked' : ''} ${ready ? '' : 'disabled'}></label>`;
    box.innerHTML = `<div class="rz-set-card"><h3>Обновления</h3>`
      + toggle('application', 'Обновлять RAZVILKA ночью', 'Новая стабильная версия ставится сама; при сбое возвращается прежняя.')
      + toggle('components', 'Обновлять способы обхода ночью', 'NFQWS2, Sing-box и другие компоненты обновляются с проверкой и откатом.')
      + `<div class="rz-set-row"><span><b>Версия</b><small>${html(version ? 'Установлена ' + version : 'Загружаем…')}</small></span><button type="button" class="secondary" data-rz-set-update>Проверить обновления</button></div></div>`
      + `<div class="rz-set-card"><h3>Устройства</h3><div class="rz-set-row"><span><b>Для кого работает обход</b><small>${html(devices)}</small></span><button type="button" class="secondary" data-view="devices">Открыть</button></div></div>`
      + `<div class="rz-set-card"><h3>Резервная копия и помощь</h3><div class="rz-set-row"><span><b>Настройки</b><small>Сервисы и маршруты, без ключей и паролей.</small></span><button type="button" class="secondary" data-rz-set-export>Скачать</button></div><div class="rz-set-row"><span><b>Отчёт для поддержки</b><small>Без ключей, паролей, адресов устройств и истории сайтов.</small></span><button type="button" class="secondary" data-rz-doc-report>Скачать</button></div></div>`
      + (ui.settingsError ? `<p class="rz-sh-error" role="alert">${html(ui.settingsError)}</p>` : '')
      + `<p class="rz-sh-foot">Остальные параметры (DNS, списки сайтов, стратегии, перенос аккаунтов) — в <button type="button" class="link-button" data-rz-set-advanced>расширенном режиме</button>.</p>`;
  }

  // renderDevicesNote says in one line whom the bypass serves, above the list.
  function renderDevicesNote() {
    const grid = document.getElementById('deviceGrid');
    if (!grid) return;
    let note = document.getElementById('rzDevicesScope');
    if (!note) {
      note = document.createElement('p');
      note.id = 'rzDevicesScope';
      note.className = 'rz-devices-scope';
      grid.before(note);
    }
    const p = snapshot()?.policy;
    const text = !p ? '' : p.all_lan ? 'Обход работает для всех устройств домашней сети. Здесь можно дать устройствам понятные имена.'
      : `Обход работает только для выбранных устройств: ${Array.isArray(p.default_sources) ? p.default_sources.length : 0}. Здесь можно дать устройствам понятные имена.`;
    if (note.textContent !== text) note.textContent = text;
  }

  async function saveNightly(field, on) {
    const snap = snapshot();
    if (!snap?.policy?.setup_complete || ui.settingsBusy) return;
    ui.settingsBusy = field; ui.settingsError = ''; renderSettings(true);
    try {
      const policy = withNightly(snap.policy, field, on);
      const request = typeof interfaceRequest === 'function'
        ? (path, options = {}) => interfaceRequest(path, { ...options, body: options.body === undefined ? undefined : JSON.stringify(options.body) })
        : (path, options = {}) => api(path, { ...options, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
      await request('/api/v1/autonomy', { method: 'PUT', body: { expected_revision: snap.policy.revision, policy, confirm: 'SAVE_AUTONOMY', release_safe_mode: false } });
      const fresh = await request('/api/v1/autonomy');
      window.dispatchEvent(new CustomEvent('razvilka:autonomy-state', { detail: fresh }));
      if (typeof interfaceToast === 'function') interfaceToast(on ? 'Ночное обновление включено.' : 'Ночное обновление выключено: версии будут только проверяться.');
    } catch (e) {
      ui.settingsError = e?.message || 'Настройка не сохранена.';
    } finally {
      ui.settingsBusy = ''; renderSettings(true);
    }
  }

  function onSettingsChange(event) {
    const field = event.target?.dataset?.rzSetNightly;
    if (field) void saveNightly(field, event.target.checked);
  }
  function onSettingsClick(event) {
    const target = event.target.closest('button');
    if (!target) return;
    if (target.hasAttribute('data-rz-set-update')) { if (typeof openAppUpdate === 'function') void openAppUpdate(); return; }
    if (target.hasAttribute('data-rz-set-export')) { if (typeof exportConfig === 'function') void exportConfig(); return; }
    if (target.hasAttribute('data-rz-doc-report')) { if (typeof downloadDiagnostics === 'function') void downloadDiagnostics(); return; }
    if (target.hasAttribute('data-rz-set-advanced')) setEnabled(false);
  }

  window.addEventListener('razvilka:autonomy-state', () => { render(); renderSettings(); renderDevicesNote(); });
  window.addEventListener('razvilka:app-update', () => render());
  document.addEventListener('razvilka:panel-availability', () => render());
  document.addEventListener('DOMContentLoaded', apply);
  if (document.readyState !== 'loading') apply();
  setInterval(() => { if (!document.hidden) { render(); renderSettings(); renderDevicesNote(); } }, 3000);
})(typeof window !== 'undefined' ? window : globalThis);
