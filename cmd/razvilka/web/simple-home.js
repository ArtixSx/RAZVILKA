/* Simple mode: the owner's main use is to add or remove services; the
 * autopilot does the rest. The home page shows one status line, the managed
 * services and a catalog search. Everything else stays in advanced mode.
 * Pure helpers are exported for tests; actions reuse interfaceManage. */
(function (root) {
  'use strict';
  const OK = new Set(['healthy', 'applied']);
  const PROGRESS = new Set(['pending', 'checking', 'applying', 'searching', 'scope-pending', 'removal-pending', 'rate-limited']);
  const SHORT = {
    pending: 'Ждёт проверки', checking: 'Проверяется', applying: 'Включается', searching: 'Подбирается способ обхода',
    'scope-pending': 'Применяется к устройствам', 'removal-pending': 'Убирается', 'rate-limited': 'Пауза между попытками',
    'component-stopped': 'Нужный компонент не запущен', 'component-unavailable': 'Нужный компонент не готов',
    'apply-refused': 'Не удалось включить, автопилот повторит', unconfirmed: 'Проверка не дала ответа, автопилот повторит',
    'requires-review': 'Нужна проверка журнала', 'manual-change': 'Изменён вручную', paused: 'На паузе',
    'network-unknown': 'Сеть не определена', 'checker-unavailable': 'Проверка временно недоступна',
    'catalog-unavailable': 'Источник подключений недоступен', 'definition-changed': 'Состав сервиса изменился',
    'unsupported-scenario': 'Нет подходящей проверки', 'origin-expired': 'Истёк источник подключения',
    'removal-blocked': 'Снятие приостановлено'
  };

  function bucket(state) {
    if (OK.has(state)) return 'ok';
    if (!state || PROGRESS.has(state)) return 'progress';
    return 'problem';
  }

  function names(catalog, snapshot) {
    const out = {};
    for (const s of snapshot?.catalog_services || []) if (s?.id) out[s.id] = s.name || s.id;
    for (const s of catalog || []) if (s?.id) out[s.id] = s.name || out[s.id] || s.id;
    return out;
  }

  // model turns the autopilot snapshot into what the simple home renders.
  function model(snapshot, catalog) {
    if (!snapshot || typeof snapshot !== 'object') return { phase: 'loading', services: [], tone: 'progress', title: 'Загружаем состояние…', text: '' };
    const policy = snapshot.policy || {};
    const label = names(catalog, snapshot);
    const services = Object.entries(snapshot.services || {}).filter(([, s]) => s && !s.removing).map(([id]) => {
      const runtime = snapshot.runtime?.[id] || {};
      const state = runtime.state || 'pending';
      const detail = String(runtime.message || '').slice(0, 220);
      // A waiting service says when it continues ("…через 12 мин.").
      const next = state === 'rate-limited' && /Следующая попытка[^.]*через \d+ мин/.exec(detail);
      return { id, name: label[id] || id, state, bucket: bucket(state), short: next ? next[0] : SHORT[state] || (OK.has(state) ? 'Работает' : 'Проверяется'), detail };
    }).sort((a, b) => ({ problem: 0, progress: 1, ok: 2 }[a.bucket] - { problem: 0, progress: 1, ok: 2 }[b.bucket]) || a.name.localeCompare(b.name, 'ru'));
    for (const s of services) if (s.bucket === 'ok') s.short = 'Работает';
    const count = kind => services.filter(s => s.bucket === kind).length;
    const base = { services, managed: new Set(services.map(s => s.id)) };
    if (!policy.setup_complete) return { ...base, phase: 'setup', tone: 'setup', title: 'Давайте настроим обход', text: 'Выберите сервисы и устройства — дальше автопилот всё сделает сам.' };
    if (snapshot.stopped || policy.enabled === false) return { ...base, phase: 'off', tone: 'problem', title: 'Автопилот выключен', text: 'Сервисы не проверяются и не переключаются. Включите автопилот в настройках.' };
    if (!services.length) return { ...base, phase: 'empty', tone: 'setup', title: 'Добавьте первый сервис', text: 'Нажмите «Добавить сервис» и выберите, что должно открываться.' };
    const problems = count('problem'), progress = count('progress');
    if (problems) return { ...base, phase: 'ready', tone: 'problem', title: `${plural(problems, 'сервис пока не работает', 'сервиса пока не работают', 'сервисов пока не работают')}`, text: 'Автопилот продолжает попытки. Причина указана у сервиса.' };
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

  root.RazvilkaSimpleHome = Object.freeze({ model, available, bucket, plural });
  if (typeof document === 'undefined') return;

  const KEY = 'razvilka.simpleMode';
  const ui = { open: false, query: '', busy: '', error: '', key: '' };
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
    toggle.querySelector('b').textContent = on ? 'Расширенный режим' : 'Простой режим';
    toggle.querySelector('small').textContent = on ? 'Все разделы и ручные настройки' : 'Только сервисы и устройства';
  }
  function apply() {
    const on = enabled();
    document.body.classList.toggle('rz-simple', on);
    ensure();
    label();
    if (on && typeof state === 'object' && state && !['overview', 'devices', 'settings'].includes(state.currentView)) {
      document.querySelector('[data-main-nav="overview"]')?.click();
    }
    render(true);
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

  function serviceRow(s) {
    const busy = ui.busy === s.id;
    return `<li class="rz-sh-service rz-sh-${s.bucket}"><span class="rz-sh-dot" aria-hidden="true"></span><div><b>${html(s.name)}</b><small title="${html(s.detail)}">${html(s.short)}</small></div><button type="button" class="secondary" data-rz-sh-remove="${html(s.id)}" ${busy ? 'disabled' : ''}>${busy ? 'Убираем…' : 'Убрать'}</button></li>`;
  }

  function addPanel(m) {
    if (!ui.open) return '';
    const list = available(catalog(), m.managed, ui.query);
    const rows = list.map(s => `<li><div><b>${html(s.name || s.id)}</b><small>${html(s.category || '')}</small></div><button type="button" class="primary" data-rz-sh-add-id="${html(s.id)}" ${ui.busy ? 'disabled' : ''}>${ui.busy === s.id ? 'Добавляем…' : 'Добавить'}</button></li>`).join('');
    const empty = catalog().length ? 'Ничего не найдено. Попробуйте другое название или добавьте свой сайт.' : 'Каталог ещё загружается…';
    return `<div class="rz-sh-add"><label class="rz-sh-search"><span>Какой сервис должен открываться?</span><input type="search" data-rz-sh-query placeholder="Например, YouTube или Discord" value="${html(ui.query)}" autocomplete="off"></label><ul class="rz-sh-catalog">${rows || `<li class="rz-sh-empty">${empty}</li>`}</ul><button type="button" class="link-button" data-rz-sh-custom>Нет в списке? Добавить свой сайт</button></div>`;
  }

  function render(force = false) {
    if (!enabled()) return;
    const home = ensure();
    if (!home) return;
    const snap = snapshot();
    const m = model(snap, catalog());
    const key = JSON.stringify([m.phase, m.tone, m.title, m.services.map(s => [s.id, s.state, s.short]), ui.open, ui.query, ui.busy, ui.error, catalog().length]);
    if (!force && key === ui.key) return;
    const focused = document.activeElement?.matches?.('[data-rz-sh-query]');
    ui.key = key;
    const action = m.phase === 'setup' ? '<button type="button" class="primary" data-view="autopilot">Начать настройку</button>'
      : m.phase === 'off' ? '<button type="button" class="primary" data-view="autopilot">Открыть автопилот</button>' : '';
    const canAdd = m.phase === 'ready' || m.phase === 'empty';
    home.innerHTML = `<div class="rz-sh-status rz-sh-${m.tone}"><span class="rz-sh-badge" aria-hidden="true"></span><div><h2>${html(m.title)}</h2><p>${html(m.text)}</p></div>${action}</div>`
      + (canAdd ? `<div class="rz-sh-head"><h3>Мои сервисы</h3><button type="button" class="${ui.open ? 'secondary' : 'primary'}" data-rz-sh-toggle-add aria-expanded="${ui.open}">${ui.open ? 'Готово' : 'Добавить сервис'}</button></div>${addPanel(m)}`
        + (m.services.length ? `<ul class="rz-sh-list">${m.services.map(serviceRow).join('')}</ul>` : '') : '')
      + (ui.error ? `<p class="rz-sh-error" role="alert">${html(ui.error)}</p>` : '')
      + '<p class="rz-sh-foot">Автопилот сам подбирает способ обхода, проверяет доступ и переключается при сбое. Вам нужно только выбрать сервисы.</p>';
    if (focused) {
      const input = home.querySelector('[data-rz-sh-query]');
      if (input) { input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
    }
  }

  async function act(id, remove) {
    if (typeof interfaceManage !== 'function' || ui.busy) return;
    ui.busy = id; ui.error = ''; render(true);
    try {
      await interfaceManage(id, true, remove);
      if (typeof interfaceToast === 'function') interfaceToast(remove ? 'Сервис убирается. Его обход будет снят.' : 'Сервис добавлен. Автопилот проверит и включит его.');
    } catch (e) {
      ui.error = e?.message || 'Действие не выполнено.';
    } finally {
      ui.busy = ''; render(true);
    }
  }

  function onClick(event) {
    const target = event.target.closest('button');
    if (!target) return;
    if (target.hasAttribute('data-rz-sh-toggle-add')) { ui.open = !ui.open; ui.error = ''; render(true); if (ui.open) document.querySelector('[data-rz-sh-query]')?.focus(); return; }
    if (target.dataset.rzShAddId) { void act(target.dataset.rzShAddId, false); return; }
    if (target.dataset.rzShRemove) { void act(target.dataset.rzShRemove, true); return; }
    if (target.hasAttribute('data-rz-sh-custom')) {
      const dialog = document.getElementById('a1-addServiceDialog');
      if (dialog && !dialog.open) dialog.showModal();
    }
  }
  function onInput(event) {
    if (!event.target.matches('[data-rz-sh-query]')) return;
    ui.query = event.target.value; render();
  }

  window.addEventListener('razvilka:autonomy-state', () => render());
  document.addEventListener('DOMContentLoaded', apply);
  if (document.readyState !== 'loading') apply();
  setInterval(() => { if (!document.hidden) render(); }, 3000);
})(typeof window !== 'undefined' ? window : globalThis);
