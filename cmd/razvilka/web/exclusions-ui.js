'use strict';

// Exclusions: sites and devices that must not use a bypass. The page edits the
// NFQWS2 exclude list and its Keenetic access policy through ordinary drafts;
// nothing changes on the router until «Проверить и применить».
const exclusionsView = { epoch: 0, loading: false, exclude: null, auto: null, ipExclude: null, mode: null, stock: null, query: '', showStock: false, busy: false, message: '' };

function exclusionDomain(value) {
  const domain = String(value || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/[/?#:].*$/, '').replace(/^\*\./, '').replace(/\.$/, '');
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/.test(domain) ? domain : '';
}

function exclusionLines(content) {
  return String(content || '').split(/\r?\n/).map((line) => line.trim().toLowerCase()).filter((line) => line && !line.startsWith('#'));
}

// Every host list of NFQWS2 also matches subdomains.
function exclusionCovered(domain, entries) {
  const parts = domain.split('.');
  return parts.some((_, index) => entries.has(parts.slice(index).join('.')));
}

async function loadExclusions() {
  const epoch = ++exclusionsView.epoch;
  exclusionsView.loading = true; renderExclusions();
  const read = (file) => api(`/api/v1/engine-configs/nfqws2/file?file=${file}`).catch(() => null);
  try {
    const [exclude, auto, ipExclude, mode, stock] = await Promise.all([
      read('exclude-list'), read('auto-list'), read('ipset-exclude'),
      api('/api/v1/nfqws2/setup-mode').catch(() => null),
      api('/api/v1/nfqws2/exclusions').catch(() => null),
    ]);
    if (epoch !== exclusionsView.epoch) return;
    Object.assign(exclusionsView, { exclude, auto, ipExclude, mode, stock: new Set(stock?.stock || []), message: exclude ? '' : 'Список исключений NFQWS2 недоступен: проверьте, установлен ли NFQWS2.' });
  } finally {
    if (epoch === exclusionsView.epoch) { exclusionsView.loading = false; renderExclusions(); }
  }
}

function exclusionStaged(file) { return file?.source === 'staged'; }

function renderExclusionSites() {
  const view = exclusionsView, entries = exclusionLines(view.exclude?.content), stock = view.stock || new Set();
  const own = entries.filter((domain) => !stock.has(domain));
  const removed = [...stock].filter((domain) => !entries.includes(domain));
  const query = view.query.trim().toLowerCase();
  const standard = entries.filter((domain) => stock.has(domain) && (!query || domain.includes(query)));
  const staged = exclusionStaged(view.exclude);
  const row = (domain, removable) => `<li><code>${esc(domain)}</code>${removable ? `<button type="button" class="text-button" data-exclusion-remove="${esc(domain)}" aria-label="Убрать ${esc(domain)} из исключений">Убрать</button>` : ''}</li>`;
  return `<div class="exclusion-head"><h3>Сайты без обхода</h3><span class="tag">${entries.length} в списке</span></div>
    <p class="exclusion-lead">NFQWS2 не обрабатывает эти сайты и их поддомены. Сюда стоит добавлять сайты, которые открываются и без обхода, но с ним работают хуже: Госуслуги, банки, игры, российские сервисы.</p>
    <form class="exclusion-add" id="exclusionAddForm"><input id="exclusionAddInput" autocomplete="off" placeholder="Например: bank.example" aria-label="Сайт без обхода"/><button type="submit" class="primary"${view.busy || !view.exclude ? ' disabled' : ''}>Добавить</button></form>
    <h4>Добавлены вами · ${own.length}</h4>
    ${own.length ? `<ul class="exclusion-list">${own.map((domain) => row(domain, true)).join('')}</ul>` : '<p class="r5-caption">Пока нет. Стандартные исключения пакета ниже уже действуют.</p>'}
    <details class="exclusion-stock"${view.showStock ? ' open' : ''}><summary>Стандартные исключения nfqws2-keenetic · ${entries.length - own.length}${removed.length ? ` · убрано вами: ${removed.length}` : ''}</summary>
      <input id="exclusionSearch" autocomplete="off" placeholder="Поиск по стандартным" value="${esc(view.query)}" aria-label="Поиск по стандартным исключениям"/>
      <ul class="exclusion-list">${standard.slice(0, 300).map((domain) => row(domain, true)).join('')}</ul>
      ${removed.length ? `<p class="r5-caption">Убраны из стандартных: ${removed.map((domain) => `<code>${esc(domain)}</code>`).join(' ')}</p>` : ''}
    </details>
    ${staged ? '<p class="exclusion-draft">Список изменён и ещё не применён.</p>' : ''}`;
}

function renderExclusionAuto() {
  const view = exclusionsView, entries = new Set(exclusionLines(view.exclude?.content));
  const found = exclusionLines(view.auto?.content).filter((domain) => !exclusionCovered(domain, entries));
  return `<div class="exclusion-head"><h3>Найдено автоматически</h3><span class="tag">${found.length}</span></div>
    <p class="exclusion-lead">Режим AUTO NFQWS2 сам добавляет сайты, которые не открылись без обхода. Иногда сюда попадают и лишние: если сайт работает без обхода или с ним ломается, нажмите «Не обходить».</p>
    ${found.length ? `<ul class="exclusion-list">${found.map((domain) => `<li><code>${esc(domain)}</code><button type="button" class="secondary" data-exclusion-add="${esc(domain)}"${view.busy ? ' disabled' : ''}>Не обходить</button></li>`).join('')}</ul>` : '<p class="r5-caption">Автоматически найденных сайтов нет или все уже исключены.</p>'}`;
}

function renderExclusionDevices() {
  const mode = exclusionsView.mode, runtime = mode?.policy_runtime, name = mode?.policy_name || 'nfqws';
  const exclude = !!mode?.policy_exclude, found = runtime?.found === true;
  let state = 'NFQWS2 обрабатывает все устройства сети.';
  if (found && runtime.exclude) state = `Устройства из политики «${runtime.name}» NFQWS2 не обрабатывает.`;
  else if (found) state = `NFQWS2 обрабатывает только устройства из политики «${runtime.name}».`;
  const pending = mode && runtime && (runtime.exclude !== exclude || runtime.name !== name);
  return `<div class="exclusion-head"><h3>Устройства без обхода</h3></div>
    <p class="exclusion-state"><b>${esc(state)}</b></p>
    <p class="exclusion-lead">NFQWS2 отличает устройства по политике доступа Keenetic. Чтобы исключить телевизор, рабочий ноутбук или приставку:</p>
    <ol class="exclusion-steps">
      <li>В веб-интерфейсе Keenetic откройте «Интернет» → «Приоритеты подключений» и создайте политику доступа с именем <code>${esc(name)}</code>, включив в ней основное подключение к интернету.</li>
      <li>В «Списке устройств» назначьте этой политике устройства, которым обход не нужен.</li>
      <li>Здесь включите «Исключить устройства политики» и нажмите «Проверить и применить».</li>
    </ol>
    <p class="r5-caption">Политику и назначения устройств RAZVILKA не меняет: в новой политике Keenetic без разрешённого подключения устройство останется без интернета.</p>
    <label class="exclusion-toggle"><input type="checkbox" id="exclusionPolicyToggle"${exclude ? ' checked' : ''}${exclusionsView.busy || !mode?.available ? ' disabled' : ''}/> <span>Исключить устройства политики «${esc(name)}» из NFQWS2</span></label>
    ${runtime && !found ? `<p class="r5-caption">Политика «${esc(runtime.name)}» в Keenetic пока не найдена${exclude ? ': после её создания и перезапуска NFQWS2 исключение начнёт действовать' : ''}.</p>` : ''}
    ${pending ? '<p class="exclusion-draft">Настройка изменена и ещё не применена.</p>' : ''}
    <p class="r5-caption">Для обходов через узлы, WARP и WireGuard устройства выбираются в карточке сервиса.</p>`;
}

function renderExclusions() {
  const root = document.getElementById('exclusionsContent');
  if (!root) return;
  const view = exclusionsView;
  if (view.loading && !view.exclude && !view.mode) { root.innerHTML = '<p class="r5-caption">Читаем списки NFQWS2…</p>'; return; }
  const drafts = exclusionStaged(view.exclude) || view.mode?.source === 'staged';
  root.innerHTML = `${view.message ? `<p class="exclusion-message" role="status">${esc(view.message)}</p>` : ''}
    ${drafts ? `<div class="exclusion-apply"><span>Изменения исключений сохранены в черновике NFQWS2.</span><button type="button" class="primary" data-exclusion-apply${view.busy ? ' disabled' : ''}>Проверить и применить</button></div>` : ''}
    <div class="exclusion-grid"><article class="panel exclusion-panel">${renderExclusionSites()}</article><article class="panel exclusion-panel">${renderExclusionDevices()}</article></div>
    <article class="panel exclusion-panel">${renderExclusionAuto()}</article>`;
}

async function exclusionOperation(message, action) {
  if (exclusionsView.busy) return;
  exclusionsView.busy = true; exclusionsView.message = ''; renderExclusions();
  try { await action(); exclusionsView.message = message; }
  catch (error) { exclusionsView.message = error.message || 'Изменение не сохранено.'; }
  finally { exclusionsView.busy = false; await loadExclusions(); }
}

function stageExcludeList(lines) {
  const content = `${lines.join('\n')}\n`;
  return api('/api/v1/engine-configs/nfqws2/file?file=exclude-list', { method: 'PUT', body: JSON.stringify({ content }) });
}

function addExcludedSite(value) {
  const domain = exclusionDomain(value);
  if (!domain) { exclusionsView.message = 'Укажите адрес сайта, например bank.example.'; renderExclusions(); return; }
  const raw = String(exclusionsView.exclude?.content || '').split(/\r?\n/).filter((line, index, all) => line.trim() || index < all.length - 1);
  if (exclusionLines(raw.join('\n')).includes(domain)) { exclusionsView.message = `${domain} уже в исключениях.`; renderExclusions(); return; }
  void exclusionOperation(`${domain} добавлен в исключения. Нажмите «Проверить и применить».`, () => stageExcludeList([...raw, domain]));
}

function removeExcludedSite(domain) {
  const raw = String(exclusionsView.exclude?.content || '').split(/\r?\n/);
  const kept = raw.filter((line) => line.trim().toLowerCase() !== domain);
  while (kept.length && !kept.at(-1).trim()) kept.pop();
  void exclusionOperation(`${domain} убран из исключений. Нажмите «Проверить и применить».`, () => stageExcludeList(kept));
}

function stagePolicyExclusion(exclude) {
  const values = { POLICY_EXCLUDE: exclude ? '1' : '0' };
  if (!exclusionsView.mode?.policy_name) values.POLICY_NAME = 'nfqws';
  void exclusionOperation(exclude ? 'Исключение устройств политики сохранено в черновике.' : 'Устройства политики снова будут обрабатываться.', () =>
    api('/api/v1/engine-configs/nfqws2/guided?file=main', { method: 'PUT', body: JSON.stringify({ values }) }));
}

function applyExclusions() {
  if (exclusionsView.busy || typeof applyDraft !== 'function') return;
  exclusionsView.busy = true; renderExclusions();
  Promise.resolve(applyDraft('engine', 'nfqws2')).catch(() => {}).finally(() => { exclusionsView.busy = false; void loadExclusions(); });
}

function bindExclusions() {
  const root = document.getElementById('exclusionsContent');
  if (!root) return;
  root.addEventListener('submit', (event) => {
    if (event.target.id !== 'exclusionAddForm') return;
    event.preventDefault();
    addExcludedSite(document.getElementById('exclusionAddInput')?.value);
  });
  root.addEventListener('click', (event) => {
    const button = event.target.closest('button');
    if (!button || button.disabled) return;
    if (button.dataset.exclusionAdd) addExcludedSite(button.dataset.exclusionAdd);
    else if (button.dataset.exclusionRemove) removeExcludedSite(button.dataset.exclusionRemove);
    else if (button.hasAttribute('data-exclusion-apply')) applyExclusions();
  });
  root.addEventListener('change', (event) => { if (event.target.id === 'exclusionPolicyToggle') stagePolicyExclusion(event.target.checked); });
  root.addEventListener('toggle', (event) => { if (event.target.classList?.contains('exclusion-stock')) exclusionsView.showStock = event.target.open; }, true);
  root.addEventListener('input', (event) => {
    if (event.target.id !== 'exclusionSearch') return;
    exclusionsView.query = event.target.value;
    const position = event.target.selectionStart;
    renderExclusions();
    const search = document.getElementById('exclusionSearch');
    search?.focus(); search?.setSelectionRange(position, position);
  });
  document.addEventListener('razvilka:view-change', (event) => { if (event.detail === 'exclusions') void loadExclusions(); });
}

bindExclusions();
