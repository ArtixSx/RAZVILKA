'use strict';

// Browser handles only an allowlisted location ID and a public review receipt.
// The source bytes never leave the router through these endpoints.
(() => {
  const el = (id) => document.getElementById(id);
  const root = el('cloudflareLegacy');
  if (!root) return;
  const section = el('cloudflareCopies');
  const select = el('cloudflareLegacySource');
  const review = el('cloudflareLegacyReview');
  const copy = el('cloudflareLegacyCopy');
  const cancel = el('cloudflareLegacyCancel');
  const message = el('cloudflareLegacyMessage');
  const refresh = el('cloudflareLegacyRefresh');
  let sources = new Set();
  let pending = null;
  let request = null;
  let generation = 0;

  function busy(value) {
    select.disabled = value || !sources.size;
    el('cloudflareLegacyPreviewButton').disabled = value || !sources.size;
    refresh.disabled = value;
    copy.disabled = value || !pending;
    root.setAttribute('aria-busy', String(value));
  }
  function reset() {
    generation++;
    request?.abort(); request = null;
    pending = null;
    copy.hidden = cancel.hidden = true;
    review.textContent = 'После проверки покажем формат файла. Ключи не передаются в браузер.';
    message.textContent = ''; message.className = '';
    busy(false);
  }
  function close() {
    sources = new Set();
    select.innerHTML = '<option value="">Откройте раздел для загрузки расположений</option>';
    refresh.hidden = true;
    reset();
  }
  function fail(error) {
    reset();
    message.className = 'cloudflare-copy-error';
    message.textContent = error.message || 'Не удалось выполнить операцию. Исходные профили не изменены.';
  }
  function begin() { reset(); request = new AbortController(); busy(true); return { ticket: generation, controller: request }; }
  function current(operation) { return generation === operation.ticket && !operation.controller.signal.aborted; }
  function finish(operation) { if (current(operation)) { request = null; busy(false); } }

  async function load() {
    const operation = begin();
    sources = new Set();
    select.innerHTML = '<option value="">Загрузка расположений…</option>';
    refresh.hidden = true;
    try {
      const payload = await api('/api/v1/cloudflare/legacy/sources', { signal: operation.controller.signal });
      if (!current(operation)) return;
      const locations = payload.sources;
      if (!Array.isArray(locations) || locations.length > 8 || locations.some((item) => !/^[a-z0-9-]{1,48}$/.test(item.id) || typeof item.label !== 'string')) throw new Error('Панель вернула неполный список расположений. Повторите загрузку.');
      sources = new Set(locations.map((item) => item.id));
      select.innerHTML = locations.map((item) => `<option value="${esc(item.id)}">${esc(item.label)}</option>`).join('') || '<option value="">Нет разрешённых расположений</option>';
      if (!locations.length) message.textContent = 'Для этой установки перенос с роутера недоступен. Используйте добавление файла с компьютера выше.';
    } catch (error) {
      if (current(operation)) { fail(error); refresh.hidden = false; }
    } finally { finish(operation); }
  }

  el('cloudflareLegacyForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (request || !sources.has(select.value)) return;
    const sourceID = select.value;
    const operation = begin();
    review.textContent = 'Читаем только выбранный файл. Рабочий обход не меняется…';
    try {
      const payload = await api('/api/v1/cloudflare/legacy/preview', { method: 'POST', signal: operation.controller.signal, body: JSON.stringify({ source_id: sourceID }) });
      if (!current(operation)) return;
      const result = payload.review;
      if (!result || result.source_id !== sourceID || !/^[a-f0-9]{64}$/.test(result.review_digest) || !result.account) throw new Error('Результат проверки неполный. Проверьте профиль заново.');
      const summary = cloudflareAccountSummary(result.account);
      review.innerHTML = `<b>${esc(summary.name)}</b><span class="cloudflare-copy-state">${esc(summary.state)}</span><p>Сохранится отдельная копия. Исходный файл и работающий обход останутся без изменений.</p>`;
      pending = { source_id: sourceID, review_digest: result.review_digest };
      copy.textContent = result.account.format === 'opaque-archive' ? 'Сохранить только архивную копию' : 'Сохранить отдельную копию';
      copy.hidden = cancel.hidden = false;
    } catch (error) { if (current(operation)) fail(error); }
    finally { finish(operation); }
  });

  copy.addEventListener('click', async () => {
    if (!pending || request) return;
    const body = JSON.stringify({ ...pending, confirm: 'COPY_LEGACY_ACCOUNT' });
    const operation = begin();
    message.textContent = 'Повторно проверяем файл и сохраняем копию…';
    try {
      await api('/api/v1/cloudflare/legacy/copy', { method: 'POST', signal: operation.controller.signal, body });
      if (!current(operation)) return;
      reset();
      message.textContent = 'Копия сохранена. Исходный файл, работающий обход и маршруты не изменены. Повторное копирование того же файла не создаёт дубликат.';
      document.dispatchEvent(new Event('razvilka:cloudflare-copies-changed'));
    } catch (error) {
      if (current(operation)) { fail(error); message.textContent += ' При потере соединения обновите список копий перед повторной попыткой.'; }
    } finally { finish(operation); }
  });

  select.addEventListener('change', reset);
  cancel.addEventListener('click', reset);
  refresh.addEventListener('click', load);
  section.addEventListener('toggle', () => { if (section.open) load(); else close(); });
  document.addEventListener('razvilka:auth-required', close);
  document.addEventListener('razvilka:view-change', (event) => {
    if (event.detail !== 'settings') close();
    else if (section.open) load();
  });
  window.addEventListener('pagehide', close);
})();
