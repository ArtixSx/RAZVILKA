'use strict';

// Deliberately separate structural recognition from remote/route evidence.
function cloudflareAccountSummary(account) {
  const names = { 'usque-v1': 'USQUE · MASQUE', 'wgcf-account-v1': 'wgcf · аккаунт WireGuard', 'wireguard-v1': 'WARP / WireGuard · профиль' };
  const recognized = !!names[account?.format];
  return {
    name: names[account?.format] || 'Архив неизвестного формата',
    state: recognized ? 'Структура распознана · связь не проверена' : 'Только архив · запуск не поддерживается',
    detail: recognized ? 'Сохранение не подключает обход и не подтверждает доступность сервисов.' : 'Файл можно сохранить как копию. Для запуска потребуется совместимый формат.',
    saveLabel: recognized ? 'Сохранить копию аккаунта' : 'Сохранить только архив',
  };
}

(() => {
  const root = document.querySelector('#cloudflareCopies');
  if (!root) return;
  const el = (id) => document.getElementById(id);
  const kind = el('cloudflareCopyKind');
  const fileInput = el('cloudflareCopyFile');
  const preview = el('cloudflareCopyPreview');
  const save = el('cloudflareCopySave');
  const message = el('cloudflareCopyMessage');
  const list = el('cloudflareCopyList');
  let pending = null; // Private bytes live only until save/cancel/navigation/logout.
  let generation = 0;
  let request = null;
  let listRequest = null;

  function setBusy(busy) {
    kind.disabled = fileInput.disabled = el('cloudflareCopyPreviewButton').disabled = busy;
    save.disabled = busy || !pending;
    el('cloudflareCopyForm').setAttribute('aria-busy', String(busy));
  }
  function clearSelection(clearFile = true) {
    generation++;
    request?.abort(); request = null;
    pending = null;
    if (clearFile) fileInput.value = '';
    save.hidden = true;
    setBusy(false);
    message.textContent = '';
    message.className = '';
    preview.textContent = 'Выберите свой файл. До сохранения ничего не записывается на роутер.';
  }
  function resetPrivateView() {
    clearSelection();
    listRequest?.abort(); listRequest = null;
    list.textContent = 'Нажмите «Обновить список» после входа.';
  }
  function fail(error) {
    message.className = 'cloudflare-copy-error';
    message.textContent = error.message || 'Операция не выполнена. Повторите попытку.';
  }
  function card(account) {
    const summary = cloudflareAccountSummary(account);
    const date = account.created_at ? new Date(account.created_at).toLocaleString('ru-RU') : '';
    return `<article class="cloudflare-copy-card"><b>${esc(summary.name)}</b><span class="cloudflare-copy-state">${esc(summary.state)}</span><p>${esc(summary.detail)}</p><small>Копия ${esc(String(account.id || '').slice(-8))}${date ? ` · ${esc(date)}` : ''}</small></article>`;
  }
  async function loadList() {
    listRequest?.abort();
    const active = new AbortController();
    listRequest = active;
    el('cloudflareCopyRefresh').disabled = true;
    list.textContent = 'Загрузка копий…';
    try {
      const payload = await api('/api/v1/cloudflare/accounts', { signal: active.signal });
      if (listRequest !== active || active.signal.aborted) return;
      const accounts = payload.accounts || [];
      list.innerHTML = `<p>Сохранено ${accounts.length} из ${Number(payload.limit) || 32}. Ни одна копия здесь не считается работающим обходом.</p>${accounts.map(card).join('') || '<p>Копий пока нет. Добавьте имеющийся файл слева.</p>'}`;
    } catch (error) {
      if (listRequest === active && !active.signal.aborted) list.textContent = error.message || 'Список недоступен.';
    } finally {
      if (listRequest === active) listRequest = null;
      el('cloudflareCopyRefresh').disabled = false;
    }
  }

  el('cloudflareCopyForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    clearSelection(false);
    const file = fileInput.files?.[0];
    if (!file || !file.size || file.size > 256 * 1024) {
      fail(new Error('Выберите непустой файл размером до 256 КиБ.'));
      return;
    }
    const ticket = generation;
    const active = new AbortController();
    request = active;
    setBusy(true);
    preview.textContent = 'Проверяем структуру файла. Подключение не запускается…';
    try {
      const content = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
      if (ticket !== generation || active.signal.aborted) return;
      const sourceKind = kind.value;
      const payload = await api('/api/v1/cloudflare/import/preview', { method: 'POST', signal: active.signal, body: JSON.stringify({ source_kind: sourceKind, content }) });
      if (ticket !== generation || active.signal.aborted) return;
      const summary = cloudflareAccountSummary(payload.account);
      pending = { source_kind: sourceKind, content };
      preview.innerHTML = `<b>${esc(summary.name)}</b><span class="cloudflare-copy-state">${esc(summary.state)}</span><p>${esc(summary.detail)}</p>`;
      save.textContent = summary.saveLabel;
      save.hidden = false;
    } catch (error) {
      if (ticket === generation && !active.signal.aborted) {
        pending = null;
        preview.textContent = 'Файл не сохранён.';
        fail(error instanceof TypeError ? new Error('Не удалось прочитать файл UTF-8 или связаться с панелью. Проверьте файл и подключение.') : error);
      }
    } finally {
      if (ticket === generation) { request = null; setBusy(false); }
    }
  });

  save.addEventListener('click', async () => {
    if (!pending || request) return;
    const ticket = generation;
    const active = new AbortController();
    request = active;
    setBusy(true);
    message.textContent = 'Сохраняем отдельную копию…';
    try {
      await api('/api/v1/cloudflare/import', { method: 'POST', signal: active.signal, body: JSON.stringify({ ...pending, confirm: 'SAVE_ACCOUNT_COPY' }) });
      if (ticket !== generation || active.signal.aborted) return;
      clearSelection();
      message.textContent = 'Копия сохранена. Рабочий профиль и маршруты не изменены. Повторный импорт того же файла не создаёт дубликат.';
      await loadList();
    } catch (error) {
      if (ticket === generation && !active.signal.aborted) {
        // Forget private content on any failure; idempotent retry is a new import.
        clearSelection();
        fail(error);
      }
    } finally {
      if (ticket === generation) { request = null; setBusy(false); }
    }
  });

  kind.addEventListener('change', () => clearSelection());
  fileInput.addEventListener('change', () => clearSelection(false));
  el('cloudflareCopyRefresh').addEventListener('click', loadList);
  root.addEventListener('toggle', () => { if (root.open) loadList(); else resetPrivateView(); });
  document.addEventListener('razvilka:auth-required', resetPrivateView);
  document.addEventListener('razvilka:view-change', (event) => { if (event.detail !== 'settings') resetPrivateView(); });
  window.addEventListener('pagehide', resetPrivateView);
})();
