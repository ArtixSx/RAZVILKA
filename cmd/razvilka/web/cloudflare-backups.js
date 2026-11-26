'use strict';

// This screen never handles decrypted account files. Only the archive password
// and ciphertext survive preview, until restore/cancel/navigation/logout.
(() => {
  const el = (id) => document.getElementById(id);
  const root = el('cloudflareArchives');
  if (!root) return;
  const password = el('cloudflareArchivePassword');
  const repeat = el('cloudflareArchiveRepeat');
  const importPassword = el('cloudflareArchiveImportPassword');
  const fileInput = el('cloudflareArchiveFile');
  const review = el('cloudflareArchiveReview');
  const restore = el('cloudflareArchiveRestore');
  const cancel = el('cloudflareArchiveCancel');
  const message = el('cloudflareArchiveMessage');
  const controls = [password, repeat, importPassword, fileInput, el('cloudflareArchiveExport'), el('cloudflareArchivePreview')];
  let pending = null;
  let active = null;
  let generation = 0;

  function busy(value) {
    controls.forEach((control) => { control.disabled = value; });
    restore.disabled = value || !pending;
    root.setAttribute('aria-busy', String(value));
  }
  function clearPasswords() { password.value = repeat.value = importPassword.value = ''; }
  function reset(clearFields = true) {
    generation++;
    active?.abort(); active = null;
    pending = null;
    if (clearFields) { clearPasswords(); fileInput.value = ''; }
    restore.hidden = cancel.hidden = true;
    busy(false);
    review.textContent = 'Сначала покажем, сколько копий будет добавлено. Проверка ничего не меняет.';
    message.textContent = ''; message.className = '';
  }
  function fail(error) {
    reset();
    message.className = 'cloudflare-copy-error';
    message.textContent = error instanceof SyntaxError ? 'Файл не является архивом JSON. Выберите архив аккаунтов Cloudflare.' : error.message || 'Операция не завершена. Проверьте соединение и повторите.';
  }
  function passwordValid(value) {
    const size = new TextEncoder().encode(value).length;
    return value.length >= 12 && size <= 256;
  }
  function begin() {
    reset(false);
    active = new AbortController();
    busy(true);
    return { ticket: generation, controller: active };
  }
  function current(operation) { return operation.ticket === generation && !operation.controller.signal.aborted; }

  el('cloudflareArchiveExportForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (active) return;
    if (!passwordValid(password.value) || password.value !== repeat.value) {
      fail(new Error('Введите одинаковый пароль в оба поля: минимум 12 символов, максимум 256 байт UTF-8.'));
      return;
    }
    const operation = begin();
    const body = JSON.stringify({ password: password.value });
    clearPasswords();
    message.textContent = 'Шифруем копии аккаунтов. На роутере это может занять некоторое время…';
    try {
      const envelope = await api('/api/v1/cloudflare/backups/export', { method: 'POST', body, signal: operation.controller.signal });
      if (!current(operation)) return;
      downloadJSON(envelope, `razvilka-cloudflare-copies-${timestampName()}.json`);
      reset();
      message.textContent = 'Архив подготовлен и передан браузеру для скачивания. Проверьте, что файл сохранился, и сохраните пароль отдельно.';
    } catch (error) { if (current(operation)) fail(error); }
    finally { if (current(operation)) { active = null; busy(false); } }
  });

  el('cloudflareArchiveImportForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (active) return;
    const file = fileInput.files?.[0];
    // Existing encrypted envelopes use byte-based password validation.
    const size = new TextEncoder().encode(importPassword.value).length;
    if (!file || !file.size || file.size > 18 * 1024 * 1024 || size < 12 || size > 256) {
      fail(new Error('Выберите архив JSON до 18 МиБ и введите его пароль (12–256 байт).'));
      return;
    }
    const operation = begin();
    const archivePassword = importPassword.value;
    clearPasswords();
    review.textContent = 'Расшифровываем и проверяем архив. Копии пока не добавляются…';
    try {
      const envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer()));
      if (!current(operation)) return;
      const payload = await api('/api/v1/cloudflare/backups/preview', { method: 'POST', signal: operation.controller.signal, body: JSON.stringify({ password: archivePassword, envelope }) });
      if (!current(operation)) return;
      const result = payload.review;
      if (!result || !Number.isInteger(result.added) || !Number.isInteger(result.existing) || result.added < 0 || result.existing < 0 || result.added + result.existing > 32 || !/^[a-f0-9]{64}$/.test(result.digest)) throw new Error('Панель вернула неполный результат. Проверьте архив ещё раз.');
      const summary = `Будет добавлено: ${result.added}. Уже сохранено: ${result.existing}. Существующие ключи и рабочие маршруты не заменяются.`;
      if (!result.added) {
        reset();
        review.textContent = summary;
        message.textContent = 'Все копии уже есть в хранилище. Восстановление не требуется.';
        return;
      }
      pending = { password: archivePassword, envelope, preview_digest: result.digest };
      review.textContent = summary;
      restore.textContent = `Добавить копии (${result.added})`;
      restore.hidden = cancel.hidden = false;
    } catch (error) { if (current(operation)) fail(error); }
    finally { if (current(operation)) { active = null; busy(false); } }
  });

  restore.addEventListener('click', async () => {
    if (!pending || active) return;
    const body = JSON.stringify({ ...pending, confirm: 'RESTORE_ACCOUNT_COPIES' });
    pending = null;
    const operation = { ticket: generation, controller: new AbortController() };
    active = operation.controller;
    busy(true);
    // Cancellation cannot undo a server commit already in progress.
    cancel.hidden = true;
    message.textContent = 'Добавляем копии. Рабочие профили и маршруты не затрагиваются…';
    try {
      await api('/api/v1/cloudflare/backups/restore', { method: 'POST', body, signal: operation.controller.signal });
      if (!current(operation)) return;
      reset();
      message.textContent = 'Копии добавлены. Существующие ключи сохранены; обходы и маршруты не изменены.';
      document.dispatchEvent(new Event('razvilka:cloudflare-copies-changed'));
    } catch (error) {
      if (current(operation)) {
        fail(error);
        message.textContent += ' Если соединение оборвалось, обновите список копий: повторное восстановление того же архива не создаст дубликаты.';
      }
    } finally { if (current(operation)) { active = null; busy(false); } }
  });

  [password, repeat, importPassword].forEach((input) => input.addEventListener('input', () => reset(false)));
  fileInput.addEventListener('change', () => reset(false));
  cancel.addEventListener('click', () => reset());
  el('cloudflareCopies').addEventListener('toggle', () => { if (!el('cloudflareCopies').open) reset(); });
  document.addEventListener('razvilka:auth-required', () => reset());
  document.addEventListener('razvilka:view-change', (event) => { if (event.detail !== 'settings') reset(); });
  window.addEventListener('pagehide', () => reset());
})();
