import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
const fn = source.match(/async function importPrivateBackup\([^]*?\n}\n/);
assert.ok(fn, 'real import function must remain testable');
for (const mode of ['rollback', 'recovery-required', 'disconnect', 'success-refresh-error', 'success', 'cancel']) {
  const elements = new Map(['confirmPrivateBackup', 'privateBackupImportPassword', 'previewPrivateBackup', 'privateBackupPreview'].map(id => [id, { disabled: false, value: 'synthetic secret password', textContent: '', innerHTML: '' }]));
  const state = { privateBackupEnvelope: { ciphertext: 'synthetic encrypted archive' }, privateBackupPreview: { valid: true } };
  let requests = 0;
  const notices = [];
  const context = vm.createContext({
    state, $: selector => elements.get(selector.slice(1)),
    askConfirmation: async () => mode !== 'cancel',
    esc: value => String(value).replaceAll('<', '&lt;'),
    api: async () => {
      requests++;
      if (mode.startsWith('success')) return { ok: true };
      const error = new Error('synthetic private internal cause');
      if (mode === 'rollback') error.payload = { rolled_back: true, recovery_required: false, code: 'PRIVATE_BACKUP_IMPORT_ROLLED_BACK', phase: 'engine_files' };
      if (mode === 'recovery-required') error.payload = { rolled_back: false, recovery_required: true, code: 'PRIVATE_BACKUP_RECOVERY_REQUIRED', phase: 'engine_files' };
      throw error;
    },
    refreshAll: async () => { if (mode === 'success-refresh-error') throw new Error('refresh failed'); },
    showPlan: async () => {},
    showDetails: (body, title) => notices.push({ body, title }),
  });
  vm.runInContext(fn[0], context);
  await context.importPrivateBackup();
  if (mode === 'cancel') { assert.equal(requests, 0); assert.ok(state.privateBackupPreview.valid); continue; }
  assert.equal(requests, 1);
  assert.equal(state.privateBackupEnvelope, null);
  assert.equal(state.privateBackupPreview, null);
  assert.equal(elements.get('privateBackupImportPassword').value, '');
  assert.equal(elements.get('confirmPrivateBackup').disabled, true);
  assert.equal(elements.get('previewPrivateBackup').disabled, true);
  const text = elements.get('privateBackupPreview').innerHTML;
  if (mode === 'recovery-required') assert.match(text, /не все изменения удалось отменить/);
  if (mode === 'rollback') assert.match(text, /Изменения этой операции отменены/);
  if (mode === 'disconnect') assert.match(text, /Не удалось подтвердить результат/);
  if (mode === 'success-refresh-error') assert.match(text, /Импорт выполнен/);
  assert.ok(!JSON.stringify(notices).includes('synthetic private internal cause'));
  await context.importPrivateBackup();
  assert.equal(requests, 1, 'stale preview cannot submit again');
}
console.log('Private backup import outcome UI checks passed');
