import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../cmd/razvilka/web/cloudflare-backups.js', import.meta.url), 'utf8');
const html = readFileSync(new URL('../cmd/razvilka/web/index.html', import.meta.url), 'utf8');
class Element {
  handlers = {}; value = ''; textContent = ''; files = []; hidden = false; disabled = false;
  addEventListener(name, fn) { (this.handlers[name] ||= []).push(fn); }
  setAttribute() {}
  async fire(name, event = {}) { for (const fn of this.handlers[name] || []) await fn({ preventDefault() {}, ...event }); }
  dispatchEvent(event) { return this.fire(event.type, event); }
}
const elements = new Map([...html.matchAll(/id="(cloudflare[^"]+)"/g)].map((match) => [match[1], new Element()]));
const document = new Element();
document.getElementById = (id) => { assert.ok(elements.has(id), `missing DOM id ${id}`); return elements.get(id); };
const window = new Element();
const el = (id) => document.getElementById(`cloudflareArchive${id}`);
const calls = [], downloads = [];
const envelope = { kind: 'razvilka-private-backup', ciphertext: 'synthetic encrypted fixture' };
const preview = { review: { added: 1, existing: 0, digest: 'a'.repeat(64) } };
let nextError, deferred, nextPreview;
const context = vm.createContext({ document, window, AbortController, TextDecoder, TextEncoder, Error, SyntaxError, Event,
  downloadJSON: (...args) => downloads.push(args), timestampName: () => 'fixture-date',
  api: async (path, options) => {
    calls.push({ path, options });
    if (nextError) { const error = nextError; nextError = null; throw error; }
    if (deferred) return deferred;
    if (path.endsWith('/export')) return envelope;
    return nextPreview || preview;
  },
});
vm.runInContext(source, context);
const fixture = () => {
  el('ImportPassword').value = 'synthetic fixture password';
  el('File').files = [{ size: 80, arrayBuffer: async () => new TextEncoder().encode(JSON.stringify(envelope)).buffer }];
};
const allPasswordsCleared = () => {
  for (const id of ['Password', 'Repeat', 'ImportPassword']) assert.equal(el(id).value, '', `${id} retained`);
};
assert.equal(calls.length, 0, 'must not poll archives');
el('Password').value = 'mismatch strong password';
el('Repeat').value = 'different strong password';
await el('ExportForm').fire('submit');
assert.equal(calls.length, 0);
allPasswordsCleared();
el('Password').value = el('Repeat').value = 'synthetic fixture password';
await el('ExportForm').fire('submit');
assert.equal(calls[0].path, '/api/v1/cloudflare/backups/export');
assert.equal(downloads.length, 1);
assert.equal(downloads[0][0], envelope);
allPasswordsCleared();

fixture();
await el('ImportForm').fire('submit');
assert.equal(el('Restore').hidden, false);
assert.equal(el('Restore').disabled, false);
assert.match(el('Review').textContent, /Будет добавлено: 1/);
assert.doesNotMatch(el('Review').textContent, /ciphertext|synthetic/);
allPasswordsCleared();
await el('Restore').fire('click');
let call = calls.at(-1);
assert.equal(call.path, '/api/v1/cloudflare/backups/restore');
assert.equal(JSON.parse(call.options.body).preview_digest, 'a'.repeat(64));
assert.equal(JSON.parse(call.options.body).confirm, 'RESTORE_ACCOUNT_COPIES');
const count = calls.length;
await el('Restore').fire('click');
assert.equal(calls.length, count, 'duplicate clicks must not restore twice');
assert.equal(el('Restore').hidden, true);

for (const action of [
  () => document.fire('razvilka:auth-required'),
  () => document.fire('razvilka:view-change', { detail: 'overview' }),
  () => window.fire('pagehide'),
  () => document.getElementById('cloudflareCopies').fire('toggle'),
  () => el('Cancel').fire('click'),
  () => el('File').fire('change'),
  () => el('ImportPassword').fire('input'),
]) {
  fixture(); await el('ImportForm').fire('submit');
  const before = calls.length;
  await action(); await el('Restore').fire('click');
  assert.equal(calls.length, before, 'reset must discard pending restoration');
  assert.equal(el('Restore').hidden, true);
  allPasswordsCleared();
}
fixture(); await el('ImportForm').fire('submit');
nextError = new Error('synthetic network failure');
await el('Restore').fire('click');
assert.match(el('Message').textContent, /обновите список/);
assert.equal(el('Restore').hidden, true);
allPasswordsCleared();

for (const path of ['export', 'preview', 'restore']) {
  if (path === 'restore') { fixture(); await el('ImportForm').fire('submit'); }
  fixture(); el('Password').value = el('Repeat').value = 'synthetic fixture password';
  let resolve;
  deferred = new Promise((done) => { resolve = done; });
  const inFlight = path === 'export' ? el('ExportForm').fire('submit') : path === 'preview' ? el('ImportForm').fire('submit') : el('Restore').fire('click');
  await new Promise((done) => setImmediate(done));
  const downloadCount = downloads.length;
  await document.fire('razvilka:auth-required');
  resolve(path === 'export' ? envelope : preview);
  await inFlight;
  deferred = null;
  assert.equal(downloads.length, downloadCount, 'late export must not download after logout');
  assert.equal(el('Restore').hidden, true, 'late response resurrected restore');
  allPasswordsCleared();
}
fixture(); nextPreview = { review: { added: 0, existing: 1, digest: 'a'.repeat(64) } };
await el('ImportForm').fire('submit');
assert.equal(el('Restore').hidden, true);
assert.match(el('Message').textContent, /не требуется/);
allPasswordsCleared();
nextPreview = { review: { added: -1, existing: 0, digest: 'a'.repeat(64) } };
fixture(); await el('ImportForm').fire('submit');
assert.equal(el('Restore').hidden, true);
allPasswordsCleared();
assert.doesNotMatch(source, /sessionStorage|localStorage|console\./);
console.log('Cloudflare archive UI checks passed');
