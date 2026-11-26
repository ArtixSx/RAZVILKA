import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const elements = new Map(), listeners = new Map(), requests = [];
function element(key) {
  if (!elements.has(key)) elements.set(key, { innerHTML: '', textContent: '', hidden: false, disabled: false, open: false, classList: { toggle() {} }, addEventListener() {}, querySelector(selector) { return element(`${key} ${selector}`); }, showModal() { this.open = true; }, close() { this.open = false; } });
  return elements.get(key);
}
let handler, confirm = async () => true;
const timers = new Map(); let serial = 0;
const state = { status: { version: '0.18.1-dev' }, appUpdate: null };
const context = vm.createContext({ state, $: element, esc: String, AbortController, Promise, Date, Number, Math, JSON, String,
  setTimeout: callback => { const id = ++serial; timers.set(id, callback); return id; }, clearTimeout: id => timers.delete(id),
  document: { addEventListener: (name, callback) => listeners.set(name, callback), body: { appendChild() {} }, createElement: name => element(name) },
  api: async (url, options = {}) => { requests.push({ url, options }); return handler(url, options); },
  askConfirmation: (...args) => confirm(...args)
});
vm.runInContext(readFileSync(new URL('../cmd/razvilka/web/app-update-ui.js', import.meta.url), 'utf8'), context);
const fresh = { installed_version: '0.18.1-dev', latest_version: '0.19.0', state: 'update', update_available: true, can_prepare: true, checked_at: new Date().toISOString() };
const ready = { id: 'reviewed-job', state: 'ready', can_apply: true, can_cancel: false, review_token: 'review-token', config_revision: 19, release: { version: '0.19.0', architecture: 'arm64', archive: { size: 10000000 } }, message: 'Пакет проверен' };
assert.equal(context.appUpdateBadge(null).label, 'Не проверено');
assert.equal(context.appUpdateBadge({ ...fresh, checked_at: '2001-01-01T00:00:00Z' }).kind, '');
assert.equal(context.appUpdateBadge({ ...fresh, state: 'development', update_available: false }).label, 'Тестовая сборка');
assert.equal(context.appUpdateBadge({ ...fresh, state: 'ahead', update_available: false }).label, 'Новее релиза');
assert.equal(context.appUpdateBadge({ ...fresh, state: 'check-failed' }).label, 'Ошибка проверки');

context.bindAppUpdateUI();
handler = async url => url.startsWith('/api/v1/update') ? structuredClone(fresh) : { state: 'idle' };
await context.openAppUpdate();
assert.equal(requests.filter(r => r.options.method === 'POST').length, 0, 'opening version badge mutated app');
handler = async (url, options) => { assert.equal(url, '/api/v1/self-update/prepare'); assert.equal(JSON.parse(options.body).confirm, 'PREPARE_APP_UPDATE'); return { state: 'preparing', can_cancel: true }; };
await context.prepareAppUpdate();
assert.equal(requests.filter(r => r.url.endsWith('/apply')).length, 0, 'download automatically installed release');
handler = async (url, options) => { assert.equal(url, '/api/v1/self-update/current'); assert.equal(options.method, 'DELETE'); return { state: 'cancelled', can_cancel: false }; };
await context.cancelAppUpdatePreparation();
context.closeAppUpdate();

handler = async url => url.startsWith('/api/v1/update') ? structuredClone(fresh) : structuredClone(ready);
await context.openAppUpdate();
let releaseConfirm;
confirm = () => new Promise(resolve => { releaseConfirm = resolve; });
const pending = context.installAppUpdate();
context.closeAppUpdate(); releaseConfirm(true); await pending;
assert.equal(requests.filter(r => r.url.endsWith('/apply')).length, 0, 'closed modal submitted stale confirmed release');

await context.openAppUpdate(); confirm = async () => true;
handler = async (url, options) => { assert.equal(url, '/api/v1/self-update/apply'); const body = JSON.parse(options.body); assert.deepEqual(body, { job_id: ready.id, review_token: ready.review_token, config_revision: 19, confirm: 'INSTALL_APP_UPDATE' }); return { state: 'installing', can_apply: false, helper_pid: 123 }; };
await context.installAppUpdate(); await context.installAppUpdate();
assert.equal(requests.filter(r => r.url.endsWith('/apply')).length, 1, 'duplicate click installed twice');
context.closeAppUpdate();

listeners.get('razvilka:auth-required')();
let resolveOld;
handler = () => new Promise(resolve => { resolveOld = resolve; });
const stale = context.refreshAppUpdate(true); listeners.get('razvilka:auth-required')(); resolveOld(fresh); await stale;
assert.equal(state.appUpdate, null, 'signed-out response repainted stale update authority');
state.appUpdate = { ...fresh, state: 'development', update_available: false, can_prepare: false };
handler = async () => ({ state: 'idle' });
const before = requests.length;
await context.prepareAppUpdate(); assert.equal(requests.length, before, 'older stable offered on dev build');
console.log('App update UI: truthful badge, read-only opening, explicit prepare/install, bound review, duplicate and stale cancellation passed');
