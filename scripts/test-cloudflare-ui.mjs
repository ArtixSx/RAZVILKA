import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../cmd/razvilka/web/cloudflare-accounts.js', import.meta.url), 'utf8');
const html = readFileSync(new URL('../cmd/razvilka/web/index.html', import.meta.url), 'utf8');
const appSource = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');

class Element {
  handlers = {};
  value = ''; textContent = ''; innerHTML = ''; files = []; hidden = false; disabled = false;
  addEventListener(name, fn) { this.handlers[name] = fn; }
  setAttribute() {}
  async fire(name, event = {}) { return this.handlers[name]?.({ preventDefault() {}, ...event }); }
}
const elements = new Map([...html.matchAll(/id="(cloudflare[^"]+)"/g)].map((match) => [match[1], new Element()]));
const document = new Element();
document.querySelector = () => elements.get('cloudflareCopies');
document.getElementById = (id) => { assert.ok(elements.has(id), `missing DOM id ${id}`); return elements.get(id); };
const window = new Element();
const calls = [];
let nextError = null;
let previewDeferred = null;
const context = vm.createContext({
  document, window, AbortController, TextDecoder, Error, TypeError,
  esc: (value) => String(value).replaceAll('<', '&lt;').replaceAll('>', '&gt;'),
  api: async (path, options) => {
    calls.push({ path, options });
    if (nextError) { const error = nextError; nextError = null; throw error; }
    if (path.endsWith('/preview') && previewDeferred) return previewDeferred;
    return path.endsWith('/accounts') ? { accounts: [], limit: 32 } : { account: { format: 'wireguard-v1', verification: 'imported-unverified' } };
  },
});
vm.runInContext(source, context);
const el = (id) => document.getElementById(id);
const form = el('cloudflareCopyForm');
const file = el('cloudflareCopyFile');
const kind = el('cloudflareCopyKind');
const save = el('cloudflareCopySave');
const selectFixture = () => {
  kind.value = 'wireguard-profile';
  file.files = [{ size: 16, arrayBuffer: async () => new TextEncoder().encode('fixture-private').buffer }];
};

for (const format of ['usque-v1', 'wgcf-account-v1', 'wireguard-v1', 'opaque-archive', 'future']) {
  const summary = context.cloudflareAccountSummary({ format, verification: 'pass', running: true });
  assert.doesNotMatch(summary.state, /^(Работает|Доступен|Проверен)$/i);
  assert.match(summary.state, /не проверена|не поддерживается/);
}
assert.equal(calls.length, 0, 'opening the application must not poll provider copies');
await form.fire('submit');
assert.equal(calls.length, 0, 'no file must not submit');
selectFixture();
await form.fire('submit');
assert.equal(calls.length, 1);
assert.equal(calls[0].path, '/api/v1/cloudflare/import/preview');
assert.equal(save.hidden, false);
assert.equal(save.disabled, false);
assert.doesNotMatch(el('cloudflareCopyPreview').innerHTML, /fixture-private/);
await save.fire('click');
assert.equal(calls[1].path, '/api/v1/cloudflare/import');
assert.equal(JSON.parse(calls[1].options.body).confirm, 'SAVE_ACCOUNT_COPY');
assert.equal(save.hidden, true);
const count = calls.length;
await save.fire('click');
assert.equal(calls.length, count, 'save must forget the private candidate after success');

selectFixture();
await form.fire('submit');
await document.fire('razvilka:auth-required');
await save.fire('click');
assert.equal(save.hidden, true);
assert.equal(calls.length, count + 1, 'logout must discard private pending input');

selectFixture();
await form.fire('submit');
nextError = new Error('fixture network failure');
await save.fire('click');
const afterError = calls.length;
await save.fire('click');
assert.equal(calls.length, afterError, 'failed save must discard private pending input');
assert.equal(save.hidden, true);

selectFixture();
let resolvePreview;
previewDeferred = new Promise((resolve) => { resolvePreview = resolve; });
const inFlight = form.fire('submit');
await new Promise((resolve) => setImmediate(resolve));
await document.fire('razvilka:view-change', { detail: 'overview' });
resolvePreview({ account: { format: 'usque-v1' } });
await inFlight;
assert.equal(save.hidden, true, 'late response must not resurrect private data after navigation');
assert.equal(save.disabled, true);
assert.match(appSource, /dispatchEvent\(new Event\('razvilka:auth-required'\)\)/);
assert.match(appSource, /dispatchEvent\(new CustomEvent\('razvilka:view-change'/);
assert.doesNotMatch(source, /sessionStorage|localStorage|console\./);
console.log('Cloudflare copy UI checks passed');
