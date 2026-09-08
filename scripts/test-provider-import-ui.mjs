import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
const functions = ['renderRemoteProfilePreview', 'previewRemoteProfile', 'importRemoteProfile'].map(name => {
  const match = source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));
  assert.ok(match, name);
  return match[0];
}).join('\n');
const elements = new Map();
const element = name => {
  if (!elements.has(name)) elements.set(name, { value: '', disabled: false, textContent: '', innerHTML: '', addEventListener() {} });
  return elements.get(name);
};
const state = { remoteProfilePreview: null, remoteProfileSelectedIndex: 0, remoteProfileReviewedInput: '', remoteProfileBusy: false };
const preview = { node_count: 1, nodes: [{ name: 'Good', protocol: 'VLESS', server: 'example.test', port: 443 }], rejected: [{ index: 2, code: 'UNSUPPORTED_TRANSPORT', reason: '<unsafe>' }] };
let handler;
let calls = 0;
const context = vm.createContext({
  state, $: element, $$: () => [],
  esc: value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;'),
  api: async (...args) => { calls++; return handler(...args); },
  showDetails() {}, showNotice() {}, refreshEngineConfigs: async () => {}, switchEngineTab() {},
});
vm.runInContext(functions, context);
element('#remoteProfileURI').value = 'reviewed-list';
handler = async () => ({ preview });
await context.previewRemoteProfile();
assert.equal(element('#remoteProfileImportButton').disabled, false);
assert.match(element('#remoteProfileImportButton').textContent, /1 выбранный/);
assert.match(element('#remoteProfilePreview').innerHTML, /Отклонено: 1/);
assert.match(element('#remoteProfilePreview').innerHTML, /&lt;unsafe&gt;/);
assert.doesNotMatch(element('#remoteProfilePreview').innerHTML, /<unsafe>/);

// Programmatic edit must also invalidate permission to import (without an input event).
element('#remoteProfileURI').value = 'different-list';
const before = calls;
await context.importRemoteProfile();
assert.equal(calls, before);
element('#remoteProfileURI').value = 'reviewed-list';
let finish;
handler = async (url, options) => {
  assert.equal(url, '/api/v1/provider-profiles/import');
  const body = JSON.parse(options.body);
  assert.equal(body.accept_partial, true);
  assert.equal(body.selected_index, 0);
  return new Promise(resolve => { finish = resolve; });
};
const pending = context.importRemoteProfile();
await context.importRemoteProfile();
assert.equal(calls, before + 1, 'double import');
finish({ ok: true });
await pending;
assert.equal(element('#remoteProfileURI').value, '');
assert.equal(element('#remoteProfileImportButton').disabled, true);

// Late preview may not authorize a changed input.
element('#remoteProfileURI').value = 'old-input';
handler = () => new Promise(resolve => { finish = resolve; });
const stale = context.previewRemoteProfile();
element('#remoteProfileURI').value = 'new-input';
finish({ preview });
await stale;
assert.equal(state.remoteProfilePreview, null);
assert.equal(element('#remoteProfileImportButton').disabled, true);

handler = async () => { const err = new Error('Rejected'); err.payload = { preview: { node_count: 0, rejected: preview.rejected } }; throw err; };
await context.previewRemoteProfile();
assert.match(element('#remoteProfilePreview').innerHTML, /Нет подходящих узлов/);
assert.match(element('#remoteProfilePreview').innerHTML, /Отклонено: 1/);
assert.equal(element('#remoteProfileImportButton').disabled, true);
assert.equal(state.remoteProfileBusy, false);
console.log('Partial provider import UI checks passed');
