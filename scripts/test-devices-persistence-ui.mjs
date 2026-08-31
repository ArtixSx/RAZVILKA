import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
const html = readFileSync(new URL('../cmd/razvilka/web/index.html', import.meta.url), 'utf8');
const names = ['acceptDeviceList', 'renderDevices', 'refreshDevices'];
const code = names.map(name => {
  const match = source.match(new RegExp('(?:async )?function ' + name + '\\([^]*?\\n}\\n'));
  assert.ok(match, name + ' remains testable');
  return match[0];
}).join('\n');
assert.match(html, /id="devicePersistenceWarning"[^>]*role="status"[^>]*hidden/);
assert.match(source, /\['devices', '\/api\/v1\/devices\?view=status'\]/);

const elements = new Map(['devicePersistenceWarning', 'deviceSearch', 'deviceGrid', 'deviceEmpty', 'deviceGroupSuggestions', 'refreshDevices'].map(id => [id, { value: '', textContent: '', innerHTML: '', style: {}, hidden: true }]));
const state = {};
let payload = { devices: [], persistence_warning: '<b>Сохранение не подтверждено</b>' };
let fail = false;
let notices = 0;
const context = vm.createContext({
  state, $: selector => elements.get(selector.slice(1)),
  api: async url => { assert.equal(url, '/api/v1/devices?view=status'); if (fail) throw new Error('unavailable'); return payload; },
  showDetails: () => { notices++; },
});
vm.runInContext(code, context);
await context.refreshDevices();
assert.equal(elements.get('devicePersistenceWarning').hidden, false);
assert.equal(elements.get('devicePersistenceWarning').textContent, payload.persistence_warning);
assert.equal(elements.get('devicePersistenceWarning').innerHTML, '', 'warning must be text, never HTML');
assert.equal(elements.get('refreshDevices').disabled, false);
payload = { devices: [], persistence_warning: '' };
await context.refreshDevices();
assert.equal(elements.get('devicePersistenceWarning').hidden, true);
payload = [];
await context.refreshDevices();
assert.equal(state.devices, payload, 'legacy array fallback');
assert.equal(state.devicePersistenceWarning, '');
fail = true;
await context.refreshDevices();
assert.equal(notices, 1);
assert.equal(elements.get('refreshDevices').disabled, false);
console.log('Device persistence warning UI checks passed');
