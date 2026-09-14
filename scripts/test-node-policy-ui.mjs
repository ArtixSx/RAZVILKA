import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
const elements = new Map();
const $ = id => { if (!elements.has(id)) elements.set(id, { value: '', innerHTML: '', textContent: '', hidden: false, disabled: false, open: false, showModal() { this.open = true; }, close() { this.open = false; } }); return elements.get(id); };
let selected = ['node-a'], handler, refreshed = 0;
const requests = [];
const service = { id: 'telegram', name: 'Telegram', applied_enabled: true, applied_route: 'sing-box:group-a', applied_sources: ['192.168.1.40/32'] };
const base = { schema: 1, service_id: 'telegram', revision: 4, enabled: true, mode: 'auto', group_id: 'group-a', device_sources: ['192.168.1.40/32'], allowed_node_ids: ['node-a'], allowed_source_ids: ['source-a'], trust_classes: ['manual'], allowed_engines: ['sing-box'], check_interval_seconds: 60, hold_down_seconds: 600, max_switches_per_hour: 3 };
const inventory = { groups: [{ id: 'group-a', name: 'Группа', mode: 'fallback', node_ids: ['node-a', 'node-b'] }], nodes: [{ id: 'node-a', name: 'Мой сервер', origins: [{ source_id: 'source-a' }] }, { id: 'node-b', name: 'Публичный', origins: [{ source_id: 'source-b' }] }], sources: [{ id: 'source-a', kind: 'manual' }, { id: 'source-b', kind: 'subscription' }] };
const policyData = { config_revision: 17, policies: { telegram: { policy: base, persisted: true, reason: 'Готово' } } };
const context = vm.createContext({ state: { services: [service] }, $, $$: selector => selector.includes(':checked') ? selected.map(id => ({ dataset: { policyNode: id } })) : [], AbortController, Promise, Set, Number, String, encodeURIComponent, esc: String,
  nodeScopeText: sources => sources.join(', '), nodeDisplayName: node => node.name, nodeBrowserSourceName: id => id,
  api: async (url, options) => { requests.push({ url, options }); return handler(url, options); }, refreshAfterMutation: async () => { refreshed++; } });
vm.runInContext(readFileSync(new URL('../cmd/razvilka/web/node-policy-ui.js', import.meta.url), 'utf8'), context);
const read = async url => url.endsWith('/services') ? structuredClone([service]) : url.endsWith('/nodes') ? structuredClone(inventory) : structuredClone(policyData);
handler = read;
await context.openNodePolicy('telegram');
assert.match($('#nodePolicyGroup').textContent, /192\.168\.1\.40\/32/);
assert.match($('#nodePolicyMembers').innerHTML, /Публичный источник/);
let finish;
handler = (url, options) => {
  assert.equal(url, '/api/v1/service-policies/telegram');
  const body = JSON.parse(options.body);
  assert.equal(body.config_revision, 17); assert.equal(body.expected_revision, 4);
  assert.deepEqual(body.policy.allowed_node_ids, ['node-a']);
  assert.deepEqual(body.policy.allowed_source_ids, ['source-a']);
  assert.deepEqual(body.policy.trust_classes, ['manual'], 'unselected public node expanded source trust');
  assert.deepEqual(body.policy.device_sources, ['192.168.1.40/32']);
  return new Promise(resolve => { finish = resolve; });
};
const event = { preventDefault() {} };
const saving = context.saveNodePolicy(event);
await context.saveNodePolicy(event);
assert.equal(requests.filter(item => item.options?.method === 'PUT').length, 1);
context.closeNodePolicy();
finish({ reason: 'Разрешено', live_applied: false }); await saving;
assert.equal(refreshed, 0, 'closed policy request repainted authenticated state');
assert.equal($('#nodePolicyStatus').textContent, '');
assert.ok(requests.every(item => !item.url.endsWith('/apply')), 'saving permissions applied a route');

handler = read; await context.openNodePolicy('telegram'); selected = [];
const before = requests.length; await context.saveNodePolicy(event);
assert.equal(requests.length, before, 'empty auto membership submitted');
context.closeNodePolicy();
handler = url => new Promise(resolve => { if (url.endsWith('/service-policies')) finish = () => resolve(structuredClone(policyData)); else resolve(url.endsWith('/nodes') ? structuredClone(inventory) : structuredClone([service])); });
const loading = context.openNodePolicy('telegram'); context.closeNodePolicy(); finish(); await loading;
assert.equal($('#nodePolicyDialog').open, false); assert.equal($('#nodePolicyMembers').innerHTML, '');
console.log('Service policy UI: explicit node/source trust, fixed device scope, revision, no implicit route apply and cancellation passed');
