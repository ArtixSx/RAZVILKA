import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
const names = ['nodeByID', 'openNodeCheck', 'updateNodeCheckSelection', 'closeNodeCheck', 'runNodeCheck', 'previewNodeRoute', 'closeNodeRoute', 'applyNodeRoute', 'waitNodeApplyJob', 'nodeRecoveryBanner'];
const functions = names.map(name => {
  const match = source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));
  assert.ok(match, name);
  return match[0];
}).join('\n');
const elements = new Map();
const $ = id => {
  if (!elements.has(id)) elements.set(id, { value: '', textContent: '', innerHTML: '', hidden: false, disabled: false, checked: false, open: false, style: {}, classList: { toggle() {} }, querySelector(selector) { return $(`${id} ${selector}`); }, showModal() { this.open = true; }, close() { this.open = false; } });
  return elements.get(id);
};
const state = { services: [{ id: 'telegram', name: 'Telegram', probe_url: 'https://telegram.org' }], nodes: { nodes: [{ id: 'node-a', name: 'Name <private>' }] }, routeOptions: [] };
let handler;
const calls = [];
let timer;
const context = vm.createContext({ state, $, $$: () => [], AbortController, Date, Number, JSON, encodeURIComponent,
  esc: value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;'),
  api: async (url, options) => { calls.push({ url, options }); return handler(url, options); },
  refreshNodes: async () => {}, refreshAfterMutation: async () => {}, setTimeout: fn => { timer = fn; return 1; }, clearTimeout() {},
  nodeDisplayName: node => node.name || 'узел',
});
const browserSource = readFileSync(new URL('../cmd/razvilka/web/node-browser.js', import.meta.url), 'utf8');
vm.runInContext(browserSource.match(/function nodeServiceScenario\([^]*?\n}\n/)[0] + functions, context);
assert.equal(context.nodeRecoveryBanner({ state: 'idle' }), '');
assert.equal(context.nodeRecoveryBanner({ state: 'recovered', message: 'Применённые маршруты восстановлены' }), '', 'historical recovery must not claim routes are still running');
assert.match(context.nodeRecoveryBanner({ state: 'revalidating', message: '<untrusted>' }), /Повторная проверка.*&lt;untrusted&gt;/);
assert.doesNotMatch(context.nodeRecoveryBanner({ state: 'network-stale', message: 'Проверка не завершена' }), /восстановлен/);
assert.match(context.nodeRecoveryBanner({ state: 'requires-review' }), /требует вашего внимания/);
// An explicit browser service wins over an unrelated historical node check.
state.services.push({ id: 'youtube', name: 'YouTube', probe_url: 'https://youtube.com' });
state.nodes.nodes[0].health = { service_id: 'telegram' };
$('#nodeBrowserService').value = 'youtube';
context.openNodeCheck('node-a');
assert.equal($('#nodeCheckService').value, 'youtube', 'historical proof replaced the selected service');
context.closeNodeCheck();
$('#nodeBrowserService').value = '';
context.openNodeCheck('node-a');
assert.equal($('#nodeCheckService').value, 'telegram', 'history is a fallback only without a valid browser selection');
context.closeNodeCheck();
state.nodes.nodes[0].state = 'expired';
context.openNodeCheck('node-a');
assert.equal($('#nodeCheckDialog').open, false, 'expired subscription opened a check flow');
assert.equal(state.nodeFlow, null);
delete state.nodes.nodes[0].state;
const begin = () => { context.openNodeCheck('node-a'); $('#nodeCheckService').value = 'telegram'; };
const event = { preventDefault() {} };
begin();
let finish;
handler = () => new Promise(resolve => { finish = resolve; });
const running = context.runNodeCheck(event);
await context.runNodeCheck(event);
assert.equal(calls.length, 1, 'double check request');
finish({ ok: true, result: { node_id: 'node-a', service_id: 'telegram', available: true } });
await running;
assert.equal($('#nodeCheckPreview').hidden, false);
assert.equal(calls.length, 1, 'check auto-applied or auto-previewed');

begin();
const late = context.runNodeCheck(event);
context.closeNodeCheck();
assert.equal(calls.at(-1).options.signal.aborted, true);
finish({ ok: true, result: { node_id: 'node-a', service_id: 'telegram', available: true } });
await late;
assert.equal($('#nodeCheckPreview').hidden, true, 'closed check gained authority');

const response = { ready: true, safe_mode: false, review: { node_id: 'node-a', service_id: 'telegram', review_token: 'token', reviewed_digest: 'digest', revision: 7, generation: 4, expires_at: new Date(Date.now() + 60000).toISOString() }, service_name: 'Telegram', node_name: 'Name <private>', note: 'One service', transaction: { blockers: [] } };
begin();
handler = async () => response;
await context.previewNodeRoute();
assert.equal($('#nodeRouteApply').disabled, false);
assert.match($('#nodeRouteSummary').innerHTML, /&lt;private&gt;/);
assert.doesNotMatch($('#nodeRouteSummary').innerHTML, /Name <private>/);
handler = (url, options) => {
  assert.equal(url, '/api/v1/nodes/node-a/apply');
  assert.deepEqual(JSON.parse(options.body), { service_id: 'telegram', review_token: 'token', reviewed_digest: 'digest', revision: 7, generation: 4, confirm: 'APPLY_NODE_ROUTE', idempotency_key: 'node-apply-token' });
  return new Promise(resolve => { finish = resolve; });
};
const beforeApply = calls.length;
const applying = context.applyNodeRoute();
await context.applyNodeRoute();
assert.equal(calls.length, beforeApply + 1, 'double apply');
context.closeNodeRoute();
assert.equal(calls.at(-1).options.signal.aborted, true);
finish({ live_applied: true });
await applying;
assert.doesNotMatch($('#nodeRouteStatus').textContent, /Маршрут применён/);
assert.equal(state.nodeRouteReview, null, 'closed window retained private review');
assert.equal($('#nodeRouteDialog').open, false);

context.closeNodeRoute();
begin();
handler = async () => response;
await context.previewNodeRoute();
handler = async () => ({ live_applied: true });
await context.applyNodeRoute();
assert.equal($('#nodeRouteStatus').textContent, 'Маршрут применён и прошёл проверки. Проверьте сервис на выбранном устройстве.');

context.closeNodeRoute();
begin();
handler = async () => ({ ...response, ready: false, safe_mode: true });
await context.previewNodeRoute();
assert.equal($('#nodeRouteApply').disabled, true);
assert.match($('#nodeRouteStatus').textContent, /безопасный режим/);

context.closeNodeRoute();
begin();
handler = () => new Promise(resolve => { finish = resolve; });
const latePreview = context.previewNodeRoute();
context.closeNodeCheck();
finish(response);
await latePreview;
assert.equal(state.nodeRouteReview, null, 'closed preview became applicable');

begin();
handler = async () => response;
await context.previewNodeRoute();
timer();
assert.equal($('#nodeRouteApply').disabled, true, 'expired review remained applicable');
context.closeNodeRoute();

console.log('Node reviewed apply, double submission and cancellation checks passed');
