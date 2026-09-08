import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const elements = new Map();
const $ = id => { if (!elements.has(id)) elements.set(id, { value: '', textContent: '', disabled: false, hidden: false }); return elements.get(id); };
const state = { status: { revision: 12 }, services: [{ id: 'telegram', name: 'Telegram', applied_sources: ['192.168.1.40/32'] }], devices: [], nodeFlow: null };
let fresh = false, handler, refreshed = 0;
const calls = [];
const context = vm.createContext({ state, $, $$: () => [], AbortController, Date, Number, JSON, Set, encodeURIComponent,
  nodeByID: id => ({ id }), nodeServiceHealth: () => ({ state: fresh ? 'available' : 'inconclusive' }),
  api: async (url, options) => { calls.push({ url, options }); return handler(url, options); }, refreshAll: async () => { refreshed++; }, esc: String });
vm.runInContext(readFileSync(new URL('../cmd/razvilka/web/node-intent-ui.js', import.meta.url), 'utf8'), context);
const pass = { ok: true, result: { node_id: 'node-a', service_id: 'telegram', available: true } };
const preview = { ready: true, scope_selection: 'applied', effective_scope: { mode: 'selected', sources: ['192.168.1.40/32'], summary: '192.168.1.40/32' }, review: { node_id: 'node-a', service_id: 'telegram', revision: 12, generation: 5, review_token: 'one-use-token', reviewed_digest: 'digest', expires_at: new Date(Date.now() + 60000).toISOString() } };
const begin = () => { calls.length = 0; fresh = false; state.status.revision = 12; state.nodeFlow = { id: 'node-a', busy: false }; $('#nodeCheckID').value = 'node-a'; $('#nodeCheckService').value = 'telegram'; $('#nodeIntentScope').value = 'applied'; $('#nodeIntentSources').value = ''; $('#nodeCheckResult').textContent = ''; context.renderNodeIntentScope(); };
const success = async (url, options) => {
  if (url.endsWith('/check')) return pass;
  if (url.endsWith('/preview')) { assert.deepEqual(JSON.parse(options.body), { service_id: 'telegram', scope: { mode: 'applied' }, expected_revision: 12 }); return preview; }
  if (url.endsWith('/apply')) { assert.deepEqual(JSON.parse(options.body), { service_id: 'telegram', review_token: 'one-use-token', reviewed_digest: 'digest', revision: 12, generation: 5, confirm: 'APPLY_NODE_ROUTE' }); return { live_applied: true }; }
  throw new Error(url);
};
begin(); handler = success;
await context.runNodeIntent();
assert.deepEqual(calls.map(item => item.url.split('/').at(-1)), ['check', 'preview', 'apply']);
assert.match($('#nodeCheckResult').textContent, /включено и прошло проверку/);
assert.equal(refreshed, 1);

begin(); fresh = true;
await context.runNodeIntent();
assert.deepEqual(calls.map(item => item.url.split('/').at(-1)), ['preview', 'apply'], 'fresh proof did not skip only the redundant isolated check');

begin(); handler = async () => ({ ok: false, result: { ...pass.result, available: false, message: 'Контрольный адрес недоступен' } });
await context.runNodeIntent();
assert.equal(calls.length, 1, 'inconclusive check allowed apply');
assert.match($('#nodeCheckResult').textContent, /Контрольный адрес/);

for (const change of [{ revision: 13 }, { node_id: 'node-b' }, { service_id: 'youtube' }, { expires_at: '2001-01-01T00:00:00Z' }, { expires_at: 'invalid' }]) {
  begin(); fresh = true; handler = async () => ({ ...preview, review: { ...preview.review, ...change } });
  await context.runNodeIntent();
  assert.equal(calls.length, 1, `stale/mismatched review applied: ${JSON.stringify(change)}`);
}

begin(); state.status.revision = 13;
await context.runNodeIntent();
assert.equal(calls.length, 0, 'a background refresh replaced the revision of an already displayed intent');
begin(); fresh = true; handler = async () => ({ ...preview, effective_scope: { mode: 'all', sources: [] } });
await context.runNodeIntent();
assert.equal(calls.length, 1, 'preview broadened the displayed scope to all LAN');

let finish;
begin(); handler = () => new Promise(resolve => { finish = resolve; });
const checking = context.runNodeIntent();
await context.runNodeIntent();
assert.equal(calls.length, 1, 'double submission started another operation');
state.nodeFlow.controller.abort(); state.nodeFlow = null;
finish(pass); await checking;
assert.equal(calls.length, 1, 'closed/logout check gained preview/apply authority');

begin(); fresh = true;
const reviewing = context.runNodeIntent();
state.nodeFlow.controller.abort(); state.nodeFlow = null;
finish(preview); await reviewing;
assert.equal(calls.length, 1, 'closed/logout preview gained apply authority');

begin(); $('#nodeIntentScope').value = ''; context.renderNodeIntentScope();
await context.runNodeIntent(); assert.equal(calls.length, 0, 'a new service silently chose all LAN');
$('#nodeIntentScope').value = 'selected'; context.renderNodeIntentScope();
await context.runNodeIntent(); assert.equal(calls.length, 0, 'empty device choice silently became all LAN');
console.log('Single-action node flow, explicit scope, fresh-proof shortcut, revision and cancellation fences passed');
