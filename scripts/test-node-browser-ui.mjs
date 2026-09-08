import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../cmd/razvilka/web/node-browser.js', import.meta.url), 'utf8');
const elements = new Map();
const $ = id => {
  if (!elements.has(id)) elements.set(id, { value: '', textContent: '', innerHTML: '', hidden: false, disabled: false, checked: false, open: false, style: {}, classList: { toggle() {} }, setAttribute() {}, contains() { return false; }, querySelector(selector) { return $(`${id} ${selector}`); }, showModal() { this.open = true; }, close() { this.open = false; }, focus() {} });
  return elements.get(id);
};
const profile = 'wan:test-network';
const now = Date.now();
let clockNow = now;
class TestDate extends Date { constructor(...args) { super(...(args.length ? args : [clockNow])); } static now() { return clockNow; } }
const fresh = service => ({ service_id: service, network_profile: profile, route_path_id: 'sing-box:node-bbbbbb', verdict: 'PASS', state: 'available', test_level: 'service', checked_at: new Date(now - 1000).toISOString(), expires_at: new Date(now + 60000).toISOString() });
const state = { services: [{ id: 'telegram', name: 'Telegram', probe_url: 'https://telegram.org' }, { id: 'youtube', name: 'YouTube', probe_url: 'https://youtube.com' }], nodes: { available: true, network_profile: profile, nodes: [], sources: [{ id: 'feed', kind: 'community' }, { id: 'manual', kind: 'manual' }], country_metadata: {}, groups: [] }, nodeFeeds: { available: true, sources: [{ source_id: 'feed', name: 'Каталог' }], presets: [{ id: 'public', name: 'Публичный каталог' }] } };
const calls = [];
let handler = async () => ({});
let scheduled;
const document = { hidden: false, activeElement: null, getElementById: id => $(`#${id}`), addEventListener() {} };
const domQueries = new Map();
state.currentView = 'nodes';
$('#authScreen').hidden = true;
const esc = value => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const context = vm.createContext({ state, $, $$: selector => domQueries.get(selector) || [], Date: TestDate, document, Intl, JSON, Set, Map, Number, String, encodeURIComponent, esc,
  api: async (url, options) => { calls.push({ url, options }); return handler(url, options); },
  nodeExpiryText: () => 'Актуален', nodeRecoveryBanner: () => '', renderNodeGroups() {},
  refreshNodes: async () => {}, askConfirmation: async () => true, showDetails() {},
  closeNodeCheck() {}, clearNodeReveal() {}, showAuth() { $('#authScreen').hidden = false; },
  setTimeout: callback => { scheduled = callback; return 1; }, clearTimeout() {},
  nodeByID: id => state.nodes.nodes.find(node => node.id === id),
});
vm.runInContext(source + '\nthis.browser = nodeBrowser; this.renderNodes = renderNodeBrowser; this.renderNodeFeeds = renderNodeSubscriptions;', context);
const node = (id, health = {}) => ({ id, name: `Узел ${id.replace('node-', '')}`, protocol: 'VLESS', transport: 'tcp', tls: true, state: 'quarantined', origins: [{ source_id: 'feed' }], health });
state.nodes.nodes = [node('node-aaaaaa'), node('node-bbbbbb', { history: [fresh('telegram')] })];
state.nodes.country_metadata = { 'node-aaaaaa': { country_code: 'NL', country_source: 'publisher' } };
$('#nodeBrowserService').value = 'telegram';
context.renderNodes();
assert.equal(calls.length, 0, 'rendering started network work');
assert.match($('#nodeList').innerHTML, /Нидерланды/);
assert.match($('#nodeList').innerHTML, /Работает/);
assert.match($('#nodeList').innerHTML, /Пинг · TCP/);
assert.equal(context.nodeServiceHealth(state.nodes.nodes[1], 'youtube').state, 'quarantined', 'Telegram proof leaked to YouTube');
for (const checked_at of [undefined, '', 'bad', '0001-01-01T00:00:00Z']) {
  state.nodes.nodes[0].health = { checked_at, message: '<private-label>' };
  context.renderNodes();
  assert.doesNotMatch($('#nodeList').innerHTML, /01\.01\.1|private-label/);
}
state.nodes.nodes[0].name = '<img src=x onerror=alert(1)>';
context.renderNodes();
assert.match($('#nodeList').innerHTML, /&lt;img/);
assert.doesNotMatch($('#nodeList').innerHTML, /<img/);
context.browser.pings = [{ node_id: 'node-aaaaaa', reachable: true, latency_ms: 17, checked_at: new Date(now).toISOString(), network_profile: profile }];
context.renderNodes();
assert.match($('#nodeList').innerHTML, /17 мс/);
assert.equal(context.nodeServiceHealth(state.nodes.nodes[0], 'telegram').state, 'quarantined', 'TCP ping granted service availability');
context.browser.pings[0].network_profile = 'another-network';
assert.equal(context.nodePassivePing('node-aaaaaa'), null);
context.browser.pings[0].network_profile = profile;
$('#nodeSort').value = 'latency';
assert.equal(context.nodeFilteredList()[0].id, 'node-aaaaaa');
$('#nodeStateFilter').value = 'available';
assert.deepEqual(Array.from(context.nodeFilteredList(), item => item.id), ['node-bbbbbb']);
$('#nodeStateFilter').value = '';
context.browser.country = 'NL';
assert.equal(context.nodeFilteredList().length, 1);
context.browser.country = '';
context.browser.source = 'manual';
assert.equal(context.nodeFilteredList().length, 0);
context.browser.source = '';

const expired = { ...node('node-cccccc'), state: 'expired' };
state.nodes.nodes.push(expired);
context.browser.selected.add(expired.id);
context.renderNodes();
assert.equal(context.browser.selected.has(expired.id), false);
assert.equal(context.nodeCanCheck(expired), false);
const udp = { ...node('node-dddddd'), protocol: 'hysteria2' };
assert.equal(context.nodeSupportsTCPPing(udp), false);
assert.match(context.renderNodeBrowserCard(udp, 'telegram'), /Через сервис/);
assert.match(context.renderNodeBrowserCard(udp, 'telegram'), /data-node-ping="node-dddddd" disabled/);
assert.match(context.renderNodeBrowserCard(expired, 'telegram'), /data-node-ping="node-cccccc" disabled/);

// Pending request rejects repeated clicks. A batch never calls route apply.
context.browser.selected.add('node-aaaaaa');
let finish;
handler = () => new Promise(resolve => { finish = resolve; });
const start = context.startNodeBrowserCheck('tcp');
await context.startNodeBrowserCheck('tcp');
assert.equal(calls.length, 1);
assert.deepEqual(JSON.parse(calls[0].options.body), { node_ids: ['node-aaaaaa'], mode: 'tcp', service_id: '' });
const readAPI = url => {
  if (url === '/api/v1/nodes') return state.nodes;
  if (url === '/api/v1/routes/options') return [];
  if (url === '/api/v1/node-feeds') return state.nodeFeeds;
  if (url === '/api/v1/node-autofallback') return { services: [] };
  if (url === '/api/v1/node-checks/current') return { job: { id: 1, state: 'completed', mode: 'tcp', total: 1, completed: 1 }, pings: [] };
  throw new Error(`unexpected read ${url}`);
};
handler = async url => readAPI(url);
finish({ job: { id: 1, state: 'running', mode: 'tcp', total: 1, completed: 0 } });
await start;
assert.equal(context.browser.job.state, 'completed');
assert.equal(calls.length, 6);
assert.ok(calls.every(call => !call.url.includes('/apply')));

// Saved private URL is cleared; only the source identifier is used for refresh.
$('#nodeFeedPreset').value = 'custom'; $('#nodeFeedURL').value = 'https://example.org/sub?token=private';
$('#nodeFeedName').value = 'Личная'; $('#nodeFeedInterval').value = '360'; $('#nodeFeedLimit').value = '64'; $('#nodeFeedPartial').checked = true;
handler = async (url, options) => {
  if (url === '/api/v1/node-feeds' && options?.method === 'POST') { const body = JSON.parse(options.body); assert.equal(body.enabled, true); assert.equal(body.refresh_interval_minutes, 360); return { source: { source_id: 'saved' } }; }
  if (url === '/api/v1/node-feeds/saved/sync') return { job: { id: 'sync-1' } };
  if (url === '/api/v1/node-feeds/jobs/sync-1') return { job: { status: 'completed', message: 'Готово' } };
  return readAPI(url);
};
await context.saveNodeSubscription({ preventDefault() {} });
assert.equal($('#nodeFeedURL').value, '');
assert.ok(calls.some(call => call.url === '/api/v1/node-feeds/saved/sync'));
assert.ok(calls.every(call => !call.url.includes('undefined')));
assert.doesNotMatch($('#nodeFeedSources').innerHTML + $('#nodeFeedStatus').textContent, /token=private/);
assert.ok(calls.every(call => !call.url.includes('/apply')), 'saving a subscription applied a route');

state.nodeFeeds.sources = [{ source_id: 'partial', saved: true, status: 'needs_acceptance', revision: 7, name: 'Каталог', enabled: false, limit: 16, refresh_interval_minutes: 60 }];
context.renderNodeSubscriptions();
assert.match($('#nodeFeedSources').innerHTML, /data-feed-accept="partial"/);
handler = async (url, options) => {
  if (url === '/api/v1/node-feeds/partial' && options?.method === 'PUT') {
    assert.deepEqual(JSON.parse(options.body), { revision: 7, name: 'Каталог', enabled: false, refresh_interval_minutes: 60, limit: 16, accept_partial: true, confirm: 'UPDATE_NODE_FEED' });
    return { ok: true };
  }
  if (url === '/api/v1/node-feeds/partial/sync') return { job: { id: 'partial-job' } };
  if (url === '/api/v1/node-feeds/jobs/partial-job') return { job: { status: 'completed', result: { imported: 3 } } };
  return readAPI(url);
};
await context.acceptNodeSubscriptionPartial('partial');
assert.ok(calls.some(call => call.url === '/api/v1/node-feeds/partial' && call.options?.method === 'PUT'));
assert.ok(calls.every(call => !call.url.includes('/apply')), 'partial acceptance changed a route');

// Fallback operations also own the stores: discover them using only job memory.
const beforeFallback = calls.length;
handler = async url => url.endsWith('/node-autofallback') ? { active: true } : readAPI(url);
await context.pollNodeBrowserChecks();
assert.deepEqual(calls.slice(beforeFallback).map(call => call.url).sort(), ['/api/v1/node-autofallback', '/api/v1/node-checks/current']);

// Labels distinguish actual UDP/QUIC transports and retain user aliases.
assert.equal(context.nodeTransportLabel({ protocol: 'hysteria2' }), 'QUIC');
assert.equal(context.nodeTransportLabel({ protocol: 'wireguard' }), 'UDP');
assert.equal(context.nodeTransportLabel({ protocol: 'vless', transport: 'ws' }), 'WS');
const named = { id: 'node-dddddd', name: 'Узел dddddd', country_code: 'SE', protocol: 'vless', transport: 'tcp' };
const nameBefore = context.nodeDisplayName(named);
assert.match(nameBefore, /^Швеция \[TCP\] · \d+$/);
context.nodeDisplayName({ ...named, id: 'node-eeeeee' });
assert.equal(context.nodeDisplayName(named), nameBefore, 'a new entry renumbered an existing connection');
assert.equal(context.nodeDisplayName({ ...named, name: 'Мой сервер' }), 'Мой сервер');

// A polling redraw must retain the reader's expanded card and keyboard focus.
const oldDetails = { open: true }, newDetails = { open: false };
const oldFocus = { id: '', tagName: 'INPUT', isConnected: true, attributes: [{ name: 'data-node-select', value: 'node-aaaaaa' }] };
const newFocus = { getAttribute: () => 'node-aaaaaa', focus() { document.activeElement = this; } };
const oldCard = { dataset: { nodeCard: 'node-aaaaaa' }, querySelector: () => oldDetails };
const newCard = { dataset: { nodeCard: 'node-aaaaaa' }, querySelector: () => newDetails };
document.activeElement = oldFocus;
$('#view-nodes').contains = element => element === oldFocus;
domQueries.set('#nodeList [data-node-card]', [oldCard]);
domQueries.set('[data-node-select]', [newFocus]);
let drawnHTML = $('#nodeList').innerHTML;
Object.defineProperty($('#nodeList'), 'innerHTML', { configurable: true, get: () => drawnHTML, set(value) { drawnHTML = value; oldFocus.isConnected = false; document.activeElement = null; domQueries.set('#nodeList [data-node-card]', [newCard]); } });
context.renderNodes();
assert.equal(newDetails.open, true, 'refresh collapsed an expanded card');
assert.equal(document.activeElement, newFocus, 'refresh discarded keyboard focus');
assert.equal(context.browser.selected.has('node-aaaaaa'), true, 'refresh discarded selection');
Object.defineProperty($('#nodeList'), 'innerHTML', { configurable: true, writable: true, value: drawnHTML });
document.activeElement = null;
domQueries.clear();

// Read-only idle refresh advances expiry and uses the router's latest network.
handler = async url => readAPI(url);
clockNow = now + 61000;
await scheduled();
assert.equal(context.nodeServiceHealth(state.nodes.nodes[1], 'telegram').state, 'stale');
assert.doesNotMatch($('#nodeList').innerHTML, /<b class="ok">Работает<\/b>/, 'expired proof stayed green without a user action');
clockNow = now;
handler = async url => url === '/api/v1/nodes' ? { ...state.nodes, network_profile: 'wan:changed' } : readAPI(url);
await context.pollNodeBrowserChecks();
assert.equal(context.nodeServiceHealth(state.nodes.nodes[1], 'telegram').state, 'stale', 'network change reused an old service result');
state.nodes.network_profile = profile;
const proof = state.nodes.nodes[1].health.history[0];
proof.checked_at = new Date(now + 1000).toISOString();
assert.equal(context.nodeServiceHealth(state.nodes.nodes[1], 'telegram').state, 'stale', 'clock rollback reused future proof');
proof.checked_at = new Date(now - 1000).toISOString();
proof.verdict = 'PARTIAL';
assert.equal(context.nodeServiceHealth(state.nodes.nodes[1], 'telegram').state, 'inconclusive', 'a partial result was presented as working or definitely failed');
proof.verdict = 'INCONCLUSIVE';
assert.equal(context.nodeServiceHealth(state.nodes.nodes[1], 'telegram').label, 'Не удалось проверить');
proof.verdict = 'FAIL';
assert.equal(context.nodeServiceHealth(state.nodes.nodes[1], 'telegram').state, 'degraded');
proof.verdict = 'PASS';
proof.route_path_id = 'sing-box:node-aaaaaa';
assert.equal(context.nodeServiceHealth(state.nodes.nodes[1], 'telegram').state, 'inconclusive', 'another node proof granted a definitive verdict');
proof.route_path_id = 'sing-box:node-bbbbbb';
context.browser.pings = [{ node_id: 'node-aaaaaa', reachable: true, latency_ms: 17, network_profile: profile, checked_at: new Date(now).toISOString() }];
clockNow = now + 10 * 60000;
assert.equal(context.nodePassivePing('node-aaaaaa'), null, 'expired TCP result remained visible');
clockNow = now - 1;
assert.equal(context.nodePassivePing('node-aaaaaa'), null, 'clock rollback reused a future TCP result');
clockNow = now;

// Logout fences an in-flight response and all scheduled follow-up requests.
handler = url => url.endsWith('/node-autofallback') ? Promise.resolve({ active: false }) : new Promise(resolve => { finish = resolve; });
const beforeLogout = calls.length;
const pending = context.pollNodeBrowserChecks();
context.stopNodeBrowserRefresh(true);
finish({ job: { state: 'running', mode: 'service' }, pings: [] });
await pending;
assert.equal(calls.length, beforeLogout + 2, 'logout allowed metadata follow-up requests');
assert.equal(context.browser.job, null, 'a late response restored a logged-out job');
assert.equal(context.browser.timer, null, 'logout restarted polling');
await context.pollNodeBrowserChecks();
await context.pollNodeFeedJob('old-job');
assert.equal(calls.length, beforeLogout + 2, 'logged-out page polled protected data');
context.browser.authRequired = false;
context.browser.viewActive = false;
await context.pollNodeBrowserChecks();
assert.equal(calls.length, beforeLogout + 2, 'inactive node page refreshed in the background');
context.browser.viewActive = true;
document.hidden = true;
await context.pollNodeBrowserChecks();
assert.equal(calls.length, beforeLogout + 2, 'hidden document refreshed in the background');

console.log('Node browser filtering, proof expiry, transport labels, focus, polling, logout and subscriptions passed');
