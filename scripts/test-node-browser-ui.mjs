import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';

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
state.status = { revision: 9 };
const session = new Map();
let handler = async () => ({});
let scheduled;
const document = { hidden: false, activeElement: null, getElementById: id => $(`#${id}`), addEventListener() {} };
const domQueries = new Map();
state.currentView = 'nodes';
$('#authScreen').hidden = true;
const esc = value => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const context = vm.createContext({ state, $, $$: selector => domQueries.get(selector) || [], Date: TestDate, document, Intl, JSON, Set, Map, Number, String, encodeURIComponent, esc,
  crypto: webcrypto, sessionStorage: { getItem: key => session.get(key) || null, setItem: (key,value) => session.set(key,value), removeItem: key => session.delete(key) },
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
context.browser.job = {mode:'service',scope:'all-vless',state:'failed',total:64,completed:21,result_state:'not-retained'};
context.renderNodeBatchStatus();
assert.match($('#nodeBatchMessage').textContent,/Подробные результаты прежнего запуска не сохранены/);
assert.doesNotMatch($('#nodeBatchMessage').textContent,/подходят: 0|отказ: 0/);
context.browser.job.result_state='current-process';context.browser.job.passed=5;
context.renderNodeBatchStatus();
assert.match($('#nodeBatchMessage').textContent,/подходят: 5/);
for (const [mode, label] of [['tcp','TCP'],['service-check','Проверка сервисов'],['service-select','Подбор подключений']]) {
  context.browser.job = {mode,state:'completed',total:1,completed:1};
  context.renderNodeBatchStatus();
  assert.ok($('#nodeBatchMessage').textContent.includes(label));
  if (mode !== 'tcp') assert.doesNotMatch($('#nodeBatchMessage').textContent,/TCP/,'a service job was labeled as a TCP ping');
}
context.browser.job = {state:'failed',total:1,completed:0};
context.renderNodeBatchStatus();
assert.doesNotMatch($('#nodeBatchMessage').textContent,/TCP/,'unknown failed operation invented a test type');
context.browser.job = null;
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
assert.equal(context.browser.selected.has(expired.id), true, 'expired nodes remain selectable for explicit removal, not checking');
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
const acceptedBody = JSON.parse(calls[0].options.body);
assert.match(acceptedBody.idempotency_key,/^[a-f0-9]{32}$/);
assert.deepEqual({ ...acceptedBody, idempotency_key: undefined }, { node_ids: ['node-aaaaaa'], mode: 'tcp', service_id: '', expected_revision: 9, idempotency_key: undefined });
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

// Metadata contention cannot turn a completed check into a failed check.
for (const failureStatus of [409,503]) {
 const prior=state.nodes;
 handler=async url=>{
  if (url==='/api/v1/nodes') throw Object.assign(Error('metadata busy'),{status:failureStatus,payload:{code:'RESTORE_OPERATION_BUSY'}});
  if (url==='/api/v1/node-feeds') return {...state.nodeFeeds,revision:failureStatus};
  return readAPI(url);
 };
 await context.pollNodeBrowserChecks();
 assert.equal(context.browser.job.state,'completed');
 assert.equal(state.nodes,prior,'failed registry read cleared retained nodes');
 assert.equal(state.nodeFeeds.revision,failureStatus,'unrelated successful read discarded');
 assert.doesNotMatch($('#nodeBatchMessage').textContent,/Не удалось обновить проверку/);
 assert.equal($('#nodeBrowserReadNotice').hidden,false);
 if(failureStatus===409)assert.match($('#nodeBrowserReadNotice').textContent,/после текущей операции/);
}
handler=async url=>readAPI(url);await context.pollNodeBrowserChecks();
assert.equal($('#nodeBrowserReadNotice').hidden,true,'notice survived successful refresh');

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

state.nodeFeeds.sources = [{ source_id: 'stopped', saved: true, status: 'interrupted', imported: 32, cursor: 39, snapshot_entries: 71 }];
context.renderNodeSubscriptions();
assert.match($('#nodeFeedSources').innerHTML, /Обновление прервано — прежние подключения сохранены/);
assert.match($('#nodeFeedSources').innerHTML, /Просмотрено 39 из 71/);
assert.doesNotMatch($('#nodeFeedSources').innerHTML, /data-feed-cancel/);

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
assert.equal(context.nodeServiceHealth(state.nodes.nodes[1], 'telegram').label, 'Нет однозначного результата');
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

// Lost POST response and reload reuse identity, rather than starting another job.
document.hidden = false;
context.browser.authRequired = false;
context.browser.job = null;
const checkIntent = {node_ids:['node-aaaaaa'], mode:'tcp', service_id:''};
let lostBody;
handler = async (_url,options) => { lostBody=JSON.parse(options.body); throw new Error('response lost'); };
await assert.rejects(context.submitSelectedNodeCheck(checkIntent),/response lost/);
vm.runInContext('nodeCheckPendingRequest = null',context); // reload retains sessionStorage only
handler = async (_url,options) => { assert.equal(JSON.parse(options.body).idempotency_key,lostBody.idempotency_key); return {job:{id:42,state:'completed'}}; };
assert.equal((await context.submitSelectedNodeCheck(checkIntent)).job.id,42);
assert.equal(session.has('razvilka.node-check-request'),false);
for (const phase of ['queued','interrupted']) {
 context.browser.job={id:42,state:phase,mode:'service',total:2,completed:1};
 context.renderNodeBatchStatus();
 assert.equal($('#nodeBatchCancel').hidden,false,'saved pending job cannot be canceled');
 const prior=calls.length;
 await context.startNodeBrowserCheck('tcp',['node-aaaaaa']);
 assert.equal(calls.length,prior,'waiting job allowed duplicate click');
}
context.browser.job=null;
let finishSubmit;
handler=()=>new Promise(resolve=>{finishSubmit=resolve;});
const submitting=context.startNodeBrowserCheck('tcp',['node-aaaaaa']);
const beforeSubmitLogout=calls.length;
context.stopNodeBrowserRefresh(true);
finishSubmit({job:{id:43,state:'queued'},pings:[]});
await submitting;
assert.equal(context.browser.job,null,'late POST response restored logged-out state');
assert.equal(calls.length,beforeSubmitLogout,'late POST initiated polling');
assert.equal(session.has('razvilka.node-check-request'),false);
console.log('Node browser filtering, proof expiry, transport labels, focus, polling, logout, durable retries and subscriptions passed');
