import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';

const source = readFileSync(new URL('../cmd/razvilka/web/service-dashboard-ui.js', import.meta.url), 'utf8');
const html = readFileSync(new URL('../cmd/razvilka/web/index.html', import.meta.url), 'utf8');
const future = () => new Date(Date.now() + 60000).toISOString();
const deferred = () => { let resolve, reject; const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };

function fixture() {
  const elements = new Map(), listeners = new Map(), calls = [], opened = [], timers = new Map();
  let timerID = 0;
  const document = { activeElement: null, addEventListener(name, fn) { const rows = listeners.get(name) || []; rows.push(fn); listeners.set(name, rows); } };
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      id, value: '', checked: false, disabled: false, hidden: false, open: false, dataset: {}, listeners: {}, options: [], _html: '',
      addEventListener(name, fn) { this.listeners[name] = fn; },
      contains(item) { return item?.parentID === id; },
      focus() { document.activeElement = this; },
      add(option) { this.options.push(option); },
      set innerHTML(value) { this._html = value; this.options = [...value.matchAll(/<option value="([^"]*)"/g)].map(match => ({ value: match[1] })); },
      get innerHTML() { return this._html; },
      querySelectorAll(selector) {
        const attribute = selector.slice(1, -1);
        return [...this._html.matchAll(/<(?:button|select)\b([^>]*)>/g)].filter(match => match[1].includes(attribute + '=')).map(match => {
          const child = { parentID: id, dataset: {}, focus() { document.activeElement = this; } };
          for (const item of match[1].matchAll(/data-([a-z-]+)="([^"]*)"/g)) child.dataset[item[1].replace(/-([a-z])/g, (_, ch) => ch.toUpperCase())] = item[2];
          return child;
        });
      },
    });
    return elements.get(id);
  }
  const $ = id => element(id.replace(/^#/, ''));
  const state = { status: { revision: 9 }, currentView: 'services', devices: [], routeOptions: [{ id: 'auto', selectable: true }, { id: 'direct', selectable: true }, { id: 'warp', name: 'WARP', selectable: false }], nodes: { nodes: [{ id: 'node-a', name: 'Швеция TCP' }] }, services: [
    { id: 'youtube', name: 'YouTube', category: 'Видео', enabled: true, route: 'auto', applied_enabled: true, applied_route: 'auto', applied_state: { enabled: true, route: 'nfqws' }, applied_sources: ['192.168.1.40/32'], sources: ['192.168.1.40/32'], planned_engine: 'warp', observed_state: {}, domains: ['youtube.com'] },
    { id: 'telegram', name: 'Telegram', category: 'Чаты', enabled: false, route: 'auto', applied_enabled: false, applied_state: { enabled: false, route: 'auto' }, planned_engine: 'warp', domains: ['telegram.org'] },
  ] };
  state.serviceControl = { config_revision: 9, schedule: { enabled: false, interval_seconds: 300, service_ids: ['youtube'] }, results: [], job: null };
  let handler = async () => { throw new Error('Unexpected API call'); };
  const dispatch = (name, detail) => { for (const fn of listeners.get(name) || []) fn({ detail }); };
  const session = new Map();
  const context = vm.createContext({ state, $, document, URL, Set, Date, Number, Math, JSON, Promise, AbortController,
    crypto: webcrypto, sessionStorage: { getItem: key => session.get(key) || null, setItem: (key, value) => session.set(key, value), removeItem: key => session.delete(key) },
    Option: function(text, value) { this.text = text; this.value = value; },
    setTimeout(fn) { timers.set(++timerID, fn); return timerID; }, clearTimeout(id) { timers.delete(id); }, queueMicrotask,
    esc: value => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;'),
    routeLabel: route => route, nodeScopeText: sources => sources.length ? sources.join(', ') : 'Вся локальная сеть', nodeDisplayName: node => node.name,
    nodePassivePing: () => null, nodeBrowser: { pings: [] }, nodeCanCheck: node => !node.disabled && node.state !== 'expired', nodeSupportsTCPPing: node => !['wireguard', 'hysteria2'].includes(node.protocol),
    populateServiceCategories() {}, serviceMatches: service => !$('#serviceSearch').value || service.name.includes($('#serviceSearch').value),
    api: async (url, options = {}) => { calls.push({ url, ...options }); return handler(url, options); },
    acceptWorkspaceControl(control) { if (state.serviceControl && control.config_revision < state.serviceControl.config_revision) return false; state.serviceControl = control; return true; },
    setView(name) { dispatch('razvilka:view-change', name); state.currentView = name; },
    openServiceScope: id => opened.push(['scope', id]), showServiceDetails: id => opened.push(['details', id]),
    openCustomServiceDialog: id => opened.push(['custom', id]), openNodeCheck: (id, service) => opened.push(['node', id, service]),
    renderStatus() {}, renderOverviewQuickServices() {}, renderOverviewServices() {}, renderReadiness() {}, renderSettings() {},
  });
  vm.runInContext(source, context);
  const nodeSource = readFileSync(new URL('../cmd/razvilka/web/node-browser.js', import.meta.url), 'utf8');
  vm.runInContext(nodeSource.slice(nodeSource.indexOf('let nodeCheckPendingRequest'),nodeSource.indexOf('async function pollNodeBrowserChecks')),context);
  const dashboard = vm.runInContext('serviceDashboard', context);
  context.bindServiceDashboard(); context.renderServiceDashboard();
  const click = (id, data) => $(id).listeners.click({ target: { closest(selector) { if (selector === 'button') return { dataset: data, disabled: false }; const key = selector.slice(6, -1).replace(/-([a-z])/g, (_, ch) => ch.toUpperCase()); return data[key] !== undefined ? { dataset: data } : null; } } });
  return { context, $, state, dashboard, document, calls, opened, timers, dispatch, click, setHandler(fn) { handler = fn; } };
}

// Applied state, exact service evidence and latency are three independent facts.
{
  const f = fixture(), service = f.state.services[0];
  assert.equal(f.context.serviceDashboardSummary(service).route, 'nfqws');
  assert.equal(f.context.serviceDashboardSummary(service).label, 'Не проверен');
  assert.doesNotMatch(f.$('#serviceList').innerHTML, /<b>warp<\/b>/, 'calculated WARP became a working route');
  assert.match(f.$('#serviceList').innerHTML, /Рекомендация пока не проверена/);
  const proof = { service_id: 'youtube', kind: 'check', checked_route: 'nfqws', status: 'pass', available: true, config_revision: 9, checked_at: new Date(Date.now()-1000).toISOString(), valid_until: future(), freshness_verified: true, latency_ms: 2030 };
  f.dashboard.control.results = [proof];
  assert.equal(f.context.serviceDashboardSummary(service).label, 'Сервис доступен');
  assert.equal(f.context.serviceDashboardSummary(service).pingLabel, 'Пинг: —');
  assert.match(f.context.serviceDashboardCard(service), /Время проверки: 2030 мс · это не пинг/);
  for (const change of [{ freshness_verified: false }, { stale: true }, { config_revision: 8 }, { valid_until: new Date(0).toISOString() }, { checked_route: 'warp' }, { available: false }, { kind: 'select', recommended_node_id: 'node-a' }]) {
    f.dashboard.control.results = [{ ...proof, ...change }];
    assert.notEqual(f.context.serviceDashboardSummary(service).label, 'Сервис доступен', JSON.stringify(change));
  }
  f.dashboard.control.results = [{ ...proof, kind: 'select', recommended_node_id: 'node-a', checked_route: 'sing-box:node-a' }];
  assert.match(f.context.serviceDashboardRecommendation(service), /ещё не назначено/);
  f.click('#serviceList', { sdUse: 'node-a', sdService: 'youtube' });
  assert.deepEqual(f.opened, [['node', 'node-a', 'youtube']]);
  f.state.status.revision = 10;
  f.click('#serviceList', { sdUse: 'node-a', sdService: 'youtube' });
  assert.equal(f.opened.length, 1, 'stale recommendation opened an apply flow');
  f.state.serviceControl.runtime_state = 'stopped';
  assert.equal(f.context.serviceDashboardSummary(service).route, '');
  assert.equal(f.context.serviceDashboardSummary(service).label, 'Остановлен');
  f.context.renderServiceDashboardControl();
  assert.match(f.$('#serviceCheckStatus').textContent, /Проверка не включает их; применение включит выбранные сервисы после проверки/);
}

// A direct check without an applied route remains useful, including while a
// different route is pending, but must never claim that pending bypass works.
{
  const f = fixture(), service = f.state.services[1];
  service.enabled = true; service.route = 'warp'; service.dirty = true;
  const proof = { service_id: 'telegram', kind: 'check', checked_route: 'direct', applied_route: '', scope_required: true, status: 'pass', available: true, config_revision: 9, checked_at: new Date(Date.now()-1000).toISOString(), valid_until: future(), freshness_verified: true };
  f.dashboard.control.results = [proof];
  let summary = f.context.serviceDashboardSummary(service);
  assert.equal(summary.route, ''); assert.equal(summary.label, 'Напрямую: доступен');
  assert.match(summary.detail, /с роутера/); assert.match(summary.detail, /Обход не включён/);
  assert.match(summary.detail, /неприменённые настройки эта проверка не подтверждает/);
  assert.match(f.context.serviceDashboardCard(service), /Применённый маршрут<\/small><b>Не включён<\/b>/);
  for (const [status, available, label] of [['fail', false, 'Напрямую: недоступен'], ['inconclusive', false, 'Напрямую: результат неясен'], ['pass', false, 'Напрямую: результат неясен'], ['not-ready', false, 'Напрямую: результат неясен']]) {
    f.dashboard.control.results = [{ ...proof, status, available }];
    summary = f.context.serviceDashboardSummary(service);
    assert.equal(summary.route, ''); assert.equal(summary.label, label);
  }
  for (const change of [{ stale: true }, { freshness_verified: false }, { valid_until: new Date(0).toISOString() }, { config_revision: 8 }, { kind: 'select' }, { checked_route: 'warp' }, { applied_route: 'direct' }, { recommended_node_id: 'node-a' }]) {
    f.dashboard.control.results = [{ ...proof, ...change }];
    summary = f.context.serviceDashboardSummary(service);
    assert.equal(summary.route, ''); assert.equal(summary.label, 'Не включён', JSON.stringify(change));
  }
  f.dashboard.control.results = [proof];
  service.applied_state = { enabled: true, route: 'warp' };
  assert.notEqual(f.context.serviceDashboardSummary(service).label, 'Сервис доступен', 'direct probe confirmed a different applied route');
  service.applied_state.enabled = false; f.state.serviceControl.runtime_state = 'stopped';
  summary = f.context.serviceDashboardSummary(service);
  assert.equal(summary.route, ''); assert.equal(summary.label, 'Напрямую: доступен');
}

// TCP ping is a real bounded node-check request for the applied node. It has no
// implied service result and is never offered for UDP or an unapplied route.
{
  const f = fixture(), service = f.state.services[0];
  service.applied_state.route = 'sing-box:node-a'; service.route = 'sing-box:node-other';
  f.setHandler(() => ({ job: { id: 2, mode: 'tcp', state: 'running' } }));
  await f.context.serviceDashboardPing('youtube');
  assert.equal(f.calls[0].url, '/api/v1/node-checks');
  const body = JSON.parse(f.calls[0].body);
  assert.match(body.idempotency_key,/^[a-f0-9]{32}$/);
  assert.deepEqual({ ...body, idempotency_key: undefined }, { node_ids: ['node-a'], mode: 'tcp', expected_revision: 9, idempotency_key: undefined });
  assert.equal(f.$('#serviceCancelCheck').hidden, true, 'service cancellation should not cancel a different job type');
  assert.notEqual(f.context.serviceDashboardSummary(service).label, 'Сервис доступен');
  f.context.nodePassivePing = () => ({ reachable: true, latency_ms: 42 });
  assert.equal(f.context.serviceDashboardSummary(service).pingLabel, 'Пинг TCP: 42 мс');
  f.state.nodes.nodes[0].protocol = 'wireguard';
  assert.equal(f.context.serviceDashboardPingNode(service), null);
  service.applied_state.enabled = false;
  assert.equal(f.context.serviceDashboardPingNode(service), null);
}

// No re-render closes details or steals focus; an open native select survives.
{
  const f = fixture();
  f.click('#serviceList', { sdExpand: 'youtube' });
  f.document.activeElement = { parentID: 'serviceList', dataset: { sdFocus: 'check-youtube' } };
  f.context.renderServiceDashboard();
  assert.equal(f.document.activeElement.dataset.sdFocus, 'check-youtube');
  assert.match(f.$('#serviceList').innerHTML, /aria-expanded="true" aria-controls="sd-details-youtube"/);
  const before = f.$('#serviceList').innerHTML;
  f.document.activeElement = { parentID: 'serviceList', matches: selector => selector === '[data-sd-route]' };
  f.state.services[0].name = '<script>';
  f.context.renderServiceDashboard(); assert.equal(f.$('#serviceList').innerHTML, before);
  f.document.activeElement = null; f.context.renderServiceDashboard();
  assert.match(f.$('#serviceList').innerHTML, /&lt;script&gt;/); assert.doesNotMatch(f.$('#serviceList').innerHTML, /<script>/);
}

// Jobs bind the exact requested services and shown revision, admit one request,
// and never chain automatically into a route mutation.
{
  const f = fixture(), pending = deferred(); f.setHandler(() => pending.promise);
  const first = f.context.serviceDashboardStart('check', ['youtube']);
  await f.context.serviceDashboardStart('select', ['telegram']);
  assert.equal(f.calls.length, 1);
  const payload = JSON.parse(f.calls[0].body);
  assert.match(payload.idempotency_key, /^[a-f0-9]{32}$/);
  delete payload.idempotency_key;
  assert.deepEqual(payload, { kind: 'check', service_ids: ['youtube'], expected_revision: 9 });
  pending.resolve({ job: { id: 17, state: 'running', mode: 'service-check' } }); await first;
  assert.equal(f.context.serviceDashboardJobActive(), true);
  assert.equal(f.$('#serviceCheckAll').disabled, true);
  assert.equal(f.calls.filter(call => call.url.includes('/apply')).length, 0);
  const cancel = deferred(); f.setHandler((url, options) => options.method === 'DELETE' ? cancel.promise : { job: { id: 18, state: 'running', mode: 'service-check' } });
  const cancellation = f.context.serviceDashboardCancel();
  assert.equal(f.calls.at(-1).url, '/api/v1/service-control/current?job_id=17');
  cancel.resolve({}); await cancellation;
  assert.equal(f.dashboard.control.job.id, 18);
  assert.equal(f.calls.filter(call => call.method === 'DELETE').length, 1, 'cancel retried against a replacement job');
}
// A lost POST response retains its token across reload; an acknowledged job or
// logout clears it. An interrupted server task is still active, never a new POST.
{
  const f = fixture();
  f.setHandler(() => { throw new Error('response lost'); });
  await f.context.serviceDashboardStart('check', ['youtube']);
  const first = JSON.parse(f.calls.at(-1).body).idempotency_key;
  f.dashboard.pendingRequest = null; // reload, sessionStorage remains
  await f.context.serviceDashboardStart('check', ['youtube']);
  assert.equal(JSON.parse(f.calls.at(-1).body).idempotency_key, first);
  f.setHandler(() => ({ job: { id: 54, state: 'queued', mode: 'service-check' } }));
  await f.context.serviceDashboardStart('check', ['youtube']);
  assert.equal(JSON.parse(f.calls.at(-1).body).idempotency_key, first);
  assert.equal(f.dashboard.pendingRequest, null);
  f.dashboard.control.job.state = 'interrupted';
  assert.equal(f.context.serviceDashboardJobActive(), true);
  f.context.serviceDashboardRequestToken('private reference');
  f.dispatch('razvilka:auth-required');
  assert.equal(f.dashboard.pendingRequest, null);
  assert.equal(f.context.sessionStorage.getItem('razvilka.service-job-request'), null);
}
for (const event of ['razvilka:auth-required', 'razvilka:view-change']) {
  const f = fixture(), pending = deferred(); f.setHandler(() => pending.promise);
  const request = f.context.serviceDashboardStart('select', ['youtube']);
  f.dispatch(event, 'overview'); pending.resolve({ job: { id: 17, state: 'running', mode: 'service-select' } }); await request;
  assert.equal(f.dashboard.operation, null);
  assert.equal(f.dashboard.control?.job?.id, undefined, `late job response survived ${event}`);
  assert.equal(f.calls[0].signal.aborted, true);
}

// Memory status is safe while the checker owns the stores. It cannot refresh
// evidence or make a recommendation current without the full verified endpoint.
{
  const f = fixture();
  f.setHandler(url => { assert.equal(url, '/api/v1/service-control/current'); return { job: { id: 3, mode: 'service-select', state: 'running' }, results: [{ service_id: 'youtube', available: true, status: 'pass', checked_at: new Date(Date.now()-1000).toISOString(), valid_until: future(), freshness_verified: false }], pings: [] }; });
  await f.context.refreshServiceControl();
  assert.equal(f.calls.length, 1);
  assert.equal(f.dashboard.control.results.length, 0);
  assert.equal(f.context.serviceDashboardSummary(f.state.services[0]).label, 'Не проверен');
}

// Changing an interval preserves the saved service list. Revision conflicts do
// not re-submit the timer with a newer authority or expand it to new services.
{
  const f = fixture();
  f.$('#serviceScheduleInterval').value = '900'; f.$('#serviceScheduleInterval').listeners.change();
  f.state.services.push({ id: 'new', name: 'New' }); f.state.serviceControl.config_revision = 10;
  let writes = 0;
  f.setHandler((url, options) => {
    if (options.method === 'PUT') { writes++; assert.deepEqual(JSON.parse(options.body), { expected_revision: 9, schedule: { enabled: false, interval_seconds: 900, service_ids: ['youtube'] }, confirm: 'SAVE_SERVICE_CONTROL' }); const error = new Error('Настройки изменились'); error.status = 409; throw error; }
    return url.endsWith('/current') ? { job: null } : f.state.serviceControl;
  });
  await f.context.serviceDashboardSaveSchedule();
  assert.equal(writes, 1); assert.equal(f.dashboard.scheduleDirty, false);
}

// Editor input is captured before a request; a later UI selection or logout
// cannot change which service/scope was saved or publish stale fetched state.
{
  const f = fixture(), pending = deferred(); f.setHandler(() => pending.promise);
  const request = f.context.serviceDashboardEdit('youtube', { route: 'direct' });
  f.state.services[0].sources = ['192.168.1.90/32'];
  await f.context.serviceDashboardEdit('telegram', { enabled: true });
  assert.equal(f.calls.length, 1);
  assert.deepEqual(JSON.parse(f.calls[0].body), { enabled: true, route: 'direct', sources: ['192.168.1.40/32'] });
  f.dispatch('razvilka:auth-required'); pending.resolve({ id: 'youtube', ok: true }); await request;
  assert.equal(f.calls.length, 1, 'logout continued staging into follow-up reads');
  assert.equal(f.state.services[0].route, 'auto', 'an unconfirmed save changed local applied/desired state');
}

// Website lookup sends hostnames only, never URL tokens, and never creates or
// enables a service until the existing explicit custom-service dialog is used.
{
  const f = fixture();
  assert.deepEqual([...f.context.serviceWebsiteHosts('https://www.YouTube.com/watch?v=private#token\ntelegram.org')], ['www.youtube.com', 'telegram.org']);
  for (const input of ['https://user:secret@youtube.com', 'file:///etc/passwd', '127.0.0.1', 'localhost', 'https://[::1]', Array(13).fill('a.example').join('\n')]) assert.throws(() => f.context.serviceWebsiteHosts(input));
  f.$('#serviceWebsiteInput').value = 'https://youtube.com/watch?v=secret\nunknown.example';
  f.setHandler(url => url.endsWith('q=youtube.com') ? { matches: [{ service_id: 'youtube', service_name: 'YouTube', matched_rule: 'youtube.com' }] } : { matches: [] });
  await f.context.discoverServiceWebsites();
  assert.deepEqual(f.calls.map(call => call.url), ['/api/v1/diagnostics/domain?q=youtube.com', '/api/v1/diagnostics/domain?q=unknown.example']);
  assert.equal(f.calls.filter(call => call.method && call.method !== 'GET').length, 0);
  assert.equal(f.opened.length, 0);
  f.click('#serviceWebsiteResults', { sdCreate: '1' });
  assert.deepEqual(f.opened, [['custom', undefined]]);
  assert.equal(f.$('#customServiceDomains').value, 'unknown.example');
  assert.equal(f.$('#customServiceProbe').value, 'https://unknown.example/');
  assert.equal(f.calls.length, 2);
}
{
  const f = fixture(), pending = deferred(); f.$('#serviceWebsiteInput').value = 'old.example'; f.setHandler(() => pending.promise);
  const request = f.context.discoverServiceWebsites();
  f.$('#serviceWebsiteInput').value = 'new.example'; f.$('#serviceWebsiteInput').listeners.input();
  pending.resolve({ matches: [] }); await request;
  assert.equal(f.dashboard.lookupResults.length, 0, 'late lookup restored results for edited input');
  assert.equal(f.calls[0].signal.aborted, true);
  assert.equal(f.$('#serviceWebsiteFind').disabled, false);
}

for (const id of ['serviceCheckAll', 'serviceAutoPickTarget', 'serviceScheduleAll', 'serviceWebsiteInput', 'serviceWebsiteResults']) assert.equal((html.match(new RegExp(`id="${id}"`, 'g')) || []).length, 1, `${id} is not unique`);
assert.match(html, /service-dashboard-ui\.js/);
console.log('Service dashboard: applied/evidence/ping distinction, focus/details, job identity and cancellation, stale schedule scope, auth/edit fences, and hostname-only confirmed discovery passed');

// R3: an expiry alone cannot prove a check happened; future/missing timestamps
// must not paint a service green. Group summaries use this same function.
{
 const f=fixture(),service=f.state.services[0];
 service.observed_state={route:'nfqws',level:'service-confirmed',outcome:'service_accepted',checked_at:new Date(Date.now()-1000).toISOString(),fresh_until:future()};
 assert.equal(f.context.serviceDashboardSummary(service).kind,'good');
 for(const checked of ['', 'broken', new Date(Date.now()+30000).toISOString()]) {
  service.observed_state.checked_at=checked;
  assert.notEqual(f.context.serviceDashboardSummary(service).kind,'good');
 }
 const p={kind:'check',service_id:'youtube',status:'pass',available:true,checked_route:'nfqws',config_revision:9,freshness_verified:true,valid_until:future(),checked_at:new Date(Date.now()-1000).toISOString()};
 f.dashboard.control.results=[p];assert.equal(f.context.serviceDashboardSummary(service).kind,'good');
 for(const checked_at of ['', 'invalid', new Date(Date.now()+10000).toISOString()]) {
  f.dashboard.control.results=[{...p,checked_at}];
  assert.notEqual(f.context.serviceDashboardSummary(service).kind,'good');
 }
}
console.log('R3 service evidence timestamp regression: passed');
