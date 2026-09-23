import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import vm from 'node:vm';

const read = name => readFileSync(new URL('../' + name, import.meta.url), 'utf8');
const app = read('cmd/razvilka/web/app.js');
const ui = read('cmd/razvilka/web/interface.js');
const html = read('cmd/razvilka/web/index.html');
const model = createRequire(import.meta.url)('../cmd/razvilka/web/interface-model.js');
const discord = { id: 'discord', name: 'Discord', enabled: false, applied_enabled: true,
  route: 'auto', applied_route: 'sing-box:node', dirty: true, route_dirty: true, sources_dirty: true };
const untouched = { id: 'other', name: 'Other', enabled: false, applied_enabled: false };
assert.deepEqual(model.filterServices([discord, untouched], { scope: 'selected' }).map(s => s.id), ['discord']);
assert.deepEqual(model.filterServices([discord, untouched], { scope: 'changed' }).map(s => s.id), ['discord']);
assert.deepEqual(model.filterServices([{ ...discord, dirty: false, route_dirty: false, sources_dirty: false }], { scope: 'selected' }).map(s => s.id), ['discord']);
assert.equal(discord.enabled, false, 'showing an applied service must not turn its desired selection on');
assert.equal(model.filterServices([{ ...untouched, sources_dirty: true }], { scope: 'changed' }).length, 1);
assert.equal(model.filterServices([{ ...untouched, route_dirty: true }], { scope: 'changed' }).length, 1);

const elements = new Map();
const element = id => {
  if (!elements.has(id)) elements.set(id, { value: 'old search', textContent: '', focus() { this.focused = true; }, scrollIntoView() { this.scrolled = true; } });
  return elements.get(id);
};
const events = [];
const state = { currentView: 'autopilot', status: { services_pending_changes: true, devices_pending_changes: true }, services: [discord, untouched] };
const interfaceState = { filter: 'selected', query: 'unrelated', category: 'Видео' };
const ctx = vm.createContext({ state, interfaceState, $: element,
  setView: view => { state.currentView = view; events.push(view); },
  renderInterfaceServices: () => { ctx.visible = model.filterServices(state.services, { scope: interfaceState.filter, query: interfaceState.query, category: interfaceState.category }); },
  interfaceSummaries: () => ({}), showNotice: (...args) => events.push(args),
  routeLabel: route => route === 'auto' ? 'Автопилот' : 'Подключение Sing-box' });
const slice = (source, start, end) => {
  const a = source.indexOf(start), b = source.indexOf(end, a + start.length);
  assert.ok(a >= 0 && b > a);
  return source.slice(a, b);
};
vm.runInContext(slice(app, 'function openPendingChanges()', 'function renderSystem()'), ctx);
vm.runInContext(slice(ui, 'function interfaceOpenServiceChanges()', 'function interfaceEngineCard('), ctx);
ctx.openPendingChanges();
assert.equal(state.currentView, 'services');
assert.equal(interfaceState.filter, 'changed');
assert.equal(interfaceState.query, '');
assert.equal(interfaceState.category, '');
assert.equal(element('#ui3ServiceSearch').value, '');
assert.deepEqual(ctx.visible.map(s => s.id), ['discord']);
assert.equal(element('#serviceDraftBar').scrolled, true);
assert.equal(element('#applyServiceChanges').focused, true);
ctx.renderPendingServiceChanges();
assert.match(element('#serviceChangeSummary').textContent, /Discord: Подключение Sing-box → Выключен/);
assert.doesNotMatch(element('#serviceChangeSummary').textContent, /Other/);
assert.equal(discord.enabled, false);
ctx.openPendingChanges();
assert.equal(state.currentView, 'devices', 'the remaining device changes must not loop back to the current services page');
state.status = { dns_pending_changes: true }; ctx.openPendingChanges(); assert.equal(state.currentView, 'dns');
state.status = { sources_pending_changes: true }; ctx.openPendingChanges(); assert.equal(state.currentView, 'sources');
state.status = {}; ctx.openPendingChanges(); assert.match(events.at(-1)[1], /Изменений для применения нет/);
state.engineConfigs = [{id:'nfqws2',files:[{id:'main',staged:false},{id:'user-list',staged:true}]},{id:'xray',files:[{id:'main',staged:true}]}];
state.selectedEngine='nfqws2';state.selectedEngineFile='main';
ctx.selectEngine=async id=>{state.selectedEngine=id;};
ctx.selectEngineFile=async id=>{state.selectedEngineFile=id;};
ctx.switchEngineTab=name=>{state.engineTab=name;};
await ctx.openPendingEngineChanges();
assert.equal(state.currentView,'engineconfig');assert.equal(state.selectedEngineFile,'user-list');assert.equal(state.engineTab,'config');
assert.equal(element('#engineFileSelect').focused,true);
state.selectedEngine='unmodified';state.selectedEngineFile='main';ctx.selectEngine=async()=>{};
await ctx.openPendingEngineChanges();assert.equal(state.selectedEngine,'unmodified');assert.equal(state.selectedEngineFile,'main','cancel must keep the edited file');
state.selectedEngine='nfqws2';state.engineIntent={};await ctx.openPendingEngineChanges();assert.equal(state.selectedEngineFile,'main','busy operation keeps its context');state.engineIntent=null;
state.engineConfigs=[];await ctx.openPendingEngineChanges();assert.match(events.at(-1)[1],/Получаем состав изменений/);
assert.equal(html.indexOf('id="serviceDraftBar"') < html.indexOf('id="ui3ServiceExpert"'), true, 'apply controls must be outside the collapsed advanced section');
assert.equal((html.match(/id="serviceDraftBar"/g) || []).length, 1);
assert.match(html, /data-rz-filter="changed"/);
console.log('PASS pending changes: actual deselection, visible scope actions, filters, DNS, device navigation, no mutations');
