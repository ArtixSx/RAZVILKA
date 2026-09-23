import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../cmd/razvilka/web/panel-snapshot.js', import.meta.url), 'utf8');
function fixture() {
  const elements = new Map(), listeners = new Map();
  const state = { authenticated: true, services: [], dataLoad: { services: { phase: 'busy', loaded: false } } };
  let generation = 1;
  const context = { state, Date, console, $: id => elements.get(id),
    document: { addEventListener: (name, fn) => listeners.set(name, fn), getElementById: id => elements.get('#' + id) },
    panelSnapshotCurrent: n => n === generation,
    cancelPanelRefresh: () => generation++,
    showAuth: () => { state.authenticated = false; listeners.get('razvilka:auth-required')(); },
    renderPanelLoad: () => context.renderSavedPanelSnapshot(),
    renderMetrics() {}, api: async () => snapshot(),
  };
  for (const id of ['panelSavedNotice', 'ui3ServiceCatalog', 'ui3HomeServices', 'serviceList', 'ui3InspectorContent']) elements.set('#' + id, { hidden: true, textContent: 'protected' });
  vm.createContext(context); vm.runInContext(source, context);
  return { context, state, elements, listeners };
}
function snapshot(revision = 1) {
  return { schema: 1, instance_id: 'a'.repeat(32), revision, generated_at: new Date().toISOString(),
    data_age_ms: 2000, max_age_seconds: 900, state: 'retained', dataplane: 'not-checked',
    data: { config: { revision: 8 }, sources: [], services: [{ id: 'telegram', name: 'Telegram',
      desired: { enabled: false, route: 'auto' }, applied: { enabled: true, route: 'sing-box:old' },
      sources: [], applied_sources: ['192.168.1.40/32'], route_dirty: true }] } };
}
let count = 0;
async function test(name, fn) { await fn(); count++; console.log('PASS ' + name); }
await test('fresh login during busy gets saved desired/applied scope without proof', async () => {
  const f = fixture(); await f.context.loadSavedPanelSnapshot(1, {});
  const service = f.state.services[0];
  assert.equal(service.enabled, false); assert.equal(service.applied_enabled, true);
  assert.equal(service.applied_sources[0], '192.168.1.40/32');
  assert.equal(service.presentation_only, true); assert.equal(service.evidence_status, 'unknown');
  assert.equal(f.state.dataLoad.services.phase, 'busy');
  assert.match(f.elements.get('#panelSavedNotice').textContent, /2 сек назад/);
});
await test('late saved image cannot overwrite a completed live read', async () => {
  const f = fixture(); f.state.services = [{ id: 'new-live-service' }];
  f.state.dataLoad.services = { phase: 'ready', loaded: true };
  await f.context.loadSavedPanelSnapshot(1, {});
  assert.equal(f.state.services[0].id, 'new-live-service');
  assert.equal(f.elements.get('#panelSavedNotice').hidden, true);
});
await test('older publication and malformed success preserve the valid snapshot', async () => {
  const f = fixture(); f.context.api = async () => snapshot(2); await f.context.loadSavedPanelSnapshot(1, {});
  const saved = f.state.savedPanel;
  f.context.api = async () => snapshot(1); await f.context.loadSavedPanelSnapshot(1, {});
  assert.equal(f.state.savedPanel, saved);
  f.context.api = async () => ({ ...snapshot(3), data: { services: null } });
  await f.context.loadSavedPanelSnapshot(1, {}); assert.equal(f.state.savedPanel, saved);
});
await test('expired images stop supplying cards even after a later busy error clears metadata', async () => {
  const f = fixture(); await f.context.loadSavedPanelSnapshot(1, {});
  f.state.dataLoad.services = { phase: 'busy', loaded: true };
  f.state.savedPanel.value.data_age_ms = 900000;
  f.context.renderSavedPanelSnapshot();
  assert.equal(f.state.services.length, 0); assert.equal(f.state.dataLoad.services.loaded, false);
  assert.match(f.elements.get('#panelSavedNotice').textContent, /не означает.*удалены/);
});
await test('logout clears saved private presentation and fences delayed HTTP body', async () => {
  const f = fixture(); await f.context.loadSavedPanelSnapshot(1, {});
  let resolve; f.context.api = () => new Promise(r => resolve = r);
  const pending = f.context.loadSavedPanelSnapshot(1, {});
  f.context.cancelPanelRefresh(); f.context.showAuth(); resolve(snapshot(2)); await pending;
  assert.equal(f.state.savedPanel, null); assert.equal(f.state.services.length, 0);
  assert.equal(f.elements.get('#ui3ServiceCatalog').textContent, '');
  assert.equal(f.elements.get('#panelSavedNotice').hidden, true);
});
await test('snapshot 401 revokes the session but a timeout never erases valid settings', async () => {
  const f = fixture(); await f.context.loadSavedPanelSnapshot(1, {});
  f.context.api = async () => { throw new Error('timeout'); }; await f.context.loadSavedPanelSnapshot(1, {});
  assert.equal(f.state.services.length, 1);
  f.context.api = async () => { throw Object.assign(new Error('login'), { status: 401 }); };
  await f.context.loadSavedPanelSnapshot(1, {}); assert.equal(f.state.services.length, 0); assert.equal(f.state.authenticated, false);
});
await test('fallback card has no action able to apply incomplete state', async () => {
  const ui = readFileSync(new URL('../cmd/razvilka/web/interface.js', import.meta.url), 'utf8');
  const fn = ui.match(/function interfaceServiceCard\([^]*?\n}\n/)[0];
  const context = { esc: s => String(s).replaceAll('<', '&lt;'), consoleServiceIcon: () => 'TG',
    rim: { category: () => 'Связь' }, interfaceRouteName: s => s };
  vm.createContext(context); vm.runInContext(fn, context);
  const card = context.interfaceServiceCard({ presentation_only: true, id: 'tg', name: '<img>', enabled: false, route: 'auto', sources: [] }, {});
  assert.match(card, /&lt;img>/); assert.doesNotMatch(card, /<button|data-r5-add|data-rz-action/);
});
await test('unknown and busy settings do not claim working mode or enable a toggle', async () => {
  const app = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
  const fn = app.match(/function renderSettingsMode\([^]*?\n}\n/)[0];
  const elements = new Map();
  const context = { state: { status: {}, dataLoad: {} }, Date,
    $: id => { if (!elements.has(id)) elements.set(id, {}); return elements.get(id); } };
  vm.createContext(context); vm.runInContext(fn, context); context.renderSettingsMode();
  assert.equal(elements.get('#settingSafeMode').textContent, 'Состояние уточняется');
  assert.equal(elements.get('#settingRevision').textContent, '—');
  assert.equal(elements.get('#toggleSafeMode').disabled, true);
  context.state.status = { safe_mode: true, revision: 8, applied_revision: 4 };
  context.state.dataLoad.status = { phase: 'ready' }; context.renderSettingsMode();
  assert.equal(elements.get('#settingSafeMode').textContent, 'Безопасный');
  assert.equal(elements.get('#settingRevision').textContent, '8 / 4');
  assert.equal(elements.get('#toggleSafeMode').disabled, false);
  context.state.dataLoad.status.phase = 'busy'; context.renderSettingsMode();
  assert.equal(elements.get('#toggleSafeMode').disabled, true);
});
console.log(JSON.stringify({ status: 'passed', tests: count }));
