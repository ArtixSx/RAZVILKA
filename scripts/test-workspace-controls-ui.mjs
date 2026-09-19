import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const elements = new Map(), events = new Map();
const $ = id => { if (!elements.has(id)) elements.set(id, { hidden: false, disabled: false, textContent: '', attributes: {}, handlers: {}, classList: { toggle() {} }, setAttribute(key, value) { this.attributes[key] = value; }, addEventListener(key, fn) { this.handlers[key] = fn; } }); return elements.get(id); };
const state = { serviceControl: null, components: [] }, calls = [], notices = [], views = [], details = [];
let request = async () => ({}), refreshes = 0;
const context = vm.createContext({ state, $, Number, document: { hidden: false, addEventListener: (name, fn) => events.set(name, fn) },
  api: async (path, options) => { calls.push({ path, options }); return request(path, options); },
  setTimeout: () => 1, clearTimeout() {}, esc: value => String(value ?? '').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;'),
  setView: name => views.push(name), showNotice: (...args) => notices.push(args), showDetails: (...args) => details.push(args), renderAudit() {}, refreshAfterMutation: async () => { refreshes++; }, renderOverviewQuickServices() {}, refreshComponents() {}, manageComponent() {} });
vm.runInContext(readFileSync(new URL('../cmd/razvilka/web/workspace-controls.js', import.meta.url), 'utf8') + '\nthis.control = workspaceControl;', context);
context.bindWorkspaceControls();
$('#authScreen').hidden = true;
events.get('razvilka:auth-restored')();
const snapshot = { config_revision: 10, mode: 'manual', runtime_state: 'unconfigured', running: false, resume_available: false };
context.acceptWorkspaceControl(snapshot);
await context.toggleWorkspaceRuntime();
assert.deepEqual(views, ['services']); assert.equal(calls.length, 0, 'unconfigured power silently applied pending routes');
assert.equal(context.acceptWorkspaceControl({ ...snapshot, config_revision: 9, mode: 'auto' }), false);
assert.equal(state.serviceControl.mode, 'manual', 'old snapshot overrode newer mode');

let release;
request = () => new Promise(resolve => { release = resolve; });
const first = context.changeWorkspaceMode('auto');
await context.changeWorkspaceMode('auto');
assert.equal(calls.length, 1, 'double click duplicated mode mutation');
assert.deepEqual(JSON.parse(calls[0].options.body), { expected_revision: 10, mode: 'auto', confirm: 'SAVE_SERVICE_CONTROL' });
release({ ...snapshot, config_revision: 11, mode: 'auto' }); await first;
assert.equal(state.serviceControl.mode, 'auto'); assert.equal(refreshes, 1);

context.acceptWorkspaceControl({ ...snapshot, config_revision: 12, running: true, runtime_state: 'running' });
request = async path => { if (path.endsWith('/runtime')) throw new Error('busy'); return state.serviceControl; };
await context.toggleWorkspaceRuntime();
assert.equal(state.serviceControl.running, true, 'refused stop displayed stopped');
const stop = calls.find(call => call.path.endsWith('/runtime'));
assert.deepEqual(JSON.parse(stop.options.body), { expected_revision: 12, action: 'stop', confirm: 'STOP_OWNED_ROUTES' });

const beforeBusy = state.serviceControl;
request = async () => { throw Object.assign(new Error('checking'), { status: 409 }); };
await context.refreshWorkspaceControl();
assert.equal(state.serviceControl, beforeBusy, 'normal busy gate erased known runtime state');
const countBeforeBusyMode = calls.length;
await context.changeWorkspaceMode('auto');
assert.equal(calls.length, countBeforeBusyMode, 'mode edit ignored active operation gate');
context.acceptWorkspaceControl({ ...snapshot, config_revision: 12, runtime_state: 'unknown', running: false, can_stop: true });
assert.equal($('#projectPower').disabled, false, 'unknown runtime could not be stopped');
assert.equal($('#projectPower').attributes['aria-label'], 'Остановить маршруты RAZVILKA');

request = () => new Promise(resolve => { release = resolve; });
const late = context.changeWorkspaceMode('auto');
const noticesBefore = notices.length;
events.get('razvilka:auth-required')();
release({ ...snapshot, config_revision: 13, mode: 'auto' }); await late;
assert.equal(state.serviceControl, null, 'late completion revived admin state');
assert.equal(notices.length, noticesBefore, 'late completion displayed success after logout');
assert.equal($('#projectPower').disabled, true);

events.get('razvilka:auth-restored')();
context.acceptWorkspaceControl({ ...snapshot, config_revision: 14, runtime_state: 'stopped', safe_mode: true, resume_available: true });
const countBeforeSafe = calls.length;
await context.toggleWorkspaceRuntime();
assert.equal(views.at(-1), 'settings');
assert.equal(calls.length, countBeforeSafe, 'power silently bypassed safe mode');
context.acceptWorkspaceControl({ ...snapshot, config_revision: 15, runtime_state: 'running', running: true, safe_mode: true });
request = async () => ({ ok: true, control: { ...snapshot, config_revision: 16, runtime_state: 'stopped' } });
await context.toggleWorkspaceRuntime();
assert.equal(calls.at(-1).path, '/api/v1/service-control/runtime', 'safe mode prevented stopping active routes');
assert.equal(JSON.parse(calls.at(-1).options.body).action, 'stop');

state.loadIssues = [{ section: 'sources', message: 'Источник недоступен' }];
request = async () => ({ events: [{ outcome: 'failed', path: '/api/v1/test', status: 502 }] });
await $('#projectLog').handlers.click();
assert.equal(details.at(-1)[0].detail_kind, 'project-log');
assert.equal(details.at(-1)[0].load_issues[0].section, 'sources');
assert.equal(details.at(-1)[0].audit.events[0].outcome, 'failed');
request = () => new Promise(resolve => { release = resolve; });
const lateLog = context.openWorkspaceLog();
const detailCount = details.length;
events.get('razvilka:auth-required')();
release({ events: [{ path: '/private' }] }); await lateLog;
assert.equal(details.length, detailCount, 'late log opened after logout');

state.components = [{ id: 'sing-box', installed: true, installed_version: '1.10', available_version: '1.11', update_available: true, can_update: true }];
assert.match(context.engineVersionHTML({ id: 'sing-box', installed: true }), /1\.10[^]*→ 1\.11/);
state.components[0].update_available = false;
assert.doesNotMatch(context.engineVersionHTML({ id: 'sing-box', installed: true }), /→/);
assert.match(context.engineVersionHTML({ id: 'unknown', installed: true }), /Версия не определена/);
console.log('Workspace controls: exact revision, no implicit routes, double-click/refusal/logout guards and factual versions passed');
