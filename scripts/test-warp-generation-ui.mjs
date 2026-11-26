import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
const functions = ['renderWarpManager', 'generateWarp'].map(name => {
  const match = source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));
  assert.ok(match, name);
  return match[0];
}).join('\n');
const elements = new Map();
const $ = id => {
  if (!elements.has(id)) elements.set(id, { value: '', textContent: '', innerHTML: '', hidden: false, disabled: false, checked: false, options: [], classList: { toggle() {} } });
  return elements.get(id);
};
const state = { selectedEngine: 'warp-wg', components: [], services: [], status: {}, warp: { generator_installed: true, generator_kind: 'native-cloudflare', registration_state: 'none' } };
const calls = [];
const context = vm.createContext({ state, $, JSON, String,
  esc: String, evidenceLevelLabel: String,
  askConfirmation: async () => true,
  api: async (url, options) => { calls.push({ url, options }); return { ok: true, message: 'staged' }; },
  refreshEngineConfigs: async () => {}, refreshWarp: async () => {}, showNotice() {},
  showDetails() { throw new Error('offline recovery unexpectedly requires registration consent'); },
});
vm.runInContext(functions, context);
context.renderWarpManager();
assert.equal($('#warpGenerate').disabled, false, 'native generation requires an installed runtime');
assert.equal($('#warpRotate').disabled, false, 'native fresh generation requires wgcf');
assert.equal($('#warpCanary').disabled, true, 'generation readiness incorrectly enabled runtime proof');

state.warp.registration_state = 'pending-review';
context.renderWarpManager();
assert.equal($('#warpGenerate').disabled, true, 'unknown registration outcome allows another creation');
assert.equal($('#warpRotate').disabled, true);
assert.match($('#warpNote').textContent, /Загрузить свой/);
state.warp.candidate_staged = true;
context.renderWarpManager();
assert.equal($('#warpCheck').disabled, false, 'checking file structure needs no tunnel runtime');
assert.equal($('#warpCanary').disabled, true);
state.warp.recovery_available = true;
context.renderWarpManager();
assert.equal($('#warpGenerate').disabled, false);
assert.equal($('#warpGenerate').textContent, 'Восстановить профиль');
assert.equal($('#warpRotate').disabled, true);
await context.generateWarp(false);
assert.equal(calls.length, 1);
const request = JSON.parse(calls[0].options.body);
assert.equal(request.fresh, false);
assert.equal(request.accept_tos, false, 'offline recovery declared a new registration');

state.warp.registration_state = 'local-state-invalid';
context.renderWarpManager();
assert.equal($('#warpGenerate').disabled, true);
assert.equal($('#warpRotate').disabled, true);
const canaryFunction = source.match(/async function checkWarpCanary\([^]*?\n}\n/);
assert.ok(canaryFunction);
vm.runInContext(canaryFunction[0], context);
state.services = [{ id: 'owned-service', name: 'Сервис' }];
$('#warpCanaryService').value = 'owned-service';
context.renderWarpManager = () => {};
for (const raw of ['context deadline exceeded', 'canary probe deadline exceeded', 'request timeout before admission']) {
  const notices = [];
  context.api = async () => { throw Object.assign(new Error(raw), { status: 503, payload: { error: raw } }); };
  context.showNotice = (...args) => notices.push(args);
  await context.checkWarpCanary();
  assert.equal(notices.length, 1);
  assert.match(notices[0][2], /не подтверждены/);
  assert.doesNotMatch(notices[0][2], /туннель поднялся|туннель.*работает/i);
}
vm.runInContext(source.match(/async function checkWarpConnectivity\([^]*?\n}\n/)[0], context);
context.api = async () => ({
  ok: true, registration: { ready: true, message: 'HEAD HTTP 405' },
  masque_tcp: { ready: true, latency_ms: 73 }, masque_http2: { ready: false },
});
let report;
context.showDetails = data => { report = data; };
await context.checkWarpConnectivity();
assert.equal(report.checks[0].status, 'ЕСТЬ ОТВЕТ');
assert.equal(report.checks[1].latency_ms, 73);
assert.equal(report.checks[1].status, 'ЕСТЬ СОЕДИНЕНИЕ');
assert.equal(report.checks[2].status, 'НЕ ПРОВЕРЯЛСЯ');
state.warp = { registration_state: 'registered', account_registered: true, generator_installed: true };
const followups = [];
context.api = async () => ({ok: true});
context.refreshEngineConfigs = async () => { throw new Error('readback offline'); };
context.showNotice = (...args) => followups.push(args);
await context.generateWarp(false);
vm.runInContext(source.match(/async function importWarpFile\([^]*?\n}\n/)[0], context);
await context.importWarpFile({target: {files: [{size: 8, text: async () => 'fixture'}]}});
assert.deepEqual(followups.map(x => x[1]), ['Профиль WARP сохранён', 'Профиль WARP загружен']);
assert.ok(followups.every(x => x[2].includes('Обновите страницу')));
context.api = async () => { throw Object.assign(new Error('unresolved'), {payload:{code:'WARP_REGISTRATION_PENDING'}}); };
context.refreshWarp = async () => { state.warp.registration_state = 'pending-review'; state.warp.recovery_available = false; };
await context.generateWarp(false);
let opened = 0;
$('#warpImportInput').click = () => opened++;
assert.equal(followups.at(-1)[5].label, 'Загрузить свой .conf');
followups.at(-1)[5].run();
assert.equal(opened, 1);
console.log('WARP generation, offline import/recovery, transport and canary evidence: PASS');
