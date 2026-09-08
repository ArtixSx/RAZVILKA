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
console.log('WARP native generation and offline recovery UI gates: PASS');
