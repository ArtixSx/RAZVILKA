import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// The service passport offers "Подтвердить новый состав" only when the
// autopilot stopped on a changed definition of a service it manages.
const source = readFileSync(new URL('../cmd/razvilka/web/interface.js', import.meta.url), 'utf8');
const match = source.match(/function interfaceInspectorControls\(service\)\{[^]*?\n\}\n/);
assert.ok(match, 'interfaceInspectorControls');
const readiness = source.match(/function interfaceServiceActionsReady\(service\)\{[^]*?\n\}/);
const dataReady = source.match(/function interfaceDataReady\(key\)\{[^\n]+\}/);
assert.ok(readiness, 'actual service action readiness');
assert.ok(dataReady, 'actual service data readiness');
const context = vm.createContext({ esc: String, interfaceState: { busy: false, authRevoked: false },
  state: { authenticated: true, dataLoad: { services: { loaded: true, phase: 'ready' } } }, consoleAutonomyError: null, consoleSnapshot: null });
vm.runInContext(dataReady[0] + '\n' + readiness[0] + '\n' + match[0], context);
const render = (runtimeState, managed = { enabled: true }) => {
  context.consoleSnapshot = { policy: { setup_complete: true }, services: managed ? { roblox: managed } : {}, runtime: { roblox: { state: runtimeState } } };
  return context.interfaceInspectorControls({ id: 'roblox' });
};
assert.match(render('definition-changed'), /data-rz-action="confirm-definition"[^>]*>Подтвердить новый состав/);
assert.doesNotMatch(render('healthy'), /confirm-definition/);
assert.doesNotMatch(render('definition-changed', { enabled: false }), /confirm-definition/, 'paused service offered confirmation');
assert.doesNotMatch(render('definition-changed', null), /confirm-definition/, 'unmanaged service offered confirmation');
for (const unavailable of ['unauthenticated', 'revoked', 'unloaded', 'loading', 'failed', 'exclusions-loading', 'presentation-only']) {
  context.state = { authenticated: true, dataLoad: { services: { loaded: true, phase: 'ready' } } };
  context.interfaceState.authRevoked = false;
  if (unavailable === 'unauthenticated') context.state.authenticated = false;
  if (unavailable === 'revoked') context.interfaceState.authRevoked = true;
  if (unavailable === 'unloaded') context.state.dataLoad.services.loaded = false;
  if (unavailable === 'loading') context.state.dataLoad.services.phase = 'loading';
  if (unavailable === 'failed') context.state.dataLoad.services.phase = 'error';
  if (unavailable === 'exclusions-loading') {
    context.state.resourceExclusions = {};
    context.state.dataLoad.resourceExclusions = { phase: 'loading' };
  }
  render('definition-changed');
  const html = context.interfaceInspectorControls({ id: 'roblox', presentation_only: unavailable === 'presentation-only' });
  assert.match(html, /data-panel-refresh/, unavailable + ' did not request fresh settings');
  assert.doesNotMatch(html, /data-rz-action=/, unavailable + ' exposed a service mutation');
}
const dispatch = source.match(/interfaceManage\(id,action===[^;\n]+/);
assert.ok(dispatch, 'actual inspector service action dispatch');
const confirmation = vm.runInNewContext(dispatch[0], { id: 'roblox', action: 'confirm-definition', interfaceManage: (...args) => args });
assert.deepEqual(Array.from(confirmation), ['roblox', true, false, false], 'confirmation must keep the service enabled without removing its definition');
console.log('Inspector controls: changed definition confirmation offered only for managed services');
