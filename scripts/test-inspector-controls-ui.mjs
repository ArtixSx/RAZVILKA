import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// The service passport offers "Подтвердить новый состав" only when the
// autopilot stopped on a changed definition of a service it manages.
const source = readFileSync(new URL('../cmd/razvilka/web/interface.js', import.meta.url), 'utf8');
const match = source.match(/function interfaceInspectorControls\(service\)\{[^]*?\n\}\n/);
assert.ok(match, 'interfaceInspectorControls');
const context = vm.createContext({ esc: String, interfaceState: { busy: false }, consoleAutonomyError: null, consoleSnapshot: null });
vm.runInContext(match[0], context);
const render = (runtimeState, managed = { enabled: true }) => {
  context.consoleSnapshot = { policy: { setup_complete: true }, services: managed ? { roblox: managed } : {}, runtime: { roblox: { state: runtimeState } } };
  return context.interfaceInspectorControls({ id: 'roblox' });
};
assert.match(render('definition-changed'), /data-rz-action="confirm-definition"[^>]*>Подтвердить новый состав/);
assert.doesNotMatch(render('healthy'), /confirm-definition/);
assert.doesNotMatch(render('definition-changed', { enabled: false }), /confirm-definition/, 'paused service offered confirmation');
assert.doesNotMatch(render('definition-changed', null), /confirm-definition/, 'unmanaged service offered confirmation');
assert.match(source, /interfaceManage\(id,action==='manage'\|\|action==='confirm-definition',action==='remove'\)/, 'confirmation does not keep the service enabled');
console.log('Inspector controls: changed definition confirmation offered only for managed services');
