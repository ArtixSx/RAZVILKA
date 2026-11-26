import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
const source = readFileSync(new URL('../cmd/razvilka/web/interface.js', import.meta.url), 'utf8');
const action = source.match(/function interfaceReturnInspectorFocus\([^]*?\n}\n/)[0];
for (const mode of ['connected', 'replaced', 'removed', 'logout', 'navigation']) {
  let focused;
  const old = { isConnected: mode === 'connected', focus: () => focused = 'old' };
  const current = { dataset: { rzInspect: 'youtube' }, focus: () => focused = 'current' };
  const context = { state: { currentView: mode === 'navigation' ? 'settings' : 'services' },
    interfaceState: { inspector: 'youtube', returnFocus: old, authRevoked: mode === 'logout' },
    $$: () => mode === 'removed' ? [] : [current], $: () => ({ focus: () => focused = 'search' }) };
  vm.runInNewContext(action + '\ninterfaceReturnInspectorFocus();', context);
  assert.equal(focused, { connected: 'old', replaced: 'current', removed: 'search' }[mode]);
  assert.equal(context.interfaceState.inspector, null);
  assert.equal(context.interfaceState.returnFocus, null);
}
console.log('Inspector focus survives card refresh; logout/navigation do not steal focus');
