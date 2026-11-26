// A typed or pasted panel link with a malformed escape must fall back to the
// default view instead of throwing; ordinary links keep working.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const code = fs.readFileSync(new URL('../cmd/razvilka/web/console.js', import.meta.url), 'utf8');
const segment = code.match(/function consoleRouteSegment\(value\)\{[^\n]*\}/)[0];
const route = code.match(/function consoleRouteHash\(\)\{[\s\S]*?\r?\n\}/)[0];
let checks = 0;
function run(hash, initialized = false) {
  const calls = [];
  const ctx = {
    location: { hash },
    consoleEngineMeta: { xray: {}, nfqws2: {} },
    document: { getElementById: (id) => ['view-overview', 'view-services'].includes(id) },
    consoleInitialized: initialized,
    setView: (view) => calls.push(['view', view]),
    consoleNavigate: (view, engine) => calls.push(['navigate', view, engine]),
  };
  vm.runInNewContext(`${segment}\n${route}\nconsoleRouteHash();`, ctx);
  checks++;
  return calls;
}
assert.deepEqual(run('#/engine/%'), [['view', 'overview']], 'malformed escape falls back');
assert.deepEqual(run('#/engine/%E0%A4%A'), [['view', 'overview']], 'truncated escape falls back');
assert.deepEqual(run('#/engine/xray'), [['navigate', 'engineconfig', 'xray']], 'engine link');
assert.deepEqual(run('#/engine/unknown'), [['view', 'overview']], 'unknown engine falls back');
assert.deepEqual(run('#/services'), [['view', 'services']], 'ordinary view link');
assert.deepEqual(run('#/engine/%', true), [], 'later malformed link leaves the current view');
console.log(JSON.stringify({ suite: 'console-route-hash', passed: checks }));
