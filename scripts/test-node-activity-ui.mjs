import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const elements = new Map();
const $ = id => { if (!elements.has(id)) elements.set(id, { hidden: true, disabled: false, textContent: '', addEventListener() {} }); return elements.get(id); };
$('#authScreen').hidden = true;
const listeners = new Map();
const calls = [];
let handler;
const state = {};
const context = vm.createContext({ $, state, Date, Boolean, Promise, setTimeout: () => 1, clearTimeout() {},
  document: { hidden: false, getElementById: id => $(`#${id}`), addEventListener: (name, callback) => listeners.set(name, callback) },
  api: async (url, options) => { calls.push({ url, options }); return handler(url, options); }, refreshAll: async () => {}, showAuth() {},
});
vm.runInContext(readFileSync(new URL('../cmd/razvilka/web/node-activity-ui.js', import.meta.url), 'utf8'), context);
handler = async url => url.endsWith('/node-autofallback') ? { active: true, services: [] } : { job: null };
assert.equal(await context.refreshNodeActivity(), true);
assert.equal($('#nodeActivityNotice').hidden, false);
assert.equal($('#nodeActivityCancel').hidden, false);
assert.ok(calls.every(call => call.url.endsWith('/node-autofallback') || call.url.endsWith('/node-checks/current')), 'busy refresh requested locked stores');
await context.cancelNodeActivity();
assert.ok(calls.some(call => call.url === '/api/v1/node-autofallback' && call.options?.method === 'DELETE'));

context.resetNodeActivity();
listeners.get('razvilka:auth-restored')();
handler = async url => url.endsWith('/node-autofallback') ? { active: false } : { job: { id: 3, mode: 'service', state: 'running', total: 4, completed: 2 } };
assert.equal(await context.refreshNodeActivity(), true);
await context.cancelNodeActivity();
assert.ok(calls.some(call => call.url === '/api/v1/node-checks/current' && call.options?.method === 'DELETE'));

context.resetNodeActivity();
listeners.get('razvilka:auth-restored')();
const resolvers = [];
handler = () => new Promise(resolve => resolvers.push(resolve));
const late = context.refreshNodeActivity();
listeners.get('razvilka:auth-required')();
resolvers[0]({ job: { mode: 'service', state: 'running' } }); resolvers[1]({ active: true });
await late;
assert.equal($('#nodeActivityNotice').hidden, true, 'late pre-logout response restored protected UI');
assert.equal(context.nodeActivityActive(), false);
const beforeBlocked = calls.length;
await context.refreshNodeActivity();
await context.cancelNodeActivity();
assert.equal(calls.length, beforeBlocked, 'logged-out activity made protected requests');

// Cancel may finish after logout; it must not start new status reads or timers.
listeners.get('razvilka:auth-restored')();
handler = async url => url.endsWith('/node-autofallback') ? { active: true } : { job: null };
await context.refreshNodeActivity();
let finishCancel;
handler = (url, options) => { assert.equal(options?.method, 'DELETE'); return new Promise(resolve => { finishCancel = resolve; }); };
const canceling = context.cancelNodeActivity();
const afterCancelRequest = calls.length;
listeners.get('razvilka:auth-required')();
finishCancel({ ok: true });
await canceling;
assert.equal(calls.length, afterCancelRequest, 'a late cancel polled a logged-out session');
assert.equal($('#nodeActivityNotice').hidden, true);

listeners.get('razvilka:auth-restored')();
context.document.hidden = true;
listeners.get('visibilitychange')();
await context.refreshNodeActivity();
assert.equal(calls.length, afterCancelRequest, 'hidden activity made protected requests');

// The full page authenticates before consulting activity, and while busy it
// stops after those memory reads so login and cancellation remain accessible.
context.document.hidden = false;
context.hideAuth = () => { $('#authScreen').hidden = true; listeners.get('razvilka:auth-restored')(); };
const app = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
const refreshAll = app.match(/async function refreshAll\([^]*?\n}\n/)[0];
vm.runInContext(refreshAll, context);
handler = async url => {
  if (url === '/api/v1/auth/status') return { authenticated: true };
  if (url === '/api/v1/node-checks/current') return { job: { mode: 'service', state: 'running', completed: 1, total: 10 } };
  if (url === '/api/v1/node-autofallback') return { active: false };
  throw new Error(`busy page requested locked endpoint ${url}`);
};
const beforeBootstrap = calls.length;
assert.equal(await context.refreshAll(), true);
assert.deepEqual(calls.slice(beforeBootstrap).map(call => call.url), ['/api/v1/auth/status', '/api/v1/node-checks/current', '/api/v1/node-autofallback']);
handler = async url => {
  if (url === '/api/v1/auth/status') return { authenticated: false };
  if (url === '/api/v1/status') throw Object.assign(new Error('busy'), { status: 423 });
  throw new Error(`unauthenticated page requested ${url}`);
};
assert.equal(await context.refreshAll(), false, 'a cached running job bypassed fresh authentication');
console.log('Busy operation cancel, memory-only polling and logout fencing passed');
