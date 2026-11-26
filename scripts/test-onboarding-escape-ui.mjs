import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// G02-T05: service names are catalog/community data. Every onboarding step
// that lists them must render them as text, never as HTML.
const source = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
const functions = ['esc', 'renderOnboarding'].map((name) => {
  const match = source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));
  assert.ok(match, name);
  return match[0];
}).join('\n');
const elements = new Map();
const $ = (id) => {
  if (!elements.has(id)) elements.set(id, { innerHTML: '', textContent: '', disabled: false, hidden: false });
  return elements.get(id);
};
const hostile = '<img src=x onerror=alert(1)>';
const service = (id, enabled) => ({ id, name: `${hostile}${id}`, icon: '<b>i</b>', enabled, custom: false, route: 'auto', probe_url: 'https://example.test/' });
const state = {
  onboardingStep: 0,
  components: [{ id: 'nfqws2', name: `${hostile}NFQWS2`, installed: true, available: true }],
  services: ['youtube', 'discord', 'telegram', 'chatgpt', 'claude', 'gemini', 'twitch'].map((id, index) => service(id, index < 3)),
  metrics: { capacity: {} },
  status: {},
  system: {},
};
const context = vm.createContext({ state, $, String, Number, Math, Array, Object, JSON });
vm.runInContext(functions, context);
for (const step of [0, 1, 2, 3]) {
  state.onboardingStep = step;
  context.renderOnboarding();
  const html = $('#onboardingContent').innerHTML + $('#onboardingSteps').innerHTML;
  assert.doesNotMatch(html, /<img src=x/, `step ${step + 1} rendered service or component HTML`);
  assert.doesNotMatch(html, /<b>i<\/b>/, `step ${step + 1} rendered an icon as HTML`);
}
state.onboardingStep = 3;
context.renderOnboarding();
assert.match($('#onboardingContent').innerHTML, /&lt;img src=x onerror=alert\(1\)&gt;youtube/, 'selected service missing from the plan step');
console.log('Onboarding steps render catalog names as text');

// Run the real legacy wizard handlers across a pending component operation.
// A completion from an old login must never reopen a modal above the login form.
const extract = name => source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`))[0];
const deferred = () => { let resolve; const promise = new Promise(yes => { resolve = yes; }); return { promise, resolve }; };
function sessionFixture() {
  const elements = new Map(), document = new EventTarget(), calls = [];
  const $ = id => {
    if (!elements.has(id)) elements.set(id, Object.assign(new EventTarget(), {
      hidden: id === '#authScreen', open: id === '#onboardingDialog',
      close() { this.open = false; }, showModal() { this.open = true; calls.push('open'); },
    }));
    return elements.get(id);
  };
  const pending = deferred(), workflowState = { epoch: 1 };
  const ctx = vm.createContext({ state: { onboardingStep: 1 }, workflowState, $, document,
    renderOnboarding: () => calls.push('render'), setOnboardingDone: () => calls.push('done'),
    onboardingDone: () => false, onboardingNeeded: () => true,
    manageComponent: () => pending.promise, refreshComponents: () => pending.promise, toggleService: () => pending.promise,
    setView: view => calls.push(view), setNodeBrowserTab() {}, onboardingNext() {},
    workflowSession: epoch => epoch === workflowState.epoch && $('#authScreen').hidden,
  });
  vm.runInContext(['openOnboarding', 'closeOnboarding', 'onboardingAction'].map(extract).join('\n'), ctx);
  const start = source.indexOf("  $('#overviewOnboarding').addEventListener");
  vm.runInContext(source.slice(start, source.indexOf("  $('#componentStrip').addEventListener", start)), ctx);
  return { ctx, $, calls, pending, workflowState,
    click(kind) { const button = { dataset: { onboardingComponent: 'nfqws2', onboardingService: 'youtube' } }; return ctx.onboardingAction({ target: { closest: selector => selector === `[data-onboarding-${kind}]` ? button : null } }); },
    logout() { workflowState.epoch++; $('#authScreen').hidden = false; document.dispatchEvent(new Event('razvilka:auth-required')); },
  };
}
for (const kind of ['component', 'refresh', 'service']) {
  for (const relogin of [false, true]) {
    const f = sessionFixture(), action = f.click(kind);
    f.logout(); if (relogin) f.$('#authScreen').hidden = true;
    f.pending.resolve(true); await action;
    assert.equal(f.$('#onboardingDialog').open, false, `${kind} reopened after logout`);
    assert.deepEqual(f.calls, [], `${kind} rendered or advanced an old session`);
    assert.equal(f.ctx.state.onboardingStep, 1);
  }
  const f = sessionFixture(), action = f.click(kind);
  f.pending.resolve(true); await action;
  assert.ok(f.calls.includes('render'), `${kind} lost its current-session result`);
  if (kind === 'component') { assert.ok(f.calls.includes('open')); assert.equal(f.ctx.state.onboardingStep, 2); }
}
{
  const f = sessionFixture(); f.logout();
  assert.equal(f.$('#onboardingDialog').open, false, 'open wizard blocks the login form');
  f.ctx.openOnboarding(true); assert.deepEqual(f.calls, [], 'forced wizard opens above login');
  await f.click('nodes'); assert.deepEqual(f.calls, [], 'logged-out wizard still navigates');
}
{
  const f = sessionFixture(), action = f.click('component');
  f.logout(); f.pending.resolve(false); await action;
  assert.deepEqual(f.calls, [], 'revoked component result reopened the wizard');
}
console.log('PASS wizard closes on auth loss and old component/refresh/service completions cannot reopen or advance it');
