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
