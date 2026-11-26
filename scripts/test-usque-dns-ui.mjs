import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
const fn = source.match(/async function checkUsqueDNSCandidate\([^]*?\n}\n/);
assert.ok(fn);
const selector = { value: 'quad9-unfiltered', disabled: false };
const output = { innerHTML: '' };
const button = { disabled: false, textContent: '' };
let fail = false;
let calls = 0;
const context = vm.createContext({
  $: name => name === '#usqueDNSCandidateProfile' ? selector : output,
  esc: value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;'),
  api: async (url, options) => {
    calls++;
    assert.equal(url, '/api/v1/diagnostics/usque/dns-candidate');
    assert.deepEqual(JSON.parse(options.body), { profile_id: 'quad9-unfiltered' });
    assert.equal(selector.disabled, true);
    if (fail) throw new Error('<img src=x onerror=alert(1)>');
    return { results: [{ transport: 'DoH', server: '<unsafe>', status: 'pass', ipv4: true, addresses: 2 }] };
  },
});
vm.runInContext(fn[0], context);
const event = { currentTarget: button };
const pending = context.checkUsqueDNSCandidate(event);
await context.checkUsqueDNSCandidate(event);
await pending;
assert.equal(calls, 1, 'double-click must not send a second probe');
assert.match(output.innerHTML, /&lt;unsafe&gt;/);
assert.doesNotMatch(output.innerHTML, /<unsafe>/);
assert.equal(button.disabled, false);
assert.equal(selector.disabled, false);
fail = true;
await context.checkUsqueDNSCandidate(event);
assert.match(output.innerHTML, /&lt;img/);
assert.doesNotMatch(output.innerHTML, /<img/);
assert.equal(button.disabled, false);
assert.equal(selector.disabled, false);
console.log('USQUE DNS candidate UI behavior checks passed');
