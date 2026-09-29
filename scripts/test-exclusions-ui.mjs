import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// «Исключения»: sites and devices without a bypass, edited as NFQWS2 drafts.
const source = readFileSync(new URL('../cmd/razvilka/web/exclusions-ui.js', import.meta.url), 'utf8');
const root = { innerHTML: '', listeners: {}, addEventListener(name, fn) { this.listeners[name] = fn; } };
const calls = [];
let files = {
  'exclude-list': { source: 'live', content: 'gosuslugi.ru\napple.com\n' },
  'auto-list': { source: 'live', content: 'www.apple.com\ninstagram.com\nmagnit.ru\n' },
  'ipset-exclude': { source: 'live', content: '' },
};
const mode = { available: true, source: 'live', policy_name: 'nfqws', policy_exclude: false, policy_runtime: { name: 'nfqws', exclude: false, found: false } };
const api = async (path, options = {}) => {
  calls.push({ path, options });
  if (path.startsWith('/api/v1/engine-configs/nfqws2/file?file=')) {
    const file = path.split('file=')[1];
    if (options.method === 'PUT') { files[file] = { source: 'staged', content: JSON.parse(options.body).content }; return files[file]; }
    return files[file];
  }
  if (path === '/api/v1/nfqws2/setup-mode') return mode;
  if (path === '/api/v1/nfqws2/exclusions') return { stock: ['gosuslugi.ru'] };
  if (path.startsWith('/api/v1/engine-configs/nfqws2/guided')) return { source: 'staged' };
  throw new Error('unexpected ' + path);
};
const context = vm.createContext({ document: { getElementById: (id) => id === 'exclusionsContent' ? root : null, addEventListener() {} }, api, esc: (value) => String(value).replaceAll('<', '&lt;').replaceAll('"', '&quot;'), Promise, JSON, Set, console });
vm.runInContext(source + '\nthis.view = exclusionsView;', context);

assert.equal(context.exclusionDomain('https://Bank.Example/login?x=1'), 'bank.example');
assert.equal(context.exclusionDomain('*.sub.example.'), 'sub.example');
assert.equal(context.exclusionDomain('not a domain'), '');
assert.equal(context.exclusionDomain('192.168.1.1'), '', 'IP address accepted as a site');

await context.loadExclusions();
assert.match(root.innerHTML, /Добавлены вами · 1/, 'own exclusions not separated from the package defaults');
assert.match(root.innerHTML, /Стандартные исключения nfqws2-keenetic · 1/);
// Subdomains of an excluded site are already covered and not suggested.
assert.doesNotMatch(root.innerHTML, /data-exclusion-add="www\.apple\.com"/);
assert.match(root.innerHTML, /data-exclusion-add="magnit\.ru"/);
assert.match(root.innerHTML, /NFQWS2 обрабатывает все устройства сети/);
assert.match(root.innerHTML, /Политика «nfqws» в Keenetic пока не найдена/);

context.addExcludedSite('https://Bank.Example/');
await new Promise((resolve) => setTimeout(resolve, 0)); await new Promise((resolve) => setTimeout(resolve, 0));
const put = calls.find((call) => call.options.method === 'PUT' && call.path.includes('exclude-list'));
assert.equal(JSON.parse(put.options.body).content, 'gosuslugi.ru\napple.com\nbank.example\n');
assert.match(root.innerHTML, /Проверить и применить/, 'staged exclusions have no apply action');

context.removeExcludedSite('apple.com');
await new Promise((resolve) => setTimeout(resolve, 0)); await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(files['exclude-list'].content, 'gosuslugi.ru\nbank.example\n');

context.stagePolicyExclusion(true);
await new Promise((resolve) => setTimeout(resolve, 0));
const guided = calls.find((call) => call.path.includes('/guided?file=main'));
assert.deepEqual(JSON.parse(guided.options.body), { values: { POLICY_EXCLUDE: '1' } });
console.log('Exclusions: site normalisation, own/default split, covered suggestions, drafts and policy toggle');
