import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const elements = new Map();
const $ = id => { if (!elements.has(id)) elements.set(id, { value: '', innerHTML: '', hidden: false, listeners: {}, addEventListener(name, handler) { this.listeners[name] = handler; } }); return elements.get(id); };
const chosen = [];
const state = { services: [{ id: 'telegram', name: 'Telegram', probe_url: 'https://telegram.org', enabled: true, route: 'sing-box:node-499', applied_enabled: true, applied_route: 'sing-box:node-498', applied_sources: ['192.168.1.40/32'] }], nodes: { nodes: Array.from({ length: 500 }, (_, index) => ({ id: `node-${index}`, name: index === 499 ? '<unsafe>' : `Country ${index}`, protocol: 'vless' })), groups: [] }, nodeAutofallback: { services: [] }, routeOptions: [] };
const context = vm.createContext({ state, $, $$: () => [], document: { activeElement: null, addEventListener() {} }, Set,
  esc: value => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;'),
  nodeCanCheck: node => !node.disabled, nodeDisplayName: node => node.name, nodeCountry: () => ({ flag: 'NL' }), nodeTransportLabel: () => 'TCP',
  nodeServiceHealth: (node, service) => ({ state: node.id === 'node-1' && service === 'telegram' ? 'available' : 'quarantined', label: 'Не проверен', kind: 'unknown' }),
  nodeServiceScenario: service => `${service.name}: веб`, nodeScopeText: sources => sources.join(', '), routeLabel: route => route,
  openNodeCheck: (node, service) => chosen.push({ node, service }), openNodeGroupUse() {}, openServiceScope() {}, nodeBrowser: { selected: new Set() }, renderNodes() {}, setNodeBrowserTab() {} });
vm.runInContext(readFileSync(new URL('../cmd/razvilka/web/node-service-ui.js', import.meta.url), 'utf8'), context);
context.renderNodeServices();
const html = $('#nodeServiceSelectors').innerHTML;
assert.equal((html.match(/data-service-node=/g) || []).length, 8, 'a 500-node inventory generated an unbounded service selector');
assert.match(html, /&lt;unsafe&gt;/); assert.doesNotMatch(html, /<unsafe>/);
assert.match(html, /node-service-card applied[^]*?data-service-node="node-498"/);
assert.match(html, /node-service-card selected[^]*?data-service-node="node-499"/);
assert.match(html, /192\.168\.1\.40\/32/);
assert.match(html, /Telegram: веб/);
context.bindNodeServices();
$('#nodeServiceSelectors').listeners.click({ target: { closest: selector => selector === '[data-service-node]' ? { dataset: { serviceNode: 'node-1', serviceId: 'telegram' } } : null } });
assert.deepEqual(chosen, [{ node: 'node-1', service: 'telegram' }], 'selector lost its visible service on click');
state.services[0].applied_enabled = false;
context.renderNodeServices();
assert.doesNotMatch($('#nodeServiceSelectors').innerHTML, /node-service-card applied/);
console.log('Service selectors: bounded rendering, explicit service, applied vs selected scope and escaped labels passed');
