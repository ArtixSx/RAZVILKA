import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// A device with dozens of temporary IPv6 addresses keeps a readable card.
const source = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
const match = source.match(/function deviceAddressesHTML\(ips\) \{[^]*?\n\}\n/);
assert.ok(match, 'deviceAddressesHTML');
const context = vm.createContext({ esc: value => String(value).replaceAll('<', '&lt;') });
vm.runInContext(match[0], context);
assert.match(context.deviceAddressesHTML([]), /IP пока неизвестен/);
const few = context.deviceAddressesHTML(['192.168.1.2', 'fe80::1']);
assert.equal((few.match(/<code>/g) || []).length, 2);
assert.doesNotMatch(few, /details/);
const many = context.deviceAddressesHTML(Array.from({ length: 30 }, (_, i) => `fe80::${i}`));
assert.equal((many.split('<details')[0].match(/<code>/g) || []).length, 4, 'more than four addresses shown before the disclosure');
assert.match(many, /<summary>Ещё 26 адрес\(ов\)<\/summary>/);
assert.equal((many.match(/<code>/g) || []).length, 30, 'hidden addresses were dropped');
assert.doesNotMatch(context.deviceAddressesHTML(['<b>']), /<b>/, 'address not escaped');
console.log('Device addresses: long lists collapse after four entries without losing any');
