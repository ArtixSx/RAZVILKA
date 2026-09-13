import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../cmd/razvilka/web/theme.js',import.meta.url),'utf8');
function page(saved,blocked=false){
  const writes=[],meta={setAttribute(name,value){this[name]=value;}};
  const ctx={document:{documentElement:{dataset:{}},querySelector:()=>meta},window:{},localStorage:{getItem(){if(blocked)throw Error('denied');return saved;},setItem(key,value){if(blocked)throw Error('denied');writes.push([key,value]);}}};
  vm.runInNewContext(source,ctx);return {ctx,writes,meta};
}
for(const value of [null,undefined,'','invalid','dark']){
  const p=page(value);assert.equal(p.ctx.document.documentElement.dataset.theme,'dark');assert.equal(p.meta.content,'#0c121b');assert.equal(p.writes.length,0);
}
const light=page('light');assert.equal(light.ctx.document.documentElement.dataset.theme,'light');assert.equal(light.meta.content,'#f5f6f8');assert.equal(light.writes.length,0);
light.ctx.window.RazvilkaTheme.apply('dark',true);assert.deepEqual(light.writes,[['razvilka.interface.theme','dark']]);
assert.equal(page(light.writes[0][1]).ctx.document.documentElement.dataset.theme,'dark');
const denied=page(null,true);assert.equal(denied.ctx.window.RazvilkaTheme.apply('light',true),'light');assert.equal(denied.ctx.document.documentElement.dataset.theme,'light');
const html=readFileSync(new URL('../cmd/razvilka/web/index.html',import.meta.url),'utf8');
assert.match(html,/<html data-theme="dark"/);assert.ok(html.indexOf('/theme.js?')<html.indexOf('rel="stylesheet"'));
console.log('PASS theme: dark first visit, explicit light, reload, invalid preference, blocked storage, early paint');
