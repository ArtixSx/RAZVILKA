import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const html = readFileSync(new URL('../cmd/razvilka/web/index.html', import.meta.url), 'utf8');
const source = readFileSync(new URL('../cmd/razvilka/web/cloudflare-migration.js', import.meta.url), 'utf8');
class Element {
  handlers = {}; value = ''; textContent = ''; innerHTML = ''; hidden = false; disabled = false; open = false;
  addEventListener(name, fn) { (this.handlers[name] ||= []).push(fn); }
  setAttribute() {}
  async fire(name, event = {}) { for (const fn of this.handlers[name] || []) await fn({preventDefault(){}, ...event}); }
  dispatchEvent(event) { return this.fire(event.type, event); }
}
const elements = new Map([...html.matchAll(/id="(cloudflare[^"]+)"/g)].map((match) => [match[1],new Element()]));
const document = new Element(), window = new Element();
document.getElementById = (id) => { assert.ok(elements.has(id),`missing ${id}`); return elements.get(id); };
const calls = [];
let error, deferred, badReview;
const preview = { review: {source_id:'fixture',review_digest:'a'.repeat(64),account:{format:'wireguard-v1'}} };
const context = vm.createContext({document,window,Event,AbortController,Error,
  esc:(value)=>String(value).replaceAll('<','&lt;'),
  cloudflareAccountSummary:()=>({name:'WARP',state:'Структура распознана · связь не проверена'}),
  api:async(path,options)=>{
    calls.push({path,options});
    if(error){const failure=error;error=null;throw failure;}
    if(deferred)return deferred;
    if(path.endsWith('/sources'))return {sources:[{id:'fixture',label:'Synthetic source'}]};
    return badReview || preview;
  },
});
vm.runInContext(source,context);
const el=(id)=>document.getElementById(`cloudflareLegacy${id}`);
const section=document.getElementById('cloudflareCopies');
const open=async()=>{section.open=true;await section.fire('toggle');el('Source').value='fixture';};
const check=()=>el('Form').fire('submit');
assert.equal(calls.length,0,'startup must not scan sources');
await open();
assert.equal(calls[0].path,'/api/v1/cloudflare/legacy/sources');
assert.equal(el('PreviewButton').disabled,false);
await check();
assert.equal(el('Copy').hidden,false);
assert.equal(el('Copy').disabled,false);
assert.deepEqual(JSON.parse(calls.at(-1).options.body),{source_id:'fixture'});
await el('Copy').fire('click');
assert.deepEqual(JSON.parse(calls.at(-1).options.body),{source_id:'fixture',review_digest:'a'.repeat(64),confirm:'COPY_LEGACY_ACCOUNT'});
const count=calls.length;await el('Copy').fire('click');assert.equal(calls.length,count);
assert.equal(el('Copy').hidden,true);

for(const reset of [()=>el('Source').fire('change'),()=>el('Cancel').fire('click'),()=>document.fire('razvilka:auth-required'),()=>document.fire('razvilka:view-change',{detail:'overview'}),()=>window.fire('pagehide')]) {
  await open();await check();const before=calls.length;
  await reset();await el('Copy').fire('click');assert.equal(calls.length,before);assert.equal(el('Copy').hidden,true);
}
await open();await check();error=new Error('Исходный файл изменился');await el('Copy').fire('click');
assert.equal(el('Copy').hidden,true);assert.match(el('Message').textContent,/изменился/);

for(const stage of ['sources','preview','copy']) {
  await open();if(stage==='copy')await check();
  let resolve;deferred=new Promise(done=>resolve=done);
  const running=stage==='sources'?open():stage==='preview'?check():el('Copy').fire('click');
  await new Promise(done=>setImmediate(done));
  await document.fire('razvilka:view-change',{detail:'overview'});
  resolve(stage==='sources'?{sources:[{id:'fixture',label:'Late'}]}:preview);
  await running;deferred=null;
  assert.equal(el('Copy').hidden,true,'late response resurrected confirmation');
  assert.equal(el('PreviewButton').disabled,true);
}
await open();badReview={review:{source_id:'different',review_digest:'a'.repeat(64),account:{}}};await check();
assert.equal(el('Copy').hidden,true,'preview for another source accepted');
assert.doesNotMatch(source,/sessionStorage|localStorage|console\./);
console.log('Cloudflare migration UI checks passed');
