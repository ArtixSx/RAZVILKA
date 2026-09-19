import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const require=createRequire(import.meta.url), m=require('../cmd/razvilka/web/extension-lab.js');
let passed=0;function test(name,fn){fn();passed++;console.log('PASS',name);}
const source='vless://fixture@example.com:443';
test('selected node is converted to zero-based index',()=>assert.deepEqual(m.mihomo(source,2,18090).options,{index:1,socks_port:18090}));
for(const [i,p] of [[0,18090],[1,53],[1,65536],[1.1,18090],[513,18090]])test('reject bad index/port '+i+':'+p,()=>assert.throws(()=>m.mihomo(source,i,p)));
test('reject absent source',()=>assert.throws(()=>m.mihomo('',1,18090)));
test('reject oversized content',()=>assert.throws(()=>m.mihomo('a'.repeat(262145),1,18090)));
test('export requires review',()=>assert.throws(()=>m.mihomo(source,1,18090,'export','')));
test('export requires exact confirmation operation',()=>assert.equal(m.mihomo(source,1,18090,'export','a'.repeat(64)).confirm,'BUILD_MIHOMO_CONFIG'));
test('import requires review',()=>assert.throws(()=>m.pack('{}',false,'import','')));
test('signed flag and review retained',()=>{const q=m.pack('{}',true,'import','a'.repeat(64));assert.equal(q.signed,true);assert.equal(q.confirm,'IMPORT_STRATEGY_CANDIDATES');});
for(const obj of [null,{}, {live_applied:true},{live_applied:false,service_verified:true},{live_applied:false,native_validated:true}])test('never display earned runtime for passive result '+JSON.stringify(obj),()=>assert.throws(()=>m.safeResult(obj)));
test('passive result accepted',()=>assert.equal(m.safeResult({live_applied:false}).live_applied,false));
const preview={live_applied:false,native_validated:false,service_verified:false,protocol:'vless',socks_port:18090,source:{engine_id:'mihomo',selected_index:1,nodes:[{server:'unused.example',port:443},{protocol:'VLESS',server:'chosen.example',port:8443,tls:true,transport:'ws',security:'reality',engine_id:'sing-box',name:'private-label',uuid:'private-uuid',password:'private-password',warnings:['Проверка сертификата отключена в исходном профиле.']}],warnings:['DNS и TUN не включены.']}};
test('Mihomo summary describes selected connection and no successful network proof',()=>{const text=m.mihomoSummary(preview);for(const value of ['Выбран узел 2 из 2','VLESS','chosen.example:8443','WebSocket','TLS + Reality','127.0.0.1:18090','Подключение не проверялось и не включено','Проверка сертификата отключена','DNS и TUN не включены'])assert.ok(text.includes(value),value);assert.doesNotMatch(text,/unused\.example|engine_id|native_validated|source_index|sing-box|private-/);});
test('Mihomo summary never serializes config or additional secret fields',()=>{const text=m.mihomoSummary({...preview,config:'secret YAML',private_key:'secret key'});assert.doesNotMatch(text,/secret YAML|secret key|private-uuid|private-password|private-label/);});
test('Mihomo summary brackets IPv6 endpoints and identifies plain TCP',()=>{const other=structuredClone(preview);other.source.selected_index=0;other.source.nodes[0]={server:'2001:db8::1',port:443,tls:false,transport:'tcp'};assert.match(m.mihomoSummary(other),/\[2001:db8::1\]:443/);assert.match(m.mihomoSummary(other),/TLS выключен/);});
test('Mihomo summary refuses missing selected node and false runtime claims',()=>{assert.throws(()=>m.mihomoSummary({...preview,source:{selected_index:9,nodes:[]}}));assert.throws(()=>m.mihomoSummary({...preview,service_verified:true}));});
const html=readFileSync(new URL('../cmd/razvilka/web/index.html',import.meta.url),'utf8'),js=readFileSync(new URL('../cmd/razvilka/web/extension-lab.js',import.meta.url),'utf8');
test('one dialog and all referenced DOM controls exist',()=>{assert.equal((html.match(/id="extensionLabDialog"/g)||[]).length,1);for(const match of js.matchAll(/el\('(ext5[^']+)'\)/g))assert.ok(html.includes(`id="${match[1]}"`),match[1]);});
test('no independent polling/localStorage/remote requests',()=>{assert.ok(!/localStorage|setInterval|fetch\(/.test(js));assert.ok(js.includes('workflowSession(epoch)'));assert.ok(js.includes('serial'));assert.ok(js.includes('auth-required'));});
test('passive tools not new routes',()=>{assert.ok(html.includes('data-extension-open="mihomo"'));assert.ok(!html.includes('data-engine-id="mihomo"'));assert.ok(!js.includes('/api/v1/apply'));});

function fixture(){
 const elements=new Map(),documentEvents=new Map(),requests=[];
 const ids=[...html.matchAll(/<button\b[^>]*\bid="(ext5[^"]+)"/g)].map(match=>match[1]);
 const el=id=>{if(!elements.has(id))elements.set(id,{value:'',disabled:false,hidden:false,open:true,files:[],events:new Map(),textContent:'',addEventListener(type,fn){this.events.set(type,fn);},setAttribute(){},replaceChildren(){},querySelectorAll(){return ids.filter(id=>!['ext5Close','ext5Cancel'].includes(id)).map(el);},showModal(){this.open=true;},close(){this.open=false;this.events.get('close')?.();}});return elements.get(id);};
 const workflowState={epoch:1};
 const ctx={TextEncoder,AbortController,document:{getElementById:el,querySelectorAll:()=>[],addEventListener:(name,fn)=>documentEvents.set(name,fn)},workflowState,workflowSession:epoch=>epoch===workflowState.epoch,workflowError:error=>error.message,workflowRequest:async(path,options)=>{requests.push({path,options});return {};}};
 vm.runInNewContext(js,ctx);el('ext5MIndex').value='1';el('ext5MPort').value='18090';
 return {el,requests,workflowState,documentEvents,click:id=>el(id).events.get('click')()};
}
function pendingFile(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {file:{size:80,text:()=>promise},resolve,reject};}
async function asyncTest(name,fn){await fn();passed++;console.log('PASS',name);}

await asyncTest('file read blocks preview of previous content until new contents arrive',async()=>{
 const f=fixture(),file=pendingFile();f.el('ext5MText').value=source;f.el('ext5MFile').files=[file.file];
 const reading=f.el('ext5MFile').events.get('change')();
 assert.equal(f.el('ext5MText').value,'');assert.equal(f.el('ext5MPreview').disabled,true);assert.equal(f.el('ext5Cancel').hidden,false);
 f.click('ext5MPreview');assert.equal(f.requests.length,0);
 file.resolve('new-profile');await reading;assert.equal(f.el('ext5MText').value,'new-profile');assert.equal(f.el('ext5MPreview').disabled,false);assert.equal(f.el('ext5MExport').disabled,true);
});
await asyncTest('failed or oversized replacement cannot leave previous profile under new filename',async()=>{
 const f=fixture(),file=pendingFile();f.el('ext5MText').value=source;f.el('ext5MFile').files=[file.file];
 const reading=f.el('ext5MFile').events.get('change')();file.reject(new Error('read failed'));await reading;
 assert.equal(f.el('ext5MText').value,'');assert.match(f.el('ext5Status').textContent,/Не удалось/);assert.equal(f.el('ext5MPreview').disabled,false);
 f.el('ext5MText').value=source;f.el('ext5MFile').files=[{size:262145,text(){throw new Error('must not read');}}];await f.el('ext5MFile').events.get('change')();
 assert.equal(f.el('ext5MText').value,'');assert.match(f.el('ext5Status').textContent,/превышает/);
});
await asyncTest('canceled file read cannot overwrite newer pasted content',async()=>{
 const f=fixture(),file=pendingFile();f.el('ext5PFile').files=[file.file];const reading=f.el('ext5PFile').events.get('change')();
 f.el('ext5PText').value='new paste';f.el('ext5PText').events.get('input')();file.resolve('obsolete file');await reading;
 assert.equal(f.el('ext5PText').value,'new paste');assert.equal(f.el('ext5PPreview').disabled,false);assert.equal(f.el('ext5PImport').disabled,true);
});
await asyncTest('logout clears content and fences pending local file read',async()=>{
 const f=fixture(),file=pendingFile();f.el('ext5MFile').files=[file.file];const reading=f.el('ext5MFile').events.get('change')();
 f.workflowState.epoch++;f.documentEvents.get('razvilka:auth-required')();file.resolve('private profile');await reading;
 assert.equal(f.el('ext5MText').value,'');assert.equal(f.el('extensionLabDialog').open,false);assert.match(f.el('ext5Status').textContent,/Требуется вход/);
});
console.log(JSON.stringify({suite:'extension-lab',passed}));
