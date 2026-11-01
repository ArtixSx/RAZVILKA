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
test('native validation requires current review and distinct confirmation',()=>{assert.throws(()=>m.mihomo(source,1,18090,'validate'));assert.equal(m.mihomo(source,1,18090,'validate','a'.repeat(64)).confirm,'VALIDATE_MIHOMO_CONFIG');});
const nativeReview='a'.repeat(64), nativeReply={review:nativeReview,live_applied:false,draft_persisted:false,validation:{config_sha256:nativeReview,version:'1.19.33',native_validated:true,service_verified:false,live_applied:false},result:{native_validated:true,service_verified:false,live_applied:false,config:''}};
test('service probe binds review, catalog id and current revision with distinct confirmation',()=>{const q=m.probeMihomo(source,1,18090,nativeReview,'service',4);assert.equal(q.action,'probe');assert.equal(q.confirm,'PROBE_MIHOMO_SERVICE');assert.equal(q.service_id,'service');assert.equal(q.expected_revision,4);for(const [s,r] of [['',4],['service',undefined],['service',0]])assert.throws(()=>m.probeMihomo(source,1,18090,nativeReview,s,r));});
const serviceReply={review:nativeReview,live_applied:false,draft_persisted:false,recovery_required:false,probe:{review_sha256:nativeReview,config_sha256:'b'.repeat(64),service_id:'service',network_profile:'wan-current',service_verified:true,cleanup_verified:true,live_applied:false}};
test('service proof accepts distinct pinned profile only with joined cleanup',()=>assert.match(m.serviceMihomo(serviceReply,nativeReview,'service'),/Процесс завершён/));
test('service proof rejects stale service, missing cleanup and live claims',()=>{for(const mutate of [q=>q.review='c'.repeat(64),q=>q.probe.review_sha256='c'.repeat(64),q=>q.probe.service_id='other',q=>delete q.probe.config_sha256,q=>q.probe.cleanup_verified=false,q=>q.probe.service_verified=false,q=>q.probe.live_applied=true,q=>q.live_applied=true,q=>q.recovery_required=true]){const q=structuredClone(serviceReply);mutate(q);assert.throws(()=>m.serviceMihomo(q,nativeReview,'service'));}});
test('native validation reports config acceptance without runtime proof',()=>assert.match(m.nativeMihomo(nativeReply,nativeReview),/Доступ сервиса не проверялся/));
test('native result rejects stale digest, hidden config and manufactured runtime claims',()=>{for(const mutate of [q=>q.review='b'.repeat(64),q=>q.validation.config_sha256='b'.repeat(64),q=>q.validation.service_verified=true,q=>q.validation.live_applied=true,q=>q.result.service_verified=true,q=>q.result.native_validated=false,q=>q.result.config='secret',q=>q.draft_persisted=true]){const q=structuredClone(nativeReply);mutate(q);assert.throws(()=>m.nativeMihomo(q,nativeReview));}});
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

function fixture(reply=async()=>({})){
 const elements=new Map(),documentEvents=new Map(),requests=[];
 const ids=[...html.matchAll(/<button\b[^>]*\bid="(ext5[^"]+)"/g)].map(match=>match[1]);
 const el=id=>{if(!elements.has(id))elements.set(id,{value:'',disabled:false,hidden:false,open:true,files:[],events:new Map(),textContent:'',addEventListener(type,fn){this.events.set(type,fn);},setAttribute(){},replaceChildren(){},querySelectorAll(){return ids.filter(id=>!['ext5Close','ext5Cancel'].includes(id)).map(el);},showModal(){this.open=true;},close(){this.open=false;this.events.get('close')?.();}});return elements.get(id);};
 const workflowState={epoch:1};
 const ctx={TextEncoder,AbortController,state:{status:{revision:4},services:[]},document:{getElementById:el,querySelectorAll:()=>[],addEventListener:(name,fn)=>documentEvents.set(name,fn)},workflowState,workflowSession:epoch=>epoch===workflowState.epoch,workflowError:error=>error.message,workflowRequest:async(path,options)=>{requests.push({path,options});return reply(path,options);}};
 vm.runInNewContext(js,ctx);el('ext5MIndex').value='1';el('ext5MPort').value='18090';
 return {el,requests,workflowState,documentEvents,click:id=>el(id).events.get('click')()};
}
function pendingFile(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {file:{size:80,text:()=>promise},resolve,reject};}
async function asyncTest(name,fn){await fn();passed++;console.log('PASS',name);}
for(const fence of ['input','logout','cancel','close'])await asyncTest('native validation late response cannot survive '+fence,async()=>{
 let finish;const pending=new Promise(resolve=>finish=resolve);
 const f=fixture(async(_path,options)=>JSON.parse(options.body).action==='preview'?{review:nativeReview,live_applied:false,result:preview}:pending);
 f.el('ext5MText').value=source;f.click('ext5MPreview');await new Promise(setImmediate);
 assert.equal(f.el('ext5MValidate').disabled,false);f.click('ext5MValidate');
 assert.equal(f.requests.length,2);assert.equal(JSON.parse(f.requests[1].options.body).confirm,'VALIDATE_MIHOMO_CONFIG');
 if(fence==='input'){f.el('ext5MText').value='new-profile';f.el('ext5MText').events.get('input')();}
 else if(fence==='logout'){f.workflowState.epoch++;f.documentEvents.get('razvilka:auth-required')();}
 else if(fence==='close')f.el('extensionLabDialog').close();else f.click('ext5Cancel');
 const before=f.el('ext5MResult').textContent;finish(nativeReply);await new Promise(setImmediate);
 assert.equal(f.el('ext5MResult').textContent,before);assert.doesNotMatch(f.el('ext5MResult').textContent,/Профиль принят/);assert.equal(f.requests[1].options.controller.signal.aborted,true);
});
for(const fence of ['service','input','logout','cancel','close'])await asyncTest('native service proof late response cannot survive '+fence,async()=>{
 let finish;const pending=new Promise(resolve=>finish=resolve);
 const f=fixture(async(_path,options)=>JSON.parse(options.body).action==='preview'?{review:nativeReview,live_applied:false,result:preview}:pending);
 f.el('ext5MText').value=source;f.click('ext5MPreview');await new Promise(setImmediate);
 f.el('ext5MService').value='service';f.click('ext5MProbe');assert.equal(f.requests.length,2);
 assert.equal(JSON.parse(f.requests[1].options.body).confirm,'PROBE_MIHOMO_SERVICE');
 if(fence==='service'){f.el('ext5MService').value='other';f.el('ext5MService').events.get('change')();}
 else if(fence==='input'){f.el('ext5MText').value='new-profile';f.el('ext5MText').events.get('input')();}
 else if(fence==='logout'){f.workflowState.epoch++;f.documentEvents.get('razvilka:auth-required')();}
 else if(fence==='close')f.el('extensionLabDialog').close();else f.click('ext5Cancel');
 const before=f.el('ext5MResult').textContent;finish(serviceReply);await new Promise(setImmediate);
 assert.equal(f.el('ext5MResult').textContent,before);assert.doesNotMatch(f.el('ext5MResult').textContent,/Сервис доступен/);
 assert.equal(f.requests[1].options.controller.signal.aborted,true);
});

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
