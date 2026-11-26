// Production callers and transport only; no HTTP/browser/native runtime proof.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const extract=name=>{const match=source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));assert(match,name);return match[0];};
const functions=['api','friendlyErrorMessage','panelReadContext','panelReadContextCurrent','invalidatePanelReads','readPanelResource','renderAuthBusy','showAuth','hideAuth','planWithRetainedNodeCheck','applyDraft','showPlan','renderStatus'].map(extract).join('\n');
const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};};
const flush=()=>new Promise(resolve=>setImmediate(resolve));
const preview=()=>({review:{expected_revision:12,reviewed_digest:'exact-reviewed-digest'},transaction:{ready:true,blockers:[],actions:[],routes:[]}});
const committed=()=>({ok:true,live_applied:true,execution:{state:'committed'},service_health:'unverified'});

function fixture(){
  let now=0,serial=0,handler=async(path,options)=>options.method==='POST'?committed():preview();
  let review=async()=>true,refresh=async()=>{};
  const elements=new Map(),calls=[],notices=[],timers=new Map(),auth=[];
  const document=Object.assign(new EventTarget(),{activeElement:null});
  const $=id=>{if(!elements.has(id))elements.set(id,Object.assign(new EventTarget(),{value:'visible dirty form',textContent:'Apply',innerHTML:'',disabled:false,hidden:true,open:false,returnValue:'',classList:{toggle(){},remove(){}},
    close(value=''){this.open=false;this.returnValue=value;this.dispatchEvent(new Event('close'));this.onClose?.();},showModal(){this.open=true;},
    contains(element){return element===this;},focus(){document.activeElement=this;},blur(){document.activeElement=null;},setAttribute(){},removeAttribute(){}}));return elements.get(id);};
  const state={authGeneration:0,authenticated:true,status:{revision:12,safe_mode:false,pending_changes:true},engineEditorDirty:true,currentView:'settings'};
  const c={state,$,$$:()=>[],document,Event,Headers,AbortController,Number,JSON,Object,Promise,Map,Set,encodeURIComponent,
    Date:class extends Date{static now(){return now;}},ADMIN_TOKEN_KEY:'unit',sessionStorage:{getItem:()=>null},panelReads:{epoch:0,entries:new Map()},
    setTimeout(fn,ms){timers.set(++serial,{fn,at:now+ms,ms});return serial;},clearTimeout(id){timers.delete(id);},
    fetch:async(path,options)=>{calls.push({path,options});const value=await handler(path,options);return {ok:true,json:async()=>value};},
    retainedNodeDependency:()=>null,checkRetainedNodeRoute:async()=>{},needsApplyReview:()=>true,reviewApplyPlan:value=>review(value),
    refreshCoreAfterEdit:()=>refresh(),refreshEngineConfigs:async()=>{},fallbackLabels:{},
    showNotice:(...args)=>notices.push(args),showRouteDependencyNotice:error=>notices.push(['error','dependency',error.message]),
    nodeActivityActive:()=>false,evidenceAtLeast:()=>false,evidenceLevelLabel:value=>value||'none',esc:String,
    formatUptime:()=>'',renderPendingServiceChanges(){},pendingChangeViews:()=>[],
  };
  document.addEventListener('razvilka:auth-required',event=>auth.push(event.type));
  vm.createContext(c);vm.runInContext(functions,c);
  return {c,state,$,calls,notices,timers,auth,handler(fn){handler=fn;},review(fn){review=fn;},refresh(fn){refresh=fn;},
    async advance(ms){now+=ms;for(const [id,timer] of [...timers])if(timer.at<=now){timers.delete(id);timer.fn();}await flush();}};
}
{
 const f=fixture();vm.runInContext(extract('reviewApplyPlan'),f.c);
 const pending=f.c.reviewApplyPlan({change_summary:{scope:'exclusions',network_change:true,working_change:true},transaction:{ready:true}});
 assert.match(f.$('#applyReviewTitle').textContent,/исключений ресурсов/);
 assert.match(f.$('#applyReviewContent').innerHTML,/Изменения сетевой конфигурации по плану/);
 assert.doesNotMatch(f.$('#applyReviewContent').innerHTML,/новых сетевых изменений/);
 f.$('#applyReviewDialog').close('');await pending;
}
{
 const f=fixture();const receipt={...committed(),note:'Dataplane activated, health-checked and committed.'};
 f.handler((_path,options)=>options.method==='POST'?receipt:preview());await f.c.applyDraft();
 const success=f.notices.find(item=>item[0]==='success');assert.ok(success);assert.equal(success[2],'Применение подтверждено. Доступ к сервисам проверяется отдельно.');assert.equal(success[3].note,receipt.note);
}
const posts=f=>f.calls.filter(call=>call.options.method==='POST');
const successful=f=>f.notices.filter(notice=>notice[0]==='success');
let passed=0;async function test(name,run){await run();passed++;console.log('PASS '+name);}

await test('ordinary and scoped plan preserve the eight-minute operation and one-minute closing grace',async()=>{
  for(const path of ['/api/v1/plan','/api/v1/plan?scope=services']){
    const f=fixture(),waiting=deferred();let signal;
    f.handler((_path,options)=>{signal=options.signal;signal.addEventListener('abort',()=>waiting.reject(Object.assign(new Error('abort'),{name:'AbortError'})),{once:true});return waiting.promise;});
    const pending=f.c.api(path),outcome=pending.catch(error=>error);await flush();
    assert.equal([...f.timers.values()][0].ms,550000);
    await f.advance(30000);assert.equal(signal.aborted,false);await f.advance(450000);assert.equal(signal.aborted,false);
    await f.advance(60000);assert.equal(signal.aborted,false);
    waiting.resolve(preview());assert.equal((await outcome).review.expected_revision,12);assert.equal(f.timers.size,0);
  }
});
await test('plan deadline is finite and other metadata retains its existing limits',async()=>{
  for(const [path,options,expected] of [['/api/v1/plan',{readTimeoutMs:9999999},550000],['/api/v1/status',{},20000],['/api/v1/components?refresh=true',{readTimeoutMs:9999999},110000]]){
    const f=fixture(),waiting=deferred();let signal;
    f.handler((_path,options)=>{signal=options.signal;signal.addEventListener('abort',()=>waiting.reject(Object.assign(new Error('abort'),{name:'AbortError'})),{once:true});return waiting.promise;});
    const outcome=f.c.api(path,options).catch(error=>error);await flush();assert.equal([...f.timers.values()][0].ms,expected);
    await f.advance(expected);assert.equal((await outcome).code,'READ_TIMEOUT');assert.equal(signal.aborted,true);assert.equal(f.calls.length,1);assert.equal(f.timers.size,0);
  }
});
await test('POST Apply has no short read timer and stays pending through the server budget',async()=>{
  const f=fixture(),waiting=deferred();f.handler((_path,options)=>options.method==='POST'?waiting.promise:preview());
  const pending=f.c.applyDraft();await flush();assert.equal(posts(f).length,1);assert.equal(f.timers.size,0);
  await f.advance(540000);assert.equal(f.state.applyRequest.phase,'apply');assert.equal(successful(f).length,0);assert.equal(posts(f).length,1);
  f.c.renderStatus();assert.equal(f.$('#applySettings').disabled,true);assert.equal(f.$('#applySettings').textContent,'Применение…');
  waiting.resolve(committed());await pending;assert.equal(successful(f).length,1);assert.equal(f.state.applyRequest,null);assert.equal(f.$('#applySettings').disabled,false);
  assert.match(successful(f)[0][2],/Доступ к сервисам проверяется отдельно/);
});
await test('second Apply in any scope cannot create a second plan or mutation while pending',async()=>{
  for(const phase of ['plan','review','apply']){
    const f=fixture(),waiting=deferred();
    f.handler((_path,options)=>phase==='plan'&&options.method==='GET'&&!posts(f).length?waiting.promise:phase==='apply'&&options.method==='POST'?waiting.promise:options.method==='POST'?committed():preview());
    if(phase==='review')f.review(()=>waiting.promise);
    const pending=f.c.applyDraft();await flush();const count=f.calls.length;
    assert.equal(await f.c.applyDraft('services'),null);assert.equal(f.calls.length,count);
    waiting.resolve(phase==='review'?true:phase==='apply'?committed():preview());await pending;assert.equal(posts(f).length,1);assert.equal(f.state.applyRequest,null);
  }
});
await test('review keeps its exact revision and digest even if observed status changes',async()=>{
  const f=fixture();f.review(async()=>{f.state.status.revision=13;return true;});await f.c.applyDraft();
  assert.deepEqual(JSON.parse(posts(f)[0].options.body),preview().review);assert.equal(posts(f).length,1);
});
await test('accepted and pending responses never become a successful Apply or clear a dirty form',async()=>{
  for(const response of [{ok:true},{ok:true,persistent:true,job:{state:'queued'}},{pending_changes:true},{scope_pending_changes:true}]){
    const f=fixture();f.handler((_path,options)=>options.method==='POST'?response:preview());await f.c.applyDraft();
    assert.equal(successful(f).length,0);assert.equal(f.notices.at(-1)[0],'review');assert.equal(f.state.engineEditorDirty,true);assert.equal(f.$('#engineEditor').value,'visible dirty form');assert.equal(posts(f).length,1);
  }
});
await test('safe-mode reviewed receipt remains separate from live application',async()=>{
  const f=fixture();f.handler((_path,options)=>options.method==='POST'?{safe_mode:true,reviewed:true,live_applied:false}:preview());await f.c.applyDraft();
  assert.equal(successful(f).length,0);assert.match(f.notices.at(-1)[1],/План проверен/);assert.equal(f.notices.at(-1)[0],'review');
});
await test('late plan review or Apply response from a former auth generation cannot publish or continue',async()=>{
  for(const phase of ['plan','review','apply']){
    const f=fixture(),waiting=deferred();f.handler((_path,options)=>phase==='plan'&&options.method==='GET'?waiting.promise:phase==='apply'&&options.method==='POST'?waiting.promise:options.method==='POST'?committed():preview());
    if(phase==='review')f.review(()=>waiting.promise);
    const pending=f.c.applyDraft();await flush();f.state.authGeneration++;
    waiting.resolve(phase==='review'?true:phase==='apply'?committed():preview());await pending;
    assert.equal(posts(f).length,phase==='apply'?1:0);assert.equal(successful(f).length,0);assert.equal(f.notices.length,0);assert.equal(f.state.applyRequest,null);assert.equal(f.$('#applySettings').disabled,false);assert.equal(f.state.engineEditorDirty,true);
  }
});
await test('new auth releases old pending Plan or POST ownership and late old finally cannot enable new controls',async()=>{
  for(const phase of ['plan','review','apply','readback']){
    const f=fixture(),oldResponse=deferred(),newPlan=deferred();
    f.handler((_path,options)=>phase==='plan'&&options.method==='GET'?oldResponse.promise:phase==='apply'&&options.method==='POST'?oldResponse.promise:options.method==='POST'?committed():preview());
    if(phase==='review')f.review(()=>{f.$('#applyReviewDialog').open=true;return oldResponse.promise;});
    if(phase==='readback')f.refresh(()=>oldResponse.promise);
    const oldPending=f.c.applyDraft();await flush();const oldOwner=f.state.applyRequest,oldCalls=f.calls.length;
    const oldSignal=f.calls.find(call=>call.options.method===(phase==='apply'?'POST':'GET')).options.signal;
    f.c.showAuth(f.state.status,'session closed');
    assert.equal(f.state.applyRequest,null,'old pending Apply still owns the UI after actual showAuth');
    if(phase==='plan'||phase==='apply')assert.equal(oldSignal.aborted,true);
    assert.equal(f.$('#applySettings').disabled,false);assert.equal(successful(f).length,0);
    f.c.hideAuth();f.review(async()=>true);f.refresh(async()=>{});f.handler((_path,options)=>options.method==='POST'?{ok:true}:newPlan.promise);
    const newPending=f.c.applyDraft();await flush();const newOwner=f.state.applyRequest;
    assert.ok(newOwner);assert.notEqual(newOwner,oldOwner);assert.equal(f.calls.length,oldCalls+1);assert.equal(f.calls.at(-1).options.method,'GET');
    assert.equal(posts(f).length,phase==='plan'||phase==='review'?0:1,'auth restoration replayed an unknown POST');
    oldResponse.resolve(phase==='plan'?preview():phase==='review'?true:phase==='apply'?committed():undefined);await oldPending;
    assert.equal(f.state.applyRequest,newOwner);assert.equal(f.$('#applySettings').disabled,true);assert.equal(f.$('#applySettings').textContent,'Проверка…');
    assert.equal(f.calls.at(-1).options.signal.aborted,false);assert.equal(successful(f).length,0);assert.equal(f.state.engineEditorDirty,true);
    const fresh={...preview(),review:{expected_revision:13,reviewed_digest:'new-session-reviewed-digest'}};
    newPlan.resolve(fresh);await newPending;
    assert.deepEqual(JSON.parse(posts(f).at(-1).options.body),fresh.review);assert.equal(posts(f).length,phase==='plan'||phase==='review'?1:2);
    assert.equal(successful(f).length,0);assert.equal(f.state.applyRequest,null);
  }
});
await test('actual auth lifecycle closes an old Apply review without approving or closing the next review',async()=>{
  const f=fixture(),caller=new AbortController();vm.runInContext(extract('reviewApplyPlan'),f.c);
  const oldPending=f.c.applyDraft('all','',{signal:caller.signal});await flush();assert.equal(f.$('#applyReviewDialog').open,true);
  f.c.showAuth(f.state.status,'session closed');assert.equal(f.$('#applyReviewDialog').open,false);assert.equal(f.state.applyRequest,null);
  f.c.hideAuth();const newPending=f.c.applyDraft();await flush();const newOwner=f.state.applyRequest;
  assert.ok(newOwner);assert.equal(f.$('#applyReviewDialog').open,true);assert.equal(posts(f).length,0);
  await oldPending;caller.abort();await flush();assert.equal(f.$('#applyReviewDialog').open,true);assert.equal(f.state.applyRequest,newOwner);assert.equal(f.$('#applySettings').disabled,true);
  f.$('#applyReviewDialog').close('');await newPending;assert.equal(posts(f).length,0);assert.equal(successful(f).length,0);
});
await test('caller cancellation closes pending review and sends no Apply',async()=>{
  const f=fixture(),waiting=deferred(),controller=new AbortController();
  f.review(()=>{f.$('#applyReviewDialog').open=true;f.$('#applyReviewDialog').onClose=()=>waiting.resolve(false);return waiting.promise;});
  const pending=f.c.applyDraft('all','',{signal:controller.signal});await flush();controller.abort();await pending;
  assert.equal(f.$('#applyReviewDialog').open,false);assert.equal(posts(f).length,0);assert.equal(successful(f).length,0);assert.equal(f.state.applyRequest,null);
});
await test('caller cancellation during POST retains unknown outcome and never grants late success',async()=>{
  const f=fixture(),waiting=deferred(),controller=new AbortController();f.handler((_path,options)=>options.method==='POST'?waiting.promise:preview());
  const pending=f.c.applyDraft('all','',{signal:controller.signal});await flush();controller.abort();waiting.resolve(committed());await pending;
  assert.equal(posts(f).length,1);assert.equal(successful(f).length,0);assert.equal(f.state.applyRequest,null);assert.equal(f.state.engineEditorDirty,true);assert.equal(f.$('#engineEditor').value,'visible dirty form');
});
await test('POST network loss and actual changed-review refusal remain unconfirmed without replay',async()=>{
  for(const error of [new TypeError('connection lost'),Object.assign(new Error('Проверьте журнал и откройте новый план.'),{status:409,payload:{code:'APPLY_REVIEW_CHANGED'}})]){
    const f=fixture();f.handler((_path,options)=>{if(options.method==='POST')throw error;return preview();});await f.c.applyDraft();
    assert.equal(posts(f).length,1);assert.equal(successful(f).length,0);assert.equal(f.notices.at(-1)[0],'review');assert.match(f.notices.at(-1)[1],/не подтверждён/);
    assert.equal(f.state.engineEditorDirty,true);assert.equal(f.$('#engineEditor').value,'visible dirty form');assert.equal(f.state.applyRequest,null);
  }
});
await test('failed readback after POST does not assert that the mutation was blocked',async()=>{
  const f=fixture();f.refresh(async()=>{throw new Error('status unavailable');});await f.c.applyDraft();
  assert.equal(posts(f).length,1);assert.equal(successful(f).length,0);assert.equal(f.notices.at(-1)[1],'Состояние после применения не прочитано');assert.equal(f.notices.at(-1)[0],'review');assert.equal(f.state.engineEditorDirty,true);
});
await test('server failure advice is retained and an initial plan failure is not automatically replayed',async()=>{
  const f=fixture(),failure={title:'Проверка отклонена',message:'Причина сервера',resolution:'Проверьте журнал'};
  f.handler((_path,options)=>{if(options.method==='POST')throw Object.assign(new Error('failure'),{payload:{failure}});return preview();});await f.c.applyDraft();
  assert.equal(f.notices.at(-1)[0],'error');assert.equal(f.notices.at(-1)[1],failure.title);assert.match(f.notices.at(-1)[2],/Причина сервера/);assert.equal(posts(f).length,1);
  const before=fixture();before.handler(()=>{throw new Error('plan unavailable');});await before.c.applyDraft();assert.equal(before.calls.length,1);assert.equal(posts(before).length,0);assert.equal(before.state.applyRequest,null);
});
await test('passive plan joins only pending reads and every later view performs a fresh GET',async()=>{
  const f=fixture(),waiting=deferred();f.handler(()=>waiting.promise);
  const first=f.c.showPlan(),second=f.c.showPlan();await flush();assert.equal(f.calls.length,1);assert.match(f.$('#planBox').innerHTML,/Проверяем план/);
  waiting.resolve(preview());await Promise.all([first,second]);assert.equal(f.timers.size,0);
  await f.c.showPlan();assert.equal(f.calls.length,2);assert.equal(f.c.panelReads.entries.size,0);
});
await test('auth revocation aborts passive plan and ignores an old JSON response without restoring private data',async()=>{
  const f=fixture(),waiting=deferred();f.handler(()=>waiting.promise);const pending=f.c.showPlan();await flush();const signal=f.calls[0].options.signal;
  f.state.authGeneration++;f.c.invalidatePanelReads();assert.equal(signal.aborted,true);waiting.resolve({...preview(),note:'PRIVATE OLD PLAN'});await pending;
  assert.doesNotMatch(f.$('#planBox').innerHTML,/PRIVATE OLD PLAN|ГОТОВО К ПРИМЕНЕНИЮ/);assert.equal(f.c.panelReads.entries.size,0);assert.equal(f.timers.size,0);
});
await test('ordinary plan and Apply 401 use the existing auth flow without continuing or claiming a result',async()=>{
  for(const phase of ['plan','apply','passive']){
    const f=fixture();f.handler((_path,options)=>{if(phase!=='apply'||options.method==='POST')throw Object.assign(new Error('login required'),{status:401});return preview();});
    if(phase==='passive')await f.c.showPlan();else await f.c.applyDraft();
    assert.deepEqual(f.auth,['razvilka:auth-required']);assert.equal(f.$('#authMessage').textContent,'login required');assert.equal(successful(f).length,0);assert.equal(posts(f).length,phase==='apply'?1:0);assert.equal(f.state.authenticated,false);assert.equal(f.state.applyRequest??null,null);
  }
});
console.log(JSON.stringify({suite:'ordinary-apply-ui',mode:'production-functions-no-runtime',passed}));
