import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../cmd/razvilka/web/component-recovery-ui.js',import.meta.url),'utf8');
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};}
function snapshot(phase='awaiting-live-acceptance',pending=true){return {revision:7,recovery_required:pending,transaction:{schema_version:1,transaction_id:'a'.repeat(32),component:'xray',phase,before_version:'1.0',after_version:'2.0',updated_at:new Date().toISOString()},capabilities:{supported_actions:['accept-live','accept-installed-idle','rollback','verify-rollback','abandon-prepared'],available_actions:pending?['accept-live','rollback','verify-rollback','abandon-prepared']:[],quiescence_confirmed:false,inactivity_confirmed:false,installed_idle_accepted:phase==='accepted-installed-idle',live_proof_required:true}};}
const pure={};vm.createContext(pure);vm.runInContext(source,pure);const model=pure.RazvilkaComponentRecovery;
function fixture(view='engines'){
  const requests=[],listeners=new Map(),notices=[],panel={innerHTML:'',contains:()=>false};
  const state={authenticated:true,currentView:view,status:{safe_mode:false,revision:7},serviceControl:{stopped:false}};
  let confirm=async()=>true,authCalls=0;
  let now=Date.now();class Clock extends Date{static now(){return now;}}
  const ctx={state,Date:Clock,AbortController,Promise,esc:value=>String(value??'').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),
    document:{hidden:false,activeElement:null,querySelectorAll:()=>[panel],addEventListener(name,fn){listeners.set(name,fn);}},
    api(path,options={}){const pending=deferred();requests.push({path,options,...pending});return pending.promise;},
    askConfirmation:(...args)=>confirm(...args),showNotice:(...args)=>notices.push(args),routeLabel:id=>id,
    renderInterfaceEngines(){},renderComponents(){},
    showAuth(){authCalls++;state.authenticated=false;listeners.get('razvilka:auth-required')();}
  };
  vm.createContext(ctx);vm.runInContext(source,ctx);
  const click=(selector,action='accept-live')=>listeners.get('click')({target:{closest:value=>value===selector?{disabled:false,dataset:{componentRepair:selector==='[data-component-repair]'?action:undefined}}:null}});
  return {ctx,state,requests,notices,panel,authCalls:()=>authCalls,
    advance:milliseconds=>{now+=milliseconds;},
    confirm:fn=>{confirm=fn;},clickRead:()=>click('[data-component-recovery-read]'),clickRepair:action=>click('[data-component-repair]',action),
    revoke(){listeners.get('razvilka:auth-required')();state.authenticated=false;},
    view(name){listeners.get('razvilka:view-change')({detail:name});state.currentView=name;},
    async ready(value=snapshot()){await flush();assert.equal(requests[0].path,'/api/v1/components/recovery');requests[0].resolve(value);await flush();},
  };
}
let total=0;async function test(name,fn){await fn();total++;console.log('PASS '+name);}
await test('no positive acceptance from phase, candidate or historical receipt',()=>{
  for(const phase of ['awaiting-live-acceptance','upgrade-finished','upgrade-started','rollback-started'])assert.equal(model.summary(snapshot(phase)).tone,'unknown');
  const accepted=snapshot('accepted',false);assert.equal(model.summary(accepted).tone,'unknown');
  assert.equal(model.summary(accepted,{transaction_id:'b'.repeat(32),component:'xray',live_accepted:true}).tone,'unknown');
  assert.equal(model.summary(accepted,{transaction_id:'a'.repeat(32),component:'xray',live_accepted:true}).tone,'good');
  assert.equal(model.summary(accepted,{transaction_id:'a'.repeat(32),component:'xray',installed_idle_accepted:true}).tone,'unknown');
});
await test('historical unknown offers no force, replay or operator boolean',()=>{
  for(const phase of ['upgrade-started','rollback-started'])assert.equal(model.summary(snapshot(phase)).actions.length,0);
  assert.deepEqual(Array.from(model.summary(snapshot('awaiting-rollback-acceptance')).actions),['verify-rollback']);
});
await test('invalid, future, corrupt and inconsistent data fail closed',()=>{
  for(const value of [{},{...snapshot(),revision:-1},{...snapshot(),recovery_required:false},snapshot('future-phase'),{...snapshot(),transaction:{...snapshot().transaction,component:'unknown'}}]) {
    assert.equal(model.valid(value),false);assert.equal(model.summary(value).actions.length,0);
  }
});
await test('only schema 1/2 are known; schema 2 idle acceptance stays neutral',()=>{
  for(const schema of [1,2]){const value=snapshot();value.transaction.schema_version=schema;assert.equal(model.valid(value),true);}
  for(const schema of [0,3,999,'2']){const value=snapshot();value.transaction.schema_version=schema;assert.equal(model.valid(value),false);}
  const idle=snapshot('accepted-installed-idle',false);assert.equal(model.valid(idle),false);
  idle.transaction.schema_version=2;assert.equal(model.valid(idle),true);
  const receipt={transaction_id:idle.transaction.transaction_id,component:'xray',installed_idle_accepted:true,live_accepted:true};
  const observed=model.summary(idle,receipt);assert.equal(observed.tone,'unknown');assert.equal(observed.actions.length,0);
  assert.match(observed.detail,/доступ сервисов ещё не подтверждены/);
  const pending=snapshot();pending.transaction.schema_version=2;
  assert(!Array.from(model.summary(pending).actions).includes('accept-installed-idle'),'idle action guessed before HTTP capabilities');
});
await test('server capabilities restrict actions; idle needs schema 2 and both trusted observations',()=>{
  const value=snapshot();delete value.capabilities;assert.equal(model.summary(value).actions.length,0);
  const idle=snapshot();idle.transaction.schema_version=2;idle.capabilities.available_actions=['accept-installed-idle'];
  assert.equal(model.summary(idle).actions.length,0);idle.capabilities.quiescence_confirmed=true;assert.equal(model.summary(idle).actions.length,0);
  idle.capabilities.inactivity_confirmed=true;assert.deepEqual(Array.from(model.summary(idle).actions),['accept-installed-idle']);
  idle.capabilities.available_actions=[];assert.equal(model.summary(idle).actions.length,0);
  idle.capabilities.available_actions=['future-action'];assert.equal(model.valid(idle),false);
});
await test('matching idle POST and separate idle GET settle with a neutral label',async()=>{
  const before=snapshot();before.transaction.schema_version=2;before.capabilities.quiescence_confirmed=before.capabilities.inactivity_confirmed=true;
  before.capabilities.available_actions=['accept-installed-idle'];const f=fixture();await f.ready(before);f.clickRepair('accept-installed-idle');await flush();
  assert.equal(JSON.parse(f.requests[1].options.body).action,'accept-installed-idle');
  assert.equal(Object.keys(JSON.parse(f.requests[1].options.body)).length,5,'operator flags were added');
  f.requests[1].resolve({recovery_required:false,installed_idle_accepted:true,live_accepted:false});await flush();
  const settled=snapshot('accepted-installed-idle',false);settled.transaction.schema_version=2;f.requests[2].resolve(settled);await flush();
  assert.equal(f.ctx.componentRecoveryFence(),false);assert.equal(f.ctx.componentRecoverySummary('xray').tone,'unknown');
  assert.match(f.notices.at(-1)[1],/Неактивная версия/);
});
await test('idle result missing its exact acceptance fields cannot settle or replay',async()=>{
  const before=snapshot();before.transaction.schema_version=2;before.capabilities.quiescence_confirmed=before.capabilities.inactivity_confirmed=true;
  before.capabilities.available_actions=['accept-installed-idle'];const f=fixture();await f.ready(before);f.clickRepair('accept-installed-idle');await flush();
  f.requests[1].resolve({recovery_required:false,live_accepted:true});await flush();f.clickRepair('accept-installed-idle');await flush();
  assert.equal(f.requests.length,2);assert.equal(f.ctx.componentRecoveryFence(),true);assert.equal(f.notices.length,0);
});
await test('Home/login do not read recovery; navigation issues only single GET',async()=>{
  const f=fixture('overview');await flush();assert.equal(f.requests.length,0);
  f.state.authenticated=false;f.view('engines');await flush();assert.equal(f.requests.length,0);
  f.state.authenticated=true;f.view('engines');await flush();f.clickRead();f.clickRead();await flush();
  assert.equal(f.requests.length,1);assert.equal(f.requests[0].options.method,undefined);
  f.requests[0].resolve(snapshot());await flush();assert.equal(f.requests.filter(r=>r.options.method==='POST').length,0);
});
await test('POST has matching transaction and CAS, then independent journal read',async()=>{
  const f=fixture();await f.ready();f.clickRepair();f.clickRepair();await flush();
  assert.equal(f.requests.length,2);const request=f.requests[1];assert.equal(request.options.method,'POST');
  assert.deepEqual(JSON.parse(request.options.body),{transaction_id:'a'.repeat(32),component:'xray',action:'accept-live',expected_revision:7,confirm:'REPAIR_COMPONENT_TRANSACTION'});
  request.resolve({recovery_required:false,live_accepted:true});await flush();
  assert.equal(f.requests[2].options.method,undefined);assert.equal(f.ctx.componentRecoveryFence(),true);
  f.requests[2].resolve(snapshot('accepted',false));await flush();assert.equal(f.ctx.componentRecoveryFence(),false);
  assert.equal(f.ctx.componentRecoverySummary('xray').tone,'good');assert.equal(f.notices[0][0],'review');
});
await test('500/409 unknown writes require explicit read and never replay',async()=>{
  for(const status of [409,500]){
    const f=fixture();await f.ready();f.clickRepair();await flush();
    f.requests[1].reject(Object.assign(new Error('unconfirmed repair'),{status}));await flush();
    f.clickRepair();await flush();assert.equal(f.requests.length,2);assert.equal(f.ctx.componentRecoveryFence(),true);
    assert.match(f.panel.innerHTML,/unconfirmed repair/);
    f.clickRead();await flush();f.requests[2].resolve(snapshot('rollback-started'));await flush();
    assert.equal(f.requests.filter(r=>r.options.method==='POST').length,1);assert.doesNotMatch(f.panel.innerHTML,/data-component-repair=/);
  }
});
await test('202-shaped pending response never shows settled or live acceptance',async()=>{
  const f=fixture();await f.ready();f.clickRepair();await flush();
  f.requests[1].resolve({ok:true,recovery_required:true,pending_live_acceptance:true,live_accepted:true});await flush();
  assert.equal(f.ctx.componentRecoveryFence(),true);assert.equal(f.notices.length,0);
  assert.equal(f.requests.length,2,'pending response silently issued another action or read');
});
await test('confirmation or cancellation cannot retain obsolete CAS authority',async()=>{
  const f=fixture();await f.ready();const confirmation=deferred();f.confirm(()=>confirmation.promise);f.clickRepair();await flush();
  f.state.status.revision=8;confirmation.resolve(true);await flush();assert.equal(f.requests.length,1);assert.equal(f.ctx.componentRecoveryFence(),true);
});
await test('Safe Mode and Stop block repair without disabling GET',async()=>{
  for(const flag of ['safe_mode','stopped']){
    const f=fixture();await f.ready();if(flag==='safe_mode')f.state.status.safe_mode=true;else f.state.serviceControl.stopped=true;
    f.clickRepair();await flush();assert.equal(f.requests.length,1);
    f.clickRead();await flush();assert.equal(f.requests.length,2);f.requests[1].resolve(snapshot());await flush();
  }
});
await test('late POST/read/error cannot revive data after logout',async()=>{
  for(const pendingKind of ['read','post']){
    const f=fixture();await f.ready();if(pendingKind==='read')f.clickRead();else f.clickRepair();await flush();
    const old=f.requests[1];f.revoke();old.resolve(pendingKind==='read'?snapshot('accepted',false):{recovery_required:false,live_accepted:true});await flush();
    assert.equal(f.ctx.componentRecoverySummary('xray'),null);assert.equal(f.notices.length,0);assert.equal(f.authCalls(),0);
  }
  const f=fixture();await flush();f.revoke();f.requests[0].reject(Object.assign(new Error('old session'),{status:401}));await flush();assert.equal(f.authCalls(),0);
});
await test('current 401 closes the session; 503 keeps journal visible and fenced',async()=>{
  const f=fixture();await flush();f.requests[0].reject(Object.assign(new Error('journal not readable'),{status:503}));await flush();
  assert.match(f.panel.innerHTML,/journal not readable/);assert.equal(f.ctx.componentRecoveryFence(),true);
  f.clickRead();await flush();f.requests[1].reject(Object.assign(new Error('expired session'),{status:401}));await flush();assert.equal(f.authCalls(),1);
});
await test('stale enabled action gives a visible readback and never posts',async()=>{
  const f=fixture();await f.ready();assert.match(f.panel.innerHTML,/data-component-repair="accept-live"/);
  f.advance(60001);f.clickRepair();await flush();
  assert.equal(f.requests.length,2);assert.equal(f.requests[1].options.method,undefined);
  assert.match(f.panel.innerHTML,/Сведения устарели/);
  f.requests[1].resolve(snapshot());await flush();
  assert.equal(f.requests.filter(request=>request.options.method==='POST').length,0);
  assert.match(f.notices.at(-1)[1],/Журнал обновлён/);
});
await test('leaving a pending action releases the ticket and allows explicit readback',async()=>{
  const f=fixture();await f.ready();f.clickRepair();await flush();const old=f.requests[1];
  f.view('overview');f.view('engines');await flush();f.clickRead();await flush();
  assert.equal(f.requests.length,3,'obsolete action blocked independent readback');
  assert.equal(f.requests[2].options.method,undefined);
  f.requests[2].resolve(snapshot('rollback-started'));await flush();
  old.resolve({recovery_required:false,live_accepted:true});await flush();
  assert.equal(f.ctx.componentRecoverySummary('xray').tone,'unknown');
  assert.doesNotMatch(f.panel.innerHTML,/data-component-repair=/);assert.equal(f.notices.length,0);
});
await test('leaving while review is pending cancels POST and releases buttons',async()=>{
  const f=fixture();await f.ready();const confirmation=deferred();f.confirm(()=>confirmation.promise);f.clickRepair();await flush();
  f.view('overview');f.view('engines');await flush();confirmation.resolve(true);await flush();
  assert.equal(f.requests.filter(request=>request.options.method==='POST').length,0);
  f.clickRead();await flush();assert.equal(f.requests.length,2);
});
console.log(JSON.stringify({suite:'component-recovery',tests:total}));
