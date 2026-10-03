import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../cmd/razvilka/web/component-recovery-ui.js',import.meta.url),'utf8');
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};}
function snapshot(phase='awaiting-live-acceptance',pending=true){return {revision:7,recovery_required:pending,transaction:{schema_version:1,transaction_id:'a'.repeat(32),component:'xray',phase,before_version:'1.0',after_version:'2.0',updated_at:new Date().toISOString()}};}
const pure={};vm.createContext(pure);vm.runInContext(source,pure);const model=pure.RazvilkaComponentRecovery;
function fixture(view='engines'){
  const requests=[],listeners=new Map(),notices=[],panel={innerHTML:'',contains:()=>false};
  const state={authenticated:true,currentView:view,status:{safe_mode:false,revision:7},serviceControl:{stopped:false}};
  let confirm=async()=>true,authCalls=0;
  const ctx={state,Date,AbortController,Promise,esc:value=>String(value??'').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),
    document:{hidden:false,activeElement:null,querySelectorAll:()=>[panel],addEventListener(name,fn){listeners.set(name,fn);}},
    api(path,options={}){const pending=deferred();requests.push({path,options,...pending});return pending.promise;},
    askConfirmation:(...args)=>confirm(...args),showNotice:(...args)=>notices.push(args),routeLabel:id=>id,
    renderInterfaceEngines(){},renderComponents(){},
    showAuth(){authCalls++;state.authenticated=false;listeners.get('razvilka:auth-required')();}
  };
  vm.createContext(ctx);vm.runInContext(source,ctx);
  const click=selector=>listeners.get('click')({target:{closest:value=>value===selector?{disabled:false,dataset:{componentRepair:selector==='[data-component-repair]'?'accept-live':undefined}}:null}});
  return {ctx,state,requests,notices,panel,authCalls:()=>authCalls,
    confirm:fn=>{confirm=fn;},clickRead:()=>click('[data-component-recovery-read]'),clickRepair:()=>click('[data-component-repair]'),
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
console.log(JSON.stringify({suite:'component-recovery',tests:total}));
