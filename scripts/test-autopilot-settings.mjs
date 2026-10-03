import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const src=fs.readFileSync(new URL('../cmd/razvilka/web/autopilot-settings.js',import.meta.url),'utf8');
const c={};vm.createContext(c);vm.runInContext(src,c);const model=c.RazvilkaQuickPolicy;
const policy={schema:1,revision:12,setup_complete:true,enabled:true,check_seconds:300,reserve_seconds:1800,reserve_target:3,candidates_per_round:2,source_ids:['private-source'],protocols:['vless'],preferred_routes:['xray'],default_sources:['192.168.1.20'],all_lan:false,application:{mode:'prepare'},components:{mode:'check'}};
const inputs={check_seconds:'120',reserve_seconds:'1200',reserve_target:'4',candidates_per_round:'1'};
let total=0;function test(n,f){f();total++;console.log('PASS '+n);}
async function asyncTest(n,f){await f();total++;console.log('PASS '+n);}

function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};}
function fixture(){
  const elements=new Map(),listeners=new Map(),documentListeners=new Map(),requests=[];
  const element=id=>{
    if(!elements.has(id))elements.set(id,{value:'',textContent:'',disabled:false,events:{},addEventListener(name,fn){this.events[name]=fn;}});
    return elements.get(id);
  };
  const context={Date,Number,JSON,console,CustomEvent:class{constructor(type){this.type=type;}},
    document:{getElementById:element,addEventListener:(name,fn)=>documentListeners.set(name,fn),dispatchEvent(){}},
    addEventListener:(name,fn)=>listeners.set(name,fn),
    interfaceRequest(path,options={}){const pending=deferred();requests.push({path,options,...pending});return pending.promise;}
  };
  vm.createContext(context);vm.runInContext(src,context);
  return {element,requests,
    snapshot:(revision=policy.revision)=>({policy:{...policy,revision},server_time:new Date().toISOString()}),
    publish:next=>listeners.get('razvilka:autonomy-state')({detail:next}),
    edit(){element('autoQuickCheck').value='180';element('autoQuickForm').events.input();},
    submit:()=>element('autoQuickForm').events.submit({preventDefault(){}}),
    reload:()=>element('a1-reloadButton').events.click(),
    logout:()=>documentListeners.get('razvilka:auth-required')(),
    leave(){const event={prevented:false,preventDefault(){this.prevented=true;}};listeners.get('beforeunload')?.(event);return event;}
  };
}
test('ordinary edit preserves every authority-bearing and unknown future field',()=>{const next=model.draft(policy,inputs);for(const key of Object.keys(policy))if(!(key in inputs))assert.equal(JSON.stringify(next[key]),JSON.stringify(policy[key]),key);assert.equal(policy.check_seconds,300);assert.equal(next.check_seconds,120);});
test('range and type constraints match server policy',()=>{for(const [k,v] of [['check_seconds','59'],['check_seconds','3601'],['reserve_seconds','119'],['reserve_seconds','86401'],['reserve_target','5'],['candidates_per_round','0'],['check_seconds','1e3'],['check_seconds',''],['check_seconds','Infinity'],['check_seconds',null]])assert.throws(()=>model.draft(policy,{...inputs,[k]:v}));});
test('first setup is not silently enabled by interval form',()=>assert.throws(()=>model.draft({...policy,setup_complete:false},inputs)));
test('stale or fenced snapshot cannot enable save',()=>{const now=Date.now(),snapshot={policy,server_time:new Date(now).toISOString()};assert(model.current(snapshot,now,now));assert(!model.current(snapshot,now,now+60000));assert(!model.current(snapshot,now,now-1));assert(!model.current({...snapshot,blocked:true},now,now));assert(!model.current({...snapshot,observation:{state:'retained'}},now,now));});
test('navigation and normal polling never submit writes',()=>{const requests=[],listeners={},elements=new Map();const el=id=>{if(!elements.has(id))elements.set(id,{value:'',events:{},addEventListener(n,f){this.events[n]=f;}});return elements.get(id);};const context={Date,Number,JSON,console,CustomEvent:class{},document:{getElementById:el,addEventListener(){}},addEventListener:(n,f)=>listeners[n]=f,interfaceRequest:(...args)=>{requests.push(args);return Promise.resolve({});}};vm.createContext(context);vm.runInContext(src,context);listeners['razvilka:autonomy-state']({detail:{policy,server_time:new Date().toISOString()}});assert.equal(requests.length,0);assert.equal(elements.get('autoQuickCheck').value,300);});
test('unsaved fields survive newer published revision and save is fenced',()=>{const listeners={},elements=new Map();const el=id=>{if(!elements.has(id))elements.set(id,{value:'',events:{},addEventListener(n,f){this.events[n]=f;}});return elements.get(id);};const context={Date,Number,JSON,console,CustomEvent:class{},document:{getElementById:el,addEventListener(){}},addEventListener:(n,f)=>listeners[n]=f};vm.createContext(context);vm.runInContext(src,context);const time=new Date().toISOString();listeners['razvilka:autonomy-state']({detail:{policy,server_time:time}});el('autoQuickCheck').value='180';el('autoQuickForm').events.input();listeners['razvilka:autonomy-state']({detail:{policy:{...policy,revision:13},server_time:time}});assert.equal(el('autoQuickCheck').value,'180');assert.equal(el('autoQuickSave').disabled,true);});
for(const kind of ['missing-policy','invalid-time','older-snapshot','retained','blocked'])await asyncTest('unknown write remains fenced after unusable readback: '+kind,async()=>{
  const f=fixture(),initial=f.snapshot();f.publish(initial);f.edit();
  const save=f.submit();f.requests[0].reject(new Error('connection lost'));await save;
  assert.equal(f.element('autoQuickSave').disabled,true);
  const reload=f.reload();let response=f.snapshot();
  if(kind==='missing-policy')response={};
  if(kind==='invalid-time')response.server_time='invalid';
  if(kind==='older-snapshot')response.server_time='2000-01-01T00:00:00Z';
  if(kind==='retained')response.observation={state:'retained'};
  if(kind==='blocked')response.blocked=true;
  f.requests[1].resolve(response);await reload;
  // A later passive poll cannot substitute for the rejected independent read.
  f.publish(initial);
  assert.equal(f.element('autoQuickCheck').value,'180');
  assert.equal(f.element('autoQuickSave').disabled,true,'unusable readback released the write fence');
  await f.submit();assert.equal(f.requests.filter(r=>r.options.method==='PUT').length,1,'unknown write was resubmitted');
  const retry=f.reload();f.requests.at(-1).resolve(f.snapshot());await retry;
  assert.equal(f.element('autoQuickSave').disabled,false,'valid independent read did not restore editing');
  assert.equal(f.element('autoQuickCheck').value,'180');
});

await asyncTest('late failed PUT cannot fence a new authenticated form',async()=>{
  const f=fixture();f.publish(f.snapshot());f.edit();const save=f.submit();
  f.logout();f.publish(f.snapshot(13));f.edit();
  f.requests[0].reject(new Error('old session aborted'));await save;
  f.edit();assert.equal(f.element('autoQuickSave').disabled,false);
  assert.equal(f.element('autoQuickCheck').value,'180');
  assert.equal(f.requests.length,1);
});

await asyncTest('unknown write reconciliation coalesces repeated clicks and retains draft',async()=>{
  const f=fixture();f.publish(f.snapshot());f.edit();const save=f.submit();
  f.requests[0].reject(Object.assign(new Error('server error'),{status:500}));await save;
  const reload=f.reload();await f.reload();assert.equal(f.requests.length,2);
  f.requests[1].resolve(f.snapshot(13));await reload;
  assert.equal(f.element('autoQuickCheck').value,'180');
  assert.equal(f.element('autoQuickSave').disabled,true,'new revision must require explicit draft reset');
  f.element('autoQuickReset').events.click();assert.equal(f.element('autoQuickSave').disabled,false);
  assert.equal(f.element('autoQuickCheck').value,300);
});

await asyncTest('successful PUT with invalid readback cannot report saved or discard draft',async()=>{
  const f=fixture();f.publish(f.snapshot());f.edit();const save=f.submit();
  f.requests[0].resolve({});await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.requests[1].path,'/api/v1/autonomy');
  f.requests[1].resolve({...f.snapshot(13),server_time:'invalid'});await save;
  assert.equal(f.element('autoQuickCheck').value,'180');
  assert.equal(f.element('autoQuickSave').disabled,true);
  assert.doesNotMatch(f.element('autoQuickMessage').textContent,/Параметры сохранены/);
});

await asyncTest('valid save preserves policy authority and waits for live revision',async()=>{
  const f=fixture();f.publish(f.snapshot());f.edit();const save=f.submit();
  const request=f.requests[0],body=JSON.parse(request.options.body);
  assert.equal(request.path,'/api/v1/autonomy');assert.equal(request.options.method,'PUT');
  assert.equal(body.expected_revision,policy.revision);assert.equal(body.confirm,'SAVE_AUTONOMY');assert.equal(body.release_safe_mode,false);
  for(const key of Object.keys(policy))if(key!=='check_seconds')assert.deepEqual(body.policy[key],policy[key],key);
  f.requests[0].resolve({});await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.element('autoQuickSave').disabled,true);
  const next=f.snapshot(13);next.policy.check_seconds=180;f.requests[1].resolve(next);await save;
  assert.equal(f.element('autoQuickCheck').value,180);assert.equal(f.element('autoQuickSave').disabled,false);
  assert.match(f.element('autoQuickMessage').textContent,/Параметры сохранены/);
});

await asyncTest('revision conflict retains draft and never repeats PUT automatically',async()=>{
  const f=fixture();f.publish(f.snapshot());f.edit();const save=f.submit();
  f.requests[0].reject(Object.assign(new Error('revision conflict'),{status:409}));await save;
  f.publish(f.snapshot(13));assert.equal(f.element('autoQuickCheck').value,'180');
  assert.equal(f.element('autoQuickSave').disabled,true);await f.submit();assert.equal(f.requests.length,1);
});

await asyncTest('late successful reconciliation cannot overwrite a new session draft',async()=>{
  const f=fixture();f.publish(f.snapshot());f.edit();const save=f.submit();
  f.requests[0].reject(new Error('connection lost'));await save;const reload=f.reload();
  f.logout();f.publish(f.snapshot(14));f.element('autoQuickCheck').value='240';f.element('autoQuickForm').events.input();
  f.requests[1].resolve(f.snapshot(13));await reload;
  assert.equal(f.element('autoQuickCheck').value,'240');assert.equal(f.element('autoQuickSave').disabled,false);
  assert.match(f.element('autoQuickRevision').textContent,/14/);assert.equal(f.requests.length,2);
});
test('leaving warns only while quick policy changes remain unsaved',()=>{
  const f=fixture();f.publish(f.snapshot());assert.equal(f.leave().prevented,false);
  f.edit();const dirty=f.leave();assert.equal(dirty.prevented,true);assert.equal(dirty.returnValue,'');
  f.element('autoQuickReset').events.click();assert.equal(f.leave().prevented,false);
  f.edit();f.logout();assert.equal(f.leave().prevented,false);
});

function published(f,instance,serverTime,revision=12,checkSeconds=300){
  const snapshot=f.snapshot(revision);snapshot.server_time=serverTime;snapshot.policy.check_seconds=checkSeconds;
  snapshot.observation={instance_id:instance.repeat(32),state:'available',revision:1,data_age_ms:0,observed_at:serverTime};return snapshot;
}
test('new process accepts an earlier server clock but fences drafts at the same policy revision',()=>{
  const f=fixture(),old=published(f,'a','2026-10-03T15:00:00Z');f.publish(old);f.edit();
  f.publish(published(f,'b','2026-10-03T14:00:00Z',12,240));
  assert.equal(f.element('autoQuickCheck').value,'180');assert.equal(f.element('autoQuickSave').disabled,true,'restart did not fence the old policy draft');
  f.publish({...old,server_time:'2026-10-03T16:00:00Z'});
  f.element('autoQuickReset').events.click();assert.equal(f.element('autoQuickCheck').value,240,'old process replaced the restarted process');
  assert.equal(f.element('autoQuickSave').disabled,false);
  f.publish(published(f,'b','2026-10-03T13:00:00Z',12,600));assert.equal(f.element('autoQuickCheck').value,240,'older same-process snapshot was accepted');
  f.logout();f.publish(old);assert.equal(f.element('autoQuickCheck').value,300,'new login inherited retired process state');
});

await asyncTest('live readback without instance id retains the publication ordering context',async()=>{
  const f=fixture();f.publish(published(f,'a','2026-10-03T15:00:00Z'));f.edit();const save=f.submit();
  f.requests[0].resolve({});await new Promise(resolve=>setImmediate(resolve));
  const live=f.snapshot(13);live.server_time='2026-10-03T15:01:00Z';live.policy.check_seconds=180;
  f.requests[1].resolve(live);await save;assert.equal(f.leave().prevented,false);
  f.publish(published(f,'b','2026-10-03T14:00:00Z',13,240));assert.equal(f.element('autoQuickCheck').value,240);
  assert.equal(f.element('autoQuickSave').disabled,false);assert.equal(f.requests.length,2);
});

await asyncTest('process change while reconciling cannot unlock an unknown write using an old response',async()=>{
  const f=fixture(),old=published(f,'a','2026-10-03T15:00:00Z');f.publish(old);f.edit();const save=f.submit();
  f.requests[0].reject(new Error('connection lost'));await save;const reload=f.reload();
  const restarted=published(f,'b','2026-10-03T14:00:00Z',12,240);f.publish(restarted);
  f.requests[1].resolve({...old,observation:undefined});await reload;
  f.element('autoQuickReset').events.click();assert.equal(f.element('autoQuickCheck').value,240);
  assert.equal(f.element('autoQuickSave').disabled,true,'pre-restart live response unlocked the write');
  assert.equal(f.leave().prevented,true,'unknown write lost its unload warning after resetting draft');
  const retry=f.reload();f.requests[2].resolve({...restarted,observation:undefined});await retry;
  assert.equal(f.element('autoQuickSave').disabled,false);assert.equal(f.leave().prevented,false);
  assert.equal(f.requests.filter(r=>r.options.method==='PUT').length,1);
});
console.log(JSON.stringify({suite:'autopilot-settings',tests:total}));
