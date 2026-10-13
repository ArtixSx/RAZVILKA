// Pure client admission/privacy checks. No HTTP, browser, VM or evidence fixture.
import assert from 'node:assert/strict';
import {realHTTPSettings,realHTTPFixture,realHTTPIdentity,realHTTPIdentityFacts,realHTTPAwaitIdentity,realHTTPCode,realHTTPFailure,realHTTPAssert,realHTTPDiagnosis,realHTTPUIReadAllowed,realHTTPSharedScopeFacts} from './test-ui-real-http-browser.mjs';

const instance='a'.repeat(32),env={RAZVILKA_QA_UI_FIXTURE:'disposable-linux',RAZVILKA_QA_UI_URL:'http://127.0.0.1:19001/',
  RAZVILKA_QA_UI_INSTANCE:instance,RAZVILKA_QA_UI_CHROME:'installed-chrome',RAZVILKA_QA_UI_SESSION:'private-session.json'};
let checks=0;
const check=action=>{action();checks++;};
const reject=(action,code)=>check(()=>{try{action();assert.fail('expected rejection');}catch(error){assert.equal(realHTTPFailure(error,'admission').code,code);}});
check(()=>assert.equal(realHTTPSettings(env).draftMutations,false));
check(()=>assert.equal(realHTTPSettings(env,['--draft-mutations']).draftMutations,true));
check(()=>assert.equal(realHTTPSettings(env,['--prepare-policy']).preparePolicy,true));
reject(()=>realHTTPSettings({...env,RAZVILKA_QA_UI_FIXTURE:'production'}),'QA_FIXTURE_REQUIRED');
for(const url of ['http://name:password@127.0.0.1:19001/','http://127.0.0.1:19001/path','http://127.0.0.1:19001/?token=secret','http://127.0.0.1:19001/#secret','file:///tmp/qa']){
  reject(()=>realHTTPSettings({...env,RAZVILKA_QA_UI_URL:url}),'INVALID_QA_ORIGIN');
}
reject(()=>realHTTPSettings({...env,RAZVILKA_QA_UI_INSTANCE:undefined}),'QA_INSTANCE_REQUIRED');
reject(()=>realHTTPSettings(env,['--policy-transport']),'INVALID_ARGUMENTS');
reject(()=>realHTTPSettings(env,['--draft-mutations','--draft-mutations']),'INVALID_ARGUMENTS');
reject(()=>realHTTPSettings({...env,RAZVILKA_QA_UI_USERNAME:'qa',RAZVILKA_QA_UI_PASSWORD:'private'}),'QA_AUTH_REQUIRED');
reject(()=>realHTTPSettings({...env,RAZVILKA_QA_UI_SESSION:undefined,RAZVILKA_QA_UI_USERNAME:'qa'}),'QA_AUTH_REQUIRED');
reject(()=>realHTTPSettings(env,['--setup-account']),'QA_SETUP_TOKEN_REQUIRED');
reject(()=>realHTTPSettings({...env,RAZVILKA_QA_UI_SETUP_TOKEN:'private-token'},[]),'QA_SETUP_TOKEN_REQUIRED');
reject(()=>realHTTPSettings({...env,RAZVILKA_QA_UI_SETUP_TOKEN:'private-token'},['--setup-account']),'QA_SETUP_TOKEN_REQUIRED');
check(()=>assert.equal(realHTTPSettings({...env,RAZVILKA_QA_UI_SESSION:undefined,RAZVILKA_QA_UI_USERNAME:'qa',RAZVILKA_QA_UI_PASSWORD:'private'}).session,null));
check(()=>assert.equal(realHTTPSettings({...env,RAZVILKA_QA_UI_SESSION:undefined,RAZVILKA_QA_UI_USERNAME:'qa',RAZVILKA_QA_UI_PASSWORD:'private',RAZVILKA_QA_UI_SETUP_TOKEN:'private-token'},['--setup-account']).setupAccount,true));
const envelope={schema:1,instance_id:instance,state:'available',dataplane:'not-checked',data_age_ms:10,max_age_seconds:300};
check(()=>assert.deepEqual(realHTTPIdentityFacts({...envelope,data_age_ms:453,max_age_seconds:900,
  admission:{state:'idle',exclusive:false,fenced:false},data:{private_profile:'private URI'},headers:{Authorization:'private token'}},instance),
  {schema_valid:true,instance_matches:true,state:'available',dataplane_valid:true,data_age_ms:453,max_age_seconds:900,
    age_valid:true,within_age_limit:true,admission_state:'idle',admission_exclusive:false,admission_fenced:false}));
check(()=>assert.deepEqual(realHTTPIdentityFacts({schema:'private',instance_id:'private token',state:'private URI',dataplane:'private',
  data_age_ms:'private age',max_age_seconds:{secret:'private'},admission:{state:'private operation label',exclusive:'private',fenced:{secret:'private'}}},instance),
  {schema_valid:false,instance_matches:false,state:'unknown',dataplane_valid:false,data_age_ms:null,max_age_seconds:null,
    age_valid:false,within_age_limit:false,admission_state:null,admission_exclusive:null,admission_fenced:null}));
const fixture=()=>({snapshot:structuredClone(envelope),inventory:{...structuredClone(envelope),data:{system:{opt_ready:true,kernel:'6.1-qa'}}},
  status:{safe_mode:true,live_active:false,revision:1},services:[{enabled:false,applied_state:{enabled:false}}],nodes:{nodes:[],groups:[]},
  autonomy:{policy:{revision:1,check_seconds:120,reserve_seconds:600,setup_complete:true,enabled:false,inherit_new_services:false,application:{mode:'off'},components:{mode:'off'}}},recovery:{recovery_required:false}});
check(()=>realHTTPFixture(fixture(),instance));
check(()=>{const value=fixture();value.status.revision=0;value.status.applied_revision=0;realHTTPFixture(value,instance);});
for(const revision of [-1,1.5,Number.MAX_SAFE_INTEGER+1,undefined]){
  reject(()=>{const value=fixture();value.status.revision=revision;realHTTPFixture(value,instance);},'QA_PRIVATE_SAFE_MODE_REQUIRED');
}
reject(()=>realHTTPIdentity({...envelope,instance_id:'b'.repeat(32)},instance),'QA_INSTANCE_MISMATCH_OR_STALE');
reject(()=>realHTTPIdentity({...envelope,data_age_ms:120000},instance),'QA_INSTANCE_MISMATCH_OR_STALE');
reject(()=>realHTTPIdentity({...envelope,state:'retained'},instance),'QA_INSTANCE_MISMATCH_OR_STALE');
reject(()=>{const value=fixture();value.inventory.data.system.opt_ready=false;realHTTPFixture(value,instance);},'QA_OPT_INVENTORY_REQUIRED');
reject(()=>{const value=fixture();value.status.live_active=true;realHTTPFixture(value,instance);},'QA_PRIVATE_SAFE_MODE_REQUIRED');
reject(()=>{const value=fixture();value.services[0].applied_state.enabled=true;realHTTPFixture(value,instance);},'QA_DISABLED_SERVICES_REQUIRED');
reject(()=>{const value=fixture();value.nodes.nodes.push({});realHTTPFixture(value,instance);},'QA_EMPTY_NODE_STORE_REQUIRED');
reject(()=>{const value=fixture();value.autonomy.policy.components.mode='install';realHTTPFixture(value,instance);},'QA_AUTOMATION_OFF_REQUIRED');
reject(()=>{const value=fixture();value.autonomy.policy.reserve_seconds=120;realHTTPFixture(value,instance);},'QA_POLICY_TUNING_REQUIRED');
reject(()=>{const value=fixture();value.recovery.recovery_required=true;realHTTPFixture(value,instance);},'QA_RECOVERY_CLEAR_REQUIRED');
check(()=>assert.equal(realHTTPCode('NODE_HISTORY_ADMISSION_REQUIRED'),'NODE_HISTORY_ADMISSION_REQUIRED'));
for(const path of ['/api/v1/networkpolicy/review','/api/v1/networkpolicy/scope-options']){
  check(()=>assert.equal(realHTTPUIReadAllowed(path,'GET'),true));
  for(const method of ['POST','PUT','DELETE','PATCH'])check(()=>assert.equal(realHTTPUIReadAllowed(path,method),false));
}
for(const path of ['/api/v1/networkpolicy/exclusions','/api/v1/apply','/api/v1/networkpolicy/review?private=token'])check(()=>assert.equal(realHTTPUIReadAllowed(path,'GET'),false));
for(const code of ['BINDINGS_UNAVAILABLE','SOURCE_UNAVAILABLE','HOME_ROLE_UNKNOWN','NETWORK_POLICY_SCOPE_OPTIONS_CHANGED'])check(()=>assert.equal(realHTTPCode(code),code));
const scopeFacts={branch:'first-setup',saved_segment_count:0,saved_excluded_device_count:0,unobserved_excluded_device_count:0,retained_ids_checked:false,
  observation_state:'unavailable',observation_code:'SOURCE_UNAVAILABLE',effect_authorized:false,live_applied:false};
check(()=>assert.deepEqual(realHTTPSharedScopeFacts({...scopeFacts,private_ids:['private URI'],policy:{password:'secret'}}),scopeFacts));
const savedScopeFacts={...scopeFacts,branch:'saved-policy',saved_segment_count:1,saved_excluded_device_count:2,unobserved_excluded_device_count:1,retained_ids_checked:true,observation_state:'partial',observation_code:'BINDINGS_UNAVAILABLE'};
check(()=>assert.deepEqual(realHTTPSharedScopeFacts(savedScopeFacts),savedScopeFacts));
reject(()=>realHTTPSharedScopeFacts({...scopeFacts,retained_ids_checked:true}),'QA_SCOPE_FACTS_INVALID');
reject(()=>realHTTPSharedScopeFacts({...savedScopeFacts,unobserved_excluded_device_count:0}),'QA_SCOPE_FACTS_INVALID');
reject(()=>realHTTPSharedScopeFacts({...scopeFacts,effect_authorized:true}),'QA_SCOPE_FACTS_INVALID');
reject(()=>realHTTPSharedScopeFacts({...scopeFacts,saved_segment_count:'private identifier'}),'QA_SCOPE_FACTS_INVALID');
check(()=>assert.equal(realHTTPSharedScopeFacts({...scopeFacts,observation_code:'PRIVATE_UNKNOWN_VALUE'}).observation_code,'UNKNOWN_TYPED_CODE'));
check(()=>assert.equal(realHTTPCode('PRIVATE_UNRECOGNIZED_VALUE'),'UNKNOWN_TYPED_CODE'));
for(const code of ['private value',`TOKEN_${'A'.repeat(100)}`,{secret:'private'},null])check(()=>assert.equal(realHTTPCode(code),null));
check(()=>{
  const error=Object.assign(new Error('private credentials URI response body'),{actual:'private',expected:'private',cause:'private'});
  assert.deepEqual(realHTTPFailure(error,'known-scenario'),{stage:'known-scenario',status:'failed',code:'CLIENT_FAILED'});
});
assert.equal(await realHTTPDiagnosis('UI_NODE_IMPORT',()=>7),7);checks++;
for(const id of ['UI_STRATEGY_LOCAL_FIXTURE','UI_STRATEGY_LOCAL_EDITOR','UI_STRATEGY_LOCAL_BOOKEND','UI_SCOPE_FIXTURE','UI_SCOPE_EDITOR','UI_SCOPE_OBSERVATION','UI_SCOPE_NAVIGATION','UI_SCOPE_BOOKEND',
  'UI_ENGINE_CARD_INITIAL_REFRESH','UI_ENGINE_CARD_FOCUSED_REFRESH','UI_ENGINE_CARD_PROFILE_OPEN','UI_ENGINE_CARD_WORKFLOW_PROGRESS',
  'UI_ENGINE_CARD_EXPERT_DRAFT','UI_ENGINE_CARD_OTHER_CANCEL','UI_ENGINE_CARD_CHECK_RETURN','UI_ENGINE_CARD_DISCARD_DRAFT',
  'UI_ENGINE_CARD_MOBILE_LAYOUT','UI_ENGINE_CARD_RETURN_OVERVIEW']){
  try{
    await realHTTPDiagnosis(id,()=>assert.equal('private catalog id','private candidate material'));
    assert.fail('expected private assertion failure');
  }catch(error){
    assert.deepEqual(realHTTPFailure(error,'known-scenario'),{stage:id,status:'failed',code:'ASSERTION_FAILED'});checks++;
  }
}
try{
  await realHTTPDiagnosis('UI_NODE_REMAINING_VLESS',()=>assert.equal('private actual URI','private expected profile'));
  assert.fail('expected assertion failure');
}catch(error){
  assert.deepEqual(realHTTPFailure(error,'known-scenario'),{stage:'UI_NODE_REMAINING_VLESS',status:'failed',code:'ASSERTION_FAILED'});checks++;
}
try{
  await realHTTPDiagnosis('UI_POLICY_CAS_EXPLICIT_READ',()=>{throw Object.assign(new Error('private DOM credentials'),{name:'TimeoutError'});});
  assert.fail('expected timeout failure');
}catch(error){
  assert.deepEqual(realHTTPFailure(error,'known-scenario'),{stage:'UI_POLICY_CAS_EXPLICIT_READ',status:'failed',code:'TIMEOUT'});checks++;
}
try{
  await realHTTPDiagnosis('UI_POLICY_CAS_RECEIPT',()=>realHTTPAssert(false,'HTTP_UI_WRITE_REJECTED'));
  assert.fail('expected HTTP failure');
}catch(error){
  assert.deepEqual(realHTTPFailure(error,'known-scenario'),{stage:'UI_POLICY_CAS_RECEIPT',status:'failed',code:'HTTP_UI_WRITE_REJECTED'});checks++;
}
let invoked=false;
try{
  await realHTTPDiagnosis('private dynamic ID',()=>{invoked=true;});
  assert.fail('expected diagnostic ID rejection');
}catch(error){
  assert.equal(invoked,false);
  assert.deepEqual(realHTTPFailure(error,'known-scenario'),{stage:'known-scenario',status:'failed',code:'INVALID_DIAGNOSTIC_ID'});checks++;
}
const idle={...envelope,admission:{state:'idle',exclusive:false,fenced:false}};
const busy={...idle,state:'retained',admission:{state:'busy',exclusive:true,fenced:false}};
const waitFixture=values=>{
  let elapsed=0,reads=0,pauses=0;
  return {read:async timeout=>{assert(timeout>0&&timeout<=3000);return values[Math.min(reads++,values.length-1)];},
    clock:{now:()=>elapsed,pause:async ms=>{elapsed+=ms;pauses++;}},counts:()=>({reads,pauses,elapsed})};
};
const waitReject=async(values,code)=>{
  const f=waitFixture(values);
  try{await realHTTPAwaitIdentity(instance,f.read,f.clock);assert.fail('expected identity wait rejection');}
  catch(error){assert.equal(realHTTPFailure(error,'known-scenario').code,code);}
  checks++;return f.counts();
};
{
  const f=waitFixture([idle]);assert.equal(await realHTTPAwaitIdentity(instance,f.read,f.clock),idle);
  assert.deepEqual(f.counts(),{reads:1,pauses:0,elapsed:0});checks++;
}
{
  const f=waitFixture([{...idle,state:'retained',data_age_ms:12000},idle]);
  assert.equal(await realHTTPAwaitIdentity(instance,f.read,f.clock),idle);
  assert.deepEqual(f.counts(),{reads:2,pauses:1,elapsed:500});checks++;
}
{
  const f=waitFixture([{...idle,admission:{state:'shared',exclusive:false,fenced:false}},busy,idle]);
  assert.equal(await realHTTPAwaitIdentity(instance,f.read,f.clock),idle);
  assert.deepEqual(f.counts(),{reads:3,pauses:2,elapsed:1000});checks++;
}
assert.deepEqual(await waitReject([busy,{...idle,instance_id:'b'.repeat(32)}],'QA_INSTANCE_MISMATCH_OR_STALE'),{reads:2,pauses:1,elapsed:500});
assert.deepEqual(await waitReject([{...busy,admission:{state:'recovery-required',exclusive:true,fenced:true}}],'QA_IDENTITY_ADMISSION_FENCED'),{reads:1,pauses:0,elapsed:0});
assert.deepEqual(await waitReject([{...busy,data_age_ms:120000}],'QA_INSTANCE_MISMATCH_OR_STALE'),{reads:1,pauses:0,elapsed:0});
for(const value of [{...busy,schema:2},{...busy,dataplane:'unknown'},{...busy,max_age_seconds:1,data_age_ms:1000}]){
  assert.deepEqual(await waitReject([value],'QA_INSTANCE_MISMATCH_OR_STALE'),{reads:1,pauses:0,elapsed:0});
}
for(const admission of [undefined,{state:'unknown',exclusive:false,fenced:false},{state:'idle',exclusive:false,fenced:undefined}]){
  assert.deepEqual(await waitReject([{...idle,admission}],'QA_IDENTITY_ADMISSION_INVALID'),{reads:1,pauses:0,elapsed:0});
}
for(const state of ['empty','expired','unknown']){
  assert.deepEqual(await waitReject([{...idle,state}],'QA_INSTANCE_MISMATCH_OR_STALE'),{reads:1,pauses:0,elapsed:0});
}
{
  const counts=await waitReject([{...idle,state:'retained',data_age_ms:12000}],'QA_IDENTITY_WAIT_TIMEOUT');
  assert(counts.reads<=17);assert.equal(counts.elapsed,8000);
}
{
  let elapsed=0;
  try{await realHTTPAwaitIdentity(instance,async()=>{elapsed=9000;return idle;},{now:()=>elapsed,pause:async()=>{assert.fail('overdue read must stop');}});assert.fail('expected overdue rejection');}
  catch(error){assert.equal(realHTTPFailure(error,'known-scenario').code,'QA_IDENTITY_WAIT_TIMEOUT');checks++;}
}
console.log('PASS pure real HTTP client checks '+checks);
