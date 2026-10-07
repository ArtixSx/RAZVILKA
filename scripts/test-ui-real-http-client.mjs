// Pure client admission/privacy checks. No HTTP, browser, VM or evidence fixture.
import assert from 'node:assert/strict';
import {realHTTPSettings,realHTTPFixture,realHTTPIdentity,realHTTPCode,realHTTPFailure,realHTTPAssert,realHTTPDiagnosis} from './test-ui-real-http-browser.mjs';

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
check(()=>assert.equal(realHTTPCode('PRIVATE_UNRECOGNIZED_VALUE'),'UNKNOWN_TYPED_CODE'));
for(const code of ['private value',`TOKEN_${'A'.repeat(100)}`,{secret:'private'},null])check(()=>assert.equal(realHTTPCode(code),null));
check(()=>{
  const error=Object.assign(new Error('private credentials URI response body'),{actual:'private',expected:'private',cause:'private'});
  assert.deepEqual(realHTTPFailure(error,'known-scenario'),{stage:'known-scenario',status:'failed',code:'CLIENT_FAILED'});
});
assert.equal(await realHTTPDiagnosis('UI_NODE_IMPORT',()=>7),7);checks++;
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
console.log('PASS pure real HTTP client checks '+checks);
