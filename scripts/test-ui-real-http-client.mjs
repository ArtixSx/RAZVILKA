// Pure client admission/privacy checks. No HTTP, browser, VM or evidence fixture.
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {realHTTPEnginePanelRead,realHTTPAIGroupFacts,realHTTPAIGroupDiagnosis,realHTTPInstallCommunityBrowseModel,realHTTPInstallNodeBrowseModel} from './ui-real-http-scenarios.mjs';
import {realHTTPSettings,realHTTPFixture,realHTTPIdentity,realHTTPIdentityFacts,realHTTPAwaitIdentity,realHTTPAwaitInventory,realHTTPCode,realHTTPFailure,realHTTPAssert,realHTTPDiagnosis,realHTTPUIReadAllowed,realHTTPSharedScopeFacts} from './test-ui-real-http-browser.mjs';

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
  status:{safe_mode:false,live_active:false,revision:1},services:[{enabled:false,applied_state:{enabled:false}}],nodes:{nodes:[],groups:[]},
  autonomy:{policy:{revision:1,check_seconds:120,reserve_seconds:600,setup_complete:true,enabled:false,inherit_new_services:false,application:{mode:'off'},components:{mode:'off'}}},recovery:{recovery_required:false}});
check(()=>realHTTPFixture(fixture(),instance));
check(()=>{const value=fixture();value.status.revision=0;value.status.applied_revision=0;realHTTPFixture(value,instance);});
for(const revision of [-1,1.5,Number.MAX_SAFE_INTEGER+1,undefined]){
  reject(()=>{const value=fixture();value.status.revision=revision;realHTTPFixture(value,instance);},'QA_PRIVATE_INACTIVE_REQUIRED');
}
reject(()=>realHTTPIdentity({...envelope,instance_id:'b'.repeat(32)},instance),'QA_INSTANCE_MISMATCH_OR_STALE');
reject(()=>realHTTPIdentity({...envelope,data_age_ms:120000},instance),'QA_INSTANCE_MISMATCH_OR_STALE');
reject(()=>realHTTPIdentity({...envelope,state:'retained'},instance),'QA_INSTANCE_MISMATCH_OR_STALE');
reject(()=>{const value=fixture();value.inventory.data.system.opt_ready=false;realHTTPFixture(value,instance);},'QA_OPT_INVENTORY_REQUIRED');
reject(()=>{const value=fixture();value.status.live_active=true;realHTTPFixture(value,instance);},'QA_PRIVATE_INACTIVE_REQUIRED');
reject(()=>{const value=fixture();value.status.safe_mode=true;realHTTPFixture(value,instance);},'QA_PRIVATE_INACTIVE_REQUIRED');
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
  'UI_ENGINE_CARD_MOBILE_LAYOUT','UI_ENGINE_CARD_RETURN_OVERVIEW',
  'UI_AI_GROUP_NAVIGATION','UI_AI_GROUP_CATALOG','UI_AI_GROUP_OPEN','UI_AI_GROUP_READBACK',
  'UI_AI_GROUP_SEARCH','UI_AI_GROUP_CLOSE','UI_AI_GROUP_BOOKEND',
  'UI_NODE_SAVED_HTTP','UI_NODE_SAVED_BUSY_MODEL','UI_NODE_SAVED_SEARCH','UI_NODE_SAVED_OFFLINE_MODEL',
  'UI_NODE_SAVED_LIVE_RETRY','UI_NODE_SAVED_LATE_MODEL','UI_NODE_SAVED_TTL_MODEL','UI_NODE_SAVED_BOOKEND']){
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
{
  const available={...envelope,data:{system:{opt_ready:true,kernel:'qa'},private_value:'private response body'}},retained={...available,state:'retained',data_age_ms:63336};
  const rejectInventory=async(values,code)=>{
    const f=waitFixture(values);
    await assert.rejects(realHTTPAwaitInventory(instance,f.read,f.clock),error=>{
      assert.deepEqual(realHTTPFailure(error,'inventory-preflight'),{stage:'inventory-preflight',status:'failed',code});return true;
    });
    checks++;return f.counts();
  };
  {
    const f=waitFixture([available]),before=structuredClone(available);
    assert.equal(await realHTTPAwaitInventory(instance,f.read,f.clock),available);assert.deepEqual(available,before);
    assert.equal(Object.hasOwn(available,'admission'),false);assert.deepEqual(f.counts(),{reads:1,pauses:0,elapsed:0});checks++;
  }
  {
    const f=waitFixture([retained,available]),before=structuredClone(retained);
    assert.equal(await realHTTPAwaitInventory(instance,f.read,f.clock),available);assert.deepEqual(retained,before);
    assert.equal(retained.state,'retained');assert.deepEqual(f.counts(),{reads:2,pauses:1,elapsed:500});checks++;
  }
  for(const state of ['available','retained'])assert.deepEqual(await rejectInventory([retained,{...available,state,instance_id:'b'.repeat(32)}],'QA_INSTANCE_MISMATCH_OR_STALE'),{reads:2,pauses:1,elapsed:500});
  for(const value of [null,{...retained,schema:2},{...retained,dataplane:'unknown'},{...retained,data_age_ms:'private age'},
    {...retained,data_age_ms:-1},{...retained,data_age_ms:Infinity},{...retained,max_age_seconds:0},
    {...retained,max_age_seconds:1,data_age_ms:1000},{...retained,data_age_ms:120000},
    ...['empty','expired','unknown'].map(state=>({...retained,state}))]){
    assert.deepEqual(await rejectInventory([value],'QA_INSTANCE_MISMATCH_OR_STALE'),{reads:1,pauses:0,elapsed:0});
  }
  {
    const counts=await rejectInventory([retained],'QA_INVENTORY_WAIT_TIMEOUT');
    assert(counts.reads<=17);assert.equal(counts.elapsed,8000);
  }
  {
    let reads=0,pauses=0;
    await assert.rejects(realHTTPAwaitInventory(instance,async()=>{reads++;return retained;},{now:()=>0,pause:async ms=>{assert.equal(ms,500);pauses++;}}),
      error=>realHTTPFailure(error,'inventory-preflight').code==='QA_INVENTORY_WAIT_TIMEOUT');
    assert.equal(reads,17);assert.equal(pauses,17);checks++;
  }
  for(const returnedAt of [8000,9000]){
    let elapsed=0,reads=0;
    await assert.rejects(realHTTPAwaitInventory(instance,async timeout=>{assert.equal(timeout,3000);reads++;elapsed=returnedAt;return available;},
      {now:()=>elapsed,pause:async()=>assert.fail('late available must refuse before another pause')}),
      error=>realHTTPFailure(error,'inventory-preflight').code==='QA_INVENTORY_WAIT_TIMEOUT');
    assert.equal(reads,1);checks++;
  }
  {
    let elapsed=0,reads=0;const timeouts=[];
    const value=await realHTTPAwaitInventory(instance,async timeout=>{assert(timeout<=8000-elapsed);timeouts.push(timeout);elapsed+=++reads<3?2700:1599;return reads<3?retained:available;},
      {now:()=>elapsed,pause:async ms=>{assert(ms>0&&ms<=500);elapsed+=ms;}});
    assert.equal(value,available);assert.deepEqual(timeouts,[3000,3000,1600]);assert.equal(elapsed,7999);checks++;
  }
  for(const kind of ['http','network']){
    let reads=0,original;
    if(kind==='http')try{realHTTPAssert(false,'HTTP_READ_REJECTED');}catch(error){original=error;}
    else original=Object.assign(new Error('private request credentials and URI'),{actual:'private body'});
    await assert.rejects(realHTTPAwaitInventory(instance,async()=>{reads++;throw original;},{now:()=>0,pause:async()=>assert.fail('read errors must not retry')}),error=>error===original);
    assert.equal(reads,1);assert.deepEqual(realHTTPFailure(original,'inventory-preflight'),{stage:'inventory-preflight',status:'failed',code:kind==='http'?'HTTP_READ_REJECTED':'CLIENT_FAILED'});checks++;
  }
}
{
  const fixture=({catalog=false,open=false,count=1,visible=true}={})=>{
    const state={currentView:'services',dataLoad:{services:{phase:'ready'}}},panelLoad={request:null};
    const interfaceState={filter:catalog?'all':'selected',query:'',category:''};
    const target={open,visibility:visible?'visible':'hidden',private_id:'private service ID',
      querySelector:()=>({textContent:'ИИ-сервисы private catalog title'}),getBoundingClientRect:()=>({width:100,height:40})};
    const child={private_id:'private icon ID'},button={disabled:false,fieldsetDisabled:false,inert:false,visibility:'visible',private_id:'private button ID',
      rect:{left:40,top:100,width:160,height:40},getBoundingClientRect(){return this.rect;},matches:()=>button.fieldsetDisabled,
      closest:()=>button.inert?{private_id:'private ancestor ID'}:null,contains:element=>element===button||element===child};
    const dom={buttons:[button],canonical:button,active:true,auth:{hidden:true},modal:null,hit:child};
    const context={state,panelLoad,interfaceState,innerWidth:1280,innerHeight:900,
      document:{querySelectorAll:selector=>selector==='[data-r5-catalog]'?dom.buttons:Array.from({length:count},()=>target),
        getElementById:id=>id==='r5CatalogButton'?dom.canonical:id==='view-services'?{classList:{contains:()=>dom.active}}:id==='authScreen'?dom.auth:null,
        querySelector:()=>dom.modal,elementFromPoint:()=>dom.hit},getComputedStyle:element=>({visibility:element.visibility})};
    vm.createContext(context);let observations=0;
    const page={evaluate:fn=>{observations++;return vm.runInContext('('+fn.toString()+')',context)();}};
    return {state,panelLoad,interfaceState,target,button,dom,page,observations:()=>observations};
  };
  const actionFacts={catalog_button_count:'1',catalog_id_exists:true,catalog_locator_matches_id:true,services_view_active:true,
    catalog_button_visible:true,catalog_button_enabled:true,catalog_button_inert:false,catalog_center_in_view:true,catalog_center_receives_events:true,auth_hidden:true,modal_open:false};
  const capture=async action=>{
    const rows=[],log=console.log;
    console.log=value=>{assert.equal(typeof value,'string');assert(value.startsWith('AI_GROUP_DIAGNOSTIC '));rows.push(JSON.parse(value.slice('AI_GROUP_DIAGNOSTIC '.length)));};
    try{await action(rows);}
    finally{console.log=log;}
  };
  for(const catalog of [false,true])for(const open of [false,true]){
    const f=fixture({catalog,open});
    const facts=await realHTTPAIGroupFacts(f.page);
    assert.deepEqual(JSON.parse(JSON.stringify(facts)),{current_services:true,panel_pending:false,services_ready:true,catalog_mode:catalog,
      query_empty:true,category_empty:true,group_count:'1',target_visible:true,target_open:open,...actionFacts});
    assert.equal(f.interfaceState.filter,catalog?'all':'selected');assert.equal(f.target.open,open);assert.equal(f.observations(),1);checks++;
    await capture(async rows=>{
      const error=Object.assign(new Error('private response body and credentials'),{name:'TimeoutError',actual:'private profile URI'});let calls=0;
      await assert.rejects(realHTTPAIGroupDiagnosis(f.page,'UI_AI_GROUP_OPEN',realHTTPDiagnosis,()=>{
        calls++;f.target.open=!f.target.open;throw error;
      }),caught=>caught===error);
      assert.equal(calls,1);assert.equal(f.target.open,!open);assert.equal(f.interfaceState.filter,catalog?'all':'selected');
      assert.equal(rows.length,2);assert.deepEqual(rows.map(row=>[row.checkpoint,row.moment,row.target_open]),
        [['UI_AI_GROUP_OPEN','before',open],['UI_AI_GROUP_OPEN','failed',!open]]);
      assert(rows.every(row=>row.observation_available===true));assert(!JSON.stringify(rows).includes('private'));
      assert.deepEqual(realHTTPFailure(error,'known-scenario'),{stage:'UI_AI_GROUP_OPEN',status:'failed',code:'TIMEOUT'});checks++;
    });
  }
  for(const count of [0,2,1000]){
    const f=fixture({count,open:true}),facts=await realHTTPAIGroupFacts(f.page);
    assert.equal(facts.group_count,count===0?'0':'many');assert.equal(facts.target_open,false);assert.equal(facts.target_visible,false);
    assert(!JSON.stringify(facts).includes('private'));checks++;
  }
  {
    const f=fixture({visible:false,open:true});f.state.currentView='private view';f.state.dataLoad.services.phase='private error';f.panelLoad.request=Promise.resolve();
    f.interfaceState.query='private search URI';f.interfaceState.category='private category ID';
    assert.deepEqual(JSON.parse(JSON.stringify(await realHTTPAIGroupFacts(f.page))),{current_services:false,panel_pending:true,services_ready:false,catalog_mode:false,
      query_empty:false,category_empty:false,group_count:'1',target_visible:false,target_open:true,...actionFacts});checks++;
  }
  const actionCases=[
    [f=>{f.dom.buttons=[];f.dom.canonical=null;},{catalog_button_count:'0',catalog_id_exists:false,catalog_locator_matches_id:false,
      catalog_button_visible:false,catalog_button_enabled:false,catalog_center_in_view:false,catalog_center_receives_events:false}],
    [f=>{f.dom.buttons=[];},{catalog_button_count:'0',catalog_locator_matches_id:false,catalog_button_visible:false,
      catalog_button_enabled:false,catalog_center_in_view:false,catalog_center_receives_events:false}],
    [f=>{f.dom.buttons.push({...f.button,private_id:'private duplicate ID'});},{catalog_button_count:'many',catalog_locator_matches_id:false,
      catalog_button_visible:false,catalog_button_enabled:false,catalog_center_in_view:false,catalog_center_receives_events:false}],
    [f=>{f.dom.canonical={private_id:'private different canonical ID'};},{catalog_locator_matches_id:false}],
    [f=>{f.button.visibility='hidden';},{catalog_button_visible:false}],
    [f=>{f.button.visibility='collapse';},{catalog_button_visible:false}],
    [f=>{f.button.rect.width=0;},{catalog_button_visible:false}],
    [f=>{f.button.disabled=true;},{catalog_button_enabled:false}],
    [f=>{f.button.fieldsetDisabled=true;},{catalog_button_enabled:false}],
    [f=>{f.button.inert=true;},{catalog_button_inert:true}],
    [f=>{f.button.rect.top=-200;},{catalog_center_in_view:false,catalog_center_receives_events:false}],
    [f=>{f.button.rect.top=900;},{catalog_center_in_view:false,catalog_center_receives_events:false}],
    [f=>{f.dom.hit={private_id:'private covering element ID'};},{catalog_center_receives_events:false}],
    [f=>{f.dom.active=false;f.dom.auth.hidden=false;f.dom.modal={private_id:'private dialog ID'};},{services_view_active:false,auth_hidden:false,modal_open:true}]
  ];
  for(const [prepare,expected] of actionCases){
    const f=fixture();prepare(f);const facts=await realHTTPAIGroupFacts(f.page);
    assert.deepEqual(Object.fromEntries(Object.keys(actionFacts).map(key=>[key,facts[key]])),{...actionFacts,...expected});
    assert(!JSON.stringify(facts).includes('private'));assert.equal(f.interfaceState.filter,'selected');assert.equal(f.target.open,false);assert.equal(f.observations(),1);checks++;
  }
  await capture(async rows=>{
    const page={evaluate:()=>{throw new Error('private page error');}},error=Object.assign(new Error('private action error'),{name:'TimeoutError'});let calls=0;
    await assert.rejects(realHTTPAIGroupDiagnosis(page,'UI_AI_GROUP_READBACK',realHTTPDiagnosis,()=>{calls++;throw error;}),caught=>caught===error);
    assert.equal(calls,1);assert.deepEqual(rows,[{checkpoint:'UI_AI_GROUP_READBACK',moment:'before',observation_available:false},
      {checkpoint:'UI_AI_GROUP_READBACK',moment:'failed',observation_available:false}]);
    assert.deepEqual(realHTTPFailure(error,'known-scenario'),{stage:'UI_AI_GROUP_READBACK',status:'failed',code:'TIMEOUT'});checks++;
    assert.equal(await realHTTPAIGroupDiagnosis(page,'UI_AI_GROUP_BOOKEND',realHTTPDiagnosis,()=>{calls++;return 7;}),7);
    assert.equal(calls,2);assert.deepEqual(rows[2],{checkpoint:'UI_AI_GROUP_BOOKEND',moment:'before',observation_available:false});checks++;
  });
  await capture(async rows=>{
    const f=fixture();let calls=0;
    await assert.rejects(realHTTPAIGroupDiagnosis(f.page,'private dynamic ID',realHTTPDiagnosis,()=>calls++),error=>realHTTPFailure(error,'known-scenario').code==='INVALID_DIAGNOSTIC_ID');
    assert.equal(calls,0);assert.equal(f.observations(),0);assert.deepEqual(rows,[]);checks++;
  });
}
{
  const held=()=>{let resolve;const promise=new Promise(done=>resolve=done);return {promise,resolve};};
  const fixture=()=>{
    const state={authGeneration:4,currentView:'engines',dataLoad:{status:{phase:'loading'},engineConfigs:{phase:'loading'}}};
    const panelLoad={generation:8,view:'engines',request:null},initial=held(),next=held();let refreshes=0;
    const context={state,panelLoad,$:()=>({hidden:true}),refreshAll(){refreshes++;panelLoad.generation++;panelLoad.request=next.promise;return next.promise;}};
    panelLoad.request=initial.promise;vm.createContext(context);
    const page={evaluate:(fn,arg)=>vm.runInContext('('+fn.toString()+')',context)(arg),waitForFunction:async(fn,arg)=>assert.equal(vm.runInContext('('+fn.toString()+')',context)(arg),true)};
    const complete=(read,phase='ready')=>{state.dataLoad.status.phase=phase;state.dataLoad.engineConfigs.phase='ready';panelLoad.request=null;read.resolve(true);};
    return {state,panelLoad,page,initial,next,complete,refreshes:()=>refreshes};
  };
  const f=fixture(),initialRead=realHTTPEnginePanelRead(f.page,{afterGeneration:7});let settled=false;initialRead.then(()=>settled=true);
  await Promise.resolve();assert.equal(settled,false);assert.equal(f.refreshes(),0);f.complete(f.initial);await initialRead;checks++;
  const fresh=realHTTPEnginePanelRead(f.page,{explicit:true});assert.equal(f.refreshes(),1);f.complete(f.next);await fresh;assert.equal(f.refreshes(),1);checks++;
  const queued=fixture(),explicitRead=realHTTPEnginePanelRead(queued.page,{explicit:true});assert.equal(queued.refreshes(),0);
  queued.complete(queued.initial);await new Promise(resolve=>setImmediate(resolve));assert.equal(queued.refreshes(),1);queued.complete(queued.next);await explicitRead;checks++;
  for(const phase of ['busy','error']){
    const failed=fixture(),read=realHTTPEnginePanelRead(failed.page);const rejection=assert.rejects(read,error=>error.code==='ERR_ASSERTION');failed.complete(failed.initial,phase);await rejection;checks++;
    const refreshed=fixture();refreshed.complete(refreshed.initial);const freshRead=realHTTPEnginePanelRead(refreshed.page,{explicit:true});
    const freshRejection=assert.rejects(freshRead,error=>error.code==='ERR_ASSERTION');refreshed.complete(refreshed.next,phase);await freshRejection;assert.equal(refreshed.refreshes(),1);checks++;
  }
  for(const leave of ['auth','view','generation']){
    const stale=fixture(),read=realHTTPEnginePanelRead(stale.page);const rejection=assert.rejects(read,error=>error.code==='ERR_ASSERTION');
    if(leave==='auth')stale.state.authGeneration++;else if(leave==='view')stale.state.currentView='settings';else stale.panelLoad.generation++;
    stale.complete(stale.initial);await rejection;checks++;
  }
}
{
  const delegated=[],context=vm.createContext({workflowRequest:async(...args)=>{delegated.push(args);return {actual_transport:true};}});
  vm.runInContext('('+realHTTPInstallCommunityBrowseModel.toString()+')()',context);
  const model=vm.runInContext('__rzCommunityBrowseQA',context);
  await assert.rejects(context.workflowRequest('/api/v1/community/services?q=test'),error=>error.status===409&&error.payload.code==='RESTORE_OPERATION_BUSY');checks++;
  assert.equal(delegated.length,0);checks++;
  model.phase='live';assert.equal((await context.workflowRequest('/api/v1/community/services?q=test',{readTimeoutMs:3000},12000)).actual_transport,true);
  assert.deepEqual(delegated[0],['/api/v1/community/services?q=test',{readTimeoutMs:3000},12000]);checks++;
  for(const path of ['/api/v1/apply','/api/v1/community/services/example/import','/api/v1/community/source-preview']){
    await assert.rejects(context.workflowRequest(path,{method:'POST'}),/prohibits non-GET/);checks++;
  }
  assert.equal(model.blocked_non_get,3);assert.equal(delegated.length,1);checks++;
  await assert.rejects(context.workflowRequest('/api/v1/community/unknown'),/Unknown community workflow/);checks++;
  const pending=context.workflowRequest('/api/v1/community/services/example/preview');let settled=false;pending.then(()=>{settled=true;});
  await Promise.resolve();assert.equal(settled,false);assert.equal(delegated.length,1);checks++;
  model.resolve({model_only:true});assert.equal((await pending).model_only,true);assert.equal(model.preview_settled,true);checks++;
  assert.equal((await context.workflowRequest('/api/v1/status')).actual_transport,true);assert.equal(delegated.length,2);checks++;
}
{
  const delegated=[],actual={actual_transport:true,revision:7};
  const context=vm.createContext({api:async(...args)=>{delegated.push(args);return actual;}});
  vm.runInContext('('+realHTTPInstallNodeBrowseModel.toString()+')()',context);
  const model=vm.runInContext('__rzNodeBrowseQA',context);
  await assert.rejects(context.api('/api/v1/nodes'),error=>error.status===409&&error.payload.code==='RESTORE_OPERATION_BUSY');checks++;
  model.phase='offline';await assert.rejects(context.api('/api/v1/nodes'),error=>error.name==='TypeError');checks++;
  assert.equal(delegated.length,0);checks++;
  model.phase='live';assert.equal(await context.api('/api/v1/nodes',{readTimeoutMs:3000},12000),actual);checks++;
  assert.deepEqual(delegated[0],['/api/v1/nodes',{readTimeoutMs:3000},12000]);checks++;
  for(const path of ['/api/v1/apply','/api/v1/nodes/example/reveal','/api/v1/nodes/import','/api/v1/node-checks']){
    await assert.rejects(context.api(path,{method:'POST'}),/prohibits non-GET/);checks++;
  }
  assert.equal(model.blocked_non_get,4);assert.equal(delegated.length,1);checks++;
  for(const path of ['/api/v1/nodes/unknown','/api/v1/nodes?alias=1','/api/v1/panel/nodes/']){
    await assert.rejects(context.api(path),/Unknown .* read refused/);checks++;
  }
  assert.equal(await context.api('/api/v1/panel/nodes'),actual);assert.equal(delegated.length,2);checks++;
  model.hold_saved=true;
  const pending=context.api('/api/v1/panel/nodes');let settled=false;pending.then(()=>{settled=true;});
  await new Promise(resolve=>setImmediate(resolve));assert.equal(settled,false);assert.equal(typeof model.resolve,'function');assert.equal(delegated.length,3);checks++;
  model.resolve({forged_body:true});assert.equal(await pending,actual,'held body was substituted instead of delayed');assert.equal(model.saved_settled,true);checks++;
  assert.equal(await context.api('/api/v1/status'),actual);assert.equal(delegated.length,4);checks++;
}
console.log('PASS pure real HTTP client checks '+checks);
