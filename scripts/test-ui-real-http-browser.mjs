// External client only: existing coordinator-owned disposable Linux QA instance.
// No server spawn, fixture copies, downloads, response interception or screenshots.
// Optional fresh QA account/policy setup requires separate explicit flags.
// Private response dumps, native probes and Apply are excluded.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdirSync,mkdtempSync,readFileSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runRealHTTPReadScenarios,runRealHTTPOfflineSources,runRealHTTPDraftScenarios,realHTTPDiagnosticIDs} from './ui-real-http-scenarios.mjs';

const diagnostics=new WeakMap();
const diagnosticStages=new WeakMap(),allowedDiagnosticIDs=new Set(realHTTPDiagnosticIDs);
const publicCodes=new Set(['NODE_HISTORY_ADMISSION_REQUIRED','PARTIAL_IMPORT_CONFIRMATION_REQUIRED','APPLY_REVIEW_CHANGED','WIREGUARD_ASSIGNMENT_CHANGED',
  'OBSERVED','NO_HOME_CANDIDATES','SOURCE_UNAVAILABLE','SOURCE_TIMEOUT','SOURCE_CANCELED','BOUNDS_EXCEEDED','ALIAS_CONFLICT',
  'AMBIGUOUS_BINDINGS','HOME_UNAVAILABLE','HOME_ROLE_UNKNOWN','BINDINGS_UNAVAILABLE','BINDINGS_ROUTER_UNKNOWN','BINDINGS_CONFLICT','NETWORK_POLICY_SCOPE_OPTIONS_CHANGED']);
export function realHTTPUIReadAllowed(path,method) {
  return method==='GET'&&['/api/v1/networkpolicy/review','/api/v1/networkpolicy/scope-options'].includes(path);
}
export function realHTTPSharedScopeFacts(value) {
  realHTTPAssert(value&&['first-setup','saved-policy'].includes(value.branch)
    &&['saved_segment_count','saved_excluded_device_count','unobserved_excluded_device_count'].every(key=>Number.isSafeInteger(value[key])&&value[key]>=0&&value[key]<=128)
    &&['available','partial','unavailable'].includes(value.observation_state)&&value.effect_authorized===false&&value.live_applied===false,'QA_SCOPE_FACTS_INVALID');
  realHTTPAssert(value.branch==='saved-policy'
    ? value.saved_segment_count===1&&value.saved_excluded_device_count>0&&value.unobserved_excluded_device_count>0&&value.unobserved_excluded_device_count<=value.saved_excluded_device_count&&value.retained_ids_checked===true
    : value.saved_segment_count===0&&value.saved_excluded_device_count===0&&value.unobserved_excluded_device_count===0&&value.retained_ids_checked===false,'QA_SCOPE_FACTS_INVALID');
  return {branch:value.branch,saved_segment_count:value.saved_segment_count,saved_excluded_device_count:value.saved_excluded_device_count,
    unobserved_excluded_device_count:value.unobserved_excluded_device_count,retained_ids_checked:value.retained_ids_checked,
    observation_state:value.observation_state,observation_code:realHTTPCode(value.observation_code),effect_authorized:false,live_applied:false};
}
export function realHTTPAssert(condition,code) {
  assert(/^[A-Z][A-Z0-9_]{0,79}$/.test(code));
  if(condition)return;
  const error=new Error('Real HTTP QA check failed');diagnostics.set(error,code);throw error;
}
export function realHTTPCode(value) {
  if(typeof value!=='string'||!/^[A-Z][A-Z0-9_]{0,79}$/.test(value))return null;
  return publicCodes.has(value)?value:'UNKNOWN_TYPED_CODE';
}
export function realHTTPFailure(error,stage) {
  return {stage:diagnosticStages.get(error)||stage,status:'failed',code:diagnostics.get(error)||({AssertionError:'ASSERTION_FAILED',TimeoutError:'TIMEOUT'}[error?.name]||'CLIENT_FAILED')};
}
export async function realHTTPDiagnosis(id,action) {
  realHTTPAssert(allowedDiagnosticIDs.has(id),'INVALID_DIAGNOSTIC_ID');
  try{return await action();}
  catch(error){
    if(error&&typeof error==='object'&&!diagnosticStages.has(error))diagnosticStages.set(error,id);
    throw error;
  }
}
export function realHTTPSettings(env,args=[]) {
  realHTTPAssert(args.every(arg=>['--draft-mutations','--setup-account','--prepare-policy'].includes(arg))&&new Set(args).size===args.length,'INVALID_ARGUMENTS');
  realHTTPAssert(env.RAZVILKA_QA_UI_FIXTURE==='disposable-linux','QA_FIXTURE_REQUIRED');
  let url;try{url=new URL(env.RAZVILKA_QA_UI_URL);}catch(_){realHTTPAssert(false,'QA_ORIGIN_REQUIRED');}
  realHTTPAssert(['http:','https:'].includes(url.protocol)&&!url.username&&!url.password&&!url.search&&!url.hash&&url.pathname==='/','INVALID_QA_ORIGIN');
  realHTTPAssert(/^[a-f0-9]{32}$/.test(env.RAZVILKA_QA_UI_INSTANCE||''),'QA_INSTANCE_REQUIRED');
  realHTTPAssert(!!env.RAZVILKA_QA_UI_CHROME,'CHROME_REQUIRED');
  const session=env.RAZVILKA_QA_UI_SESSION,username=env.RAZVILKA_QA_UI_USERNAME,password=env.RAZVILKA_QA_UI_PASSWORD;
  realHTTPAssert(!!session!==!!(username&&password)&&!(session&&(username||password))&&!(!!username!==!!password),'QA_AUTH_REQUIRED');
  const setupAccount=args.includes('--setup-account'),setupToken=env.RAZVILKA_QA_UI_SETUP_TOKEN;
  realHTTPAssert(setupAccount?!!setupToken&&!session:!setupToken,'QA_SETUP_TOKEN_REQUIRED');
  return {origin:url.origin,instance:env.RAZVILKA_QA_UI_INSTANCE,chrome:resolve(env.RAZVILKA_QA_UI_CHROME),session:session?resolve(session):null,
    username,password,setupAccount,setupToken:setupToken?resolve(setupToken):null,preparePolicy:args.includes('--prepare-policy'),
    draftMutations:args.includes('--draft-mutations'),output:env.RAZVILKA_QA_UI_OUTPUT?resolve(env.RAZVILKA_QA_UI_OUTPUT):null};
}
function realHTTPIdentityFieldsValid(value,instance) {
  return value?.schema===1&&value.instance_id===instance&&value.dataplane==='not-checked'
    &&Number.isFinite(value.data_age_ms)&&value.data_age_ms>=0&&Number.isFinite(value.max_age_seconds)&&value.max_age_seconds>0
    &&value.data_age_ms<Math.min(value.max_age_seconds*1000,120000);
}
export function realHTTPIdentity(value,instance) {
  realHTTPAssert(realHTTPIdentityFieldsValid(value,instance)&&value.state==='available','QA_INSTANCE_MISMATCH_OR_STALE');
}
export async function realHTTPAwaitIdentity(instance,read,{now=()=>performance.now(),pause=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}) {
  // GET-only admission observation. The server still admits the later write.
  const deadline=now()+8000;
  for(let attempt=0;attempt<17;attempt++){
    const remaining=deadline-now();realHTTPAssert(remaining>0,'QA_IDENTITY_WAIT_TIMEOUT');
    const value=await read(Math.max(1,Math.min(3000,Math.ceil(remaining))));
    realHTTPAssert(realHTTPIdentityFieldsValid(value,instance)&&['available','retained'].includes(value.state),'QA_INSTANCE_MISMATCH_OR_STALE');
    const admission=value.admission;
    realHTTPAssert(typeof admission?.exclusive==='boolean'&&typeof admission.fenced==='boolean'
      &&['idle','shared','busy','recovery-required'].includes(admission.state),'QA_IDENTITY_ADMISSION_INVALID');
    realHTTPAssert(!admission.fenced&&admission.state!=='recovery-required','QA_IDENTITY_ADMISSION_FENCED');
    realHTTPAssert(now()<deadline,'QA_IDENTITY_WAIT_TIMEOUT');
    if(value.state==='available'&&admission.state==='idle'&&!admission.exclusive){realHTTPIdentity(value,instance);return value;}
    await pause(Math.max(0,Math.min(500,deadline-now())));
  }
  realHTTPAssert(false,'QA_IDENTITY_WAIT_TIMEOUT');
}
export async function realHTTPAwaitInventory(instance,read,{now=()=>performance.now(),pause=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}) {
  // Observe a new real publication; retained inventory never satisfies preflight.
  const deadline=now()+8000;
  for(let attempt=0;attempt<17;attempt++){
    const remaining=deadline-now();realHTTPAssert(remaining>0,'QA_INVENTORY_WAIT_TIMEOUT');
    const value=await read(Math.max(1,Math.min(3000,Math.ceil(remaining))));
    realHTTPAssert(realHTTPIdentityFieldsValid(value,instance)&&['available','retained'].includes(value.state),'QA_INSTANCE_MISMATCH_OR_STALE');
    realHTTPAssert(now()<deadline,'QA_INVENTORY_WAIT_TIMEOUT');
    if(value.state==='available'){realHTTPIdentity(value,instance);return value;}
    await pause(Math.max(0,Math.min(500,deadline-now())));
  }
  realHTTPAssert(false,'QA_INVENTORY_WAIT_TIMEOUT');
}
export function realHTTPIdentityFacts(value,instance) {
  const age=value?.data_age_ms,limit=value?.max_age_seconds;
  const ageValid=Number.isFinite(age)&&age>=0&&Number.isFinite(limit)&&limit>0;
  const admission=value?.admission;
  return {schema_valid:value?.schema===1,instance_matches:value?.instance_id===instance,
    state:['empty','available','retained','expired'].includes(value?.state)?value.state:'unknown',
    dataplane_valid:value?.dataplane==='not-checked',data_age_ms:Number.isFinite(age)?age:null,max_age_seconds:Number.isFinite(limit)?limit:null,
    age_valid:ageValid,within_age_limit:ageValid&&age<Math.min(limit*1000,120000),
    admission_state:['idle','shared','busy','recovery-required'].includes(admission?.state)?admission.state:null,
    admission_exclusive:typeof admission?.exclusive==='boolean'?admission.exclusive:null,
    admission_fenced:typeof admission?.fenced==='boolean'?admission.fenced:null};
}
export function realHTTPPrivateFixture({snapshot,inventory,status,services,nodes,recovery},instance) {
  realHTTPIdentity(snapshot,instance);realHTTPIdentity(inventory,instance);
  realHTTPAssert(inventory.data?.system?.opt_ready===true&&typeof inventory.data.system.kernel==='string'&&inventory.data.system.kernel.length>0,'QA_OPT_INVENTORY_REQUIRED');
  realHTTPAssert(status?.safe_mode===true&&status.live_active===false&&Number.isSafeInteger(status.revision)&&status.revision>=0,'QA_PRIVATE_SAFE_MODE_REQUIRED');
  realHTTPAssert(Array.isArray(services)&&services.length>0&&services.every(row=>row.enabled===false&&row.applied_state?.enabled===false&&!row.applied_enabled),'QA_DISABLED_SERVICES_REQUIRED');
  realHTTPAssert(Array.isArray(nodes?.nodes)&&nodes.nodes.length===0&&Array.isArray(nodes.groups)&&nodes.groups.length===0,'QA_EMPTY_NODE_STORE_REQUIRED');
  realHTTPAssert(recovery?.recovery_required===false,'QA_RECOVERY_CLEAR_REQUIRED');
}
export function realHTTPFixture(value,instance) {
  realHTTPPrivateFixture(value,instance);
  const {autonomy}=value;
  const policy=autonomy?.policy;
  realHTTPAssert(policy?.setup_complete===true&&policy.enabled===false&&policy.inherit_new_services===false&&policy.application?.mode==='off'&&policy.components?.mode==='off','QA_AUTOMATION_OFF_REQUIRED');
  realHTTPAssert(Number.isSafeInteger(policy.revision)&&policy.revision>=1&&Number.isSafeInteger(policy.check_seconds)&&policy.check_seconds>=60&&policy.check_seconds<=3600
    &&Number.isSafeInteger(policy.reserve_seconds)&&policy.reserve_seconds>=Math.max(600,policy.check_seconds)&&policy.reserve_seconds<=86400,'QA_POLICY_TUNING_REQUIRED');
}
function serviceIntent(rows) {
  return JSON.stringify(rows.map(row=>({id:row.id,enabled:row.enabled,route:row.route,sources:row.sources,
    applied:row.applied_state,applied_sources:row.applied_sources,profile:row.wireguard_profile_revision,applied_profile:row.applied_wireguard_profile_revision})));
}
export async function runRealHTTPUI(config) {
  const {chromium}=createRequire(import.meta.url)('playwright');
  const parent=config.output||join(fileURLToPath(new URL('../',import.meta.url)),'.review-local');mkdirSync(parent,{recursive:true});
  const directory=mkdtempSync(join(parent,'ui-linux-real-'));
  const report={boundary:'actual HTTP/browser to supplied coordinator-owned Linux QA; no native probe or Apply',mode:config.draftMutations?'draft-mutations':'read-only',
    account_setup:config.setupAccount===true,policy_setup:config.preparePolicy===true,status:'running',steps:[],requests:[],identity_checks:[],browser_errors:0,cleanup_required:false};
  let browser,context,page,stage='launch',fixtureVerified=false;
  const browserRequests=[],records=new WeakMap();
  const recordResponse=async(response,path,method,source)=>{
    const receipt=await response.json().catch(()=>null);
    report.requests.push({method,path,status:response.status(),code:realHTTPCode(receipt?.code),source});return receipt;
  };
  const readJSON=async(path,headers={},timeout=30000)=>{
    realHTTPAssert(/^\/api\/v1\/[a-z0-9/-]+$/.test(path),'INVALID_READ_PATH');
    const response=await context.request.get(config.origin+path,{headers,maxRedirects:0,maxRetries:0,timeout});
    const receipt=await recordResponse(response,path,'GET','verification');
    if(['/api/v1/panel/snapshot','/api/v1/panel/inventory'].includes(path)){
      report.identity_checks.push({path,...realHTTPIdentityFacts(receipt,config.instance)});
      if(report.identity_checks.length>64)report.identity_checks.shift();
    }
    realHTTPAssert(response.status()===200,'HTTP_READ_REJECTED');return receipt;
  };
  const checkIdentity=async()=>realHTTPAwaitIdentity(config.instance,timeout=>readJSON('/api/v1/panel/snapshot',{},timeout));
  const beforeMutation=async()=>{
    realHTTPAssert(config.draftMutations&&fixtureVerified,'DRAFT_MUTATION_NOT_AUTHORIZED');await checkIdentity();report.cleanup_required=true;
  };
  const writeJSON=async(path,method,data)=>{
    realHTTPAssert(method==='POST'&&path==='/api/v1/node-groups'||method==='PUT'&&path==='/api/v1/autonomy','UNDECLARED_WRITE');
    await beforeMutation();const response=await context.request.fetch(config.origin+path,{method,headers:{Origin:config.origin},data,maxRedirects:0,maxRetries:0,timeout:30000});
    const receipt=await recordResponse(response,path,method,'verification');realHTTPAssert([200,201].includes(response.status()),'HTTP_WRITE_REJECTED');return receipt;
  };
  const uiReceipt=async(path,method,action,expectedStatus=200)=>{
    await beforeMutation();
    const pending=page.waitForResponse(response=>response.url()===config.origin+path&&response.request().method()===method);
    const [response]=await Promise.all([pending,action()]);
    const receipt=await recordResponse(response,path,method,'ui-receipt');realHTTPAssert(response.status()===expectedStatus,'HTTP_UI_WRITE_REJECTED');return receipt;
  };
  const uiRead=async(path,action)=>{
    realHTTPAssert(realHTTPUIReadAllowed(path,'GET'),'UNDECLARED_UI_READ');
    const pending=page.waitForResponse(response=>response.url()===config.origin+path&&response.request().method()==='GET');
    const [response]=await Promise.all([pending,action()]);
    const receipt=await recordResponse(response,path,'GET','ui-read-receipt');realHTTPAssert(response.status()===200,'HTTP_UI_READ_REJECTED');return receipt;
  };
  const test=async(name,boundary,action)=>{
    stage=name;await action();realHTTPAssert(report.browser_errors===0,'BROWSER_ERROR');
    const index=report.steps.length+1;report.steps.push({scenario:name,status:'passed'});console.log('PASS scenario '+index);
  };
  try {
    browser=await chromium.launch({executablePath:config.chrome,headless:true});
    context=await browser.newContext({viewport:{width:1280,height:900},serviceWorkers:'block',...(config.session?{storageState:config.session}:{})});
    stage='authenticate-existing-QA-account';
    if(config.setupAccount){
      stage='verify-fresh-QA-before-account-setup';
      const token=readFileSync(config.setupToken,'utf8').trim();realHTTPAssert(/^[A-Za-z0-9_+/=-]{32,128}$/.test(token),'QA_RECOVERY_TOKEN_INVALID');
      const headers={Authorization:'Bearer '+token,Origin:config.origin};
      realHTTPIdentity(await readJSON('/api/v1/panel/snapshot',headers),config.instance);
      const auth=await readJSON('/api/v1/auth/status',headers);realHTTPAssert(auth.setup_required===true&&auth.using_recovery_key===true,'QA_FRESH_ACCOUNT_REQUIRED');
      report.cleanup_required=true;
      const response=await context.request.post(config.origin+'/api/v1/auth/setup',{headers,data:{username:config.username,password:config.password},maxRedirects:0,maxRetries:0,timeout:30000});
      report.requests.push({method:'POST',path:'/api/v1/auth/setup',status:response.status(),code:null,source:'explicit-QA-account-setup'});
      realHTTPAssert(response.status()===200,'QA_ACCOUNT_SETUP_REJECTED');
    }
    if(!config.session){
      const response=await context.request.post(config.origin+'/api/v1/auth/login',{headers:{Origin:config.origin},data:{username:config.username,password:config.password},maxRedirects:0,maxRetries:0,timeout:30000});
      report.requests.push({method:'POST',path:'/api/v1/auth/login',status:response.status(),code:null,source:'authentication'});
      realHTTPAssert(response.status()===200,'QA_LOGIN_REJECTED');
    }
    stage='verify-QA-instance';const auth=await readJSON('/api/v1/auth/status');realHTTPAssert(auth.authenticated===true,'QA_SESSION_REQUIRED');
    const snapshot=await readJSON('/api/v1/panel/snapshot');realHTTPIdentity(snapshot,config.instance);
    const inventory=await realHTTPAwaitInventory(config.instance,timeout=>readJSON('/api/v1/panel/inventory',{},timeout)),nodes=await readJSON('/api/v1/nodes'),recovery=await readJSON('/api/v1/components/recovery');
    let status=await readJSON('/api/v1/status'),services=await readJSON('/api/v1/services'),autonomy=await readJSON('/api/v1/autonomy');
    if(config.preparePolicy){
      stage='prepare-disabled-QA-policy';realHTTPPrivateFixture({snapshot,inventory,status,services,nodes,recovery},config.instance);
      const previous=autonomy.policy;
      realHTTPAssert(previous?.schema===1&&previous.setup_complete===false&&previous.enabled===false&&Number.isSafeInteger(previous.revision),'QA_FRESH_POLICY_REQUIRED');
      await checkIdentity();report.cleanup_required=true;
      const policy={...previous,setup_complete:true,enabled:false,inherit_new_services:false,default_sources:['192.168.1.50/32'],check_seconds:120,reserve_seconds:600,reserve_target:3,candidates_per_round:2,
        application:{...previous.application,mode:'off'},components:{...previous.components,mode:'off'}};
      const response=await context.request.put(config.origin+'/api/v1/autonomy',{headers:{Origin:config.origin},data:{expected_revision:previous.revision,policy,confirm:'SAVE_AUTONOMY',release_safe_mode:false},maxRedirects:0,maxRetries:0,timeout:30000});
      await recordResponse(response,'/api/v1/autonomy','PUT','explicit-QA-policy-setup');realHTTPAssert(response.status()===200,'QA_POLICY_SETUP_REJECTED');
      autonomy=await readJSON('/api/v1/autonomy');status=await readJSON('/api/v1/status');services=await readJSON('/api/v1/services');
    }
    realHTTPFixture({snapshot,inventory,status,services,nodes,autonomy,recovery},config.instance);fixtureVerified=true;
    report.steps.push({scenario:'existing disposable QA preflight',status:'passed'});
    page=await context.newPage();page.setDefaultTimeout(30000);page.on('pageerror',()=>report.browser_errors++);
    page.on('request',request=>{
      const url=new URL(request.url());if(url.origin!==config.origin){report.browser_errors++;return;}
      if(!url.pathname.startsWith('/api/'))return;
      const path=/^\/api\/v1\/[a-zA-Z0-9/_-]+$/.test(url.pathname)?url.pathname:'/api/unknown';
      const entry={method:request.method(),path,status:null,code:null,source:'browser'};records.set(request,entry);report.requests.push(entry);browserRequests.push(entry);
    });
    page.on('response',response=>{const entry=records.get(response.request());if(entry)entry.status=response.status();});
    stage='open-existing-embedded-UI';const document=await page.goto(config.origin,{waitUntil:'domcontentloaded'});
    realHTTPAssert(document?.status()===200,'DOCUMENT_REJECTED');
    const csp=document.headers()['content-security-policy'];realHTTPAssert(csp?.includes("default-src 'self'")&&csp.includes("frame-ancestors 'none'"),'CSP_REQUIRED');
    await page.waitForFunction(()=>state.authenticated&&!panelLoad.request);
    const shared={page,requests:browserRequests,test,readJSON,writeJSON,uiReceipt,uiRead,beforeMutation,diagnose:realHTTPDiagnosis,
      recordSharedScope:value=>{report.shared_scope=realHTTPSharedScopeFacts(value);}};
    await runRealHTTPReadScenarios(shared);await runRealHTTPOfflineSources(shared);
    if(config.draftMutations)await runRealHTTPDraftScenarios(shared);
    stage='verify-final-QA-boundary';await checkIdentity();
    const after=await readJSON('/api/v1/status'),afterServices=await readJSON('/api/v1/services'),afterPolicy=await readJSON('/api/v1/autonomy');
    realHTTPAssert(after.safe_mode===true&&after.live_active===false&&after.revision===status.revision&&after.applied_revision===status.applied_revision,'QA_DATAPLANE_CHANGED');
    realHTTPAssert(serviceIntent(afterServices)===serviceIntent(services),'QA_SERVICE_INTENT_CHANGED');
    realHTTPAssert(afterPolicy.policy.enabled===false&&afterPolicy.policy.application.mode==='off'&&afterPolicy.policy.components.mode==='off','QA_AUTOMATION_CHANGED');
    const allowed=request=>request.method==='GET'||config.draftMutations&&request.method==='POST'&&['/api/v1/nodes/import','/api/v1/nodes/delete-batch'].includes(request.path)
      ||config.draftMutations&&request.method==='PUT'&&request.path==='/api/v1/autonomy';
    realHTTPAssert(browserRequests.every(allowed),'UNDECLARED_BROWSER_MUTATION');realHTTPAssert(report.browser_errors===0,'BROWSER_ERROR');
    report.status='passed';
  }catch(error){report.status='failed';report.failure=realHTTPFailure(error,stage);}
  finally{
    if(browser)try{await browser.close();}catch(_){report.status='failed';report.failure||={stage:'close-browser',status:'failed',code:'BROWSER_CLOSE_FAILED'};}
    writeFileSync(join(directory,'result.json'),JSON.stringify(report,null,2));
  }
  if(report.status==='failed')console.error('FAIL '+report.failure.code);
  return {directory,report};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const result=await runRealHTTPUI(realHTTPSettings(process.env,process.argv.slice(2)));
    console.log('Status '+result.report.status);console.log('Local report: '+join(result.directory,'result.json'));if(result.report.status!=='passed')process.exitCode=1;
  }catch(error){console.error('FAIL '+realHTTPFailure(error,'settings').code);process.exitCode=1;}
}
