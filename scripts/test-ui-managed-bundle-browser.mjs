// Source-only handoff: ROOT runs this against its existing genuine Linux AMD64
// fixture and installed Chrome. No server/VM launch, managed source mock,
// account/policy setup, install/recovery/native request or response substitution.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdirSync,mkdtempSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {realHTTPSettings,realHTTPAssert,realHTTPFailure,realHTTPIdentityFacts,realHTTPAwaitIdentity,realHTTPPrivateFixture} from './test-ui-real-http-browser.mjs';
import {inactiveBrowserDecision,inactiveReceipt} from './test-ui-inactive-exclusions-browser.mjs';

const base='/api/v1/components/nfqws2/managed-bundle';
const planPath=base+'/plan',installedPath=base+'/installed',statusPath='/api/v1/status';
const managedPaths=new Set([planPath,installedPath]);
const reason='Для этой платформы ещё нет проверенного пакета управляемого NFQWS2.';
const codes=new Set(['MANAGED_NFQWS_PLATFORM_UNREVIEWED','MANAGED_NFQWS_SOURCE_UNAVAILABLE']);
const panel='#ui3EngineGrid [data-engine-card="nfqws2"] [data-managed-nfq-panel]';
const serviceIntent=rows=>JSON.stringify(rows.map(row=>({id:row.id,enabled:row.enabled,route:row.route,sources:row.sources,
  applied:row.applied_state,applied_sources:row.applied_sources,profile:row.wireguard_profile_revision,applied_profile:row.applied_wireguard_profile_revision})));

export function managedUISettings(env,args=[]) {
  realHTTPAssert(args.length===1&&args[0]==='--managed-bundle-amd64-read-only','MANAGED_READ_ONLY_OPT_IN_REQUIRED');
  return {...realHTTPSettings(env),managedAMD64ReadOnly:true};
}
export function managedBrowserDecision(origin,url,method) {
  let target;try{target=new URL(url);}catch(_){return 'INVALID_REQUEST';}
  if(target.origin!==origin)return 'CROSS_ORIGIN_REQUEST';
  if(managedPaths.has(target.pathname))return method!=='GET'?'UNDECLARED_MUTATION':target.search?'UNDECLARED_READ_QUERY':null;
  return inactiveBrowserDecision(origin,url,method);
}
export function managedPublicPath(origin,url) {
  let target;try{target=new URL(url);}catch(_){return 'unknown';}
  if(target.origin!==origin)return 'foreign';
  if(managedPaths.has(target.pathname))return target.pathname;
  return target.pathname.startsWith('/api/')&&inactiveBrowserDecision(origin,origin+target.pathname,'GET')===null?target.pathname:target.pathname.startsWith('/api/')?'/api/unknown':'asset';
}
export function managedPublicCode(value) {return value==null?null:codes.has(value)?value:'UNKNOWN_TYPED_CODE';}
export function managedTraceFacts(row) {
  return {method:['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].includes(row.method)?row.method:'OTHER',
    path:[planPath,installedPath,statusPath].includes(row.path)?row.path:'/api/unknown',
    status:Number.isInteger(row.status)&&row.status>=100&&row.status<=599?row.status:null,
    started_event:Number.isSafeInteger(row.start)&&row.start>0?row.start:null,
    finished_event:Number.isSafeInteger(row.finished)&&row.finished>0?row.finished:null,
    failed:row.failed===true,managed_caller:row.managed_caller===true};
}
export function managedUnreviewedPlan(value,revision) {
  realHTTPAssert(value?.revision===revision&&Number.isSafeInteger(revision)&&revision>=0&&value.ready===false
    &&value.code==='MANAGED_NFQWS_PLATFORM_UNREVIEWED'&&value.reason===reason&&!Object.hasOwn(value,'bundle')
    &&value.installed_idle===false&&value.compatibility_ready===false&&value.working_routes_changed===false,'AMD64_UNREVIEWED_PLAN_REQUIRED');
}
export function managedSourceAbsent(value) {
  realHTTPAssert(value?.code==='MANAGED_NFQWS_SOURCE_UNAVAILABLE'&&value.installed_idle===false&&value.working_routes_changed===false,'MANAGED_SOURCE_ABSENT_REQUIRED');
}
export function managedReadSequence(rows) {
  // CDP's genuine initiator stack identifies the caller; unrelated status
  // polling cannot stand in for its third GET or make a parallel read pass.
  const own=rows.filter(row=>row.managed_caller);
  realHTTPAssert(own.length===3,'MANAGED_CALLER_READ_COUNT');
  realHTTPAssert(own.every((row,index)=>row.method==='GET'&&row.path===[planPath,installedPath,statusPath][index]
    &&row.status===[200,503,200][index]&&Number.isSafeInteger(row.start)&&row.start>0&&Number.isSafeInteger(row.finished)
    &&row.start<row.finished&&!row.failed&&(index===0||own[index-1].finished<row.start)),'MANAGED_READS_NOT_SEQUENTIAL');
  return {plan_gets:1,installed_gets:1,status_gets:1,sequential:true,
    reads:own.map(row=>({method:'GET',path:row.path,status:row.status,started_event:row.start,finished_event:row.finished,managed_caller:true}))};
}
function managedInitiator(stack,origin,depth=0) {
  if(!stack||depth>8)return false;
  return (stack.callFrames||[]).slice(0,64).some(frame=>{
    try{const url=new URL(frame.url);return url.origin===origin&&url.pathname==='/managed-nfq-bundle-ui.js';}catch(_){return false;}
  })||managedInitiator(stack.parent,origin,depth+1);
}
export async function runManagedBundleUI(config) {
  realHTTPAssert(config.managedAMD64ReadOnly===true&&!config.setupAccount&&!config.preparePolicy&&!config.draftMutations,'MANAGED_READ_ONLY_OPT_IN_REQUIRED');
  const {chromium}=createRequire(import.meta.url)('playwright');
  const parent=config.output||join(fileURLToPath(new URL('../',import.meta.url)),'.review-local');mkdirSync(parent,{recursive:true});
  const directory=mkdtempSync(join(parent,'ui-managed-amd64-real-'));
  const report={boundary:'genuine existing Linux AMD64 HTTP/browser; read-only managed caller; no installation or native claim',
    mode:'explicit-managed-bundle-amd64-read-only',status:'running',steps:[],requests:[],identity_checks:[],caller_reads:[],browser_errors:0,blocked_requests:0,blocked:[]};
  const browserRequests=[],records=new WeakMap(),trace=[],traceRecords=new Map();
  let browser,context,page,stage='launch',initial,event=0,overflow=false;
  const appendRequest=row=>{if(report.requests.length<2048)report.requests.push(row);else overflow=true;};
  const record=async(response,path,source)=>{
    const value=await response.json().catch(()=>null);
    appendRequest({method:'GET',path,status:response.status(),code:managedPublicCode(value?.code),source});return value;
  };
  const readJSON=async(path,expected=200,timeout=20000)=>{
    realHTTPAssert(managedBrowserDecision(config.origin,config.origin+path,'GET')===null&&!path.includes('?'),'UNDECLARED_READ');
    const response=await context.request.get(config.origin+path,{maxRedirects:0,maxRetries:0,timeout});
    const value=await record(response,path,'verification');
    if(['/api/v1/panel/snapshot','/api/v1/panel/inventory'].includes(path)){
      report.identity_checks.push({path,...realHTTPIdentityFacts(value,config.instance)});if(report.identity_checks.length>64)report.identity_checks.shift();
    }
    realHTTPAssert(response.status()===expected,'HTTP_READ_REJECTED');
    if(managedPaths.has(path))realHTTPAssert(response.headers()['cache-control']?.includes('no-store'),'MANAGED_RESPONSE_NO_STORE_REQUIRED');
    return value;
  };
  const identity=()=>realHTTPAwaitIdentity(config.instance,timeout=>readJSON('/api/v1/panel/snapshot',200,timeout));
  const reviewUnconfigured=value=>realHTTPAssert(value?.revision===initial.status.revision&&Object.hasOwn(value,'policy')&&value.policy===null
    &&Object.hasOwn(value,'consent')&&value.consent===null&&value.live_applied===false,'QA_SCOPE_OR_CONSENT_CHANGED');
  const bookend=async()=>{
    await identity();const status=await readJSON(statusPath),services=await readJSON('/api/v1/services'),autonomy=await readJSON('/api/v1/autonomy');
    realHTTPAssert(status.safe_mode===true&&status.live_active===false&&status.revision===initial.status.revision&&status.applied_revision===initial.status.applied_revision,'QA_DATAPLANE_CHANGED');
    realHTTPAssert(serviceIntent(services)===serviceIntent(initial.services),'QA_SERVICE_INTENT_CHANGED');
    realHTTPAssert(JSON.stringify(autonomy.policy)===JSON.stringify(initial.autonomy.policy),'QA_AUTOMATION_CHANGED');
    const exclusions=inactiveReceipt(await readJSON('/api/v1/networkpolicy/exclusions'),[]);
    realHTTPAssert(JSON.stringify(exclusions)===JSON.stringify(initial.exclusions),'QA_EXCLUSIONS_OR_APPLIED_CHANGED');
    reviewUnconfigured(await readJSON('/api/v1/networkpolicy/review'));
    realHTTPAssert(JSON.stringify(await readJSON('/api/v1/components/recovery'))===JSON.stringify(initial.recovery),'QA_RECOVERY_CHANGED');
    managedSourceAbsent(await readJSON(installedPath,503));
  };
  const step=async(name,action)=>{
    stage=name;await action();realHTTPAssert(!overflow&&report.browser_errors===0&&report.blocked_requests===0,'BROWSER_BOUNDARY_FAILED');
    report.steps.push({scenario:name,status:'passed'});console.log('PASS '+name);
  };
  const enterEngines=async()=>{
    await page.locator('.nav[data-view="engines"]').click();
    await page.waitForFunction(()=>state.currentView==='engines'&&!panelLoad.request);
    await page.locator(panel).waitFor({state:'visible'});
    await page.waitForFunction(()=>document.querySelector('#view-engines [data-component-recovery-panel]')?.textContent.includes('Незавершённых обновлений нет'));
  };
  const noNavigationRead=start=>realHTTPAssert(browserRequests.slice(start).every(row=>row.method==='GET'&&!managedPaths.has(row.path)),'NAVIGATION_STARTED_MANAGED_READ_OR_WRITE');
  const explicitRead=async()=>{
    await identity();const start=browserRequests.length,traceStart=trace.length;
    const planResponse=page.waitForResponse(response=>response.url()===config.origin+planPath&&response.request().method()==='GET',{timeout:65000});
    const installedResponse=page.waitForResponse(response=>response.url()===config.origin+installedPath&&response.request().method()==='GET',{timeout:65000});
    const responses=Promise.all([planResponse,installedResponse]);
    // Attach a rejection handler before click so a failed click does not leave
    // pending response waits with an unhandled rejection.
    responses.catch(()=>{});
    await page.locator(panel+' [data-managed-nfq-read]').click();
    const [plan,installed]=await responses;
    realHTTPAssert(plan.status()===200&&installed.status()===503,'AMD64_MANAGED_HTTP_SHAPE');
    for(const response of [plan,installed])realHTTPAssert(response.headers()['cache-control']?.includes('no-store'),'MANAGED_RESPONSE_NO_STORE_REQUIRED');
    const planValue=await record(plan,planPath,'ui-readback');managedUnreviewedPlan(planValue,initial.status.revision);
    managedSourceAbsent(await record(installed,installedPath,'ui-readback'));
    await page.waitForFunction(selector=>{
      const card=document.querySelector(selector),read=card?.querySelector('[data-managed-nfq-read]');
      return read&&!read.disabled&&card.querySelector('[role="status"]')?.textContent==='Для этой платформы ещё нет проверенного пакета управляемого NFQWS2.';
    },panel,{timeout:65000});
    assert.equal(await page.locator(panel+' [data-managed-nfq-install]').isEnabled(),false);
    // Wait for CDP's completion event as well as the already settled UI. No
    // response or page state is edited and background polling stays enabled.
    for(let attempt=0;attempt<80;attempt++){
      const own=trace.slice(traceStart).filter(row=>row.managed_caller);
      if(own.length===3&&own.every(row=>row.finished!==null))break;
      await new Promise(resolve=>setTimeout(resolve,25));
    }
    const caller=trace.slice(traceStart);report.caller_reads.push(managedReadSequence(caller));
    const reads=browserRequests.slice(start);
    realHTTPAssert(reads.every(row=>row.method==='GET')&&reads.filter(row=>row.path===planPath).length===1&&reads.filter(row=>row.path===installedPath).length===1,'MANAGED_UI_READ_COUNT');
    await bookend();
  };
  try{
    browser=await chromium.launch({executablePath:config.chrome,headless:true});
    context=await browser.newContext({viewport:{width:1280,height:900},serviceWorkers:'block',...(config.session?{storageState:config.session}:{})});
    stage='authenticate';if(!config.session){
      const response=await context.request.post(config.origin+'/api/v1/auth/login',{headers:{Origin:config.origin},data:{username:config.username,password:config.password},maxRedirects:0,maxRetries:0,timeout:20000});
      appendRequest({method:'POST',path:'/api/v1/auth/login',status:response.status(),code:null,source:'authentication'});realHTTPAssert(response.status()===200,'QA_LOGIN_REJECTED');
    }
    stage='verify-private-amd64-fixture';realHTTPAssert((await readJSON('/api/v1/auth/status')).authenticated===true,'QA_SESSION_REQUIRED');
    const snapshot=await identity(),inventory=await readJSON('/api/v1/panel/inventory'),status=await readJSON(statusPath),services=await readJSON('/api/v1/services'),nodes=await readJSON('/api/v1/nodes'),recovery=await readJSON('/api/v1/components/recovery');
    realHTTPPrivateFixture({snapshot,inventory,status,services,nodes,recovery},config.instance);
    realHTTPAssert(inventory.data.system.architecture==='amd64','QA_AMD64_REQUIRED');
    const autonomy=await readJSON('/api/v1/autonomy');realHTTPAssert(autonomy.policy?.enabled===false&&autonomy.policy.application?.mode==='off'&&autonomy.policy.components?.mode==='off','QA_AUTOMATION_OFF_REQUIRED');
    const exclusions=inactiveReceipt(await readJSON('/api/v1/networkpolicy/exclusions'),[]);
    realHTTPAssert(exclusions.revision===status.revision&&Number.isSafeInteger(status.applied_revision)&&status.applied_revision>=0,'QA_INITIAL_REVISION_MISMATCH');
    initial={status,services,recovery,autonomy,exclusions};reviewUnconfigured(await readJSON('/api/v1/networkpolicy/review'));managedSourceAbsent(await readJSON(installedPath,503));
    report.initial={architecture:'amd64',config_revision:status.revision,applied_revision:status.applied_revision,policy_revision:0,exclusion_revision:exclusions.exclusion_revision};
    await context.route('**/*',async route=>{
      const request=route.request(),decision=managedBrowserDecision(config.origin,request.url(),request.method());
      if(decision){report.blocked_requests++;if(report.blocked.length<64)report.blocked.push({method:['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].includes(request.method())?request.method():'OTHER',path:managedPublicPath(config.origin,request.url()),code:decision});await route.abort('blockedbyclient');}
      else await route.continue();
    });
    page=await context.newPage();page.setDefaultTimeout(30000);page.on('pageerror',()=>report.browser_errors++);
    page.on('request',request=>{
      const url=new URL(request.url());if(url.origin!==config.origin||!url.pathname.startsWith('/api/'))return;
      const row={method:['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].includes(request.method())?request.method():'OTHER',path:managedPublicPath(config.origin,request.url()),status:null,code:null,source:'browser'};
      records.set(request,row);if(browserRequests.length<1024)browserRequests.push(row);else overflow=true;appendRequest(row);
    });
    page.on('response',response=>{const row=records.get(response.request());if(row)row.status=response.status();});
    const cdp=await context.newCDPSession(page);
    cdp.on('Network.requestWillBeSent',value=>{
      const path=managedPublicPath(config.origin,value.request.url);if(![planPath,installedPath,statusPath].includes(path))return;
      if(trace.length>=512){overflow=true;return;}
      const row={method:value.request.method,path,start:++event,status:null,finished:null,failed:false,managed_caller:managedInitiator(value.initiator?.stack,config.origin)};
      trace.push(row);traceRecords.set(value.requestId,row);
    });
    cdp.on('Network.responseReceived',value=>{const row=traceRecords.get(value.requestId);if(row)row.status=value.response.status;});
    cdp.on('Network.loadingFinished',value=>{const row=traceRecords.get(value.requestId);if(row){row.finished=++event;traceRecords.delete(value.requestId);}});
    cdp.on('Network.loadingFailed',value=>{const row=traceRecords.get(value.requestId);if(row){row.failed=true;row.finished=++event;traceRecords.delete(value.requestId);}});
    await cdp.send('Network.enable');
    stage='open-genuine-embedded-UI';const document=await page.goto(config.origin,{waitUntil:'domcontentloaded'});realHTTPAssert(document?.status()===200,'DOCUMENT_REJECTED');
    const csp=document.headers()['content-security-policy'];realHTTPAssert(csp?.includes("default-src 'self'")&&csp.includes("frame-ancestors 'none'"),'CSP_REQUIRED');
    await page.waitForFunction(()=>state.authenticated&&!panelLoad.request);
    await step('navigation has no managed GET or business POST',async()=>{
      await enterEngines();noNavigationRead(0);assert.equal(await page.locator(panel+' [data-managed-nfq-install]').isEnabled(),false);await bookend();
    });
    await step('explicit genuine AMD64 read is sequential and displays refusal',explicitRead);
    await step('leave and return keep installation blocked without automatic managed reads',async()=>{
      const start=browserRequests.length;await page.locator('.nav[data-view="overview"]').click();await page.waitForFunction(()=>state.currentView==='overview'&&!panelLoad.request);await enterEngines();noNavigationRead(start);
      assert.equal(await page.locator(panel+' [data-managed-nfq-install]').isEnabled(),false);await bookend();
    });
    await step('reload stays read-only and a second explicit read gets fresh refusal',async()=>{
      const start=browserRequests.length;await page.reload({waitUntil:'domcontentloaded'});await page.waitForFunction(()=>state.authenticated&&!panelLoad.request);await enterEngines();noNavigationRead(start);
      assert.equal(await page.locator(panel+' [data-managed-nfq-install]').isEnabled(),false);await explicitRead();
    });
    stage='final-boundary';await identity();realHTTPAssert(!overflow&&report.browser_errors===0&&report.blocked_requests===0&&browserRequests.every(row=>row.method==='GET'),'BROWSER_BOUNDARY_FAILED');
    realHTTPAssert(browserRequests.filter(row=>row.path===planPath).length===2&&browserRequests.filter(row=>row.path===installedPath).length===2,'MANAGED_FINAL_READ_COUNT');
    report.final={...report.initial,config_unchanged:true,applied_unchanged:true,scope_unchanged:true,consent_unchanged:true,live_unchanged:true,services_unchanged:true,automation_unchanged:true,recovery_unchanged:true,
      managed_source_absent:true,install_disabled:true,reason_visible:true,business_mutations:0,managed_posts:0,browser_plan_gets:2,browser_installed_gets:2,caller_status_gets:2};report.status='passed';
  }catch(error){report.status='failed';report.failure=realHTTPFailure(error,stage);}
  finally{
    if(browser)try{await browser.close();}catch(_){report.status='failed';report.failure||={stage:'close-browser',status:'failed',code:'BROWSER_CLOSE_FAILED'};}
    report.caller_trace=trace.map(managedTraceFacts);
    writeFileSync(join(directory,'result.json'),JSON.stringify(report,null,2));
  }
  if(report.status==='failed')console.error('FAIL '+report.failure.code);
  return {directory,report};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{const result=await runManagedBundleUI(managedUISettings(process.env,process.argv.slice(2)));console.log('Status '+result.report.status);console.log('Local report: '+join(result.directory,'result.json'));if(result.report.status!=='passed')process.exitCode=1;}
  catch(error){console.error('FAIL '+realHTTPFailure(error,'settings').code);process.exitCode=1;}
}
