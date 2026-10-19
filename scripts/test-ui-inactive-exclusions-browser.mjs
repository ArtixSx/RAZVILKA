// Opt-in external client for an existing coordinator-owned disposable Linux QA.
// No VM/server launch, policy setup, Apply, native probe, response interception,
// source fabrication or private response dumps. Original base suite is unchanged.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdirSync,mkdtempSync,readFileSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {realHTTPSettings,realHTTPAssert,realHTTPFailure,realHTTPIdentity,realHTTPIdentityFacts,realHTTPAwaitIdentity,realHTTPPrivateFixture} from './test-ui-real-http-browser.mjs';

const pathExclusions='/api/v1/networkpolicy/exclusions';
const pathReview='/api/v1/networkpolicy/review';
const matchKinds=new Set(['service','exact','suffix','ip','cidr']);
const readPaths=new Set(['/api/v1/auth/status','/api/v1/status','/api/v1/panel/snapshot','/api/v1/panel/inventory','/api/v1/panel/autonomy','/api/v1/panel/availability',
  '/api/v1/services','/api/v1/metrics','/api/v1/audit/current','/api/v1/service-control','/api/v1/service-control/current','/api/v1/update','/api/v1/plan',
  '/api/v1/node-checks/current','/api/v1/node-autofallback','/api/v1/routes/options','/api/v1/nodes','/api/v1/node-feeds',
  '/api/v1/devices','/api/v1/engine-configs','/api/v1/autonomy','/api/v1/components/recovery',pathExclusions,pathReview,
  '/api/v1/nfqws2/setup-mode','/api/v1/nfqws2/exclusions','/api/v1/engine-configs/nfqws2/file']);
const matchImage=rows=>JSON.stringify(rows.map(row=>({kind:row.kind,value:row.value})).sort((a,b)=>(a.kind+'\n'+a.value).localeCompare(b.kind+'\n'+b.value)));
const serviceIntent=rows=>JSON.stringify(rows.map(row=>({id:row.id,enabled:row.enabled,route:row.route,sources:row.sources,
  applied:row.applied_state,applied_sources:row.applied_sources,profile:row.wireguard_profile_revision,applied_profile:row.applied_wireguard_profile_revision})));
const revision=n=>Number.isSafeInteger(n)&&n>=0;
const arrayEmpty=value=>value===null||Array.isArray(value)&&value.length===0;

export function inactiveUISettings(env,args=[]) {
  realHTTPAssert(args.every(arg=>['--inactive-exclusion-mutations','--setup-account'].includes(arg))&&new Set(args).size===args.length,'INVALID_ARGUMENTS');
  realHTTPAssert(args.includes('--inactive-exclusion-mutations'),'INACTIVE_MUTATION_OPT_IN_REQUIRED');
  const settings=realHTTPSettings(env,args.filter(arg=>arg==='--setup-account'));
  return {...settings,inactiveMutations:true};
}
export function inactiveManualRequest(data,observed,manual) {
  return !!data&&typeof data==='object'&&revision(observed?.revision)&&revision(observed?.exclusion_revision)&&Array.isArray(manual)&&Object.keys(data).length===4
    && ['expected_revision','expected_policy_revision','expected_exclusion_revision','manual'].every(key=>Object.hasOwn(data,key))
    && data.expected_revision===observed.revision&&data.expected_policy_revision===0&&data.expected_exclusion_revision===observed.exclusion_revision
    && Array.isArray(data.manual)&&data.manual.length<=512&&data.manual.every(row=>row&&Object.keys(row).length===2&&matchKinds.has(row.kind)&&typeof row.value==='string')
    && matchImage(data.manual)===matchImage(manual);
}
export function inactiveBrowserDecision(origin,url,method,data=null,ticket=null) {
  let target;try{target=new URL(url);}catch(_){return 'INVALID_REQUEST';}
  if(target.origin!==origin)return 'CROSS_ORIGIN_REQUEST';
  if(method==='GET'){
    if(!target.pathname.startsWith('/api/'))return target.pathname==='/'||/^\/[a-zA-Z0-9_./-]+\.(js|css|svg|ico|png|woff2?)$/.test(target.pathname)?null:'UNKNOWN_ASSET';
    if(!readPaths.has(target.pathname))return 'UNDECLARED_READ';
    const queries={
      '/api/v1/metrics':{limit:['120']},'/api/v1/audit/current':{limit:['40']},'/api/v1/devices':{view:['status']},
      '/api/v1/service-control/current':{job_id:'integer'},
      '/api/v1/engine-configs/nfqws2/file':{file:['exclude-list','auto-list','ipset-exclude']}
    };
    for(const [key,value] of target.searchParams){const values=queries[target.pathname]?.[key];if(!values||!(values==='integer'?/^[1-9][0-9]*$/.test(value):values.includes(value)))return 'UNDECLARED_READ_QUERY';}
    return null;
  }
  if(method!=='POST'||target.pathname!==pathExclusions||target.search||!ticket||ticket.consumed)return 'UNDECLARED_MUTATION';
  return inactiveManualRequest(data,ticket.observed,ticket.manual)?null:'INVALID_MANUAL_MUTATION';
}
export function inactiveReceipt(value,manual) {
  realHTTPAssert(value?.ok===true&&value.scope_configured===false&&value.storage_state==='inactive'&&value.live_applied===false,'INACTIVE_STORAGE_REQUIRED');
  realHTTPAssert(['revision','policy_revision','exclusion_revision','applied_revision'].every(key=>revision(value[key]))&&value.policy_revision===0,'INACTIVE_REVISIONS_REQUIRED');
  realHTTPAssert(value.russian_enabled===false&&value.russian_auto_update_allowed===false&&typeof value.desired_matches_applied==='boolean','INACTIVE_RU_DISABLED_REQUIRED');
  const stored=value.resource_exclusions,effective=value.effective,clients=effective?.clients;
  realHTTPAssert(Object.hasOwn(value,'resource_exclusions')&&(!stored||stored.schema===1&&stored.revision===value.exclusion_revision&&stored.russian_snapshot==null),'INACTIVE_DOCUMENT_REQUIRED');
  realHTTPAssert(!stored||Object.hasOwn(stored,'manual')&&(stored.manual===null||Array.isArray(stored.manual)),'INACTIVE_DOCUMENT_MANUAL_REQUIRED');
  realHTTPAssert(Array.isArray(effective?.manual)&&effective.policy_revision===0&&effective.revision===value.exclusion_revision&&effective.russian_enabled===false
    &&arrayEmpty(effective.russian)&&arrayEmpty(effective.legacy_rules)&&arrayEmpty(effective.broad_tlds)&&effective.russian_snapshot==null&&/^[a-f0-9]{64}$/.test(effective.digest||''),'INACTIVE_EFFECTIVE_REQUIRED');
  realHTTPAssert(clients?.mode===''&&clients.new_devices===''&&['segment_ids','device_ids','excluded_device_ids','excluded_cidrs'].every(key=>Object.hasOwn(clients,key)&&arrayEmpty(clients[key])),'INACTIVE_EMPTY_SCOPE_REQUIRED');
  realHTTPAssert(matchImage(stored?.manual||[])===matchImage(manual)&&matchImage(effective.manual)===matchImage(manual),'INACTIVE_MANUAL_MISMATCH');
  realHTTPAssert(stored||value.exclusion_revision===0,'INACTIVE_DOCUMENT_REVISION_MISMATCH');
  return value;
}
function reviewUnconfigured(value,expectedRevision) {
  realHTTPAssert(value?.revision===expectedRevision&&Object.hasOwn(value,'policy')&&value.policy===null
    &&Object.hasOwn(value,'consent')&&value.consent===null&&value.live_applied===false,'INACTIVE_SCOPE_OR_CONSENT_CHANGED');
}
export async function runInactiveExclusionsUI(config) {
  realHTTPAssert(config.inactiveMutations===true&&config.preparePolicy===false&&config.draftMutations===false,'INACTIVE_MUTATION_OPT_IN_REQUIRED');
  const {chromium}=createRequire(import.meta.url)('playwright');
  const parent=config.output||join(fileURLToPath(new URL('../',import.meta.url)),'.review-local');mkdirSync(parent,{recursive:true});
  const directory=mkdtempSync(join(parent,'ui-inactive-real-'));
  const report={boundary:'actual HTTP/browser on existing disposable Linux QA; manual inactive storage only, no policy/consent/Apply/native/source changes',
    mode:'explicit-inactive-exclusion-mutations',status:'running',steps:[],requests:[],identity_checks:[],browser_errors:0,blocked_requests:0,blocked:[],cleanup_required:false};
  const browserRequests=[],records=new WeakMap();
  let browser,context,page,stage='launch',verified=false,uiTicket=null,expected,initial;
  const record=async(response,path,method,source)=>{
    const data=await response.json().catch(()=>null),knownCodes=new Set(['NETWORK_POLICY_EXCLUSIONS_CHANGED','NETWORK_POLICY_EXCLUSIONS_INVALID','NETWORK_POLICY_SCOPE_REQUIRED','NETWORK_POLICY_LIST_REQUIRED','NETWORK_POLICY_EXCLUSIONS_UNAVAILABLE']);
    report.requests.push({method,path,status:response.status(),code:data?.code?knownCodes.has(data.code)?data.code:'UNKNOWN_TYPED_CODE':null,source});return data;
  };
  const readJSON=async(path,headers={},timeout=30000)=>{
    realHTTPAssert(readPaths.has(path),'UNDECLARED_READ');
    const response=await context.request.get(config.origin+path,{headers,maxRedirects:0,maxRetries:0,timeout});
    const data=await record(response,path,'GET','verification');
    if(['/api/v1/panel/snapshot','/api/v1/panel/inventory'].includes(path)){report.identity_checks.push({path,...realHTTPIdentityFacts(data,config.instance)});if(report.identity_checks.length>64)report.identity_checks.shift();}
    realHTTPAssert(response.status()===200,'HTTP_READ_REJECTED');return data;
  };
  const identity=()=>realHTTPAwaitIdentity(config.instance,timeout=>readJSON('/api/v1/panel/snapshot',{},timeout));
  const beforeMutation=async()=>{realHTTPAssert(verified&&config.inactiveMutations,'INACTIVE_MUTATION_NOT_AUTHORIZED');await identity();report.cleanup_required=true;};
  const writeManual=async(observed,manual,status=200)=>{
    await beforeMutation();
    const body={expected_revision:observed.revision,expected_policy_revision:0,expected_exclusion_revision:observed.exclusion_revision,manual};
    realHTTPAssert(inactiveManualRequest(body,observed,manual),'INVALID_MANUAL_MUTATION');
    const response=await context.request.post(config.origin+pathExclusions,{headers:{Origin:config.origin},data:body,maxRedirects:0,maxRetries:0,timeout:30000});
    const value=await record(response,pathExclusions,'POST','explicit-second-writer');realHTTPAssert(response.status()===status,'HTTP_WRITE_REJECTED');return value;
  };
  const uiSave=async(observed,manual)=>{
    await beforeMutation();uiTicket={observed,manual};
    try{
      const pending=page.waitForResponse(response=>response.url()===config.origin+pathExclusions&&response.request().method()==='POST');
      const [response]=await Promise.all([pending,page.locator('#resourceExclusionsContent [data-resource-save]').click()]);
      const value=await record(response,pathExclusions,'POST','ui-receipt');realHTTPAssert(response.status()===200,'HTTP_UI_WRITE_REJECTED');return value;
    }finally{uiTicket=null;}
  };
  const bookend=async(observed,manual)=>{
    await identity();const value=inactiveReceipt(await readJSON(pathExclusions),manual);
    realHTTPAssert(value.revision===observed.revision&&value.exclusion_revision===observed.exclusion_revision,'INACTIVE_READBACK_REVISION_CHANGED');
    reviewUnconfigured(await readJSON(pathReview),observed.revision);
    const status=await readJSON('/api/v1/status'),services=await readJSON('/api/v1/services'),autonomy=await readJSON('/api/v1/autonomy');
    realHTTPAssert(status.safe_mode===true&&status.live_active===false&&status.revision===observed.revision&&status.applied_revision===initial.status.applied_revision,'QA_DATAPLANE_CHANGED');
    realHTTPAssert(value.applied_revision===initial.exclusions.applied_revision&&JSON.stringify(value.applied_effective)===JSON.stringify(initial.exclusions.applied_effective),'INACTIVE_APPLIED_CHANGED');
    realHTTPAssert(serviceIntent(services)===serviceIntent(initial.services),'QA_SERVICE_INTENT_CHANGED');
    realHTTPAssert(JSON.stringify(autonomy.policy)===JSON.stringify(initial.autonomy.policy),'QA_AUTOMATION_CHANGED');
    return value;
  };
  const step=async(name,action)=>{stage=name;await action();realHTTPAssert(report.browser_errors===0&&report.blocked_requests===0,'BROWSER_BOUNDARY_FAILED');report.steps.push({scenario:name,status:'passed'});console.log('PASS '+name);};
  const enterExclusions=async()=>{
    await page.locator('.nav[data-view="devices"]').click();await page.waitForFunction(()=>state.currentView==='devices'&&!panelLoad.request);
    await page.locator('#interfaceSubnav [data-rz-nav="exclusions"]').click();
    await page.waitForFunction(()=>state.currentView==='exclusions'&&!panelLoad.request&&state.dataLoad.resourceExclusions?.phase==='ready'&&!resourceExclusionsEditor.pending);
  };
  const add=async(kind,value)=>{
    await page.locator('#resourceExclusionKind').selectOption(kind);
    if(kind==='service')await page.locator('#resourceExclusionValue').selectOption(value);else await page.locator('#resourceExclusionValue').fill(value);
    await page.locator('#resourceExclusionAddForm button[type="submit"]').click();
  };
  const readUIBase=()=>page.evaluate(()=>({revision:resourceExclusionsEditor.base.revision,exclusion_revision:resourceExclusionsEditor.base.exclusion_revision}));
  const waitSaved=()=>page.waitForFunction(()=>!resourceExclusionsEditor.pending&&!resourceExclusionsEditor.dirty&&!resourceExclusionsEditor.unknown&&!resourceExclusionsEditor.conflict);
  try{
    browser=await chromium.launch({executablePath:config.chrome,headless:true});
    context=await browser.newContext({viewport:{width:1280,height:900},serviceWorkers:'block',...(config.session?{storageState:config.session}:{})});
    if(config.setupAccount){
      stage='verify-fresh-account';const token=readFileSync(config.setupToken,'utf8').trim();realHTTPAssert(/^[A-Za-z0-9_+/=-]{32,128}$/.test(token),'QA_RECOVERY_TOKEN_INVALID');
      const headers={Authorization:'Bearer '+token,Origin:config.origin};realHTTPIdentity(await readJSON('/api/v1/panel/snapshot',headers),config.instance);
      const auth=await readJSON('/api/v1/auth/status',headers);realHTTPAssert(auth.setup_required===true&&auth.using_recovery_key===true,'QA_FRESH_ACCOUNT_REQUIRED');
      report.cleanup_required=true;const response=await context.request.post(config.origin+'/api/v1/auth/setup',{headers,data:{username:config.username,password:config.password},maxRedirects:0,maxRetries:0,timeout:30000});
      report.requests.push({method:'POST',path:'/api/v1/auth/setup',status:response.status(),code:null,source:'explicit-QA-account-setup'});realHTTPAssert(response.status()===200,'QA_ACCOUNT_SETUP_REJECTED');
    }
    stage='authenticate';if(!config.session){const response=await context.request.post(config.origin+'/api/v1/auth/login',{headers:{Origin:config.origin},data:{username:config.username,password:config.password},maxRedirects:0,maxRetries:0,timeout:30000});report.requests.push({method:'POST',path:'/api/v1/auth/login',status:response.status(),code:null,source:'authentication'});realHTTPAssert(response.status()===200,'QA_LOGIN_REJECTED');}
    stage='verify-disposable-inactive-instance';realHTTPAssert((await readJSON('/api/v1/auth/status')).authenticated===true,'QA_SESSION_REQUIRED');
    const snapshot=await identity(),inventory=await readJSON('/api/v1/panel/inventory'),status=await readJSON('/api/v1/status'),services=await readJSON('/api/v1/services'),nodes=await readJSON('/api/v1/nodes'),recovery=await readJSON('/api/v1/components/recovery');
    realHTTPPrivateFixture({snapshot,inventory,status,services,nodes,recovery},config.instance);
    const autonomy=await readJSON('/api/v1/autonomy');realHTTPAssert(autonomy.policy?.enabled===false&&autonomy.policy.application?.mode==='off'&&autonomy.policy.components?.mode==='off','QA_AUTOMATION_OFF_REQUIRED');
    expected=inactiveReceipt(await readJSON(pathExclusions),[]);reviewUnconfigured(await readJSON(pathReview),expected.revision);
    realHTTPAssert(status.revision===expected.revision&&revision(status.applied_revision),'INACTIVE_INITIAL_REVISION_MISMATCH');
    initial={status,services,autonomy,exclusions:expected};verified=true;
    await context.route('**/*',async route=>{
      const request=route.request();let body=null;try{body=request.postDataJSON();}catch(_){/* Invalid data is refused by the boundary. */}
      const decision=inactiveBrowserDecision(config.origin,request.url(),request.method(),body,uiTicket);
      if(decision){report.blocked_requests++;const url=new URL(request.url());report.blocked.push({method:['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].includes(request.method())?request.method():'OTHER',path:readPaths.has(url.pathname)?url.pathname:url.pathname.startsWith('/api/')?'/api/unknown':'asset',code:decision});await route.abort('blockedbyclient');}
      else{if(request.method()==='POST')uiTicket.consumed=true;await route.continue();}
    });
    page=await context.newPage();page.setDefaultTimeout(30000);page.on('pageerror',()=>report.browser_errors++);
    page.on('request',request=>{const url=new URL(request.url());if(url.origin!==config.origin||!url.pathname.startsWith('/api/'))return;const entry={method:request.method(),path:readPaths.has(url.pathname)?url.pathname:'/api/unknown',status:null,code:null,source:'browser'};records.set(request,entry);browserRequests.push(entry);report.requests.push(entry);});
    page.on('response',response=>{const entry=records.get(response.request());if(entry)entry.status=response.status();});
    stage='open-genuine-embedded-UI';const document=await page.goto(config.origin,{waitUntil:'domcontentloaded'});realHTTPAssert(document?.status()===200,'DOCUMENT_REJECTED');
    const csp=document.headers()['content-security-policy'];realHTTPAssert(csp?.includes("default-src 'self'")&&csp.includes("frame-ancestors 'none'"),'CSP_REQUIRED');
    await page.waitForFunction(()=>state.authenticated&&!panelLoad.request);
    await step('inactive editor and both service lists are navigation-only',async()=>{
      const start=browserRequests.length;await enterExclusions();
      assert.equal(await page.locator('#resourceExclusionKind').isEnabled(),true);assert.equal(await page.locator('#resourceRussianEnabled').isEnabled(),false);assert.equal(await page.locator('#resourceRussianAuto').isEnabled(),false);
      await page.locator('.nav[data-view="services"]').click();await page.waitForFunction(()=>state.currentView==='services'&&!panelLoad.request&&state.dataLoad.resourceExclusions?.phase==='ready');
      assert.equal(await page.locator('#resourceBypassTab').textContent(),'Обходить');assert.equal(await page.locator('#resourceExcludedTab').isVisible(),true);await page.locator('#resourceExcludedTab').click();
      assert.match(await page.locator('#ui3ServiceCatalog').textContent(),/Сохранение списка не включает обход/);assert.equal(browserRequests.slice(start).filter(r=>r.method!=='GET').length,0);
      await enterExclusions();await bookend(expected,[]);
    });
    const manual=[{kind:'service',value:services[0].id},{kind:'exact',value:'ui-inactive.example'}];
    await step('manual-only Save has one POST and independent GET without scope or consent',async()=>{
      const draftStart=browserRequests.length;await add(manual[0].kind,manual[0].value);await add(manual[1].kind,manual[1].value);assert.equal(browserRequests.slice(draftStart).filter(r=>r.method!=='GET').length,0);
      const start=browserRequests.length,before=expected;const receipt=inactiveReceipt(await uiSave(before,manual),manual);await waitSaved();
      assert.equal(receipt.revision,before.revision+1);assert.equal(receipt.exclusion_revision,before.exclusion_revision+1);expected=receipt;
      assert.equal(browserRequests.slice(start).filter(r=>r.method==='POST'&&r.path===pathExclusions).length,1);assert(browserRequests.slice(start).some(r=>r.method==='GET'&&r.path===pathExclusions));
      assert.deepEqual(await readUIBase(),{revision:receipt.revision,exclusion_revision:receipt.exclusion_revision});await bookend(expected,manual);
    });
    await step('real page reload retains manual document while policy and Applied stay unchanged',async()=>{
      const start=browserRequests.length;await page.reload({waitUntil:'domcontentloaded'});await page.waitForFunction(()=>state.authenticated&&!panelLoad.request);await enterExclusions();
      const saved=await page.evaluate(()=>resourceExclusionsEditor.draft);assert.equal(matchImage(saved),matchImage(manual));assert.equal(browserRequests.slice(start).filter(r=>r.method!=='GET').length,0);await bookend(expected,manual);
    });
    const localDraft=[...manual,{kind:'exact',value:'ui-retained-draft.example'}],secondManual=[...manual,{kind:'exact',value:'ui-second-writer.example'}];
    await step('genuine second writer and stale 409 preserve UI draft until explicit reset',async()=>{
      await add('exact','ui-retained-draft.example');const stale=expected,base=await readUIBase();
      expected=inactiveReceipt(await writeManual(stale,secondManual),secondManual);assert.equal(expected.revision,stale.revision+1);assert.equal(expected.exclusion_revision,stale.exclusion_revision+1);
      const rejected=await writeManual(stale,localDraft,409);assert.equal(rejected.code,'NETWORK_POLICY_EXCLUSIONS_CHANGED');assert.equal(rejected.live_applied,false);
      const start=browserRequests.length;await page.locator('#resourceExclusionsContent [data-panel-refresh]').click();await page.waitForFunction(()=>!panelLoad.request&&resourceExclusionsEditor.conflict&&resourceExclusionsEditor.dirty);
      assert.deepEqual(await readUIBase(),base);assert.equal(matchImage(await page.evaluate(()=>resourceExclusionsEditor.draft)),matchImage(localDraft));assert.equal(await page.locator('#resourceExclusionsContent [data-resource-save]').isEnabled(),false);assert.equal(browserRequests.slice(start).filter(r=>r.method!=='GET').length,0);
      await bookend(expected,secondManual);await page.locator('#resourceExclusionsContent [data-resource-reset]').click();await waitSaved();assert.equal(matchImage(await page.evaluate(()=>resourceExclusionsEditor.draft)),matchImage(secondManual));
    });
    await step('explicit manual clear returns to the absent inactive document and verifies after reload',async()=>{
      const draftStart=browserRequests.length;while(await page.locator('#resourceExclusionsContent [data-resource-remove]').count())await page.locator('#resourceExclusionsContent [data-resource-remove]').first().click();assert.equal(browserRequests.slice(draftStart).filter(r=>r.method!=='GET').length,0);
      const before=expected,start=browserRequests.length;expected=inactiveReceipt(await uiSave(before,[]),[]);await waitSaved();assert.equal(expected.revision,before.revision+1);assert.equal(expected.exclusion_revision,0);assert.equal(expected.resource_exclusions,null,'an emptied list must not keep the document that closes ordinary Apply');
      assert.equal(browserRequests.slice(start).filter(r=>r.method==='POST'&&r.path===pathExclusions).length,1);assert(browserRequests.slice(start).some(r=>r.method==='GET'&&r.path===pathExclusions));await bookend(expected,[]);
      await page.reload({waitUntil:'domcontentloaded'});await page.waitForFunction(()=>state.authenticated&&!panelLoad.request);await enterExclusions();assert.equal(await page.evaluate(()=>resourceExclusionsEditor.draft.length),0);assert.equal(await page.locator('#resourceRussianEnabled').isEnabled(),false);assert.equal(await page.locator('#resourceRussianAuto').isEnabled(),false);await bookend(expected,[]);
    });
    stage='final-boundary';await identity();realHTTPAssert(report.browser_errors===0&&report.blocked_requests===0,'BROWSER_BOUNDARY_FAILED');
    realHTTPAssert(browserRequests.every(row=>row.method==='GET'||row.method==='POST'&&row.path===pathExclusions),'UNDECLARED_BROWSER_MUTATION');
    realHTTPAssert(browserRequests.filter(row=>row.method==='POST').length===2,'INACTIVE_UI_POST_COUNT_CHANGED');
    realHTTPAssert(expected.revision===initial.exclusions.revision+3&&expected.exclusion_revision===0,'INACTIVE_REVISION_ADVANCE_CHANGED');
    report.final={policy_revision:0,config_revision:expected.revision,exclusion_revision:expected.exclusion_revision,manual_count:0,
      scope_unchanged:true,consent_unchanged:true,applied_unchanged:true,live_unchanged:true,ru_disabled:true,ui_posts:2,second_writer_posts:2};report.status='passed';
  }catch(error){report.status='failed';report.failure=realHTTPFailure(error,stage);}
  finally{
    if(browser)try{await browser.close();}catch(_){report.status='failed';report.failure||={stage:'close-browser',status:'failed',code:'BROWSER_CLOSE_FAILED'};}
    writeFileSync(join(directory,'result.json'),JSON.stringify(report,null,2));
  }
  if(report.status==='failed')console.error('FAIL '+report.failure.code);
  return {directory,report};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{const result=await runInactiveExclusionsUI(inactiveUISettings(process.env,process.argv.slice(2)));console.log('Status '+result.report.status);console.log('Local report: '+join(result.directory,'result.json'));if(result.report.status!=='passed')process.exitCode=1;}
  catch(error){console.error('FAIL '+realHTTPFailure(error,'settings').code);process.exitCode=1;}
}
