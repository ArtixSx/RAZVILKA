// Opt-in real CRUD against an EXISTING empty, private Safe Mode app fixture.
// Optional --service-draft checks real named service PUT; no setup/probe/Apply.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {mkdirSync,mkdtempSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {failureDiagnostic} from './measure-ui-http-browser.mjs';

export function realWGSettings(env) {
 const url=new URL(env.RAZVILKA_WG_UI_URL);
 assert(['http:','https:'].includes(url.protocol)&&!url.username&&!url.password&&!url.search&&!url.hash&&url.pathname==='/','Supply an existing private fixture HTTP(S) origin');
 assert(env.RAZVILKA_WG_UI_FIXTURE==='empty-private','Declare the existing fixture empty-private');
 assert(env.RAZVILKA_WG_UI_CHROME,'Supply installed Chrome; no downloads');
 const session=env.RAZVILKA_WG_UI_SESSION,credentials=!!env.RAZVILKA_WG_UI_USERNAME&&!!env.RAZVILKA_WG_UI_PASSWORD;
 assert(!!session!==credentials,'Supply either an existing session or username/password');
 return {origin:url.origin,chrome:resolve(env.RAZVILKA_WG_UI_CHROME),session:session?resolve(session):null,username:env.RAZVILKA_WG_UI_USERNAME,password:env.RAZVILKA_WG_UI_PASSWORD,
  output:env.RAZVILKA_WG_UI_OUTPUT?resolve(env.RAZVILKA_WG_UI_OUTPUT):null};
}
export function realWGDecision(origin,id,url,method,serviceID=null) {
 const target=new URL(url);
 if(target.origin!==origin)return false;
 if(['GET','HEAD','OPTIONS'].includes(method))return target.searchParams.get('refresh')!=='true'&&target.searchParams.get('force')!=='true';
 return method==='POST'&&['/api/v1/auth/login','/api/v1/wireguard/profiles'].includes(target.pathname)
   ||['PUT','DELETE'].includes(method)&&target.pathname==='/api/v1/wireguard/profiles/'+id
   ||method==='PUT'&&serviceID!==null&&target.pathname==='/api/v1/services/'+encodeURIComponent(serviceID);
}
export function realWGServiceBodyAllowed(body,approved) {
 if(!approved||body?.enabled!==false||!Number.isSafeInteger(body.expected_revision)||!/^wireguard:ui-wg-[a-f0-9]{12}$/.test(body.route||'')||!/^[a-f0-9]{64}$/.test(body.expected_profile_revision||''))return false;
 try{assert.deepEqual(body,approved);return true;}catch(_){return false;}
}
function publicProfile(view,id) {
 assert.equal(view?.profile?.id,id);assert.equal(view.profile.engine,'wireguard');assert.equal(view.profile.verification,'syntax-only');
 assert.match(view.profile.revision,/^[a-f0-9]{64}$/);assert.equal(view.route,'wireguard:'+id);assert.equal(view.reserve,true);assert.deepEqual(view.references,[]);
 assert.deepEqual(Object.keys(view.profile).sort(),['engine','id','name','revision','verification']);
 return view.profile.revision;
}
export async function runRealWG(config,{serviceDraft=false}={}) {
 const {chromium}=createRequire(import.meta.url)('playwright');
 const local=config.output||join(fileURLToPath(new URL('../',import.meta.url)),'.review-local');mkdirSync(local,{recursive:true});
 const directory=mkdtempSync(join(local,'wg-real-ui-')),id='ui-wg-'+randomBytes(6).toString('hex');
 const report={boundary:serviceDraft?'actual authenticated Handler + embedded UI; named WG service draft CAS and lost delivery; no Apply':'actual authenticated Handler + embedded browser UI; syntax-only profile CRUD',started_at:new Date().toISOString(),steps:[],requests:[],blocked:[],browser_errors:0,cleanup_required:false};
 let browser,context,page,stage='launch',attempted=false,loginAllowed=!config.session,approvedRevision=null;
 const path='/api/v1/wireguard/profiles',target=path+'/'+id,requestRecords=new WeakMap();
 const serviceGate={id:null,body:null,drop:false,droppedStatus:null};
 const {privateKey,publicKey}=generateKeyPairSync('x25519');
 const privateBytes=Buffer.from(privateKey.export({format:'jwk'}).d,'base64url').toString('base64');
 const publicBytes=Buffer.from(publicKey.export({format:'jwk'}).x,'base64url').toString('base64');
 const content=port=>`[Interface]\nPrivateKey = ${privateBytes}\nAddress = 10.66.0.2/32\n[Peer]\nPublicKey = ${publicBytes}\nEndpoint = fixture.invalid:${port}\nAllowedIPs = 0.0.0.0/0\n`;
 const guard=()=>assert.equal(report.blocked.length,0,'unexpected action outside the declared WG gate');
 const readJSON=async endpoint=>{const response=await context.request.get(config.origin+endpoint);report.requests.push({method:'GET',path:endpoint,status:response.status(),source:'verification'});assert.equal(response.status(),200);return response.json();};
 try {
  browser=await chromium.launch({executablePath:config.chrome,headless:true});report.browser_version=browser.version();
  context=await browser.newContext({viewport:{width:1280,height:900},...(config.session?{storageState:config.session}:{})});
  page=await context.newPage();page.setDefaultTimeout(45000);page.on('pageerror',()=>report.browser_errors++);
  page.on('request',request=>{if(!request.url().startsWith(config.origin+'/api/'))return;const record={method:request.method(),path:new URL(request.url()).pathname,status:null,source:'browser'};requestRecords.set(request,record);report.requests.push(record);});
  page.on('response',response=>{const record=requestRecords.get(response.request());if(record)record.status=response.status();});
  // Boundary handlers only continue or abort real requests. Never fulfill,
  // replace fetch/API/state, or supply a response/evidence object to the page.
  await page.route('**/*',async route=>{
   const request=route.request(),url=new URL(request.url()),method=request.method();
   let allowed=realWGDecision(config.origin,id,request.url(),method,serviceGate.id);
   if(method==='POST'&&url.pathname==='/api/v1/auth/login'){allowed=allowed&&loginAllowed;loginAllowed=false;}
   if(['POST','PUT','DELETE'].includes(method)&&url.pathname.startsWith(path)){
    try{
     const body=request.postDataJSON();
     if(method==='POST')allowed=allowed&&body.id===id&&body.name==='WG UI fixture'&&body.content===content(51820);
     else if(method==='PUT')allowed=allowed&&body.name==='WG UI fixture updated'&&body.content===content(51821)&&body.expected_revision===approvedRevision;
     else allowed=allowed&&body.expected_revision===approvedRevision;
    }catch(_){allowed=false;}
   }
   let drop=false;
   if(method==='PUT'&&serviceGate.id&&url.pathname==='/api/v1/services/'+encodeURIComponent(serviceGate.id)){
    try{allowed=allowed&&realWGServiceBodyAllowed(request.postDataJSON(),serviceGate.body);}catch(_){allowed=false;}
    if(allowed){drop=serviceGate.drop;serviceGate.body=null;serviceGate.drop=false;}
   }
   if(!allowed){report.blocked.push({method,path:url.origin===config.origin?url.pathname:'external'});await route.abort('blockedbyclient');return;}
   if(drop){
    // One real Handler write completes, then its browser delivery is lost.
    // No response body is read, fulfilled, fabricated or saved.
    const response=await route.fetch({maxRetries:0,maxRedirects:0});serviceGate.droppedStatus=response.status();
    report.requests.push({method,path:url.pathname,status:response.status(),source:'real-handler-delivery-aborted'});
    await route.abort('failed');return;
   }
   await route.continue();
  });
  stage='authenticate';await page.goto(config.origin);
  if(!config.session){await page.locator('#authScreen').waitFor({state:'visible'});await page.locator('#loginUsername').fill(config.username);await page.locator('#loginPassword').fill(config.password);await page.locator('#loginForm button[type="submit"]').click();}
  await page.waitForFunction(()=>state.authenticated&&!panelLoad.request);guard();
  stage='verify-empty-private-fixture';
  const statusBefore=await readJSON('/api/v1/status'),servicesBefore=await readJSON('/api/v1/services'),before=await readJSON(path);
  assert.equal(statusBefore.safe_mode,true);assert.equal(statusBefore.live_active,false);
  assert(servicesBefore.every(service=>!service.enabled&&!service.applied_enabled&&!service.applied_state?.enabled));
  assert.deepEqual(before.profiles,[]);assert(Number.isSafeInteger(before.config_revision));
  report.steps.push({name:'empty private Safe Mode fixture',status:'passed'});
  stage='open-wireguard-workspace';
  await page.locator('.nav[data-view="engines"]').click();await page.locator('[data-engine-disclosure="wireguard-flow"] summary').click();
  await page.locator('[data-engine-step="profile"][data-card-engine="wireguard"]').click();
  await page.waitForFunction(()=>state.currentView==='engineconfig'&&state.selectedEngine==='wireguard'&&wgProfiles.loaded&&!wgProfiles.read&&!wgProfiles.needsRead);
  assert.equal(await page.locator('#wgProfileSave').isEnabled(),true);guard();
  stage='create-via-ui';await page.locator('#wgProfileFormDisclosure summary').click();
  await page.locator('#wgProfileID').fill(id);await page.locator('#wgProfileName').fill('WG UI fixture');await page.locator('#wgProfileContent').fill(content(51820));
  attempted=true;report.cleanup_required=true;
  await page.evaluate(()=>{const form=document.getElementById('wgProfileForm');form.requestSubmit();form.requestSubmit();});
  await page.waitForFunction(id=>!wgProfiles.mutation&&!wgProfiles.read&&!wgProfiles.needsRead&&wgProfiles.profiles.some(view=>view.profile.id===id),id);
  const createRevision=publicProfile(await readJSON(target),id);
  approvedRevision=createRevision;
  assert.equal(report.requests.filter(request=>request.source==='browser'&&request.method==='POST'&&request.path===path).length,1);
  assert.equal(await page.locator('#wgProfileContent').inputValue(),'');
  report.steps.push({name:'create + one POST + real single-profile readback',status:'passed'});guard();
  if(serviceDraft){
   const original=servicesBefore.find(service=>service.id==='youtube'&&!service.custom&&['auto','direct'].includes(service.route));
   assert(original,'Fixture requires disabled built-in youtube with auto/direct intent');serviceGate.id=original.id;
   const servicePath='/api/v1/services/'+encodeURIComponent(original.id),routeID='wireguard:'+id;
   const intent=service=>({id:service.id,enabled:service.enabled,route:service.route,sources:service.sources||[],profile:service.wireguard_profile_revision||'',applied:service.applied_state,applied_sources:service.applied_sources||[],applied_profile:service.applied_wireguard_profile_revision||''});
   const disabled=services=>assert(services.every(service=>!service.enabled&&!service.applied_enabled&&!service.applied_state?.enabled));
   const puts=()=>report.requests.filter(record=>record.source==='browser'&&record.method==='PUT'&&record.path===servicePath);
   const expectBody=(revision,profile,sources=original.sources||[])=>serviceGate.body={enabled:false,route:routeID,sources:[...sources],expected_revision:revision,expected_profile_revision:profile};
   const visible=()=>page.locator('[data-sd-route="'+original.id+'"]');
   const reviewed=()=>visible().evaluate((select,route)=>{const option=[...select.options].find(option=>option.value===route);return {config:Number(select.dataset.configRevision),profile:option?.dataset.profileRevision,disabled:option?.disabled};},routeID);
   const noReplay=async()=>{const count=puts().length;await page.evaluate(serviceID=>serviceDashboardEdit(serviceID,{enabled:false}),original.id);assert.equal(puts().length,count);assert.equal(await visible().isEnabled(),false);guard();};
   const reread=async()=>{
    const start=report.requests.length,count=puts().length;await page.locator('[data-sd-read-draft="'+original.id+'"]').click();
    await page.waitForFunction(serviceID=>!serviceDashboard.edit&&!serviceDashboard.draftUnconfirmed.has(serviceID),original.id);
    const reads=report.requests.slice(start).filter(record=>record.source==='browser');
    for(const endpoint of ['/api/v1/status','/api/v1/services','/api/v1/routes/options'])assert.equal(reads.filter(record=>record.method==='GET'&&record.path===endpoint).length,1);
    assert(reads.every(record=>record.method==='GET'));assert.equal(puts().length,count);guard();
   };
   const rejectSelection=async()=>{
    const count=puts().length;await visible().selectOption(routeID);
    await page.waitForFunction(serviceID=>!serviceDashboard.edit&&serviceDashboard.draftUnconfirmed.has(serviceID),original.id);
    assert.equal(puts().length,count+1);assert.equal(puts().at(-1).status,409);await noReplay();
   };
   const verifiedPut=async(endpoint,data,source)=>{
    const response=await context.request.put(config.origin+endpoint,{headers:{Origin:config.origin},data,maxRetries:0,maxRedirects:0});
    report.requests.push({method:'PUT',path:endpoint,status:response.status(),source});assert.equal(response.status(),200);
   };
   stage='service-open-reviewed-option';await page.locator('.nav[data-view="services"]').click();
   await page.waitForFunction(()=>state.currentView==='services'&&!panelLoad.request&&state.dataLoad.routeOptions?.phase==='ready');
   if(!await page.locator('#ui3ServiceExpert').evaluate(element=>element.open))await page.locator('#ui3ServiceExpert > summary').click();
   await page.locator('#serviceSearch').fill(original.name);await page.locator('[data-sd-expand="'+original.id+'"]').click();
   const first=await reviewed();assert.equal(first.profile,createRevision);assert.equal(first.config,statusBefore.revision);assert.equal(first.disabled,false);
   stage='service-real-profile-drift';await verifiedPut(target,{name:'WG UI fixture updated',content:content(51821),expected_revision:createRevision},'profile-drift');
   const nextRevision=publicProfile(await readJSON(target),id);assert.notEqual(nextRevision,createRevision);approvedRevision=nextRevision;
   expectBody(first.config,first.profile);await rejectSelection();
   assert.deepEqual(intent((await readJSON('/api/v1/services')).find(service=>service.id===original.id)),intent(original));
   await reread();const second=await reviewed();assert.equal(second.profile,nextRevision);assert.equal(second.config,first.config);
   report.steps.push({name:'real stale profile409; intent unchanged; explicit three GETs without replay',status:'passed'});
   stage='service-real-config-drift';await verifiedPut(servicePath,{enabled:false,route:'direct',sources:original.sources||[]},'config-drift');
   const driftStatus=await readJSON('/api/v1/status');assert(driftStatus.revision>second.config);assert.equal(driftStatus.safe_mode,true);assert.equal(driftStatus.live_active,false);
   expectBody(second.config,second.profile);await rejectSelection();
   const drifted=(await readJSON('/api/v1/services')).find(service=>service.id===original.id);assert.equal(drifted.route,'direct');assert.equal(drifted.wireguard_profile_revision||'','');
   await reread();const current=await reviewed();assert.equal(current.config,driftStatus.revision);assert.equal(current.profile,nextRevision);
   report.steps.push({name:'real stale config409; direct draft retained; explicit three GETs without replay',status:'passed'});
   stage='service-real-named-draft';const count=puts().length;expectBody(current.config,current.profile);await visible().selectOption(routeID);
   await page.waitForFunction(({serviceID,route,revision})=>!serviceDashboard.edit&&!serviceDashboard.draftUnconfirmed.has(serviceID)&&state.services.some(service=>service.id===serviceID&&service.route===route&&service.wireguard_profile_revision===revision),{serviceID:original.id,route:routeID,revision:nextRevision});
   assert.equal(puts().length,count+1);assert.equal(puts().at(-1).status,200);
   const saved=(await readJSON('/api/v1/services')).find(service=>service.id===original.id);assert.equal(saved.enabled,false);assert.equal(saved.route,routeID);assert.equal(saved.wireguard_profile_revision,nextRevision);
   assert.deepEqual(saved.applied_state,original.applied_state);assert.deepEqual(saved.applied_sources||[],original.applied_sources||[]);assert.equal(saved.applied_wireguard_profile_revision||'',original.applied_wireguard_profile_revision||'');
   report.steps.push({name:'real UI PUT both CAS revisions; disabled named draft readback; applied state unchanged',status:'passed'});guard();
   stage='service-real-lost-delivery';await page.locator('[data-sd-scope="'+original.id+'"]').click();
   await page.locator('#serviceScopeMode').selectOption('selected');await page.locator('#serviceScopeSources').fill('192.0.2.40/32');
   const scopeStatus=await readJSON('/api/v1/status');expectBody(scopeStatus.revision,nextRevision,['192.0.2.40/32']);serviceGate.drop=true;
   await page.locator('#serviceScopeForm button[type="submit"]').click();
   await page.waitForFunction(serviceID=>serviceDashboard.draftUnconfirmed.has(serviceID),original.id);assert.equal(serviceGate.droppedStatus,200);
   await page.locator('#serviceScopeCancel').click();await noReplay();
   const stored=(await readJSON('/api/v1/services')).find(service=>service.id===original.id);assert.equal(stored.enabled,false);assert.equal(stored.route,routeID);assert.equal(stored.wireguard_profile_revision,nextRevision);assert.deepEqual(stored.sources,['192.0.2.40/32']);assert.deepEqual(stored.applied_state,original.applied_state);
   await reread();assert.deepEqual(await page.evaluate(serviceID=>state.services.find(service=>service.id===serviceID).sources,original.id),['192.0.2.40/32']);
   report.steps.push({name:'real scope PUT committed200; delivery aborted; unknown fence; explicit GETs without replay',status:'passed'});
   stage='service-private-fixture-cleanup';await verifiedPut(servicePath,{enabled:false,route:original.route,sources:original.sources||[]},'fixture-cleanup');
   assert.deepEqual(intent((await readJSON('/api/v1/services')).find(service=>service.id===original.id)),intent(original));
   await page.locator('.nav[data-view="engines"]').click();const disclosure=page.locator('[data-engine-disclosure="wireguard-flow"]');if(!await disclosure.evaluate(element=>element.open))await disclosure.locator('summary').click();
   await page.locator('[data-engine-step="profile"][data-card-engine="wireguard"]').click();
   await page.waitForFunction(()=>state.currentView==='engineconfig'&&state.selectedEngine==='wireguard'&&wgProfiles.loaded&&!wgProfiles.read&&!wgProfiles.needsRead);
   publicProfile(await readJSON(target),id);await page.locator('[data-wg-delete="'+id+'"]').click();await page.locator('#actionDialogConfirm').click();
   await page.waitForFunction(id=>!wgProfiles.mutation&&!wgProfiles.read&&!wgProfiles.needsRead&&!wgProfiles.profiles.some(view=>view.profile.id===id),id);
   assert.deepEqual((await readJSON(path)).profiles,[]);const absent=await context.request.get(config.origin+target);report.requests.push({method:'GET',path:target,status:absent.status(),source:'verification'});assert.equal(absent.status(),404);
   const finalStatus=await readJSON('/api/v1/status'),finalServices=await readJSON('/api/v1/services');assert.equal(finalStatus.safe_mode,true);assert.equal(finalStatus.live_active,false);disabled(finalServices);
   assert.deepEqual(finalServices.map(intent),servicesBefore.map(intent));assert.equal(puts().length,4);assert.equal(report.browser_errors,0);guard();
   report.cleanup_required=false;report.steps.push({name:'original disabled intent restored; profile deleted; empty404; applied/network unchanged',status:'passed'});
   return report;
  }
  stage='replace-via-ui';await page.locator('[data-wg-replace="'+id+'"]').click();
  assert.equal(await page.locator('#wgProfileContent').inputValue(),'');assert.equal(await page.locator('#wgProfileID').isEnabled(),false);
  await page.locator('#wgProfileName').fill('WG UI fixture updated');await page.locator('#wgProfileContent').fill(content(51821));await page.locator('#wgProfileSave').click();
  await page.waitForFunction(id=>!wgProfiles.mutation&&!wgProfiles.read&&!wgProfiles.needsRead&&wgProfiles.profiles.some(view=>view.profile.id===id&&view.profile.name==='WG UI fixture updated'),id);
  const replaced=await readJSON(target),updatedRevision=publicProfile(replaced,id);assert.notEqual(updatedRevision,createRevision);
  approvedRevision=updatedRevision;
  assert.equal(await page.locator('#wgProfileContent').inputValue(),'');
  report.steps.push({name:'replace + changed revision + real readback',status:'passed'});guard();
  stage='real-stale-cas';
  const conflict=await context.request.put(config.origin+target,{headers:{Origin:config.origin},data:{name:'WG UI rejected stale revision',content:content(51820),expected_revision:createRevision}});
  report.requests.push({method:'PUT',path:target,status:conflict.status(),source:'negative-cas'});assert.equal(conflict.status(),409);
  assert.equal(publicProfile(await readJSON(target),id),updatedRevision);report.steps.push({name:'stale CAS rejected409; updated profile retained',status:'passed'});
  stage='delete-via-ui';await page.locator('[data-wg-delete="'+id+'"]').click();await page.locator('#actionDialogConfirm').click();
  await page.waitForFunction(id=>!wgProfiles.mutation&&!wgProfiles.read&&!wgProfiles.needsRead&&!wgProfiles.profiles.some(view=>view.profile.id===id),id);
  const after=await readJSON(path);assert.deepEqual(after.profiles,[]);assert.equal(after.config_revision,before.config_revision);
  const absent=await context.request.get(config.origin+target);report.requests.push({method:'GET',path:target,status:absent.status(),source:'verification'});assert.equal(absent.status(),404);
  report.cleanup_required=false;report.steps.push({name:'delete + real empty collection + GET404',status:'passed'});guard();
  stage='unchanged-network-config';const statusAfter=await readJSON('/api/v1/status');assert.equal(statusAfter.revision,statusBefore.revision);assert.equal(statusAfter.safe_mode,true);assert.equal(statusAfter.live_active,false);
  const servicesAfter=await readJSON('/api/v1/services');assert(servicesAfter.every(service=>!service.enabled&&!service.applied_enabled&&!service.applied_state?.enabled));
  assert.equal(report.requests.filter(request=>request.source==='browser'&&request.method==='PUT'&&request.path===target).length,1);
  assert.equal(report.requests.filter(request=>request.source==='browser'&&request.method==='DELETE'&&request.path===target).length,1);
  assert.equal(report.browser_errors,0);report.steps.push({name:'network config revision and disabled services unchanged',status:'passed'});
 }catch(error){report.failure=failureDiagnostic(error,stage);if(attempted){report.fixture_profile_id=id;if(serviceGate.id)report.fixture_service_id=serviceGate.id;}throw error;}
 finally{if(browser)await browser.close();report.finished_at=new Date().toISOString();writeFileSync(join(directory,'result.json'),JSON.stringify(report,null,2));console.log('Real WG UI artifacts: '+directory);}
 return report;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.includes('--help'))console.log('Supply RAZVILKA_WG_UI_URL, FIXTURE=empty-private, CHROME, and SESSION or USERNAME/PASSWORD for an existing disposable Safe Mode app. Optional OUTPUT. Default: six-step CRUD. --service-draft: only named service CAS/lost-delivery gate plus necessary create/cleanup; no Apply or server setup. See UI_RU.md.');
 else try{const serviceDraft=process.argv.includes('--service-draft');await runRealWG(realWGSettings(process.env),{serviceDraft});console.log(serviceDraft?'PASS actual named WG service draft CAS/readback/lost delivery; no Apply/native claim':'PASS actual WG Handler/UI CRUD and stale CAS; syntax-only, no service/Apply claim');}catch(error){const diagnostic=failureDiagnostic(error,'runner');console.error('Real WG UI gate failed; private exception details omitted ('+diagnostic.name+')');process.exitCode=1;}
}
