// Opt-in real CRUD against an EXISTING empty, private Safe Mode app fixture.
// No server/setup, response fixtures, probes, routes, Apply or network changes.
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
export function realWGDecision(origin,id,url,method) {
 const target=new URL(url);
 if(target.origin!==origin)return false;
 if(['GET','HEAD','OPTIONS'].includes(method))return target.searchParams.get('refresh')!=='true'&&target.searchParams.get('force')!=='true';
 return method==='POST'&&['/api/v1/auth/login','/api/v1/wireguard/profiles'].includes(target.pathname)
   ||['PUT','DELETE'].includes(method)&&target.pathname==='/api/v1/wireguard/profiles/'+id;
}
function publicProfile(view,id) {
 assert.equal(view?.profile?.id,id);assert.equal(view.profile.engine,'wireguard');assert.equal(view.profile.verification,'syntax-only');
 assert.match(view.profile.revision,/^[a-f0-9]{64}$/);assert.equal(view.route,'wireguard:'+id);assert.equal(view.reserve,true);assert.deepEqual(view.references,[]);
 assert.deepEqual(Object.keys(view.profile).sort(),['engine','id','name','revision','verification']);
 return view.profile.revision;
}
export async function runRealWG(config) {
 const {chromium}=createRequire(import.meta.url)('playwright');
 const local=config.output||join(fileURLToPath(new URL('../',import.meta.url)),'.review-local');mkdirSync(local,{recursive:true});
 const directory=mkdtempSync(join(local,'wg-real-ui-')),id='ui-wg-'+randomBytes(6).toString('hex');
 const report={boundary:'actual authenticated Handler + embedded browser UI; syntax-only profile CRUD',started_at:new Date().toISOString(),steps:[],requests:[],blocked:[],browser_errors:0,cleanup_required:false};
 let browser,context,page,stage='launch',attempted=false,loginAllowed=!config.session,approvedRevision=null;
 const path='/api/v1/wireguard/profiles',target=path+'/'+id,requestRecords=new WeakMap();
 const {privateKey,publicKey}=generateKeyPairSync('x25519');
 const privateBytes=Buffer.from(privateKey.export({format:'jwk'}).d,'base64url').toString('base64');
 const publicBytes=Buffer.from(publicKey.export({format:'jwk'}).x,'base64url').toString('base64');
 const content=port=>`[Interface]\nPrivateKey = ${privateBytes}\nAddress = 10.66.0.2/32\n[Peer]\nPublicKey = ${publicBytes}\nEndpoint = fixture.invalid:${port}\nAllowedIPs = 0.0.0.0/0\n`;
 const guard=()=>assert.equal(report.blocked.length,0,'unexpected action outside named profile CRUD');
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
   let allowed=realWGDecision(config.origin,id,request.url(),method);
   if(method==='POST'&&url.pathname==='/api/v1/auth/login'){allowed=allowed&&loginAllowed;loginAllowed=false;}
   if(['POST','PUT','DELETE'].includes(method)&&url.pathname.startsWith(path)){
    try{
     const body=request.postDataJSON();
     if(method==='POST')allowed=allowed&&body.id===id&&body.name==='WG UI fixture'&&body.content===content(51820);
     else if(method==='PUT')allowed=allowed&&body.name==='WG UI fixture updated'&&body.content===content(51821)&&body.expected_revision===approvedRevision;
     else allowed=allowed&&body.expected_revision===approvedRevision;
    }catch(_){allowed=false;}
   }
   if(!allowed){report.blocked.push({method,path:url.origin===config.origin?url.pathname:'external'});await route.abort('blockedbyclient');return;}
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
 }catch(error){report.failure=failureDiagnostic(error,stage);if(attempted)report.fixture_profile_id=id;throw error;}
 finally{if(browser)await browser.close();report.finished_at=new Date().toISOString();writeFileSync(join(directory,'result.json'),JSON.stringify(report,null,2));console.log('Real WG UI artifacts: '+directory);}
 return report;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.includes('--help'))console.log('Supply RAZVILKA_WG_UI_URL, FIXTURE=empty-private, CHROME, and SESSION or USERNAME/PASSWORD for an existing disposable Safe Mode app. Optional OUTPUT. Real CRUD only; never provisions or starts a server. See UI_RU.md.');
 else try{await runRealWG(realWGSettings(process.env));console.log('PASS actual WG Handler/UI CRUD and stale CAS; syntax-only, no service/Apply claim');}catch(error){const diagnostic=failureDiagnostic(error,'runner');console.error('Real WG UI gate failed; private exception details omitted ('+diagnostic.name+')');process.exitCode=1;}
}
