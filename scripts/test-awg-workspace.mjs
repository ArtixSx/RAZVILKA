import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const read=n=>readFileSync(new URL('../'+n,import.meta.url),'utf8');
const html=read('cmd/razvilka/web/index.html'),js=read('cmd/razvilka/web/awg-workspace.js'),app=read('cmd/razvilka/web/app.js');
let passed=0;function test(n,f){f();passed++;console.log('PASS '+n);}
for(const id of ['awgWorkspace','awgProfilePane','awgWarpIntro','awgImportDialog','awgPreviewImport','awgStageImport','awgCanary','awgCanaryService','awgCancelCanary','warpAllowAccountRefresh','warpHealthInterval'])test('visible control '+id,()=>assert.ok(html.includes(`id="${id}"`)));
test('one generator surface',()=>assert.equal((html.match(/id="warpManager"/g)||[]).length,1));
test('local API only',()=>{assert.doesNotMatch(js,/fetch\(['"]https?:|iframe|window\.fetch\s*=/);assert.match(js,/\/api\/v1\/amneziawg\/preview/);});
test('no browser scheduler',()=>assert.doesNotMatch(js,/setInterval\s*\(/));
test('secret never stored in browser preferences',()=>assert.doesNotMatch(js,/localStorage|sessionStorage/));
test('preview before stage',()=>assert.match(js,/expected_sha256:intent\.result\.preview\.sha256,base_sha256:intent\.result\.base_sha256/));
test('staging explicit consent',()=>assert.match(js,/confirm:'STAGE_AWG_PROFILE'/));
test('explicit bounded canary',()=>{assert.match(js,/confirm:'PROBE_AWG_PROFILE'/);assert.match(js,/125000/);assert.match(js,/probe\?\.abort\(\)/);});
test('Safe Mode prevents UI probe',()=>assert.match(js,/state\.status\?\.safe_mode/));
test('cannot silently apply import',()=>assert.match(js,/!result\.staged\|\|result\.live_applied/));
test('auth clears secret input',()=>assert.match(js,/awgUI\.epoch\+\+[\s\S]*awgImportText'\)\.value=''/));
test('separate account refresh consent',()=>{assert.match(app,/allow_account_refresh/);assert.match(html,/warpAllowAccountRefresh/);});
test('dirty editor preserved',()=>assert.match(js,/state\.engineEditorDirty/));
test('no fake ready',()=>assert.match(js,/!d\?\.syntax_valid/));
test('proof bound to profile service runtime and time',()=>{assert.match(js,/base_sha256,service/);assert.match(js,/loaded_module_version/);assert.match(js,/Date.now\(\)<awgUI.proof.until/);});
console.log(JSON.stringify({suite:'awg-workspace-contract',passed}));

const wgCode=read('cmd/razvilka/web/wireguard-profiles-ui.js');
const wgHash='a'.repeat(64),wgNextHash='b'.repeat(64);
const wgView=(id='home',name='Дом')=>({profile:{id,name,revision:wgHash,engine:'wireguard',verification:'syntax-only'},route:'wireguard:'+id,reserve:true,references:[]});
const flush=()=>new Promise(resolve=>setImmediate(resolve));
const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};};
function wgFixture(view='engineconfig'){
 const state={authenticated:true,currentView:view,selectedEngine:'wireguard',services:[]},elements=new Map(),listeners=new Map(),calls=[],confirmations=[];
 const $=id=>{if(!elements.has(id))elements.set(id,{value:'',hidden:id!=='#authScreen',disabled:false,innerHTML:'',textContent:'',open:false,files:[],focus(){},replaceChildren(){this.innerHTML='';},addEventListener(name,callback){this[name]=callback;}});return elements.get(id);};
 $('#authScreen').hidden=true;
 let profiles=[wgView()],responder=async(path,options)=>{
  if(!options.method)return {profiles,config_revision:7};
  const body=JSON.parse(options.body);
  if(options.method==='DELETE'){profiles=[];return {deleted:true,live_applied:false};}
  const view=wgView(body.id||path.split('/').at(-1),body.name);view.profile.revision=wgNextHash;profiles=[view];return {saved:true,live_applied:false,profile:view};
 };
 const ctx=vm.createContext({state,$,document:{hidden:false,addEventListener(name,callback){listeners.set(name,callback);}},AbortController,TextEncoder,Set,encodeURIComponent,
  esc:v=>String(v??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),
  api:async(path,options={})=>{calls.push({path,options});return responder(path,options);},
  askConfirmation:async(...args)=>{confirmations.push(args);return true;},invalidateEngineProgress(){},
 });
 vm.runInContext(wgCode,ctx);const model=vm.runInContext('wgProfiles',ctx);
 return {ctx,state,$,model,calls,listeners,confirmations,set:fn=>responder=fn,profiles:()=>profiles};
}
const ready=async f=>{while(f.model.read)await flush();};
const fill=(f,id='new')=>{f.$('#wgProfileID').value=id;f.$('#wgProfileName').value='Личный';f.$('#wgProfileContent').value='[Interface]\nPrivateKey = synthetic-test-private\n[Peer]\nPublicKey = synthetic-test-public';};
let f=wgFixture();await ready(f);
assert.equal(f.calls.length,1,'opening WG workspace repeats catalog reads');
assert.equal(f.$('#wgProfileSave').disabled,false);
assert.match(f.$('#wgProfileList').innerHTML,/Сохранён без назначений/);
assert.doesNotMatch(f.$('#wgProfileList').innerHTML,/доступ подтверждён|автоматический резерв|Применено/);
fill(f);await f.ctx.wgProfilesSave();
assert.equal(f.calls.filter(call=>call.options.method==='POST').length,1);
assert.deepEqual(Object.keys(JSON.parse(f.calls.find(call=>call.options.method==='POST').options.body)).sort(),['content','id','name']);
assert.equal(f.$('#wgProfileContent').value,'','accepted save retained a private key');
assert.match(f.model.message,/Проверен только синтаксис/);
f.ctx.wgProfilesEdit('new');assert.equal(f.$('#wgProfileContent').value,'','replace read a private profile back into the form');
assert.equal(f.$('#wgProfileID').disabled,true);assert.equal(f.$('#wgProfileFormDisclosure').open,true);
f.$('#wgProfileContent').value='synthetic replacement';await f.ctx.wgProfilesSave();
const replacement=f.calls.find(call=>call.options.method==='PUT');
assert.equal(replacement.path,'/api/v1/wireguard/profiles/new');
assert.deepEqual(JSON.parse(replacement.options.body),{name:'Личный',content:'synthetic replacement',expected_revision:wgNextHash});
await f.ctx.wgProfilesDelete('new');
assert.deepEqual(JSON.parse(f.calls.find(call=>call.options.method==='DELETE').options.body),{expected_revision:wgNextHash});
assert.equal(f.model.profiles.length,0);assert.equal(f.confirmations.length,1);
assert.equal(f.calls.some(call=>/apply|testlab|nodes|services/.test(call.path)),false,'profile CRUD gained route/check authority');

f=wgFixture();await ready(f);
const secret='extra-private-response';
f.set(async()=>({profiles:[{...wgView(),content:secret,profile:{...wgView().profile,private_key:secret}}],config_revision:7}));
await f.ctx.refreshWireGuardProfiles();assert.doesNotMatch(JSON.stringify(f.model),new RegExp(secret),'public metadata copied secret response fields');
f.model.profiles[0].references=[{kind:'draft',service_id:'telegram'}];f.ctx.renderWireGuardProfiles();
assert.match(f.$('#wgProfileList').innerHTML,/data-wg-delete="home" disabled/);
await f.ctx.wgProfilesDelete('home');assert.equal(f.confirmations.length,0,'referenced profile offered deletion');

for(const error of [Object.assign(new Error('private-message'),{status:404}),Object.assign(new Error('private-message'),{status:409,payload:{references:[{kind:'dataplane-committed',service_id:'telegram'}]}}),Object.assign(new Error('private-message'),{status:503,payload:{outcome:'unconfirmed',restoration_confirmed:true}}),new Error('private-message')]){
 f=wgFixture();await ready(f);fill(f);
 f.set(async()=>{throw error;});await f.ctx.wgProfilesSave();
 assert.equal(f.model.needsRead,true);assert.equal(f.$('#wgProfileSave').disabled,true);assert.equal(f.model.profiles[0].profile.id,'home');
 assert.match(f.$('#wgProfileContent').value,/synthetic-test-private/,'failed save erased the editable form');
 assert.doesNotMatch(f.model.message,/private-message/,'server error echoed private data');
 const count=f.calls.length;await f.ctx.wgProfilesSave();assert.equal(f.calls.length,count,'unknown/CAS outcome replayed without readback');
 f.set(async()=>({profiles:[wgView()],config_revision:7}));await f.ctx.refreshWireGuardProfiles();assert.equal(f.$('#wgProfileSave').disabled,false);
}
for(const tamper of [result=>({...result,live_applied:true}),result=>({...result,saved:false}),result=>({...result,outcome:'unconfirmed'}),result=>({...result,profile:wgView('foreign','Личный')}),result=>({...result,profile:{...wgView('new','Личный'),profile:{...wgView('new','Личный').profile,verification:'service-confirmed'}}})]){
 f=wgFixture();await ready(f);fill(f);f.set(async()=>tamper({saved:true,live_applied:false,profile:wgView('new','Личный')}));await f.ctx.wgProfilesSave();
 assert.equal(f.model.needsRead,true,'invalid saved receipt enabled another write');assert.equal(f.$('#wgProfileSave').disabled,true);
}
f=wgFixture();await ready(f);fill(f);const writing=deferred();f.set(()=>writing.promise);
const save=f.ctx.wgProfilesSave();await f.ctx.wgProfilesSave();
assert.equal(f.calls.filter(call=>call.options.method==='POST').length,1,'double click created two profiles');
f.state.currentView='services';f.listeners.get('razvilka:view-change')({detail:'services'});
assert.equal(f.$('#wgProfileContent').value,'','leaving workspace retained the private form');
writing.resolve({saved:true,live_applied:false,profile:wgView('new','Личный')});await save;
f.state.currentView='engineconfig';f.ctx.renderWireGuardProfiles();
assert.equal(f.model.needsRead,true,'late save response cleared the unknown outcome');assert.equal(f.$('#wgProfileSave').disabled,true);

f=wgFixture();await ready(f);fill(f);const reading=deferred();f.set(()=>reading.promise);
const readBack=f.ctx.refreshWireGuardProfiles();f.listeners.get('razvilka:auth-required')();f.$('#authScreen').hidden=false;
reading.resolve({profiles:[wgView('foreign')],config_revision:8});await readBack;
assert.equal(f.model.profiles.length,0);assert.equal(f.$('#wgProfileContent').value,'');assert.equal(f.model.loaded,false,'late read revived a logged-out catalog');
assert.doesNotMatch(wgCode,/localStorage|sessionStorage|setInterval|\/api\/v1\/apply|\/api\/v1\/testlab/);
f=wgFixture('overview');assert.equal(f.calls.length,0,'hidden WG workspace read its catalog');
f.ctx.document.hidden=true;f.state.currentView='engineconfig';f.ctx.renderWireGuardProfiles();assert.equal(f.calls.length,0,'background document read WG catalog');
f.ctx.document.hidden=false;await f.ctx.refreshWireGuardProfiles();assert.equal(f.calls.length,1);
const fileReading=deferred();f.$('#wgProfileFile').files=[{size:20,text:()=>fileReading.promise}];
const fileRead=f.$('#wgProfileFile').change();f.ctx.wgProfilesClearForm();fileReading.resolve('late synthetic private key');await fileRead;
assert.equal(f.$('#wgProfileContent').value,'','late file read restored a cleared private form');
console.log('PASS named WG CRUD: typed metadata, exact CAS payloads, references, unknown receipts, single-flight and auth/navigation fences');
const {realWGSettings,realWGDecision}=await import('./test-wireguard-profile-http-browser.mjs');
const realWGEnv={RAZVILKA_WG_UI_URL:'http://127.0.0.1:18851',RAZVILKA_WG_UI_FIXTURE:'empty-private',RAZVILKA_WG_UI_CHROME:'/installed/chrome',RAZVILKA_WG_UI_SESSION:'/private/session.json'};
assert.equal(realWGSettings(realWGEnv).origin,'http://127.0.0.1:18851');
for(const patch of [{RAZVILKA_WG_UI_FIXTURE:'loaded'},{RAZVILKA_WG_UI_URL:'http://user:pass@localhost/'},{RAZVILKA_WG_UI_URL:'http://localhost/path'},{RAZVILKA_WG_UI_USERNAME:'test',RAZVILKA_WG_UI_PASSWORD:'synthetic'}])assert.throws(()=>realWGSettings({...realWGEnv,...patch}));
const origin=realWGEnv.RAZVILKA_WG_UI_URL,id='ui-wg-test';
assert.equal(realWGDecision(origin,id,origin+'/api/v1/wireguard/profiles','POST'),true);
for(const method of ['PUT','DELETE'])assert.equal(realWGDecision(origin,id,origin+'/api/v1/wireguard/profiles/'+id,method),true);
for(const [url,method] of [['/api/v1/apply','POST'],['/api/v1/testlab/routes','POST'],['/api/v1/auth/setup','POST'],['/api/v1/service-control/stop','POST'],['/api/v1/wireguard/profiles/foreign','DELETE'],['/api/v1/components?refresh=true','GET']])assert.equal(realWGDecision(origin,id,origin+url,method),false);
assert.equal(realWGDecision(origin,id,'https://external.invalid/','GET'),false);
console.log('PASS real WG harness settings and request boundary; actual Handler CRUD remains the coordinator gate');
