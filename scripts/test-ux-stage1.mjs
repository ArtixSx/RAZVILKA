// Runs against full repository files by default. Local excerpt mode is explicit.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const app = readFileSync(process.env.RAZVILKA_TEST_APP || new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
const autonomy = readFileSync(process.env.RAZVILKA_TEST_AUTONOMY || new URL('../cmd/razvilka/web/console-autonomy.js', import.meta.url), 'utf8');
const heartbeat = readFileSync(process.env.RAZVILKA_TEST_HEARTBEAT || new URL('../cmd/razvilka/web/panel-availability.js', import.meta.url), 'utf8');
const extract = name => {const m=app.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`)); assert(m, name);return m[0];};
const flush=()=>new Promise(r=>setImmediate(r));
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const results=[];
async function test(name,fn){let timer;try{await Promise.race([fn(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('test deadline')),4000);})]);results.push({name,status:'passed'});console.log('PASS',name);}catch(e){results.push({name,status:'failed',error:e.message});console.error('FAIL',name,e.stack);}finally{clearTimeout(timer);}}
const helpers=['panelSectionState','panelBusy','panelSnapshotCurrent','schedulePanelRetry','cancelPanelRefresh','renderPanelLoad','renderPanelSection','acceptPanelSection','acceptPanelInventory','settlePanelReads','refreshAll','refreshAfterMutation','loadPanelSnapshot'];
const renderNames=['renderStatus','renderSettings','renderSystem','renderMetrics','renderServices','renderOverviewQuickServices','renderOverviewServices','renderReadiness','renderEngines','renderEngineControl','renderComponents','renderWarpManager','renderSources','renderNodes','renderConnections','renderDevices','renderTestLab','renderEngineLab','renderAudit','renderStrategyLab','renderDNS','renderDNSPlan','renderDNSServiceBindings'];
function fixture(){
 const els=new Map(),calls=[],renders=[],timers=new Map();let serial=0,handler;
 const state={authenticated:true,status:{},services:[],engineConfigs:[],dataLoad:{},loadIssues:[]};
 const panelLoad={generation:0,request:null,controller:null,retryTimer:null,retryCount:0};
 const $=key=>{if(!els.has(key))els.set(key,{hidden:true,value:'',textContent:'',classList:{toggle(){}}});return els.get(key);};
 const ctx={state,panelLoad,$,AbortController,Date,console,document:{hidden:false},
 setTimeout(fn,ms){timers.set(++serial,{fn,ms});return serial;},clearTimeout(id){timers.delete(id);},
 hideAuth(){state.authenticated=true;$('#authScreen').hidden=true;},showAuth(){state.authenticated=false;$('#authScreen').hidden=false;ctx.cancelPanelRefresh();},
 refreshNodeActivity:async()=>false,scheduleNodeActivity(){},showNotice(){},consoleInitialSetup(){},acceptDeviceList:v=>state.devices=v};
 for(const n of renderNames)ctx[n]=()=>renders.push(n);
 ctx.api=async(url,opt={})=>{calls.push({url,opt});return handler(url,opt);};
 vm.createContext(ctx);vm.runInContext(helpers.map(extract).join('\n'),ctx);
 const arrays=new Set(['/api/v1/services','/api/v1/engines','/api/v1/engine-configs','/api/v1/components','/api/v1/sources','/api/v1/routes/options']);
 const normal=url=>url==='/api/v1/auth/status'?{authenticated:true}:url==='/api/v1/status'?{authenticated:true,version:'test',revision:2}:url==='/api/v1/services'?[{id:'telegram'}]:url==='/api/v1/panel/inventory'?{schema:1,dataplane:'not-checked',state:'available',instance_id:'a'.repeat(32),revision:1,data_age_ms:0,max_age_seconds:300,observed_at:new Date().toISOString(),data:{components:[],engines:[],system:{}}}:arrays.has(url)?[]:{};
 handler=normal;
 return {ctx,state,panelLoad,calls,renders,timers,$,normal,handler:fn=>handler=fn};
}
await test('slow status no longer gates services and engine sections',async()=>{
 const f=fixture(),slow=deferred();f.handler(url=>url==='/api/v1/status'?slow.promise:f.normal(url));
 const p=f.ctx.refreshAll();await flush();assert.equal(f.state.services.length,1);assert.equal(f.state.dataLoad.engineConfigs.loaded,true);
 slow.resolve(f.normal('/api/v1/status'));assert.equal(await p,true);
});
for(const status of [409,503,500])await test(`status HTTP ${status} preserves independent sections`,async()=>{
 const f=fixture();f.state.status={version:'last-good'};
 f.handler(url=>{if(url==='/api/v1/status')throw Object.assign(new Error('injected failure'),{status,payload:{code:status===409?'RESTORE_OPERATION_BUSY':'BROKEN'}});return f.normal(url);});
 await f.ctx.refreshAll();assert.equal(f.state.services.length,1);assert.equal(f.state.dataLoad.system.loaded,true);assert.equal(f.state.status.version,'last-good');assert(f.timers.size);
});
await test('slow activity cannot block bootstrap and core reads',async()=>{
 const f=fixture();f.ctx.refreshNodeActivity=()=>new Promise(()=>{});assert.equal(await f.ctx.refreshAll(),true);assert.equal(f.state.services.length,1);
});
await test('busy activity is not treated as a global UI read lock',async()=>{
 const f=fixture();f.ctx.refreshNodeActivity=async()=>true;await f.ctx.refreshAll();assert(f.calls.some(x=>x.url==='/api/v1/services'));
});
await test('concurrency remains bounded to four and refresh coalesces',async()=>{
 const f=fixture(),queue=[];let active=0,max=0;
 f.handler(url=>{if(url==='/api/v1/auth/status')return f.normal(url);const d=deferred();active++;max=Math.max(max,active);queue.push(()=>{active--;d.resolve(f.normal(url));});return d.promise;});
 const a=f.ctx.refreshAll(),b=f.ctx.refreshAll();await flush();assert.equal(queue.length,4);
 while(f.panelLoad.request){while(queue.length)queue.shift()();await flush();}
 await Promise.all([a,b]);assert.equal(max,4);assert.equal(f.calls.filter(x=>x.url==='/api/v1/auth/status').length,1);
});
await test('null service JSON never erases the last valid catalogue',async()=>{
 const f=fixture();await f.ctx.refreshAll();const prior=f.state.services;f.handler(url=>url==='/api/v1/services'?null:f.normal(url));await f.ctx.refreshAll();assert.equal(f.state.services,prior);assert.equal(f.state.dataLoad.services.phase,'error');
});
await test('401 cancels sibling results and opens login',async()=>{
 const f=fixture(),slow=deferred();f.handler(url=>url==='/api/v1/status'?Promise.reject(Object.assign(new Error('login'),{status:401})):url==='/api/v1/services'?slow.promise:f.normal(url));
 const p=f.ctx.refreshAll();await flush();slow.resolve([{id:'stale-private'}]);await p;assert.equal(f.$('#authScreen').hidden,false);assert.equal(f.state.services.length,0);assert.equal(f.timers.size,0);
});
await test('post-write readback rejects a late pre-write snapshot',async()=>{
 const f=fixture(),slow=deferred();let committed=false;
 f.handler(url=>url==='/api/v1/services'?(committed?[{id:'new'}]:slow.promise):f.normal(url));
 const first=f.ctx.refreshAll();await flush();committed=true;await f.ctx.refreshAfterMutation();slow.resolve([{id:'old'}]);await first;assert.equal(f.state.services[0].id,'new');
});
await test('one renderer failure does not suppress completed sibling reads',async()=>{
 const f=fixture();f.ctx.renderStatus=()=>{throw new Error('status render');};f.ctx.renderInterface=()=>{throw new Error('interface render');};
 await f.ctx.refreshAll();assert.equal(f.state.dataLoad.services.loaded,true);assert.equal(f.state.dataLoad.engineConfigs.loaded,true);assert(Object.keys(f.state.uiRenderIssues).length);
});
await test('failed-only retries do not reload every successful section',async()=>{
 const f=fixture();await f.ctx.refreshAll();f.handler(url=>{if(url==='/api/v1/services')throw new Error('temporary');return f.normal(url);});await f.ctx.refreshAll();f.calls.length=0;f.handler(f.normal);await f.ctx.refreshAll(true);
 assert.deepEqual(f.calls.map(x=>x.url),['/api/v1/auth/status','/api/v1/status','/api/v1/services']);
});
await test('navigation is local and survives broken optional renderers',async()=>{
 const f=fixture(),classes=new Map();f.state.engineEditorDirty=true;f.state.engineEditorVersion=42;
 f.ctx.document={getElementById:id=>id==='view-settings'?{}:null,dispatchEvent(){}};
 f.ctx.CustomEvent=CustomEvent;f.ctx.CSS={escape:s=>s};f.ctx.$$=selector=>selector==='.view'?[{id:'view-settings',classList:{toggle:(_key,on)=>classes.set('settings',on)}}]:[];
 f.ctx.window={matchMedia:()=>({matches:false}),scrollTo(){}};f.ctx.viewMeta={settings:['Настройки','Общие']};f.ctx.renderWorkspaceNavigation=()=>{};
 for(const name of ['consoleViewChanged','renderStatus','renderInterface','renderInterfaceNavigation'])f.ctx[name]=()=>{throw new Error('injected');};
 vm.runInContext(extract('setView'),f.ctx);f.ctx.setView('settings');assert.equal(classes.get('settings'),true);assert.equal(f.state.currentView,'settings');assert.equal(f.state.engineEditorDirty,true);assert.equal(f.state.engineEditorVersion,42);assert.equal(f.calls.length,0);assert.equal(f.$('#pageTitle').textContent,'Настройки');
});
function confirmationFixture(){
 const dialog=Object.assign(new EventTarget(),{open:false,returnValue:'',showModal(){this.open=true;},close(value=''){this.returnValue=value;this.open=false;this.dispatchEvent(new Event('close'));}});
 const document=new EventTarget();const ctx={document,$:s=>s==='#actionDialog'?dialog:{textContent:''}};vm.createContext(ctx);vm.runInContext(extract('askConfirmation'),ctx);return {dialog,document,ask:ctx.askConfirmation};
}
await test('double confirmation invocation cannot approve two actions',async()=>{
 const f=confirmationFixture();const first=f.ask('first','one');const second=f.ask('second','two');assert.equal(await second,false);f.dialog.close('confirm');assert.equal(await first,true);
});
await test('Escape never reuses an earlier approval',async()=>{
 const f=confirmationFixture();let p=f.ask('first','one');f.dialog.close('confirm');assert.equal(await p,true);p=f.ask('second','two');f.dialog.dispatchEvent(new Event('cancel'));f.dialog.close();assert.equal(await p,false);
});
await test('logout revokes a pending confirmation and releases it',async()=>{
 const f=confirmationFixture();const p=f.ask('delete','one');f.document.dispatchEvent(new Event('razvilka:auth-required'));assert.equal(await p,false);assert.equal(f.dialog.open,false);const next=f.ask('new','two');f.dialog.close('confirm');assert.equal(await next,true);
});
await test('showModal error fails closed without wedging the next dialog',async()=>{
 const f=confirmationFixture();f.dialog.showModal=()=>{throw new Error('broken')};assert.equal(await f.ask('x','x'),false);f.dialog.showModal=function(){this.open=true;};const next=f.ask('x','x');f.dialog.close('confirm');assert.equal(await next,true);
});
for(const [requested,expected] of [[undefined,20000],[3000,3000],[1,250],[110000,110000],[200000,110000]])await test(`GET deadline ${requested} clamps to ${expected}`,async()=>{
 let duration,fetchSignal;const ctx={Headers,AbortController,ADMIN_TOKEN_KEY:'fixture',sessionStorage:{getItem:()=>null},setTimeout(_fn,ms){duration=ms;return 1;},clearTimeout(){},fetch:async(_url,opt)=>{fetchSignal=opt.signal;return {ok:true,json:async()=>({ok:true})};}};
 vm.createContext(ctx);vm.runInContext(extract('api'),ctx);await ctx.api('/api/v1/panel/availability',requested===undefined?{}:{readTimeoutMs:requested});assert.equal(duration,expected);assert(fetchSignal instanceof AbortSignal);
});
await test('read deadline also aborts a delayed response body',async()=>{
 let timer,signal;const ctx={Headers,AbortController,ADMIN_TOKEN_KEY:'fixture',sessionStorage:{getItem:()=>null},setTimeout(fn){timer=fn;return 1;},clearTimeout(){},fetch:async(_url,opt)=>{signal=opt.signal;return {ok:true,json:()=>new Promise((_r,reject)=>signal.addEventListener('abort',()=>reject(new Error('aborted'))))};}};
 vm.createContext(ctx);vm.runInContext(extract('api'),ctx);const pending=ctx.api('/read');await flush();timer();await assert.rejects(pending,e=>e.code==='READ_TIMEOUT');assert(signal.aborted);
});
await test('mutations keep caller cancellation and are never automatically replayed',async()=>{
 let timers=0,calls=0;const caller=new AbortController();const ctx={Headers,AbortController,ADMIN_TOKEN_KEY:'fixture',sessionStorage:{getItem:()=>null},setTimeout(){timers++;},clearTimeout(){},fetch:async(_url,opt)=>{calls++;assert.equal(opt.signal,caller.signal);throw new Error('connection lost');}};
 vm.createContext(ctx);vm.runInContext(extract('api'),ctx);await assert.rejects(ctx.api('/api/v1/apply',{method:'POST',signal:caller.signal}));assert.equal(calls,1);assert.equal(timers,0);
});
const policyMatch=autonomy.match(/function policyConsentRequired\([^]*?\n  }/);assert(policyMatch);
const pc={};vm.createContext(pc);vm.runInContext(policyMatch[0],pc);const needs=pc.policyConsentRequired;
const base=()=>({setup_complete:true,revision:2,enabled:true,all_lan:false,default_sources:['192.168.1.2'],source_ids:['trusted'],protocols:['vless','tuic'],preferred_routes:['nfqws2'],inherit_new_services:true,update_channel:'stable',check_seconds:300,reserve_seconds:900,reserve_target:2,candidates_per_round:2,failure_confirm_seconds:30,max_switches_per_hour:4,timezone:'Europe/Warsaw',application:{mode:'check',start:'02:00',end:'04:00',days:[1,2]},components:{mode:'check',start:'02:00',end:'04:00',days:[1,2]}});
const policyCases=[
 ['unchanged approved policy',p=>{},false],['check interval',p=>p.check_seconds=600,false],['reserve budget within server bounds',p=>p.reserve_target=3,false],['pause',p=>p.enabled=false,false],['same-permission schedule',p=>p.application.start='03:00',false],['remove a protocol',p=>p.protocols=['vless'],false],['remove a source',p=>p.source_ids=[],false],['disable inheritance',p=>p.inherit_new_services=false,false],['new source',p=>p.source_ids.push('new'),true],['new protocol',p=>p.protocols.push('hysteria2'),true],['new transport',p=>p.preferred_routes.push('usque'),true],['wider scope',p=>{p.all_lan=true;p.default_sources=[]},true],['different device',p=>p.default_sources=['192.168.1.3'],true],['preview updates',p=>p.update_channel='preview',true],['prepare instead of check',p=>p.application.mode='prepare',true],['unknown future update mode',p=>p.application.mode='install',true],['new future permission field',p=>p.allow_remote_script=true,true],['unknown update-window field',p=>p.components.allow_install=true,true]
];
for(const [label,edit,expected]of policyCases)await test('policy: '+label,async()=>{const old=base(),next=base();edit(next);const before=JSON.stringify([old,next]);assert.equal(needs(old,next),expected);assert.equal(JSON.stringify([old,next]),before,'classifier mutated policy');});
await test('policy: first setup and Safe Mode release still require consent',async()=>{const p=base();assert(needs(null,p));assert(needs({...p,setup_complete:false},p));assert(needs(p,p,true));});
await test('policy: enabling future-service inheritance requires consent',async()=>{const old=base();old.inherit_new_services=false;assert(needs(old,base()));});
const hb={AbortController,Date};vm.createContext(hb);vm.runInContext(heartbeat,hb);const model=hb.RazvilkaPanelAvailability;
const snapshot=(busy=false)=>({schema:1,name:'RAZVILKA',panel:'responding',dataplane:'not-checked',admission:{state:busy?'busy':'idle',active:busy?1:0,exclusive:busy,fenced:false}});
function monitorFixture(){let handler=async()=>snapshot(),serial=0,visible=true;const timers=new Map(),published=[],calls=[],auth=[];const control=model.createController({request:opt=>{calls.push(opt);return handler(opt)},publish:v=>published.push(v),isVisible:()=>visible,setTimeout(fn,ms){timers.set(++serial,{fn,ms});return serial;},clearTimeout:id=>timers.delete(id),now:()=>1000,onAuthRequired:()=>auth.push(true)});return {control,timers,published,calls,auth,handler:fn=>handler=fn,visible:v=>visible=v};}
await test('availability validates shape and never accepts a route-health claim',async()=>{assert(model.validSnapshot(snapshot()));assert(!model.validSnapshot({...snapshot(),dataplane:'healthy'}));assert(!model.validSnapshot({...snapshot(),admission:{state:'idle',active:1,exclusive:true,fenced:false}}));assert(!model.validSnapshot(null));});
await test('heartbeat single-flight and busy retry are bounded',async()=>{const f=monitorFixture(),d=deferred();f.handler(()=>d.promise);f.control.start();const a=f.control.refresh(),b=f.control.refresh();assert.equal(a,b);await flush();assert.equal(f.calls.length,1);assert.equal(f.calls[0].readTimeoutMs,3000);d.resolve(snapshot(true));await a;assert.equal([...f.timers.values()][0].ms,5000);});
await test('heartbeat backoff avoids request storms',async()=>{const f=monitorFixture();f.handler(async()=>{throw new Error('timeout')});f.control.start();const delays=[];for(let i=0;i<7;i++){await f.control.refresh();delays.push([...f.timers.values()][0].ms);}assert.deepEqual(delays,[5000,10000,20000,40000,60000,60000,60000]);assert.equal(f.calls.length,7);});
await test('stopped heartbeat discards late results and cancels its request',async()=>{const f=monitorFixture(),d=deferred();f.handler(()=>d.promise);f.control.start();const p=f.control.refresh();await flush();f.control.stop();assert(f.calls[0].signal.aborted);d.resolve(snapshot());await p;assert.equal(f.published.length,0);assert.equal(f.timers.size,0);});
await test('401 stops heartbeat and requests authentication once',async()=>{const f=monitorFixture();f.handler(async()=>{throw Object.assign(new Error('login'),{status:401})});f.control.start();await f.control.refresh();assert.equal(f.auth.length,1);assert.equal(f.timers.size,0);assert.equal(f.published.at(-1),null);});
await test('404 mixed-version response stops automatic retries',async()=>{const f=monitorFixture();f.handler(async()=>{throw Object.assign(new Error('not found'),{status:404})});f.control.start();await f.control.refresh();assert.equal(f.published.at(-1).kind,'unsupported');assert.equal(f.timers.size,0);await f.control.refresh();assert.equal(f.calls.length,1);});
await test('old heartbeat response cannot supersede a new session',async()=>{const f=monitorFixture(),old=deferred();f.handler(()=>old.promise);f.control.start();const first=f.control.refresh();await flush();f.control.stop();f.handler(async()=>snapshot(true));f.control.start();await f.control.refresh();old.resolve(snapshot());await first;assert.equal(f.published.length,1);assert.equal(f.published[0].admission.state,'busy');});
await test('heartbeat descriptions do not fabricate service availability',async()=>{const text=model.describe({kind:'unreachable'});assert.match(text,/не доказывает/);assert.match(model.describe({kind:'responding',admission:{state:'recovery-required'}}),/восстановления журнала/);});
const summary={suite:'ux-stage1',mode:process.env.RAZVILKA_TEST_APP?'audited-source-excerpts-and-new-files':'repository-files',passed:results.filter(r=>r.status==='passed').length,failed:results.filter(r=>r.status==='failed').length,tests:results};
console.log(JSON.stringify(summary));
process.exitCode=summary.failed?1:0;
