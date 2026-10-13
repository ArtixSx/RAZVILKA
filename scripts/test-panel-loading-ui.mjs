import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const names=['panelReadContext','panelReadContextCurrent','invalidatePanelReads','readPanelResource','panelViewKeys','panelViewRequests','refreshPanelView','panelSectionState','panelBusy','refreshPanelLoadNotice','panelSnapshotCurrent','schedulePanelRetry','cancelPanelRefresh','renderPanelLoad','renderPanelSection','acceptPanelSection','acceptPanelInventory','inventoryObservationStale','refreshPanelInventory','cancelPanelInventoryRefresh','settlePanelReads','refreshAll','refreshAfterMutation','refreshCoreAfterEdit','loadPanelSnapshot'];
const extract=name=>{const match=source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));assert(match,name);return match[0];};
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};}
function fixture(){
 const elements=new Map(),calls=[],renders=[],timers=new Map(),notices=[],events=[];
 let timer=0,activity=false,activityError=null,handler;
 const state={currentView:'engineconfig',status:{},services:[],engineConfigs:[],dataLoad:{},loadIssues:[]};
 const panelLoad={generation:0,request:null,controller:null,retryTimer:null,retryCount:0};
 const $=id=>{if(!elements.has(id))elements.set(id,{hidden:true,textContent:'',value:'',classList:{toggle(){}}});return elements.get(id);};
 const api=async(url,options={})=>{calls.push({url,options});return handler(url,options);};
 const context={state,panelLoad,panelReads:{epoch:0,entries:new Map()},inventoryRead:null,$,AbortController,Date,console,CustomEvent:class{constructor(type){this.type=type;}},document:{hidden:false,dispatchEvent:event=>events.push(event.type)},
 setTimeout(fn,ms){const id=++timer;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},
 api,hideAuth(){$('#authScreen').hidden=true;},showAuth(){$('#authScreen').hidden=false;context.cancelPanelRefresh();},
 refreshNodeActivity:async()=>{if(activityError)throw activityError;return activity;},scheduleNodeActivity(){},
 showNotice:(...args)=>{notices.push(args);state.noticeDetails=args[3];$('#notice').hidden=false;},hideNotice(){state.noticeDetails=null;$('#notice').hidden=true;},consoleInitialSetup(){},acceptDeviceList:v=>{state.devices=v;},
 };
 for(const name of ['renderStatus','renderSettings','renderSystem','renderMetrics','renderServices','renderOverviewQuickServices','renderOverviewServices','renderReadiness','renderEngines','renderEngineControl','renderComponents','renderWarpManager','renderSources','renderNodes','renderConnections','renderDevices','renderTestLab','renderEngineLab','renderAudit','renderStrategyLab','renderDNS','renderDNSPlan','renderDNSServiceBindings'])context[name]=()=>renders.push(name);
 vm.createContext(context);vm.runInContext(names.map(extract).join('\n'),context);
 const arrays=new Set(['/api/v1/services','/api/v1/engines','/api/v1/engine-configs','/api/v1/components','/api/v1/sources','/api/v1/routes/options']);
 const normal=url=>{
   if(url==='/api/v1/auth/status')return {authenticated:true};
   if(url==='/api/v1/status')return {version:'fixture',authenticated:true,revision:34};
   if(url==='/api/v1/services')return [{id:'telegram',name:'Telegram',enabled:true}];
   if(url==='/api/v1/panel/inventory')return {schema:1,dataplane:'not-checked',state:'available',revision:1,instance_id:'a'.repeat(32),data_age_ms:0,max_age_seconds:300,observed_at:new Date().toISOString(),data:{components:[],engines:[],system:{}}};
   return arrays.has(url)?[]:{};
 };
 handler=normal;
 return {context,state,panelLoad,calls,renders,timers,notices,events,$,normal,
   handler:fn=>{handler=fn;},activity:value=>{activity=value;},activityError:value=>{activityError=value;},
   retry(){const item=[...timers.values()].find(value=>value.ms===10000||value.ms===5000);assert(item,'retry missing');timers.clear();item.fn();},
 };
}
function engineFixture(){
 const f=fixture();Object.assign(f.state,{authenticated:true,authGeneration:4,currentView:'engines',selectedEngine:'sing-box',selectedEngineFile:'main',engineConfigs:[],engineEditorDirty:false});
 Object.assign(f.context,{captureEngineEditorContext:()=>({}),engineEditorContextCurrent:()=>true,engineIntentCurrent:()=>true,
   selectedEngineView:()=>f.state.engineConfigs.find(e=>e.id===f.state.selectedEngine),invalidateEngineEditorContext(){},
   noticeBelongsOnlyToEngine:()=>false,askConfirmation:async()=>true,setView:name=>{f.state.currentView=name;}});
 vm.runInContext(['readEngineNavigationMetadata','refreshEngineConfigs','openEngineConfiguration','selectEngine'].map(extract).join('\n'),f.context);
 return f;
}
function holdEngineNavigation(f){
 const status=deferred(),catalog=deferred(),configs=[{id:'xray',files:[{id:'main'}]}];let statuses=0,catalogs=0;
 f.handler(url=>{
   if(url==='/api/v1/status')return ++statuses===1?status.promise:Promise.reject(Object.assign(new Error('modeled admission busy'),{status:409,payload:{code:'RESTORE_OPERATION_BUSY'}}));
   if(url==='/api/v1/engine-configs')return ++catalogs===1?catalog.promise:configs;
   return f.normal(url);
 });
 f.context.refreshPanelView('engines');
 return {status,catalog,configs,counts:()=>({status:statuses,catalog:catalogs}),finish:async()=>{status.resolve(f.normal('/api/v1/status'));catalog.resolve(configs);await f.panelLoad.request;}};
}
let count=0;
async function test(name,fn){await fn();count++;console.log('PASS',name);}

await test('engines waits for status settlement before protected reads and keeps inventory parallel',async()=>{
 for(const inventoryTiming of ['early','late']){
   const f=engineFixture(),status=deferred(),inventory=deferred(),services=deferred();
   f.handler(url=>url==='/api/v1/status'?status.promise:url==='/api/v1/panel/inventory'?inventory.promise:url==='/api/v1/services'?services.promise:f.normal(url));
   const refresh=f.context.refreshAll();await flush();
   assert.equal(f.calls.filter(call=>call.url==='/api/v1/panel/inventory').length,1);
   assert.equal(f.calls.filter(call=>['/api/v1/services','/api/v1/engine-configs'].includes(call.url)).length,0,'protected metadata overlapped the exclusive status reader');
   if(inventoryTiming==='early'){inventory.resolve(f.normal('/api/v1/panel/inventory'));await flush();assert.equal(f.state.dataLoad.inventory.phase,'ready');assert.equal(f.state.dataLoad.status.phase,'loading');}
   status.resolve(f.normal('/api/v1/status'));await flush();
   assert.equal(f.state.dataLoad.status.phase,'ready');assert.equal(f.state.dataLoad.engineConfigs.phase,'ready');assert.equal(f.state.dataLoad.services.phase,'loading');
   if(inventoryTiming==='late')assert.equal(f.state.dataLoad.inventory.phase,'loading','slow inventory became a catalog prerequisite');
   services.resolve(f.normal('/api/v1/services'));inventory.resolve(f.normal('/api/v1/panel/inventory'));assert.equal(await refresh,true);
   for(const url of ['/api/v1/status','/api/v1/services','/api/v1/engine-configs'])assert.equal(f.calls.filter(call=>call.url===url).length,1);
   assert.equal(f.calls.filter(call=>call.options.method&&call.options.method!=='GET').length,0);
 }
});

await test('engines busy status stays busy while independent metadata succeeds and existing retry can recover',async()=>{
 const f=engineFixture(),services=[{id:'fresh-service'}],configs=[{id:'fresh-engine'}];
 f.handler(url=>url==='/api/v1/status'?Promise.reject(Object.assign(new Error('modeled writer busy'),{status:409,payload:{code:'RESTORE_OPERATION_BUSY'}})):url==='/api/v1/services'?services:url==='/api/v1/engine-configs'?configs:f.normal(url));
 assert.equal(await f.context.refreshAll(),true);
 assert.equal(f.state.dataLoad.status.phase,'busy');
 assert.equal(f.state.services[0].id,services[0].id);assert.equal(f.state.engineConfigs[0].id,configs[0].id);
 for(const key of ['services','engineConfigs'])assert.equal(f.state.dataLoad[key].phase,'ready');
 assert.equal(f.state.loadIssues.length,1);assert.equal(f.state.loadIssues[0].section,'status');assert.equal(f.state.loadIssues[0].busy,true);
 f.handler(f.normal);f.retry();await f.panelLoad.request;
 for(const key of ['status','services','engineConfigs'])assert.equal(f.state.dataLoad[key].phase,'ready');
 for(const url of ['/api/v1/services','/api/v1/engine-configs'])assert.equal(f.calls.filter(call=>call.url===url).length,1);
 assert.equal(f.state.loadIssues.length,0);
});

await test('engines preserves independent metadata after an ordinary status error',async()=>{
 const f=engineFixture();f.handler(url=>url==='/api/v1/status'?Promise.reject(Object.assign(new Error('status unavailable'),{status:503})):f.normal(url));
 assert.equal(await f.context.refreshAll(),true);assert.equal(f.state.dataLoad.status.phase,'error');
 for(const key of ['services','engineConfigs'])assert.equal(f.state.dataLoad[key].phase,'ready');
 assert.equal(f.state.loadIssues.length,1);assert.equal(f.state.loadIssues[0].section,'status');
});

await test('engines revokes queued metadata on status 401, auth epoch, navigation or mutation cancellation',async()=>{
 for(const leave of ['401','auth','view','read-epoch']){
   const f=engineFixture(),status=deferred();f.handler(url=>url==='/api/v1/status'?status.promise:f.normal(url));
   const refresh=f.context.refreshAll();await flush();
   if(leave==='401')status.reject(Object.assign(new Error('login expired'),{status:401}));
   else{if(leave==='auth'){f.state.authGeneration++;f.context.showAuth();}else if(leave==='view'){f.state.currentView='settings';f.context.cancelPanelRefresh();}else f.context.invalidatePanelReads();status.resolve(f.normal('/api/v1/status'));}
   await refresh;assert.equal(f.calls.filter(call=>['/api/v1/services','/api/v1/engine-configs'].includes(call.url)).length,0);
   assert.equal(f.state.engineConfigs.length,0);assert(!f.renders.includes('renderEngineControl'));assert.equal(f.timers.size,0);
 }
});

await test('other views retain concurrent metadata while status is pending',async()=>{
 const f=fixture(),status=deferred();f.handler(url=>url==='/api/v1/status'?status.promise:f.normal(url));
 const refresh=f.context.refreshAll();await flush();
 for(const url of ['/api/v1/services','/api/v1/engine-configs'])assert.equal(f.calls.filter(call=>call.url===url).length,1);
 assert.equal(f.state.dataLoad.engineConfigs.phase,'ready');status.resolve(f.normal('/api/v1/status'));await refresh;
});

await test('legacy unowned metadata refresh duplicates active navigation and exposes its 409',async()=>{
 const f=engineFixture(),held=holdEngineNavigation(f);await flush();
 await assert.rejects(f.context.refreshEngineConfigs(),error=>error.status===409&&error.payload.code==='RESTORE_OPERATION_BUSY');
 await held.finish();assert.deepEqual(held.counts(),{status:2,catalog:2});
});

await test('missing-catalog card joins the actual navigation snapshot and selects its exact engine',async()=>{
 const f=engineFixture(),held=holdEngineNavigation(f);await flush();const opened=f.context.openEngineConfiguration('xray');
 assert.deepEqual(held.counts(),{status:1,catalog:0});await held.finish();assert.equal(await opened,true);assert.deepEqual(held.counts(),{status:1,catalog:1});
 assert.equal(f.state.selectedEngine,'xray');assert.equal(f.state.currentView,'engineconfig');
 assert.equal(f.calls.filter(call=>call.options.method&&call.options.method!=='GET').length,0);
});

await test('same-owner status or catalog failure rejects the card without a fallback read',async()=>{
 for(const section of ['status','catalog'])for(const phase of ['busy','error']){
   const f=engineFixture(),held=holdEngineNavigation(f);await flush();const opened=f.context.openEngineConfiguration('xray');
   const error=Object.assign(new Error('modeled '+phase),{status:phase==='busy'?409:503,payload:{code:phase==='busy'?'RESTORE_OPERATION_BUSY':'SOURCE_UNAVAILABLE'}});
   if(section==='catalog'){held.status.resolve(f.normal('/api/v1/status'));await flush();held.catalog.reject(error);}else{held.status.reject(error);held.catalog.resolve(held.configs);}
   assert.equal(await opened,false);assert.equal(f.state.selectedEngine,'sing-box');assert.equal(f.state.currentView,'engines');
   assert.deepEqual(held.counts(),{status:1,catalog:1});assert.equal(f.state.dataLoad[section==='status'?'status':'engineConfigs'].phase,phase);
   assert.match(f.notices.at(-1)[1],/не прочитаны/);assert.equal(f.notices.at(-1)[2],'modeled '+phase);
 }
});

await test('ordinary refresh joins navigation and a subsequent explicit refresh obtains one fresh pair',async()=>{
 const f=engineFixture(),held=holdEngineNavigation(f);await flush();const joined=f.context.refreshAll();
 assert.deepEqual(held.counts(),{status:1,catalog:0});await held.finish();await joined;assert.deepEqual(held.counts(),{status:1,catalog:1});
 f.handler(f.normal);await f.context.refreshAll();
 for(const url of ['/api/v1/status','/api/v1/engine-configs'])assert.equal(f.calls.filter(call=>call.url===url).length,2);
});

await test('card with an existing description starts no metadata fallback',async()=>{
 const f=engineFixture();f.state.engineConfigs=[{id:'xray',files:[{id:'main'}]}];
 assert.equal(await f.context.openEngineConfiguration('xray'),true);assert.equal(f.calls.length,0);assert.equal(f.state.currentView,'engineconfig');
});

await test('navigation without a snapshot owner shares active metadata GETs and never their completed bodies',async()=>{
 const f=engineFixture(),status=deferred(),catalog=deferred();let statuses=0,catalogs=0;
 const configs=[{id:'xray',files:[{id:'main'}]}];
 f.handler(url=>url==='/api/v1/status'?(++statuses===1?status.promise:f.normal(url)):url==='/api/v1/engine-configs'?(++catalogs===1?catalog.promise:configs):f.normal(url));
 const observedStatus=f.context.readPanelResource('/api/v1/status'),observedCatalog=f.context.readPanelResource('/api/v1/engine-configs');await flush();
 const read=f.context.readEngineNavigationMetadata();await flush();assert.equal(statuses,1);assert.equal(catalogs,1);
 status.resolve(f.normal('/api/v1/status'));catalog.resolve(configs);await Promise.all([observedStatus,observedCatalog]);assert.equal(await read,true);
 assert.equal(await f.context.readEngineNavigationMetadata(),true);assert.equal(statuses,2);assert.equal(catalogs,2);
});

await test('unowned navigation exposes current 409 and 401 without admitting catalog or status',async()=>{
 for(const status of [409,401]){
   const f=engineFixture(),catalog=deferred();
   f.handler(url=>url==='/api/v1/status'?Promise.reject(Object.assign(new Error('modeled read denied'),{status,payload:{code:status===409?'RESTORE_OPERATION_BUSY':'AUTH_REQUIRED'}})):catalog.promise);
   assert.equal(await f.context.openEngineConfiguration('xray'),false);catalog.resolve([{id:'xray',files:[{id:'main'}]}]);await flush();
   assert.equal(f.state.selectedEngine,'sing-box');assert.equal(f.state.engineConfigs.length,0);assert.equal(f.state.status.revision,undefined);assert.equal(f.calls.length,2);
   if(status===401)assert.equal(f.$('#authScreen').hidden,false);else assert.match(f.notices.at(-1)[1],/не прочитаны/);
 }
});

await test('post-write engine readback remains independent of pre-write passive transports',async()=>{
 const f=engineFixture(),oldStatus=deferred(),oldCatalog=deferred();let committed=false;
 f.handler(url=>url==='/api/v1/status'?(committed?{revision:35}:oldStatus.promise):url==='/api/v1/engine-configs'?(committed?[{id:'after-write'}]:oldCatalog.promise):f.normal(url));
 const beforeStatus=f.context.readPanelResource('/api/v1/status'),beforeCatalog=f.context.readPanelResource('/api/v1/engine-configs');await flush();committed=true;
 assert.equal(await f.context.refreshEngineConfigs(),true);assert.equal(f.state.status.revision,35);assert.equal(f.state.engineConfigs[0].id,'after-write');
 for(const url of ['/api/v1/status','/api/v1/engine-configs'])assert.equal(f.calls.filter(call=>call.url===url).length,2);
 oldStatus.resolve({revision:34});oldCatalog.resolve([{id:'before-write'}]);await Promise.all([beforeStatus,beforeCatalog]);
 assert.equal(f.state.status.revision,35);assert.equal(f.state.engineConfigs[0].id,'after-write');
});

await test('old navigation owner cannot open a card after auth, view, request or snapshot changes',async()=>{
 for(const leave of ['auth','view','request','snapshot']){
   const f=engineFixture(),held=holdEngineNavigation(f);await flush();const opened=f.context.openEngineConfiguration('xray');
   if(leave==='auth')f.state.authGeneration++;else if(leave==='view')f.state.currentView='settings';else if(leave==='request')f.state.engineNavigationRequest++;else f.panelLoad.generation++;
   await held.finish();assert.equal(await opened,false);assert.equal(f.state.selectedEngine,'sing-box');
   assert.deepEqual(held.counts(),{status:1,catalog:leave==='request'?1:0});assert.equal(f.notices.length,0);
 }
});

await test('passive navigation metadata cannot replace state after its auth, view or request is revoked',async()=>{
 for(const leave of ['auth','view','request']){
   const f=engineFixture(),status=deferred(),catalog=deferred();let current=true;
   f.handler(url=>url==='/api/v1/status'?status.promise:catalog.promise);
   const read=f.context.readEngineNavigationMetadata(()=>current);const outcome=read.then(value=>value,error=>error.name);await flush();
   if(leave==='auth')f.state.authGeneration++;else if(leave==='view')f.state.currentView='settings';else current=false;
   status.resolve({revision:99});catalog.resolve([{id:'old-result'}]);assert.equal(await outcome,leave==='auth'?'AbortError':false);
   assert.equal(f.state.status.revision,undefined);assert.equal(f.state.engineConfigs.length,0);
 }
});

await test('passive readers share transport while navigation cancels only its subscription',async()=>{
 const f=fixture(),pending=deferred(),controller=new AbortController();f.handler(()=>pending.promise);
 const old=f.context.readPanelResource('/api/v1/nodes',{signal:controller.signal});
 const kept=f.context.readPanelResource('/api/v1/nodes');await flush();
 assert.equal(f.calls.length,1);const rejected=assert.rejects(old,error=>error.name==='AbortError');controller.abort();await rejected;
 assert.equal(f.calls[0].options.signal.aborted,false,'one view canceled a shared transport');
 pending.resolve({nodes:[{id:'current'}]});assert.equal((await kept).nodes[0].id,'current');
});

await test('brief list cache is copied, expires, and never caches auth, gates or review journals',async()=>{
 const f=fixture();f.handler(()=>[{id:'server'}]);
 const value=await f.context.readPanelResource('/api/v1/services');value[0].id='local-edit';
 assert.equal((await f.context.readPanelResource('/api/v1/services'))[0].id,'server');assert.equal(f.calls.length,1);
 f.context.panelReads.entries.get('/api/v1/services').receivedAt=Date.now()-1001;
 await f.context.readPanelResource('/api/v1/services');assert.equal(f.calls.length,2);
 for(const url of ['/api/v1/auth/status','/api/v1/status','/api/v1/service-control','/api/v1/service-control/current','/api/v1/components/recovery']) {
  const start=f.calls.length;await f.context.readPanelResource(url);await f.context.readPanelResource(url);assert.equal(f.calls.length-start,2,url+' reused a completed authority read');
 }
});

await test('read failure is exposed, never cached, and the next observer retries immediately',async()=>{
 const f=fixture();f.handler(()=>{throw Object.assign(new Error('busy'),{status:409});});
 await assert.rejects(f.context.readPanelResource('/api/v1/nodes'),error=>error.status===409);
 f.handler(()=>({nodes:[]}));assert.equal((await f.context.readPanelResource('/api/v1/nodes')).nodes.length,0);assert.equal(f.calls.length,2);
});

await test('new auth epoch fences ignored cancellation without clearing the newer read',async()=>{
 const f=fixture(),old=deferred(),fresh=deferred();f.handler(()=>old.promise);
 const previous=f.context.readPanelResource('/api/v1/nodes');const rejected=assert.rejects(previous,error=>error.name==='AbortError');await flush();
 f.state.authGeneration=1;f.context.invalidatePanelReads();f.handler(()=>fresh.promise);
 const next=f.context.readPanelResource('/api/v1/nodes');await flush();old.resolve({nodes:[{id:'private-old'}]});await rejected;
 fresh.resolve({nodes:[{id:'new-session'}]});assert.equal((await next).nodes[0].id,'new-session');
 assert.equal((await f.context.readPanelResource('/api/v1/nodes')).nodes[0].id,'new-session');assert.equal(f.calls.length,2);
});

await test('canceled subscriber and invalidated ticket cannot admit a delayed protected GET',async()=>{
 const f=fixture(),controller=new AbortController();controller.abort();
 await assert.rejects(f.context.readPanelResource('/api/v1/nodes',{signal:controller.signal}),error=>error.name==='AbortError');assert.equal(f.calls.length,0);
 const pending=f.context.readPanelResource('/api/v1/nodes');const rejected=assert.rejects(pending,error=>error.name==='AbortError');f.context.invalidatePanelReads();await rejected;assert.equal(f.calls.length,0);
});

await test('late old 401 is a canceled read and cannot revoke a newer auth epoch',async()=>{
 const f=fixture(),old=deferred();f.handler(()=>old.promise);
 const previous=f.context.readPanelResource('/api/v1/status');const rejected=assert.rejects(previous,error=>error.name==='AbortError'&&!error.status);await flush();
 f.state.authGeneration=1;f.context.invalidatePanelReads();f.handler(f.normal);await f.context.readPanelResource('/api/v1/status');
 old.reject(Object.assign(new Error('old login expired'),{status:401}));await rejected;
});

await test('same-view bootstrap notifications join the snapshot instead of restarting authentication',async()=>{
 const f=fixture(),pending=deferred();f.state.authenticated=true;f.handler(url=>url==='/api/v1/services'?pending.promise:f.normal(url));
 const initial=f.context.refreshAll();await flush();const generation=f.panelLoad.generation;
 f.context.refreshPanelView('engineconfig');f.context.refreshPanelView('engineconfig');assert.equal(f.panelLoad.generation,generation);
 pending.resolve(f.normal('/api/v1/services'));await initial;assert.equal(f.calls.filter(call=>call.url==='/api/v1/auth/status').length,1);
});

await test('navigation joins recent lists and explicit refresh reads them again',async()=>{
 const f=fixture();f.state.authenticated=true;await f.context.refreshAll();const before=f.calls.filter(call=>call.url==='/api/v1/services').length;
 f.state.currentView='nodes';f.context.refreshPanelView('nodes');await f.panelLoad.request;
 assert.equal(f.calls.filter(call=>call.url==='/api/v1/services').length,before,'navigation ignored the recent shared list');
 await f.context.refreshAll();assert.equal(f.calls.filter(call=>call.url==='/api/v1/services').length,before+1,'explicit refresh reused a completed list');
});

await test('general refresh requests protected auxiliary data only after authentication',async()=>{
 const f=fixture();f.context.document.hidden=true;await f.context.refreshAll();
 assert.deepEqual(f.events,['razvilka:panel-refresh']);
 const loggedOut=fixture();loggedOut.handler(url=>url==='/api/v1/auth/status'?{authenticated:false}:loggedOut.normal(url));
 await loggedOut.context.refreshAll();assert.deepEqual(loggedOut.events,[]);
});

await test('inventory heartbeat shares a flight, fences logout and never redraws editable forms',async()=>{
 const f=fixture();f.state.authenticated=true;
 const pending=deferred();f.handler(()=>pending.promise);
 const first=f.context.refreshPanelInventory(),second=f.context.refreshPanelInventory();
 assert.equal(first,second);await flush();assert.equal(f.calls.length,1);
 pending.resolve(f.normal('/api/v1/panel/inventory'));assert.equal(await first,true);
 assert(f.renders.includes('renderComponents'));assert(!f.renders.includes('renderEngineControl'));assert(!f.renders.includes('renderDNS'));
 const late=deferred();f.handler(()=>late.promise);const request=f.context.refreshPanelInventory();await flush();
 f.state.authenticated=false;f.context.cancelPanelInventoryRefresh();f.state.components=[];
 const value=f.normal('/api/v1/panel/inventory');value.data.components=[{id:'private',installed:true}];late.resolve(value);
 assert.equal(await request,false);assert.equal(f.state.components.length,0);
 const calls=f.calls.length;f.state.authenticated=true;f.context.document.hidden=true;await f.context.refreshPanelInventory();assert.equal(f.calls.length,calls);
});

await test('inventory reads memory endpoint, stamps age and rejects pre-write data without comparing clocks',async()=>{
 const f=fixture();await f.context.refreshAll();
 assert(!f.calls.some(c=>['/api/v1/engines','/api/v1/system','/api/v1/components'].includes(c.url)));
 const value=f.normal('/api/v1/panel/inventory');
 value.observed_at='2020-01-01T00:00:00Z'; // Deliberately different router clock.
 value.data.components=[{id:'usque',installed:true,installed_version:'1.0.1',available_version:'1.0.3',checked_at:'2019-12-31T00:00:00Z'}];
 value.revision=2;
 f.state.inventoryInvalidatedAt=1000;
 f.context.acceptPanelInventory(value,1100);
 assert.equal(f.state.components[0].installed_version,'1.0.1');
 assert.equal(f.state.components[0].checked_at,'2019-12-31T00:00:00Z','local observation refreshed upstream check time');
 assert.equal(f.context.inventoryObservationStale(),false);
 const previous=f.state.components;
 value.data_age_ms=200;
 assert.throws(()=>f.context.acceptPanelInventory(value,1100),/ещё собираются/);
 assert.equal(f.state.components,previous);
 f.state.inventoryInvalidatedAt=0;
 value.state='retained';value.data_age_ms=2000;
 f.context.acceptPanelInventory(value,Date.now());
 assert.equal(f.context.inventoryObservationStale(),true);
 f.state.inventoryObservation.retained=false;f.state.inventoryObservation.ageMS=60000;
 assert.equal(f.context.inventoryObservationStale(),true);
});

await test('empty expired and invalid inventory never turn unavailable into uninstalled',async()=>{
 const f=fixture();await f.context.refreshAll();
 f.state.components=[{id:'usque',installed:true}];const previous=f.state.components;
 for(const change of [{state:'expired',data:undefined},{state:'empty',data:undefined},{data:{components:null,engines:[],system:{}}}]) {
   assert.throws(()=>f.context.acceptPanelInventory({...f.normal('/api/v1/panel/inventory'),...change}));
   assert.equal(f.state.components,previous);
 }
});

await test('pending inventory keeps retrying and its notice clears when the heartbeat recovers',async()=>{
 const f=fixture();f.state.authenticated=true;let pending=true;
 f.handler(url=>url==='/api/v1/panel/inventory'&&pending?{...f.normal(url),state:'empty',data:undefined}:f.normal(url));
 await f.context.refreshAll();
 assert.equal(f.state.dataLoad.inventory.phase,'busy');
 assert.equal(f.notices.at(-1)[1],'Сведения обновляются');
 assert.equal(f.state.noticeDetails.issues[0].busy,true);
 f.panelLoad.retryCount=3;f.retry();await flush();await flush();
 assert([...f.timers.values()].some(value=>value.ms===5000),'pending observation exhausted the failure retry budget');
 pending=false;assert.equal(await f.context.refreshPanelInventory(),true);
 assert.equal(f.$('#notice').hidden,true);assert.equal(f.state.noticeDetails,null);
 assert.equal(f.state.loadIssues.length,0);
});

await test('recovery removes only resolved sections and never dismisses a newer action notice',async()=>{
 const f=fixture();f.state.authenticated=true;
 f.handler(url=>{if(url==='/api/v1/services'||url==='/api/v1/panel/inventory')throw new Error('read failed');return f.normal(url);});
 await f.context.refreshAll();assert.equal(f.state.noticeDetails.issues.length,2);
 f.handler(f.normal);await f.context.refreshPanelInventory();
 assert.equal(f.state.noticeDetails.issues.length,1);assert.equal(f.state.noticeDetails.issues[0].section,'services');
 const action={error:'Apply failed'};f.context.showNotice('error','Ошибка применения','Сеть не изменена',action);
 await f.context.refreshAll(true);
 assert.equal(f.state.noticeDetails,action);assert.equal(f.$('#notice').hidden,false);
});

await test('loading details explain each pending section without a successful operation claim',async()=>{
 const f=fixture();f.context.esc=value=>String(value).replaceAll('<','&lt;');f.context.technicalDetails=()=>'';
 vm.runInContext(extract('renderGenericDetails'),f.context);
 const html=f.context.renderGenericDetails({detail_kind:'panel-load',issues:[{section:'inventory',busy:true,message:'Ожидание <данных>'}]});
 assert.match(html,/Ожидаем свежие сведения/);assert.match(html,/Компоненты/);assert.match(html,/&lt;данных>/);
 assert.doesNotMatch(html,/Операция завершена|detail-hero pass/);
});

await test('slow services cannot hold settings, engine metadata or other completed reads',async()=>{
 const f=fixture(),slow=deferred();f.handler(url=>url==='/api/v1/services'?slow.promise:f.normal(url));
 const refresh=f.context.refreshAll();await flush();await flush();
 assert(!f.renders.includes('renderSettings'),'hidden settings stayed untouched');assert(f.renders.includes('renderSystem'));assert(f.renders.includes('renderEngineControl'));
 assert.equal(f.state.dataLoad.services.loaded,false);assert.equal(f.state.dataLoad.engineConfigs.loaded,true);
 slow.resolve(f.normal('/api/v1/services'));assert.equal(await refresh,true);assert.equal(f.state.services.length,1);
});

await test('refresh coalesces and performs at most four reads in parallel',async()=>{
 const f=fixture(),pending=[];let active=0,max=0;
 f.handler(url=>{
  if(['/api/v1/auth/status','/api/v1/status'].includes(url))return f.normal(url);
  const d=deferred();active++;max=Math.max(max,active);
  pending.push(()=>{active--;d.resolve(f.normal(url));});return d.promise;
 });
 const first=f.context.refreshAll(),second=f.context.refreshAll();await flush();
 assert.equal(pending.length,4);assert.equal(f.calls.filter(c=>c.url==='/api/v1/auth/status').length,1);
 while(f.panelLoad.request){while(pending.length)pending.shift()();await flush();}
 assert.equal(await first,true);assert.equal(await second,true);assert.equal(max,4);
});

await test('failed services preserves last valid list and automatically retries only failed GET',async()=>{
 const f=fixture();await f.context.refreshAll();const prior=f.state.services;
 f.handler(url=>{if(url==='/api/v1/services')throw new Error('read unavailable');return f.normal(url);});
 await f.context.refreshAll();assert.equal(f.state.services,prior);assert.equal(f.state.dataLoad.services.loaded,true);
 assert.equal(f.state.dataLoad.services.phase,'error');
 f.handler(f.normal);f.calls.length=0;f.retry();await flush();await flush();
 assert.deepEqual(f.calls.map(c=>c.url),['/api/v1/auth/status','/api/v1/status','/api/v1/services']);
 assert.equal(f.state.dataLoad.services.phase,'ready');
});

await test('incomplete successful JSON does not erase the last valid services list',async()=>{
 const f=fixture();await f.context.refreshAll();const prior=f.state.services;
 f.handler(url=>url==='/api/v1/services'?null:f.normal(url));await f.context.refreshAll();
 assert.equal(f.state.services,prior);assert.equal(f.state.dataLoad.services.phase,'error');
});

for(const helper of ['refreshAfterMutation','refreshCoreAfterEdit'])await test(helper+' fences pre-write reads and obtains a post-write snapshot',async()=>{
 const f=fixture(),oldRead=deferred();let committed=false,reads=0;
 f.handler(url=>{if(url!=='/api/v1/services')return f.normal(url);reads++;return committed?[{id:'after-write'}]:oldRead.promise;});
 const initial=f.context.refreshAll();await flush();committed=true;
 assert.equal(await f.context[helper](),true);
 assert.equal(f.state.services[0].id,'after-write');assert.equal(reads,2);
 for(const key of ['engineConfigs','nodes','system'])assert.equal(f.state.dataLoad[key]?.phase,'ready',key+' was stranded by the canceled initial load');
 oldRead.resolve([{id:'before-write'}]);assert.equal(await initial,false);
 assert.equal(f.state.services[0].id,'after-write','late old body overwrote committed readback');
});

await test('public runtime metadata renders before the unauthenticated early return',async()=>{
 const f=fixture();f.handler(url=>url==='/api/v1/auth/status'?{authenticated:false}:f.normal(url));
 assert.equal(await f.context.refreshAll(),false);
 assert.deepEqual(f.calls.map(c=>c.url),['/api/v1/auth/status','/api/v1/status']);
 assert.equal(f.state.status.version,'fixture');assert(f.renders.includes('renderStatus'));
 assert.equal(f.$('#authScreen').hidden,false);
});

await test('late services refresh only the active dependent UI without replacing DNS provider inputs',async()=>{
 for(const [view,wanted] of [['dns','bindings'],['testlab','testlab'],['strategylab','strategy'],['engineconfig','engine']]) {
 const f=fixture(),slow=deferred(),counts={dns:[],bindings:[],testlab:[],warp:[],strategy:[],engine:[]};f.state.currentView=view;
 for(const [key,name] of Object.entries({dns:'renderDNS',bindings:'renderDNSServiceBindings',testlab:'renderTestLab',warp:'renderWarpManager',strategy:'renderStrategyLab',engine:'renderEngineControl'}))f.context[name]=()=>counts[key].push(f.state.services.length);
 f.handler(url=>url==='/api/v1/services'?slow.promise:f.normal(url));
 const refresh=f.context.refreshAll();await flush();await flush();slow.resolve(f.normal('/api/v1/services'));await refresh;
 assert.equal(counts[wanted].at(-1),1,view);
 if(view==='dns')assert.deepEqual(counts.dns,[0],'service arrival replaced editable DNS provider');
 if(view!=='engineconfig')assert.equal(counts.engine.length,0,'hidden engine editor redrawn');
 }
});

await test('late route options refresh the already rendered test matrix',async()=>{
 const f=fixture(),slow=deferred(),counts=[];f.state.currentView='testlab';
 f.context.renderTestLab=()=>counts.push(f.state.routeOptions?.length||0);
 f.handler(url=>url==='/api/v1/routes/options'?slow.promise:f.normal(url));
 const refresh=f.context.refreshAll();await flush();await flush();
 slow.resolve([{id:'direct'}]);await refresh;assert.equal(counts.at(-1),1);
});

await test('late DNS plan only redraws plan/actions and preserves typed provider fields',async()=>{
 const f=fixture();f.state.currentView='dns';f.context.esc=String;vm.runInContext(extract('renderDNSPlan'),f.context);
 f.state.dns={dirty:true};f.state.dnsPlan={ready:false,recommendation:'fixture plan',checks:[],steps:[]};
 f.$('#dnsCustomName').value='unsaved DNS';f.$('#dnsNextDNSID').value='unsaved ID';
 f.context.renderDNS=()=>{f.$('#dnsCustomName').value='';f.$('#dnsNextDNSID').value='';};
 f.context.renderPanelSection('dnsPlan');
 assert.equal(f.$('#dnsCustomName').value,'unsaved DNS');assert.equal(f.$('#dnsNextDNSID').value,'unsaved ID');
 assert.match(f.$('#dnsPlan').innerHTML,/fixture plan/);
});

await test('auxiliary activity read failure does not block core loading',async()=>{
 const f=fixture();f.activityError(new Error('activity failed'));await f.context.refreshAll();
 assert.equal(f.state.services.length,1);assert(!f.renders.includes('renderSettings'),'hidden settings stayed untouched');
});

await test('activity cannot gate reads; a busy section retries without suppressing unrelated sections',async()=>{
 const f=fixture();f.activity(true);
 f.handler(url=>{if(url==='/api/v1/services')throw Object.assign(new Error('busy'),{status:409,payload:{code:'RESTORE_OPERATION_BUSY'}});return f.normal(url);});
 await f.context.refreshAll();
 assert(f.calls.some(c=>c.url==='/api/v1/panel/inventory'));assert.equal(f.state.dataLoad.services.phase,'busy');
 assert.equal(f.state.dataLoad.system.loaded,true);assert.equal(f.state.dataLoad.engines.loaded,true);
 f.handler(f.normal);f.retry();await flush();await flush();assert.equal(f.state.services.length,1);
});

await test('late pre-logout read cannot restore protected data or schedule retries',async()=>{
 const f=fixture(),slow=deferred();f.handler(url=>url==='/api/v1/services'?slow.promise:f.normal(url));
 const refresh=f.context.refreshAll();await flush();f.context.cancelPanelRefresh();f.$('#authScreen').hidden=false;
 slow.resolve(f.normal('/api/v1/services'));assert.equal(await refresh,false);
 assert.equal(f.state.services.length,0);assert.equal(f.timers.size,0);
});

await test('section 401 cancels sibling reads and opens login without stale responses',async()=>{
 const f=fixture(),slow=deferred();
 f.handler(url=>url==='/api/v1/services'?Promise.reject(Object.assign(new Error('login'),{status:401})):url==='/api/v1/panel/inventory'?slow.promise:f.normal(url));
 const refresh=f.context.refreshAll();await flush();slow.resolve([{id:'private-old-result'}]);await refresh;
 assert.equal(f.$('#authScreen').hidden,false);assert.equal(f.state.engines,undefined);assert.equal(f.timers.size,0);
});

await test('GET deadline also covers delayed JSON body, aborts fetch and releases its timer',async()=>{
 const timers=new Map();let timedSignal;
 const context={Headers,AbortController,ADMIN_TOKEN_KEY:'fixture',sessionStorage:{getItem:()=>null},
 setTimeout(fn){timers.set(1,fn);return 1;},clearTimeout(id){timers.delete(id);},
 fetch:async(_url,options)=>{timedSignal=options.signal;return {ok:true,json:()=>new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(Object.assign(new Error('abort'),{name:'AbortError'}))))};}};
 vm.createContext(context);vm.runInContext(extract('api')+'\n'+extract('friendlyErrorMessage'),context);
 const pending=context.api('/api/v1/services');await flush();timers.get(1)();
 await assert.rejects(pending,error=>error.code==='READ_TIMEOUT');assert.equal(timedSignal.aborted,true);assert.equal(timers.size,0);
});

await test('mutation uses caller cancellation without read timeout or automatic replay',async()=>{
 const controller=new AbortController();let observed,timers=0,calls=0;
 const context={Headers,AbortController,ADMIN_TOKEN_KEY:'fixture',sessionStorage:{getItem:()=>null},
 setTimeout(){timers++;},clearTimeout(){},fetch:async(_url,options)=>{calls++;observed=options.signal;return {ok:true,json:async()=>({ok:true})};}};
 vm.createContext(context);vm.runInContext(extract('api'),context);
 await context.api('/api/v1/apply',{method:'POST',signal:controller.signal});assert.equal(observed,controller.signal);assert.equal(timers,0);assert.equal(calls,1);
});
console.log(JSON.stringify({status:'passed',tests:count}));
await import('./test-source-offline-ui.mjs');
