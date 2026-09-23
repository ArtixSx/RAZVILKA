import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const names=['panelSectionState','panelBusy','panelSnapshotCurrent','schedulePanelRetry','cancelPanelRefresh','renderPanelLoad','renderPanelSection','acceptPanelSection','settlePanelReads','refreshAll','refreshAfterMutation','refreshCoreAfterEdit','loadPanelSnapshot'];
const extract=name=>{const match=source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));assert(match,name);return match[0];};
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};}
function fixture(){
 const elements=new Map(),calls=[],renders=[],timers=new Map(),notices=[];
 let timer=0,activity=false,activityError=null,handler;
 const state={status:{},services:[],engineConfigs:[],dataLoad:{},loadIssues:[]};
 const panelLoad={generation:0,request:null,controller:null,retryTimer:null,retryCount:0};
 const $=id=>{if(!elements.has(id))elements.set(id,{hidden:true,textContent:'',value:'',classList:{toggle(){}}});return elements.get(id);};
 const api=async(url,options={})=>{calls.push({url,options});return handler(url,options);};
 const context={state,panelLoad,$,AbortController,Date,console,document:{hidden:false},
 setTimeout(fn,ms){const id=++timer;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},
 api,hideAuth(){$('#authScreen').hidden=true;},showAuth(){$('#authScreen').hidden=false;context.cancelPanelRefresh();},
 refreshNodeActivity:async()=>{if(activityError)throw activityError;return activity;},scheduleNodeActivity(){},
 showNotice:(...args)=>notices.push(args),consoleInitialSetup(){},acceptDeviceList:v=>{state.devices=v;},
 };
 for(const name of ['renderStatus','renderSettings','renderSystem','renderMetrics','renderServices','renderOverviewQuickServices','renderOverviewServices','renderReadiness','renderEngines','renderEngineControl','renderComponents','renderWarpManager','renderSources','renderNodes','renderConnections','renderDevices','renderTestLab','renderEngineLab','renderAudit','renderStrategyLab','renderDNS','renderDNSPlan','renderDNSServiceBindings'])context[name]=()=>renders.push(name);
 vm.createContext(context);vm.runInContext(names.map(extract).join('\n'),context);
 const arrays=new Set(['/api/v1/services','/api/v1/engines','/api/v1/engine-configs','/api/v1/components','/api/v1/sources','/api/v1/routes/options']);
 const normal=url=>{
   if(url==='/api/v1/auth/status')return {authenticated:true};
   if(url==='/api/v1/status')return {version:'fixture',authenticated:true,revision:34};
   if(url==='/api/v1/services')return [{id:'telegram',name:'Telegram',enabled:true}];
   return arrays.has(url)?[]:{};
 };
 handler=normal;
 return {context,state,panelLoad,calls,renders,timers,notices,$,normal,
   handler:fn=>{handler=fn;},activity:value=>{activity=value;},activityError:value=>{activityError=value;},
   retry(){const item=[...timers.values()].find(value=>value.ms===10000||value.ms===5000);assert(item,'retry missing');timers.clear();item.fn();},
 };
}
let count=0;
async function test(name,fn){await fn();count++;console.log('PASS',name);}

await test('slow services cannot hold settings, engine metadata or other completed reads',async()=>{
 const f=fixture(),slow=deferred();f.handler(url=>url==='/api/v1/services'?slow.promise:f.normal(url));
 const refresh=f.context.refreshAll();await flush();await flush();
 assert(f.renders.includes('renderSettings'));assert(f.renders.includes('renderSystem'));assert(f.renders.includes('renderEngineControl'));
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

await test('late service catalogue updates dependent lists without replacing the DNS provider form',async()=>{
 const f=fixture(),slow=deferred(),counts={dns:[],bindings:[],testlab:[],warp:[],strategy:[],engine:[]};
 for(const [key,name] of Object.entries({dns:'renderDNS',bindings:'renderDNSServiceBindings',testlab:'renderTestLab',warp:'renderWarpManager',strategy:'renderStrategyLab',engine:'renderEngineControl'}))f.context[name]=()=>counts[key].push(f.state.services.length);
 f.handler(url=>url==='/api/v1/services'?slow.promise:f.normal(url));
 const refresh=f.context.refreshAll();await flush();await flush();
 slow.resolve(f.normal('/api/v1/services'));await refresh;
 for(const key of ['bindings','testlab','warp','strategy','engine'])assert.equal(counts[key].at(-1),1,key);
 assert.deepEqual(counts.dns,[0],'service arrival rerendered the editable DNS provider');
});

await test('late route options refresh the already rendered test matrix',async()=>{
 const f=fixture(),slow=deferred(),counts=[];
 f.context.renderTestLab=()=>counts.push(f.state.routeOptions?.length||0);
 f.handler(url=>url==='/api/v1/routes/options'?slow.promise:f.normal(url));
 const refresh=f.context.refreshAll();await flush();await flush();
 slow.resolve([{id:'direct'}]);await refresh;assert.equal(counts.at(-1),1);
});

await test('late DNS plan only redraws plan/actions and preserves typed provider fields',async()=>{
 const f=fixture();f.context.esc=String;vm.runInContext(extract('renderDNSPlan'),f.context);
 f.state.dns={dirty:true};f.state.dnsPlan={ready:false,recommendation:'fixture plan',checks:[],steps:[]};
 f.$('#dnsCustomName').value='unsaved DNS';f.$('#dnsNextDNSID').value='unsaved ID';
 f.context.renderDNS=()=>{f.$('#dnsCustomName').value='';f.$('#dnsNextDNSID').value='';};
 f.context.renderPanelSection('dnsPlan');
 assert.equal(f.$('#dnsCustomName').value,'unsaved DNS');assert.equal(f.$('#dnsNextDNSID').value,'unsaved ID');
 assert.match(f.$('#dnsPlan').innerHTML,/fixture plan/);
});

await test('auxiliary activity read failure does not block core loading',async()=>{
 const f=fixture();f.activityError(new Error('activity failed'));await f.context.refreshAll();
 assert.equal(f.state.services.length,1);assert(f.renders.includes('renderSettings'));
});

await test('activity cannot gate reads; a busy section retries without suppressing unrelated sections',async()=>{
 const f=fixture();f.activity(true);
 f.handler(url=>{if(url==='/api/v1/services')throw Object.assign(new Error('busy'),{status:409,payload:{code:'RESTORE_OPERATION_BUSY'}});return f.normal(url);});
 await f.context.refreshAll();
 assert(f.calls.some(c=>c.url==='/api/v1/system'));assert.equal(f.state.dataLoad.services.phase,'busy');
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
 f.handler(url=>url==='/api/v1/services'?Promise.reject(Object.assign(new Error('login'),{status:401})):url==='/api/v1/engines'?slow.promise:f.normal(url));
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
