import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source=readFileSync(new URL('../cmd/razvilka/web/console-autonomy.js',import.meta.url),'utf8');
const coreSource=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const hideAuthSource=coreSource.slice(coreSource.indexOf('function hideAuth() {'),coreSource.indexOf('\nasync function submitSetup('));
const showAuthSource=coreSource.slice(coreSource.indexOf('function showAuth('),coreSource.indexOf('\nfunction hideAuth() {')).replace('function showAuth(', 'function actualShowAuth(');
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};}
function snapshot(revision=1){
 const window={mode:'check',start:'02:00',end:'03:00',days:[1]};
 return {policy:{revision,enabled:true,setup_complete:true,timezone:'UTC',all_lan:false,default_sources:['192.0.2.1/32'],source_ids:['feed-fixture'],protocols:['vless'],preferred_routes:[],reserve_target:2,candidates_per_round:2,check_seconds:300,reserve_seconds:600,application:window,components:window},services:{},runtime:{},catalog_services:[],source_presets:[],server_time:'2026-09-13T10:00:00Z'};
}
function fixture(authenticated=true,staticInputs=[]){
 const elements=new Map(),documentListeners=new Map(),windowListeners=new Map(),requests=[],timeouts=new Map(),published=[],inputs=new Map([['static',staticInputs.map(input=>({closest:()=>({}),...input}))]]);
 let timerID=0,authCalls=0;
 function element(id){
  if(!elements.has(id)){const classes=new Set();elements.set(id,{value:'',textContent:'',innerHTML:'',hidden:false,disabled:false,checked:false,options:[],dataset:{},open:false,events:new Map(),classList:{toggle(){},add:value=>classes.add(value),remove:value=>classes.delete(value),contains:value=>classes.has(value)},addEventListener(type,fn){this.events.set(type,fn);},setAttribute(){},removeAttribute(){},close(){this.open=false;},showModal(){this.open=true;},focus(){},reset(){}});}
  const result=elements.get(id);
  result.contains=target=>target===result;
  result.closest=()=>null;
  if(['a1-starterItems','a1-initialExtras','a1-appDays','a1-engineDays','a1-wizardSources'].includes(id)&&!Object.getOwnPropertyDescriptor(result,'innerHTML').get){
   let html='';Object.defineProperty(result,'innerHTML',{get:()=>html,set(value){html=value;inputs.set(id,[...value.matchAll(/<input\b([^>]+)>/g)].map(([,attrs])=>({name:/name="([^"]*)"/.exec(attrs)?.[1],value:/value="([^"]*)"/.exec(attrs)?.[1],checked:/\bchecked\b/.test(attrs),closest:()=>({})})));}});
  }
  return result;
 }
 function listen(map,type,fn){if(!map.has(type))map.set(type,[]);map.get(type).push(fn);}
 function dispatch(map,event){for(const listener of map.get(event.type)||[])listener(event);}
 const document={hidden:false,getElementById:element,querySelectorAll:selector=>{const scoped=/^#(a1-[\w-]+) input(:checked)?$/.exec(selector);if(scoped)return (inputs.get(scoped[1])||[]).filter(input=>!scoped[2]||input.checked);const name=/input\[name="([^"]*)"\]/.exec(selector)?.[1];return name?[...inputs.values()].flat().filter(input=>input.name===name&&(!selector.includes(':checked')||input.checked)):[];},addEventListener:(type,fn)=>listen(documentListeners,type,fn),dispatchEvent:event=>dispatch(documentListeners,event)};
 const window={location:{hash:'#autopilot'},addEventListener:(type,fn)=>listen(windowListeners,type,fn),dispatchEvent:event=>{published.push(event);dispatch(windowListeners,event);}};
 const context={document,window,AbortController,URL,console,sessionStorage:{getItem:()=>''},state:{authenticated,services:[],currentView:'autopilot'},Event:class{constructor(type){this.type=type;}},CustomEvent:class{constructor(type,options={}){this.type=type;this.detail=options.detail;}},setView(view){context.state.currentView=view;},confirm:()=>{throw Error('native confirm must not run');},askConfirmation:async()=>true,$:selector=>element(selector.startsWith('#')?selector.slice(1):selector),ADMIN_TOKEN_KEY:'fixture-admin-token',
  setTimeout(fn,ms){const id=++timerID;timeouts.set(id,{fn,ms});return id;},clearTimeout:id=>timeouts.delete(id),setInterval:()=>++timerID,clearInterval(){},
  showAuth(){authCalls++;document.dispatchEvent({type:'razvilka:auth-required'});},
  fetch(path,options){const pending=deferred();requests.push({path,options,...pending});return pending.promise;}
 };
 vm.runInNewContext(source,context);
 vm.runInNewContext(hideAuthSource+'\n'+showAuthSource,context);
 return {requests,timeouts,published,contextView:()=>context.state.currentView,confirmWith:fn=>{context.askConfirmation=fn;},e:id=>element('a1-'+id),inputs:name=>[...inputs.values()].flat().filter(input=>input.name===name),authCalls:()=>authCalls,
  hideAuth:()=>context.hideAuth(),actualShowAuth:status=>context.actualShowAuth(status||null,'Войдите снова.'),coreElement:element,
  event:(type,detail)=>{if(type==='razvilka:auth-restored')context.state.authenticated=true;if(type==='razvilka:auth-required')context.state.authenticated=false;document.dispatchEvent({type,detail});},
  respond(index,status,data){if(requests[index].path==='/api/v1/panel/autonomy'&&status===200&&data?.policy)data={schema:1,instance_id:'a'.repeat(32),revision:data.policy.revision||1,observed_at:data.server_time,data_age_ms:0,state:'available',dataplane:'not-checked',data};requests[index].resolve({status,ok:status>=200&&status<300,json:async()=>data});},
  delayedBody(index,status){const body=deferred();requests[index].resolve({status,ok:status>=200&&status<300,json:()=>body.promise});return body;},
  clickTarget:target=>document.dispatchEvent({type:'click',target}),
  click(id){element('a1-'+id).events.get('click')({preventDefault(){}});},
  runRetry(){const entry=[...timeouts.entries()].find(([,value])=>value.ms===1500);assert.ok(entry,'retry timer missing');timeouts.delete(entry[0]);entry[1].fn();}
 };
}
let passed=0;
async function test(name,fn){await fn();passed++;console.log('PASS',name);}

await test('initial setup discovery is not canceled by an early protected autonomy read',async()=>{
 const f=fixture(false);assert.equal(f.requests.length,0,'protected request ran before core authentication discovery');
 f.event('razvilka:panel-refresh');f.event('razvilka:view-change','subscription-settings');
 assert.equal(f.requests.length,0,'unauthenticated navigation started protected reads');
 f.actualShowAuth({authenticated:false,setup_required:true,username:''});
 assert.equal(f.coreElement('authSetupPanel').hidden,false);assert.equal(f.coreElement('authLoginPanel').hidden,true);
 f.event('razvilka:view-change','autopilot');assert.equal(f.requests.length,0);
 f.hideAuth();assert.equal(f.requests.length,1);assert.equal(f.requests[0].path,'/api/v1/panel/autonomy');
 f.respond(0,200,snapshot(1));await flush();assert.equal(f.e('workspace').hidden,false);
});

await test('initial 401 notice clears on restored login and fresh state is requested',async()=>{
 const f=fixture();f.respond(0,401,{});await flush();
 assert.equal(f.authCalls(),1);assert.match(f.e('notice').textContent,/Войдите/);assert.equal(f.e('workspace').hidden,true);
 f.event('razvilka:auth-restored');assert.equal(f.e('notice').textContent,'');assert.equal(f.requests.length,2);
 f.respond(1,200,snapshot(2));await flush();
 assert.equal(f.e('workspace').hidden,false);assert.equal(f.e('authRequired').hidden,true);assert.equal(f.e('notice').textContent,'');
 assert.match(f.e('connectionLabel').textContent,/Состояние роутера/);
});

await test('late pre-login 401 cannot reopen authentication or undo current loading admission',async()=>{
 const f=fixture();f.event('razvilka:auth-restored');
 assert.equal(f.requests[0].options.signal.aborted,true);assert.equal(f.requests.length,2);
 f.respond(0,401,{});await flush();
 assert.equal(f.authCalls(),0);assert.equal(f.e('notice').textContent,'');
 f.click('reloadButton');assert.equal(f.requests.length,2,'old finally cleared the current loading flag');
 f.respond(1,200,snapshot(3));await flush();assert.equal(f.e('workspace').hidden,false);
});

await test('authentication epoch checked again after delayed JSON parsing',async()=>{
 const f=fixture(),oldBody=f.delayedBody(0,401);await flush();
 f.event('razvilka:auth-restored');f.respond(1,200,snapshot(4));await flush();
 oldBody.resolve({error:'old-session-error'});await flush();
 assert.equal(f.authCalls(),0);assert.equal(f.e('notice').textContent,'');assert.equal(f.e('workspace').hidden,false);
});

for(const mode of ['http-error','network-error','success'])await test('logout rejects late refresh '+mode,async()=>{
 const f=fixture();f.event('razvilka:auth-required');const notice=f.e('notice').textContent;
 if(mode==='network-error')f.requests[0].reject(new Error('obsolete-network-error'));
 else f.respond(0,mode==='success'?200:503,mode==='success'?snapshot():{error:'obsolete-server-error'});
 await flush();assert.equal(f.e('notice').textContent,notice);assert.equal(f.e('workspace').hidden,true);
 assert.equal(f.published.filter(event=>event.type==='razvilka:autonomy-state').length,0);
 assert.equal(f.published.filter(event=>event.type==='razvilka:autonomy-error').length,1);
});

await test('late source failure cannot replace a post-login notice or source state',async()=>{
 const f=fixture();f.respond(0,200,snapshot());await flush();
 f.event('razvilka:view-change','subscription-settings');
 const oldSource=f.requests.findIndex(request=>request.path==='/api/v1/node-feeds');assert.notEqual(oldSource,-1);
 f.event('razvilka:auth-required');f.event('razvilka:auth-restored');
 const latestSource=f.requests.findLastIndex(request=>request.path==='/api/v1/node-feeds');
 const latestState=f.requests.findLastIndex(request=>request.path==='/api/v1/panel/autonomy');
 f.respond(latestSource,200,{sources:[]});f.respond(latestState,200,snapshot(2));await flush();
 f.requests[oldSource].reject(new Error('obsolete-source-error'));await flush();
 assert.equal(f.e('notice').textContent,'');assert.match(f.e('sourcesList').innerHTML,/Подписки пока не сохранены/);
});

await test('late busy mutation is rejected before scheduling an automatic retry',async()=>{
 const f=fixture();f.respond(0,200,snapshot());await flush();f.click('pauseButton');
 const oldMutation=f.requests.findIndex(request=>request.options.method==='PUT');assert.notEqual(oldMutation,-1);
 f.event('razvilka:auth-required');f.event('razvilka:auth-restored');
 const fresh=f.requests.length-1;f.respond(fresh,200,snapshot(2));await flush();
 f.respond(oldMutation,409,{not_started:true,code:'RESTORE_OPERATION_BUSY'});await flush();
 assert.equal([...f.timeouts.values()].filter(timer=>timer.ms===1500).length,0);
 assert.equal(f.requests.filter(request=>request.options.method==='PUT').length,1);
 assert.equal(f.e('notice').textContent,'');
});

await test('already scheduled retry cannot replay a mutation in a new session',async()=>{
 const f=fixture();f.respond(0,200,snapshot());await flush();f.click('pauseButton');
 f.respond(1,409,{not_started:true,code:'RESTORE_OPERATION_BUSY'});await flush();
 f.event('razvilka:auth-required');f.event('razvilka:auth-restored');
 f.runRetry();await flush();assert.equal(f.requests.filter(request=>request.options.method==='PUT').length,1);
 f.respond(f.requests.length-1,200,snapshot(2));await flush();assert.equal(f.e('notice').textContent,'');
});

await test('pause completion cannot announce success after logout during its readback',async()=>{
 const f=fixture();f.respond(0,200,snapshot());await flush();f.click('pauseButton');
 f.respond(1,200,{});await flush();assert.equal(f.requests[2].path,'/api/v1/autonomy');
 f.event('razvilka:auth-required');const notice=f.e('notice').textContent;
 f.respond(2,200,snapshot(2));await flush();assert.equal(f.e('notice').textContent,notice);assert.equal(f.e('workspace').hidden,true);
});

await test('ordinary core refresh hideAuth calls preserve active mutation and open inspector',async()=>{
 const f=fixture();f.actualShowAuth();
 // The initial visible auth screen causes exactly one restoration transition.
 f.hideAuth();assert.equal(f.requests[0].options.signal.aborted,true);assert.equal(f.requests.length,2);
 f.respond(1,200,snapshot(2));await flush();
 f.coreElement('detailsPanel').classList.add('open');f.click('pauseButton');
 const mutation=f.requests[2];assert.equal(mutation.options.method,'PUT');
 // refreshAll calls this twice during an ordinary authenticated refresh.
 f.hideAuth();f.hideAuth();
 assert.equal(mutation.options.signal.aborted,false);assert.equal(f.requests.length,3);
 assert.equal(f.coreElement('detailsPanel').classList.contains('open'),true);
 f.respond(2,200,{});await flush();f.respond(3,200,snapshot(3));await flush();
 assert.match(f.e('notice').textContent,/Автоматика на паузе/);
});

await test('actual logout and login still invalidate the previous mutation and close inspector',async()=>{
 const f=fixture();f.actualShowAuth();f.hideAuth();f.respond(1,200,snapshot(2));await flush();f.click('pauseButton');
 f.coreElement('detailsPanel').classList.add('open');f.actualShowAuth();
 assert.equal(f.requests[2].options.signal.aborted,true);assert.equal(f.coreElement('authScreen').hidden,false);
 f.hideAuth();assert.equal(f.requests.length,4);assert.equal(f.coreElement('detailsPanel').classList.contains('open'),false);
 f.respond(3,200,snapshot(3));await flush();f.respond(2,401,{});await flush();
 assert.equal(f.coreElement('authScreen').hidden,true);assert.equal(f.e('notice').textContent,'');
 assert.equal(f.requests.filter(request=>request.options.method==='PUT').length,1);
});

await test('before first setup the hero action opens the wizard without writing',async()=>{
 const f=fixture(),initial=snapshot();initial.policy.setup_complete=false;initial.policy.enabled=false;
 f.respond(0,200,initial);await flush();
 assert.equal(f.e('pauseButton').textContent,'Начать настройку');assert.equal(f.e('pauseButton').disabled,false);
 const before=f.requests.length;f.click('pauseButton');await flush();
 assert.equal(f.requests.length,before,'opening the wizard must not send a request');
});

await test('quick start saves a whole-network policy through the shared consent path',async()=>{
 // The protocol boxes are static wizard markup that fillWizard checks.
 const f=fixture(true,[{name:'protocol',value:'vless',checked:true}]),initial=snapshot();initial.policy.setup_complete=false;initial.policy.enabled=false;initial.policy.failure_confirm_seconds=60;initial.policy.max_switches_per_hour=6;
 initial.starter={eligible:true,items:[{id:'youtube',name:'YouTube'},{id:'discord',name:'Discord'}]};
 f.respond(0,200,initial);await flush();
 assert.equal(f.e('quickStart').hidden,false);assert.equal(f.e('wizardLayout').hidden,true);
 assert.match(f.e('quickStarter').textContent,/Для автоматического подбора выбраны: YouTube, Discord/);
 assert.match(f.e('quickStarter').textContent,/Подключение включится после проверки/);
 assert.doesNotMatch(f.e('quickStarter').textContent,/Сразу подключаются/);
 const before=f.requests.length;f.click('quickStartButton');await flush();
 assert.equal(f.requests.length,before,'without consent nothing is sent');assert.match(f.e('quickError').textContent,/Отметьте разрешение/);
 f.e('quickConsent').checked=true;f.click('quickStartButton');await flush();
 const put=f.requests.find(r=>r.options?.method==='PUT');assert.ok(put,'policy was not saved: '+f.e('quickError').textContent);
 const body=JSON.parse(put.options.body);
 assert.equal(put.path,'/api/v1/autonomy');assert.equal(body.confirm,'SAVE_AUTONOMY');
 assert.equal(body.policy.all_lan,true);assert.equal(body.policy.enabled,true);assert.equal(body.policy.setup_complete,true);assert.deepEqual(body.policy.default_sources,[]);
});

await test('advanced setup keeps the full four-step wizard',async()=>{
 const f=fixture(),initial=snapshot();initial.policy.setup_complete=false;
 f.respond(0,200,initial);await flush();f.click('quickAdvanced');
 assert.equal(f.e('quickStart').hidden,true);assert.equal(f.e('wizardLayout').hidden,false);
});

await test('changed starter definition preserves subset and revokes previous consent',async()=>{
 const f=fixture(),initial=snapshot();initial.policy.setup_complete=false;
 initial.starter={eligible:true,sha256:'a'.repeat(64),items:[{id:'one',name:'One',domains:1},{id:'two',name:'Two',domains:2}]};
 f.respond(0,200,initial);await flush();assert.equal(f.inputs('initial-starter').filter(x=>x.checked).length,2);
 f.inputs('initial-starter')[1].checked=false;f.e('confirmConsent').checked=true;f.e('wizardForm').events.get('input')();
 f.event('razvilka:view-change','onboard');
 const changed=structuredClone(initial);changed.starter.sha256='b'.repeat(64);changed.starter.items.push({id:'three',name:'Three',domains:3});
 f.respond(1,200,changed);await flush();
 assert.deepEqual(f.inputs('initial-starter').filter(x=>x.checked).map(x=>x.value),['one']);
 assert.equal(f.e('confirmConsent').checked,false);assert.match(f.e('wizardError').textContent,/Состав базового набора изменился/);
});

await test('unchanged starter refresh keeps choice and consent',async()=>{
 const f=fixture(),initial=snapshot();initial.policy.setup_complete=false;initial.starter={eligible:true,sha256:'a'.repeat(64),items:[{id:'one',name:'One',domains:1},{id:'two',name:'Two',domains:2}]};
 f.respond(0,200,initial);await flush();f.inputs('initial-starter')[1].checked=false;f.e('confirmConsent').checked=true;f.e('wizardForm').events.get('input')();
 f.event('razvilka:view-change','onboard');f.respond(1,200,initial);await flush();
 assert.deepEqual(f.inputs('initial-starter').filter(x=>x.checked).map(x=>x.value),['one']);assert.equal(f.e('confirmConsent').checked,true);
});

await test('forced read waits for earlier poll and then obtains a newer snapshot',async()=>{
 const f=fixture();f.respond(0,200,snapshot(1));await flush();
 f.event('razvilka:view-change','onboard');f.click('reloadButton');f.click('reloadButton');assert.equal(f.requests.length,2,'forced reload overlapped poll');
 f.respond(1,200,snapshot(2));await flush();assert.equal(f.requests.length,3,'forced reload was dropped');
 f.respond(2,200,snapshot(3));await flush();assert.match(f.e('revisionLabel').textContent,/3/);assert.equal(f.requests.length,3,'repeated clicks queued redundant forced reads');
});

await test('queued forced read is discarded across authentication change',async()=>{
 const f=fixture();f.click('reloadButton');f.event('razvilka:auth-required');f.event('razvilka:auth-restored');
 f.respond(0,200,snapshot(1));await flush();assert.equal(f.requests.length,2,'old-session reload was replayed');
 f.respond(1,200,snapshot(2));await flush();assert.match(f.e('revisionLabel').textContent,/2/);
});

await test('ordinary polling uses published snapshot and retained data cannot report enabled',async()=>{
 const f=fixture();assert.equal(f.requests[0].path,'/api/v1/panel/autonomy');f.respond(0,200,snapshot(1));await flush();
 f.event('razvilka:view-change','onboard');
 f.respond(1,200,{schema:1,instance_id:'a'.repeat(32),revision:2,state:'retained',dataplane:'not-checked',data_age_ms:10,observed_at:'2026-09-13T10:00:01Z',data:snapshot(1)});await flush();
 assert.equal(f.e('heroState').textContent,'Состояние обновляется');assert.equal(f.e('healthyCount').textContent,'—');
 assert.equal(f.e('pauseButton').disabled,false,'pause must remain available during a long operation');
 assert.equal(f.published.at(-1).type,'razvilka:autonomy-error');
});

await test('poll preceding completed write cannot overwrite its direct readback',async()=>{
 const f=fixture();f.respond(0,200,snapshot(1));await flush();f.click('pauseButton');
 f.respond(1,200,{});await flush();assert.equal(f.requests[2].path,'/api/v1/autonomy');
 const changed=snapshot(2);changed.policy.enabled=false;changed.server_time='2026-09-13T10:00:02Z';
 f.respond(2,200,changed);await flush();f.event('razvilka:view-change','onboard');
 f.respond(3,200,snapshot(1));await flush();
 assert.match(f.e('revisionLabel').textContent,/2/);assert.equal(f.e('pauseButton').textContent,'Возобновить автоматику');
});

await test('expired or malformed publication never starts an unprotected live fallback',async()=>{
 for(const response of [{state:'expired'},{schema:1,state:'available',data:snapshot()},{}]) {
  const f=fixture();f.respond(0,200,response);await flush();
  assert.equal(f.requests.length,1);assert.equal(f.published.filter(x=>x.type==='razvilka:autonomy-state').length,0);
  assert.equal(f.e('connectionLabel').textContent,'Нет свежего ответа');
 }
});

await test('source removal readback preserves unsaved wizard fields',async()=>{
 const f=fixture();f.respond(0,200,snapshot(1));await flush();
 f.e('scopeAddresses').value='192.168.1.77/32';f.e('wizardForm').events.get('input')();
 f.event('razvilka:source-consent-changed');assert.equal(f.requests[1].path,'/api/v1/autonomy');
 const changed=snapshot(2);changed.policy.default_sources=['192.168.1.88/32'];f.respond(1,200,changed);await flush();
 assert.equal(f.e('scopeAddresses').value,'192.168.1.77/32','background readback discarded local work');
});

await test('login during worker operation shows saved permissions with stale status',async()=>{
 const f=fixture();f.respond(0,200,{schema:1,instance_id:'b'.repeat(32),revision:1,state:'retained',dataplane:'not-checked',data_age_ms:5000,observed_at:'2026-09-13T10:00:00Z',data:snapshot(1)});await flush();
 assert.equal(f.e('workspace').hidden,false);assert.equal(f.e('heroState').textContent,'Состояние обновляется');
 assert.equal(f.e('scopeAddresses').value,'192.0.2.1/32');assert.equal(f.e('pauseButton').disabled,false);
 assert.match(f.e('connectionLabel').textContent,/Последние настройки/);
});

await test('home navigation and panel refresh retry an unavailable publication without replacing edits',async()=>{
 const f=fixture();f.respond(0,200,{state:'expired'});await flush();
 f.event('razvilka:view-change','overview');assert.equal(f.requests.length,2);
 assert.equal(f.requests[1].path,'/api/v1/panel/autonomy');
 f.event('razvilka:panel-refresh');assert.equal(f.requests.length,2,'refresh overlapped the admitted read');
 f.respond(1,200,snapshot(1));await flush();
 assert.equal(f.published.at(-1).type,'razvilka:autonomy-state');
 f.e('scopeAddresses').value='192.168.1.77/32';f.e('wizardForm').events.get('input')();
 f.event('razvilka:panel-refresh');assert.equal(f.requests[2].path,'/api/v1/panel/autonomy');
 const changed=snapshot(2);changed.policy.default_sources=['192.168.1.88/32'];f.respond(2,200,changed);await flush();
 assert.equal(f.e('scopeAddresses').value,'192.168.1.77/32');
 assert.equal(f.e('workspace').hidden,false);
});

await test('logout fences a late read started by the general refresh button',async()=>{
 const f=fixture();f.respond(0,200,snapshot(1));await flush();
 f.event('razvilka:panel-refresh');assert.equal(f.requests.length,2);
 f.event('razvilka:auth-required');f.respond(1,200,snapshot(2));await flush();
 assert.equal(f.e('workspace').hidden,true);
 assert.equal(f.published.filter(x=>x.type==='razvilka:autonomy-state').length,1);
});

await test('dirty source form keeps rendered revision across a newer source read',async()=>{
 const f=fixture();f.respond(0,200,snapshot());await flush();
 f.event('razvilka:view-change','subscription-settings');
 let reads=f.requests.map((r,i)=>({r,i})).filter(x=>x.r.path==='/api/v1/node-feeds');
 const saved={source_id:'feed-example',saved:true,revision:1,enabled:true,refresh_interval_minutes:60};
 f.respond(reads.at(-1).i,200,{sources:[saved]});await flush();
 const html=f.e('sourcesList').innerHTML;
 f.e('sourcesList').events.get('input')({});
 f.event('razvilka:view-change','subscription-settings');
 reads=f.requests.map((r,i)=>({r,i})).filter(x=>x.r.path==='/api/v1/node-feeds');
 f.respond(reads.at(-1).i,200,{sources:[{...saved,revision:2,enabled:false}]});await flush();
 assert.equal(f.e('sourcesList').innerHTML,html);
 const form={dataset:{feedForm:'feed-example'},elements:{enabled:{value:'true'},interval:{value:'90'}}};
 f.e('sourcesList').events.get('submit')({preventDefault(){},target:{closest:()=>form}});
 const write=f.requests.at(-1);assert.equal(write.options.method,'PUT');
 assert.equal(JSON.parse(write.options.body).revision,1,'new server revision must not authorize old form');
 assert.equal(JSON.parse(write.options.body).refresh_interval_minutes,90);
 f.respond(f.requests.length-1,409,{error:'Источник изменился'});await flush();
 assert.equal(f.e('sourcesList').innerHTML,html);
});

await test('older source reload cannot replace a newer response or later edits',async()=>{
 const f=fixture();f.respond(0,200,snapshot());await flush();
 f.event('razvilka:view-change','subscription-settings');
 f.event('razvilka:view-change','subscription-settings');
 let reads=f.requests.map((r,i)=>({r,i})).filter(x=>x.r.path==='/api/v1/node-feeds');
 f.respond(reads.at(-1).i,200,{sources:[{source_id:'newer',saved:true,revision:2}]});await flush();
 const html=f.e('sourcesList').innerHTML;
 f.respond(reads.at(-2).i,200,{sources:[{source_id:'older',saved:true,revision:1}]});await flush();
 assert.equal(f.e('sourcesList').innerHTML,html);
 f.click('reloadSources');await flush();
 f.e('sourcesList').events.get('input')({});
 f.respond(f.requests.length-1,200,{sources:[{source_id:'after-edit',saved:true,revision:3}]});await flush();
 assert.equal(f.e('sourcesList').innerHTML,html);
});

await test('one-off preset opens existing save form without fetching or writing',async()=>{
 const f=fixture();f.respond(0,200,snapshot());await flush();
 f.event('razvilka:view-change','subscription-settings');
 const index=f.requests.findIndex(r=>r.path==='/api/v1/node-feeds');
 f.respond(index,200,{presets:[{id:'example'}],sources:[{source_id:'feed-example',saved:false}]});await flush();
 let changed=0;f.coreElement('nodeFeedPreset').dispatchEvent=()=>changed++;
 f.coreElement('nodeSubscriptions').scrollIntoView=()=>{};
 const before=f.requests.length;
 f.clickTarget({closest:selector=>selector==='[data-feed-add]'?{dataset:{feedAdd:'feed-example'}}:selector==='[data-autonomy]'?{}:null});
 assert.equal(f.coreElement('nodeFeedPreset').value,'example');assert.equal(changed,1);
 assert.equal(f.coreElement('nodeSubscriptions').hidden,false);assert.equal(f.requests.length,before);
});

await test('custom one-off keeps source context without reconstructing secret URL',async()=>{
 const f=fixture();f.respond(0,200,snapshot());await flush();
 f.event('razvilka:view-change','subscription-settings');
 const index=f.requests.findIndex(r=>r.path==='/api/v1/node-feeds');
 f.respond(index,200,{presets:[],sources:[{source_id:'custom-source',name:'My source',saved:false,url:'https://redacted.example/'}]});await flush();
 f.e('subscriptionForm').scrollIntoView=()=>{};
 const before=f.requests.length;
 f.clickTarget({closest:selector=>selector==='[data-feed-add]'?{dataset:{feedAdd:'custom-source'}}:selector==='[data-autonomy]'?{}:null});
 assert.equal(f.e('subscriptionName').value,'My source');assert.equal(f.e('subscriptionURL').value,'');
 assert.equal(f.requests.length,before);assert.match(f.e('notice').textContent,/полный HTTPS/);
});

await test('editing while source save is pending preserves dirty form after success',async()=>{
 const f=fixture();f.respond(0,200,snapshot());await flush();
 f.event('razvilka:view-change','subscription-settings');
 const i=f.requests.findIndex(r=>r.path==='/api/v1/node-feeds');
 f.respond(i,200,{sources:[{source_id:'feed-example',saved:true,revision:1}]});await flush();
 const html=f.e('sourcesList').innerHTML;
 const form={dataset:{feedForm:'feed-example'},elements:{enabled:{value:'true'},interval:{value:'90'}}};
 f.e('sourcesList').events.get('input')({});
 f.e('sourcesList').events.get('submit')({preventDefault(){},target:{closest:()=>form}});
 const count=f.requests.length;
 form.elements.interval.value='120';f.e('sourcesList').events.get('input')({});
 f.respond(count-1,200,{ok:true});await flush();
 assert.equal(form.elements.interval.value,'120');assert.equal(f.e('sourcesList').innerHTML,html);
 assert.equal(f.requests.length,count,'success must not clear newer dirty edits and reload');
});

await test('wizard explicit discard does not discard edits made during its read',async()=>{
 const f=fixture();f.respond(0,200,snapshot());await flush();
 f.event('razvilka:view-change','onboard');f.respond(1,200,snapshot());await flush();
 f.e('checkInterval').value='600';f.e('wizardForm').events.get('input')({});
 f.click('reloadButton');await flush();const i=f.requests.length-1;
 f.e('checkInterval').value='777';f.e('wizardForm').events.get('input')({});
 f.respond(i,200,snapshot(2));await flush();
 assert.equal(f.e('checkInterval').value,'777');assert.equal(f.e('revisionLabel').textContent,'Редакция 1');
});

await test('wizard discard waits for pending poll without consuming newer edits',async()=>{
 const f=fixture();f.respond(0,200,snapshot());await flush();
 f.event('razvilka:view-change','onboard');
 f.click('reloadButton');f.e('checkInterval').value='777';f.e('wizardForm').events.get('input')({});
 f.respond(1,200,snapshot());await flush();
 f.respond(2,200,snapshot(2));await flush();
 assert.equal(f.e('checkInterval').value,'777');assert.equal(f.e('revisionLabel').textContent,'Редакция 1');
});

await test('wizard ordinary confirmed discard loads the new revision',async()=>{
 const f=fixture();f.respond(0,200,snapshot());await flush();
 f.event('razvilka:view-change','onboard');f.respond(1,200,snapshot());await flush();
 f.e('checkInterval').value='777';f.e('wizardForm').events.get('input')({});
 f.click('reloadButton');await flush();f.respond(f.requests.length-1,200,snapshot(2));await flush();
 assert.equal(f.e('checkInterval').value,300);assert.equal(f.e('revisionLabel').textContent,'Редакция 2');
});

await test('wizard save readback preserves edits made while PUT was pending',async()=>{
 const f=fixture(true,[{name:'protocol',value:'vless',checked:true}]),initial=snapshot();
 initial.policy.failure_confirm_seconds=60;initial.policy.max_switches_per_hour=6;
 f.respond(0,200,initial);await flush();f.event('razvilka:view-change','onboard');f.respond(1,200,initial);await flush();
 f.e('checkInterval').value='180';f.e('wizardForm').events.get('input')({});
 f.click('nextStep');f.click('nextStep');f.click('nextStep');
 f.e('confirmConsent').checked=true;
 const saving=f.e('wizardForm').events.get('submit')({preventDefault(){}});await flush();
 const i=f.requests.length-1;assert.equal(f.requests[i].options.method,'PUT',f.e('wizardError').textContent);
 f.e('checkInterval').value='240';f.e('wizardForm').events.get('input')({});
 f.respond(i,200,{ok:true});await flush();
 const next=snapshot(2);next.policy.check_seconds=180;f.respond(i+1,200,next);await saving;
 assert.equal(f.e('checkInterval').value,'240');assert.equal(f.e('revisionLabel').textContent,'Редакция 1');
 assert.equal(f.contextView(),'onboard');assert.match(f.e('notice').textContent,/Новые изменения ещё не сохранены/);
});

await test('wizard ordinary successful save returns to overview with saved revision',async()=>{
 const f=fixture(true,[{name:'protocol',value:'vless',checked:true}]),initial=snapshot();
 initial.policy.failure_confirm_seconds=60;initial.policy.max_switches_per_hour=6;
 f.respond(0,200,initial);await flush();f.event('razvilka:view-change','onboard');f.respond(1,200,initial);await flush();
 f.e('checkInterval').value='180';f.e('wizardForm').events.get('input')({});
 f.click('nextStep');f.click('nextStep');f.click('nextStep');f.e('confirmConsent').checked=true;
 const saving=f.e('wizardForm').events.get('submit')({preventDefault(){}});await flush();
 const i=f.requests.length-1;assert.equal(f.requests[i].options.method,'PUT');
 f.respond(i,200,{ok:true});await flush();
 const next=snapshot(2);next.policy.check_seconds=180;f.respond(i+1,200,next);await saving;
 assert.equal(f.contextView(),'autopilot');assert.equal(f.e('revisionLabel').textContent,'Редакция 2');
 assert.match(f.e('notice').textContent,/Настройки сохранены на роутере/);
 assert.doesNotMatch(f.e('notice').textContent,/Новые изменения/);
});

for(const button of ['reloadButton','reloadSources']){
 await test(button+' asynchronous cancel preserves dirty fields and sends no read',async()=>{
  const f=fixture();f.respond(0,200,snapshot());await flush();
  f.e('checkInterval').value='777';
  (button==='reloadButton'?f.e('wizardForm'):f.e('sourcesList')).events.get('input')({});
  const pending=deferred();f.confirmWith(()=>pending.promise);const before=f.requests.length;
  f.click(button);assert.equal(f.requests.length,before);pending.resolve(false);await flush();
  assert.equal(f.requests.length,before);assert.equal(f.e('checkInterval').value,'777');
 });
 for(const change of ['logout','view','new-edit'])await test(button+' rejects late consent after '+change,async()=>{
  const f=fixture();f.respond(0,200,snapshot());await flush();
  const edited=button==='reloadButton'?f.e('wizardForm'):f.e('sourcesList');edited.events.get('input')({});
  const pending=deferred();f.confirmWith(()=>pending.promise);f.click(button);
  if(change==='logout')f.event('razvilka:auth-required');
  else if(change==='view')f.event('razvilka:view-change','managed');
  else {f.e('checkInterval').value='777';edited.events.get('input')({});}
  const before=f.requests.length;pending.resolve(true);await flush();
  assert.equal(f.requests.length,before,'late consent started a read');
  if(change==='new-edit')assert.equal(f.e('checkInterval').value,'777');
 });
}
for(const outcome of ['cancel','logout','view','revision','accept'])await test('remove service async consent '+outcome,async()=>{
 const f=fixture(),initial=snapshot();initial.catalog_services=[{id:'telegram',name:'Telegram',custom:true}];
 f.respond(0,200,initial);await flush();const pending=deferred();f.confirmWith(()=>pending.promise);
 f.clickTarget({closest:selector=>selector==='[data-autonomy]'?{}:selector==='[data-remove]'?{dataset:{remove:'telegram'}}:null});
 const before=f.requests.length;
 if(outcome==='logout')f.event('razvilka:auth-required');
 if(outcome==='view')f.event('razvilka:view-change','managed');
 if(outcome==='revision'){
  f.event('razvilka:panel-refresh');const next=snapshot(2);next.catalog_services=initial.catalog_services;
  f.respond(f.requests.length-1,200,next);await flush();
 }
 pending.resolve(outcome!=='cancel');await flush();
 const writes=f.requests.filter(r=>r.options.method==='DELETE');
 assert.equal(writes.length,outcome==='accept'?1:0);
 if(outcome==='accept'){
  const body=JSON.parse(writes[0].options.body);assert.equal(body.expected_revision,1);assert.equal(body.delete_definition,true);
 }
 if(outcome==='cancel')assert.equal(f.requests.length,before);
});

console.log(JSON.stringify({status:'passed',tests:passed}));
