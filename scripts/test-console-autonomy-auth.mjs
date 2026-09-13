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
function fixture(){
 const elements=new Map(),documentListeners=new Map(),windowListeners=new Map(),requests=[],timeouts=new Map(),published=[];
 let timerID=0,authCalls=0;
 function element(id){
  if(!elements.has(id)){const classes=new Set();elements.set(id,{value:'',textContent:'',innerHTML:'',hidden:false,disabled:false,checked:false,options:[],dataset:{},open:false,events:new Map(),classList:{toggle(){},add:value=>classes.add(value),remove:value=>classes.delete(value),contains:value=>classes.has(value)},addEventListener(type,fn){this.events.set(type,fn);},setAttribute(){},removeAttribute(){},close(){this.open=false;},showModal(){this.open=true;},focus(){},reset(){}});}
  return elements.get(id);
 }
 function listen(map,type,fn){if(!map.has(type))map.set(type,[]);map.get(type).push(fn);}
 function dispatch(map,event){for(const listener of map.get(event.type)||[])listener(event);}
 const document={hidden:false,getElementById:element,querySelectorAll:()=>[],addEventListener:(type,fn)=>listen(documentListeners,type,fn),dispatchEvent:event=>dispatch(documentListeners,event)};
 const window={location:{hash:'#autopilot'},addEventListener:(type,fn)=>listen(windowListeners,type,fn),dispatchEvent:event=>{published.push(event);dispatch(windowListeners,event);}};
 const context={document,window,AbortController,URL,console,sessionStorage:{getItem:()=>''},state:{services:[],currentView:'autopilot'},Event:class{constructor(type){this.type=type;}},CustomEvent:class{constructor(type,options={}){this.type=type;this.detail=options.detail;}},setView(){},confirm:()=>true,$:selector=>element(selector.startsWith('#')?selector.slice(1):selector),ADMIN_TOKEN_KEY:'fixture-admin-token',
  setTimeout(fn,ms){const id=++timerID;timeouts.set(id,{fn,ms});return id;},clearTimeout:id=>timeouts.delete(id),setInterval:()=>++timerID,clearInterval(){},
  showAuth(){authCalls++;document.dispatchEvent({type:'razvilka:auth-required'});},
  fetch(path,options){const pending=deferred();requests.push({path,options,...pending});return pending.promise;}
 };
 vm.runInNewContext(source,context);
 vm.runInNewContext(hideAuthSource+'\n'+showAuthSource,context);
 return {requests,timeouts,published,e:id=>element('a1-'+id),authCalls:()=>authCalls,
  hideAuth:()=>context.hideAuth(),actualShowAuth:()=>context.actualShowAuth(null,'Войдите снова.'),coreElement:element,
  event:(type,detail)=>document.dispatchEvent({type,detail}),
  respond(index,status,data){requests[index].resolve({status,ok:status>=200&&status<300,json:async()=>data});},
  delayedBody(index,status){const body=deferred();requests[index].resolve({status,ok:status>=200&&status<300,json:()=>body.promise});return body;},
  click(id){element('a1-'+id).events.get('click')({preventDefault(){}});},
  runRetry(){const entry=[...timeouts.entries()].find(([,value])=>value.ms===1500);assert.ok(entry,'retry timer missing');timeouts.delete(entry[0]);entry[1].fn();}
 };
}
let passed=0;
async function test(name,fn){await fn();passed++;console.log('PASS',name);}

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
 const latestState=f.requests.findLastIndex(request=>request.path==='/api/v1/autonomy');
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
 const f=fixture();
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
 const f=fixture();f.hideAuth();f.respond(1,200,snapshot(2));await flush();f.click('pauseButton');
 f.coreElement('detailsPanel').classList.add('open');f.actualShowAuth();
 assert.equal(f.requests[2].options.signal.aborted,true);assert.equal(f.coreElement('authScreen').hidden,false);
 f.hideAuth();assert.equal(f.requests.length,4);assert.equal(f.coreElement('detailsPanel').classList.contains('open'),false);
 f.respond(3,200,snapshot(3));await flush();f.respond(2,401,{});await flush();
 assert.equal(f.coreElement('authScreen').hidden,true);assert.equal(f.e('notice').textContent,'');
 assert.equal(f.requests.filter(request=>request.options.method==='PUT').length,1);
});

console.log(JSON.stringify({status:'passed',tests:passed}));
