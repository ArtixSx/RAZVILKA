import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source=fs.readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const functions=source.slice(source.indexOf('function showAuth('),source.indexOf('async function submitSetup('));
const elements=new Map(), published=[];
const documentState={activeElement:null,dispatchEvent:e=>published.push(e.type)};
const $=id=>{
  if(!elements.has(id)){
    const panel=/^#setup/.test(id)?'setup':/^#(login|recovery)/.test(id)?'login':null;
    elements.set(id,{id,panel,shell:['#logoutButton','#serviceSearch'].includes(id),hidden:true,inert:false,textContent:'',attributes:new Map(),classList:{remove(){}},
      contains(target){return this===target || id==='.app-shell'&&target?.shell || id==='#authScreen'&&!!target?.panel || id==='#authSetupPanel'&&target?.panel==='setup' || id==='#authLoginPanel'&&target?.panel==='login';},
      focus(){assert(!this.shell||!$('.app-shell').inert,'focused the inert application');documentState.activeElement=this;},
      blur(){if(documentState.activeElement===this)documentState.activeElement=null;},
      setAttribute(name,value){if(name==='aria-hidden'&&value==='true')assert(!this.contains(documentState.activeElement),'aria-hidden applied while background retains focus');this.attributes.set(name,value);},
      removeAttribute(name){this.attributes.delete(name);}
    });
  }
  return elements.get(id);
};
const state={authenticated:false,status:{}};
const ctx=vm.createContext({state,$,document:documentState,Event:class{constructor(type){this.type=type;}},sessionStorage:{getItem:()=>''},ADMIN_TOKEN_KEY:'test'});
vm.runInContext(functions,ctx);
$('#serviceSearch').focus();
ctx.hideAuth();
assert.deepEqual(published,['razvilka:auth-restored'],'saved cookie did not activate polling on initial hidden login screen');
assert.equal(documentState.activeElement,$('#serviceSearch'),'cookie bootstrap stole focus');assert.equal($('.app-shell').inert,false);
ctx.hideAuth();
assert.equal(published.length,1,'periodic status read restarted authentication generation');
$('#logoutButton').focus();
ctx.showAuth({setup_required:false});
assert.equal(state.authenticated,false);
assert.equal($('.app-shell').inert,true);assert.equal($('.app-shell').attributes.get('aria-hidden'),'true');
assert($('#authLoginPanel').contains(documentState.activeElement),'focus did not move to the login form');
ctx.hideAuth();
assert.equal($('.app-shell').inert,false);assert.equal($('.app-shell').attributes.has('aria-hidden'),false);
assert(!$('#authScreen').contains(documentState.activeElement),'hidden authentication form retained focus');
assert.deepEqual(published,['razvilka:auth-restored','razvilka:auth-required','razvilka:auth-restored']);
console.log('Initial cookie session, repeated refresh and re-login lifecycle: PASS');

ctx.showAuth({setup_required:true});assert($('#authSetupPanel').contains(documentState.activeElement));
ctx.showAuth({setup_required:false});assert($('#authLoginPanel').contains(documentState.activeElement),'focus stayed in the hidden setup panel');
$('#recoveryToken').focus();ctx.showAuth({setup_required:false},'Recovery key не принят.');
assert.equal(documentState.activeElement,$('#recoveryToken'),'repeated auth notice interrupted recovery entry');
ctx.hideAuth();assert.equal($('.app-shell').inert,false);assert(!$('#authScreen').contains(documentState.activeElement));
console.log('PASS focus and inert lifecycle for logout, setup and recovery');

// Run the shared request wrapper with the actual core API/parser so a response
// body can complete after logout/login, even if its transport was aborted.
const interfaceSource=fs.readFileSync(new URL('../cmd/razvilka/web/interface.js',import.meta.url),'utf8');
const requestSource=interfaceSource.match(/async function interfaceRequest\([^]*?\n}\n/)[0];
const workflowSource=fs.readFileSync(new URL('../cmd/razvilka/web/workflow-actions.js',import.meta.url),'utf8');
const workflowRequestSource=workflowSource.match(/async function workflowRequest\([^]*?\n}\n/)[0];
const apiSource=source.slice(source.indexOf('async function api('),source.indexOf('\nfunction friendlyErrorMessage('));
const panelReadsSource=source.slice(source.indexOf('const panelReads ='),source.indexOf('\nconst viewMeta ='));
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};}
function requestFixture(wrapper='interface'){
  const requests=[],timers=new Map(),savedInvalidations=[],versions={version:{textContent:'vCURRENT'},footerVersion:{textContent:'vCURRENT'}};let authCalls=0,timerID=0;
  const context={AbortController,Headers,Set,state:{status:{},authenticated:true,authGeneration:1},interfaceState:{authEpoch:1},interfaceRequests:new Set(),
    workflowState:{epoch:1,controllers:new Set()},workflowSession:epoch=>epoch===context.workflowState.epoch&&context.state.authenticated,
    ADMIN_TOKEN_KEY:'test',sessionStorage:{getItem:()=> 'fixture-token'},friendlyErrorMessage:value=>value,
    document:{getElementById:id=>versions[id]||null},
    invalidateSavedNodeBrowse:value=>savedInvalidations.push(['nodes',value]),
    invalidateSavedDeviceBrowse:value=>savedInvalidations.push(['devices',value]),
    invalidateSavedCommunityBrowse:value=>savedInvalidations.push(['community',value]),
    setTimeout(fn){const id=++timerID;timers.set(id,fn);return id;},clearTimeout:id=>timers.delete(id),
    fetch(path,options){const pending=deferred();requests.push({path,options,...pending});return pending.promise;},
    showAuth(){authCalls++;context.state.authenticated=false;context.state.authGeneration++;context.interfaceState.authEpoch++;context.workflowState.epoch++;context.invalidatePanelReads();}
  };
  vm.createContext(context);vm.runInContext(panelReadsSource+'\n'+apiSource+'\n'+requestSource+'\n'+workflowRequestSource,context);
  return {context,requests,timers,savedInvalidations,versions,authCalls:()=>authCalls,
    request:options=>context[wrapper==='workflow'?'workflowRequest':'interfaceRequest']('/api/v1/autonomy',options),
    newSession(){for(const controller of [...context.interfaceRequests,...context.workflowState.controllers])controller.abort();context.interfaceState.authEpoch++;context.workflowState.epoch++;context.state.authGeneration++;context.invalidatePanelReads();context.state.authenticated=true;}
  };
}

for(const wrapper of ['interface','workflow']){
for(const status of [401,200]){
  const f=requestFixture(wrapper),body=deferred(),pending=f.request();
  const result=pending.then(value=>({value}),error=>({error}));
  f.requests[0].resolve({ok:status===200,status,text:()=>body.promise,json:()=>body.promise});await flush();
  f.newSession();body.resolve(status===200?{policy:{revision:1}}:'{"error":"old session"}');
  const settled=await result;
  assert.equal(f.authCalls(),0,'late 401 revoked a new session');
  assert.equal(f.context.state.authenticated,true);
  assert.equal(settled.error?.name,'AuthGenerationChanged','old response escaped the request epoch');
  assert.equal(f.context.interfaceRequests.size,0);assert.equal(f.context.workflowState.controllers.size,0);assert.equal(f.timers.size,0);
  console.log('PASS '+wrapper+' request rejects late parsed response '+status);
}

for(const status of [401,200]){
  const f=requestFixture(wrapper),body=deferred(),pending=f.request({method:'PUT',body:'{"expected_revision":12}'});
  const oldResult=pending.catch(error=>error);
  f.requests[0].resolve({ok:status===200,status,text:()=>body.promise,json:()=>body.promise});await flush();
  f.newSession();
  const freshResult=f.context.readPanelResource('/api/v1/services').then(value=>({value}),error=>({error}));await flush();
  assert.equal(f.requests.length,2,'fresh session must start its own read');
  const fresh=f.requests[1],before=f.savedInvalidations.length;
  body.resolve(status===200?{saved:true}:JSON.stringify({name:'RAZVILKA',version:'0.0.0-old-session',error:'old session expired'}));
  assert.equal((await oldResult).name,'AuthGenerationChanged');
  assert.equal(fresh.options.signal.aborted,false,'old mutation completion canceled the new session read');
  assert.equal(f.savedInvalidations.length,before,'old mutation invalidated new-session browse state');
  assert.equal(f.versions.version.textContent,'vCURRENT');assert.equal(f.versions.footerVersion.textContent,'vCURRENT','old error body changed the new session version');
  assert.equal(f.authCalls(),0,'old mutation 401 revoked the new session');
  fresh.resolve({ok:true,status:200,json:async()=>[{id:'fresh-service'}]});
  const settled=await freshResult;
  assert.equal(settled.error,undefined,'new session read was fenced by an old completion');
  assert.equal(JSON.stringify(settled.value),'[{"id":"fresh-service"}]');
  assert.equal(f.context.interfaceRequests.size,0);assert.equal(f.context.workflowState.controllers.size,0);assert.equal(f.timers.size,0);
  console.log('PASS '+wrapper+' old mutation '+status+' preserves the new session read and presentation');
}

{
  const f=requestFixture(wrapper),pending=f.request(),result=pending.catch(error=>error);
  f.requests[0].resolve({ok:false,status:401,text:async()=>'{"name":"RAZVILKA","version":"0.20.0-current","error":"current session expired"}'});
  assert.equal((await result).status,401);assert.equal(f.authCalls(),1);assert.equal(f.context.state.authenticated,false);
  assert.equal(f.versions.version.textContent,'v0.20.0-current');assert.equal(f.versions.footerVersion.textContent,'v0.20.0-current');
  assert.equal(f.context.workflowState.controllers.size,0);assert.equal(f.timers.size,0);console.log('PASS '+wrapper+' current 401 still revokes authentication');
}

{
  const f=requestFixture(wrapper);
  const firstRead=f.context.readPanelResource('/api/v1/services').catch(error=>error);await flush();
  const first=f.requests[0],pending=f.request({method:'PUT',body:'{"expected_revision":12}'}),write=f.requests[1];
  assert.equal(first.options.signal.aborted,true,'current mutation must invalidate reads before writing');
  first.resolve({ok:true,status:200,json:async()=>[{id:'before-write'}]});assert.equal((await firstRead).name,'AbortError');
  const duringRead=f.context.readPanelResource('/api/v1/services').catch(error=>error);await flush();
  const during=f.requests[2];assert.equal(during.options.signal.aborted,false);
  write.resolve({ok:true,status:200,json:async()=>({saved:true})});assert.deepEqual(await pending,{saved:true});
  assert.equal(during.options.signal.aborted,true,'current mutation completion must invalidate concurrent reads');
  during.resolve({ok:true,status:200,json:async()=>[{id:'during-write'}]});assert.equal((await duringRead).name,'AbortError');
  assert.deepEqual(f.savedInvalidations,[['nodes',true],['devices',true],['community',true],['nodes',true],['devices',true],['community',true]]);
  assert.equal(f.timers.size,0);console.log('PASS '+wrapper+' current mutation still invalidates reads before and after writing');
}

{
  const f=requestFixture(wrapper),options={method:'PUT',body:'{"expected_revision":12}'},pending=f.request(options);
  const request=f.requests[0];assert.equal(request.options.credentials,'same-origin');assert.equal(request.options.headers.get('authorization'),'Bearer fixture-token');
  assert.equal(request.options.headers.get('content-type'),'application/json');assert.equal(request.options.body,options.body);
  request.resolve({ok:true,status:200,json:async()=>({saved:true})});assert.deepEqual(await pending,{saved:true});
  assert.equal(f.authCalls(),0);assert.equal(f.context.workflowState.controllers.size,0);assert.equal(f.timers.size,0);console.log('PASS '+wrapper+' request preserves credentials and mutation body');
}
}
