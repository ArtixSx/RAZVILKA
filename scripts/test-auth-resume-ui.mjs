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
const apiSource=source.slice(source.indexOf('async function api('),source.indexOf('\nfunction friendlyErrorMessage('));
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};}
function requestFixture(){
  const requests=[],timers=new Map();let authCalls=0,timerID=0;
  const context={AbortController,Headers,Set,state:{status:{},authenticated:true},interfaceState:{authEpoch:1},interfaceRequests:new Set(),
    ADMIN_TOKEN_KEY:'test',sessionStorage:{getItem:()=> 'fixture-token'},friendlyErrorMessage:value=>value,
    setTimeout(fn){const id=++timerID;timers.set(id,fn);return id;},clearTimeout:id=>timers.delete(id),
    fetch(path,options){const pending=deferred();requests.push({path,options,...pending});return pending.promise;},
    showAuth(){authCalls++;context.state.authenticated=false;context.interfaceState.authEpoch++;}
  };
  vm.createContext(context);vm.runInContext(apiSource+'\n'+requestSource,context);
  return {context,requests,timers,authCalls:()=>authCalls,
    request:options=>context.interfaceRequest('/api/v1/autonomy',options),
    newSession(){for(const controller of context.interfaceRequests)controller.abort();context.interfaceState.authEpoch++;context.state.authenticated=true;}
  };
}

for(const status of [401,200]){
  const f=requestFixture(),body=deferred(),pending=f.request();
  const result=pending.then(value=>({value}),error=>({error}));
  f.requests[0].resolve({ok:status===200,status,text:()=>body.promise,json:()=>body.promise});await flush();
  f.newSession();body.resolve(status===200?{policy:{revision:1}}:'{"error":"old session"}');
  const settled=await result;
  assert.equal(f.authCalls(),0,'late 401 revoked a new session');
  assert.equal(f.context.state.authenticated,true);
  assert.equal(settled.error?.name,'AuthGenerationChanged','old response escaped the request epoch');
  assert.equal(f.context.interfaceRequests.size,0);assert.equal(f.timers.size,0);
  console.log('PASS shared request rejects late parsed response '+status);
}

{
  const f=requestFixture(),pending=f.request(),result=pending.catch(error=>error);
  f.requests[0].resolve({ok:false,status:401,text:async()=>'{"error":"current session expired"}'});
  assert.equal((await result).status,401);assert.equal(f.authCalls(),1);assert.equal(f.context.state.authenticated,false);
  assert.equal(f.timers.size,0);console.log('PASS current 401 still revokes authentication');
}

{
  const f=requestFixture(),options={method:'PUT',body:'{"expected_revision":12}'},pending=f.request(options);
  const request=f.requests[0];assert.equal(request.options.credentials,'same-origin');assert.equal(request.options.headers.get('authorization'),'Bearer fixture-token');
  assert.equal(request.options.headers.get('content-type'),'application/json');assert.equal(request.options.body,options.body);
  request.resolve({ok:true,status:200,json:async()=>({saved:true})});assert.deepEqual(await pending,{saved:true});
  assert.equal(f.authCalls(),0);assert.equal(f.timers.size,0);console.log('PASS request preserves credentials and mutation body');
}
