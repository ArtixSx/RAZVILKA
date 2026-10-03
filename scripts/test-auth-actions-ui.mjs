import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const actions=source.slice(source.indexOf('async function submitSetup('),source.indexOf('\nfunction askConfirmation('));
const helpers=source.includes('function renderAuthBusy(')?source.slice(source.indexOf('function renderAuthBusy('),source.indexOf('\nfunction showAuth(')):'';
const show=source.slice(source.indexOf('function showAuth('),source.indexOf('\nasync function submitSetup('));
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};}
function fixture(){
  const elements=new Map(),requests=[],events=[],storage=new Map();let reads=0,plans=0,streams=0;
  const $=id=>{if(!elements.has(id))elements.set(id,{value:'',textContent:'',hidden:true,disabled:false,inert:false,classList:{remove(){}},contains:()=>false,focus(){},setAttribute(){},removeAttribute(){}});return elements.get(id);};
  const context={state:{authenticated:false,status:{}},$, $$:()=>[$('#loginSubmit'),$('#setupSubmit'),$('#recoverySubmit'),$('#useRecovery'),$('#logoutButton')],
    ADMIN_TOKEN_KEY:'test',sessionStorage:{getItem:key=>storage.get(key),setItem:(key,value)=>storage.set(key,value),removeItem:key=>storage.delete(key)},
    Event:class{constructor(type){this.type=type;}},document:{activeElement:null,dispatchEvent:event=>events.push(event.type)},
    api(path,options={}){const pending=deferred();requests.push({path,options,...pending});return pending.promise;},
    refreshAll:async()=>{reads++;return true;},showPlan:async()=>{plans++;},startConnectionStream:()=>{streams++;}
  };
  vm.createContext(context);vm.runInContext(helpers+'\n'+show+'\n'+actions,context);
  return {context,$,requests,events,storage,reads:()=>reads,plans:()=>plans,streams:()=>streams,
    submit:name=>context[name]({preventDefault(){}}),revoke:()=>context.showAuth({authenticated:false})};
}
let total=0;
async function test(name,fn){await fn();total++;console.log('PASS '+name);}

for(const name of ['submitLogin','submitSetup','recoverAccount'])await test(name+' combines repeated submits while pending',async()=>{
  const f=fixture();f.$('#setupPassword').value=f.$('#setupPasswordRepeat').value='private';
  f.$('#recoveryPassword').value=f.$('#recoveryPasswordRepeat').value='private';f.$('#recoveryToken').value='private-token';
  const first=f.submit(name),second=f.submit(name);
  assert.equal(f.requests.length,1,'repeated auth request');assert.equal(f.$('#loginSubmit').disabled,true);
  f.requests[0].resolve({});await Promise.all([first,second]);
  assert.equal(f.context.state.authenticated,true);assert.equal(f.$('#loginSubmit').disabled,false);
  assert.equal(f.reads(),1);assert.equal(f.plans(),1);assert.equal(f.streams(),1);
});

for(const name of ['submitLogin','submitSetup','recoverAccount'])for(const outcome of ['resolve','reject'])await test(name+' ignores late '+outcome+' after auth revocation',async()=>{
  const f=fixture();f.$('#setupPassword').value=f.$('#setupPasswordRepeat').value='private';
  f.$('#recoveryPassword').value=f.$('#recoveryPasswordRepeat').value='private';f.$('#recoveryToken').value='private-token';
  const pending=f.submit(name);f.revoke();f.$('#loginPassword').value='new draft';f.$('#authMessage').textContent='new session notice';
  f.requests[0][outcome](outcome==='resolve'?{}:new Error('old auth failure'));await pending;
  assert.equal(f.context.state.authenticated,false);assert.equal(f.$('#authMessage').textContent,'new session notice');
  assert.equal(f.$('#loginPassword').value,'new draft');assert.equal(f.reads(),0);assert.equal(f.$('#loginSubmit').disabled,false);
});

await test('revoked login cannot clear the new pending action',async()=>{
  const f=fixture(),old=f.submit('submitLogin');f.revoke();
  const next=f.submit('submitLogin');f.requests[0].reject(new Error('old failure'));await old;
  assert.equal(f.$('#loginSubmit').disabled,true);assert.equal(f.requests.length,2);
  f.requests[1].resolve({});await next;assert.equal(f.$('#loginSubmit').disabled,false);assert.equal(f.reads(),1);
});

await test('logout closes the panel before HTTP and survives failed status read',async()=>{
  const f=fixture();f.context.state.authenticated=true;f.$('#authScreen').hidden=true;f.storage.set('test','old-token');
  let closed=0;f.context.state.stream={close(){closed++;}};
  const pending=f.context.logout(),duplicate=f.context.logout();
  assert.equal(f.context.state.authenticated,false);assert.equal(f.$('.app-shell').inert,true);
  assert.equal(closed,1);assert.equal(f.storage.has('test'),false);
  assert.equal(f.requests.length,1);assert.equal(f.requests[0].path,'/api/v1/auth/logout');
  f.requests[0].resolve({});await flush();assert.equal(f.requests[1].path,'/api/v1/auth/status');
  f.requests[1].reject(new Error('status transport failed'));await Promise.all([pending,duplicate]);
  assert.equal(f.context.state.authenticated,false);assert.equal(f.$('.app-shell').inert,true);assert.equal(f.$('#authScreen').hidden,false);
  assert.equal(f.$('#loginSubmit').disabled,false);assert.equal(f.reads(),0);
});

await test('current login error uses the actual HTTP error',async()=>{
  const f=fixture(),pending=f.submit('submitLogin');
  f.requests[0].reject(new Error('Сервер временно недоступен.'));await pending;
  assert.equal(f.$('#authMessage').textContent,'Сервер временно недоступен.');assert.equal(f.$('#loginSubmit').disabled,false);
});

await test('current invalid credentials retain the clear login message',async()=>{
  const f=fixture(),pending=f.submit('submitLogin');
  f.requests[0].reject(Object.assign(new Error('Нужно снова войти в RAZVILKA.'),{status:401}));await pending;
  assert.equal(f.$('#authMessage').textContent,'Неверный логин или пароль.');
});

await test('login stops before plan and SSE when post-login reads are revoked',async()=>{
  const f=fixture(),readback=deferred();f.context.refreshAll=()=>readback.promise;
  const pending=f.submit('submitLogin');f.requests[0].resolve({});await flush();
  assert.equal(f.context.state.authenticated,true);f.revoke();readback.resolve(true);await pending;
  assert.equal(f.context.state.authenticated,false);assert.equal(f.plans(),0);assert.equal(f.streams(),0);
});

await test('unknown logout offers explicit retry and late status error cannot affect next session',async()=>{
  const f=fixture();f.context.state.authenticated=true;const first=f.context.logout();
  f.requests[0].reject(new Error('logout response lost'));await flush();
  f.requests[1].reject(new Error('status response lost'));await first;
  assert.equal(f.$('#authLogoutRetry').hidden,false);assert.equal(f.$('#authLogoutRetry').disabled,false);
  const retry=f.context.logout();f.requests[2].reject(new Error('old logout failure'));await flush();
  f.revoke();f.$('#authMessage').textContent='new session';
  f.requests[3].reject(new Error('old status failure'));await retry;
  assert.equal(f.$('#authLogoutRetry').hidden,true);assert.equal(f.$('#authMessage').textContent,'new session');
});
console.log(JSON.stringify({suite:'auth-actions',tests:total}));
