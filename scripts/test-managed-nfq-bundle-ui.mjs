// Production caller checks only: no server, HTTP, bundle install or native execution.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const read=name=>readFileSync(new URL('../'+name,import.meta.url),'utf8');
const source=read('cmd/razvilka/web/managed-nfq-bundle-ui.js'),base='/api/v1/components/nfqws2/managed-bundle';
const bundle={provider_id:'reviewed-provider',flavor:'reviewed-flavor',architecture:'arm64',manifest_sha256:'a'.repeat(64)};
const plan=(extra={})=>({revision:7,ready:true,code:'READY',reason:'Пакет подготовлен для установки.',bundle:{...bundle},installed_idle:false,compatibility_ready:false,working_routes_changed:false,...extra});
const observation=(extra={})=>({installed_idle:true,provider_id:bundle.provider_id,flavor:bundle.flavor,manifest_sha256:bundle.manifest_sha256,receipt_id:'b'.repeat(32),working_routes_changed:false,...extra});
const receipt=(extra={})=>({schema:1,provider_id:bundle.provider_id,flavor:bundle.flavor,manifest_sha256:bundle.manifest_sha256,transaction_id:'b'.repeat(32),generation_path:'/private/generation',state:'ready-idle',...extra});
const success=(extra={})=>({ok:true,receipt:receipt(),installed_idle:true,compatibility_ready:true,working_routes_changed:false,...extra});
const unavailable=()=>Object.assign(new Error('source unavailable'),{status:503,payload:{code:'MANAGED_NFQWS_SOURCE_UNAVAILABLE',installed_idle:false}});
const flush=()=>new Promise(resolve=>setImmediate(resolve));
const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};};
const pure={};vm.createContext(pure);vm.runInContext(source,pure);const model=pure.RazvilkaManagedNFQBundle;
const recoveryPure={};vm.createContext(recoveryPure);vm.runInContext(read('cmd/razvilka/web/component-recovery-ui.js'),recoveryPure);
const terminalJournal=(phase='rolled-back')=>({revision:7,recovery_required:false,transaction:{schema_version:3,transaction_id:'b'.repeat(32),component:'nfqws2',phase,before_version:'absent',after_version:bundle.flavor,updated_at:new Date().toISOString()},capabilities:{supported_actions:['resume','rollback'],available_actions:[],quiescence_confirmed:false,inactivity_confirmed:false,installed_idle_accepted:phase==='accepted-installed-idle',live_proof_required:false}});
function fixture(view='engines'){
  const requests=[],listeners=new Map(),notices=[],timers=new Set(),inventory=[];
  const state={authenticated:true,currentView:view,status:{revision:7,safe_mode:true},serviceControl:{stopped:true},components:[{id:'nfqws2',installed:true,running:false}]};
  let now=Date.now(),fenced=false,authCalls=0;class Clock extends Date{static now(){return now;}}
  const context={state,Date:Clock,AbortController,Promise,RazvilkaComponentRecovery:recoveryPure.RazvilkaComponentRecovery,
    esc:value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])),
    document:{hidden:false,addEventListener(name,handler){listeners.set(name,handler);}},
    api(path,options={}){const request=deferred();requests.push({path,options,...request});return request.promise;},
    componentRecoveryFence:()=>fenced,componentUpdatePending(){fenced=true;},renderComponents(){},renderInterfaceEngines(){},
    refreshComponents:async refresh=>{inventory.push(refresh);return true;},showNotice:(...args)=>notices.push(args),
    showAuth(){authCalls++;state.authenticated=false;listeners.get('razvilka:auth-required')();},
    setTimeout(fn,milliseconds){const timer={fn,milliseconds};timers.add(timer);return timer;},clearTimeout(timer){timers.delete(timer);}
  };
  vm.createContext(context);vm.runInContext(source,context);
  const click=selector=>listeners.get('click')({target:{closest:value=>value===selector?{disabled:false}:null}});
  const f={context,state,requests,notices,inventory,timers,authCalls:()=>authCalls,card:()=>context.managedNFQBundleCard('nfqws2'),
    clickRead:()=>click('[data-managed-nfq-read]'),clickInstall:()=>click('[data-managed-nfq-install]'),
    advance:milliseconds=>{now+=milliseconds;},fence:value=>{fenced=value;},
    revoke(){state.authenticated=false;listeners.get('razvilka:auth-required')();},
    view(name){state.currentView=name;listeners.get('razvilka:view-change')({detail:name});},
    async resolveRead(index=0,p=plan(),installed=null,revision=p.revision){
      assert.deepEqual(requests.slice(index,index+3).map(request=>request.path),[base+'/plan',base+'/installed','/api/v1/status']);
      requests[index].resolve(p);if(installed)requests[index+1].resolve(installed);else requests[index+1].reject(unavailable());
      requests[index+2].resolve({revision});await flush();
    },async ready(p=plan(),installed=null,revision=p.revision){this.clickRead();await flush();await this.resolveRead(0,p,installed,revision);}
  };return f;
}
let total=0;async function test(name,fn){await fn();total++;console.log('PASS '+name);}
await test('plan and installed readers reject partial, future and changed identity facts',()=>{
  assert(model.validPlan(plan()));assert(model.matches(plan(),observation()));
  for(const value of [{},plan({revision:-1}),plan({working_routes_changed:true}),plan({ready:'yes'}),plan({bundle:{...bundle,manifest_sha256:'bad'}})])assert.equal(model.validPlan(value),false);
  for(const value of [{},observation({installed_idle:false}),observation({working_routes_changed:true}),observation({receipt_id:''})])assert.equal(model.validInstalled(value),false);
  assert.equal(model.matches(plan(),observation({manifest_sha256:'c'.repeat(64)})),false);
});
await test('receipt matching uses schema, exact transaction, provider, flavor and hash',()=>{
  assert(model.receiptMatches(receipt(),observation()));
  for(const value of [receipt({schema:2}),receipt({state:'live'}),receipt({transaction_id:'c'.repeat(32)}),receipt({provider_id:'other'}),receipt({flavor:'other'}),receipt({manifest_sha256:'c'.repeat(64)})])assert.equal(model.receiptMatches(value,observation()),false);
});
await test('stock component detection and rendering do not create managed proof or HTTP writes',()=>{
  const f=fixture();assert.equal(f.requests.length,0);assert.match(f.card(),/Прочитайте план/);assert.match(f.card(),/data-managed-nfq-install[^>]*disabled/);assert.equal(f.context.managedNFQBundleCard('xray'),'');
  f.view('overview');f.view('engines');assert.equal(f.requests.length,0);f.clickInstall();assert.equal(f.requests.length,0);
});
await test('plan/readback navigation is three independent GETs, with no source-init POST',async()=>{
  const f=fixture();f.clickRead();f.clickRead();await flush();assert.equal(f.requests.length,3);assert(f.requests.every(request=>!request.options.method && request.options.cache==='no-store'));await f.resolveRead();
  assert.doesNotMatch(f.card(),/data-managed-nfq-install[^>]*disabled/);assert.equal(f.notices.length,0);
});
await test('a blocked plan remains readable without offering installation',async()=>{
  const f=fixture();await f.ready(plan({ready:false,code:'NOT_READY',reason:'Сначала завершите восстановление.'}));f.clickInstall();assert.equal(f.requests.length,3);assert.match(f.card(),/Сначала завершите восстановление/);
});
await test('an unavailable real lease never becomes installed from plan booleans',async()=>{
  const f=fixture();await f.ready(plan({installed_idle:true,compatibility_ready:true}));assert.doesNotMatch(f.card(),/Управляемый пакет установлен и сейчас/);assert.equal(f.notices.length,0);
});
await test('verified installed readback disables new installation and does not claim service compatibility',async()=>{
  const f=fixture();await f.ready(plan({installed_idle:true,compatibility_ready:true}),observation());assert.match(f.card(),/Управляемый пакет установлен/);assert.match(f.card(),/Совместимость и соединение проверяются отдельно/);assert.match(f.card(),/data-managed-nfq-install[^>]*disabled/);f.clickInstall();assert.equal(f.requests.length,3);
});
await test('one explicit idle install posts only observed CAS, including revision zero and Safe Mode/Stop',async()=>{
  const f=fixture();f.state.status.revision=0;await f.ready(plan({revision:0,paths:['ignored'],trusted:true}),null,0);f.clickInstall();f.clickInstall();await flush();
  assert.equal(f.requests.length,4);const request=f.requests[3];assert.equal(request.path,base+'/install');assert.equal(request.options.method,'POST');assert.deepEqual(JSON.parse(request.options.body),{expected_revision:0});assert(f.state.componentOperation);assert.equal(f.notices.length,0);
  request.resolve(success());await flush();assert.equal(f.requests.length,7);assert.equal(f.notices.length,0,'POST alone claimed installation');
  await f.resolveRead(4,plan({revision:0,installed_idle:true,compatibility_ready:true}),observation(),0);
  assert.equal(f.notices.length,1);assert.equal(f.notices[0][0],'review');assert.deepEqual(f.inventory,[false]);assert.equal(f.state.componentOperation,null);assert.equal(f.timers.size,0);
});
await test('a different independently read receipt fences an optimistic successful POST',async()=>{
  const f=fixture();await f.ready();f.clickInstall();await flush();f.requests[3].resolve(success());await flush();await f.resolveRead(4,plan(),observation({receipt_id:'c'.repeat(32)}));
  assert.equal(f.notices.length,0);assert.match(f.card(),/Исход установки/);f.clickInstall();assert.equal(f.requests.length,7);
});
await test('changed bundle identity or missing POST receipt never claims completed installation',async()=>{
  for(const response of [success({receipt:null}),success({receipt:receipt({manifest_sha256:'c'.repeat(64)})})]){
    const f=fixture();await f.ready();f.clickInstall();await flush();f.requests[3].resolve(response);await flush();
    if(f.requests.length===7)await f.resolveRead(4,plan(),observation());
    assert.equal(f.notices.length,0);assert.match(f.card(),/Исход установки/);f.clickInstall();assert.equal(f.requests.filter(request=>request.options.method==='POST').length,1);
  }
});
await test('failed independent readback cannot turn successful native receipt into a success notice',async()=>{
  const f=fixture();await f.ready();f.clickInstall();await flush();f.requests[3].resolve(success());await flush();f.requests[4].reject(new Error('read failed'));f.requests[5].reject(unavailable());f.requests[6].resolve({revision:7});await flush();
  assert.equal(f.notices.length,0);assert.match(f.card(),/Исход установки/);assert.equal(f.state.componentOperation,null);
});
await test('clean refused 409 requires fresh plan and never repeats POST automatically',async()=>{
  const f=fixture();await f.ready();f.clickInstall();await flush();f.requests[3].reject(Object.assign(new Error('refused'),{status:409,payload:{code:'MANAGED_NFQWS_INSTALL_REFUSED'}}));await flush();
  assert.match(f.card(),/Установка отклонена/);f.clickInstall();assert.equal(f.requests.length,4);f.clickRead();await flush();await f.resolveRead(4);assert.equal(f.requests.filter(request=>request.options.method==='POST').length,1);
});
await test('recovery-required 503 directs to the existing journal without install replay',async()=>{
  const f=fixture();await f.ready();f.clickInstall();await flush();f.requests[3].reject(Object.assign(new Error('pending'),{status:503,payload:{code:'MANAGED_NFQWS_RECOVERY_REQUIRED',recovery_required:true}}));await flush();
  assert.match(f.card(),/Исход установки/);f.clickInstall();assert.equal(f.requests.length,4);assert.equal(f.state.componentOperation,null);assert.equal(f.notices.length,0);
});
await test('network, timeout and generic conflicts keep an unknown write fenced after an absent read',async()=>{
  for(const error of [new Error('network'),Object.assign(new Error('timeout'),{name:'AbortError'}),Object.assign(new Error('conflict'),{status:409})]){
    const f=fixture();await f.ready();f.clickInstall();await flush();f.requests[3].reject(error);await flush();f.clickRead();await flush();await f.resolveRead(4);f.clickInstall();
    assert.equal(f.requests.filter(request=>request.options.method==='POST').length,1);assert.match(f.card(),/Исход установки/);
  }
});
await test('confirmed schema 3 rollback plus new read settles the local fence without repeating installation',async()=>{
  const f=fixture();await f.ready();f.clickInstall();await flush();f.requests[3].reject(new Error('unknown'));await flush();
  const pending=f.context.refreshManagedNFQBundle(terminalJournal());await flush();await f.resolveRead(4);await pending;
  assert.doesNotMatch(f.card(),/Исход установки/);assert.equal(f.requests.filter(request=>request.options.method==='POST').length,1);
  f.clickInstall();await flush();assert.equal(f.requests.filter(request=>request.options.method==='POST').length,2,'the new explicit click should remain available after confirmed rollback');f.requests[7].reject(new Error('end fixture'));await flush();
});
await test('invalid, mismatched revision or idle-without-source journal cannot clear an unknown install',async()=>{
  for(const journal of [{},terminalJournal('accepted-installed-idle'),{...terminalJournal(),revision:8}]){
    const f=fixture();await f.ready();f.clickInstall();await flush();f.requests[3].reject(new Error('unknown'));await flush();const pending=f.context.refreshManagedNFQBundle(journal);await flush();await f.resolveRead(4);await pending;f.clickInstall();assert.equal(f.requests.filter(request=>request.options.method==='POST').length,1);assert.match(f.card(),/Исход установки/);
  }
});
await test('stale or changed revisions fence installation and do not auto-refresh or post',async()=>{
  const f=fixture();await f.ready();f.advance(60001);f.clickInstall();assert.equal(f.requests.length,3);
  const changed=fixture();await changed.ready();changed.state.status.revision=8;changed.clickInstall();assert.equal(changed.requests.length,3);assert.match(changed.card(),/Настройки изменились/);
  const mismatched=fixture();await mismatched.ready(plan(),null,8);mismatched.clickInstall();assert.equal(mismatched.requests.length,3);
});
await test('stock component activity and recovery block POST while managed reads stay available',async()=>{
  for(const flag of ['operation','refresh','recovery']){
    const f=fixture();await f.ready();if(flag==='operation')f.state.componentOperation={id:'xray'};else if(flag==='refresh')f.state.componentRefreshRequest={};else f.fence(true);
    f.clickInstall();assert.equal(f.requests.length,3);
    if(flag==='recovery'){f.clickRead();await flush();assert.equal(f.requests.length,6);await f.resolveRead(3);}
  }
});
await test('late GET and POST cannot revive proof or show a notice after logout',async()=>{
  const readOnly=fixture();readOnly.clickRead();await flush();readOnly.revoke();await readOnly.resolveRead();assert.match(readOnly.card(),/Прочитайте план/);assert.equal(readOnly.notices.length,0);
  const writing=fixture();await writing.ready();writing.clickInstall();await flush();writing.revoke();writing.requests[3].resolve(success());await flush();assert.equal(writing.requests.length,4);assert.equal(writing.notices.length,0);assert.equal(writing.state.componentOperation,null);
});
await test('leaving a sent install releases UI busy state and requires independent read on return',async()=>{
  const f=fixture();await f.ready();f.clickInstall();await flush();f.view('overview');f.view('engines');f.requests[3].resolve(success());await flush();
  assert.equal(f.state.componentOperation,null);assert.equal(f.notices.length,0);f.clickInstall();assert.equal(f.requests.length,4);f.clickRead();await flush();await f.resolveRead(4,plan({installed_idle:true}),observation());assert.equal(f.requests.filter(request=>request.options.method==='POST').length,1);
});
await test('hidden or obsolete reads release the read ticket and do not overwrite a newer session',async()=>{
  const f=fixture();f.clickRead();await flush();f.context.document.hidden=true;await f.resolveRead();f.context.document.hidden=false;f.clickRead();await flush();assert.equal(f.requests.length,6);await f.resolveRead(3);
});
await test('current 401 closes the session and sanitized reason cannot create markup',async()=>{
  const f=fixture();f.clickRead();await flush();f.requests[0].reject(Object.assign(new Error('login'),{status:401}));f.requests[1].reject(unavailable());f.requests[2].resolve({revision:7});await flush();assert.equal(f.authCalls(),1);
  const markup=fixture();await markup.ready(plan({reason:'<img src=x onerror=bad()>',bundle:{...bundle,flavor:'<script>bad</script>'}}));assert.doesNotMatch(markup.card(),/<img|<script>/);assert.match(markup.card(),/&lt;img/);assert.doesNotMatch(markup.card(),/\/private\/generation/);
});
await test('the managed caller is wired in both actual and inherited cards, without stock action substitution',()=>{
  assert.match(read('cmd/razvilka/web/interface.js'),/managedNFQBundleCard\(id\)/);assert.match(read('cmd/razvilka/web/app.js'),/managedNFQBundleCard\(c\.id\)/);
  assert.match(read('cmd/razvilka/web/index.html'),/src="\/managed-nfq-bundle-ui\.js\?v=/);
  assert.doesNotMatch(source,/data-component-action|askConfirmation|trusted\s*:|allow_unknown\s*:|\/apply|\/consent/);
});
console.log(JSON.stringify({suite:'managed-nfq-bundle-ui',mode:'production-caller-no-native',tests:total}));
