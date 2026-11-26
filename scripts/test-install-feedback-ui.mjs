import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import vm from 'node:vm';

const read = name => readFileSync(new URL('../cmd/razvilka/web/' + name, import.meta.url), 'utf8');
const progressPath = '/api/v1/components/install-progress';
const header = 'X-Razvilka-Install-ID';
const catalogPath = '/api/v1/components';
const freshPath = catalogPath + '?refresh=true';
const settled = () => new Promise(resolve => setImmediate(resolve));

function deferred() {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return {promise, resolve, reject};
}

class Element extends EventTarget {
  textContent = '';
  open = false;
  hidden = true;
  showModal() { this.open = true; }
  close() { this.open = false; }
  click() { this.dispatchEvent(new Event('click')); }
}

function fixture() {
  const elements = new Map();
  const byId = id => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const document = new EventTarget();
  document.getElementById = byId;
  const intervals = new Set(), calls = [], reviewed = [];
  const state = {authenticated:true, currentView:'onboard', components:[]};
  const ctx = vm.createContext({
    state, document, crypto:webcrypto, Uint8Array, AbortController,
    api(path, options = {}) {
      const pending = deferred();
      calls.push({path, options, resolve:pending.resolve,reject:pending.reject});
      return pending.promise;
    },
    setInterval(fn) { intervals.add(fn); return fn; },
    clearInterval(fn) { intervals.delete(fn); },
    componentRecoveryFence:() => false,
    wizardManagedNFQ:{status:() => ({installed:false, canInstall:false}), refresh:async () => { reviewed.push('managed'); }},
    refreshComponentRecovery:async () => { reviewed.push('recovery'); },
    CSS:{escape:x => x}, $$:() => [], workflowState:{epoch:0}, workflowSession:() => state.authenticated,
    renderComponents() {}, renderEngines() {}, renderEngineControl() {}, showNotice() {},
    setTimeout:() => 1, clearTimeout() {},
    refreshComponents:async () => false
  });
  vm.runInContext(read('install-log.js'), ctx);
  vm.runInContext(read('wizard-components.js'), ctx);
  // Run the real reviewed submission so the header and number of POSTs are checked end to end.
  const app = read('app.js');
  const start = app.indexOf('async function manageComponent(');
  const end = app.indexOf('\nfunction renderStatus()', start);
  assert(start >= 0 && end > start);
  vm.runInContext(app.slice(start,end), ctx);
  const requests = path => calls.filter(r => r.path === path);
  function navigate(view) {
    state.currentView = view;
    const event = new Event('razvilka:view-change');
    event.detail = view;
    document.dispatchEvent(event);
  }
  return {ctx, state, byId, calls, requests, intervals, reviewed, navigate,
    tick:() => { for (const fn of intervals) fn(); },
    logout() { state.authenticated=false; document.dispatchEvent(new Event('razvilka:auth-required')); },
    log:ctx.RazvilkaInstallLog, wizard:ctx.RazvilkaWizardComponents};
}

const ready = {id:'xray',name:'Xray',can_install:true,installed:false};
const installed = {...ready,installed:true};
const events = [
  {at:'2026-11-26T18:00:00Z',message:'Проверяем условия установки'},
  {at:'2026-11-26T18:00:01Z',message:'Загружаем файл компонента'},
  {at:'2026-11-26T18:00:02Z',message:'Проверяем результат установки'}
];
const html = read('index.html');
assert.match(html,/<dialog id="installLogDialog"[^]*?<form method="dialog">[^]*?<button type="submit"[^>]*>Скрыть журнал<\/button>/);

async function load(f, rows) {
  const result=f.wizard.refresh();
  f.requests(freshPath).at(-1).resolve(rows);
  assert.equal(await result,true);
}

{
  const f=fixture();
  assert.equal(await f.wizard.install('xray'),false);
  assert.equal(f.calls.length,0);
  await load(f,[ready,
    {id:'sing-box',installed:true,can_install:true},
    {id:'wireguard',installed:false,external_owner:true,can_install:true},
    {id:'warp-wg',can_install:true},
    {id:'amneziawg',installed:false,can_install:true,catalog_stale:true}]);
  for (const id of ['sing-box','wireguard','warp-wg','amneziawg','usque','unknown']) assert.equal(await f.wizard.install(id),false);
  f.ctx.componentRecoveryFence=()=>true;
  assert.equal(await f.wizard.install('xray'),false);
  f.ctx.componentRecoveryFence=()=>false;
  assert.deepEqual(f.calls.map(c=>c.path),[freshPath]);
  assert.deepEqual(f.reviewed,['managed','recovery']);

  const operation=f.wizard.install('xray');
  f.requests(catalogPath+'/xray/plan?action=install')[0].resolve({ready:true});
  await settled();
  const post=f.requests(catalogPath+'/xray/install')[0];
  assert.equal(post.options.method,'POST');
  const id=post.options.headers[header];
  assert.match(id,/^[0-9a-f]{32}$/);
  assert(f.byId('installLogDialog').open);
  f.byId('installLogDialog').close();
  post.resolve({ok:true});
  await settled();
  assert.doesNotMatch(f.byId('installLogStatus').textContent,/Установка подтверждена/);
  f.requests(catalogPath)[0].resolve([installed]);
  await settled();
  f.requests('/api/v1/engines')[0].resolve([]);
  f.requests('/api/v1/engine-configs')[0].resolve([]);
  await settled();
  // No timer tick before completion. A final read must still expose the server events.
  const final=f.requests(progressPath);
  assert.equal(final.length,1);
  assert.equal(final[0].options.headers[header],id);
  assert.equal(final[0].options.cache,'no-store');
  final[0].resolve({events});
  f.requests(catalogPath)[1].resolve([installed]);
  assert.equal(await operation,true);
  await settled();
  assert(!f.byId('installLogDialog').open);
  f.byId('installLogOpen').click();
  assert(f.byId('installLogDialog').open);
  for(const event of events) assert(f.byId('installLogLines').textContent.includes(event.message));
  assert.match(f.byId('installLogStatus').textContent,/Установка подтверждена/);
  assert.equal(f.wizard.list().find(r=>r.id==='xray').installed,true);
  const count=f.calls.length; f.tick();
  assert.equal(f.calls.length,count);
  assert.equal(f.calls.filter(c=>c.options.method==='POST').length,1);
}

{
  const f=fixture();
  const old=f.log.begin('Xray');old.sent();f.tick();
  const reading=f.requests(progressPath)[0];
  old.finish('Старое завершение');
  const next=f.log.begin('WireGuard');next.sent();
  assert.notEqual(old.headers[header],next.headers[header]);
  assert(reading.options.signal.aborted);
  reading.resolve({events:[{...events[0],message:'Старый журнал'}]});
  await settled();
  assert.equal(f.requests(progressPath).length,1,'old final read must not start in new operation');
  assert(!f.byId('installLogLines').textContent.includes('Старый журнал'));
  f.tick();
  const active=f.requests(progressPath)[1];
  assert.equal(active.options.headers[header],next.headers[header]);
  next.finish('Новый итог');
  active.resolve({events:events.slice(0,1)});
  await settled();
  const last=f.requests(progressPath)[2];
  assert.equal(last.options.headers[header],next.headers[header]);
  f.logout();last.resolve({events});await settled();
  assert(last.options.signal.aborted);
  assert.equal(f.byId('installLogLines').textContent,'');
  assert(!f.byId('installLogDialog').open && f.byId('installLogOpen').hidden);
  f.byId('installLogOpen').click();
  assert(!f.byId('installLogDialog').open);
  assert.equal(f.intervals.size,0);
  assert(f.calls.every(c=>!c.options.method || c.options.method==='GET'));
}

{
  const f=fixture();
  const initial=f.wizard.refresh();
  const duplicate=f.wizard.refresh();
  assert.equal(f.requests(freshPath).length,1);
  f.navigate('overview');f.navigate('onboard');
  f.requests(freshPath)[0].resolve([ready]);
  assert.equal(await initial,false);assert.equal(await duplicate,false);
  assert.equal(f.wizard.list().length,0,'a stale catalog must not show unavailable rows in a new wizard');

  await load(f,[ready]);
  const done=deferred();
  f.ctx.manageComponent=()=>done.promise;
  const op=f.wizard.install('xray');
  f.navigate('overview');done.resolve(true);
  assert.equal(await op,false);
  assert.equal(f.requests(catalogPath).length,0,'retired page may not confirm a pending action');
}

for(const [result,row,want] of [[true,ready,false],[false,installed,false],[true,{...installed,inventory_error:'failed'},false],[true,{...installed,installed:'false'},false],[true,installed,true]]){
  const f=fixture();await load(f,[ready]);
  f.ctx.manageComponent=async()=>result;
  const op=f.wizard.install('xray');await settled();
  const reads=f.requests(catalogPath);
  assert.equal(reads.length,1);
  reads[0].resolve([row]);
  assert.equal(await op,want,'confirm requires accepted operation and clean installed readback');
}
{
  const f=fixture();await load(f,[ready]);f.ctx.manageComponent=async()=>true;
  const op=f.wizard.install('xray');await settled();
  f.navigate('overview');f.navigate('onboard');
  f.requests(catalogPath)[0].resolve([installed]);
  assert.equal(await op,false,'expired readback cannot repopulate a newer wizard instance');
  assert.equal(f.wizard.list().length,0,'a stale readback cannot populate a new wizard');
}
// Leaving and returning invalidates the click even if both views can read the same component.
{
  const f=fixture();
  await load(f,[ready]);
  const op=f.wizard.install('xray');
  const plan=f.requests(catalogPath+'/xray/plan?action=install')[0];
  assert(plan);
  f.navigate('engines');
  f.navigate('onboard');
  plan.resolve({ready:true});
  await settled();
  assert.equal(f.calls.filter(c=>c.options.method==='POST').length,0);
  assert.equal(await op,false);
}
{
  const f=fixture();
  vm.runInContext(read('managed-nfq-bundle-ui.js'), f.ctx);
  const base=catalogPath+'/nfqws2/managed-bundle';
  const plan={revision:4,ready:true,code:'',reason:'',installed_idle:false,
    compatibility_ready:false,working_routes_changed:false,
    bundle:{provider_id:'fixture',flavor:'standard',architecture:'arm64',manifest_sha256:'a'.repeat(64)}};
  async function finishRead(planRequest) {
    planRequest.resolve(plan);
    await settled();
    f.requests(base+'/installed').at(-1).reject(Object.assign(new Error('Not installed'),{
      status:503,payload:{code:'MANAGED_NFQWS_SOURCE_UNAVAILABLE',installed_idle:false}
    }));
    await settled();
    f.requests('/api/v1/status').at(-1).resolve({revision:4});
    await settled();
  }
  const initial=f.wizard.refresh();
  f.requests(freshPath)[0].resolve([{id:'nfqws2',installed:false}]);
  await settled();
  await finishRead(f.requests(base+'/plan')[0]);
  assert.equal(await initial,true);
  assert.equal(f.wizard.list().find(r=>r.id==='nfqws2').canInstall,true);
  const op=f.wizard.install('nfqws2');
  await settled();
  const checks=f.requests(base+'/plan');
  assert.equal(checks.length,2);
  f.navigate('engines');
  f.navigate('onboard');
  await finishRead(checks[1]);
  assert.equal(f.calls.filter(c=>c.options.method==='POST').length,0);
  assert.equal(await op,false);
}
// A generic installed package cannot substitute for the managed NFQ receipt.
for (const observed of [false,true]) {
  const f=fixture();
  let managedInstalled=false, submits=0;
  f.ctx.wizardManagedNFQ.status=()=>({installed:managedInstalled,canInstall:!managedInstalled});
  f.ctx.wizardManagedNFQ.install=async()=>{submits++;managedInstalled=observed;return true;};
  await load(f,[{id:'nfqws2',installed:false}]);
  const op=f.wizard.install('nfqws2');await settled();
  f.requests(catalogPath)[0].resolve([{id:'nfqws2',installed:true}]);
  assert.equal(await op,observed);
  assert.equal(submits,1);
}
console.log('PASS component installation feedback, final read, reopen, session and wizard guards');
