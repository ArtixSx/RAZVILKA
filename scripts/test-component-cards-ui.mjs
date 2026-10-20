import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const read = file => readFileSync(new URL('../' + file, import.meta.url), 'utf8');
const app = read('cmd/razvilka/web/app.js');
const consoleCode = read('cmd/razvilka/web/console.js');
const interfaceCode = read('cmd/razvilka/web/interface.js');
const slice = (source, start, end) => {
  const from = source.indexOf(start), to = source.indexOf(end, from + start.length);
  assert.ok(from >= 0 && to > from, start);
  return source.slice(from, to);
};
const esc = value => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const meta = {name:'WARP · MASQUE', tone:'amber', icon:'cloud', subtitle:'Cloudflare', description:'Profile'};
const base = {id:'usque', name:meta.name, provider:'opkg', installed:true, installed_version:'1.0.1', available_version:'1.0.3', update_available:true, can_update:true, can_remove:true, checked_at:'2026-09-20T10:00:00Z'};
const state = {components:[{...base}], engines:[{id:'usque', installed:true, version:'different runtime output'}], engineConfigs:[], services:[], dataLoad:{components:{loaded:true, phase:'ready'}}};
const model = vm.createContext({state, esc, consoleDate:value=>value, ci:()=>'', serviceDashboardApplied:service=>service.applied_state||{}, consoleEngineMeta:{usque:meta}});
vm.runInContext(slice(consoleCode, 'function consoleEngineState(', 'function consoleNavigate('), model);
vm.runInContext(slice(interfaceCode, 'const engineProgressEvidence =', 'function renderInterfaceEngines('), model);
const card = () => model.interfaceEngineCard('usque', meta);
assert.match(card(), /1\.0\.1 → 1\.0\.3/);
assert.doesNotMatch(card(), /different runtime output/);
assert.match(card(), /Процесс не запущен/);
assert.match(card(), /data-component-action="update"[^>]*>Обновить/);
assert.match(card(), /data-component-action="remove"[^>]*>Удалить/);
assert.match(card(), /data-component-refresh="usque"/);
assert.doesNotMatch(card(), /Бинарник обнаружен/, 'aggregate installed does not prove a binary path');
state.engines[0].binary_path='/opt/bin/usque';
assert.match(card(), /Бинарник обнаружен/);
state.engines[0].installed=false;
assert.doesNotMatch(card(), /Бинарник обнаружен/, 'a contradictory path alone does not prove installation');
state.engines[0].installed=true;
delete state.engines[0].binary_path;
assert.equal((card().match(/data-engine-step="profile"/g)||[]).length,1);
assert.equal((card().match(/data-engine-step="check"/g)||[]).length,1);
assert.equal((card().match(/data-engine-step="apply"/g)||[]).length,1);
assert.match(card(), /aria-current="step"/);
assert.match(card(), /Все шаги настройки/);

state.components[0] = {...base, update_check_error:'Источник недоступен', catalog_stale:true, can_update:false};
assert.match(card(), /Источник недоступен/);
assert.match(card(), /1\.0\.1/);
assert.doesNotMatch(card(), /→|Обновление не требуется/);
assert.match(card(), /data-component-action="update"[^>]*disabled/);
assert.doesNotMatch(card(), /data-component-action="remove"[^>]*disabled/, 'catalog failure must not prevent a permitted removal');

// NFQWS2: updated in place while running and used by routes, only with a
// cached rollback copy; its removal stays protected.
{
  const nfq = {...base, id:'nfqws2', running:true, managed_update:true, rollback_ready:true};
  model.consoleEngineMeta.nfqws2 = meta;
  state.components = [nfq]; state.engines = [{id:'nfqws2', installed:true, running:true}];
  state.services = [{applied_state:{enabled:true, route:'nfqws2'}}];
  const nfqCard = () => model.interfaceEngineCard('nfqws2', meta);
  assert.match(nfqCard(), /data-component-action="update"(?![^>]*disabled)[^>]*>Обновить с проверкой/);
  assert.match(nfqCard(), /data-component-action="remove"[^>]*disabled/);
  state.components = [{...nfq, rollback_ready:false}];
  assert.match(nfqCard(), /data-component-action="update"[^>]*disabled[^>]*Проверить версии/);
  state.components = [{...base}]; state.engines = [{id:'usque', installed:true, version:'different runtime output'}]; state.services = [];
}
state.components[0] = {...base, running:true};
assert.match(card(), /Процесс запущен/);
assert.equal(model.consoleEngineState('usque').tone,'unknown','process alone is not accepted runtime evidence');
assert.match(card(), /data-component-action="update"[^>]*disabled/, 'unmanaged running component must not update in place');
assert.match(card(), /data-component-action="remove"[^>]*disabled/);
state.components[0] = {...base};
state.services = [{applied_state:{enabled:true, route:'usque'}}];
assert.match(card(), /data-component-action="remove"[^>]*disabled/);
state.services = [];
state.components[0] = {...base, external_owner:true};
assert.match(card(), /Внешнее управление/);
assert.match(card(), /data-component-action="remove"[^>]*disabled/);
state.components[0] = {...base, lifecycle_block_reason:'Компонент нужен другому пакету'};
assert.match(card(), /Компонент нужен другому пакету/);
assert.match(card(), /data-component-action="remove"[^>]*disabled/);

state.components[0] = {...base, installed:false, installed_version:'', update_available:false, can_install:true, can_remove:false};
state.engines = [];
assert.match(card(), /Не установлен/);
assert.match(card(), /Доступна 1\.0\.3/);
assert.match(card(), /data-component-action="install"[^>]*>Установить/);
assert.doesNotMatch(card(), /data-component-action="remove"/);

state.components = []; state.engineConfigs = [{id:'usque', installed:true}];
assert.equal(model.consoleEngineState('usque').installed, true, 'config installed evidence must use installed, not nonexistent available');
assert.match(card(), /Версия не определена/);
state.engineConfigs = [];
assert.match(card(), /Нет данных об установке/);
assert.doesNotMatch(card(), /Не установлен/);
assert.match(card(), /Нет данных о процессе/);

state.components = [{...base, installed:false, installed_version:'', inventory_error:'Не прочитан список пакетов'}];
assert.match(card(), /Нет данных об установке/);
assert.match(card(), /Не удалось проверить установку/);
assert.match(card(), /data-component-action="install"[^>]*disabled/);

state.components = [{...base, available_version:'1.0.1', update_available:false, checked_at:''}];
assert.match(card(), /Проверка обновлений ещё не подтверждена/);
state.components[0].checked_at = base.checked_at;
assert.match(card(), /Обновление не требуется/);
state.components[0].checked_at = 'invalid';
assert.doesNotMatch(card(), /Обновление не требуется/);
state.components[0] = {...base, installed_version_source:'runtime', update_available:false};
assert.match(card(), /Обнаружен отдельный компонент/);
assert.doesNotMatch(card(), /Обновление не требуется/);
state.components[0].installed_version = '<script>secret</script>';
state.components[0].update_check_error = '<img src=x onerror=attack()>';
assert.doesNotMatch(card(), /<script>|<img src=x/);
assert.match(card(), /&lt;script&gt;/);

// The component strip must distinguish an unconfirmed managed runtime from
// a known stopped process without discarding detector installation facts.
{
  const elements = Object.fromEntries(['componentSummary', 'componentEmpty', 'componentStrip'].map(id => [id, {}]));
  const current = {components:[], engineConfigs:[], componentFilter:'all'};
  const ctx = vm.createContext({state:current, esc, $:selector=>elements[selector.slice(1)], $$:()=>[], inventoryObservationStale:()=>false});
  vm.runInContext(slice(app, 'function renderComponents(', 'async function refreshComponents('), ctx);
  const render = component => {
    current.components = [component];
    ctx.renderComponents();
    return elements.componentStrip.innerHTML;
  };
  const installed = {...base, update_available:false, configured:true, running:false, can_install:false, can_update:false, can_remove:false};
  for (const id of ['nfqws2', 'xray']) {
    const unknown = render({...installed, id, runtime_observation:'unknown'});
    assert.match(unknown, /component-runtime unknown">СОСТОЯНИЕ НЕ ПОДТВЕРЖДЕНО/);
    assert.doesNotMatch(unknown, /НАСТРОЕН · НЕ ЗАПУЩЕН|component-runtime running/);
    assert.match(unknown, /установлена 1\.0\.1/);
    assert.match(elements.componentSummary.innerHTML, /Установлено<\/span><b>1<\/b>/);
    assert.doesNotMatch(unknown, /component-verification verified/, 'runtime observation must not verify installation');
    assert.match(render({...installed, id}), /component-runtime configured">НАСТРОЕН · НЕ ЗАПУЩЕН/);
    assert.match(render({...installed, id, running:true, runtime_observation:'unknown'}), /component-runtime unknown">СОСТОЯНИЕ НЕ ПОДТВЕРЖДЕНО/, 'unknown must take precedence over process flags');
    const owned = render({...installed, id, running:true, runtime_observation:'owned'});
    assert.match(owned, /component-runtime running">ЗАПУЩЕН/);
    assert.doesNotMatch(owned, /component-verification verified/, 'structural ownership must not verify installation');
  }
}

const lifecycleCode = slice(app, 'async function refreshComponents(', 'function renderStatus(');
function fixture() {
  const calls=[], notices=[], details=[];
  const refreshButton={disabled:false,textContent:''};
  const component={...base};
  const current={components:[component], engines:[], engineConfigs:[], dataLoad:{},currentView:'overview',homeSummaryRenders:0};
  const workflowState={epoch:1};
  let responder=async path=>path.includes('/plan?')?{ready:true,steps:[]}:
    path.startsWith('/api/v1/components/')?{ok:true}:
    path.startsWith('/api/v1/components')?[{...component}]:[];
  let confirmation=async()=>true;
  const ctx=vm.createContext({
    state:current,workflowState,workflowSession:epoch=>epoch===workflowState.epoch,
    $:()=>refreshButton,$$:()=>[],CSS:{escape:s=>s},panelBusy:()=>false,
    panelSectionState:(key,phase,error)=>{current.dataLoad[key]={loaded:phase==='ready'||current.dataLoad[key]?.loaded===true,phase,message:error?.message||''};},
    api:async(path,options={})=>{calls.push({path,options});return responder(path,options);},
    askConfirmation:(...args)=>confirmation(...args),
    showNotice:(...args)=>notices.push(args),showDetails:(...args)=>details.push(args),
    refreshHomeEngineSummary(){current.homeSummaryRenders++;},renderComponents(){},renderEngineControl(){},renderEngines(){},renderConsole(){},renderInterfaceEngines(){},
  });
  vm.runInContext(lifecycleCode,ctx);
  return {ctx,state:current,calls,notices,details,workflowState,refreshButton,setResponder:fn=>responder=fn,setConfirmation:fn=>confirmation=fn};
}
let f=fixture();
await f.ctx.manageComponent('usque','remove');
assert.deepEqual(f.calls.filter(c=>c.options.method==='POST').map(c=>c.path), ['/api/v1/components/usque/remove']);
assert.ok(f.calls[0].path.endsWith('/plan?action=remove'));
assert.equal(f.calls[0].options.readTimeoutMs,110000);
assert.equal(f.state.componentOperation,null);

f=fixture(); f.setResponder(async()=>({ready:false,blockers:[{code:'SERVICE_DEPENDENCY'}]}));
await f.ctx.manageComponent('usque','remove');
assert.equal(f.calls.length,1,'blocked removal must stop before POST');
assert.equal(f.details.length,1);
assert.equal(f.state.componentOperation,null);

f=fixture(); f.setConfirmation(async()=>false);
await f.ctx.manageComponent('usque','remove');
assert.equal(f.calls.length,1,'cancelled confirmation must not POST');
assert.equal(f.state.componentOperation,null);

f=fixture();
f.setResponder(async (path,options)=>path.includes('/plan?')?{ready:true}:options.method==='POST'?{ok:false}:[{...base}]);
assert.equal(await f.ctx.manageComponent('usque','remove'),false);
assert.equal(f.notices.some(notice=>notice[0]==='success'),false,'unconfirmed response must not announce successful removal');

f=fixture();f.setResponder(async(path,options)=>path.includes('/plan?')?{ready:true}:options.method==='POST'?{ok:true,pending_live_acceptance:true,transaction_id:'a'.repeat(32)}:[{...base}]);
assert.equal(await f.ctx.manageComponent('usque','update'),true);
assert.equal(f.calls.filter(call=>call.options.method==='POST').length,1);
assert.equal(f.notices.some(notice=>notice[0]==='success'),false,'202 candidate must not claim accepted update');
assert.match(f.notices.at(-1)[1],/принятие версии ожидается/);

f=fixture(); let finishPlan;
f.setResponder(()=>new Promise(resolve=>{finishPlan=resolve;}));
const first=f.ctx.manageComponent('usque','update');
await f.ctx.manageComponent('usque','remove');
assert.equal(f.calls.length,1,'double click must not open a second component plan');
f.workflowState.epoch++;
finishPlan({ready:true,steps:[]}); await first;
assert.equal(f.calls.length,1,'late plan after logout must not gain mutation authority');
assert.equal(f.notices.length,0);

f=fixture(); const previous=f.state.components;
f.setResponder(async()=>{throw new Error('opkg update unavailable');});
assert.equal(await f.ctx.refreshComponents(true),false);
assert.equal(f.state.components,previous,'failed refresh discarded installed component data');
assert.equal(f.state.componentRefreshRequest,null);
assert.equal(f.refreshButton.disabled,false);
assert.match(f.state.componentCatalogError,/opkg/);

f=fixture(); let finishRefresh;
f.setResponder(()=>new Promise(resolve=>{finishRefresh=resolve;}));
const refresh=f.ctx.refreshComponents(true);
const duplicate=f.ctx.refreshComponents(true);
await Promise.resolve();
assert.equal(f.calls.length,1,'double refresh must share one catalog request');
assert.equal(f.calls[0].options.readTimeoutMs,110000);
finishRefresh([{...base,available_version:'1.0.4'}]); await Promise.all([refresh,duplicate]);
assert.equal(f.state.components[0].available_version,'1.0.4');
assert.equal(f.state.homeSummaryRenders,1,'explicit refresh updates home component status');
assert.equal(f.state.componentRefreshRequest,null);

f=fixture(); const old=f.state.components;
f.setResponder(()=>new Promise(resolve=>{finishRefresh=resolve;}));
const late=f.ctx.refreshComponents(true); await Promise.resolve();
f.workflowState.epoch++;
finishRefresh([{...base,installed_version:'late'}]); await late;
assert.equal(f.state.components,old,'late catalog response revived state after logout');
assert.equal(f.notices.length,0);

const delegated=[];
const actionContext=vm.createContext({
  refreshComponents:flag=>delegated.push(['refresh',flag]),
  manageComponent:(id,action)=>delegated.push([id,action]),
});
vm.runInContext(slice(interfaceCode,'function interfaceComponentAction(', "document.addEventListener('click',interfaceComponentAction)"),actionContext);
const click=button=>actionContext.interfaceComponentAction({target:{closest:()=>button}});
click({disabled:false,hasAttribute:name=>name==='data-component-refresh',dataset:{componentRefresh:'usque'}});
click({disabled:false,hasAttribute:()=>false,dataset:{component:'usque',componentAction:'remove'}});
click({disabled:true,hasAttribute:()=>false,dataset:{component:'usque',componentAction:'remove'}});
assert.deepEqual(delegated,[['refresh',true],['usque','remove']]);

const timers=[],transport=[];
const apiContext=vm.createContext({
  Headers,AbortController,ADMIN_TOKEN_KEY:'fixture',sessionStorage:{getItem:()=>null},
  setTimeout:(fn,delay)=>{timers.push(delay);return timers.length;},clearTimeout(){},
  fetch:async(url,options)=>{transport.push({url,options});return {ok:true,json:async()=>({ok:true})};},
  friendlyErrorMessage:value=>value,
});
vm.runInContext(slice(app,'async function api(','function friendlyErrorMessage('),apiContext);
await apiContext.api('/api/v1/components?refresh=true',{readTimeoutMs:110000});
await apiContext.api('/api/v1/status');
await apiContext.api('/api/v1/components?refresh=true',{readTimeoutMs:9999999});
await apiContext.api('/api/v1/components/usque/remove',{method:'POST',readTimeoutMs:110000});
assert.deepEqual(timers,[110000,20000,110000], 'only explicit bounded reads may wait longer; mutations must not gain read timeout');
assert.ok(transport.every(call=>!Object.hasOwn(call.options,'readTimeoutMs')),'internal timeout option leaked into fetch');
// A confirmed absence is one readiness fact, not a second version badge.
const banner = { innerHTML: '' };
Object.assign(model, { $: () => banner, $$: () => [], viewMeta: {}, consoleText() {} });
vm.runInContext(slice(consoleCode, 'function renderConsoleEngine(', 'function renderConsole(){'), model);
Object.assign(state, { selectedEngine:'usque', currentView:'engineconfig', engineConfigs:[], services:[], engines:[], inventoryObservation:undefined,
  components:[{...base, installed:false, installed_version:'', available_version:'', update_available:false}] });
model.renderConsoleEngine();
assert.equal((banner.innerHTML.match(/Не установлен/g)||[]).length,1);
assert.equal((card().match(/Не установлен/g)||[]).length,1);
state.components[0] = {...state.components[0], available_version:'1.0.3'};
model.renderConsoleEngine();
assert.match(banner.innerHTML,/Доступна 1\.0\.3/);
state.components[0] = {...state.components[0], installed:true, available_version:''};
model.renderConsoleEngine();
assert.match(banner.innerHTML,/Версия не определена/);
assert.match(card(),/Версия не определена/);
console.log('PASS component cards: truthful runtime unknown/stopped states, versions/inventory/update errors, protected actions, reviewed removal, single-flight refresh and auth fences');
