// Simple mode model checks: no DOM, server or network.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const read=name=>readFileSync(new URL('../'+name,import.meta.url),'utf8');
const context={};
vm.runInNewContext(read('cmd/razvilka/web/simple-home.js'),context);
const {model,available,plural}=context.RazvilkaSimpleHome;
const catalog=[{id:'youtube',name:'YouTube',category:'Видео'},{id:'discord',name:'Discord',category:'Мессенджеры'},{id:'roblox',name:'Roblox',category:'Игры'}];
const snap=(runtime,extra={})=>({policy:{setup_complete:true,enabled:true,revision:3},services:Object.fromEntries(Object.keys(runtime).map(id=>[id,{id,enabled:true}])),runtime:Object.fromEntries(Object.entries(runtime).map(([id,state])=>[id,{state,message:'detail '+id}])),...extra});

assert.equal(model(null,catalog).phase,'loading');
const refused=model(null,catalog,{},true);
assert.equal(refused.phase,'recovery');
assert.equal(refused.title,'Нужно восстановление');
assert.match(refused.text,/Панель отвечает/);
assert.doesNotMatch(refused.title+refused.text,/Загружаем|выключен|Добавьте первый/);
assert.equal(model(snap({youtube:'healthy'},{applied_services:{youtube:{enabled:true,route:'nfqws2'}}}),catalog,{youtube:{kind:'good',route:'nfqws2'}},true).phase,'recovery','known refusal takes precedence over retained healthy state');
assert.equal(model({policy:{setup_complete:false}},catalog).phase,'setup');
assert.match(model({policy:{setup_complete:false}},catalog).text,/Автопилот проверит доступные способы подключения/);
assert.doesNotMatch(model({policy:{setup_complete:false}},catalog).text,/всё сделает сам/);
assert.equal(model(snap({},{stopped:true}),catalog).phase,'off');
const stoppedSnapshot=snap({youtube:'healthy'},{stopped:true});
const stoppedBefore=JSON.stringify(stoppedSnapshot);
const stoppedHome=model(stoppedSnapshot,catalog);
assert.equal(stoppedHome.title,'Проект остановлен');
assert.match(stoppedHome.text,/общий переключатель проекта/);
assert.doesNotMatch(stoppedHome.text,/Включите автопилот в настройках/);
assert.equal(JSON.stringify(stoppedSnapshot),stoppedBefore,'presentation changed Stop or autonomy intent');
const pausedSnapshot=snap({},{policy:{setup_complete:true,enabled:false},stopped:false});
assert.equal(model(pausedSnapshot,catalog).title,'Автопилот на паузе');
assert.equal(model(pausedSnapshot,catalog).tone,'paused','ordinary pause is not an active check or failure');
assert.match(model(pausedSnapshot,catalog).text,/Пауза не останавливает уже применённые маршруты/);
assert.equal(model({...pausedSnapshot,stopped:true},catalog).title,'Проект остановлен','policy pause obscured explicit project Stop');
const pausedRow=model(snap({youtube:'paused'}),catalog).services[0];
assert.equal(pausedRow.bucket,'problem','presentation tone must not change aggregates');
assert.equal(pausedRow.tone,'paused');
const disabledRow=model(snap({youtube:'healthy'},{services:{youtube:{enabled:false}}}),catalog).services[0];
assert.equal(disabledRow.tone,'paused');assert.equal(disabledRow.bucket,'problem');
const failedWhilePaused=model(snap({youtube:'paused'},{applied_services:{youtube:{enabled:true,route:'nfqws2'}}}),catalog,{youtube:{kind:'bad',route:'nfqws2'}}).services[0];
assert.equal(failedWhilePaused.short,'Проверка не пройдена');assert.equal(failedWhilePaused.tone,undefined,'a current failed proof must stay red');
const shellHTML=read('cmd/razvilka/web/index.html');
assert.doesNotMatch(shellHTML,/планировщика rc\.2/);
assert.match(shellHTML,/Расписание работает на роутере/);
assert.equal(model(snap({}),catalog).phase,'empty');

const applied={youtube:{enabled:true,route:'nfqws2'},discord:{enabled:true,route:'nfqws2'}};
const proofs={youtube:{kind:'good',route:'nfqws2'},discord:{kind:'good',route:'nfqws2'}};
const ok=model(snap({youtube:'healthy',discord:'applied'},{applied_services:applied}),catalog,proofs);
assert.equal(ok.tone,'ok');
assert.equal(ok.title,'Всё работает');
assert.deepEqual(Array.from(ok.services,s=>s.short),['Работает','Работает']);

const busy=model(snap({youtube:'healthy',discord:'pending'},{applied_services:applied}),catalog,proofs);
assert.equal(busy.tone,'progress');
assert.match(busy.title,/^Настраиваю 1 сервис…$/);

const bad=model(snap({youtube:'healthy',discord:'component-stopped',roblox:'apply-refused'}),catalog);
assert.equal(bad.tone,'problem');
assert.equal(bad.title,'2 сервиса пока не работают');
assert.deepEqual(Array.from(bad.services,s=>s.id),['discord','roblox','youtube'],'problems first');
assert.equal(bad.services[0].short,'Нужный компонент не запущен');
assert.equal(bad.services[0].name,'Discord');

// A capability refusal is terminal for the current settings: it is labelled,
// never presented as a retry, and the headline promises no further attempts.
const limited=model(snap({youtube:'capability-refused',discord:'excluded'}),catalog);
assert.equal(limited.tone,'problem');
assert.equal(limited.services.find(s=>s.id==='youtube').short,'Недоступно в текущем режиме');
assert.equal(limited.services.find(s=>s.id==='discord').short,'Не разрешён списком или исключениями');
assert.doesNotMatch(limited.text+limited.services.map(s=>s.short).join(' '),/повторит|продолжает попытки|Проверяется/);
assert.match(limited.text,/не может включить их сам/);
const mixed=model(snap({youtube:'capability-refused',discord:'apply-refused'}),catalog);
assert.match(mixed.text,/нужно ваше решение/);
assert.doesNotMatch(mixed.text,/^Автопилот продолжает попытки/);
assert.equal(model(snap({discord:'apply-refused'}),catalog).text,'Автопилот продолжает попытки. Причина указана у сервиса.','retryable failures keep their wording');
// A later recheck does not make the missing domain path or stopped component
// self-repairing. Current supported paths require configuration by the owner.
const domainUnavailable=model(snap({youtube:'domain-route-unavailable'}),catalog);
assert.equal(domainUnavailable.services[0].short,'Нет подтверждённого обхода для доменного сервиса');
assert.equal(domainUnavailable.services[0].bucket,'problem');
assert.equal(domainUnavailable.services[0].detail,'detail youtube');
assert.doesNotMatch(domainUnavailable.services[0].short,/Проверяется|Работает/);
assert.equal(domainUnavailable.services[0].owner,true,'a recheck does not promise an unavailable path will configure itself');
for(const state of ['component-stopped','component-unavailable','domain-route-unavailable']){
  const waitingForOwner=model(snap({youtube:state}),catalog);
  assert.equal(waitingForOwner.services[0].owner,true,state);
  assert.match(waitingForOwner.text,/не может включить их сам/,state);
  assert.doesNotMatch(waitingForOwner.text,/продолжает попытки/,state);
}
assert.doesNotMatch(read('cmd/razvilka/web/simple-home.js'),/Автопилот проверит и включит его/,'adding a service does not promise that it will be enabled');

// Retained runtime labels are saved history: neither a current failure nor
// an assertion that the autopilot is still actively retrying.
for(const oldState of ['component-unavailable','component-stopped','apply-refused','healthy','checking']){
  const retained=model(snap({youtube:oldState},{observation:{state:'retained'},applied_services:applied}),catalog,proofs);
  assert.equal(retained.title,'Нет свежих данных автопилота',oldState);
  assert.equal(retained.services[0].bucket,'progress',oldState);
  assert.match(retained.services[0].short,/Сохранённые настройки/);
  assert.doesNotMatch(retained.title+retained.text+retained.services[0].short,/не работает|продолжает попытки|Работает|Включается|Проверяется/);
}
const retainedBad=model(snap({youtube:'healthy'},{observation:{state:'retained'},applied_services:applied}),catalog,{youtube:{kind:'bad',route:'nfqws2',detail:'fresh failed proof'}});
assert.equal(retainedBad.services[0].short,'Проверка не пройдена','independent matched bad proof remains visible');
assert.equal(retainedBad.services[0].detail,'fresh failed proof');
assert.equal(model(snap({youtube:'component-unavailable'}),catalog).title,'1 сервис пока не работает','fresh snapshot behavior is unchanged');
assert.equal(model(snap({youtube:'healthy'},{observation:{state:'retained'},safe_mode:true}),catalog).phase,'recovery','recovery takes precedence over retained presentation');

const waiting=model({...snap({discord:'rate-limited'}),runtime:{discord:{state:'rate-limited',message:'Лимит применений за час исчерпан. Следующая попытка примерно через 12 мин.'}}},catalog);
assert.equal(waiting.services[0].short,'Следующая попытка примерно через 12 мин');
assert.equal(model(snap({discord:'rate-limited'}),catalog).services[0].short,'Пауза между попытками');

const restarted=model({...snap({youtube:'pending',discord:'pending'}),applied_services:{youtube:{enabled:true}}},catalog);
assert.equal(restarted.tone,'progress','one service still waits for its first apply');
assert.equal(restarted.services.find(s=>s.id==='youtube').short,'Включён · перепроверяется');
assert.equal(restarted.services.find(s=>s.id==='discord').short,'Ждёт проверки');
assert.notEqual(model({...snap({youtube:'checking'}),applied_services:{youtube:{enabled:true}}},catalog).title,'Всё работает');
assert.equal(model({...snap({youtube:'checking'}),applied_services:{youtube:{enabled:true}}},catalog).tone,'progress');

// A restart, a successful Apply, and a historical healthy label never renew
// the exact route/revision/network proof. Only the shared fresh result does.
for(const runtime of ['pending','checking','applied','healthy']){
  const input=snap({youtube:runtime},{applied_services:applied});
  const result=model(input,catalog);
  assert.notEqual(result.title,'Всё работает',runtime);
  assert.notEqual(result.services[0].short,'Работает',runtime);
}
const returned=snap({youtube:'applied'},{applied_services:applied});
returned.runtime.youtube.message='Ваш возврат на штатный NFQWS2 применён. Веб-проверка пока не подтверждена.';
assert.match(model(returned,catalog).services[0].detail,/не подтверждена/);
assert.equal(model(returned,catalog).tone,'progress');
assert.notEqual(model(returned,catalog,{youtube:{kind:'good',route:'sing-box:node-old'}}).tone,'ok');
assert.equal(model(returned,catalog,{youtube:{kind:'bad',route:'nfqws2'}}).services[0].short,'Проверка не пройдена');
assert.notEqual(model(snap({youtube:'healthy'}),catalog,proofs).tone,'ok','unapplied service cannot borrow a PASS');
assert.notEqual(model({...returned,services:{youtube:{enabled:false}}},catalog,proofs).tone,'ok','a paused service cannot borrow a PASS');
for(const recovery of [{safe_mode:true},{blocked:true}]){
  const result=model(snap({youtube:'healthy'},{applied_services:applied,...recovery}),catalog,proofs);
  assert.equal(result.phase,'recovery');
  assert.equal(result.tone,'problem');
}

// Run the real shared proof adapter: TTL, revision, route, and the server's
// freshness verification must all survive before simple mode can turn green.
const dashboardSource=read('cmd/razvilka/web/service-dashboard-ui.js');
const proofContext={state:{status:{revision:9},serviceControl:{config_revision:9}},serviceDashboard:{control:{results:[]}}};
vm.createContext(proofContext);
vm.runInContext(['serviceDashboardApplied','serviceDashboardResult','serviceDashboardFresh','serviceDashboardSummary'].map(name=>{
  const fn=dashboardSource.match(new RegExp('function '+name+'\\([^]*?\\n}\\n'));
  assert(fn,name);return fn[0];
}).join('\n'),proofContext);
const now=Date.now();
const proof={service_id:'youtube',kind:'check',checked_route:'nfqws2',status:'pass',available:true,config_revision:9,checked_at:new Date(now-1000).toISOString(),valid_until:new Date(now+60000).toISOString(),freshness_verified:true};
const live={id:'youtube',applied_state:applied.youtube};
for(const change of [{},{freshness_verified:false},{config_revision:8},{valid_until:new Date(now-1).toISOString()},{checked_route:'sing-box:node-old'},{status:'fail',available:false}]){
  proofContext.serviceDashboard.control.results=[{...proof,...change}];
  const summary=proofContext.serviceDashboardSummary(live);
  const result=model(returned,catalog,{youtube:summary});
  assert.equal(result.services[0].bucket,Object.keys(change).length===0?'ok':change.status==='fail'?'problem':'progress',JSON.stringify(change));
}

const removing=model({...snap({youtube:'healthy'}),services:{youtube:{id:'youtube',enabled:true},discord:{id:'discord',removing:true}}},catalog);
assert.deepEqual(Array.from(removing.services,s=>s.id),['youtube'],'a service being removed is not listed');

const managed=new Set(['youtube']);
assert.deepEqual(Array.from(available(catalog,managed,''),s=>s.id),['discord','roblox']);
assert.deepEqual(Array.from(available(catalog,managed,'игр'),s=>s.id),['roblox'],'category matches');
assert.deepEqual(Array.from(available(catalog,managed,'DIS'),s=>s.id),['discord'],'case-insensitive');
assert.deepEqual(available(catalog,new Set(),'',1).length,1,'bounded');

const {communityAvailable}=context.RazvilkaSimpleHome;
const shared=[{id:'ga-netflix',name:'Netflix',category:'Видео'},{id:'ga-telegram',name:'Telegram',imported:true},{id:'ga-youtube',name:'YouTube'}];
assert.deepEqual(Array.from(communityAvailable(shared,catalog),e=>e.id),['ga-netflix'],'imported and built-in names are not offered twice');

// Exercise the actual one-click import action: overlapping source lists
// require the same explicit confirmation as the advanced import dialog.
const importAction=read('cmd/razvilka/web/simple-home.js').match(/  async function importCommunity\(id\) {[^]*?\n  }\n/);
assert(importAction);
for(const choice of ['cancel','accept','missing','clean']){
  const calls=[],prompts=[],ui={busy:'',note:'',error:'',community:[{id:'ga-test'}]};
  const preview={import_guard:'source-sha256',source_sha256:'a'.repeat(64),conflicts:choice==='clean'?[]:[{value:'shared.example',service_name:'Other service'}]};
  const actionContext={ui,render(){},api:async(path,options)=>{
    calls.push({path,options});
    return path.endsWith('/preview')?preview:{service:{id:'custom-ga-test'}};
  },interfaceManage:async(id,on)=>{calls.push({manage:id,on});return true;}};
  if(choice!=='missing')actionContext.askConfirmation=async(...args)=>{prompts.push(args);return choice==='accept';};
  vm.createContext(actionContext);vm.runInContext(importAction[0],actionContext);
  await actionContext.importCommunity('ga-test');
  const imported=calls.find(c=>c.path?.endsWith('/import'));
  assert.equal(!!imported,choice==='accept'||choice==='clean',choice);
  assert.equal(calls.some(c=>c.manage),!!imported,choice+' enrolls only an imported service');
  assert.equal(prompts.length,choice==='clean'||choice==='missing'?0:1,choice);
  if(imported){
    const body=JSON.parse(imported.options.body);
    assert.equal(body.allow_conflicts,choice==='accept');
    assert.equal(body.expected_source_sha256,preview.source_sha256);
  }
  assert.equal(ui.busy,'',choice+' releases action lock');
  assert.equal(ui.note,'',choice+' clears pending import text');
}

for(const choice of ['cancel','accept','missing']){
  const calls=[],prompts=[],ui={busy:'',note:'',error:'',community:[{id:'telegram-ip'}]};
  const preview={import_guard:'source-sha256',source_sha256:'b'.repeat(64),bundled_fallback:true,source_date:'2026-10-20',source_url:'https://core.telegram.org/resources/cidr.txt',service:{cidrs:['91.108.56.0/22']},conflicts:[]};
  const actionContext={ui,render(){},api:async(path,options)=>{calls.push({path,options});return path.endsWith('/preview')?preview:{service:{id:'custom-telegram-ip'}};},interfaceManage:async()=>{calls.push({manage:true});return true;}};
  if(choice!=='missing')actionContext.askConfirmation=async(...args)=>{prompts.push(args);assert(!calls.some(call=>call.path?.endsWith('/import')));return choice==='accept';};
  vm.createContext(actionContext);vm.runInContext(importAction[0],actionContext);await actionContext.importCommunity('telegram-ip');
  assert.equal(calls.some(call=>call.path?.endsWith('/import')),choice==='accept');assert.equal(calls.some(call=>call.manage),choice==='accept');
  if(prompts.length){assert.match(prompts[0][1],/2026-10-20/);assert.match(prompts[0][1],/https:\/\/core.telegram.org\/resources\/cidr.txt/);assert.match(prompts[0][1],/не свежая загрузка/);}
}

const {updateNotice}=context.RazvilkaSimpleHome;
assert.equal(updateNotice({update_available:true,can_prepare:true,latest_version:'0.20.1'}).text,'Вышло обновление 0.20.1');
assert.equal(updateNotice({update_available:true,can_prepare:false,latest_version:'0.20.1'}),null,'an update this router cannot prepare is not offered');
assert.equal(updateNotice({update_available:false}),null);
assert.equal(updateNotice({update_available:true,can_prepare:true,latest_version:'<b>'}),null);

const {quietEngine}=context.RazvilkaSimpleHome;
assert.equal(quietEngine('0','Не установлен'),true);
assert.equal(quietEngine('0','Процесс запущен'),false,'an installed engine stays visible');
assert.equal(quietEngine('2','Не установлен'),false,'an assigned engine stays visible');

const {doctorView,nightly,withNightly}=context.RazvilkaSimpleHome;
const doc=doctorView({schema:1,status:'fail',summary:'Есть проблема.',checks:[{id:'internet',title:'Интернет роутера',status:'ok',detail:'ok'},{id:'services',title:'Ваши сервисы',status:'fail',detail:'Не работают: 1 из 2.',items:[{id:'a',name:'YouTube',status:'ok'},{id:'b',name:'Discord',status:'fail',detail:'Не удалось включить.'}],action:{view:'engines',label:'Открыть обходы'}},{id:'x',title:'X',status:'evil',action:{view:'javascript:alert(1)'}}]});
assert.equal(doc.status,'fail');
assert.equal(doc.rows[1].items.length,1,'working services are not repeated');
assert.equal(doc.rows[1].items[0].name,'Discord');
assert.equal(doc.rows[1].action.view,'engines');
assert.equal(doc.rows[2].status,'warn','an unknown status reads as a warning');
assert.equal(doc.rows[2].action,null,'an action outside panel views is dropped');
assert.equal(doctorView({schema:2}),null);
assert.equal(nightly({mode:'install'}),true);
assert.equal(nightly({mode:'check'}),false);
const base={revision:4,application:{mode:'install',start:'03:00',end:'04:00',days:[0,1]},components:{mode:'install'}};
const off=withNightly(base,'application',false);
assert.equal(off.application.mode,'check');
assert.equal(off.application.start,'03:00','the window keeps its time');
assert.equal(base.application.mode,'install','the snapshot is not mutated');

assert.equal(plural(1,'сервис','сервиса','сервисов'),'1 сервис');
assert.equal(plural(3,'сервис','сервиса','сервисов'),'3 сервиса');
assert.equal(plural(11,'сервис','сервиса','сервисов'),'11 сервисов');
assert.equal(plural(22,'сервис','сервиса','сервисов'),'22 сервиса');

const html=read('cmd/razvilka/web/index.html');
assert.ok(html.indexOf('/simple-home.js?v=')>html.indexOf('/interface.js?v='),'loaded after interface.js');

// Execute the real generated button's delegated handler and the real shared
// router. Static app.js [data-view] bindings cannot cover a later DOM insertion.
{
  const elements=[];
  class Element {
    constructor(id=''){this.id=id;this.dataset={};this.children=[];this.events=new Map();this.innerHTML='';this.textContent='';this.hidden=false;this.className='';const classes=new Set();this.classList={contains:v=>classes.has(v),add:v=>classes.add(v),remove:v=>classes.delete(v),toggle:(v,on)=>on?classes.add(v):classes.delete(v)};elements.push(this);}
    addEventListener(type,fn){this.events.set(type,fn);}
    append(child){this.children.push(child);}
    prepend(child){this.children.unshift(child);}
    before(child){this.children.unshift(child);}
    setAttribute(){}
    focus(){}
    matches(){return false;}
    querySelector(selector){const part=/data-rz-part="([^"]+)"/.exec(selector);return part?this.children.find(c=>c.dataset.rzPart===part[1])||null:null;}
    querySelectorAll(){return [];}
  }
  const overview=new Element('view-overview'),wizard=new Element('view-onboard');
  for(const id of ['view-autopilot','view-nodes','pageTitle','pageSubtitle','consoleMenuBackdrop','consoleMenu'])new Element(id);
  const events=new Map(),windowEvents=new Map(),body=new Element('body');
  const document={body,readyState:'loading',activeElement:new Element(),hidden:false,getElementById:id=>elements.find(e=>e.id===id)||null,createElement:()=>new Element(),querySelector:()=>null,addEventListener:(type,fn)=>events.set(type,fn),dispatchEvent:()=>{}};
  const state={currentView:'overview',status:{},services:[]};
  let writes=0,modeChanges=0;
  const location={hash:'#/overview'};
  const routerContext={document,state,consoleSnapshot:{policy:{setup_complete:false,enabled:true},services:{},runtime:{}},location,
    history:{replaceState:(_a,_b,hash)=>{location.hash=hash;}},localStorage:{getItem:()=>null,setItem:()=>{modeChanges++;}},
    CustomEvent:class{constructor(type,init){this.type=type;this.detail=init.detail;}},CSS:{escape:v=>v},
    viewMeta:{overview:['Главная',''],onboard:['Первичная настройка','']},
    $:selector=>document.getElementById(selector.slice(1)),$$:selector=>selector==='.view'?elements.filter(e=>e.id.startsWith('view-')):[],
    consoleDrawerInert(){},renderWorkspaceNavigation(){},refreshPanelView(){},
    fetch:()=>{writes++;throw new Error('Navigation must not write');},api:()=>{writes++;throw new Error('Navigation must not write');},
    setInterval(){},setTimeout(){},clearTimeout(){},scrollTo(){},matchMedia:()=>({matches:false}),
    addEventListener:(type,fn)=>windowEvents.set(type,fn),
  };
  routerContext.window=routerContext;
  vm.createContext(routerContext);
  const appSource=read('cmd/razvilka/web/app.js'),consoleSource=read('cmd/razvilka/web/console.js');
  for(const [source,name] of [[appSource,'setView'],[consoleSource,'consoleViewChanged']]){
    const fn=source.match(new RegExp('function '+name+'\\([^]*?\\n}\\n'));
    assert(fn,name);vm.runInContext(fn[0],routerContext);
  }
  const simpleSource=read('cmd/razvilka/web/simple-home.js');
  // Test-only access to closure actions; production source exports no test hook.
  vm.runInContext(simpleSource.replace('  window.addEventListener(\'razvilka:autonomy-state\'', '  root.testSimpleActions={render,apply,renderSettings,renderDevicesNote};\n  window.addEventListener(\'razvilka:autonomy-state\''),routerContext);
  routerContext.testSimpleActions.render();
  const home=document.getElementById('rzSimpleHome');
  assert(home&&overview.children.includes(home),'real home was inserted dynamically');
  const status=home.children.find(e=>e.dataset.rzPart==='status');
  const rendered=status.innerHTML.match(/<button\b[^>]*data-view="([^"]+)"[^>]*>([^<]+)<\/button>/);
  assert(rendered,'setup action was rendered');
  assert.equal(rendered[2],'Начать настройку');
  const button={dataset:{view:rendered[1]},hasAttribute:()=>false};
  home.events.get('click')({target:{closest:()=>button}});
  assert.equal(state.currentView,'onboard','setup click opens existing wizard workspace');
  assert.equal(location.hash,'#/onboard','shared router updates URL');
  assert(wizard.classList.contains('active'),'wizard is visible');
  assert(!overview.classList.contains('active'),'home is no longer active');
  routerContext.testSimpleActions.apply();
  assert.equal(state.currentView,'onboard','reapplying simple mode does not redirect wizard');
  assert(body.classList.contains('rz-simple'),'simple mode remains enabled');
  assert.equal(modeChanges,0,'navigation does not toggle advanced mode');
  assert.equal(writes,0,'navigation never saves or applies configuration');

  // The periodic inventory reader updates state without rendering the hidden
  // advanced home. A later simple-mode tick must render from those new facts,
  // rather than repeatedly copying the previous "уточняется" HTML forever.
  const engineSource=new Element('ui7HomeEngines');
  engineSource.innerHTML='<p>Состояние уточняется</p>';
  state.authenticated=true;
  state.dataLoad={services:{loaded:true,phase:'ready'}};
  routerContext.interfaceDataReady=key=>state.dataLoad[key]?.loaded===true;
  routerContext.panelSectionState=(key,phase)=>{state.dataLoad[key]={loaded:true,phase};};
  for(const [source,name] of [[appSource,'inventoryObservationStale'],[appSource,'acceptPanelInventory'],[consoleSource,'consoleEngineState']]){
    const fn=source.match(new RegExp('function '+name+'\\([^]*?\\n}\\n'));
    assert(fn,name);vm.runInContext(fn[0],routerContext);
  }
  let summaryRenders=0;
  routerContext.renderHomeEngineSummary=()=>{
    summaryRenders++;
    engineSource.innerHTML=['installed','running','absent','unknown'].map(id=>`<p>${id}: ${routerContext.consoleEngineState(id).label}</p>`).join('');
  };
  const inventory=(retained=false)=>({schema:1,dataplane:'not-checked',state:retained?'retained':'available',revision:1,instance_id:'a'.repeat(32),data_age_ms:0,max_age_seconds:300,observed_at:new Date().toISOString(),data:{components:[{id:'installed',installed:true},{id:'running',installed:true,running:true},{id:'absent',installed:false}],engines:[],system:{}}});
  await Promise.resolve().then(()=>routerContext.acceptPanelInventory(inventory(),Date.now()));
  routerContext.testSimpleActions.render(true);
  const enginePart=home.children.find(e=>e.dataset.rzPart==='engines');
  assert(summaryRenders>0,'simple tick refreshes shared summary after async inventory arrival');
  assert.match(enginePart.innerHTML,/installed: Установлен/);
  assert.match(enginePart.innerHTML,/running: Процесс запущен/);
  assert.match(enginePart.innerHTML,/absent: Не установлен/);
  assert.match(enginePart.innerHTML,/unknown: Нет данных об установке/,'missing data never means not installed');
  await Promise.resolve().then(()=>routerContext.acceptPanelInventory(inventory(true),Date.now()));
  routerContext.testSimpleActions.render(true);
  assert.doesNotMatch(enginePart.innerHTML,/Процесс запущен|installed: Установлен/,'retained inventory cannot appear fresh');
  assert.match(enginePart.innerHTML,/Состояние уточняется/);
  state.inventoryObservation.retained=false;
  state.inventoryObservation.ageMS=61000;
  routerContext.testSimpleActions.render(true);
  assert.doesNotMatch(enginePart.innerHTML,/Процесс запущен/,'expired inventory cannot appear fresh');
  assert.equal(writes,0,'inventory rendering never saves or applies configuration');

  // Exercise the real renderer, not just model(): off used to suppress the
  // entire service column along with Add, despite retaining all enrollments.
  state.services=[...catalog,...['a','b','c','d'].map(id=>({id,name:`Service ${id}`})),{id:'new-site',name:'New service'}];
  const seven=Object.fromEntries(state.services.slice(0,7).map(s=>[s.id,'paused']));
  for(const stopped of [false,true]){
    routerContext.consoleSnapshot=snap(seven,{policy:{setup_complete:true,enabled:false},stopped});
    const before=JSON.stringify(routerContext.consoleSnapshot);
    routerContext.testSimpleActions.render(true);
    const main=home.children.find(e=>e.dataset.rzPart==='main');
    assert.match(main.innerHTML,/Мои сервисы/);
    assert.match(main.innerHTML,/data-rz-sh-toggle-add/);
    assert.equal((main.innerHTML.match(/data-rz-sh-remove=/g)||[]).length,7,'all paused/stopped enrollments remain visible');
    assert.equal((main.innerHTML.match(/rz-sh-service rz-sh-paused/g)||[]).length,7,'explicit paused rows use a presentation-only neutral tone');
    for(const service of state.services.slice(0,7))assert(main.innerHTML.includes(service.name));
    const toggle={dataset:{},hasAttribute:name=>name==='data-rz-sh-toggle-add'};
    home.events.get('click')({target:{closest:()=>toggle}});
    assert.match(main.innerHTML,/data-rz-sh-query/,'paused/stopped Add opens the real catalog');
    assert.match(main.innerHTML,/New service/);
    home.events.get('click')({target:{closest:()=>toggle}});
    assert.equal(JSON.stringify(routerContext.consoleSnapshot),before,'browsing changed Stop or policy intent');
    assert.equal(writes,0,'browsing enrollments must not enable policy or apply routes');
  }
  for(const fixture of [null,{policy:{setup_complete:false}},snap(seven,{blocked:true}),snap(seven,{safe_mode:true})]){
    routerContext.consoleSnapshot=fixture;routerContext.testSimpleActions.render(true);
    assert.doesNotMatch(home.children.find(e=>e.dataset.rzPart==='main').innerHTML,/data-rz-sh-toggle-add|data-rz-sh-remove=/,'unknown/setup/recovery cannot expose management');
  }
  routerContext.consoleSnapshot=snap(seven,{policy:{setup_complete:true,enabled:false}});
  for(const authenticated of [false,true]){
    state.authenticated=authenticated;routerContext.interfaceState={authRevoked:authenticated};
    routerContext.testSimpleActions.render(true);
    assert.doesNotMatch(home.children.find(e=>e.dataset.rzPart==='main').innerHTML,/data-rz-sh-toggle-add|data-rz-sh-remove=/,'logout/revoke cannot expose retained management');
  }
  state.authenticated=true;routerContext.interfaceState={authRevoked:false};
  routerContext.consoleSnapshot.policy.all_lan=true;
  new Element('view-settings');new Element('deviceGrid');
  routerContext.testSimpleActions.renderSettings(true);routerContext.testSimpleActions.renderDevicesNote();
  const settings=document.getElementById('rzSimpleSettings').innerHTML;
  assert.match(settings,/совместимых стабильных выпусков/);assert.match(settings,/Для RC может потребоваться чистая установка/);
  assert.match(settings,/Автообновление управляемого NFQWS2 пока недоступно/);
  assert.doesNotMatch(settings,/ставится сама|при сбое возвращается прежняя|обновляются с проверкой и откатом/);
  assert.match(document.getElementById('rzDevicesScope').textContent,/предназначены для всех устройств/);
  assert.doesNotMatch(settings+document.getElementById('rzDevicesScope').textContent,/Обход работает|Обход действует/);
  assert.equal(writes,0,'settings and scope text never change maintenance or route state');

  // The real home consumes the same bounded progress model as the heartbeat.
  // Progress remains visible when the autonomy observation is retained/missing,
  // and cannot renew that observation or become a successful service result.
  const availability={};vm.runInNewContext(read('cmd/razvilka/web/panel-availability.js'),availability);
  routerContext.RazvilkaPanelAvailability=availability.RazvilkaPanelAvailability;
  state.services=[{id:'youtube',name:'YouTube <img src=x onerror=alert(1)>'}];
  state.panelAvailability={kind:'responding',admission:{state:'busy',active:1,exclusive:true,fenced:false,operation:'автопилот: проверка сервисов и подписок',progress:{
    id:7,kind:'autonomy',phase:'checking',service_id:'youtube',started_at:'2026-10-31T00:00:00Z',phase_started_at:'2026-10-31T00:01:00Z',deadline_at:'2026-10-31T00:02:00Z',elapsed_seconds:65,phase_seconds:5,remaining_seconds:55,deadline_exceeded:false
  }}};
  const saved=snap({youtube:'healthy'},{observation:{state:'retained'},applied_services:{youtube:{enabled:true,route:'nfqws2'}}});
  routerContext.consoleSnapshot=saved;
  const savedBefore=JSON.stringify(saved);
  events.get('razvilka:panel-availability')();
  assert.match(status.innerHTML,/Нет свежих данных автопилота/);
  assert.match(status.innerHTML,/Проверка и применение сервиса · YouTube &lt;img/);
  assert.doesNotMatch(status.innerHTML,/<img|Всё работает/);
  assert.match(status.innerHTML,/Прошло 1 мин 5 с/);
  assert.equal(JSON.stringify(saved),savedBefore,'progress renewed retained settings or runtime evidence');
  routerContext.consoleSnapshot=null;events.get('razvilka:panel-availability')();
  assert.match(status.innerHTML,/Загружаем состояние/);
  assert.match(status.innerHTML,/Проверка и применение сервиса/,'progress vanished without a fresh autonomy snapshot');
  Object.assign(state.panelAvailability.admission.progress,{elapsed_seconds:130,phase_seconds:70,remaining_seconds:0,deadline_exceeded:true});
  events.get('razvilka:panel-availability')();
  assert.match(status.innerHTML,/Лимит времени истёк; ожидаем завершения и очистки/);
  assert.equal(state.panelAvailability.admission.state,'busy','deadline fabricated release');
  state.panelAvailability.admission.fenced=true;state.panelAvailability.admission.state='recovery-required';routerContext.interfaceRecoveryRequired=()=>true;
  events.get('razvilka:panel-availability')();
  assert.match(status.innerHTML,/Нужно восстановление/);
  assert.doesNotMatch(status.innerHTML,/Проверка и применение сервиса|Прошло/,'recovery headline did not take precedence');
  routerContext.interfaceRecoveryRequired=()=>false;state.panelAvailability.admission={state:'idle',active:0,exclusive:false,fenced:false};
  events.get('razvilka:panel-availability')();assert.doesNotMatch(status.innerHTML,/rz-sh-activity/,'released holder retained progress');
  assert.equal(writes,0,'progress rendering or heartbeat events started an API operation');
}
console.log('simple home: ok');

// The mode switch names the active mode and describes what clicking does.
{
 const source=read('cmd/razvilka/web/simple-home.js');
 const label=source.match(/  function label\(\) \{[^]*?\n  }/)[0];
 for(const on of [true,false]){
  const title={},hint={},attributes={};
  const toggle={setAttribute:(key,value)=>attributes[key]=value,querySelector:selector=>selector==='b'?title:hint};
  vm.runInNewContext(label+';label();',{enabled:()=>on,document:{getElementById:()=>toggle}});
  assert.equal(title.textContent,on?'Простой режим':'Расширенный режим');
  assert.equal(attributes['aria-checked'],String(!on));
  assert.match(hint.textContent,on?/Включить все разделы/:/Перейти к сервисам/);
 }
}

// Canceling service removal must not announce that its route will be removed.
{
 const action=read('cmd/razvilka/web/simple-home.js').match(/  async function act\([^]*?\n  }/)[0];
 for(const accepted of [false,true,undefined,'failed']){
  const toasts=[],actionState={busy:'',error:''};
  const cancelContext={ui:actionState,render(){},interfaceManage:async()=>{if(accepted==='failed')throw Error('Сервер отказал');return accepted;},interfaceToast:message=>toasts.push(message)};
  vm.createContext(cancelContext);vm.runInContext(action,cancelContext);await cancelContext.act('site',true);
  assert.equal(toasts.length,accepted===true?1:0,'unaccepted removal announced success');assert.equal(actionState.busy,'');if(accepted==='failed')assert.equal(actionState.error,'Сервер отказал');
 }
}
