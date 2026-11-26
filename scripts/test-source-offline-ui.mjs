import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const app=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const extract=name=>{const match=app.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));assert(match,name);return match[0];};
const sourceNames=['acceptSourceOfflineCatalog','sourceOfflineDate','sourceHasSavedCopy','sourceOfflineStateText','syncSourceViewControls','readSourceView','switchSourceView','handleSourceViewLifecycle','sourceStateText','sourceFreshnessText','sourceErrorText','sourceKindText','sourceDiffText','renderSources','runSourceAction','refreshSources','setSourceDraft','applySourceDraft','discardSourceDraft'];
const panelNames=['panelReadContext','panelReadContextCurrent','invalidatePanelReads','readPanelResource','panelViewKeys','panelViewRequests','panelSectionState','panelBusy','refreshPanelLoadNotice','panelSnapshotCurrent','schedulePanelRetry','cancelPanelRefresh','renderPanelLoad','renderPanelSection','acceptPanelSection','acceptPanelInventory','settlePanelReads','refreshAll','loadPanelSnapshot'];
const flush=()=>new Promise(resolve=>setImmediate(resolve));
const deferred=()=>{let resolve;const promise=new Promise(yes=>resolve=yes);return {promise,resolve};};
const base={id:'saved',name:'Сохранённый',kind:'domains',url:'https://fixture.invalid/list',description:'Список',offline:true,ready:false,entries:2,enabled:false,applied_enabled:true,dirty:true,legacy_cache:false,last_known_good:false,cache_status:'offline-cache',sha256:'a'.repeat(64),updated_at:'2026-01-02T03:04:05Z',expires_at:'2099-01-02T03:04:05Z'};
const offlineRows=()=>[base,{...base,id:'reference',name:'Справочник',kind:'reference',cache_status:'',sha256:'',updated_at:'0001-01-01T00:00:00Z',expires_at:'invalid'},
 {...base,id:'stale',name:'Просрочен',cache_status:'stale',expires_at:'2020-01-01T00:00:00Z'},
 {...base,id:'legacy',name:'Legacy',legacy_cache:true,cache_status:'offline-cache',expires_at:'2020-01-01T00:00:00Z'},
 {...base,id:'rejected',name:'LKG',last_known_good:true,last_error:'<script>rejected</script>',cache_status:'offline-cache'},
 {...base,id:'quarantine',name:'Не подтверждён',cache_status:'quarantined'},
 {...base,id:'missing',name:'Нет копии',cache_status:'missing',sha256:'',entries:0}];
function fixture(){
 const state={currentView:'sources',authenticated:true,authGeneration:3,sourceView:'online',sourceOffline:null,status:{revision:4},sources:[],services:[],dataLoad:{},loadIssues:[]};
 const elements=new Map(),calls=[],messages=[],buttons=['online','offline'].map(mode=>({dataset:{sourceView:mode},classList:{toggle(){}},setAttribute(){}}));
 const $=id=>{if(!elements.has(id))elements.set(id,{hidden:true,disabled:false,textContent:'',innerHTML:'',classList:{toggle(){}},setAttribute(){}});return elements.get(id);};
 const offline={offline:true,read_only:true,sources:offlineRows()},online=[{...base,offline:false,ready:true,enabled:true,dirty:false}];
 const panelLoad={generation:0,request:null,controller:null,retryTimer:null,retryCount:0};let responder;
 const normal=(url,options={})=>{
  if(url==='/api/v1/auth/status')return {authenticated:true};
  if(url==='/api/v1/status')return {revision:4,sources_pending_changes:true};
  if(url==='/api/v1/sources/offline')return structuredClone(offline);
  if(url==='/api/v1/sources')return structuredClone(online);
  if(url==='/api/v1/services')return [];
  if(options.method==='POST')return structuredClone(online);
  throw new Error('unexpected '+url);
 };responder=normal;
 const context=vm.createContext({state,panelLoad,panelReads:{epoch:0,entries:new Map()},sourceViewRuntime:{epoch:0,readValid:false,write:null,message:''},$, $$:selector=>selector==='[data-source-view]'?buttons:[],AbortController,Date,Set,structuredClone,
  esc:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),
  api:async(url,options={})=>{calls.push({url,options});return responder(url,options);},document:{hidden:false,dispatchEvent(){}},CustomEvent:class{},setTimeout:()=>1,clearTimeout(){},scheduleNodeActivity(){},consoleInitialSetup(){},
  showNotice:(...args)=>messages.push(args),showDetails:(...args)=>messages.push(args),hideNotice(){},hideAuth(){$('#authScreen').hidden=true;},showAuth(){state.authenticated=false;state.authGeneration++;$('#authScreen').hidden=false;context.cancelPanelRefresh();context.handleSourceViewLifecycle({type:'razvilka:auth-required'});},
 });
 for(const name of ['renderStatus','renderSettings','renderSystem','renderMetrics','renderServices','renderOverviewQuickServices','renderOverviewServices','renderReadiness','renderEngines','renderEngineControl','renderComponents','renderWarpManager','renderNodes','renderConnections','renderDevices','renderTestLab','renderEngineLab','renderAudit','renderStrategyLab','renderDNS','renderDNSPlan','renderDNSServiceBindings'])context[name]=()=>{};
 vm.runInContext([...panelNames,...sourceNames].map(extract).join('\n'),context);
 return {context,state,panelLoad,calls,messages,$,offline,online,normal,set:handler=>responder=handler};
}
let f=fixture();await f.context.readSourceView();
assert.equal(f.state.sources[0].ready,true);assert.equal(f.$('#refreshSources').disabled,false);
const live=JSON.stringify(f.state.sources),saved=JSON.stringify(f.offline),before=f.calls.length;
await f.context.switchSourceView('offline');
assert.equal(f.calls.slice(before).some(call=>call.url==='/api/v1/sources/offline'),true);
assert.equal(f.calls.slice(before).some(call=>call.url==='/api/v1/sources'),false);
assert.equal(f.calls.some(call=>call.options.method),false,'view entry refreshed or wrote sources');
assert.equal(JSON.stringify(f.state.sources),live,'offline view overwrote the active source array');
assert.equal(JSON.stringify(f.offline),saved,'offline consumer changed the source dates/settings');
for(const id of ['refreshSources','applySourceChanges','discardSourceChanges'])assert.equal(f.$('#'+id).disabled,true);
assert.equal(f.$('#readSourceView').disabled,false,'completed read left manual readback disabled');
const markup=f.$('#sourceRows').innerHTML;
for(const label of ['Справочный источник','Срок копии истёк','Копия не подтверждена','Источник требует сверки','Последнее обновление отклонено · сохранена прежняя копия','Сохранённая копия','Сохранённой копии нет'])assert.ok(markup.includes(label),label);
assert.match(markup,/Источник требует сверки · Срок копии истёк/);
assert.match(markup,/Сохранённый выбор: выключен/);assert.match(markup,/Применённый выбор: включён/);
assert.match(markup,/Загружено:/);assert.match(markup,/Срок локальной копии:/);
assert.doesNotMatch(markup,/<script>|data-source-toggle|state-dot (ok|good)|готов|PASS|актуален/);
assert.match(markup,/&lt;script&gt;rejected&lt;\/script&gt;/);
assert.doesNotMatch(f.$('#sourceOverview').innerHTML,/готов|PASS|актуален/);
assert.equal(f.$('#sourceOverviewCaption').textContent,'Сведения о сохранённых копиях');
const offCount=f.calls.length;await f.context.refreshSources();await f.context.setSourceDraft('saved',true);await f.context.applySourceDraft();await f.context.discardSourceDraft();assert.equal(f.calls.length,offCount,'programmatic offline control sent a POST');
assert.equal(f.context.sourceOfflineDate('0001-01-01T00:00:00Z'),'—');assert.equal(f.context.sourceOfflineDate('invalid'),'—');assert.equal(f.context.sourceOfflineDate(0),'—');

for(const tamper of [value=>value.offline=false,value=>value.read_only=false,value=>value.sources[0].ready=true,value=>value.sources[0].offline=false,value=>value.sources.push(value.sources[0])]){
 const bad=structuredClone(f.offline);tamper(bad);assert.throws(()=>f.context.acceptSourceOfflineCatalog(bad));
}
const withExtra=structuredClone(f.offline);withExtra.sources[0].body='private-body';withExtra.token='private-token';f.context.acceptSourceOfflineCatalog(withExtra);assert.doesNotMatch(JSON.stringify(f.state.sourceOffline),/private-body|private-token/);

// Actual panel request/generation guards fence a canceled normal-view read,
// including transports that ignore abort. The offline snapshot remains intact.
f=fixture();const old=deferred();let reached=false;
f.set((url,options)=>{if(url==='/api/v1/sources'){reached=true;return old.promise;}return f.normal(url,options);});
const initial=f.context.readSourceView();while(!reached)await flush();
await f.context.switchSourceView('offline');old.resolve([{...base,ready:true,name:'old green'}]);await initial;
assert.equal(f.state.sourceView,'offline');assert.equal(f.$('#refreshSources').disabled,true);assert.doesNotMatch(f.$('#sourceRows').innerHTML,/old green/);

f=fixture();await f.context.readSourceView();const write=deferred();
f.set((url,options)=>options.method==='POST'?write.promise:f.normal(url,options));
const refreshing=f.context.refreshSources();await f.context.switchSourceView('offline');write.resolve([{...base,ready:true,name:'late mutation'}]);await refreshing;
assert.equal(f.$('#refreshSources').disabled,true);assert.equal(f.$('#applySourceChanges').disabled,true);assert.doesNotMatch(f.$('#sourceRows').innerHTML,/late mutation/);
await f.context.switchSourceView('online');assert.equal(f.$('#refreshSources').disabled,false);
f.set(f.normal);await f.context.setSourceDraft('saved',false);assert.equal(f.calls.filter(call=>call.url.includes('/draft')).length,1,'normal source selection stopped working');
await f.context.refreshSources();await f.context.applySourceDraft();await f.context.discardSourceDraft();
for(const action of ['refresh','apply','discard'])assert.equal(f.calls.filter(call=>call.url==='/api/v1/sources/'+action&&call.options.method==='POST').length,action==='refresh'?2:1,'normal '+action+' stopped working');

for(const status of [401,403]){
 f=fixture();await f.context.switchSourceView('offline');
 f.set((url,options)=>{if(url==='/api/v1/sources/offline')throw Object.assign(new Error('authorization denied'),{status});return f.normal(url,options);});
 await f.context.readSourceView();
 assert.equal(f.$('#sourceOfflineBanner').hidden,true);assert.doesNotMatch(f.$('#sourceRows').innerHTML,/Сохранённая копия|LKG/);
 assert.equal(f.$('#refreshSources').disabled,true);assert.equal(f.calls.some(call=>call.url==='/api/v1/sources'),false,'authorization failure used normal/offline fallback');
}
f=fixture();const late=deferred();f.set((url,options)=>url==='/api/v1/sources/offline'?late.promise:f.normal(url,options));
const loading=f.context.switchSourceView('offline');while(!f.calls.some(call=>call.url==='/api/v1/sources/offline'))await flush();
f.context.showAuth();late.resolve(structuredClone(f.offline));await loading;
assert.equal(f.state.sourceOffline,null);assert.equal(f.$('#refreshSources').disabled,true);assert.doesNotMatch(f.$('#sourceRows').innerHTML,/Сохранённая копия/);
f=fixture();await f.context.readSourceView();const lateWrite=deferred();f.set((url,options)=>options.method==='POST'?lateWrite.promise:f.normal(url,options));
const applying=f.context.applySourceDraft();f.context.showAuth();lateWrite.resolve({sources:[{...base,ready:true,name:'old authenticated write'}],note:'old success'});await applying;
assert.equal(f.messages.length,0,'late pre-logout mutation published a success notice');assert.doesNotMatch(f.$('#sourceRows').innerHTML,/old authenticated write/);assert.equal(f.$('#applySourceChanges').disabled,true);
console.log('PASS source offline UI: exact GET view, immutable live data/dates, truthful warning labels, disabled writes and real panel/auth epoch fences');

for(const outcome of ['partial','failed','retained','all','none']){
 const f=fixture();await f.context.readSourceView('online');
 const good={...f.online[0],kind:'domains',applied_enabled:true,ready:true,last_error:'',last_known_good:false,legacy_cache:false,cache_status:'fresh'};
 const bad={...good,id:'telegram',ready:false,cache_status:'quarantined',last_error:'source network request failed; check DNS, HTTPS and availability'};
 const rows=outcome==='partial'?[good,bad]:outcome==='failed'?[bad]:outcome==='retained'?[{...bad,ready:true,last_known_good:true,cache_status:'last-known-good'},{...good,applied_enabled:false},{...good,kind:'reference'}]:outcome==='all'?[good]:[{...good,applied_enabled:false}];
 f.set((url,options)=>url==='/api/v1/sources/refresh'?rows:f.normal(url,options));await f.context.refreshSources();
 const detail=f.messages.at(-1);assert.equal(detail[1],({partial:'Источники обновлены частично',failed:'Источники не обновлены',retained:'Источники не обновлены',all:'Источники обновлены',none:'Нет используемых источников'})[outcome]);
 if(outcome==='retained')assert.match(detail[0].message,/0 из 1/,'retained copy, draft-only source and reference must not count as refreshed');
 if(outcome==='partial'||outcome==='failed'){assert.match(detail[0].message,outcome==='partial'?/1 из 2/:/0 из 1/);const html=f.$('#sourceRows').innerHTML;assert.match(html,/Не удалось загрузить источник/);assert.match(html,/<details><summary>Технические сведения об ошибке<\/summary><p>source network request failed/);}
}
console.log('PASS source refresh distinguishes partial/all/none/failure and keeps raw errors in technical details');
