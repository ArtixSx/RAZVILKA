// Production presentation/caller checks only; no HTTP/native/NFQ execution.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const functions=['strategyCompatibilityView','strategyManualSelectionInput','renderStrategyLab','updateStrategyMemory','validateStrategyCandidate','probeStrategyCandidate'].map(name=>{
  const match=source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));assert(match,name);return match[0];
}).join('\n');
const full={ok:true,native:true,lua_checked:true,code:'COMPATIBLE',checked_at:'2020-01-02T03:04:05Z'};
function fixture(validation=full,safety={temporary_scoped_firewall_probe:false}) {
  const elements=new Map(),calls=[],details=[];
  const $=id=>{if(!elements.has(id))elements.set(id,{value:id==='#strategyTarget'?'youtube':id==='#strategyFamily'?'ipv4':'',disabled:false,innerHTML:'',textContent:'',classList:{toggle(){}},addEventListener(){}});return elements.get(id);};
  const candidate={id:'candidate-1',pool_id:'tls',name:'Candidate',arguments:'--filter-tcp=443',validation};
  const state={authGeneration:0,currentView:'strategylab',status:{safe_mode:true,live_active:false},services:[{id:'youtube',name:'YouTube',probe_url:'https://youtube.example/'}],strategyLab:{pools:[{id:'tls',name:'TLS',protocol:'tcp'}],candidates:[candidate],safety},z2kPreview:{}};
  let handler=async(path,options)=>options.method==='POST'?candidate:state.strategyLab;
  const c={state,$,esc:value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])),Number,Map,Math,AbortController,setTimeout,clearTimeout,
    api:async(path,options={})=>{calls.push({path,...options});return handler(path,options);},showDetails:(value,title)=>details.push({value,title}),serviceName:()=> 'YouTube',importZ2KStrategies(){},askConfirmation:async()=>{calls.push({confirm:true});return false;}};
  vm.createContext(c);vm.runInContext(functions,c);
  return {c,state,$,calls,details,setHandler(fn){handler=fn;}};
}
let passed=0;async function check(name,fn){await fn();passed++;console.log('PASS '+name);}
await check('saved native plus Lua success is historical, without a current-installation or connection claim',()=>{const f=fixture(),v=f.c.strategyCompatibilityView(full);assert.equal(v.compatible,true);assert.equal(v.title,'Последняя проверка совместимости пройдена');assert.equal(v.label,'ПРОВЕРКА ПРОЙДЕНА');assert.match(v.checkedAt,/2020/);assert.match(v.note,/Повторите проверку перед применением/);assert.doesNotMatch(v.title,/установленным|подтверждена|маршрут|доступ|Нативная проверка пройдена/);});
await check('missing or invalid saved timestamp never borrows the current time',()=>{for(const checked_at of [undefined,'not-a-date',null])assert.equal(fixture().c.strategyCompatibilityView({...full,checked_at}).checkedAt,'Время последней проверки не указано');});
await check('manual unchecked selection is neutral without a health or confidence claim',()=>{const f=fixture();f.state.strategyLab.selections=[{service_id:'youtube',protocol:'tcp',ip_family:'ipv4',candidate_id:'candidate-1',mode:'manual',frozen:true,status:'manual-unchecked',healthy:false,confidence:0,reason:'стратегия выбрана вручную; проверка здоровья ещё не выполнена'}];f.c.renderStrategyLab();const html=f.$('#strategyMemory').innerHTML;assert.match(html,/strategy-memory-card pending/);assert.match(html,/ВЫБРАНО ВРУЧНУЮ · ОЖИДАЕТ ПРОВЕРКИ/);assert.match(html,/проверка здоровья ещё не выполнена/);assert.doesNotMatch(html,/class="strategy-memory-card (?:healthy|degraded)"|% доверия|РАБОТАЕТ|ЕСТЬ ОШИБКИ/);assert.equal(f.calls.length,0);});
await check('manual frozen degraded snapshot preserves genuine stale evidence reason',()=>{const f=fixture();f.state.strategyLab.selections=[{service_id:'youtube',protocol:'tcp',ip_family:'ipv4',candidate_id:'candidate-1',mode:'manual',frozen:true,status:'frozen-degraded',healthy:false,confidence:0,reason:'результаты проверки устарели'}];f.c.renderStrategyLab();const html=f.$('#strategyMemory').innerHTML;assert.match(html,/strategy-memory-card degraded/);assert.match(html,/результаты проверки устарели/);assert.doesNotMatch(html,/ОЖИДАЕТ ПРОВЕРКИ|strategy-memory-card (?:pending|healthy)/);});
await check('manual frozen healthy snapshot retains the genuine eligible result',()=>{const f=fixture();f.state.strategyLab.selections=[{service_id:'youtube',protocol:'tcp',ip_family:'ipv4',candidate_id:'candidate-1',mode:'manual',frozen:true,status:'frozen-healthy',healthy:true,confidence:1,reason:'свежие подтверждённые проверки'}];f.c.renderStrategyLab();const html=f.$('#strategyMemory').innerHTML;assert.match(html,/strategy-memory-card healthy/);assert.match(html,/ЗАКРЕПЛЕНО/);assert.match(html,/100% доверия/);assert.doesNotMatch(html,/ОЖИДАЕТ ПРОВЕРКИ|strategy-memory-card (?:pending|degraded)/);});
for(const validation of [{ok:true},{ok:true,native:true},{ok:true,lua_checked:true},{ok:true,native:true,lua_checked:true,quiescence_unknown:true},null])await check('partial/uncertain result does not become compatibility '+JSON.stringify(validation),()=>{const v=fixture().c.strategyCompatibilityView(validation);assert.equal(v.compatible,false);assert.notEqual(v.tone,'pass');});
await check('explicit compatibility rejection is separate from unconfirmed result',()=>{const v=fixture().c.strategyCompatibilityView({ok:false,native:false,code:'COMPATIBILITY_REJECTED'});assert.equal(v.label,'ПРОВЕРКА ОТКЛОНЕНА');assert.equal(v.compatible,false);});
await check('legacy native timeout remains unconfirmed rather than incompatible',()=>{const v=fixture().c.strategyCompatibilityView({ok:false,native:true,code:'VALIDATION_TIMEOUT'});assert.equal(v.label,'НЕ ПОДТВЕРЖДЕНО');assert.equal(v.tone,'warn');});
await check('uncertain completion takes precedence over an old rejection code',()=>{const v=fixture().c.strategyCompatibilityView({ok:false,native:true,code:'NATIVE_REJECTED',quiescence_unknown:true});assert.equal(v.label,'НЕ ПОДТВЕРЖДЕНО');assert.equal(v.tone,'warn');});
await check('disabled executor preserves editable choice and historical pass without a probe affordance',()=>{const f=fixture();f.c.renderStrategyLab();assert.match(f.$('#strategyCandidates').innerHTML,/ПРОВЕРКА ПРОЙДЕНА/);assert.match(f.$('#strategyCandidates').innerHTML,/Последняя проверка:.*2020/);assert.match(f.$('#strategyCandidates').innerHTML,/Повторите проверку перед применением/);assert.match(f.$('#strategyCandidates').innerHTML,/Проверить совместимость/);assert.doesNotMatch(f.$('#strategyCandidates').innerHTML,/data-strategy-probe|СОВМЕСТИМА/);assert.match(f.$('#strategyPools').innerHTML,/1 прошли проверку/);assert.match(f.$('#strategyResourceBudget').innerHTML,/ИЗОЛИРОВАННЫЙ ТЕСТ НЕДОСТУПЕН/);assert.equal(f.$('#strategyTarget').disabled,false);assert.equal(f.$('#strategyFamily').disabled,false);assert.equal(f.calls.length,0);});
await check('partial legacy result is not counted or offered as a Lua-compatible probe',()=>{const f=fixture({ok:true,native:true},{temporary_scoped_firewall_probe:true});f.c.renderStrategyLab();assert.match(f.$('#strategyPools').innerHTML,/0 прошли проверку/);assert.doesNotMatch(f.$('#strategyCandidates').innerHTML,/data-strategy-probe/);});
await check('explicit false fences an old probe click before confirmation or POST',async()=>{const f=fixture();await f.c.probeStrategyCandidate('candidate-1');assert.equal(f.calls.length,0);assert.match(f.details[0].title,/Изолированный тест недоступен/);});
await check('explicit true preserves an existing separate probe affordance without executing it',()=>{const f=fixture(full,{temporary_scoped_firewall_probe:true});f.c.renderStrategyLab();assert.match(f.$('#strategyCandidates').innerHTML,/data-strategy-probe/);assert.equal(f.calls.length,0);assert.equal(f.$('#strategyTarget').disabled,false);});
await check('an older response without the availability field preserves the existing display',()=>{const f=fixture(full,{});f.c.renderStrategyLab();assert.match(f.$('#strategyCandidates').innerHTML,/data-strategy-probe/);assert.equal(f.calls.length,0);});
await check('Validate uses the same one POST then saved-state GET, with no new body/grant/probe',async()=>{const f=fixture();await f.c.validateStrategyCandidate('candidate-1');assert.equal(f.details.at(-1).title,'Последняя проверка совместимости пройдена');assert.equal(f.calls.length,2);const {signal,...post}=f.calls[0];assert.deepEqual(post,{path:'/api/v1/strategy-lab/candidates/candidate-1/validate',method:'POST'});assert.equal(signal.aborted,false);assert.deepEqual(f.calls[1],{path:'/api/v1/strategy-lab',cache:'no-store'});assert.equal(f.details.at(-1).value,f.state.strategyLab.candidates[0].validation);assert.match(f.$('#detailsSubtitle').textContent,/Последняя проверка:.*2020/);assert.match(f.$('#detailsSubtitle').textContent,/Повторите проверку перед применением/);assert.match(f.$('#detailsSubtitle').textContent,/Проверка соединения и применение выполняются отдельно/);});
await check('saved historical timestamp wins over a newer POST receipt',async()=>{const f=fixture();f.setHandler(async(_,opts)=>opts.method==='POST'?{id:'candidate-1',validation:{...full,checked_at:'2030-01-02T03:04:05Z'}}:f.state.strategyLab);await f.c.validateStrategyCandidate('candidate-1');assert.equal(f.details.at(-1).title,'Последняя проверка совместимости пройдена');assert.match(f.$('#detailsSubtitle').textContent,/2020/);assert.doesNotMatch(f.$('#detailsSubtitle').textContent,/2030/);});
await check('saved rejection wins over an optimistic POST receipt',async()=>{const f=fixture();f.setHandler(async(_,opts)=>opts.method==='POST'?{id:'candidate-1',validation:full}:{pools:[],candidates:[{id:'candidate-1',validation:{ok:false,native:false,code:'COMPATIBILITY_REJECTED'}}],safety:{temporary_scoped_firewall_probe:false}});await f.c.validateStrategyCandidate('candidate-1');assert.match(f.details.at(-1).title,/не подтверждена/);assert.equal(f.details.at(-1).value.ok,false);});
await check('missing saved candidate cannot borrow compatibility from POST',async()=>{const f=fixture();f.setHandler(async(_,opts)=>opts.method==='POST'?{id:'candidate-1',validation:full}:{pools:[],candidates:[],safety:{temporary_scoped_firewall_probe:false}});await f.c.validateStrategyCandidate('candidate-1');assert.match(f.details.at(-1).title,/не подтверждена/);assert.match(f.details.at(-1).value.error,/Сохранённый результат/);});
await check('failed saved-state read does not claim that successful native work was applied',async()=>{const f=fixture();f.setHandler(async(_,opts)=>{if(opts.method==='POST')return {validation:full};throw new Error('read unavailable');});await f.c.validateStrategyCandidate('candidate-1');assert.match(f.details.at(-1).title,/не подтверждена/);assert.equal(f.details.at(-1).value.error,'read unavailable');assert.equal(f.calls.length,2);});
const manualButton=()=>({dataset:{strategyManual:'candidate-1'},disabled:false});
const savedManual=(extra={})=>({service_id:'youtube',protocol:'tcp',ip_family:'ipv4',candidate_id:'candidate-1',mode:'manual',frozen:true,status:'manual-unchecked',healthy:false,confidence:0,reason:'стратегия выбрана вручную; проверка здоровья ещё не выполнена',...extra});
await check('manual action does not infer server admission from historical validation or probe availability',()=>{for(const validation of [full,{...full,code:'OTHER'}, {...full,lua_checked:false}, {...full,quiescence_unknown:true}, null]){const f=fixture(validation);f.state.strategyLab.quiescence_unknown=true;const input=f.c.strategyManualSelectionInput('candidate-1');assert.equal(input.body.mode,'manual');assert.equal('ready' in input,false);f.c.renderStrategyLab();assert.match(f.$('#strategyCandidates').innerHTML,/data-strategy-manual="candidate-1"\s+title=/);assert.equal(f.calls.length,0);}});
await check('manual button is connected to the existing candidate listener without permission-like request fields',()=>{const f=fixture();f.c.renderStrategyLab();assert.match(f.$('#strategyCandidates').innerHTML,/data-strategy-manual="candidate-1"\s+title=/);assert.deepEqual(Object.keys(f.c.strategyManualSelectionInput('candidate-1').body),['mode','service_id','protocol','ip_family','candidate_id']);assert.match(source,/if \(manual\) updateStrategyMemory\(manual, false, true\)/);});
await check('manual save sends the exact contract once then reads canonical state without network unlock',async()=>{const f=fixture(),saved={...f.state.strategyLab,selections:[savedManual()]};f.setHandler(async(_,opts)=>opts.method==='POST'?savedManual({healthy:true,confidence:1}):saved);await f.c.updateStrategyMemory(manualButton(),false,true);assert.equal(f.calls.length,2);const {signal,...request}=f.calls[0];assert.equal(signal.aborted,false);assert.deepEqual(request,{path:'/api/v1/strategy-lab/selections',method:'POST',body:JSON.stringify({mode:'manual',service_id:'youtube',protocol:'tcp',ip_family:'ipv4',candidate_id:'candidate-1'})});assert.deepEqual(f.calls[1],{path:'/api/v1/strategy-lab',cache:'no-store'});assert.equal(f.state.strategyLab,saved);assert.equal(f.details.at(-1).title,'Ручной выбор сохранён');assert.equal(f.details.at(-1).value.healthy,false);assert.match(f.$('#strategyMemory').innerHTML,/strategy-memory-card pending/);assert.doesNotMatch(f.$('#strategyMemory').innerHTML,/strategy-memory-card healthy/);assert.match(f.$('#detailsSubtitle').textContent,/Проверка здоровья и применение выполняются отдельно/);assert.equal(f.state.status.safe_mode,true);assert.equal(f.state.status.live_active,false);assert.equal(f.state.strategySelectionAction,null);});
await check('catalog service without probe URL can be chosen but cannot start a probe',async()=>{const f=fixture(full,{temporary_scoped_firewall_probe:true});delete f.state.services[0].probe_url;const saved={...f.state.strategyLab,selections:[savedManual()]};f.setHandler(async(_,opts)=>opts.method==='POST'?savedManual():saved);f.c.renderStrategyLab();assert.equal(f.$('#strategyTarget').disabled,false);assert.match(f.$('#strategyTarget').innerHTML,/value="youtube"/);await f.c.updateStrategyMemory(manualButton(),false,true);assert.equal(f.calls.length,2);f.calls.length=0;await f.c.probeStrategyCandidate('candidate-1');assert.equal(f.calls.length,0);assert.equal(f.details.at(-1).title,'Тест не запущен');});
await check('missing candidate or malformed manual tuple does not send a mutation',async()=>{for(const change of [f=>{f.state.strategyLab.candidates=[];},f=>{f.$('#strategyTarget').value='missing';},f=>{f.$('#strategyFamily').value='ipv5';},f=>{f.state.strategyLab.pools=[];},f=>{f.state.strategyLab.pools[0].protocol='other';}]){const f=fixture();change(f);await f.c.updateStrategyMemory(manualButton(),false,true);assert.equal(f.calls.length,0);assert.equal(f.details.at(-1).title,'Ручной выбор не подтверждён');}});
await check('ordinary HTTP manual contract does not offer unsupported voice UDP selection',async()=>{const f=fixture();f.state.strategyLab.pools[0].protocol='udp';f.c.renderStrategyLab();assert.match(f.$('#strategyCandidates').innerHTML,/data-strategy-manual="candidate-1" disabled/);assert.match(f.$('#strategyCandidates').innerHTML,/Ручной выбор для этого протокола пока недоступен/);await f.c.updateStrategyMemory(manualButton(),false,true);assert.equal(f.calls.length,0);assert.match(f.details.at(-1).value.error,/для этого протокола пока недоступен/);});
await check('actual source control Stop and busy refusals refresh read-only state without fallback or replay',async()=>{for(const [status,code] of [[503,'MANAGED_NFQWS_SOURCE_UNAVAILABLE'],[409,'MANAGED_NFQWS_MANUAL_SELECTION_REFUSED'],[503,'SELF_UPDATE_RECOVERY_REQUIRED'],[409,'RESTORE_OPERATION_BUSY']]){const f=fixture(),saved={...f.state.strategyLab,selections:[]};f.setHandler(async(_,opts)=>{if(opts.method==='POST')throw Object.assign(new Error('Сохранение отклонено'),{status,payload:{code,error:'Сохранение отклонено'}});return saved;});await f.c.updateStrategyMemory(manualButton(),false,true);assert.equal(f.calls.length,2);assert.equal(f.calls.filter(item=>item.method==='POST').length,1);assert.deepEqual(f.calls[1],{path:'/api/v1/strategy-lab',cache:'no-store'});assert.equal(f.state.strategyLab,saved);assert.equal(f.details.at(-1).title,'Ручной выбор не подтверждён');assert.equal(f.details.at(-1).value.response.code,code);assert.equal(f.state.strategySelectionAction,null);}});
await check('authentication or permission refusal is not replayed or followed by another unauthorized read',async()=>{for(const status of [401,403]){const f=fixture();f.setHandler(async()=>{throw Object.assign(new Error('Нет доступа'),{status});});await f.c.updateStrategyMemory(manualButton(),false,true);assert.equal(f.calls.length,1);assert.equal(f.details.at(-1).title,'Ручной выбор не подтверждён');assert.equal(f.state.strategySelectionAction,null);}});
await check('failed refusal readback preserves the original server reason and last snapshot',async()=>{const f=fixture(),before=f.state.strategyLab;f.setHandler(async(_,opts)=>{if(opts.method==='POST')throw Object.assign(new Error('Сохранение отклонено'),{status:409,payload:{code:'MANAGED_NFQWS_MANUAL_SELECTION_REFUSED'}});throw new Error('Чтение недоступно');});await f.c.updateStrategyMemory(manualButton(),false,true);assert.equal(f.calls.length,2);assert.equal(f.state.strategyLab,before);assert.equal(f.details.at(-1).value.response.code,'MANAGED_NFQWS_MANUAL_SELECTION_REFUSED');assert.equal(f.details.at(-1).value.error,'Сохранение отклонено');});
await check('successful manual POST cannot replace missing or failed canonical readback',async()=>{for(const missing of [false,true]){const f=fixture();f.setHandler(async(_,opts)=>{if(opts.method==='POST')return savedManual();if(missing)return {...f.state.strategyLab,selections:[]};throw new Error('Чтение недоступно');});await f.c.updateStrategyMemory(manualButton(),false,true);assert.equal(f.calls.length,2);assert.equal(f.details.at(-1).title,'Ручной выбор не подтверждён');assert.doesNotMatch(f.$('#strategyMemory').innerHTML,/ВЫБРАНО ВРУЧНУЮ|strategy-memory-card healthy/);}});
await check('manual single flight blocks a second click during the POST and releases after readback',async()=>{const f=fixture();let release;const pending=new Promise(resolve=>{release=resolve;});const saved={...f.state.strategyLab,selections:[savedManual()]};f.setHandler(async(_,opts)=>opts.method==='POST'?pending:saved);const first=f.c.updateStrategyMemory(manualButton(),false,true);assert.equal(f.calls.length,1);assert.match(f.$('#strategyCandidates').innerHTML,/data-strategy-manual="candidate-1" disabled/);assert.equal(f.$('#strategyTarget').disabled,true);await f.c.updateStrategyMemory(manualButton(),false,true);assert.equal(f.calls.length,1);release(savedManual());await first;assert.equal(f.calls.length,2);assert.equal(f.$('#strategyTarget').disabled,false);assert.equal(f.state.strategySelectionAction,null);});
await check('manual POST deadline aborts without replay and releases the form after a read-only refresh',async()=>{const f=fixture();let expire,cleared=false;f.c.setTimeout=(callback,delay)=>{assert.equal(delay,20000);expire=callback;return 1;};f.c.clearTimeout=()=>{cleared=true;};f.setHandler(async(_,opts)=>opts.method==='POST'?new Promise((_,reject)=>opts.signal.addEventListener('abort',()=>reject(Object.assign(new Error('aborted'),{name:'AbortError'})),{once:true})):f.state.strategyLab);const pending=f.c.updateStrategyMemory(manualButton(),false,true);expire();await pending;assert.equal(f.calls.length,2);assert.equal(f.calls.filter(item=>item.method==='POST').length,1);assert.equal(f.calls[0].signal.aborted,true);assert.equal(f.state.strategySelectionAction,null);assert.equal(f.$('#strategyTarget').disabled,false);assert.equal(cleared,true);assert.equal(f.details.at(-1).title,'Ручной выбор не подтверждён');assert.match(f.details.at(-1).value.error,/Ответ на сохранение задержался/);});
await check('manual completion after authentication changes cannot publish a saved choice',async()=>{for(const changeDuringRead of [false,true]){const f=fixture(),before=f.state.strategyLab;f.setHandler(async(_,opts)=>{if(opts.method==='POST'){if(!changeDuringRead)f.state.authGeneration++;return savedManual();}f.state.authGeneration++;return {...before,selections:[savedManual()]};});await f.c.updateStrategyMemory(manualButton(),false,true);assert.equal(f.calls.length,changeDuringRead?2:1);assert.equal(f.state.strategyLab,before);assert.equal(f.details.length,0);assert.equal(f.state.strategySelectionAction,null);}});
await check('late manual readback after leaving the laboratory does not reopen details in another view',async()=>{const f=fixture(),saved={...f.state.strategyLab,selections:[savedManual()]};f.setHandler(async(_,opts)=>{if(opts.method==='POST')return savedManual();f.state.currentView='engines';return saved;});await f.c.updateStrategyMemory(manualButton(),false,true);assert.equal(f.calls.length,2);assert.equal(f.state.strategyLab,saved);assert.equal(f.details.length,0);assert.equal(f.state.strategySelectionAction,null);});
await check('manual tuple follows the chosen protocol and IP family without inheriting TCP IPv4',async()=>{const f=fixture();f.state.strategyLab.pools[0].protocol='quic';f.$('#strategyFamily').value='ipv6';const saved={...f.state.strategyLab,selections:[savedManual({protocol:'quic',ip_family:'ipv6'})]};f.setHandler(async(_,opts)=>opts.method==='POST'?savedManual():saved);await f.c.updateStrategyMemory(manualButton(),false,true);assert.deepEqual(JSON.parse(f.calls[0].body),{mode:'manual',service_id:'youtube',protocol:'quic',ip_family:'ipv6',candidate_id:'candidate-1'});assert.equal(f.details.at(-1).title,'Ручной выбор сохранён');});
await check('existing evidence selection and reset retain their original separate request contracts',async()=>{for(const reset of [false,true]){const f=fixture();await f.c.updateStrategyMemory({dataset:{strategySelect:'candidate-1',service:'youtube',protocol:'tcp',family:'ipv4'}},reset);assert.equal(f.calls.length,2);assert.deepEqual(JSON.parse(f.calls[0].body),{action:reset?'reset':'select',service_id:'youtube',protocol:'tcp',ip_family:'ipv4',candidate_id:'candidate-1',frozen:false});assert.equal(f.calls[1].path,'/api/v1/strategy-lab');assert.equal(f.details.length,0);}});
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
await check('compatibility validation stays single-flight through POST and canonical readback', async () => {
  const f = fixture(), post = deferred(), readback = deferred();
  f.setHandler(async (_, options) => options.method === 'POST' ? post.promise : readback.promise);
  const pending = f.c.validateStrategyCandidate('candidate-1');
  assert.equal(f.calls.length, 1);
  assert.match(f.$('#strategyCandidates').innerHTML, /data-strategy-validate="candidate-1" disabled aria-busy="true">Проверка совместимости…/);
  assert.match(f.$('#strategyCandidates').innerHTML, /role="status">Проверяем NFQWS2 и Lua/);
  f.c.renderStrategyLab(); // Ordinary panel refresh must preserve pending UI.
  await f.c.validateStrategyCandidate('candidate-2');
  assert.equal(f.calls.length, 1);
  post.resolve({ validation: full });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.calls.length, 2);
  assert.match(f.$('#strategyCandidates').innerHTML, /aria-busy="true">Чтение результата…/);
  assert.match(f.$('#strategyCandidates').innerHTML, /Получаем сохранённый результат/);
  await f.c.validateStrategyCandidate('candidate-1');
  assert.equal(f.calls.length, 2);
  readback.resolve(f.state.strategyLab);
  await pending;
  assert.equal(f.state.strategyValidationAction, null);
  assert.doesNotMatch(f.$('#strategyCandidates').innerHTML, /aria-busy|role="status"/);
  assert.match(f.$('#strategyCandidates').innerHTML, /data-strategy-validate="candidate-1">Проверить совместимость/);
});
await check('compatibility delivery deadline aborts once, stays unconfirmed and releases pending UI', async () => {
  const f = fixture();
  let expire, cleared = false;
  f.c.setTimeout = (callback, delay) => { assert.equal(delay, 65000); expire = callback; return 1; };
  f.c.clearTimeout = () => { cleared = true; };
  f.setHandler(async (_, options) => new Promise((_, reject) => options.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true })));
  const pending = f.c.validateStrategyCandidate('candidate-1');
  expire();
  await pending;
  assert.equal(f.calls.length, 1); // No mutation replay or optimistic readback.
  assert.equal(f.calls[0].signal.aborted, true);
  assert.equal(f.state.strategyValidationAction, null);
  assert.equal(cleared, true);
  assert.match(f.details.at(-1).value.error, /Результат не подтверждён/);
  assert.match(f.details.at(-1).title, /не подтверждена/);
  assert.doesNotMatch(f.$('#strategyCandidates').innerHTML, /aria-busy/);
});
await check('compatibility server refusals release buttons without retry or unauthorized readback', async () => {
  for (const status of [401, 403, 409, 503]) {
    const f = fixture();
    f.setHandler(async () => { throw Object.assign(new Error('Проверка отклонена'), { status, payload: { code: 'ORIGINAL_REFUSAL' } }); });
    await f.c.validateStrategyCandidate('candidate-1');
    assert.equal(f.calls.length, 1);
    assert.equal(f.state.strategyValidationAction, null);
    assert.equal(f.details.at(-1).value.response.code, 'ORIGINAL_REFUSAL');
    assert.doesNotMatch(f.$('#strategyCandidates').innerHTML, /aria-busy/);
  }
});
await check('late compatibility completion cannot publish across authentication or navigation', async () => {
  for (const duringRead of [false, true]) {
    const f = fixture(), before = f.state.strategyLab;
    f.setHandler(async (_, options) => {
      if (options.method === 'POST') { if (!duringRead) f.state.authGeneration++; return {}; }
      f.state.authGeneration++;
      return { candidates: [] };
    });
    await f.c.validateStrategyCandidate('candidate-1');
    assert.equal(f.calls.length, duringRead ? 2 : 1);
    assert.equal(f.state.strategyLab, before);
    assert.equal(f.details.length, 0);
    assert.equal(f.state.strategyValidationAction, null);
  }
  const f = fixture();
  f.setHandler(async (_, options) => { if (options.method === 'POST') return {}; f.state.currentView = 'engines'; return f.state.strategyLab; });
  await f.c.validateStrategyCandidate('candidate-1');
  assert.equal(f.details.length, 0);
  assert.equal(f.state.strategyValidationAction, null);
});
await check('an old compatibility action cannot clear a newer authenticated action', async () => {
  const f = fixture(), oldPost = deferred(), newPost = deferred();
  let posts = 0;
  f.setHandler(async (_, options) => options.method === 'POST' ? (++posts === 1 ? oldPost.promise : newPost.promise) : f.state.strategyLab);
  const old = f.c.validateStrategyCandidate('candidate-1');
  f.state.authGeneration++;
  const next = f.c.validateStrategyCandidate('candidate-1'), newAction = f.state.strategyValidationAction;
  oldPost.resolve({});
  await old;
  assert.equal(f.state.strategyValidationAction, newAction);
  assert.equal(f.calls.length, 2);
  assert.equal(f.details.length, 0);
  newPost.resolve({});
  await next;
  assert.equal(f.calls.length, 3);
  assert.equal(f.state.strategyValidationAction, null);
});
console.log(JSON.stringify({suite:'strategy-compatibility-ui',mode:'production-functions-no-native',passed}));
