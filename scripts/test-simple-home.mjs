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
assert.equal(model({policy:{setup_complete:false}},catalog).phase,'setup');
assert.equal(model(snap({},{stopped:true}),catalog).phase,'off');
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
console.log('simple home: ok');
