// Simple mode model checks: no DOM, server or network.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const read=name=>readFileSync(new URL('../'+name,import.meta.url),'utf8');
const context={};
vm.runInNewContext(read('cmd/razvilka/web/simple-home.js'),context);
const {model,available,plural}=context.RazvilkaSimpleHome;
const catalog=[{id:'youtube',name:'YouTube',category:'Видео'},{id:'discord',name:'Discord',category:'Мессенджеры'},{id:'roblox',name:'Roblox',category:'Игры'}];
const snap=(runtime,extra={})=>({policy:{setup_complete:true,enabled:true,revision:3},services:Object.fromEntries(Object.keys(runtime).map(id=>[id,{id}])),runtime:Object.fromEntries(Object.entries(runtime).map(([id,state])=>[id,{state,message:'detail '+id}])),...extra});

assert.equal(model(null,catalog).phase,'loading');
assert.equal(model({policy:{setup_complete:false}},catalog).phase,'setup');
assert.equal(model(snap({},{stopped:true}),catalog).phase,'off');
assert.equal(model(snap({}),catalog).phase,'empty');

const ok=model(snap({youtube:'healthy',discord:'applied'}),catalog);
assert.equal(ok.tone,'ok');
assert.equal(ok.title,'Всё работает');
assert.deepEqual(Array.from(ok.services,s=>s.short),['Работает','Работает']);

const busy=model(snap({youtube:'healthy',discord:'pending'}),catalog);
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
assert.equal(model({...snap({youtube:'checking'}),applied_services:{youtube:{enabled:true}}},catalog).title,'Всё работает');

const removing=model({...snap({youtube:'healthy'}),services:{youtube:{id:'youtube'},discord:{id:'discord',removing:true}}},catalog);
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

assert.equal(plural(1,'сервис','сервиса','сервисов'),'1 сервис');
assert.equal(plural(3,'сервис','сервиса','сервисов'),'3 сервиса');
assert.equal(plural(11,'сервис','сервиса','сервисов'),'11 сервисов');
assert.equal(plural(22,'сервис','сервиса','сервисов'),'22 сервиса');

const html=read('cmd/razvilka/web/index.html');
assert.ok(html.indexOf('/simple-home.js?v=')>html.indexOf('/interface.js?v='),'loaded after interface.js');
console.log('simple home: ok');
