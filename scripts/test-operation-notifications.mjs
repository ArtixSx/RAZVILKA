import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const read=file=>readFileSync(new URL('../'+file,import.meta.url),'utf8');
const app=read('cmd/razvilka/web/app.js');
const moduleJS=read('cmd/razvilka/web/operation-notifications.js');
const extract=name=>{const match=app.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));assert(match,name);return match[0];};
class Element {
  constructor(tag){this.tagName=tag;this.children=[];this.listeners={};this.attributes={};this.hidden=false;this.textContent='';}
  set innerHTML(value){throw new Error('notifications must use textContent, never HTML');}
  setAttribute(name,value){this.attributes[name]=value;}
  append(...children){for(const child of children){child.parent=this;this.children.push(child);}}
  appendChild(child){this.append(child);}
  replaceChildren(...children){this.children=[];this.append(...children);}
  remove(){if(this.parent)this.parent.children=this.parent.children.filter(child=>child!==this);}
  contains(child){return this===child||this.children.some(row=>row.contains(child));}
  addEventListener(name,fn){this.listeners[name]=fn;}
  emit(name,event={}){this.listeners[name]?.(event);}
}
function fixture(){
  const body=new Element('body'),timers=new Map(),listeners=new Map(),elements=new Map(),details=[];
  let nextTimer=0;
  const $=selector=>{if(!elements.has(selector))elements.set(selector,new Element('div'));return elements.get(selector);};
  const state={authenticated:true,authGeneration:1};
  const ctx=vm.createContext({state,$,console,root:{},
    document:{body,createElement:tag=>new Element(tag),addEventListener:(name,fn)=>listeners.set(name,fn)},
    setTimeout:(fn,delay)=>{const id=++nextTimer;timers.set(id,{fn,delay});return id;},clearTimeout:id=>timers.delete(id),
    showDetails:(...args)=>details.push(args),
  });
  vm.runInContext(moduleJS+'\n'+extract('showNotice')+extract('hideNotice'),ctx);
  const runtime=()=>vm.runInContext('operationNotifications',ctx);
  return {ctx,state,$,body,timers,listeners,details,runtime,
    expire(){const callbacks=[...timers.values()];timers.clear();for(const timer of callbacks)timer.fn();}};
}
const more=item=>item.element.children[1].children.find(button=>button.textContent==='Подробнее');
const close=item=>item.element.children[1].children.find(button=>button.textContent==='×');
let count=0;async function test(name,run){await run();count++;console.log('PASS '+name);}

await test('completed success stays compact, escapes text, and opens existing details only by click',()=>{
  const f=fixture(),payload={message:'Установка проверена',private:'not in notification copy'};
  assert.equal(f.ctx.notifyOperationSuccess('NFQWS2: установка проверена','<img onerror=attack()> Маршруты не менялись.',payload),true);
  const item=f.runtime().items[0],copy=item.element.children[0];
  assert.equal(copy.attributes.role,'status');assert.equal(copy.attributes['aria-atomic'],'true');
  assert.equal(copy.children[1].textContent,'<img onerror=attack()> Маршруты не менялись.');
  assert.equal(f.details.length,0);assert.equal(f.timers.size,1);assert.equal([...f.timers.values()][0].delay,6500);
  assert.match(close(item).attributes['aria-label'],/Закрыть уведомление: NFQWS2/);
  more(item).emit('click');assert.equal(f.details.length,1);assert.equal(f.details[0][0],payload);
  assert.equal(f.runtime().items.length,0);assert.equal(f.timers.size,0);
  assert.equal(f.runtime().history.length,1,'details must remain available after closing the transient toast');
});

await test('success expires, closes explicitly and pauses while keyboard focus or hover uses its actions',()=>{
  const f=fixture();f.ctx.notifyOperationSuccess('Сохранено','Черновик сохранён',{});
  let item=f.runtime().items[0];item.element.emit('focusin');f.expire();assert.equal(f.runtime().items.length,1);
  item.element.emit('focusout',{relatedTarget:more(item)});assert.equal(f.timers.size,0);
  item.element.emit('focusout',{relatedTarget:null});assert.equal(f.timers.size,1);
  item.element.emit('mouseenter');f.expire();assert.equal(f.runtime().items.length,1);
  item.element.emit('mouseleave');f.expire();assert.equal(f.runtime().items.length,0);
  assert.equal(f.runtime().history[0].title,'Сохранено');
  f.runtime().historyButton.emit('click');assert.equal(f.runtime().historyPanel.hidden,false);
  f.runtime().historyPanel.children[0].emit('click');assert.equal(f.details.length,1,'expired toast lost its details action');
  f.ctx.notifyOperationSuccess('Удалено','Удаление подтверждено');item=f.runtime().items[0];
  assert.equal(more(item),undefined);close(item).emit('click');assert.equal(f.runtime().items.length,0);assert.equal(f.timers.size,0);
});

await test('bounded queue and auth invalidation release payloads and fence old details buttons',()=>{
  const f=fixture();f.ctx.notifyOperationSuccess('0','0',{});const oldest=f.runtime().items[0],oldButton=more(oldest);
  for(let i=1;i<5;i++)f.ctx.notifyOperationSuccess(String(i),String(i),{});
  assert.equal(f.runtime().items.length,3);assert.equal(f.timers.size,3);assert.equal(oldest.dismissed,true);
  oldButton.emit('click');assert.equal(f.details.length,0);
  const stale=more(f.runtime().items[0]);f.state.authGeneration++;stale.emit('click');assert.equal(f.details.length,0);
  f.state.authenticated=false;f.listeners.get('razvilka:auth-required')();
  assert.equal(f.runtime().items.length,0);assert.equal(f.timers.size,0);stale.emit('click');assert.equal(f.details.length,0);
  assert.equal(f.runtime().history.length,0);assert.equal(f.runtime().historyButton.hidden,true);
  assert.equal(f.ctx.notifyOperationSuccess('Поздний ответ','Не показывать',{}),false);
});

await test('autoclosed details history is bounded and discarded history buttons cannot revive old payloads',()=>{
  const f=fixture();f.ctx.notifyOperationSuccess('Первый','Готово',{first:true});
  const first=f.runtime().historyPanel.children[0];
  for(let i=0;i<9;i++)f.ctx.notifyOperationSuccess('Следующий '+i,'Готово',{i});
  assert.equal(f.runtime().history.length,6);assert.equal(f.runtime().historyPanel.children.length,6);
  first.emit('click');assert.equal(f.details.length,0);
  f.expire();assert.equal(f.runtime().items.length,0);assert.equal(f.runtime().historyButton.hidden,false);
  f.runtime().historyPanel.children[0].emit('click');assert.equal(f.details[0][0].i,8);
});

await test('errors, unknown outcomes and recovery remain persistent beside expiring successes',()=>{
  for(const kind of ['error','review']){
    const f=fixture();f.ctx.showNotice(kind,'Результат не подтверждён','Прочитайте журнал.',{error:'unknown'});
    assert.equal(f.state.noticeTransient,false);assert.equal(f.timers.size,0);
    f.ctx.notifyOperationSuccess('Другая операция завершена','Готово');f.expire();
    assert.equal(f.$('#notice').hidden,false);assert.equal(f.$('#noticeTitle').textContent,'Результат не подтверждён');
  }
});

await test('standalone confirmed draft save notifies, internal staging and uncertain saves do not',async()=>{
  for(const kind of ['saved','internal','unknown']){
    const notices=[],details=[],message={textContent:''},intent={engineID:'nfqws2',fileID:'main',mode:'guided',controller:new AbortController(),body:{}};
    const state={engineConfigs:[{id:'nfqws2',name:'NFQWS2'}]};
    const ctx=vm.createContext({state,$:()=>message,beginEngineIntent:()=>intent,engineIntentCurrent:()=>true,finishEngineIntent(){},refreshEngineConfigs:async()=>true,
      api:async()=>({engine_id:'nfqws2',file_id:'main',source:kind==='unknown'?'unconfirmed':'staged'}),
      notifyOperationSuccess:(...args)=>notices.push(args),showDetails:(...args)=>details.push(args)});
    vm.runInContext(extract('saveEngineDraft'),ctx);await ctx.saveEngineDraft(kind==='internal'?intent:null);
    assert.equal(notices.length,kind==='saved'?1:0);assert.equal(details.length,kind==='unknown'?1:0);
    if(kind==='saved'){assert.equal(notices[0][0],'NFQWS2: черновик сохранён');assert.match(notices[0][1],/Рабочие настройки пока прежние/);}
  }
});

await test('autonomy success still expires, errors stay visible and its close control has a separate right column',()=>{
  const source=read('cmd/razvilka/web/console-autonomy.js');
  const noticeCode=source.slice(source.indexOf('  let noticeTimer='),source.indexOf('  function formatDate('));
  assert(noticeCode.includes('function notify('));
  const f=fixture();vm.runInContext(noticeCode,f.ctx);
  f.ctx.notify('Автоматика разрешена');assert.equal(f.timers.size,1);f.expire();assert.equal(f.$('notice').hidden,true);
  f.ctx.notify('Ошибка, нужно проверить журнал',true);assert.equal(f.timers.size,0);assert.equal(f.$('notice').hidden,false);
  const css=read('cmd/razvilka/web/interface.css');
  assert.match(css,/#a1-notice:not\(\[hidden\]\)\{[^}]*grid-template-columns:minmax\(0,1fr\) auto/);
  assert.match(css,/#a1-notice>\.notice-close\{[^}]*grid-column:2;grid-row:1;justify-self:end/);
});

const html=read('cmd/razvilka/web/index.html');assert(html.indexOf('/operation-notifications.js?')<html.indexOf('/app.js?'));
assert(read('scripts/check.sh').includes('test-operation-notifications.mjs'));
console.log(`Operation notifications: ${count} modeled checks passed; no native/browser claim`);
