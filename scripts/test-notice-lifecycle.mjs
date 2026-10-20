import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const read=name=>fs.readFileSync(new URL(`../cmd/razvilka/web/${name}`,import.meta.url),'utf8');
for(const file of ['console-autonomy.js','autonomy-ui.js']){
 const source=read(file);const start=source.indexOf('  let noticeTimer=');const end=source.indexOf('\n  function ',source.indexOf('  function notify(',start)+20);
 const notice={hidden:true,textContent:'',appendChild(button){this.close=button;}};const timers=new Map();let next=0;
 const context=vm.createContext({root:{},$:()=>notice,document:{createElement:()=>({setAttribute(){},addEventListener(_,fn){this.click=fn;}})},setTimeout:fn=>{timers.set(++next,fn);return next;},clearTimeout:id=>timers.delete(id)});
 vm.runInContext(source.slice(start,end),context);
 context.notify('Настройки сохранены на роутере.');assert.equal(notice.hidden,false);assert.equal(timers.size,1);
 [...timers.values()][0]();assert.equal(notice.hidden,true);
 context.notify('Информация');context.notify('Нужна проверка журнала',true);assert.equal(timers.size,0,'replacement error must cancel old success timer');assert.equal(notice.hidden,false);notice.close.click();assert.equal(notice.hidden,true,'errors remain dismissible');
 context.notify('Сохранено');if(context.root.dismissTransientAutonomyNotice){context.root.dismissTransientAutonomyNotice();assert.equal(notice.hidden,true);context.notify('Ошибка',true);context.root.dismissTransientAutonomyNotice();assert.equal(notice.hidden,false);}
}
const app=read('app.js');const elements=new Map();const timers=new Map();let next=0;const state={};
const ctx=vm.createContext({state,$:id=>{if(!elements.has(id))elements.set(id,{hidden:true});return elements.get(id);},setTimeout:fn=>{timers.set(++next,fn);return next;},clearTimeout:id=>timers.delete(id)});
vm.runInContext(app.slice(app.indexOf('function showNotice('),app.indexOf('function onboardingDone(')),ctx);
ctx.showNotice('success','Готово','Сохранено');assert.equal(timers.size,1);ctx.showNotice('error','Ошибка','Повторите',{},false,{label:'Повторить',run(){}});assert.equal(timers.size,0);assert.ok(state.noticeAction);ctx.hideNotice();assert.equal(elements.get('#notice').hidden,true);assert.equal(state.noticeAction,null);
assert.match(app,/noticeClose'\).addEventListener\('click', hideNotice\)/);
ctx.showNotice('review','Проверить результат','Применение не подтверждено',{error:'timeout'},true);
assert.equal(elements.get('#notice').className,'notice review');
ctx.showNotice('review','Сведения обновляются','Повторим чтение',{detail_kind:'panel-load'});
assert.equal(elements.get('#notice').className,'notice review panel-load');
const css=read('interface-shell.css');assert.match(css,/body\.rz-simple #notice\.review\.panel-load[,\{]/);assert.doesNotMatch(css,/body\.rz-simple #notice\.review[,\{]/,'simple mode must not hide actionable review failures');
console.log('PASS transient notices expire; errors persist with manual dismissal; replacement cancels stale timers');
