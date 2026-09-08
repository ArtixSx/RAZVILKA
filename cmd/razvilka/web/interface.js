/* Interface R3. One API/control plane; no simulated transport in production.
   UI grouping is metadata only. Network actions retain server-side consent/CAS. */
'use strict';
const interfaceState = { query:'', filter:'selected', layout:'list', category:'', expanded:new Set(), inspector:null, returnFocus:null, busy:false, authEpoch:0, toastTimer:null };
const rim = window.RazvilkaInterfaceModel;
const interfaceHTMLCache = new WeakMap();
const interfaceRequests = new Set();
const interfaceSections = {
  overview: { title:'Ваша сеть', children:[['overview','Обзор'],['autopilot','Автопилот']] },
  services: { title:'Сервисы', children:[['services','Мои сервисы'],['managed','Политики и резерв']] },
  nodes: { title:'Подключения', children:[['nodes','Узлы'],['providers','Каталог источников'],['subscription-settings','Подписки'],['connections','Текущие соединения']] },
  engines: { title:'Обходы', children:[['engines','Все обходы'],['engineconfig','Редактор'],['strategylab','Лаборатория NFQWS2'],['dns','DNS / Smart DNS'],['testlab','Проверки']] },
  devices: { title:'Устройства', children:[['devices','Устройства и группы']] },
  activity: { title:'Наблюдение', children:[['activity','События'],['diagnostics','Диагностика']] },
  settings: { title:'Настройки', children:[['settings','Общие'],['onboard','Мастер'],['updates','Обновления'],['sources','Списки доменов']] },
};
Object.assign(viewMeta, { overview:['Обзор','Сервисы, которые важны вам'], engines:['Обходы','Специализированные инструменты, единое управление'], activity:['События','Решения, проверки и изменения'], providers:['Источники подключений','Выбранные каталоги и личные подписки'] });
function interfaceHTML(id, html) {
  const el=document.getElementById(id); if(!el || interfaceHTMLCache.get(el) === html)return;
  const focus=document.activeElement?.closest?.('[data-rz-focus]')?.getAttribute('data-rz-focus');
  el.innerHTML=html; interfaceHTMLCache.set(el,html);
  if(focus){const match=[...el.querySelectorAll('[data-rz-focus]')].find(e=>e.getAttribute('data-rz-focus')===focus);match?.focus({preventScroll:true});}
}
function interfaceServices(){return rim.selectedView(state.services||[],consoleSnapshot?.services||{});}
function interfaceSummaries() {
  const out={};
  for(const service of state.services||[]){
    const h=serviceDashboardSummary(service),managed=consoleSnapshot?.services?.[service.id];
    // Queue receipt is user intent, never an active-route or PASS claim.
    if(managed?.removing){h.kind='warn';h.label='Удаление в очереди';h.detail='Сервер ещё не подтвердил снятие маршрута.';}
    else if(managed && !service.enabled && !serviceDashboardApplied(service).enabled){
      h.kind='unknown';h.label=managed.enabled?'Ожидает настройки':'Автоподбор на паузе';h.detail='Сервис добавлен. Подтверждённого применённого пути пока нет.';
    }
    out[service.id]=h;
  }
  return out;
}
function interfaceRouteName(route) {
  if(!route)return 'Пока не назначен';
  if(route==='direct')return 'Прямое подключение';
  if(route.startsWith('sing-box:')){const id=route.slice(9);const node=(state.nodes?.nodes||[]).find(n=>n.id===id);if(node)return typeof nodeDisplayName==='function'?nodeDisplayName(node):node.name||'Узел Sing-box';}
  return routeLabel(route);
}
function interfaceAutoLabel(){const p=consoleSnapshot?.policy;if(!p)return 'Настройте Автопилот';if(!p.setup_complete)return 'Нужна настройка';if(consoleSnapshot.safe_mode || state.status?.safe_mode)return 'Safe Mode';if(consoleSnapshot.stopped)return 'Маршруты остановлены';if(consoleSnapshot.blocked)return 'Нужно восстановление';if(consoleSnapshot.manual)return 'Ручной режим';return p.enabled?'Автопилот включён':'Автопилот на паузе';}
function interfaceBadge(summary){return `<span class="ui3-status ${esc(summary.kind||'unknown')}"><i></i>${esc(summary.label||'Не проверен')}</span>`;}
function interfaceServiceCard(s,summaries,compact=false){
 const h=summaries[s.id]||{}, managed=consoleSnapshot?.services?.[s.id];
 const auto=managed?managed.enabled?'Автопилот':'Автоподбор на паузе':s.enabled?'Индивидуальная настройка':'Не добавлен';
 const pending=s.dirty===true||s.enabled!==!!serviceDashboardApplied(s).enabled;
 return `<article class="ui3-service-card ${compact?'compact':''} ${s.enabled?'':'not-selected'}" data-rz-card="${esc(s.id)}"><div class="ui3-service-card-top"><span class="ui3-service-icon tone-${esc(rim.category(s)==='ИИ-сервисы'?'violet':s.id==='youtube'?'rose':'teal')}">${consoleServiceIcon(s)}</span><div class="ui3-service-name"><h4>${esc(s.name)}</h4><span>${esc(compact?auto:rim.category(s))}</span></div><button type="button" class="ui3-more" data-rz-inspect="${esc(s.id)}" data-rz-focus="${compact?'child':'card'}-${esc(s.id)}" aria-label="Подробности: ${esc(s.name)}">${ci('chevron')}</button></div><div class="ui3-card-state">${interfaceBadge(h)}${pending?`<span class="ui3-pending-dot" title="Есть неприменённые изменения">${managed&&!s.dirty?'В очереди':'Черновик'}</span>`:''}</div><div class="ui3-card-route"><span>Сейчас</span><b title="${esc(interfaceRouteName(h.route))}">${esc(interfaceRouteName(h.route))}</b></div>${compact?'':`<div class="ui3-card-footer"><span>${esc(auto)}</span><button type="button" class="text-button" data-rz-inspect="${esc(s.id)}">${s.enabled?'Управлять':'Добавить'} ${ci('chevron')}</button></div>`}</article>`;
}
function interfaceGroupHTML(g,summaries,location){
 const a=g.summary,key=location+':'+g.name,open=interfaceState.expanded.has(key)||!!interfaceState.query;
 const route=a.routes.length>1?'Разные маршруты':a.route?interfaceRouteName(a.route):'Маршруты ещё не назначены';
 const label=a.selected?`Доступны: ${a.good}${a.pending?' · Проверяются: '+a.pending:''}${a.failed?' · Нужна проверка: '+a.failed:''}`:'Выберите нужные сервисы внутри';
 return `<details class="ui3-service-group" data-rz-group="${esc(key)}" ${open?'open':''}><summary data-rz-focus="group-${esc(key)}"><span class="ui3-service-icon tone-violet">${ci('sparkles')}</span><span class="ui3-group-heading"><strong>${esc(g.name)}</strong><small>${a.selected} из ${a.total} выбрано · ${esc(route)}</small><small class="ui3-group-health ${esc(a.kind)}">${esc(label)}</small></span><span class="ui3-group-avatars">${g.allMembers.slice(0,3).map(s=>`<span>${consoleServiceIcon(s)}</span>`).join('')}</span><span class="ui3-group-chevron">${ci('chevron')}</span></summary><div class="ui3-group-status"><span class="ui3-status ${esc(a.kind)}"><i></i>${esc(label)}</span><small>Проверка и маршрут — отдельно для каждого</small></div><div class="ui3-group-content"><div class="ui3-group-member-grid">${g.members.map(s=>interfaceServiceCard(s,summaries,true)).join('')}</div><p class="ui3-group-note">Группировка не меняет сеть. Добавляйте и настраивайте участников по отдельности.</p></div></details>`;
}
function interfaceCards(services,summaries,where){return rim.groupServices(services,interfaceServices(),summaries).map(g=>g.grouped?interfaceGroupHTML(g,summaries,where):g.members.map(s=>interfaceServiceCard(s,summaries)).join('')).join('');}
function interfaceEmpty(title,body,action=''){return `<div class="ui3-empty">${ci('grid')}<h3>${esc(title)}</h3><p>${esc(body)}</p>${action}</div>`;}
function renderInterfaceNavigation(view=state.currentView||'overview'){
 const key=Object.keys(interfaceSections).find(k=>interfaceSections[k].children.some(([v])=>v===view))||'overview',group=interfaceSections[key];
 $$('[data-main-nav]').forEach(e=>{const on=e.dataset.mainNav===key;e.classList.toggle('active',on);on?e.setAttribute('aria-current','page'):e.removeAttribute('aria-current');});
 $$('[data-mobile-nav]').forEach(e=>{const on=e.dataset.mobileNav===key;e.classList.toggle('active',on);on?e.setAttribute('aria-current','page'):e.removeAttribute('aria-current');});
 consoleText('ui3Breadcrumb',group.title);
 const sub=$('#interfaceSubnav');sub.hidden=group.children.length<2;
 interfaceHTML('interfaceSubnav',group.children.map(([v,title])=>`<button type="button" data-rz-nav="${esc(v)}" ${v===view?'aria-current="page" class="active"':''}>${esc(title)}</button>`).join(''));
}
function renderInterfaceHome(summaries){
 const selected=interfaceServices().filter(s=>s.enabled),a=rim.aggregate(selected,summaries);consoleText('ui3HomeCount',String(a.selected));consoleText('ui3NavCount',String(a.selected));
 const ready=!!state.status?.version,waiting=a.pending+a.failed;
 const title=!ready?'Читаем состояние роутера':!a.selected?'Подключите первый сервис':waiting?'Некоторым сервисам нужна проверка':'Выбранные сервисы доступны';
 const desc=!ready?'Пока нет данных — мы не считаем сеть исправной по умолчанию.':!a.selected?'Добавьте сайт или приложение. Общие разрешения задаются в мастере.':`${a.good} из ${a.selected} имеют актуальное подтверждение. ${a.pending?`${a.pending} ещё не подтверждены. `:''}${a.failed?`${a.failed} не прошли проверку. `:''}Результат относится к проверенному сценарию.`;
 interfaceHTML('ui3HealthBanner',`<span class="ui3-health-icon ${a.kind}">${ci(!ready?'clock':waiting?'activity':a.selected?'shield':'plus')}</span><div><strong>${esc(title)}</strong><p>${esc(desc)}</p></div><button type="button" class="secondary" data-console-navigate="${consoleSnapshot?.policy?.setup_complete?'autopilot':'onboard'}">${consoleSnapshot?.policy?.setup_complete?'Посмотреть автоматику':'Пройти настройку'} ${ci('chevron')}</button>`);
 interfaceHTML('ui3HomeServices',selected.length?interfaceCards(selected,summaries,'home'):interfaceEmpty('Начните со своих сервисов','Не нужно выбирать движок или сервер на первом экране.',`<button type="button" class="primary" data-console-add>Добавить сервис</button>`));
 const attention=selected.filter(s=>summaries[s.id]?.kind!=='good').slice(0,3);
 interfaceHTML('ui3Attention',`<div class="ui3-section-heading"><h3>${waiting?'Нужно внимание':'Всё под наблюдением'}</h3>${ci(waiting?'activity':'check')}</div>${attention.length?attention.map(s=>`<button type="button" class="ui3-attention-item" data-rz-inspect="${esc(s.id)}"><span class="ui3-alert-dot ${esc(summaries[s.id]?.kind)}"></span><span><b>${esc(s.name)}</b><small>${esc(summaries[s.id]?.label||'Не проверен')}</small></span>${ci('chevron')}</button>`).join(''):`<p>${a.selected?'Новых проблем в актуальных сервисных проверках нет.':'Здесь появятся проблемы выбранных сервисов.'}</p>`}`);
 consoleText('ui3RouterName',state.system?.hostname||'Роутер');consoleText('ui3RouterMeta',[state.system?.architecture,state.system?.wan_interface].filter(Boolean).join(' · ')||'Нет сведений о платформе');
 const m=state.metrics?.latest||{},cpu=m.cpu_ready===false?null:rim.finitePercent(m.cpu_percent),ram=rim.finitePercent(m.memory_used_percent);
 interfaceHTML('ui3Resources',[[cpu,'Процессор'],[ram,'Память']].map(([n,label])=>`<div class="ui3-resource"><div><span>${label}</span><b>${n===null?'Нет данных':Math.round(n)+'%'}</b></div><div class="ui3-meter" role="img" aria-label="${label}: ${n===null?'нет данных':Math.round(n)+'%'}"><i style="width:${n===null?0:n}%"></i></div></div>`).join('')+`<div class="ui3-router-temperature"><span>Температура</span><b>${typeof m.temperature_c==='number'&&Number.isFinite(m.temperature_c)?Math.round(m.temperature_c)+' °C':'Нет данных'}</b></div>`);
 const p=consoleSnapshot?.policy,app=p?.application;
 interfaceHTML('ui3Maintenance',`<span class="ui3-maintenance-icon">${ci('clock')}</span><h3>Ночное обслуживание</h3><p>${app&&app.mode!=='off'?`Приложение: ${esc(app.start)}–${esc(app.end)}<br>${esc(p.timezone)}`:'Расписание ещё не включено'}</p><span class="ui3-maintenance-note">${app?.mode==='prepare'?'Проверка и подготовка архива.':'Проверка наличия обновлений.'} Автоматическая установка пока недоступна.</span><button type="button" class="text-button" data-console-navigate="updates">Управлять расписанием ${ci('chevron')}</button>`);
 const events=(state.audit?.events||[]).slice(0,4);
 interfaceHTML('ui3HomeEvents',events.length?events.map(e=>`<div class="ui3-event"><span class="ui3-event-icon">${ci(e.outcome==='ok'?'check':'activity')}</span><div><strong>${esc(consoleAuditTitle(e))}</strong><small>${esc(e.path||'Локальная операция')}</small></div><time>${esc(consoleDate(e.timestamp))}</time></div>`).join(''):interfaceEmpty('Здесь будет история','Решения и изменения появятся после первой операции.'));
}
function renderInterfaceServices(summaries){
 $('#ui3ServiceCatalog').classList.toggle('ui3-list-layout',interfaceState.layout==='list');
 $$('[data-rz-layout]').forEach(e=>{const on=e.dataset.rzLayout===interfaceState.layout;e.classList.toggle('active',on);e.setAttribute('aria-pressed',String(on));});
 const all=interfaceServices(),cats=[...new Set(all.map(rim.category))].sort((a,b)=>a.localeCompare(b,'ru'));
 interfaceHTML('ui3CategoryFilters',[['','Все категории'],...cats.map(c=>[c,c])].map(([v,t])=>`<button type="button" class="${v===interfaceState.category?'active':''}" aria-pressed="${v===interfaceState.category}" data-rz-category="${esc(v)}" data-rz-focus="category-${esc(v)}">${esc(t)}</button>`).join(''));
 const list=rim.filterServices(all,{query:interfaceState.query,scope:interfaceState.filter,category:interfaceState.category},summaries);
 consoleText('ui3CatalogSummary',`${list.length} ${list.length===1?'сервис':'сервисов'} показано · ${all.filter(s=>s.enabled).length} выбрано в сети`);
 interfaceHTML('ui3ServiceCatalog',list.length?interfaceCards(list,summaries,'catalog'):interfaceEmpty('Ничего не найдено','Измените фильтры или добавьте свой сайт.'));
 $$('[data-rz-filter]').forEach(e=>{const on=e.dataset.rzFilter===interfaceState.filter;e.classList.toggle('active',on);e.setAttribute('aria-pressed',String(on));});
}
function renderInterfaceEngines(){
 interfaceHTML('ui3EngineGrid',Object.entries(consoleEngineMeta).map(([id,m])=>{const e=consoleEngineState(id),used=(state.services||[]).filter(s=>{const a=serviceDashboardApplied(s);return a.enabled&&(a.route===id||a.route?.startsWith(id+':'));});return `<article class="ui3-engine-card"><div class="ui3-engine-card-heading"><span class="engine-mini-icon ${m.tone}">${ci(m.icon)}</span><span class="ui3-status ${e.running?'good':'unknown'}"><i></i>${e.running?'Процесс запущен':e.installed?'Установлен':'Не установлен'}</span></div><h3>${esc(m.name)}</h3><span class="ui3-engine-subtitle">${esc(m.subtitle)}</span><p>${esc(m.description)}</p><div class="ui3-engine-meta"><span>${esc(e.version)}</span><b>${used.length} сервисов</b></div><button type="button" class="secondary" data-console-engine="${esc(id)}">${e.installed?'Открыть настройки':'Настроить компонент'} ${ci('chevron')}</button></article>`;}).join(''));
 const id=state.selectedEngine,e=consoleEngineState(id);
 interfaceHTML('ui3EngineContext',Object.entries(consoleEngineMeta).map(([k,m])=>`<button type="button" class="${k===id?'active':''}" data-console-engine="${esc(k)}" ${k===id?'aria-current="page"':''}>${ci(m.icon)}${esc(m.name)}</button>`).join(''));
 const used=state.services.filter(s=>{const a=serviceDashboardApplied(s);return a.enabled&&(a.route===id||a.route?.startsWith(id+':'));});
 const good=used.filter(s=>serviceDashboardSummary(s).kind==='good').length;
 interfaceHTML('ui3EngineSteps',[[e.installed,'Установка',e.installed?'Бинарник обнаружен':'Не подтверждена'],[e.running,'Процесс',e.running?'Запущен':'Не запущен'],[used.length>0,'Маршруты',`${used.length} сервисов`],[good>0,'Проверка',`${good} из ${used.length} подтверждены`]].map(([ok,title,detail])=>`<div class="${ok?'confirmed':''}"><span>${ci(ok?'check':'clock')}</span><section><b>${title}</b><small>${esc(detail)}</small></section></div>`).join(''));
}
function renderInterface(){
 renderInterfaceNavigation();const summary=interfaceSummaries();
 renderInterfaceHome(summary);renderInterfaceServices(summary);renderInterfaceEngines();
 consoleText('ui3SidebarAuto',interfaceAutoLabel());consoleText('ui3TopAuto',interfaceAutoLabel());
}
function interfaceOpenService(id){
 const s=state.services.find(x=>x.id===id);if(!s)return;
 const h=interfaceSummaries()[id],a=serviceDashboardApplied(s),managed=consoleSnapshot?.services?.[id],r=consoleSnapshot?.runtime?.[id],scopes=(a.sources||s.applied_sources||[]);
 interfaceState.inspector=id;if(!$('#ui3ServiceDialog').open)interfaceState.returnFocus=document.activeElement;
 const authAvailable=!!consoleSnapshot?.policy?.setup_complete;
 interfaceHTML('ui3InspectorContent',`<div class="ui3-inspector-title"><span class="ui3-service-icon tone-${rim.category(s)==='ИИ-сервисы'?'violet':'teal'}">${consoleServiceIcon(s)}</span><div><h2 id="ui3InspectorTitle" tabindex="-1">${esc(s.name)}</h2><p>${esc(rim.category(s))}</p></div></div>${interfaceBadge(h)}<p class="ui3-inspector-description">${esc(h.detail)}</p><div class="ui3-route-passport"><span class="ui3-eyebrow">ПРИМЕНЁННЫЙ МАРШРУТ</span><strong>${esc(interfaceRouteName(h.route))}</strong><small>${esc(a.enabled?scopes.length?scopes.join(', '):'Область устройств — см. действующий план':'Трафик ещё не назначен')}</small></div><dl class="ui3-inspector-facts"><dt>Управление</dt><dd>${managed?managed.enabled?'Автопилот':'Автоподбор приостановлен':'Индивидуальные настройки'}</dd><dt>Состояние задачи</dt><dd>${esc(r?.message||'Нет сообщения об операции')}</dd><dt>Резерв</dt><dd>${r?.reserves?.length||0} профилей; нужна свежая проверка перед применением</dd><dt>Последнее наблюдение</dt><dd>${esc(consoleDate(s.observed_state?.checked_at))}</dd></dl><details class="ui3-domain-details"><summary>Состав сервиса · ${(s.domains||[]).length} доменов</summary><div>${(s.domains||[]).map(d=>`<code>${esc(d)}</code>`).join('')||'<span>Доменные данные не заданы</span>'}</div></details><div class="ui3-inspector-actions"><button type="button" class="primary" data-rz-action="check">${ci('activity')} Проверить сервис</button><button type="button" class="secondary" data-rz-action="configure">Настроить маршрут ${ci('chevron')}</button>${authAvailable?`<button type="button" class="secondary" data-rz-action="${managed?.enabled?'pause':'manage'}">${ci(managed?.enabled?'pause':'route')}${managed?.enabled?'Приостановить автоподбор':'Передать Автопилоту'}</button>`:`<button type="button" class="secondary" data-rz-action="setup">Настроить Автопилот</button>`}${managed?'<button type="button" class="ui3-danger-text" data-rz-action="remove">Убрать из управляемых сервисов</button>':''}</div><p class="ui3-footnote">Проверка не меняет маршрут. Пауза Автопилота сохраняет действующее подключение. Выключение и удаление проходят серверную очередь.</p>`);
 consoleText('ui3InspectorMessage','');const d=$('#ui3ServiceDialog');if(!d.open)d.showModal();$('#ui3InspectorTitle').focus();
}
function interfaceCloseInspector(){const d=$('#ui3ServiceDialog');if(d.open)d.close();}
async function interfaceRequest(path, options={}){
 const controller=new AbortController();interfaceRequests.add(controller);const timer=setTimeout(()=>controller.abort(),20000);
 try{return await api(path,{...options,signal:controller.signal});}
 catch(e){if(e.status===401)showAuth(state.status,e.message);if(e.name==='AbortError')throw new Error('Ответ не подтверждён. Проверьте состояние операции перед повтором.');throw e;}
 finally{clearTimeout(timer);interfaceRequests.delete(controller);}
}
async function interfaceManage(id,enabled,remove=false){
 const snapshot=consoleSnapshot;if(!snapshot?.policy?.setup_complete)throw new Error('Сначала завершите первоначальную настройку.');
 const old=snapshot.services?.[id],service=state.services.find(s=>s.id===id),revision=snapshot.policy.revision;
 if(remove && !old)throw new Error('Сервис уже не находится под автономным управлением.');
 if(remove){if(!confirm(`Убрать «${service?.name||id}»? Будет поставлена задача на снятие только его маршрута.${service?.custom?' Определение пользовательского сервиса сохранится.':''}`))return;}
 const request=remove?{method:'DELETE',body:{expected_revision:revision,confirm:'REMOVE_SERVICE',delete_definition:false}}:{method:'POST',body:{service_id:id,enabled,use_defaults:!old,all_lan:old?.all_lan||false,sources:old?.sources||[],expected_revision:revision,confirm:'MANAGE_SERVICE'}};
 const epoch=interfaceState.authEpoch;
 await interfaceRequest(remove?`/api/v1/autonomy/services/${encodeURIComponent(id)}`:'/api/v1/autonomy/services',{...request,body:JSON.stringify(request.body)});
 if(epoch!==interfaceState.authEpoch)throw new Error('Сессия изменилась. Войдите снова.');
 const fresh=await interfaceRequest('/api/v1/autonomy');if(epoch!==interfaceState.authEpoch)return;
 window.dispatchEvent(new CustomEvent('razvilka:autonomy-state',{detail:fresh}));await refreshCoreAfterEdit();
 if(epoch!==interfaceState.authEpoch)return;
 if(interfaceState.inspector===id&&$('#ui3ServiceDialog').open){interfaceOpenService(id);consoleText('ui3InspectorMessage',remove?'Удаление поставлено в очередь. Маршрут ещё не считается снятым.':enabled?'Управление разрешено. Дождитесь проверки и применения.':'Автоподбор на паузе. Маршрут сохранён.');}
}
function interfaceToast(text){consoleText('ui3Toast',text);$('#ui3Toast').hidden=false;clearTimeout(interfaceState.toastTimer);interfaceState.toastTimer=setTimeout(()=>$('#ui3Toast').hidden=true,5500);}
document.addEventListener('toggle',e=>{if(!e.target.matches?.('[data-rz-group]'))return;const k=e.target.dataset.rzGroup;if(e.target.open)interfaceState.expanded.add(k);else interfaceState.expanded.delete(k);},true);
document.addEventListener('click',event=>{
 const b=event.target.closest('[data-rz-inspect],[data-rz-nav],[data-rz-category],[data-rz-filter],[data-rz-protocol],[data-rz-close],[data-rz-action],[data-rz-layout]');if(!b)return;
 if(b.hasAttribute('data-rz-layout')){interfaceState.layout=b.dataset.rzLayout==='cards'?'cards':'list';renderInterfaceServices(interfaceSummaries());return;}
 if(b.dataset.rzInspect){interfaceOpenService(b.dataset.rzInspect);return;}
 if(b.hasAttribute('data-rz-nav')){consoleNavigate(b.dataset.rzNav);return;}
 if(b.hasAttribute('data-rz-category')){interfaceState.category=b.dataset.rzCategory;renderInterfaceServices(interfaceSummaries());return;}
 if(b.hasAttribute('data-rz-filter')){interfaceState.filter=b.dataset.rzFilter;renderInterfaceServices(interfaceSummaries());return;}
 if(b.hasAttribute('data-rz-protocol')){nodeBrowser.protocol=b.dataset.rzProtocol;nodeBrowser.page=1;$$('[data-rz-protocol]').forEach(e=>{const on=e===b;e.classList.toggle('active',on);e.setAttribute('aria-pressed',String(on));});renderNodes();return;}
 if(b.hasAttribute('data-rz-close')){document.getElementById(b.dataset.rzClose)?.close();return;}
 if(b.hasAttribute('data-rz-action')){const id=interfaceState.inspector;if(!id||interfaceState.busy)return;const action=b.dataset.rzAction;
  if(action==='configure'){interfaceCloseInspector();setView('services');$('#ui3ServiceExpert').open=true;$('#serviceSearch').value=state.services.find(s=>s.id===id)?.name||'';window.RazvilkaConsoleFilters.service='all';serviceDashboard.expanded.add(id);renderServices();$('#ui3ServiceExpert').scrollIntoView({block:'start',behavior:'smooth'});return;}
  if(action==='setup'){interfaceCloseInspector();setView('onboard');return;}
  if(action==='check'){interfaceCloseInspector();setView('services');$('#ui3ServiceExpert').open=true;serviceDashboard.expanded.add(id);$('#serviceSearch').value=state.services.find(s=>s.id===id)?.name||'';renderServices();void serviceDashboardStart('check',[id]).catch(e=>interfaceToast(e.message));return;}
  interfaceState.busy=true;b.disabled=true;
  void interfaceManage(id,action==='manage',action==='remove').catch(e=>consoleText('ui3InspectorMessage',e.message)).finally(()=>{interfaceState.busy=false;if(b.isConnected)b.disabled=false;});
 }
});
$('#ui3ServiceSearch').addEventListener('input',e=>{interfaceState.query=e.target.value;renderInterfaceServices(interfaceSummaries());});
$('#ui3ServiceDialog').addEventListener('close',()=>{const previous=interfaceState.returnFocus;interfaceState.inspector=null;if(previous?.isConnected)previous.focus({preventScroll:true});});
document.addEventListener('razvilka:auth-required',()=>{interfaceState.authEpoch++;interfaceState.busy=false;for(const c of interfaceRequests)c.abort();interfaceRequests.clear();interfaceCloseInspector();consoleSnapshot=null;interfaceHTML('ui3InspectorContent','');});
// UI polling renders data only; all checks and maintenance remain server jobs.
renderInterface();
