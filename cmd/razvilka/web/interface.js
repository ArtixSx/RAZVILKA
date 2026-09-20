/* Interface R3. One API/control plane; no simulated transport in production.
   UI grouping is metadata only. Network actions retain server-side consent/CAS. */
'use strict';
const interfaceState = { query:'', filter:'selected', layout:interfaceReadLayout(), category:'', expanded:new Set(), inspector:null, returnFocus:null, busy:false, authEpoch:0, authRevoked:false, toastTimer:null };
// Only a presentation preference is stored locally: no service IDs, keys or policy.
function interfaceReadLayout() {
  try { return localStorage.getItem('razvilka.service-layout.v1') === 'list' ? 'list' : 'cards'; }
  catch (_) { return 'cards'; }
}
function interfaceSetLayout(value) {
  interfaceState.layout = value === 'list' ? 'list' : 'cards';
  try { localStorage.setItem('razvilka.service-layout.v1', interfaceState.layout); } catch (_) { /* Storage can be unavailable for a local preview. */ }
  renderInterfaceServices(interfaceSummaries());
}
const rim = window.RazvilkaInterfaceModel;
const interfaceHTMLCache = new WeakMap();
const interfaceRequests = new Set();
const interfaceSections = {
  overview: { title:'Ваша сеть', children:[['overview','Главная'],['autopilot','Автопилот']] },
  services: { title:'Сервисы', children:[['services','Мои сервисы'],['managed','Политики и резерв']] },
  nodes: { title:'Подключения', children:[['nodes','Узлы'],['providers','Каталог источников'],['subscription-settings','Подписки'],['connections','Текущие соединения']] },
  engines: { title:'Обходы', children:[['engines','Все обходы'],['engineconfig','Редактор'],['strategylab','Лаборатория NFQWS2'],['dns','DNS / Smart DNS'],['testlab','Проверки']] },
  devices: { title:'Устройства', children:[['devices','Устройства и группы']] },
  activity: { title:'Наблюдение', children:[['activity','События'],['diagnostics','Диагностика']] },
  settings: { title:'Настройки', children:[['settings','Общие'],['onboard','Мастер'],['updates','Обновления'],['sources','Списки доменов']] },
};
Object.assign(viewMeta, { overview:['Главная','Состояние сети и работа автоматики'], engines:['Обходы','Специализированные инструменты, единое управление'], activity:['События','Решения, проверки и изменения'], providers:['Источники подключений','Выбранные каталоги и личные подписки'] });
function interfaceHTML(id, html) {
  const el=document.getElementById(id); if(!el || interfaceHTMLCache.get(el) === html)return;
  const focus=document.activeElement?.closest?.('[data-rz-focus]')?.getAttribute('data-rz-focus');
  el.innerHTML=html; interfaceHTMLCache.set(el,html);
  // CSSOM assignments comply with the strict CSP; HTML style attributes do not.
  el.querySelectorAll('[data-rz-width]').forEach(bar=>{
    const width=Number(bar.dataset.rzWidth);
    bar.style.width=(Number.isFinite(width)?Math.min(100,Math.max(0,width)):0)+'%';
  });
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
 const auto=managed?managed.enabled?'Автопилот':'Автоподбор на паузе':s.enabled?'Индивидуальная настройка':s.applied_enabled?'Ожидает выключения':'Не добавлен';
 const pending=s.dirty===true||s.enabled!==!!serviceDashboardApplied(s).enabled;
 return `<article class="ui3-service-card ${compact?'compact':''} ${s.enabled?'':'not-selected'}" data-rz-card="${esc(s.id)}"><div class="ui3-service-card-top"><span class="ui3-service-icon tone-${esc(rim.category(s)==='ИИ-сервисы'?'violet':s.id==='youtube'?'rose':'teal')}">${consoleServiceIcon(s)}</span><div class="ui3-service-name"><h4>${esc(s.name)}</h4><span>${esc(compact?auto:rim.category(s))}</span></div><button type="button" class="ui3-more" data-rz-inspect="${esc(s.id)}" data-rz-focus="${compact?'child':'card'}-${esc(s.id)}" aria-label="Подробности: ${esc(s.name)}">${ci('chevron')}</button></div><div class="ui3-card-state">${interfaceBadge(h)}${pending?`<span class="ui3-pending-dot" title="Есть неприменённые изменения">${managed&&!s.dirty?'В очереди':'Есть изменения'}</span>`:''}</div><div class="ui3-card-route"><span>Сейчас</span><b title="${esc(interfaceRouteName(h.route))}">${esc(interfaceRouteName(h.route))}</b></div>${compact?'':`<div class="ui3-card-footer"><span>${esc(auto)}</span><button type="button" class="text-button" data-rz-inspect="${esc(s.id)}">${s.enabled||s.applied_enabled||pending?'Управлять':'Добавить'} ${ci('chevron')}</button></div>`}</article>`;
}
function interfaceGroupHTML(g,summaries,location){
 const a=g.summary,key=location+':'+g.name,open=interfaceState.expanded.has(key)||!!interfaceState.query;
 const route=a.routes.length>1?'Разные маршруты':a.route?interfaceRouteName(a.route):'Маршруты ещё не назначены';
 const label=a.selected?`Доступны: ${a.good}${a.pending?' · Без подтверждения: '+a.pending:''}${a.failed?' · Не прошли: '+a.failed:''}`:'Выберите нужные сервисы внутри';
 return `<details class="ui3-service-group" data-rz-group="${esc(key)}" ${open?'open':''}><summary data-rz-focus="group-${esc(key)}"><span class="ui3-service-icon tone-violet">${ci('sparkles')}</span><span class="ui3-group-heading"><strong>${esc(g.name)}</strong><small>${a.selected} из ${a.total} выбрано · ${esc(route)}</small><small class="ui3-group-health ${esc(a.kind)}">${esc(label)}</small></span><span class="ui3-group-avatars">${g.allMembers.slice(0,3).map(s=>`<span>${consoleServiceIcon(s)}</span>`).join('')}</span><span class="ui3-group-chevron">${ci('chevron')}</span></summary><div class="ui3-group-status"><span class="ui3-status ${esc(a.kind)}"><i></i>${esc(label)}</span><small>Проверка и маршрут — отдельно для каждого</small></div><div class="ui3-group-content"><div class="ui3-group-member-grid">${g.members.map(s=>interfaceServiceCard(s,summaries,true)).join('')}</div><p class="ui3-group-note">Группировка не меняет сеть. Добавляйте и настраивайте участников по отдельности.</p></div></details>`;
}
function interfaceCards(services,summaries,where){return rim.groupServices(services,interfaceServices(),summaries).map(g=>g.grouped?interfaceGroupHTML(g,summaries,where):g.members.map(s=>interfaceServiceCard(s,summaries)).join('')).join('');}
function interfaceEmpty(title,body,action=''){return `<div class="ui3-empty">${ci('grid')}<h3>${esc(title)}</h3><p>${esc(body)}</p>${action}</div>`;}
function interfaceDataReady(key){return !state.dataLoad || state.dataLoad[key]?.loaded===true;}
function interfaceLoadMessage(key){
 const load=state.dataLoad?.[key];
 return load?.phase==='busy'?'Настройки временно заняты. Повторим чтение автоматически.'
   :load?.phase==='error'?'Данные не загрузились. Это не означает, что настройки отсутствуют. Повторите обновление.'
   :'Получаем данные с роутера. Остальные разделы уже доступны.';
}
function renderInterfaceNavigation(view=state.currentView||'overview'){
 const key=Object.keys(interfaceSections).find(k=>interfaceSections[k].children.some(([v])=>v===view))||'overview',group=interfaceSections[key];
 $$('[data-main-nav]').forEach(e=>{const on=e.dataset.mainNav===key;e.classList.toggle('active',on);on?e.setAttribute('aria-current','page'):e.removeAttribute('aria-current');});
 $$('[data-mobile-nav]').forEach(e=>{const on=e.dataset.mobileNav===key;e.classList.toggle('active',on);on?e.setAttribute('aria-current','page'):e.removeAttribute('aria-current');});
 consoleText('ui3Breadcrumb',group.title);
 const sub=$('#interfaceSubnav');sub.hidden=group.children.length<2;sub.classList.toggle('home-sections',key==='overview');
 interfaceHTML('interfaceSubnav',group.children.map(([v,title])=>`<button type="button" data-rz-nav="${esc(v)}" data-rz-focus="nav-${esc(v)}" ${v===view?'aria-current="page" class="active"':''}>${key==='overview'?ci(v==='autopilot'?'route':'grid'):''}<span>${esc(title)}${key==='overview'?`<small>${v==='autopilot'?'Автоподбор и резерв':'Состояние вашей сети'}</small>`:''}</span></button>`).join(''));
}
/* Home is a read-only operational summary; Services is the configuration catalog.
   All actions below navigate to existing, scoped controllers. */
function interfaceHomeAuto(ready){
 const snapshot=ready&&!consoleAutonomyError?consoleSnapshot:null,p=snapshot?.policy;
 const label=!ready?'Данные недоступны':consoleAutonomyError?'Автономность недоступна':interfaceAutoLabel();
 const enabled=!!p?.setup_complete&&p.enabled&&!snapshot?.stopped&&!snapshot?.manual&&!snapshot?.safe_mode&&!snapshot?.blocked&&!state.status?.safe_mode;
 const managed=Object.values(snapshot?.services||{}).filter(s=>s.enabled&&!s.removing).length;
 const lastCheck=nodeActivity.fallback!==null?nodeActivity.checks:nodeBrowser.job;
 const jobs=[{job:lastCheck,view:'nodes'}, {job:serviceDashboard.control?.job,view:'services'}]
   .filter(x=>ready&&x.job&&['queued','running','canceling'].includes(x.job.state));
 const job=jobs[0],fallback=ready&&nodeActivity.fallback?.active===true;
 const phaseNames={queued:'Ожидает выполнения',fetching:'Получает кандидатов',checking:'Проверяет подключения',finished:'Завершает проверку'};
 let activity=!p?'Получаем состояние проверок.':!p.setup_complete?'Выберите сервисы и разрешённые способы подключения в мастере.':!enabled?'Автоподбор приостановлен. Настройки и текущие подключения сохранены.':'Проверяет сервисы на роутере, даже когда эта страница закрыта.';
 if(fallback)activity='В последнем снимке выполняется проверка резервного маршрута.';
 if(job){const j=job.job,total=Number.isInteger(j.total)&&j.total>=0?j.total:0,completed=Number.isInteger(j.completed)&&j.completed>=0?Math.min(j.completed,total):0;
   activity=`${j.state==='canceling'?'Завершение и очистка':phaseNames[j.phase]||phaseNames[j.state]||'Проверка на роутере'}${total?' · '+completed+' из '+total:''}.`;
 }
 const seconds=p?.check_seconds;
 const interval=Number.isFinite(seconds)&&seconds>0?(seconds%60===0?seconds/60+' мин':seconds+' с'):'Не задан';
 interfaceHTML('r42AutoPanel',`<div class="r42-panel-cap"><span class="ui3-eyebrow">АВТОПИЛОТ</span>${ci('route')}</div><h3>${esc(label)}</h3><p>${esc(consoleAutonomyError||(!p?.setup_complete?'Задайте общие правила один раз в мастере.':enabled?'Следит за разрешёнными сервисами и сохраняет работающий путь.':'Откройте Автопилот, чтобы проверить режим управления и причину паузы.'))}</p><div class="r42-auto-facts"><div><strong>${p?managed:'—'}</strong><span>под управлением</span></div><div><strong>${esc(interval)}</strong><span>интервал проверки</span></div></div><div class="r42-job-state ${job||fallback?'has-job':''}">${ci(job||fallback?'activity':'clock')}<span>${esc(activity)}</span></div><button class="text-button" type="button" data-console-navigate="${job?job.view:fallback||p?.setup_complete?'autopilot':'onboard'}" data-rz-focus="home-auto">${job||fallback?'Открыть задачу':p?.setup_complete?'Политика и очередь':'Пройти настройку'} ${ci('chevron')}</button>`);
}
function renderInterfaceHome(summaries){
 const ready=!interfaceState.authRevoked&&!!state.status?.version&&state.status?.authenticated!==false;
 const servicesReady=ready&&interfaceDataReady('services');
 const services=servicesReady?interfaceServices():[],home=rim.homeSnapshot(services,summaries),a=home.counts;
 consoleText('ui3HomeCount',servicesReady?String(a.selected):'—');consoleText('ui3NavCount',servicesReady?String(a.selected):'—');
 const stopped=servicesReady&&(consoleSnapshot?.stopped||state.serviceControl?.runtime_state==='stopped');
 const title=!servicesReady?'Состояние ещё не получено':stopped?'Маршруты RAZVILKA остановлены':!a.selected?home.appliedCount?'Есть действующие маршруты':'Добавьте первый сервис':a.failed?'Есть неуспешные проверки':a.pending?'Нужны свежие подтверждения':'Последние проверки пройдены';
 const desc=!servicesReady?'Ожидаем данные локальной панели. Отсутствие данных не означает, что интернет отключён.':stopped?'Настройки сохранены. Перед возобновлением нужно проверить актуальность маршрутов.':!a.selected?home.appliedCount?'Изменения выбора ещё не применены. Существующие подключения остаются активными.':'Подключите нужные сайты. Здесь появятся их состояние, действующие маршруты и результаты проверок.':'Доступность относится к проверенному сценарию, а не ко всем функциям сайта или приложения.';
 const tone=!servicesReady||!a.selected||stopped?'unknown':a.failed?'bad':a.pending?'warn':'good';
 const bars=[['good',a.good],['unknown',a.pending],['bad',a.failed]].map(([kind,count])=>`<i class="${kind}" data-rz-width="${a.selected?100*count/a.selected:0}"></i>`).join('');
 const firstRun=servicesReady&&!a.selected&&!home.appliedCount&&!stopped;
 $('#ui3HealthBanner').dataset.state=tone;
 const healthDetails=firstRun?`<div class="home-start-steps"><div><span>01</span><b>Выберите сервисы</b><small>Сайты и приложения из каталога или ваши собственные</small></div><div><span>02</span><b>Настройте Автопилот</b><small>Разрешите подходящие обходы и автоматические проверки</small></div></div><button type="button" class="primary" data-console-navigate="onboard" data-rz-focus="home-start">${ci('route')} Начать настройку ${ci('chevron')}</button>`:`<div class="r42-health-number"><strong>${servicesReady?a.good:'—'}</strong><span>/ ${servicesReady?a.selected:'—'}<small>сервисов прошли последнюю проверку</small></span></div><div class="r42-health-bar" role="img" aria-label="${a.good} подтверждено, ${a.pending} без подтверждения, ${a.failed} не прошли проверку">${bars}</div><div class="r42-health-legend">${servicesReady?`<span><i class="good"></i>${a.good} подтверждено</span><span><i class="unknown"></i>${a.pending} без подтверждения</span><span><i class="bad"></i>${a.failed} не прошли</span>`:'<span>Нет данных о сервисных проверках</span>'}</div>`;
 interfaceHTML('ui3HealthBanner',`<div class="r42-panel-cap"><span class="ui3-eyebrow">${firstRun?'ПЕРВОЕ ПОДКЛЮЧЕНИЕ':'ДОСТУПНОСТЬ СЕРВИСОВ'}</span><span class="ui3-status ${tone}">${ci(tone==='good'?'check':'shield')}${servicesReady?'Локальная панель':'Ожидаем данные'}</span></div><h3>${esc(title)}</h3><p>${esc(desc)}</p>${healthDetails}`);
 interfaceHomeAuto(ready);
 const attention=home.attention.slice(0,3);
 interfaceHTML('ui3Attention',`<div class="ui3-section-heading"><div><h3>Требует внимания${home.attention.length?` <span class="ui3-count">${home.attention.length}</span>`:''}</h3><p>Только исключения, не полный список сервисов</p></div>${ci('activity')}</div>${attention.length?attention.map(s=>{const h=summaries[s.id]||{};return `<button type="button" class="r42-attention-row" data-rz-inspect="${esc(s.id)}" data-rz-focus="attention-${esc(s.id)}"><span class="r42-state-mark ${esc(h.kind||'unknown')}">${ci(h.kind==='bad'?'activity':'clock')}</span><span class="r42-attention-copy"><b>${esc(s.name)}</b><small>${esc(h.label||'Нет свежей проверки')}</small></span><span class="r42-attention-route">${esc(interfaceRouteName(h.route))}</span>${ci('chevron')}</button>`;}).join(''):`<div class="r42-calm-state">${ci(servicesReady&&a.selected?'shield':'clock')}<div><b>${!servicesReady?'Нет данных для оценки':a.selected?'В актуальных проверках нет проблем':'Наблюдение ещё не настроено'}</b><p>${a.selected?'Полный состав и индивидуальные настройки — в разделе «Сервисы».':'После добавления сервисов здесь появятся их отклонения и причины.'}</p></div></div>`}${attention.length?`<button type="button" class="text-button r42-attention-link" data-r42-services="attention" data-rz-focus="all-attention">${home.attention.length>3?'Все '+home.attention.length+' в разделе «Сервисы»':'Открыть сервисы с отклонениями'} ${ci('chevron')}</button>`:''}`);
 const routeNames={nfqws2:'Локально · NFQWS2',usque:'WARP · MASQUE','warp-wg':'WARP · WireGuard','sing-box':'Sing-box · прокси',xray:'Xray · прокси',amneziawg:'AmneziaWG',direct:'Прямой путь',other:'Другой маршрут',unknown:'Маршрут не определён'};
 interfaceHTML('r42RouteDistribution',`<div class="ui3-section-heading"><div><h3>Распределение маршрутов</h3><p>${servicesReady?home.appliedCount+' применённых назначений · не объём трафика':'Число назначений ещё не получено'}</p></div><button class="text-button" data-console-navigate="engines" type="button">Обходы ${ci('chevron')}</button></div>${home.routes.length?home.routes.map((r,i)=>`<div class="r42-route-row"><span class="r42-route-name">${esc(routeNames[r.id])}</span><div class="r42-route-meter" role="img" aria-label="${esc(routeNames[r.id])}: ${r.count} назначений"><i class="route-${i%3}" data-rz-width="${100*r.count/home.appliedCount}"></i></div><b>${r.count}</b></div>`).join(''):`<p class="r42-inline-empty">${servicesReady?'Маршруты появятся после проверки и применения настроек сервисов.':'Ждём сведения о применённых маршрутах.'}</p>`}<div class="r42-route-footnote">${ci('layers')}Один путь может обслуживать несколько сервисов. Их проверки остаются независимыми.</div>`);
 consoleText('ui3RouterName',ready?state.system?.hostname||'Роутер':'Роутер не определён');
 consoleText('ui3RouterMeta',ready?[state.system?.architecture,state.system?.wan_interface?`WAN: ${state.system.wan_interface}`:''].filter(Boolean).join(' · ')||'Нет сведений о платформе':'Нет снимка');
 const m=ready?state.metrics?.latest||{}:{},at=Date.parse(m.timestamp||''),metricsFresh=Number.isFinite(at)&&at<=Date.now()&&Date.now()-at<180000;
 const cpu=metricsFresh&&m.cpu_ready===true?rim.finitePercent(m.cpu_percent):null,ram=metricsFresh&&Number.isFinite(m.memory_total_bytes)&&m.memory_total_bytes>0?rim.finitePercent(m.memory_used_percent):null;
 interfaceHTML('ui3Resources',[[cpu,'Процессор'],[ram,'Память']].map(([n,label])=>`<div class="ui3-resource"><div><span>${label}</span><b>${n===null?'Нет свежих данных':Math.round(n)+'%'}</b></div><div class="ui3-meter" role="img" aria-label="${label}: ${n===null?'нет свежих данных':Math.round(n)+'%'}"><i data-rz-width="${n===null?0:n}"></i></div></div>`).join('')+`<div class="ui3-router-temperature"><span>Температура</span><b>${metricsFresh&&typeof m.temperature_c==='number'&&Number.isFinite(m.temperature_c)?Math.round(m.temperature_c)+' °C':'Нет свежих данных'}</b></div><p class="r42-resource-note">${metricsFresh?'Последнее измерение: '+esc(consoleDate(m.timestamp)):'Показатели появятся после получения актуального снимка.'}</p>`);
 const p=ready&&!consoleAutonomyError?consoleSnapshot?.policy:null;
 const labels={off:'Выключено',check:'Проверка версий',prepare:'Подготовка архива'};
 interfaceHTML('ui3Maintenance',`<div class="ui3-section-heading"><div><h3>Ближайшее обслуживание</h3><p>${p?esc(p.timezone||'Часовой пояс не задан'):'Расписание ещё не получено'}</p></div>${ci('clock')}</div>${[['application','Приложение'],['components','Обходы']].map(([key,title])=>{const plan=p?.[key],on=plan&&plan.mode!=='off';const next=ready?consoleSnapshot?.[key==='application'?'next_application_window':'next_components_window']:null;const nextTime=Date.parse(next||''),hasNext=on&&Number.isFinite(nextTime)&&nextTime>Date.now();let date='';if(hasNext){try{date=new Date(nextTime).toLocaleString('ru-RU',{timeZone:p.timezone,day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'});}catch{date='Время требует уточнения';}}return `<div class="r42-maintenance-row"><span><b>${title}</b><small>${esc(plan?labels[plan.mode]||'Неподдержанный режим':'Не настроено')}</small></span><span>${on?esc(plan.start+'–'+plan.end):'—'}${date?`<small>Следующее: ${esc(date)}</small>`:''}</span></div>`;}).join('')}<p class="r42-resource-note">${p?'По расписанию можно проверить обновления и подготовить архив. Установка запускается вручную.':'Окна обслуживания выбираются в мастере.'}</p><button class="text-button" type="button" data-console-navigate="onboard">Изменить расписание ${ci('chevron')}</button>`);
 const events=ready?(state.audit?.events||[]).slice(0,4):[];
 interfaceHTML('ui3HomeEvents',events.length?events.map(e=>`<div class="ui3-event"><span class="ui3-event-icon">${ci(e.outcome==='ok'?'check':'activity')}</span><div><strong>${esc(consoleAuditTitle(e))}</strong><small>${e.outcome==='ok'?'Операция завершена':e.outcome==='denied'?'Запрос отклонён':e.outcome==='failed'?'Операция завершилась с ошибкой':'Итог не подтверждён'} · ${esc(e.action||'Действие панели')}</small></div><time>${esc(consoleDate(e.timestamp))}</time></div>`).join(''):`<p class="r42-inline-empty">${ready?'Здесь появится история проверок и изменений настроек.':'Журнал ещё не получен.'}</p>`);
}

function renderInterfaceServices(summaries){
 if(!interfaceDataReady('services')){
   consoleText('ui3CatalogSummary','Список сервисов ещё не получен');
   interfaceHTML('ui3ServiceCatalog',interfaceEmpty('Сервисы загружаются',interfaceLoadMessage('services'),'<button type="button" class="secondary" data-panel-refresh>Повторить загрузку</button>'));
   return;
 }
 $('#ui3ServiceCatalog').classList.toggle('ui3-list-layout',interfaceState.layout==='list');
 $('#serviceList').classList.toggle('r41-grid',interfaceState.layout!=='list');
 $$('[data-rz-layout]').forEach(e=>{const on=e.dataset.rzLayout===interfaceState.layout;e.classList.toggle('active',on);e.setAttribute('aria-pressed',String(on));});
 const all=interfaceServices(),cats=[...new Set(all.map(rim.category))].sort((a,b)=>a.localeCompare(b,'ru'));
 interfaceHTML('ui3CategoryFilters',[['','Все категории'],...cats.map(c=>[c,c])].map(([v,t])=>`<button type="button" class="${v===interfaceState.category?'active':''}" aria-pressed="${v===interfaceState.category}" data-rz-category="${esc(v)}" data-rz-focus="category-${esc(v)}">${esc(t)}</button>`).join(''));
 const list=rim.filterServices(all,{query:interfaceState.query,scope:interfaceState.filter,category:interfaceState.category},summaries);
 consoleText('ui3CatalogSummary',`${list.length} ${list.length===1?'сервис':'сервисов'} показано · ${all.filter(s=>s.enabled).length} выбрано в сети`);
 if(['error','busy','loading'].includes(state.dataLoad?.services?.phase)) consoleText('ui3CatalogSummary',`${list.length} сервисов · последние полученные данные. ${interfaceLoadMessage('services')}`);
 interfaceHTML('ui3ServiceCatalog',list.length?interfaceCards(list,summaries,'catalog'):interfaceEmpty(interfaceState.filter==='selected'&&!all.some(s=>s.enabled)?'Выберите первый сервис':'Ничего не найдено',interfaceState.filter==='selected'&&!all.some(s=>s.enabled)?'Откройте каталог и добавьте сайты, которым нужен обход.':'Попробуйте другое название или сбросьте фильтры.',`<button type="button" class="secondary" data-rz-reset-filters>Открыть весь каталог ${ci('chevron')}</button>`));
 $$('[data-rz-filter]').forEach(e=>{const on=e.dataset.rzFilter===interfaceState.filter;e.classList.toggle('active',on);e.setAttribute('aria-pressed',String(on));});
}
function interfaceOpenServiceChanges(){
 interfaceState.filter='changed';interfaceState.query='';interfaceState.category='';
 $('#ui3ServiceSearch').value='';
 setView('services');
 renderInterfaceServices(interfaceSummaries());
 $('#serviceDraftBar').scrollIntoView({block:'center',behavior:'smooth'});
 $('#applyServiceChanges').focus({preventScroll:true});
}
function interfaceEngineCard(id,meta){
 const info=consoleEngineState(id),component=info.component,update=consoleEngineUpdateState(info);
 const used=(state.services||[]).filter(service=>{const applied=serviceDashboardApplied(service);return applied.enabled&&(applied.route===id||applied.route?.startsWith(id+':'));});
 const busy=!!state.componentOperation||!!state.componentRefreshRequest||component?.operation_status==='running';
 const stale=['failed','checking'].includes(update.kind);
 const protectedComponent=component?.lifecycle_block_reason||component?.external_owner||info.running||used.length>0;
 const lifecycleAllowed=component&&!busy&&!component.inventory_error&&!protectedComponent;
 const disabledReason=component?.lifecycle_block_reason||(component?.external_owner?'Компонент управляется внешним проектом.':info.running||used.length?'Сначала остановите обход и перенесите зависимые сервисы на другой маршрут.':stale?'Обновите сведения о пакете перед изменением.':busy?'Дождитесь завершения операции.':'Нет разрешения на действие в каталоге компонентов.');
 const action=(name,label,allowed)=>`<button type="button" class="${name==='remove'?'component-remove':'primary'} component-action" data-component="${esc(id)}" data-component-action="${name}" data-rz-focus="engine-${esc(id)}-${name}" ${allowed?'':`disabled title="${esc(disabledReason)}"`}>${label}</button>`;
 let actions='';
 if(!info.installed)actions+=action('install','Установить',lifecycleAllowed&&!stale&&component.can_install===true);
 else if(component?.update_available)actions+=action('update','Обновить',lifecycleAllowed&&!stale&&component.can_update===true);
 if(info.installed)actions+=action('remove','Удалить',lifecycleAllowed&&component.can_remove===true);
 const operation=state.componentOperation?.id===id?state.componentOperation.action:component?.operation_status==='running'?component.operation_action:'';
 const operationText=operation?({install:'Установка выполняется…',update:'Обновление выполняется…',remove:'Удаление выполняется…'})[operation]||'Операция выполняется…':['failed','interrupted','receipt-error'].includes(component?.operation_status)?'Последняя операция не завершена: '+(component.operation_message||'откройте подробности компонента'):'';
 return `<article class="ui3-engine-card" data-engine-card="${esc(id)}"><div class="ui3-engine-card-heading"><span class="engine-mini-icon ${meta.tone}">${ci(meta.icon)}</span><span class="ui3-status ${info.tone}"><i></i>${esc(info.label)}</span></div><h3>${esc(meta.name)} <span class="ui3-engine-version ${update.kind==='update'?'has-update':''}">${esc(consoleEngineVersionLabel(info))}</span></h3><span class="ui3-engine-subtitle">${esc(meta.subtitle)}</span><p>${esc(meta.description)}</p><div class="ui3-engine-meta"><span>${info.installed?(info.running?'Процесс запущен':'Процесс не запущен'):info.installedKnown?'Процесс не обнаружен':'Нет данных о процессе'}</span><b>${used.length} сервисов</b></div><small class="ui3-engine-update ${update.kind}" role="status">${esc(update.text)}</small>${operationText?`<small class="ui3-engine-operation" role="status">${esc(operationText)}</small>`:''}<div class="ui3-engine-actions"><button type="button" class="secondary" data-component-refresh="${esc(id)}" data-rz-focus="engine-${esc(id)}-refresh" title="Обновить общий каталог компонентов" ${busy?'disabled':''}>${state.componentRefreshRequest?'Проверяем…':'Проверить обновления'}</button>${actions}<button type="button" class="secondary" data-console-engine="${esc(id)}" data-rz-focus="engine-${esc(id)}-settings">Настройки ${ci('chevron')}</button></div>${protectedComponent&&info.installed?`<small class="ui3-engine-action-hint">${esc(disabledReason)}</small>`:''}</article>`;
}
function renderInterfaceEngines(){
 if(!interfaceDataReady('engines') && !interfaceDataReady('engineConfigs') && !interfaceDataReady('components')){
   interfaceHTML('ui3EngineGrid',interfaceEmpty('Сведения об обходах загружаются',interfaceLoadMessage('engineConfigs'),'<button type="button" class="secondary" data-panel-refresh>Повторить загрузку</button>'));
   return;
 }
 interfaceHTML('ui3EngineGrid',Object.entries(consoleEngineMeta).map(([id,meta])=>interfaceEngineCard(id,meta)).join(''));
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
 if(typeof renderWorkflowControls==='function')renderWorkflowControls();
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
function interfaceResetFilters(){
 interfaceState.filter='all';interfaceState.query='';interfaceState.category='';
 $('#ui3ServiceSearch').value='';renderInterfaceServices(interfaceSummaries());
 $('#ui3ServiceSearch').focus({preventScroll:true});
}
document.addEventListener('toggle',e=>{if(!e.target.matches?.('[data-rz-group]'))return;const k=e.target.dataset.rzGroup;if(e.target.open)interfaceState.expanded.add(k);else interfaceState.expanded.delete(k);},true);
function interfaceComponentAction(event){
 const button=event.target.closest('#ui3EngineGrid [data-component-refresh],#ui3EngineGrid .component-action');
 if(!button||button.disabled)return;
 if(button.hasAttribute('data-component-refresh'))void refreshComponents(true);
 else void manageComponent(button.dataset.component,button.dataset.componentAction);
}
document.addEventListener('click',interfaceComponentAction);
document.addEventListener('click',event=>{
 const b=event.target.closest('[data-r42-services],[data-rz-inspect],[data-rz-nav],[data-rz-category],[data-rz-filter],[data-rz-reset-filters],[data-rz-protocol],[data-rz-close],[data-rz-action],[data-rz-layout]');if(!b)return;
 if(b.hasAttribute('data-rz-reset-filters')){interfaceResetFilters();return;}
 if(b.hasAttribute('data-r42-services')){
  interfaceState.filter=b.dataset.r42Services==='attention'?'attention':'selected';
  interfaceState.query='';interfaceState.category='';$('#ui3ServiceSearch').value='';
  consoleNavigate('services');renderInterfaceServices(interfaceSummaries());
  $('#ui3ServiceSearch').focus({preventScroll:true});return;
 }
 if(b.hasAttribute('data-rz-layout')){interfaceSetLayout(b.dataset.rzLayout);return;}
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
document.addEventListener('razvilka:auth-required',()=>{interfaceState.authRevoked=true;interfaceState.authEpoch++;interfaceState.busy=false;for(const c of interfaceRequests)c.abort();interfaceRequests.clear();interfaceCloseInspector();consoleSnapshot=null;interfaceHTML('ui3InspectorContent','');renderInterfaceHome({});});
document.addEventListener('razvilka:auth-restored',()=>{interfaceState.authRevoked=false;renderInterfaceHome(interfaceSummaries());});
// UI polling renders data only; all checks and maintenance remain server jobs.
renderInterface();
