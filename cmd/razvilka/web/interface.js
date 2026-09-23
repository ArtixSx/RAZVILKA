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
const interfaceSections = rim.taskSections;
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
function interfaceAutoLabel(){
 return rim.humanAuto(consoleSnapshot,state.status,!interfaceState.authRevoked&&!consoleAutonomyError).title;
}

function interfaceServicePresentation(service,summaries){
 const original=(state.services||[]).find(s=>s.id===service.id)||service;
 const managed=consoleSnapshot?.services?.[service.id];
 const auto=rim.humanAuto(consoleSnapshot,state.status,!interfaceState.authRevoked&&!consoleAutonomyError);
 const running=auto.state==='enabled';
 const runtime=running?consoleSnapshot?.runtime?.[service.id]:{};
 const value=rim.humanService(original,summaries?.[service.id]||{},managed,runtime,!interfaceState.authRevoked&&!['error','busy'].includes(state.dataLoad?.services?.phase));
 if(managed?.enabled===true&&!running)value.control=auto.state==='unknown'?'Состояние автоподбора не получено':auto.state==='paused'?'Автоподбор на общей паузе':'Автоподбор ограничен общей настройкой';
 return value;
}

function interfaceBadge(summary){return `<span class="ui3-status ${esc(summary.kind||'unknown')}"><i></i>${esc(summary.label||'Не проверен')}</span>`;}
function interfaceServiceCard(s,summaries,compact=false){
 if(s.presentation_only)return `<article class="ui3-service-card r5-service-card" data-rz-card="${esc(s.id)}"><div class="ui3-service-card-top"><span class="ui3-service-icon">${consoleServiceIcon(s)}</span><div class="ui3-service-name"><h4>${esc(s.name)}</h4><span>${esc(rim.category(s))}</span></div></div><div class="ui3-card-state"><span class="ui3-status unknown">Сохранённые настройки</span></div><p class="r5-service-description">Свежая доступность пока неизвестна</p><details class="r5-advanced"><summary>Выбранные настройки</summary><p>${(s.desired_state?.enabled ?? s.enabled)?'Включён':'Выключен'} · ${esc(interfaceRouteName(s.route))}</p><p>Устройства: ${s.sources?.length?esc(s.sources.join(', ')):'Все устройства в сохранённой области LAN'}</p><p>Эти данные не подтверждают действующий маршрут.</p></details><div class="ui3-card-footer"><small>Ожидаем обновления состояния</small></div></article>`;
 const h=interfaceServicePresentation(s,summaries);
 const ready=consoleSnapshot?.policy?.setup_complete===true&&!consoleAutonomyError;
 const action=h.member
   ?`<button type="button" class="secondary" data-rz-inspect="${esc(s.id)}" data-rz-focus="service-${esc(s.id)}">Открыть</button>`
   :`<button type="button" class="primary" data-r5-add="${esc(s.id)}" data-rz-focus="service-${esc(s.id)}" ${interfaceState.busy?'disabled':''}>${ready?'Добавить':'Начать настройку'}</button>`;
 return `<article class="ui3-service-card r5-service-card ${h.member?'':'not-selected'}" data-rz-card="${esc(s.id)}"><div class="ui3-service-card-top"><span class="ui3-service-icon tone-${rim.category(s)==='ИИ-сервисы'?'violet':s.id==='youtube'?'rose':'teal'}">${consoleServiceIcon(s)}</span><div class="ui3-service-name"><h4>${esc(s.name)}</h4><span>${esc(rim.category(s))}</span></div></div><div class="ui3-card-state">${interfaceBadge(h)}${h.pendingLabel?`<span class="ui3-pending-dot">${esc(h.pendingLabel)}</span>`:''}</div><p class="r5-service-description">${esc(h.member?h.control:'Доступ по выбранным правилам автопилота')}</p><div class="ui3-card-route"><span>Подключение</span><b>${esc(h.route?interfaceRouteName(h.route):'Пока не назначено')}</b></div><div class="ui3-card-footer"><small>${h.applied?'Настройки применены':'Применение не подтверждено'}</small>${action}</div></article>`;
}

function interfaceGroupHTML(g,summaries,location){
 const rows=g.allMembers.map(s=>interfaceServicePresentation(s,summaries)),selected=rows.filter(s=>s.member),good=selected.filter(s=>s.kind==='good').length;
 const key=location+':'+g.name,open=interfaceState.expanded.has(key)||!!interfaceState.query;
 const text=selected.length?`${selected.length} добавлено · ${good} работают · ${selected.length-good} без подтверждения`:'Выберите нужные ИИ-сервисы внутри';
 return `<details class="ui3-service-group r5-service-group" data-rz-group="${esc(key)}" ${open?'open':''}><summary data-rz-focus="group-${esc(key)}"><span class="ui3-service-icon tone-violet">${ci('service-ai')}</span><span class="ui3-group-heading"><strong>${esc(g.name)}</strong><small>${esc(text)}</small></span><span class="ui3-group-chevron">${ci('chevron')}</span></summary><div class="ui3-group-content"><div class="ui3-group-member-grid">${g.members.map(s=>interfaceServiceCard(s,summaries,true)).join('')}</div><p class="ui3-group-note">Для каждого сервиса — своё подключение и своя проверка.</p></div></details>`;
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
 const nav=rim.navigation(view),group=interfaceSections[nav.owner];
 $$('[data-main-nav]').forEach(e=>{const on=e.dataset.mainNav===nav.owner;e.classList.toggle('active',on);on?e.setAttribute('aria-current','page'):e.removeAttribute('aria-current');});
 $$('[data-mobile-nav]').forEach(e=>{const owner=rim.navigation(e.dataset.mobileNav).owner;const on=owner===nav.owner;e.classList.toggle('active',on);on?e.setAttribute('aria-current','page'):e.removeAttribute('aria-current');});
 consoleText('ui3Breadcrumb',nav.owner==='overview'?'Главная':nav.title);
 consoleText('pageTitle',nav.pageTitle);
 const sub=$('#interfaceSubnav');
 if(nav.owner==='settings'&&view!=='settings'){
   sub.hidden=false;
   interfaceHTML('interfaceSubnav',`<button type="button" data-rz-nav="settings">← Все настройки</button><span class="r5-location">${esc(nav.pageTitle)}</span>`);
 }else if(nav.owner==='services'&&view==='managed'){
   sub.hidden=false;interfaceHTML('interfaceSubnav','<button type="button" data-rz-nav="services">← Мои сервисы</button><span class="r5-location">Подробности автоподбора</span>');
 }else{
   sub.hidden=nav.owner!=='nodes';
   if(!sub.hidden)interfaceHTML('interfaceSubnav',group.children.map(([id,label])=>`<button type="button" data-rz-nav="${esc(id)}" ${id===view?'aria-current="page" class="active"':''}>${esc(label)}</button>`).join(''));
 }
}

function interfaceHomeAuto(ready){
 const known=ready&&!consoleAutonomyError,auto=rim.humanAuto(consoleSnapshot,state.status,known),p=known?consoleSnapshot?.policy:null;
 const enabled=auto.state==='enabled';
 const entries=enabled?Object.entries(consoleSnapshot.runtime||{}).filter(([id])=>consoleSnapshot.services?.[id]?.enabled):[];
 const active=entries.find(([,r])=>['checking','applying','searching'].includes(r.state));
 const service=active?(state.services||[]).find(s=>s.id===active[0]):null;
 const activity=active?`${service?.name||active[0]}: ${active[1].message||'выполняется задача'}`:enabled?'Состояние сервисов обновляется на роутере, даже когда браузер закрыт.':auto.detail;
 const button=auto.target==='refresh'?'<button class="secondary" type="button" data-panel-refresh>Обновить состояние</button>':`<button class="${auto.state==='setup'?'primary':'secondary'}" type="button" data-rz-nav="${esc(auto.target)}" data-rz-focus="home-auto">${esc(auto.action)}</button>`;
 const interval=p?.setup_complete&&Number.isFinite(p.check_seconds)?(p.check_seconds%60===0?p.check_seconds/60+' мин':p.check_seconds+' с'):null;
 interfaceHTML('r42AutoPanel',`<div class="r5-auto-heading"><div><span class="ui3-eyebrow">АВТОПИЛОТ</span><h2>${esc(auto.title)}</h2><p>${esc(auto.detail)}</p></div>${button}</div>${enabled?`<div class="r5-auto-activity">${ci(active?'activity':'clock')}<span>${esc(activity)}</span>${interval?`<small>Интервал проверки: ${esc(interval)}</small>`:''}</div>`:''}`);
 $('#r42AutoPanel').dataset.state=auto.tone;
}

function renderInterfaceHome(summaries){
 const ready=!interfaceState.authRevoked&&state.authenticated===true;
 const loaded=ready&&interfaceDataReady('services');
 const fresh=loaded&&!['error','busy'].includes(state.dataLoad?.services?.phase);
 const list=loaded?(state.services||[]):[];
 const counts=rim.humanCounts(list,summaries,consoleSnapshot?.services||{},rim.humanAuto(consoleSnapshot,state.status,!consoleAutonomyError).state==='enabled'?consoleSnapshot?.runtime||{}:{},fresh);
 consoleText('ui3HomeCount',loaded?counts.selected:'—');consoleText('ui3NavCount',loaded?counts.selected:'—');
 interfaceHomeAuto(ready);
 interfaceHTML('ui3HealthBanner',`<div class="r5-counts"><div><strong>${loaded?counts.selected:'—'}</strong><span>Добавлено сервисов</span></div><div><strong>${fresh?counts.good:'—'}</strong><span>Работают по проверке</span></div><div><strong>${fresh?counts.unconfirmed:'—'}</strong><span>Без подтверждения</span></div></div><p class="r5-caption">${!loaded?'Получаем сведения о сервисах.':!fresh?'Показан последний список. Свежая доступность пока неизвестна.':counts.selected?'Проверяется конкретный сценарий, а не все функции приложения.':'Сервисы пока не добавлены. Начните с настройки автопилота.'}</p>`);
 const attention=counts.rows.filter(s=>s.member&&s.actionable).slice(0,3);
 interfaceHTML('ui3Attention',`<div class="ui3-section-heading"><h3>Что требует внимания</h3>${ci('activity')}</div>${!fresh?'<p>Нет свежих данных для оценки. Это не означает, что подключения не работают.</p>':attention.length?attention.map(h=>`<button type="button" class="r5-attention-row" data-rz-inspect="${esc(h.service.id)}"><span><b>${esc(h.service.name)}</b><small>${esc(h.pendingLabel||h.label)}</small></span><span>Разобраться ${ci('chevron')}</span></button>`).join(''):`<p>${counts.selected?counts.unconfirmed?'Для части сервисов ещё нет свежего результата. Это само по себе не означает сбой.':'В последних проверках проблем не обнаружено.':'После добавления сервисов здесь появятся проблемы, требующие вашего участия.'}</p>`}`);
 const rows=counts.rows.filter(s=>s.member).slice(0,6);
 interfaceHTML('r42RouteDistribution',`<div class="ui3-section-heading"><h3>Ваши сервисы</h3><button type="button" class="text-button" data-r42-services="selected">Все сервисы ${ci('chevron')}</button></div>${rows.length?`<div class="r5-home-services">${rows.map(h=>`<div><b>${esc(h.service.name)}</b>${interfaceBadge(h)}</div>`).join('')}</div>`:'<p>Здесь будут выбранные вами сайты и приложения, а не список технических движков.</p>'}`);
 consoleText('ui3RouterName',ready?state.system?.hostname||'Роутер':'Нет сведений');
 consoleText('ui3RouterMeta',ready?state.system?.architecture||'Платформа не определена':'');
 const m=ready?state.metrics?.latest||{}:{},at=Date.parse(m.timestamp||''),recent=Number.isFinite(at)&&at<=Date.now()&&Date.now()-at<180000;
 const cpu=recent&&m.cpu_ready===true?rim.finitePercent(m.cpu_percent):null;
 const ram=recent&&Number.isFinite(m.memory_total_bytes)&&m.memory_total_bytes>0?rim.finitePercent(m.memory_used_percent):null;
 interfaceHTML('ui3Resources',[[cpu,'Процессор'],[ram,'Память']].map(([v,label])=>`<div class="r5-resource"><span>${label}</span><b>${v===null?'Нет свежих данных':Math.round(v)+'%'}</b></div>`).join(''));
 const p=ready&&!consoleAutonomyError&&consoleSnapshot?.policy?.setup_complete?consoleSnapshot.policy:null;
 interfaceHTML('ui3Maintenance',`<h3>Обслуживание</h3><p>${p?'В этой версии доступны проверка обновлений и подготовка архива. Установка запускается вручную.':'Расписание выбирается при настройке автопилота. До завершения мастера оно не считается настроенным.'}</p><button class="text-button" type="button" data-rz-nav="updates">Обновления ${ci('chevron')}</button>`);
 const events=ready&&Array.isArray(state.audit?.events)?state.audit.events.slice(0,3):[];
 interfaceHTML('ui3HomeEvents',events.length?events.map(e=>{const result=typeof projectLogEventResult==='function'?projectLogEventResult(e):{label:'Результат не уточнён'};return `<div class="ui3-event"><div><strong>${esc(consoleAuditTitle(e))}</strong><small>${esc(result.label)}</small></div><time>${esc(consoleDate(e.timestamp))}</time></div>`;}).join(''):'<p class="r5-caption">Действия появятся после настройки. Принятое задание не равно завершённому.</p>');
}

function renderInterfaceServices(summaries){
 if(!interfaceDataReady('services')){
  consoleText('ui3CatalogSummary','Список ещё не получен');
  interfaceHTML('ui3ServiceCatalog',interfaceEmpty('Получаем список сервисов',interfaceLoadMessage('services'),'<button type="button" class="secondary" data-panel-refresh>Повторить загрузку</button>'));
  return;
 }
 const all=interfaceServices(),isCatalog=interfaceState.filter==='all';
 $('#ui3ServiceCatalog').classList.toggle('ui3-list-layout',interfaceState.layout==='list');
 $('#serviceList').classList.toggle('r41-grid',interfaceState.layout!=='list');
 $$('[data-rz-layout]').forEach(e=>{const on=e.dataset.rzLayout===interfaceState.layout;e.classList.toggle('active',on);e.setAttribute('aria-pressed',String(on));});
 const categories=[...new Set(all.map(rim.category))].sort((a,b)=>a.localeCompare(b,'ru'));
 interfaceHTML('ui3CategoryFilters',[['','Все категории'],...categories.map(c=>[c,c])].map(([v,t])=>`<button type="button" class="${v===interfaceState.category?'active':''}" aria-pressed="${v===interfaceState.category}" data-rz-category="${esc(v)}">${esc(t)}</button>`).join(''));
 const normalised={};for(const s of all)normalised[s.id]=interfaceServicePresentation(s,summaries);
 const list=rim.filterServices(all,{query:interfaceState.query,scope:interfaceState.filter,category:interfaceState.category},normalised);
 const counts=rim.humanCounts(state.services||[],summaries,consoleSnapshot?.services||{},rim.humanAuto(consoleSnapshot,state.status,!consoleAutonomyError).state==='enabled'?consoleSnapshot?.runtime||{}:{},!['error','busy'].includes(state.dataLoad?.services?.phase));
 $('#ui3CategoryFilters').hidden=!isCatalog&&counts.selected<=8&&!interfaceState.category;
 consoleText('ui3CatalogSummary',`${isCatalog?'Каталог':'Ваш список'}: ${list.length} · Добавлено: ${counts.selected}${['error','busy'].includes(state.dataLoad?.services?.phase)?' · Показаны последние данные':''}`);
 const title=interfaceState.filter==='attention'?'Нет сервисов, требующих проверки':interfaceState.filter==='selected'&&!counts.selected?'Добавьте нужные сервисы':'Ничего не найдено';
 const hint=interfaceState.filter==='selected'&&!counts.selected?'Откройте каталог, выберите сайт и нажмите «Добавить».':'Попробуйте другое название или сбросьте фильтры.';
 interfaceHTML('ui3ServiceCatalog',list.length?interfaceCards(list,summaries,'catalog'):interfaceEmpty(title,hint,'<button type="button" class="secondary" data-rz-reset-filters>Открыть каталог</button>'));
 $('#r5CatalogTools').hidden=!isCatalog;
 $('#r5ServiceFilters').hidden=isCatalog;
 if($('#r6ChangedServices')){$('#r6ChangedServices').hidden=counts.changed===0;$('#r6ChangedServices').textContent=`Изменения · ${counts.changed}`;}
 consoleText('r5CatalogButton',isCatalog?'Мои сервисы':'Добавить сервис');
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
function renderInterfaceSettings(){
 interfaceHTML('r5SettingsTasks',rim.settingsTasks.map(t=>`<button type="button" class="r5-setting-task" data-rz-nav="${esc(t.target)}">${ci(t.icon)}<span><b>${esc(t.title)}</b><small>${esc(t.detail)}</small></span>${ci('chevron')}</button>`).join(''));
}

function renderInterface(){
 // A failed widget cannot retain a UI operation lock or hide other sections.
 const calls=[['navigation',()=>renderInterfaceNavigation()],['home',()=>renderInterfaceHome(interfaceSummaries())],['services',()=>renderInterfaceServices(interfaceSummaries())],['engines',()=>renderInterfaceEngines()],['settings',()=>renderInterfaceSettings()],['inspector',()=>interfaceUpdateInspector()],['auto-labels',()=>{consoleText('ui3SidebarAuto',interfaceAutoLabel());consoleText('ui3TopAuto',interfaceAutoLabel());}],['workflow',()=>{if(typeof renderWorkflowControls==='function')renderWorkflowControls();}]];
 for(const [name,render] of calls)interfaceSafeRender('interface-'+name,render);
}

async function interfaceQuickAdd(id){
 if(interfaceState.authRevoked||$('#authScreen')?.hidden===false||interfaceState.busy)return;
 const service=(state.services||[]).find(s=>s.id===id);if(!service)return;
 if(consoleAutonomyError){interfaceToast('Сначала обновите состояние автопилота. Разрешения пока не подтверждены.');return;}
 if(!consoleSnapshot?.policy?.setup_complete){setView('onboard');interfaceToast('Завершите настройку автопилота. Сервис можно добавить после сохранения правил.');return;}
 const old=consoleSnapshot.services?.[id];
 if(old||service.enabled||service.applied_enabled||service.applied_state?.enabled||service.dirty||service.route_dirty||service.sources_dirty){interfaceOpenService(id);return;}
 const epoch=interfaceState.authEpoch;
 interfaceState.busy=true;
 try{
  interfaceSafeRender('services-before-add',()=>renderInterfaceServices(interfaceSummaries()));
  await interfaceManage(id,true,false);
  if(epoch===interfaceState.authEpoch)interfaceToast('Сервис добавлен в автоподбор. Дождитесь проверки и применения подключения.');
 }catch(error){if(epoch===interfaceState.authEpoch)interfaceSafeRender('add-notice',()=>interfaceToast(error.message));}
 finally{if(epoch===interfaceState.authEpoch){interfaceState.busy=false;interfaceSafeRender('services-after-add',()=>renderInterfaceServices(interfaceSummaries()));}}
}

function interfaceTaskAction(event){
 const b=event.target.closest('[data-r5-add],[data-r5-catalog]');if(!b||b.disabled)return;
 if(b.hasAttribute('data-r5-add')){void interfaceQuickAdd(b.dataset.r5Add);return;}
 interfaceState.filter=interfaceState.filter==='all'?'selected':'all';interfaceState.query='';interfaceState.category='';
 $('#ui3ServiceSearch').value='';setView('services');renderInterfaceServices(interfaceSummaries());$('#ui3ServiceSearch').focus({preventScroll:true});
}

async function interfaceCheckService(id){
 if(interfaceState.authRevoked||$('#authScreen')?.hidden===false||interfaceState.busy||!(state.services||[]).some(s=>s.id===id))return;
 const epoch=interfaceState.authEpoch;
 const message=text=>{if(epoch!==interfaceState.authEpoch)return;interfaceSafeRender('check-notice',()=>{if(interfaceState.inspector===id&&$('#ui3ServiceDialog').open)consoleText('ui3InspectorMessage',text);else interfaceToast(text);});};
 if(serviceDashboard.operation||serviceDashboardJobActive()){message('Уже выполняется проверка. Дождитесь её завершения.');return;}
 interfaceState.busy=true;
 try{
  interfaceSafeRender('inspector-checking',()=>interfaceUpdateInspector());
  if(!Number.isSafeInteger(serviceDashboard.control?.config_revision))await refreshServiceControl();
  if(epoch!==interfaceState.authEpoch)return;
  if(!Number.isSafeInteger(serviceDashboard.control?.config_revision)){message('Настройки проверки ещё не получены. Обновите состояние и повторите.');return;}
  const previous=serviceDashboard.control?.job?.id;
  message('Запускаем проверку…');await serviceDashboardStart('check',[id]);
  if(epoch!==interfaceState.authEpoch)return;
  const job=serviceDashboard.control?.job;
  message(job?.id&&job.id!==previous?'Проверка принята. Результат появится в состоянии сервиса. Подключение не менялось.':serviceDashboard.message||'Запуск проверки не подтверждён. Сначала обновите состояние, не повторяйте действие вслепую.');
 }catch(error){message(error.message);}
 finally{if(epoch===interfaceState.authEpoch){interfaceState.busy=false;interfaceSafeRender('inspector-after-check',()=>interfaceUpdateInspector());}}
}

function interfaceUpdateInspector(){
 const id=interfaceState.inspector;if(!id||!$('#ui3ServiceDialog').open||interfaceState.authRevoked)return;
 const s=(state.services||[]).find(s=>s.id===id);
 if(!s){interfaceHTML('r5InspectorStatus','');consoleText('r5InspectorDetail','Сервис больше не найден в полученном каталоге. Рабочие маршруты этим сообщением не изменяются.');consoleText('r6InspectorRoute','Нет актуальных данных');consoleText('r6InspectorScope','Нет актуальных данных');consoleText('r6InspectorControl','Недоступно');consoleText('r6InspectorTask','Нет актуальных данных');consoleText('r6InspectorReserve','—');consoleText('r6InspectorObserved','—');consoleText('r6InspectorAddresses','');interfaceHTML('r6InspectorDomains','');interfaceHTML('r6InspectorControls','');interfaceHTML('r6InspectorRemove','');if($('#r6InspectorCheck'))$('#r6InspectorCheck').disabled=true;return;}
 const h=interfaceServicePresentation(s,interfaceSummaries()),applied=serviceDashboardApplied(s),r=consoleSnapshot?.runtime?.[id],managed=consoleSnapshot?.services?.[id];
 const sources=Array.isArray(applied.sources)?applied.sources:Array.isArray(s.applied_sources)?s.applied_sources:[];
 interfaceHTML('r5InspectorStatus',interfaceBadge(h));consoleText('r5InspectorDetail',h.detail);
 consoleText('r6InspectorRoute',h.route?interfaceRouteName(h.route):'Пока не назначено');
 consoleText('r6InspectorScope',interfaceScopeLabel(s));consoleText('r6InspectorControl',h.control);
 consoleText('r6InspectorTask',r?.message||'Данных пока нет');consoleText('r6InspectorReserve',`${Array.isArray(r?.reserves)?r.reserves.length:0} подключений; пригодность проверяется перед применением`);
 consoleText('r6InspectorObserved',consoleDate(s.observed_state?.checked_at));consoleText('r6InspectorAddresses',sources.join(', '));
 interfaceHTML('r6InspectorDomains',(Array.isArray(s.domains)?s.domains:[]).slice(0,100).map(d=>`<code>${esc(d)}</code>`).join('')+((s.domains?.length||0)>100?'<p>Показаны первые 100 доменов. Полный состав доступен в настройках сервиса.</p>':''));
 interfaceHTML('r6InspectorControls',interfaceInspectorControls(s));
 interfaceHTML('r6InspectorRemove',managed&&!managed.removing?'<button type="button" class="ui3-danger-text" data-rz-action="remove">Отключить и убрать из автопилота</button>':'');
 const check=$('#r6InspectorCheck');if(check)check.disabled=!!interfaceState.busy||!!serviceDashboard.operation||serviceDashboardJobActive()||!!managed?.removing;
}

function interfaceOpenService(id){
 const s=(state.services||[]).find(x=>x.id===id);if(!s||interfaceState.authRevoked)return;
 const h=interfaceServicePresentation(s,interfaceSummaries()),managed=consoleSnapshot?.services?.[id];
 const same=interfaceState.inspector===id&&$('#ui3ServiceDialog').open;
 interfaceState.inspector=id;if(!$('#ui3ServiceDialog').open)interfaceState.returnFocus=document.activeElement;
 // Opening the same inspector must not destroy expanded details or keyboard focus.
 if(same){interfaceUpdateInspector();return;}
 interfaceHTML('ui3InspectorContent',`<div class="ui3-inspector-title"><span class="ui3-service-icon">${consoleServiceIcon(s)}</span><div><h2 id="ui3InspectorTitle" tabindex="-1">${esc(s.name)}</h2><p>${esc(rim.category(s))}</p></div></div><div id="r5InspectorStatus">${interfaceBadge(h)}</div><p id="r5InspectorDetail" class="ui3-inspector-description">${esc(h.detail)}</p><dl class="ui3-inspector-facts"><dt>Подключение</dt><dd id="r6InspectorRoute"></dd><dt>Устройства</dt><dd id="r6InspectorScope"></dd><dt>Автоподбор</dt><dd id="r6InspectorControl"></dd></dl><div class="ui3-inspector-actions"><button type="button" class="primary" data-rz-action="check" id="r6InspectorCheck">Проверить сейчас</button><span id="r6InspectorControls"></span></div><p class="r5-caption">Проверка не меняет подключение. Пауза останавливает только автоподбор, а не доступ к сервису.</p><details class="r5-advanced"><summary>Изменить подключение и устройства</summary><p>Ручной выбор подключения и устройств применяется отдельно.</p><button type="button" class="secondary" data-rz-action="configure">Открыть настройки сервиса</button><span id="r6InspectorRemove"></span></details><details class="r5-advanced"><summary>Технические сведения</summary><dl class="ui3-inspector-facts"><dt>Последняя задача</dt><dd id="r6InspectorTask"></dd><dt>Резерв</dt><dd id="r6InspectorReserve"></dd><dt>Наблюдение</dt><dd id="r6InspectorObserved"></dd></dl><p id="r6InspectorAddresses"></p><div class="r5-domains" id="r6InspectorDomains"></div></details>`);
 consoleText('ui3InspectorMessage','');const dialog=$('#ui3ServiceDialog');if(!dialog.open)dialog.showModal();
 interfaceUpdateInspector();$('#ui3InspectorTitle').focus();
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
  if(action==='check'){void interfaceCheckService(id);return;}
  interfaceState.busy=true;b.disabled=true;
  void interfaceManage(id,action==='manage',action==='remove').catch(e=>consoleText('ui3InspectorMessage',e.message)).finally(()=>{interfaceState.busy=false;if(b.isConnected)b.disabled=false;});
 }
});
$('#ui3ServiceSearch').addEventListener('input',e=>{interfaceState.query=e.target.value;renderInterfaceServices(interfaceSummaries());});
function interfaceReturnInspectorFocus(){
 const id=interfaceState.inspector,previous=interfaceState.returnFocus;
 interfaceState.inspector=null;interfaceState.returnFocus=null;
 if(interfaceState.authRevoked||state.currentView!=='services')return;
 // Polling may replace the card while its inspector stays open.
 const target=previous?.isConnected?previous:$$('[data-rz-inspect]').find(button=>button.dataset.rzInspect===id)||$('#ui3ServiceSearch');
 target?.focus({preventScroll:true});
}
$('#ui3ServiceDialog').addEventListener('close',interfaceReturnInspectorFocus);
document.addEventListener('razvilka:auth-required',()=>{interfaceState.authRevoked=true;interfaceState.authEpoch++;interfaceState.busy=false;for(const c of interfaceRequests)c.abort();interfaceRequests.clear();interfaceCloseInspector();consoleSnapshot=null;interfaceHTML('ui3InspectorContent','');renderInterfaceHome({});});
document.addEventListener('razvilka:auth-restored',()=>{interfaceState.authRevoked=false;renderInterfaceHome(interfaceSummaries());});
document.addEventListener('click',interfaceTaskAction);
function interfaceSafeRender(key, callback){
 state.uiRenderIssues ||= {};
 try{callback();delete state.uiRenderIssues[key];return true;}
 catch(_){state.uiRenderIssues[key]='Этот блок временно не обновился. Остальные разделы доступны.';return false;}
}

function interfaceScopeLabel(service){
 const applied=serviceDashboardApplied(service),sources=Array.isArray(applied.sources)?applied.sources:Array.isArray(service.applied_sources)?service.applied_sources:[];
 return !applied.enabled?'Ещё не применены':sources.length?`Адреса и сети: ${sources.length}`:applied.all_lan===true?'Все устройства локальной сети':'Область устройств — в применённом плане';
}

function interfaceInspectorControls(service){
 const managed=consoleSnapshot?.services?.[service.id];
 const setup=consoleSnapshot?.policy?.setup_complete===true&&!consoleAutonomyError;
 if(!setup)return '<button type="button" class="secondary" data-rz-action="setup">Настроить автопилот</button>';
 if(managed?.removing)return '<span role="status">Снятие подключения уже в очереди.</span>';
 const disabled=interfaceState.busy?' disabled':'';
 return `<button type="button" class="secondary" data-rz-action="${managed?.enabled?'pause':'manage'}" data-rz-focus="inspector-control-${esc(service.id)}"${disabled}>${managed?.enabled?'Пауза автоподбора':managed?'Возобновить автоподбор':'Включить автоподбор'}</button>`;
}

// UI polling renders data only; all checks and maintenance remain server jobs.
renderInterface();
