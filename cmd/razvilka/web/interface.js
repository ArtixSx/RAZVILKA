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
  if(route.startsWith('sing-box:')){const id=route.slice(9);const node=(state.nodes?.nodes||[]).find(n=>n.id===id);if(node)return typeof nodeDisplayName==='function'?nodeDisplayName(node):node.name||'Узел Sing-box';return 'Подключение Sing-box';}
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
 const excluded=typeof interfaceExclusionMap==='function'?interfaceExclusionMap():{};
 const available=!interfaceState.authRevoked&&!['error','busy'].includes(state.dataLoad?.services?.phase)&&(!state.resourceExclusions||state.dataLoad?.resourceExclusions?.phase==='ready');
 const value=rim.humanService(original,summaries?.[service.id]||{},managed,runtime,available,excluded[service.id]||[]);
 if(!value.excluded&&managed?.enabled===true&&!running)value.control=auto.state==='unknown'?'Состояние автоподбора не получено':auto.state==='paused'?'Автоподбор на общей паузе':'Автоподбор ограничен общей настройкой';
 return value;
}

function interfaceBadge(summary){return `<span class="ui3-status ${esc(summary.kind||'unknown')}"><i></i>${esc(summary.label||'Не проверен')}</span>`;}
function interfaceServiceCard(s,summaries,compact=false){
 if(s.presentation_only)return `<article class="ui3-service-card r5-service-card" data-rz-card="${esc(s.id)}"><div class="ui3-service-card-top"><span class="ui3-service-icon">${consoleServiceIcon(s)}</span><div class="ui3-service-name"><h4>${esc(s.name)}</h4><span>${esc(rim.category(s))}</span></div></div><div class="ui3-card-state"><span class="ui3-status unknown">Сохранённые настройки</span></div><p class="r5-service-description">Свежая доступность пока неизвестна</p><details class="r5-advanced"><summary>Выбранные настройки</summary><p>${(s.desired_state?.enabled ?? s.enabled)?'Включён':'Выключен'} · ${esc(interfaceRouteName(s.route))}</p><p>Устройства: ${s.sources?.length?esc(s.sources.join(', ')):'Все устройства в сохранённой области LAN'}</p><p>Эти данные не подтверждают действующий маршрут.</p></details><div class="ui3-card-footer"><small>Ожидаем обновления состояния</small></div></article>`;
 const h=interfaceServicePresentation(s,summaries);
 const ready=consoleSnapshot?.policy?.setup_complete===true&&!consoleAutonomyError;
 const action=h.excluded?'<button type="button" class="secondary" data-rz-nav="exclusions">Исключения</button>':h.member
   ?`<button type="button" class="secondary" data-rz-inspect="${esc(s.id)}" data-rz-focus="service-${esc(s.id)}">Открыть</button>`
   :`<button type="button" class="primary" data-r5-add="${esc(s.id)}" data-rz-focus="service-${esc(s.id)}" ${interfaceState.busy?'disabled':''}>${ready?'Добавить':'Начать настройку'}</button>`;
 return `<article class="ui3-service-card r5-service-card ${h.member?'':'not-selected'}" data-rz-card="${esc(s.id)}"><div class="ui3-service-card-top"><span class="ui3-service-icon tone-${rim.category(s)==='ИИ-сервисы'?'violet':s.id==='youtube'?'rose':'teal'}">${consoleServiceIcon(s)}</span><div class="ui3-service-name"><h4>${esc(s.name)}</h4><span>${esc(rim.category(s))}</span></div></div><div class="ui3-card-state">${interfaceBadge(h)}${h.pendingLabel&&h.pendingLabel!==h.label?`<span class="ui3-pending-dot">${esc(h.pendingLabel)}</span>`:''}</div><p class="r5-service-description">${esc(h.member||h.excluded?h.control:'Доступ по выбранным правилам автопилота')}</p><div class="ui3-card-route"><span>${h.excluded?'Прежнее назначение':'Подключение'}</span><b>${esc(h.route?interfaceRouteName(h.route):'Пока не назначено')}</b></div><div class="ui3-card-footer"><small>${h.excluded?'Исключение сохранено':h.applied?'Настройки применены':'Применение не подтверждено'}</small>${action}</div></article>`;
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
function interfaceRecoveryRequired(){
 return !interfaceState.authRevoked&&state.authenticated===true&&state.panelAvailability?.kind==='responding'&&state.panelAvailability.admission?.state==='recovery-required';
}
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
   sub.hidden=false;interfaceHTML('interfaceSubnav',`<button type="button" data-rz-nav="settings">← Настройки</button><span class="r5-location">${esc(nav.pageTitle)}</span>`);
 }else{
   sub.hidden=group.children.length<2;
   if(!sub.hidden)interfaceHTML('interfaceSubnav',group.children.map(([id,label])=>`<button type="button" data-rz-nav="${esc(id)}" ${id===view?'aria-current="page" class="active"':''}>${esc(label)}</button>`).join(''));
 }
}

function interfaceHomeAuto(ready){
 const recovery=interfaceRecoveryRequired();
 const known=ready&&!consoleAutonomyError,auto=recovery?{state:'recovery',title:'Нужно восстановление',detail:'Панель отвечает. Чтение состояния и изменения приостановлены до проверки журнала. Работа обходов пока не подтверждена.',action:'Открыть диагностику',target:'diagnostics',tone:'warn'}:rim.humanAuto(consoleSnapshot,state.status,known),p=known?consoleSnapshot?.policy:null;
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

// Problems first: a failed check, then work the autopilot is doing, then
// other unconfirmed states; working services last.
function interfaceHomeOrder(rows){
 const rank=h=>h.kind==='bad'?0:h.progress?1:h.kind==='warn'?2:h.kind==='good'?4:3;
 return rows.slice().sort((a,b)=>rank(a)-rank(b)||String(a.service.name||'').localeCompare(String(b.service.name||''),'ru'));
}
function interfaceHomeServicesHTML(members,fresh){
 const heading=`<div class="ui3-section-heading"><h3>Ваши сервисы</h3><button type="button" class="text-button" data-r42-services="selected">Все сервисы ${ci('chevron')}</button></div>`;
 if(!members.length)return heading+'<p>Здесь будут выбранные вами сайты и приложения, а не список технических движков.</p>';
 const sorted=interfaceHomeOrder(members),problems=sorted.filter(h=>h.kind!=='good');
 const shown=sorted.slice(0,Math.max(8,problems.length)),hidden=sorted.length-shown.length;
 const works=n=>n%10===1&&n%100!==11?'работает':'работают';
 const tally=fresh?[[sorted.filter(h=>h.kind==='good').length,works,'good'],[sorted.filter(h=>h.progress).length,()=>'в работе автопилота','progress'],[sorted.filter(h=>h.kind==='bad').length,n=>'не '+works(n),'bad'],[sorted.filter(h=>h.kind!=='good'&&h.kind!=='bad'&&!h.progress).length,()=>'без подтверждения','warn']].filter(([n])=>n>0):[];
 const kind=h=>h.progress?'progress':h.kind||'unknown';
 const line=h=>h.kind==='good'?(h.route?interfaceRouteName(h.route):''):(h.detail||(h.route?interfaceRouteName(h.route):''));
 const row=h=>`<button type="button" class="r5-home-service" data-kind="${esc(kind(h))}" data-rz-inspect="${esc(h.service.id)}"><span class="r5-home-service-text"><b>${esc(h.service.name)}</b>${line(h)?`<small>${esc(line(h))}</small>`:''}</span>${interfaceBadge({...h,kind:kind(h)})}</button>`;
 return `${heading}${tally.length?`<div class="r5-home-tally">${tally.map(([n,label,k])=>`<span data-kind="${k}"><b>${n}</b> ${label(n)}</span>`).join('')}</div>`:''}<div class="r5-home-services">${shown.map(row).join('')}</div>${hidden>0?`<button type="button" class="text-button r5-home-more" data-r42-services="selected">Ещё ${hidden} ${works(hidden)} ${ci('chevron')}</button>`:''}`;
}

function refreshHomeEngineSummary(){
 const loaded=state.authenticated===true&&!interfaceState.authRevoked&&interfaceDataReady('services');
 const fresh=loaded&&!['error','busy'].includes(state.dataLoad?.services?.phase);
 renderHomeEngineSummary(interfaceSummaries(),loaded,fresh);
}

function renderHomeEngineSummary(summaries,loaded,fresh){
 const exclusions=typeof interfaceExclusionMap==='function'?interfaceExclusionMap():{};
 const currentSummaries=Object.fromEntries(Object.entries(summaries||{}).filter(([id])=>!exclusions[id]));
 const auto=rim.humanAuto(consoleSnapshot,state.status,!consoleAutonomyError).state==='enabled';
 const usage=rim.engineUsage(loaded?state.services:[],fresh?currentSummaries:{},auto?consoleSnapshot?.services||{}:{},fresh&&auto?consoleSnapshot?.runtime||{}:{});
 const known=state.authenticated===true&&interfaceDataReady('inventory');
 const unavailable=interfaceRecoveryRequired()?'Сведения о компонентах недоступны до проверки журнала. Их состояние пока неизвестно.':'Сведения о компонентах ещё загружаются. Это не означает, что обходы остановлены.';
 const rows=Object.entries(consoleEngineMeta).filter(([id])=>known||usage[id]);
 interfaceHTML('ui7HomeEngines',`<div class="ui3-section-heading"><h3>Обходы и сервисы</h3><button type="button" class="text-button" data-rz-nav="engines">Управление ${ci('chevron')}</button></div>${!known?`<p class="r5-caption">${unavailable}</p>`:''}<div class="ui7-engine-summary">${rows.map(([id,meta])=>{const info=consoleEngineState(id),n=usage[id]||{assigned:0,verified:0};return `<button class="ui7-engine-row" type="button" data-console-engine="${esc(id)}"><span class="engine-mini-icon ${meta.tone}">${ci(meta.icon)}</span><span><b>${esc(meta.name)}</b><small>${esc(info.label)}</small></span><span class="ui7-engine-count"><b>${loaded?n.assigned:'—'}</b><small>назначено${fresh&&n.assigned?` · ${n.verified} проверено`:''}</small></span>${ci('chevron')}</button>`;}).join('')}</div><p class="r5-caption">Считаются применённые назначения. Запущенный процесс сам по себе не подтверждает доступ.</p>`);
}

function renderInterfaceHome(summaries){
 const ready=!interfaceState.authRevoked&&state.authenticated===true;
 const loaded=ready&&interfaceDataReady('services');
 const fresh=loaded&&!['error','busy'].includes(state.dataLoad?.services?.phase);
 const list=loaded?(state.services||[]):[];
 const exclusions=typeof interfaceExclusionMap==='function'?interfaceExclusionMap():{};
 const counts=rim.humanCounts(list,summaries,consoleSnapshot?.services||{},rim.humanAuto(consoleSnapshot,state.status,!consoleAutonomyError).state==='enabled'?consoleSnapshot?.runtime||{}:{},fresh&&(!state.resourceExclusions||state.dataLoad?.resourceExclusions?.phase==='ready'),exclusions);
 const resourceListKnown=typeof resourceExclusionsSupported==='function'&&resourceExclusionsSupported();
 consoleText('ui3HomeCount',loaded?counts.selected:'—');consoleText('ui3NavCount',loaded?counts.selected:'—');
 interfaceHomeAuto(ready);
 renderHomeEngineSummary(summaries,loaded,fresh);
 interfaceHTML('ui3HealthBanner',`<div class="r5-counts"><div><strong>${loaded?counts.selected:'—'}</strong><span>${resourceListKnown?'В сохранённом списке обхода':'Добавлено сервисов'}</span></div><div><strong>${fresh?counts.good:'—'}</strong><span>Работают по проверке</span></div><div><strong>${fresh?counts.unconfirmed:'—'}</strong><span>Без подтверждения</span></div></div><p class="r5-caption">${resourceListKnown?`Без обхода: ${Object.keys(exclusions).length} сервисов. Считаются сохранённые записи, применение исключений ещё не подтверждено. `:''}${!loaded?'Получаем сведения о сервисах.':!fresh?'Показан последний список. Свежая доступность пока неизвестна.':counts.selected?'Проверяется конкретный сценарий, а не все функции приложения.':counts.excluded?'Сохранённые сервисы находятся в исключениях.':'Сервисы пока не добавлены. Начните с настройки автопилота.'}</p>`);
 const attention=counts.rows.filter(s=>s.member&&s.actionable).slice(0,3);
 // Without a decision for the owner, still name the services without a
 // confirmed result and what the autopilot is doing with them.
 const waiting=attention.length?[]:interfaceHomeOrder(counts.rows.filter(s=>s.member&&!s.excluded&&s.kind!=='good')).slice(0,3);
 const attentionRow=(h,action)=>`<button type="button" class="r5-attention-row" data-rz-inspect="${esc(h.service.id)}"><span><b>${esc(h.service.name)}</b><small>${esc(action?h.pendingDetail||h.pendingLabel||h.label:`${h.label}. ${h.detail||''}`.trim())}</small></span><span>${action?'Разобраться':'Подробнее'} ${ci('chevron')}</span></button>`;
 interfaceHTML('ui3Attention',`<div class="ui3-section-heading"><h3>Что требует внимания</h3>${ci('activity')}</div>${!fresh?'<p>Нет свежих данных для оценки. Это не означает, что подключения не работают.</p>':attention.length?attention.map(h=>attentionRow(h,true)).join(''):waiting.length?`<p class="r5-caption r5-attention-note">Вашего участия не требуется: автопилот занимается этим сам.</p>${waiting.map(h=>attentionRow(h,false)).join('')}`:`<p>${counts.selected?'В последних проверках проблем не обнаружено.':'После добавления сервисов здесь появятся проблемы, требующие вашего участия.'}</p>`}`);
 interfaceHTML('r42RouteDistribution',interfaceHomeServicesHTML(counts.rows.filter(s=>s.member&&!s.excluded),fresh));
 consoleText('ui3RouterName',ready?state.system?.hostname||'Роутер':'Нет сведений');
 consoleText('ui3RouterMeta',ready?state.system?.architecture||'Платформа не определена':'');
 const m=ready?state.metrics?.latest||{}:{},at=Date.parse(m.timestamp||''),recent=Number.isFinite(at)&&at<=Date.now()&&Date.now()-at<180000;
 const cpu=recent&&m.cpu_ready===true?rim.finitePercent(m.cpu_percent):null;
 const ram=recent&&Number.isFinite(m.memory_total_bytes)&&m.memory_total_bytes>0?rim.finitePercent(m.memory_used_percent):null;
 interfaceHTML('ui3Resources',[[cpu,'Процессор'],[ram,'Память']].map(([v,label])=>`<div class="r5-resource"><span>${label}</span><b>${v===null?'Нет свежих данных':Math.round(v)+'%'}</b></div>`).join(''));
 const p=ready&&!consoleAutonomyError&&consoleSnapshot?.policy?.setup_complete?consoleSnapshot.policy:null;
 interfaceHTML('ui3Maintenance',`<h3>Обслуживание</h3><p>${p?`Приложение: ${p.application?.mode==='install'?'автоустановка':p.application?.mode==='prepare'?'подготовка':p.application?.mode==='check'?'проверка':'выключено'}. Компоненты: ${p.components?.mode==='install'?'автообновление':p.components?.mode==='check'?'проверка':'выключено'}. Результаты проверяются отдельно.`:'Расписание выбирается при настройке автопилота. До завершения мастера оно не считается настроенным.'}</p><button class="text-button" type="button" data-rz-nav="updates">Обновления ${ci('chevron')}</button>`);
 const events=ready&&Array.isArray(state.audit?.events)?state.audit.events.slice(0,3):[];
 interfaceHTML('ui3HomeEvents',events.length?events.map(e=>{const result=typeof projectLogEventResult==='function'?projectLogEventResult(e):{label:'Результат не уточнён'};const title=typeof projectLogAction==='function'?projectLogAction(e)+(e.outcome==='failed'?' · ошибка':e.outcome==='denied'?' · отказ':''):consoleAuditTitle(e);return `<div class="ui3-event"><div><strong>${esc(title)}</strong><small>${esc(result.label)}</small></div><time>${esc(consoleDate(e.timestamp))}</time></div>`;}).join(''):'<p class="r5-caption">Действия появятся после настройки. Принятое задание не равно завершённому.</p>');
}

function renderInterfaceServices(summaries){
 if(!interfaceDataReady('services')){
  consoleText('ui3CatalogSummary','Список ещё не получен');
  interfaceHTML('ui3ServiceCatalog',interfaceEmpty('Получаем список сервисов',interfaceLoadMessage('services'),'<button type="button" class="secondary" data-panel-refresh>Повторить загрузку</button>'));
  return;
 }
 const all=interfaceServices(),isCatalog=interfaceState.filter==='all',isExcluded=interfaceState.filter==='excluded';
 const exclusionMap=typeof interfaceExclusionMap==='function'?interfaceExclusionMap():{};
 const exclusionsReady=typeof resourceExclusionsSupported==='function'&&resourceExclusionsSupported();
 if($('#resourceBypassTab'))$('#resourceBypassTab').textContent=exclusionsReady?'Обходить':'Мои сервисы';
 if($('#resourceExcludedTab'))$('#resourceExcludedTab').hidden=!exclusionsReady;
 $('#ui3ServiceCatalog').classList.toggle('ui3-list-layout',interfaceState.layout==='list');
 $('#serviceList').classList.toggle('r41-grid',interfaceState.layout!=='list');
 $$('[data-rz-layout]').forEach(e=>{const on=e.dataset.rzLayout===interfaceState.layout;e.classList.toggle('active',on);e.setAttribute('aria-pressed',String(on));});
 const categories=[...new Set(all.map(rim.category))].sort((a,b)=>a.localeCompare(b,'ru'));
 interfaceHTML('ui3CategoryFilters',[['','Все категории'],...categories.map(c=>[c,c])].map(([v,t])=>`<button type="button" class="${v===interfaceState.category?'active':''}" aria-pressed="${v===interfaceState.category}" data-rz-category="${esc(v)}">${esc(t)}</button>`).join(''));
 const normalised={};for(const s of all)normalised[s.id]=interfaceServicePresentation(s,summaries);
 const list=rim.filterServices(interfaceState.filter==='selected'?all.filter(s=>!exclusionMap[s.id]):all,{query:interfaceState.query,scope:interfaceState.filter,category:interfaceState.category},normalised);
 const counts=rim.humanCounts(state.services||[],summaries,consoleSnapshot?.services||{},rim.humanAuto(consoleSnapshot,state.status,!consoleAutonomyError).state==='enabled'?consoleSnapshot?.runtime||{}:{},!['error','busy'].includes(state.dataLoad?.services?.phase)&&(!state.resourceExclusions||state.dataLoad?.resourceExclusions?.phase==='ready'),exclusionMap);
 $('#ui3CategoryFilters').hidden=isExcluded||!isCatalog&&counts.selected<=8&&!interfaceState.category;
 consoleText('ui3CatalogSummary',exclusionsReady?`Сохранённый список: ${counts.selected} для обхода · Без обхода: ${Object.keys(exclusionMap).length} сервисов`:`${isCatalog?'Каталог':'Ваш список'}: ${list.length} · Добавлено: ${counts.selected}${['error','busy'].includes(state.dataLoad?.services?.phase)?' · Показаны последние данные':''}`);
 const title=interfaceState.filter==='attention'?'Нет сервисов, требующих проверки':interfaceState.filter==='selected'&&!counts.selected?'Добавьте нужные сервисы':'Ничего не найдено';
 const hint=interfaceState.filter==='selected'&&!counts.selected?'Откройте каталог, выберите сайт и нажмите «Добавить».':'Попробуйте другое название или сбросьте фильтры.';
 interfaceHTML('ui3ServiceCatalog',isExcluded&&typeof resourceExclusionsServicesHTML==='function'?resourceExclusionsServicesHTML(interfaceState.query):list.length?interfaceCards(list,summaries,'catalog'):interfaceEmpty(title,hint,'<button type="button" class="secondary" data-rz-reset-filters>Открыть каталог</button>'));
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
// These receipts describe completed UI requests; they grant no routing authority.
// Keep only public identity/typed outcomes, never config content or review tokens.
const engineProgressEvidence = new Map();
function engineProgressBinding(engineID,fileID='main') {
 const engine=state.engineConfigs?.find(item=>item.id===engineID),file=engine?.files?.find(item=>item.id===fileID);
 const component=state.components?.find(item=>item.id===engineID),runtime=state.engines?.find(item=>item.id===engineID);
 const revisions=[state.status?.revision,state.serviceControl?.config_revision].filter(value=>value!=null);
 if(!revisions.length||revisions.some(value=>!Number.isSafeInteger(value)||value<0))return null;
 const revision=Math.max(...revisions);
 const loaded=state.engineLoaded,loadedSame=loaded?.engine_id===engineID&&loaded.file_id===fileID;
 // FileView.sha256 is the live hash, even when a draft exists. Never bind a
 // staged validation to that live hash; use the actual Stage/read receipt.
 const sha256=file?.staged?(loadedSame&&loaded.source==='staged'?loaded.sha256:''):file?.sha256||(loadedSame&&loaded.source==='live'?loaded.sha256:'');
 if(!file||!/^[a-f0-9]{64}$/.test(sha256||'')||state.authenticated===false||typeof interfaceState!=='undefined'&&interfaceState.authRevoked)return null;
 return {engineID,fileID,sha256,staged:file.staged===true,revision,auth:state.authGeneration||0,requestedAt:Date.now(),
   profileGeneration:file.staged?file.staged_at||'':file.modified_at||'',
   generation:Number.isSafeInteger(state.nodes?.generation)?state.nodes.generation:null,network:state.nodes?.network_profile||'',
   installed:JSON.stringify([runtime?.binary_path||'',component?.installed_version||runtime?.version||'',component?.installed===true,runtime?.installed===true])};
}
function engineProgressSame(before,after,allowCommitted=false) {
 return !!before&&!!after&&['engineID','fileID','sha256','revision','auth','generation','installed'].every(key=>before[key]===after[key])
   &&(allowCommitted||before.staged===after.staged&&before.profileGeneration===after.profileGeneration)&&(!before.network||!after.network||before.network===after.network);
}
function invalidateEngineProgress(engineID='') {
 if(engineID)engineProgressEvidence.delete(engineID);else engineProgressEvidence.clear();
}
function refreshEngineProgressCards() {
 if(typeof renderInterfaceEngines!=='function'||!['engines','engineconfig'].includes(state.currentView))return;
 try{renderInterfaceEngines();}catch(_){/* A card render cannot change an operation outcome. */}
}
function engineProgressFormat(binding,result) {
 if(!binding)return;
 const current=engineProgressBinding(binding.engineID,binding.fileID);
 if(!engineProgressSame(binding,current)||result?.engine_id!==binding.engineID||result.file_id!==binding.fileID||result.ok!==true){invalidateEngineProgress(binding.engineID);return;}
 const old=engineProgressEvidence.get(binding.engineID),entry=engineProgressSame(old?.binding,current,true)?old:{};
 engineProgressEvidence.set(binding.engineID,{...entry,binding:current,format:{native:result.native===true,until:Date.now()+120000}});
}
function engineProgressProbe(binding,result,serviceID) {
 if(!binding)return;
 const current=engineProgressBinding(binding.engineID,binding.fileID),rows=(result?.results||[]).filter(row=>row.service_id===serviceID&&row.route===binding.engineID);
 const positive=rows.length>0&&rows.every(row=>{
   const proof=row.evidence_v2,exact=(expected,observed)=>!expected&&!observed||!!expected&&expected===observed;
   return row.status==='pass'&&row.verdict==='PASS'&&row.route_confirmed===true
     &&row.evidence_level==='service-confirmed'&&row.outcome==='service_accepted'&&!row.error_code&&!row.route_proof_error&&!row.negative_control_matched
     &&exact(row.expected_route_path_id,row.observed_route_path_id)
     &&proof?.schema_version===2&&proof.probe_id&&proof.service===serviceID&&proof.engine===binding.engineID&&proof.route_path_id
     &&proof.verdict==='PASS'&&proof.outcome==='service_accepted'&&!proof.error_code&&!proof.route_proof_error&&!proof.negative_control_matched
     &&exact(proof.expected_route_path_id,proof.observed_route_path_id)
     &&current?.network&&row.network_profile_id===current.network&&proof.network_profile===current.network
     &&Date.parse(proof.started_at)>=binding.requestedAt-1000&&Date.parse(proof.started_at)<=Date.parse(proof.finished_at)
     &&Date.parse(proof.finished_at)===Date.parse(row.checked_at)&&Date.parse(row.checked_at)<=Date.now()
     &&Date.parse(row.checked_at)<Date.parse(row.evidence_fresh_until)&&Date.parse(row.evidence_fresh_until)>Date.now();
 });
 // The route checker observes the installed profile, never an unapplied draft.
 if(!engineProgressSame(binding,current)||binding.staged||!positive){invalidateEngineProgress(binding.engineID);return;}
 const old=engineProgressEvidence.get(binding.engineID),entry=engineProgressSame(old?.binding,current)?old:{};
 engineProgressEvidence.set(binding.engineID,{...entry,binding:current,service:{serviceID,network:rows[0].network_profile_id,checkedAt:Math.max(...rows.map(row=>Date.parse(row.checked_at))),
   until:Math.min(Date.now()+120000,...rows.map(row=>Date.parse(row.evidence_fresh_until)))}});
}
function engineProgressApply(binding,preview,result) {
 if(!binding)return;
 const current=engineProgressBinding(binding.engineID,binding.fileID),transaction=result?.transaction,execution=result?.execution;
 const digest=preview?.review?.reviewed_digest;
 const routes=(transaction?.routes||[]).filter(route=>(route.resolved||route.route)===binding.engineID||(route.resolved||route.route||'').startsWith(binding.engineID+':'));
 const matched=engineProgressSame(binding,current,true)&&result?.ok===true&&result.live_applied===true&&!result.safe_mode&&!result.scope_pending_changes
   &&typeof digest==='string'&&digest&&preview.transaction?.digest===digest&&transaction?.digest===digest
   &&transaction.plan_id===execution?.plan_id&&execution.digest===digest&&execution.state==='committed'&&!execution.error
   &&preview.review.expected_revision===binding.revision&&transaction.revision===binding.revision
   &&Date.parse(execution.started_at)>=binding.requestedAt-1000&&Date.parse(execution.started_at)<=Date.parse(execution.finished_at)
   &&Date.parse(execution.finished_at)<=Date.now()&&Date.parse(execution.finished_at)>Date.now()-120000
   &&transaction.adapters?.includes(binding.engineID)&&routes.length>0&&routes.every(route=>(state.services||[]).some(service=>{
     const applied=serviceDashboardApplied(service);return service.id===route.service_id&&applied.enabled&&applied.route===(route.resolved||route.route);
   }));
 if(!matched){invalidateEngineProgress(binding.engineID);return;}
 const old=engineProgressEvidence.get(binding.engineID),entry=engineProgressSame(old?.binding,current,true)?old:{};
 // Services may still contain a fresh test of the previous installed profile.
 // A committed Apply is not a new service probe: require an explicit fresh test.
 engineProgressEvidence.set(binding.engineID,{...entry,binding:current,
   service:null,
   apply:{digest,routes:routes.map(route=>({serviceID:route.service_id,route:route.resolved||route.route})),until:Date.parse(execution.finished_at)+120000}});
}
function engineProgressView(engineID,fileID='main') {
 const current=engineProgressBinding(engineID,fileID),entry=engineProgressEvidence.get(engineID);
 const stopped=state.serviceControl?.runtime_state==='stopped'||state.status?.dataplane_state==='stopped'||typeof workspaceControl!=='undefined'&&workspaceControl.stopReceipt;
 const pending=state.engineIntent?.engineID===engineID||state.componentOperation?.id===engineID||typeof workflowState!=='undefined'&&workflowState.probe?.engine===engineID||state.selectedEngine===engineID&&state.engineEditorDirty
   ||['running','queued','canceling','interrupted'].includes(state.serviceControl?.durable_jobs?.find(job=>['service-stop','service-resume'].includes(job.mode))?.state)
   ||state.dataLoad?.engineConfigs?.phase==='busy'||state.dataLoad?.status?.phase==='busy';
 const negative=state.status?.last_apply_failure||['requires-review','network-stale','revalidating'].includes(state.status?.node_recovery?.state)
   ||state.dataLoad?.engineConfigs?.phase==='error'||state.dataLoad?.status?.phase==='error'
   ||typeof inventoryObservationStale==='function'&&inventoryObservationStale();
 if(!entry||stopped||negative){if(entry)invalidateEngineProgress(engineID);return {format:false,service:false,apply:false};}
 if(pending)return {format:false,service:false,apply:false};
 if(!engineProgressSame(entry.binding,current)){invalidateEngineProgress(engineID);return {format:false,service:false,apply:false};}
 const newerNegative=(state.services||[]).some(service=>{
   const observed=service.observed_state;
   return service.id===entry.service?.serviceID&&(observed?.route===engineID||observed?.route?.startsWith(engineID+':'))
     &&Date.parse(observed.checked_at)>=entry.service.checkedAt&&(observed.status!=='pass'||observed.level!=='service-confirmed'||observed.outcome!=='service_accepted');
 });
 if(newerNegative){invalidateEngineProgress(engineID);return {format:false,service:false,apply:false};}
 const format=!!(entry.format?.until>Date.now()),service=!!(entry.service?.until>Date.now()&&(!current.network||!entry.service.network||entry.service.network===current.network)&&!newerNegative);
 const applied=!!(entry.apply?.until>Date.now()&&!current.staged&&state.status?.dataplane_state==='committed'&&state.status?.live_active===true
   &&entry.apply.routes.every(route=>(state.services||[]).some(service=>{const applied=serviceDashboardApplied(service);return service.id===route.serviceID&&applied.enabled&&applied.route===route.route;})));
 return {format,service,apply:applied,native:format&&entry.format.native};
}
function engineWorkflowPresentation(id,info=consoleEngineState(id)) {
 const files=info.config?.files||[],active=state.selectedEngine===id;
 const file=(active&&files.find(file=>file.id===state.selectedEngineFile))||files.find(file=>file.id==='main')||files[0];
 const used=(state.services||[]).filter(service=>{const applied=serviceDashboardApplied(service);return applied.enabled&&(applied.route===id||applied.route?.startsWith(id+':'));});
 const binaryDetected=info.engine?.installed===true&&typeof info.engine.binary_path==='string'&&info.engine.binary_path.trim().length>0;
 const progress=engineProgressView(id,file?.id||'main'),checked=progress.format&&progress.service;
 const dirty=active&&state.engineEditorDirty===true;
 const complete={install:binaryDetected&&!info.observationStale,profile:progress.format,check:checked,apply:progress.apply};
 const steps=[['install','Установка',info.observationStale?'Сведения устарели':binaryDetected?'Бинарник обнаружен':info.installed?'Есть сведения об установке; бинарник не уточнён':info.installedKnown?'Требуется компонент':'Состояние не прочитано'],['profile','Профиль',dirty?'Есть несохранённые изменения':progress.format?'Текущий профиль прошёл проверку формата':file?.staged?'Есть подготовленные изменения':file?.exists?'Файл есть; содержимое требует проверки':'Профиль ещё не подтверждён'],['check','Проверки',`Формат: ${progress.format?(progress.native?'проверен утилитой обхода':'прошёл предварительную проверку'):'не подтверждён'}. Сервис: ${progress.service?'свежий веб-сценарий подтверждён':file?.staged?'проверяется после применения подготовленного профиля':'нужна отдельная проверка'}`],['apply','Применение',progress.apply?'Получено совпадающее подтверждение применения':file?.staged&&progress.format?'Формат проверен. Примените подготовленный профиль, затем проверьте сервис.':used.length?`Сохранённых назначений: ${used.length}`:'Назначения ещё не подтверждены']];
 // A web probe observes the live profile. Do not hold a validated staged file
 // behind that probe; Apply first, then require a fresh post-Apply service test.
 const next=!complete.install?'install':dirty||!file?.exists&&!file?.staged?'profile':file?.staged&&progress.format?'apply':!checked?'check':'apply';
 return {file,used,binaryDetected,progress,checked,complete,steps,next,current:steps.find(([step])=>step===next)};
}
function engineWorkflowSummary(id) {
 const workflow=engineWorkflowPresentation(id);
 return workflow.steps.map(([step,title,detail])=>`<div data-engine-workspace-progress="${step}" class="${workflow.complete[step]?'confirmed':''}"><span>${ci(workflow.complete[step]?'check':'clock')}</span><section><b>${esc(title)}</b><small>${esc(detail)}</small></section></div>`).join('');
}
function interfaceEngineCard(id,meta){
 const info=consoleEngineState(id),component=info.component,update=consoleEngineUpdateState(info);
 const workflow=engineWorkflowPresentation(id,info),used=workflow.used;
 const recoveryBlocked=typeof componentRecoveryFence==='function'&&componentRecoveryFence();
 const busy=!!state.componentOperation||!!state.componentRefreshRequest||component?.operation_status==='running'||recoveryBlocked;
 const stale=['failed','checking'].includes(update.kind);
 const protectedComponent=component?.lifecycle_block_reason||component?.external_owner||info.running||used.length>0;
 const lifecycleAllowed=component&&!busy&&!component.inventory_error&&!protectedComponent&&!info.observationStale;
 // NFQWS2 is updated while its routes run: checked on the router and rolled back on failure.
 const managedUpdate=component?.managed_update===true&&!component.external_owner&&!component.lifecycle_block_reason;
 const updateAllowed=managedUpdate?component&&!busy&&!component.inventory_error&&!info.observationStale&&component.rollback_ready===true:lifecycleAllowed;
 const disabledReason=recoveryBlocked?'Прочитайте журнал обновления и завершите соответствующее восстановление.':managedUpdate&&component.update_available&&!component.rollback_ready?'Нажмите «Проверить версии»: RAZVILKA сохранит копию текущей версии для отката.':component?.lifecycle_block_reason||(component?.external_owner?'Компонент управляется внешним проектом.':info.running||used.length?'Сначала остановите обход и перенесите зависимые сервисы на другой маршрут.':stale?'Обновите сведения о пакете перед изменением.':busy?'Дождитесь завершения операции.':'Нет разрешения на действие в каталоге компонентов.');
 const action=(name,label,allowed)=>`<button type="button" class="${name==='remove'?'component-remove':'primary'} component-action" data-component="${esc(id)}" data-component-action="${name}" data-rz-focus="engine-${esc(id)}-${name}" ${allowed?'':`disabled title="${esc(disabledReason)}"`}>${label}</button>`;
 const install=info.installed?'':action('install','Установить',lifecycleAllowed&&!stale&&component?.can_install===true);
 let actions='';
 if(info.installed&&component?.update_available)actions+=action('update',managedUpdate?'Обновить с проверкой':'Обновить',updateAllowed&&!stale&&component.can_update===true);
 if(info.installed)actions+=action('remove','Удалить',lifecycleAllowed&&component.can_remove===true);
 const {file,binaryDetected,progress,checked,complete,steps,next,current}=workflow;
 const installationStep=info.installed?(complete.install?'':`<button type="button" class="secondary" data-component-refresh="${esc(id)}" data-rz-focus="engine-${esc(id)}-installation-read" ${busy?'disabled':''}>Уточнить установку</button>`):install;
 const stepAction=step=>step==='install'?installationStep:`<button type="button" class="secondary" data-engine-step="${step}" data-card-engine="${esc(id)}" data-rz-focus="engine-${esc(id)}-${step}" ${state.engineIntent?'disabled':''}>Открыть ${step==='profile'?'профиль':step==='check'?'проверки':'применение'}</button>`;
 const flow=`<ol class="ui3-engine-progress" aria-label="Этапы настройки ${esc(meta.name)}">${steps.map(([step,title],index)=>`<li data-engine-progress="${step}" ${complete[step]?'data-completed="true"':''} ${step===next&&!complete[step]?'aria-current="step"':''}><span>${complete[step]?'✓':index+1}</span><b>${title}${complete[step]?' · подтверждено':''}</b></li>`).join('')}</ol><div class="ui3-engine-next"><div><b>${progress.apply&&checked?'Проверка и применение подтверждены':steps.indexOf(current)+1+'. '+current[1]}</b><small>${esc(current[2])}</small></div>${stepAction(next)}</div><details class="ui3-engine-flow-details" data-engine-disclosure="${esc(id)}-flow"><summary data-rz-focus="engine-${esc(id)}-flow">Все шаги настройки</summary><ol class="ui3-engine-workflow">${steps.map(([step,title,text],index)=>`<li><b>${index+1}. ${title}</b><small>${esc(text)}</small>${step===next?'':stepAction(step)}</li>`).join('')}</ol></details>`;
 const operation=state.componentOperation?.id===id?state.componentOperation.action:component?.operation_status==='running'?component.operation_action:'';
 const settledReceipt=info.recovery && ['accepted','accepted-installed-idle','rolled-back','abandoned'].includes(info.recovery.transaction?.phase);
 const operationText=settledReceipt&&component?.operation_status==='running'?'Журнал завершён; серверная отметка операции ещё требует обновления.':operation?({install:'Установка выполняется…',update:'Обновление выполняется…',remove:'Удаление выполняется…'})[operation]||'Операция выполняется…':['failed','interrupted','receipt-error'].includes(component?.operation_status)?'Последняя операция не завершена: '+(component.operation_message||'откройте подробности компонента'):'';
 return `<article class="ui3-engine-card" data-engine-card="${esc(id)}"><div class="ui3-engine-card-heading"><span class="engine-mini-icon ${meta.tone}">${ci(meta.icon)}</span><span class="ui3-status ${info.tone}"><i></i>${esc(info.label)}</span></div><h3>${esc(meta.name)} <span class="ui3-engine-version ${update.kind==='update'?'has-update':''}">${esc(consoleEngineVersionLabel(info))}</span></h3><span class="ui3-engine-subtitle">${esc(meta.subtitle)}</span><p>${esc(meta.description)}</p><div class="ui3-engine-meta"><span>${info.observationStale?'Ожидаем свежие сведения':info.installed?(info.running?'Процесс запущен':'Процесс не запущен'):info.installedKnown?'Процесс не обнаружен':'Нет данных о процессе'}</span><b>${used.length} сервисов</b></div><small class="ui3-engine-update ${update.kind}" role="status">${esc(update.text)}</small>${operationText?`<small class="ui3-engine-operation" role="status">${esc(operationText)}</small>`:''}${flow}${typeof managedNFQBundleCard === 'function' ? managedNFQBundleCard(id) : ''}<details class="ui3-engine-maintenance" data-engine-disclosure="${esc(id)}-maintenance"><summary data-rz-focus="engine-${esc(id)}-maintenance">Версии и обслуживание</summary>${state.inventoryObservation?`<small class="ui3-engine-observed">Состояние на ${esc(consoleDate(state.inventoryObservation.observedAt))}</small>`:''}<div class="ui3-engine-actions"><button type="button" class="secondary" data-component-refresh="${esc(id)}" data-rz-focus="engine-${esc(id)}-refresh" title="Обновить общий каталог компонентов" ${busy?'disabled':''}>${state.componentRefreshRequest?'Проверяем…':'Проверить обновления'}</button>${actions}</div>${protectedComponent&&info.installed?`<small class="ui3-engine-action-hint">${esc(disabledReason)}</small>`:''}</details></article>`;
}
function renderInterfaceEngines(){
 if(typeof renderComponentRecovery==='function')renderComponentRecovery();
 if(!interfaceDataReady('engines') && !interfaceDataReady('engineConfigs') && !interfaceDataReady('components')){
   interfaceHTML('ui3EngineGrid',interfaceEmpty('Сведения об обходах загружаются',interfaceLoadMessage('engineConfigs'),'<button type="button" class="secondary" data-panel-refresh>Повторить загрузку</button>'));
   return;
 }
 const grid=$('#ui3EngineGrid'),open=[...grid.querySelectorAll('[data-engine-disclosure][open]')].map(element=>element.dataset.engineDisclosure);
 const focus=grid.contains(document.activeElement)?document.activeElement.closest('[data-rz-focus]')?.getAttribute('data-rz-focus'):null;
 interfaceHTML('ui3EngineGrid',Object.entries(consoleEngineMeta).map(([id,meta])=>interfaceEngineCard(id,meta)).join(''));
 for(const disclosure of grid.querySelectorAll('[data-engine-disclosure]'))disclosure.open=open.includes(disclosure.dataset.engineDisclosure);
 if(focus)[...grid.querySelectorAll('[data-rz-focus]')].find(element=>element.getAttribute('data-rz-focus')===focus)?.focus({preventScroll:true});
 const id=state.selectedEngine,e=consoleEngineState(id);
 interfaceHTML('ui3EngineContext',Object.entries(consoleEngineMeta).map(([k,m])=>`<button type="button" class="${k===id?'active':''}" data-console-engine="${esc(k)}" ${k===id?'aria-current="page"':''}>${ci(m.icon)}${esc(m.name)}</button>`).join(''));
 interfaceHTML('ui3EngineSteps',engineWorkflowSummary(id));
}
async function interfaceOpenEngineStep(id,step){
 if(!['profile','check','apply'].includes(step)||!Object.hasOwn(consoleEngineMeta,id)||interfaceState.authRevoked||$('#authScreen')?.hidden===false)return;
 const epoch=interfaceState.authEpoch,request=interfaceState.engineCardRequest=(interfaceState.engineCardRequest||0)+1;
 if(!await openEngineConfiguration(id)||epoch!==interfaceState.authEpoch||request!==interfaceState.engineCardRequest||state.currentView!=='engineconfig'||state.selectedEngine!==id)return;
 switchEngineTab(step==='check'?'check':'config');
 const format=typeof engineProgressView==='function'&&engineProgressView(id,state.selectedEngineFile||'main').format;
 const target=$('#'+(step==='profile'?'engineFileSelect':step==='check'?(format?'r4ProbeService':'r4Validate'):'engineApplyConfig'));
 if(target?.disabled){showNotice('review','Подготовьте изменения профиля','Применение выполняется после подготовки и проверки выбранного файла. Этот переход не применяет изменения.');$('#engineFileSelect')?.focus({preventScroll:true});}
 else target?.focus({preventScroll:true});
}
document.addEventListener('click',event=>{const button=event.target.closest('[data-engine-step]');if(button&&!button.disabled)void interfaceOpenEngineStep(button.dataset.cardEngine,button.dataset.engineStep).catch(error=>showNotice('review','Шаг не открыт',error.message));});
function renderInterfaceSettings(){
 interfaceHTML('r5SettingsTasks',rim.settingsTasks.map(t=>`<button type="button" class="r5-setting-task" data-rz-nav="${esc(t.target)}">${ci(t.icon)}<span><b>${esc(t.title)}</b><small>${esc(t.detail)}</small></span>${ci('chevron')}</button>`).join(''));
}

function renderInterface(){
 // A failed widget cannot retain a UI operation lock or hide other sections.
 const view=state.currentView||'overview';
 const calls=[['navigation',()=>renderInterfaceNavigation()],['auto-labels',()=>{consoleText('ui3SidebarAuto',interfaceAutoLabel());consoleText('ui3TopAuto',interfaceAutoLabel());}],['workflow',()=>{if(typeof renderWorkflowControls==='function')renderWorkflowControls();}]];
 if(view==='overview')calls.push(['home',()=>renderInterfaceHome(interfaceSummaries())]);
 if(view==='services')calls.push(['services',()=>renderInterfaceServices(interfaceSummaries())]);
 if(view==='exclusions'&&typeof renderResourceExclusions==='function')calls.push(['resource-exclusions',()=>renderResourceExclusions()]);
  if(view==='devices'&&typeof renderListScope==='function')calls.push(['list-scope',()=>renderListScope()]);
 if(view==='engines'||view==='engineconfig')calls.push(['engines',()=>renderInterfaceEngines()]);
 if(view==='settings')calls.push(['settings',()=>renderInterfaceSettings()]);
 if(interfaceState.inspector)calls.push(['inspector',()=>interfaceUpdateInspector()]);
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
 const epoch=interfaceState.authEpoch;
 const requireEpoch=()=>{if(epoch!==interfaceState.authEpoch)throw Object.assign(new Error('Ответ относится к завершённой сессии.'),{name:'AuthGenerationChanged'});};
 const controller=new AbortController();interfaceRequests.add(controller);const timer=setTimeout(()=>controller.abort(),20000);
 try{const value=await api(path,{...options,signal:controller.signal});requireEpoch();return value;}
 catch(e){requireEpoch();if(e.status===401)showAuth(state.status,e.message);if(e.name==='AbortError')throw new Error('Ответ не подтверждён. Проверьте состояние операции перед повтором.');throw e;}
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
  void interfaceManage(id,action==='manage'||action==='confirm-definition',action==='remove').catch(e=>consoleText('ui3InspectorMessage',e.message)).finally(()=>{interfaceState.busy=false;if(b.isConnected)b.disabled=false;});
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
document.addEventListener('razvilka:auth-required',()=>{invalidateEngineProgress();interfaceState.authRevoked=true;interfaceState.authEpoch++;interfaceState.busy=false;for(const c of interfaceRequests)c.abort();interfaceRequests.clear();interfaceCloseInspector();consoleSnapshot=null;interfaceHTML('ui3InspectorContent','');renderInterfaceHome({});});
document.addEventListener('razvilka:auth-restored',()=>{interfaceState.authRevoked=false;renderInterfaceHome(interfaceSummaries());});
document.addEventListener('razvilka:panel-availability',()=>{if((state.currentView||'overview')==='overview')renderInterfaceHome(interfaceSummaries());});
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
 if(typeof interfaceExclusionMap==='function'&&interfaceExclusionMap()[service.id])return '<p>Исключение сохранено. Добавление или выбор подключения его не отменяет.</p><button type="button" class="secondary" data-rz-nav="exclusions">Открыть исключения</button>';
 const managed=consoleSnapshot?.services?.[service.id];
 const setup=consoleSnapshot?.policy?.setup_complete===true&&!consoleAutonomyError;
 if(!setup)return '<button type="button" class="secondary" data-rz-action="setup">Настроить автопилот</button>';
 if(managed?.removing)return '<span role="status">Снятие подключения уже в очереди.</span>';
 const disabled=interfaceState.busy?' disabled':'';
 // The autopilot stops on a changed service definition until it is confirmed;
 // confirming re-saves the same devices with the definition shown now.
 const confirm=managed?.enabled&&consoleSnapshot?.runtime?.[service.id]?.state==='definition-changed'?`<button type="button" class="primary" data-rz-action="confirm-definition"${disabled}>Подтвердить новый состав</button>`:'';
 return `${confirm}<button type="button" class="secondary" data-rz-action="${managed?.enabled?'pause':'manage'}" data-rz-focus="inspector-control-${esc(service.id)}"${disabled}>${managed?.enabled?'Пауза автоподбора':managed?'Возобновить автоподбор':'Включить автоподбор'}</button>`;
}

// UI polling renders data only; all checks and maintenance remain server jobs.
renderInterface();
