/* Unified router console. Production: same-origin APIs only. No mock transport or invented health results. */
'use strict';
const consoleEngineMeta = {
  'nfqws2': {name:'NFQWS2',icon:'bolt',tone:'mint',subtitle:'Локальный обход DPI',description:'Стратегии, доменные списки и исключения. Без внешнего VPN-сервера.',action:'Лаборатория стратегий',target:'strategylab'},
  'usque': {name:'WARP · MASQUE',icon:'cloud',tone:'amber',subtitle:'Cloudflare через USQUE',description:'Аккаунт, транспорт, конфигурация и диагностика. Подключённый процесс не равен доступному сервису.',action:'Диагностика',target:'diagnostics'},
  'warp-wg': {name:'WARP · WireGuard',icon:'shield',tone:'blue',subtitle:'WireGuard-транспорт',description:'Профиль Cloudflare, handshake и маршруты. Проверяйте доступность в вашей сети.',action:'Проверить маршрут',target:'testlab'},
  'sing-box': {name:'Sing-box',icon:'layers',tone:'violet',subtitle:'Прокси и маршрутизация',description:'Проверенные подключения, профиль движка и резервные группы. Один каталог для всех сервисов.',action:'Подключения',target:'nodes'},
  'xray': {name:'Xray',icon:'route',tone:'blue',subtitle:'Альтернативный прокси-клиент',description:'Редактор профиля и нативная проверка конфигурации перед применением.',action:'Импорт профиля',target:'engineconfig'},
  'amneziawg': {name:'AmneziaWG',icon:'lock',tone:'rose',subtitle:'Туннель к вашему серверу',description:'Совместимость формата, профиль, состояние и проверка маршрута. Версия протокола имеет значение.',action:'Проверить маршрут',target:'testlab'}
};
Object.assign(viewMeta, {
  overview:['Главная','Сервисы, маршруты и состояние вашей сети'],
  services:['Сервисы','Выберите, что должно работать. Остальное — по вашей политике.'],
  nodes:['Подключения','Личные профили, проверка доступности и резервные группы'],
  providers:['Каталог ссылок','Источники кандидатов и обновляемые подписки'],
  autopilot:['Автопилот','Общая политика, проверенные резервы и объяснение решений'],
  managed:['Управление сервисами','Индивидуальная автоматика и безопасное удаление'],
  'subscription-settings':['Расписания подписок','Обновление каталога не переключает работающий маршрут'],
  onboard:['Первичная настройка','Устройства, доверенные источники и окна обслуживания'],
  updates:['Обновления','Приложение, компоненты и безопасное обслуживание'],
  activity:['Журнал','История операций и результатов проверок'],
  engines:['Компоненты','Установка, версии и совместимость обходов'],
  devices:['Устройства','Имена, группы и область действия маршрутов'],
  diagnostics:['Диагностика','Причина сбоя, возможности системы и отчёт'],
  dns:['DNS / Smart DNS','Разрешение имён и согласование с маршрутами'],
  settings:['Настройки','Доступ, безопасность, резервные копии и интерфейс']
});
window.RazvilkaConsoleFilters={service:'all'};
let consoleSnapshot=null,consoleAutonomyError='',consoleInitialized=false,consolePaletteItems=[],consolePaletteIndex=0;
const ci=name=>`<svg class="ui-icon" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const consoleText=(id,text)=>{const el=document.getElementById(id);if(el)el.textContent=text;};
function consoleDate(value) {const d=new Date(value);return Number.isFinite(d.getTime())&&d.getFullYear()>2000?d.toLocaleString('ru-RU',{hour:'2-digit',minute:'2-digit',day:'numeric',month:'short'}):'Ещё не проверено';}
function consoleEngineState(id){
 const config=state.engineConfigs?.find(e=>e.id===id),component=state.components?.find(e=>e.id===id),engine=state.engines?.find(e=>e.id===id);
 const running=engine?.running===true||config?.running===true;
 const installed=component?.installed===true||engine?.installed===true||config?.available===true;
 return {config,component,engine,running,installed,label:running?'Процесс запущен':installed?'Готов к настройке':'Не подтверждён',tone:running?'good':'unknown',version:engine?.version||component?.installed_version||config?.version||'Версия не определена'};
}
function consoleNavigate(name,engine){
 if(engine){void openEngineConfiguration(engine).then(()=>{renderConsoleEngine();consoleViewChanged('engineconfig');if(typeof renderInterface==='function')renderInterface();}).catch(error=>showNotice('error',error.message));return;}
 setView(name);
 if(name==='providers')renderNodes();
 if(name==='updates')void refreshAppUpdate();
}
function consoleViewChanged(name){
 document.body.classList.remove('console-menu-open');$('#consoleMenuBackdrop').hidden=true;$('#consoleMenu').setAttribute('aria-expanded','false');consoleDrawerInert();
 const engine=name==='engineconfig'?state.selectedEngine:'';
 const hash=engine?`#/engine/${encodeURIComponent(engine)}`:`#/${name}`;
 if(location.hash!==hash){try{history.replaceState(null,'',hash);}catch{}}
 $$('.nav[data-console-engine]').forEach(el=>el.classList.toggle('active',el.dataset.consoleEngine===engine));
 $('#view-nodes').setAttribute('data-console-browser-mode',typeof nodeBrowser!=='undefined'?nodeBrowser.tab:'all');
 if(name==='providers'){ $('#nodeSubscriptions').hidden=false;$('#nodePublicCatalogs').hidden=false; }
 if(name==='engineconfig')renderConsoleEngine();
 if(name==='activity')setTimeout(consoleFilterAudit,0);
}
function consoleInitialSetup(){consoleRouteHash();}
function consoleRouteHash(){
 const path=location.hash.replace(/^#\/?/,'').split('/');
 if(path[0]==='engine'&&consoleEngineMeta[decodeURIComponent(path[1]||'')]){consoleNavigate('engineconfig',decodeURIComponent(path[1]));return;}
 if(path[0]&&document.getElementById(`view-${path[0]}`))setView(path[0]);
 else if(!consoleInitialized)setView('overview');
 consoleInitialized=true;
}
function renderConsoleEngine(){
 const id=state.selectedEngine,meta=consoleEngineMeta[id]||consoleEngineMeta.nfqws2,info=consoleEngineState(id);
 viewMeta.engineconfig=[meta.name,meta.subtitle];
 $('#consoleEngineBanner').innerHTML=`<span class="engine-emblem ${meta.tone}">${ci(meta.icon)}</span><div class="engine-banner-copy"><div class="eyebrow">НАСТРОЙКА КОМПОНЕНТА</div><h2>${esc(meta.name)}</h2><p>${esc(meta.description)}</p><div class="engine-banner-tags"><span class="pill ${info.tone}">${esc(info.label)}</span><span class="mono">${esc(info.version)}</span></div></div><div class="engine-banner-actions"><button type="button" class="secondary" data-console-engine-action="${esc(id)}">${ci(meta.icon)}${esc(meta.action)}</button><button type="button" class="text-button" data-console-navigate="engines">Установка и обновление ${ci('chevron')}</button></div>`;
 if(state.currentView==='engineconfig'){consoleText('pageTitle',meta.name);consoleText('pageSubtitle',meta.subtitle);$$('.nav[data-console-engine]').forEach(e=>e.classList.toggle('active',e.dataset.consoleEngine===id));}
}
function renderConsole(){
 const services=state.services||[],enabled=services.filter(s=>s.enabled||s.applied_enabled);
 consoleText('consoleServiceCount',enabled.length);
 const ribbon=$('#consoleEngineRibbon');
 ribbon.innerHTML=Object.entries(consoleEngineMeta).map(([id,m])=>{const e=consoleEngineState(id);return `<button class="engine-ribbon-item ${m.tone}" type="button" data-console-engine="${esc(id)}"><span class="engine-mini-icon">${ci(m.icon)}</span><span><strong>${esc(m.name)}</strong><small><i class="status-dot ${e.running?'good':''}"></i>${esc(e.label)}</small></span>${ci('chevron')}</button>`;}).join('');
 const summary=$('#consoleAutonomySummary');
 if(consoleSnapshot?.policy){const p=consoleSnapshot.policy,r=Object.values(consoleSnapshot.runtime||{}),active=consoleSnapshot.services||{};const healthy=r.filter(x=>['healthy','applied'].includes(x.state)).length;const attention=r.filter(x=>!['healthy','applied','paused'].includes(x.state)).length;
 summary.innerHTML=`<div class="auto-orbit">${ci(p.enabled?'route':'pause')}</div><div><strong>${!p.setup_complete?'Нужна начальная настройка':consoleSnapshot.safe_mode?'Safe Mode':consoleSnapshot.stopped?'Маршруты остановлены':consoleSnapshot.manual?'Ручное управление':p.enabled?'Автопилот включён':'Автопилот на паузе'}</strong><p>${Object.keys(active).length} в управлении · ${healthy} проверено${attention?` · ${attention} ожидают результата`:''}</p></div><button class="text-button" type="button" data-console-navigate="${p.setup_complete?'autopilot':'onboard'}">${p.setup_complete?'Политика и резерв':'Пройти настройку'} ${ci('chevron')}</button>`;
 }else{summary.innerHTML=`<div class="auto-orbit">${ci('route')}</div><div><strong>${consoleAutonomyError?'Автономность недоступна':'Загружаем политику'}</strong><p>${esc(consoleAutonomyError||'Читаем сохранённые разрешения роутера.')}</p></div><button class="text-button" type="button" data-console-navigate="onboard">Первичная настройка ${ci('chevron')}</button>`;}
 const audit=state.audit?.events||[];
 $('#consoleRecentActions').innerHTML=audit.length?audit.slice(0,4).map(e=>`<div class="recent-action"><span class="recent-symbol ${e.outcome==='ok'?'good':'warn'}">${ci(e.outcome==='ok'?'check':'clock')}</span><div><strong>${esc(consoleAuditTitle(e))}</strong><small>${esc(e.path||'Локальная операция')}</small></div><time>${esc(consoleDate(e.timestamp))}</time></div>`).join(''):'<div class="empty-inline">История появится после первой операции. Проверки и изменения не скрываются.</div>';
 renderConsoleProviders();renderConsoleUpdates();
 if(state.currentView==='engineconfig')renderConsoleEngine();
 if(state.currentView==='providers'){$('#nodeSubscriptions').hidden=false;$('#nodePublicCatalogs').hidden=false;}
 consoleFilterAudit();
 if(!consoleInitialized&&state.services.length)consoleRouteHash();
 if(typeof renderInterface==='function')renderInterface();
}
function consoleAuditTitle(e){const kind=(e.path||'').includes('check')?'Проверка подключения':(e.path||'').includes('feed')?'Обновление подписки':(e.path||'').includes('autonomy')?'Политика Автопилота':(e.path||'').includes('apply')?'Применение маршрута':(e.path||'').includes('device')?'Настройка устройства':'Операция панели';return kind+(e.outcome==='failed'?' · ошибка':e.outcome==='denied'?' · отказ':'');}
function renderConsoleProviders(){
 const presets=state.nodeFeeds?.presets||[];
 const entries=[
  {name:'Kort0881',tag:'VLESS · каталог РФ',text:'Выборка публичных подключений. Расположение и доступность проверяются отдельно.',url:'https://github.com/kort0881/vpn-vless-configs-russia',key:'kort',icon:'route',tone:'mint'},
  {name:'Goida VPN',tag:'Несколько протоколов',text:'Коллекция подписок. Выбирайте ограниченный срез, а не тысячи проверок сразу.',url:'https://avencores.github.io/goida-vpn-site/',key:'goida-extra',icon:'layers',tone:'violet'},
  {name:'VLESS Key Checker',tag:'Каталог подключений',text:'Результат издателя — подсказка. Нужна точная проверка выбранного сервиса.',url:'https://tiagorrg.github.io/vless-checker/',key:'tiagorrg',icon:'shield',tone:'blue'},
  {name:'igareck',tag:'Смешанная подписка',text:'Коллекция разных протоколов. Неподдержанные параметры не должны отбрасываться молча.',url:'https://github.com/igareck/vpn-configs-for-russia',feedURL:'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt',key:'igareck',icon:'wifi',tone:'blue'},
 {name:'Epodonios',tag:'Пакет Sub1',text:'Небольшой пакет вместо загрузки всей коллекции. Каждый узел требует локальной проверки.',url:'https://github.com/Epodonios/v2ray-configs',feedURL:'https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub1.txt',key:'epodonios',icon:'server',tone:'rose'},
 {name:'Личная подписка',tag:'Ваш источник',text:'Приватный HTTPS-адрес сохраняется на роутере. Новые ссылки не включают маршрут сами.',key:'own',icon:'lock',tone:'amber'}
 ];
 $('#consoleProviderCards').innerHTML=entries.map(x=>{const preset=presets.find(p=>p.id.includes(x.key));return `<article class="provider-feature"><div class="provider-brand"><span class="engine-mini-icon ${x.tone}">${ci(x.icon)}</span><span class="pill">${esc(x.tag)}</span></div><h3>${esc(x.name)}</h3><p>${esc(x.text)}</p><div class="provider-links"><button type="button" class="secondary" data-console-feed="${esc(preset?.id||'custom')}" data-console-feed-url="${esc(x.feedURL||'')}">${x.key==='own'?'Добавить URL':'Настроить подписку'} ${ci('plus')}</button>${x.url?`<a target="_blank" rel="noopener noreferrer" href="${esc(x.url)}" aria-label="Сайт ${esc(x.name)}">Сайт ${ci('chevron')}</a>`:''}</div></article>`;}).join('');
}
function renderConsoleUpdates(){
 $('#consoleUpdateEngines').innerHTML=Object.entries(consoleEngineMeta).map(([id,m])=>{const e=consoleEngineState(id);return `<div class="console-update-engine"><span class="engine-mini-icon ${m.tone}">${ci(m.icon)}</span><div><b>${esc(m.name)}</b><small>${esc(e.version)}</small></div><button type="button" class="text-button" data-console-navigate="engines">Управлять ${ci('chevron')}</button></div>`;}).join('');
 const p=consoleSnapshot?.policy;
 $('#consoleUpdateSchedule').innerHTML=p?`<div class="schedule-row"><span class="schedule-icon">${ci('clock')}</span><div><small>Приложение · ${esc(p.timezone)}</small><b>${p.application.mode==='off'?'Проверка отключена':esc(p.application.start+'–'+p.application.end)}</b><p>${p.application.mode==='prepare'?'Проверка и подготовка. Без автоматической установки.':'Проверка доступности обновления.'}</p></div></div><div class="schedule-row"><span class="schedule-icon">${ci('layers')}</span><div><small>Компоненты</small><b>${p.components.mode==='off'?'Проверка отключена':esc(p.components.start+'–'+p.components.end)}</b><p>Совместимость и установка — через отдельное подтверждение.</p></div></div><button type="button" class="secondary" data-console-navigate="onboard">Изменить расписание</button>`:`<p class="muted">${esc(consoleAutonomyError||'Настройте окно обслуживания в мастере. Установка не выполняется без разрешения.')}</p><button type="button" class="secondary" data-console-navigate="onboard">Открыть мастер</button>`;
}
function consoleFilterAudit(){const q=($('#consoleAuditSearch')?.value||'').toLowerCase();$$('#auditRows .audit-row').forEach(row=>row.hidden=!!q&&!row.textContent.toLowerCase().includes(q));}
function consoleDownload(name,data,type='application/json'){const url=URL.createObjectURL(new Blob([data],{type}));const a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),5000);}
function consolePalette(){
 const q=$('#consoleSearchInput').value.toLowerCase().trim();
 const pages=Object.entries(viewMeta).filter(([key])=>document.getElementById('view-'+key)&&key!=='engineconfig').map(([id,m])=>({label:m[0],detail:m[1],icon:'grid',view:id}));
 const engines=Object.entries(consoleEngineMeta).map(([id,m])=>({label:m.name,detail:m.subtitle,engine:id,icon:m.icon}));
 const services=state.services.map(s=>({label:s.name,detail:'Сервис · '+(s.domains||[]).slice(0,2).join(', '),service:s.name,view:'services',icon:'link'}));
 consolePaletteItems=[...pages,...engines,...services].filter(x=>!q||(x.label+' '+x.detail).toLowerCase().includes(q)).slice(0,18);consolePaletteIndex=0;
 $('#consoleSearchResults').innerHTML=consolePaletteItems.length?consolePaletteItems.map((x,i)=>`<button type="button" data-console-result="${i}" class="search-result ${i===0?'selected':''}">${ci(x.icon)}<span><b>${esc(x.label)}</b><small>${esc(x.detail)}</small></span>${ci('chevron')}</button>`).join(''):'<div class="empty-inline">Ничего не найдено. Попробуйте название сервиса или раздела.</div>';
}
function consoleChooseResult(index){const x=consolePaletteItems[index];if(!x)return;$('#consoleSearchDialog').close();consoleNavigate(x.view||'engineconfig',x.engine);if(x.service){if(typeof interfaceState!=='undefined'){interfaceState.query=x.service;interfaceState.filter='all';interfaceState.category='';$('#ui3ServiceSearch').value=x.service;}$('#serviceSearch').value=x.service;window.RazvilkaConsoleFilters.service='all';renderServices();}}
function consoleOpenPalette(){$('#consoleSearchDialog').showModal();$('#consoleSearchInput').value='';consolePalette();$('#consoleSearchInput').focus();}
function consoleSetTheme(theme){document.documentElement.dataset.theme=theme;$('#consoleTheme').innerHTML=ci(theme==='dark'?'sun':'moon');$('#consoleTheme').setAttribute('aria-label',theme==='dark'?'Светлая тема':'Тёмная тема');try{localStorage.setItem('razvilka.interface.theme',theme);}catch{}}
try{consoleSetTheme(localStorage.getItem('razvilka.interface.theme')==='dark'?'dark':'light');}catch{consoleSetTheme('light');}
$('#consoleTheme').addEventListener('click',()=>consoleSetTheme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
$('#consoleMenu').addEventListener('click',()=>{const open=document.body.classList.toggle('console-menu-open');$('#consoleMenuBackdrop').hidden=!open;$('#consoleMenu').setAttribute('aria-expanded',String(open));consoleDrawerInert();if(open)$('#consoleCloseMenu').focus();});
for(const id of ['consoleCloseMenu','consoleMenuBackdrop'])$('#'+id).addEventListener('click',()=>{document.body.classList.remove('console-menu-open');$('#consoleMenuBackdrop').hidden=true;$('#consoleMenu').setAttribute('aria-expanded','false');consoleDrawerInert();$('#consoleMenu').focus();});
$('#consoleSearch').addEventListener('click',consoleOpenPalette);$('#consoleSearchClose').addEventListener('click',()=>$('#consoleSearchDialog').close());$('#consoleSearchInput').addEventListener('input',consolePalette);
$('#consoleSearchResults').addEventListener('click',e=>{const b=e.target.closest('[data-console-result]');if(b)consoleChooseResult(Number(b.dataset.consoleResult));});
$('#consoleSearchInput').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();consoleChooseResult(consolePaletteIndex);}if(['ArrowDown','ArrowUp'].includes(e.key)){e.preventDefault();consolePaletteIndex=Math.max(0,Math.min(consolePaletteItems.length-1,consolePaletteIndex+(e.key==='ArrowDown'?1:-1)));$$('[data-console-result]').forEach((el,i)=>el.classList.toggle('selected',i===consolePaletteIndex));$$('[data-console-result]')[consolePaletteIndex]?.scrollIntoView({block:'nearest'});}});
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();consoleOpenPalette();}if(e.key==='Escape'&&document.body.classList.contains('console-menu-open'))$('#consoleCloseMenu').click();});
$('#consoleHelp').addEventListener('click',()=>$('#consoleHelpDialog').showModal());
$('#consoleAuditSearch').addEventListener('input',consoleFilterAudit);
$('#consoleExportAudit').addEventListener('click',()=>consoleDownload('razvilka-activity.json',JSON.stringify({exported_at:new Date().toISOString(),events:state.audit?.events||[]},null,2)));
document.addEventListener('click',async e=>{
 const close=e.target.closest('[data-console-close]');if(close){document.getElementById(close.dataset.consoleClose)?.close();return;}
 const b=e.target.closest('[data-console-engine],[data-console-navigate],[data-console-add],[data-console-service-filter],[data-console-feed],[data-console-node-tab],[data-console-engine-action]');if(!b||b.disabled)return;
 try{
 if(b.hasAttribute('data-console-engine'))consoleNavigate('engineconfig',b.dataset.consoleEngine);
 else if(b.hasAttribute('data-console-navigate'))consoleNavigate(b.dataset.consoleNavigate);
 else if(b.hasAttribute('data-console-add')){if(consoleSnapshot?.policy?.setup_complete){document.getElementById('a1-openAddService').click();}else openCustomServiceDialog();}
 else if(b.hasAttribute('data-console-service-filter')){window.RazvilkaConsoleFilters.service=b.dataset.consoleServiceFilter;$$('[data-console-service-filter]').forEach(x=>x.classList.toggle('active',x===b));renderServices();}
 else if(b.hasAttribute('data-console-node-tab')){setNodeBrowserTab(b.dataset.consoleNodeTab==='groups'?'groups':'all');$('#view-nodes').setAttribute('data-console-browser-mode',nodeBrowser.tab);$$('[data-console-node-tab]').forEach(x=>x.classList.toggle('active',x===b));}
 else if(b.hasAttribute('data-console-feed')){setView('providers');const preset=b.dataset.consoleFeed;$('#nodeFeedPreset').value=preset;$('#nodeFeedPreset').dispatchEvent(new Event('change',{bubbles:true}));if(b.dataset.consoleFeedUrl)$('#nodeFeedURL').value=b.dataset.consoleFeedUrl;$('#nodeSubscriptions').hidden=false;$('#nodeSubscriptions').scrollIntoView({behavior:'smooth',block:'start'});(preset==='custom'?$('#nodeFeedURL'):$('#nodeFeedSync')).focus();}
 else if(b.hasAttribute('data-console-engine-action')){const meta=consoleEngineMeta[b.dataset.consoleEngineAction];if(b.dataset.consoleEngineAction==='xray')switchEngineTab('transfer');else setView(meta.target);}
 }catch(error){showNotice('error',error.message);}
});
window.addEventListener('razvilka:autonomy-state',e=>{consoleAutonomyAvailability(true); consoleSnapshot=e.detail;consoleAutonomyError='';renderConsole();});
window.addEventListener('razvilka:autonomy-error',e=>{consoleAutonomyAvailability(false,e.detail.status===404?'Этот backend не содержит A1. Подключения и ручные настройки доступны; автономный мастер требует сборки A1.':e.detail.message); consoleAutonomyError=e.detail.message;if(e.detail.status===401||e.detail.status===404)consoleSnapshot=null;renderConsole();});
window.addEventListener('hashchange',consoleRouteHash);
renderConsole();

function consoleServiceIcon(service){const map={telegram:'telegram',youtube:'youtube',discord:'discord',instagram:'instagram',chatgpt:'ai',claude:'claude',gemini:'ai',perplexity:'ai',github:'github',twitch:'stream',netflix:'stream'};return map[service.id]?`<svg class="ui-icon service-logo service-${esc(service.id)}" aria-hidden="true"><use href="#i-service-${map[service.id]}"/></svg>`:esc(service.icon||service.name?.slice(0,2)||'•');}

function consoleAutonomyAvailability(available,message=''){$$('.console-autonomy-availability').forEach(el=>{el.hidden=available;el.textContent=message;});$$('[data-autonomy] form input,[data-autonomy] form select,[data-autonomy] form textarea,[data-autonomy] form button,#a1-pauseButton,[data-manage],[data-remove],[data-feed-sync]').forEach(el=>el.disabled=!available);}

function consoleDrawerInert(){document.querySelector('.sidebar').inert=window.matchMedia('(max-width:760px)').matches&&!document.body.classList.contains('console-menu-open');}
window.matchMedia('(max-width:760px)').addEventListener('change',consoleDrawerInert);consoleDrawerInert();
