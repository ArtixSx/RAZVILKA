/* RAZVILKA autonomy UI. Real endpoints only; no fake ping/PASS, browser-side
 * scheduling of router operations, or persistence of keys in browser storage. */
(function(root) {
  'use strict';
  const supportedProtocols = ['vless','hysteria2','tuic','shadowsocks'];
  const supportedRoutes = ['nfqws2','usque','warp-wg','amneziawg','wireguard','sing-box','xray'];
  const routeLabels = {nfqws2:'NFQWS2',usque:'WARP · MASQUE','warp-wg':'WARP · WireGuard',amneziawg:'AmneziaWG',wireguard:'WireGuard · свой сервер','sing-box':'Sing-box · свой сервер',xray:'Xray · свой сервер'};
  const dayLabels = [[1,'Пн'],[2,'Вт'],[3,'Ср'],[4,'Чт'],[5,'Пт'],[6,'Сб'],[0,'Вс']];
  const clone = v => JSON.parse(JSON.stringify(v));
  const escapeHTML = v => String(v ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const splitValues = v => [...new Set(String(v || '').split(/[\s,;]+/).filter(Boolean))];
  function minutes(text) { if(!/^\d{2}:\d{2}$/.test(text)) return -1; const [h,m]=text.split(':').map(Number); return h<24&&m<60 ? h*60+m : -1; }
  function validateWindow(w, component=false) {
    if(!w || !['off','check','install',...(component?[]:['prepare'])].includes(w.mode)) throw new Error('Неизвестный режим окна обслуживания.');
    if(minutes(w.start)<0||minutes(w.end)<0||w.start===w.end) throw new Error('Укажите разные корректные границы окна обслуживания.');
    if(!Array.isArray(w.days)||!w.days.length||w.days.some(d=>!Number.isInteger(d)||d<0||d>6)||new Set(w.days).size!==w.days.length) throw new Error('Выберите дни обслуживания.');
  }
  function validatePolicy(p, {allowSavedEmptyScope=false}={}) {
    if(!p || !p.timezone || p.timezone==='Local') throw new Error('Укажите часовой пояс IANA.');
    try { new Intl.DateTimeFormat('ru',{timeZone:p.timezone}).format(); } catch { throw new Error('Часовой пояс не распознан.'); }
    if(!Array.isArray(p.default_sources)||p.all_lan&&p.default_sources.length||!p.all_lan&&!p.default_sources.length&&!allowSavedEmptyScope) throw new Error('Укажите устройства либо явно выберите всю локальную сеть.');
    if(p.default_sources.length>128) throw new Error('Слишком много устройств.');
    for(const v of p.default_sources) {
      if(!/^[0-9a-fA-F:./]+$/.test(v)||/\/0$/.test(v)||v==='0.0.0.0'||v==='::'||v.startsWith('127.')||v.startsWith('::1/')) throw new Error('Нужны IP-адреса или CIDR устройств; не домены и не 0.0.0.0/0.');
    }
    if(!Array.isArray(p.source_ids)||p.source_ids.length>32||p.enabled&&!p.source_ids.length&&!p.preferred_routes?.length||p.source_ids.some(id=>! /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(id))) throw new Error('Выберите хотя бы один известный источник для автоматического подбора.');
    if(p.preferred_source_ids!==undefined&&(!Array.isArray(p.preferred_source_ids)||p.preferred_source_ids.length>32||new Set(p.preferred_source_ids).size!==p.preferred_source_ids.length||p.preferred_source_ids.some(id=>!p.source_ids.includes(id)))) throw new Error('Порядок проверки должен содержать только разрешённые источники без повторений.');
    if(!Array.isArray(p.protocols)||!p.protocols.length||p.protocols.some(x=>!supportedProtocols.includes(x))) throw new Error('Выберите поддержанные протоколы.');
    if(!Array.isArray(p.preferred_routes)||p.preferred_routes.some(x=>!supportedRoutes.includes(x))) throw new Error('Неизвестный предпочтительный обход.');
    if(p.install_missing_components!=null&&typeof p.install_missing_components!=='boolean') throw new Error('Укажите разрешение на первую установку компонентов.');
    if(p.allow_initial_warp_registration!==undefined&&(typeof p.allow_initial_warp_registration!=='boolean'||p.allow_initial_warp_registration&&!p.preferred_routes.includes('warp-wg'))) throw new Error('Разрешение на регистрацию относится к выбранному методу WARP · WireGuard.');
    if(p.allow_initial_masque_registration!==undefined&&(typeof p.allow_initial_masque_registration!=='boolean'||p.allow_initial_masque_registration&&!p.preferred_routes.includes('usque'))) throw new Error('Разрешение на регистрацию относится к выбранному методу WARP · MASQUE.');
    if(p.public_node_failure_threshold!==undefined&&(!Number.isInteger(p.public_node_failure_threshold)||p.public_node_failure_threshold<2||p.public_node_failure_threshold>8)) throw new Error('Порог удаления публичных узлов — от 2 до 8 подтверждённых отказов подряд.');
    const ranges={check_seconds:[60,3600],reserve_seconds:[60,86400],reserve_target:[1,4],candidates_per_round:[1,4],failure_confirm_seconds:[10,300],max_switches_per_hour:[1,20]};
    for(const [key,[lo,hi]] of Object.entries(ranges)) if(!Number.isInteger(p[key])||p[key]<lo||p[key]>hi) throw new Error(`Параметр ${key}: допустимо ${lo}–${hi}.`);
    if(p.reserve_seconds<p.check_seconds) throw new Error('Резерв не должен проверяться чаще основного сервиса.');
    validateWindow(p.application);validateWindow(p.components,true);
    return p;
  }
  function websiteDefinition(name, input, category = 'other') {
    name=String(name||'').trim();input=String(input||'').trim();
    if(!name||name.length>80) throw new Error('Введите название сервиса длиной до 80 символов.');
    let url;try { url=new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input)?input:`https://${input}`); } catch { throw new Error('Проверьте адрес сайта.'); }
    const host=url.hostname.toLowerCase().replace(/\.$/,'');
    if(url.protocol!=='https:'||url.username||url.password||url.port&&url.port!=='443'||!host.includes('.')||host==='localhost'||/\.(localhost|local|invalid)$/.test(host)||/^\[/.test(host)||/^\d+\.\d+\.\d+\.\d+$/.test(host)) throw new Error('Для простого мастера нужен публичный HTTPS-домен без логина и нестандартного порта.');
    if(!['other','AI','Видео','Мессенджеры','Работа'].includes(category)) throw new Error('Выберите категорию из списка.');
    return {name,category,domains:[host],strategy:['auto'],probe_url:`https://${host}/`,description:'Пользовательский сервис. Автоматическая базовая веб-проверка.',icon:'◇'};
  }
  const stateLabels={pending:'Ожидает проверки',checking:'Проверяется',healthy:'Проверен',applied:'Применён',searching:'Подбор резерва',unconfirmed:'Нет однозначного результата','service-unconfirmed':'Сервис отказал через несколько узлов',paused:'На паузе', 'manual-change':'Ручное изменение', 'network-unknown':'Сеть не определена', 'apply-refused':'Применение отклонено', 'service-checked-lan-unavailable': 'Узел проверен · маршрут для дома недоступен', 'capability-refused':'Недоступно в текущем режиме', 'domain-route-unavailable':'Нет подтверждённого обхода для доменного сервиса', excluded:'Не разрешён списком или исключениями', applying:'Применяется', 'component-unavailable':'Компонент не готов', 'component-stopped':'Компонент не запущен', 'rate-limited':'Лимит переключений', 'requires-review':'Нужна проверка журнала', 'scope-pending':'Область ещё не применена', 'origin-expired':'Истёк источник', 'definition-changed':'Состав изменился', 'unsupported-scenario':'Нет подходящего теста', 'checker-unavailable':'Проверяющий модуль недоступен', 'catalog-unavailable':'Каталог недоступен', 'removal-pending':'Снятие маршрута в очереди', 'removal-blocked':'Снятие приостановлено',removed:'Удалён'};
  stateLabels['component-window']='Ожидает окна установки';
  stateLabels['component-retry']='Ожидает повторной установки';
  Object.assign(stateLabels,{
    'warp-consent-required':'Требуется согласие на регистрацию WARP WireGuard',
    'masque-consent-required':'Требуется согласие на регистрацию MASQUE',
    'masque-registration-timeout':'Регистрация MASQUE не ответила вовремя',
    'masque-registration-pending':'Результат регистрации MASQUE требует проверки',
    'masque-target-excluded':'Адрес проверки MASQUE исключён',
    'masque-target-unavailable':'Разрешённые адреса проверки MASQUE не подтверждены',
    'masque-session-conflict':'Слот MASQUE занят',
    'masque-session-unavailable':'Сессия MASQUE недоступна',
    'masque-service-unconfirmed':'Работа сервиса через MASQUE не подтверждена',
    'masque-component-unavailable':'Компонент MASQUE недоступен',
    'masque-publication-unconfirmed':'Компонент MASQUE ожидает повторной проверки',
    'warp-registration-unreachable':'Адрес регистрации WARP недоступен',
    'warp-registration-timeout':'Регистрация WARP не ответила вовремя',
    'warp-registration-pending':'Результат регистрации WARP требует проверки',
    'warp-registration-budget':'Ожидает интервала регистрации WARP',
    'warp-profile-conflict':'Профиль WARP изменился',
    'warp-service-unconfirmed':'Работа сервиса через WARP не подтверждена'
  });
  function policyConsentRequired(previous, next, releaseSafeMode = false) {
    // Fail closed on first setup, new authority or unknown changed fields.
    // This is presentation only: server validation, revision/CAS, ownership
    // and the explicit SAVE_AUTONOMY request remain authoritative.
    if (releaseSafeMode || !previous?.setup_complete || !next?.setup_complete) return true;
    const before = JSON.parse(JSON.stringify(previous));
    const after = JSON.parse(JSON.stringify(next));
    const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    for (const field of ['source_ids', 'protocols', 'preferred_routes']) {
      if (!Array.isArray(before[field]) || !Array.isArray(after[field])) return true;
      if (after[field].some(value => !before[field].includes(value))) return true;
      delete before[field]; delete after[field];
    }
    // Priority changes order only within the already selected source consent.
    const sourceOrder = after.preferred_source_ids ?? [];
    if (!Array.isArray(sourceOrder) || new Set(sourceOrder).size !== sourceOrder.length || sourceOrder.some(id => !next.source_ids.includes(id))) return true;
    delete before.preferred_source_ids; delete after.preferred_source_ids;
    // A CIDR change is not guessed to be a subset in the browser. It still
    // needs review; only a harmless reordering of the same scope is ignored.
    if (before.all_lan !== after.all_lan) return true;
    if (!Array.isArray(before.default_sources) || !Array.isArray(after.default_sources)) return true;
    if (!equal([...before.default_sources].sort(), [...after.default_sources].sort())) return true;
    delete before.default_sources; delete after.default_sources;
    if (!before.inherit_new_services && after.inherit_new_services) return true;
    delete before.inherit_new_services; delete after.inherit_new_services;
    if (after.install_missing_components === true && before.install_missing_components !== true) return true;
    if (after.install_missing_components == null && before.install_missing_components === false && after.components?.mode === 'install') return true;
    delete before.install_missing_components; delete after.install_missing_components;
    if (after.allow_initial_warp_registration === true && before.allow_initial_warp_registration !== true) return true;
    delete before.allow_initial_warp_registration; delete after.allow_initial_warp_registration;
    if (after.allow_initial_masque_registration === true && before.allow_initial_masque_registration !== true) return true;
    delete before.allow_initial_masque_registration; delete after.allow_initial_masque_registration;
    if ((after.public_node_failure_threshold??3)<(before.public_node_failure_threshold??3)) return true;
    delete before.public_node_failure_threshold; delete after.public_node_failure_threshold;
    for (const field of ['application', 'components']) {
      const modes = field === 'application' ? ['off', 'check', 'prepare', 'install'] : ['off', 'check', 'install'];
      const oldWindow = before[field], newWindow = after[field];
      if (!oldWindow || !newWindow || modes.indexOf(oldWindow.mode) < 0 || modes.indexOf(newWindow.mode) < 0) return true;
      if (modes.indexOf(newWindow.mode) > modes.indexOf(oldWindow.mode)) return true;
      const rest = value => Object.fromEntries(Object.entries(value).filter(([key]) => !['mode', 'start', 'end', 'days'].includes(key)));
      if (!equal(rest(oldWindow), rest(newWindow))) return true;
      delete before[field]; delete after[field];
    }
    // Bounded tuning and pausing/resuming the existing policy do not expand
    // permitted devices, sources or transports. Limits are checked by server.
    for (const field of ['revision', 'enabled', 'timezone', 'check_seconds', 'reserve_seconds', 'reserve_target', 'candidates_per_round', 'failure_confirm_seconds', 'max_switches_per_hour']) {
      delete before[field]; delete after[field];
    }
    return !equal(before, after);
  }
  function candidateCooldownText(runtime, now=Date.now()) {
    const entries=(Array.isArray(runtime?.candidate_failures)?runtime.candidate_failures:[]).filter(f=>['http-403','http-451'].includes(f.code)&&Date.parse(f.observed_at)<=now&&Date.parse(f.until)>now&&Date.parse(f.until)-Date.parse(f.observed_at)<=300000);
    if(!entries.length) return '';
    const seconds=Math.ceil((Math.min(...entries.map(f=>Date.parse(f.until)))-now)/1000);
    return `Отложено подключений: ${entries.length}. Сервис вернул HTTP 403/451; новая проверка возможна через ${Math.ceil(seconds/60)} мин.`;
  }
  function panelAutonomyData(value) {
    if(value?.schema!==1 || !/^[a-f0-9]{32}$/.test(value.instance_id||'') || !Number.isSafeInteger(value.revision) || value.revision<1 || value.dataplane!=='not-checked' || !['available','retained'].includes(value.state) || !Number.isFinite(value.data_age_ms) || value.data_age_ms<0 || value.data_age_ms>=120000 || value.state==='available'&&value.data_age_ms>=15000 || !value.data?.policy || !Number.isFinite(Date.parse(value.observed_at))) throw new Error('Состояние автопилота обновляется. Последние настройки сохранены; дождитесь свежего снимка.');
    return {...value.data,observation:{state:value.state,instance_id:value.instance_id,revision:value.revision,observed_at:value.observed_at,data_age_ms:value.data_age_ms}};
  }
  function maintenanceModeText(mode, components=false) {
    if(mode==='off') return 'Выключено';
    if(mode==='install') return components?'Обновление пакетов; подтверждение результата в журнале':'Установка с откатом; при сбое нужна проверка журнала';
    if(mode==='prepare'&&!components) return 'Подготовка, без установки';
    return components?'Проверка каталога':'Проверка версии';
  }
  function sourceStatusLabel(status) {
    const labels={saved:'Сохранено',fetching:'Получение',synced:'Получено',needs_acceptance:'Нужно подтвердить частичный результат',capacity:'Достигнут предел записей',failed:'Получение не удалось',interrupted:'Получение прервано',queued:'В очереди',running:'Выполняется',completed:'Завершено',canceled:'Отменено'};
    return Object.hasOwn(labels,status)?labels[status]:status?'Неизвестный результат':'Ожидается';
  }
  function sourceDate(value,zone='UTC') {
    const date=new Date(value);
    if(!Number.isFinite(date.getTime())||date.getFullYear()<2000)return 'Ещё нет';
    try{return `${date.toLocaleString('ru-RU',{timeZone:zone,month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})} (${zone})`;}catch{return date.toISOString();}
  }
  function sourceCard(s,zone='UTC') {
    return `<article class="panel source-card" data-source-id="${escapeHTML(s.source_id)}"><div class="section-title"><h2>${escapeHTML(s.name||s.source_id)}</h2><span class="tag ${s.saved===true&&s.enabled?'':'neutral'}">${s.saved===true?(s.enabled?'Таймер включён':'Таймер выключен'):'Разовое получение · не сохранено'}</span></div><code>${escapeHTML(s.source_id)}</code><dl><dt>Последняя попытка</dt><dd>${escapeHTML(sourceDate(s.last_attempt_at,zone))}</dd><dt>Успешное получение</dt><dd>${escapeHTML(sourceDate(s.last_success_at,zone))}</dd><dt>Следующий запрос</dt><dd>${escapeHTML(sourceDate(s.next_refresh_at,zone))}</dd><dt>Последний результат</dt><dd>${escapeHTML(sourceStatusLabel(s.status))} · ${Number(s.imported||0)} записей</dd></dl>${s.saved===true?`<form class="source-actions" data-feed-form="${escapeHTML(s.source_id)}"><label><span>Интервал, мин</span><input name="interval" type="number" min="15" max="10080" value="${Number(s.refresh_interval_minutes||60)}" required></label><label><span>Таймер</span><select name="enabled"><option value="true" ${s.enabled?'selected':''}>Включён</option><option value="false" ${!s.enabled?'selected':''}>Выключен</option></select></label><button class="button small" type="submit">Сохранить</button><button class="button small" type="button" data-feed-sync="${escapeHTML(s.source_id)}">Получить сейчас</button></form>`:`<p class="subtle">Источник использован разово. Подписка и расписание не сохранены.</p><button class="button small" type="button" data-feed-add="${escapeHTML(s.source_id)}">Добавить постоянную подписку</button>`}</article>`;
  }
  function policyReadbackSnapshot(previous, next) {
    const revision=next?.policy?.revision,time=Date.parse(next?.server_time||'');
    if(!next?.policy?.setup_complete || !Number.isSafeInteger(revision) || revision<1 || !Number.isFinite(time) || next.observation?.state==='retained' || next.blocked) return null;
    if(previous?.policy && (revision<previous.policy.revision || time<Date.parse(previous.server_time))) return null;
    if(previous?.observation?.instance_id && next.observation?.instance_id && previous.observation.instance_id!==next.observation.instance_id) return null;
    // A direct GET has no publication ID. Preserve its existing instance so an
    // older passive publication cannot replace this completed write's readback.
    return {...next,...(previous?.observation?{observation:{...previous.observation,state:'available',observed_at:next.server_time}}:{})};
  }
  function requestErrorText(error, mutation=false) {
    const text=String(error?.message||'');
    if(error?.status || ['AbortError','AuthGenerationChanged'].includes(error?.name) || !/failed to fetch|networkerror|load failed|network request failed/i.test(text))return text;
    return mutation?'Нет связи с панелью. Результат действия не подтверждён. Обновите состояние перед повтором.':'Нет связи с панелью. Проверьте, что служба запущена, и обновите состояние.';
  }
  function capabilityPresentation(value) {
    const capability=value?.capabilities?.schema===1?value.capabilities.availability?.automatic_initial_apply:null;
    if(capability?.state==='blocked' && capability.available===false)return {state:'blocked',message:String(capability.message||'Автопилот приостановлен: требуется проверка условий запуска.')};
    if(capability?.state==='requires-service-plan' && capability.available===null)return {state:'requires-service-plan',message:String(capability.message||'Для каждого сервиса нужны актуальные проверки узла, области и применения.')};
    return {state:'unknown',message:'Доступность автоматического применения ещё не подтверждена. Обновите состояние панели.'};
  }
  function selectedRouteOrder(previous,checked) {
    return [...previous.filter(id=>checked.includes(id)),...checked.filter(id=>!previous.includes(id))];
  }
  function definitionChecks(review) {
    const labels={status_codes:'коды HTTP',redirect_policy:'переходы',redirect_hosts:'адреса переходов',content_types:'типы ответа',json:'ответ JSON',json_fields:'поля JSON',body_contains:'текст ответа'};
    const checks=(review.probes||[]).map(probe=>{
      const expectation=Object.entries(probe.expect||{}).map(([key,value])=>`${labels[key]||key} — ${Array.isArray(value)?value.join(', '):value}`);
      return [probe.label||probe.id,probe.url,probe.required?'обязательная':'дополнительная',...expectation].join(' · ');
    });
    if(review.probe_url)checks.unshift(review.probe_url);
    return checks;
  }
  const model={definitionChecks,selectedRouteOrder,capabilityPresentation,sourceCard,sourceDate,sourceStatusLabel,maintenanceModeText,validatePolicy,validateWindow,websiteDefinition,minutes,splitValues,escapeHTML,stateLabels,policyConsentRequired,candidateCooldownText,panelAutonomyData,policyReadbackSnapshot,requestErrorText};
  if(typeof module==='object'&&module.exports) module.exports=model;
  root.RazvilkaAutonomyModel=model;
  if(typeof document==='undefined') return;
  const $=id=>document.getElementById('a1-'+id);
  const $$=selector=>Array.from(document.querySelectorAll(selector)).filter(el=>el.closest('[data-autonomy]'));
  let preferredRouteOrder=[];
  let snapshot=null,presentationFresh=false,feeds=null,step=0,editingPolicy=null,dirty=false,loading=false,saving=false,pauseRequest=null;
  let activeTab='overview',poll=null,sourceDirty=false,adding=false,authGeneration=0,refreshRequest=null,sourceRead=0,sourceEdit=0,wizardEdit=0,viewEpoch=0;
  let consentReviewFingerprint = '';
  const requests=new Set();
  function requireGeneration(generation) { if(generation!==authGeneration){const e=new Error('Ответ относится к завершённой сессии.');e.name='AuthGenerationChanged';e.authGeneration=generation;throw e;} }
  function reportError(e,element=null) { if(e.name==='AuthGenerationChanged'||e.authGeneration!==undefined&&e.authGeneration!==authGeneration)return;if(element)element.textContent=e.message;else notify(e.message,true); }
  function nextAuthGeneration() { authGeneration++;for(const controller of requests)controller.abort();loading=false;saving=false;adding=false;pauseRequest=null; }
  let noticeTimer=null,noticeTransient=false;
  function dismissNotice() { clearTimeout(noticeTimer);noticeTimer=null;noticeTransient=false;$('notice').hidden=true; }
  root.dismissTransientAutonomyNotice=()=>{if(noticeTransient)dismissNotice();};
  function notify(message,error=false) {
    dismissNotice();
    const notice=$('notice');notice.textContent=message;notice.className=`notice${error?' error':''}`;notice.hidden=!message;
    if(!message)return;
    const close=document.createElement('button');close.type='button';close.className='notice-close';close.setAttribute('aria-label','Закрыть');close.textContent='×';close.addEventListener('click',dismissNotice);notice.appendChild(close);
    noticeTransient=!error;
    if(noticeTransient)noticeTimer=setTimeout(dismissNotice,6500);
  }
  function formatDate(value,zone) { const n=new Date(value); if(!Number.isFinite(n.getTime())||n.getFullYear()<2000) return 'Ещё нет'; try {return n.toLocaleString('ru-RU',{timeZone:zone||snapshot?.policy.timezone||'UTC',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});} catch {return n.toISOString();} }
  async function api(path,method='GET',body,attempt=0,requestGeneration=authGeneration) {
    requireGeneration(requestGeneration);
    const mutation=method!=='GET';
    if(mutation&&typeof root.invalidatePanelReads==='function')root.invalidatePanelReads();
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),20000);
    requests.add(controller);
    const headers={Accept:'application/json'};
    let token='';try {token=sessionStorage.getItem('razvilka.adminToken')||'';} catch {}
    if(token) headers.Authorization=`Bearer ${token}`;
    if(body!==undefined) headers['Content-Type']='application/json';
    try {
      const response=await fetch(path,{method,headers,credentials:'same-origin',cache:'no-store',signal:controller.signal,...(body===undefined?{}:{body:JSON.stringify(body)})});
      requireGeneration(requestGeneration);
      let data;try {data=await response.json();} catch {data={};}
      requireGeneration(requestGeneration);
      if(!response.ok && response.status===409 && data.not_started===true && data.code==='RESTORE_OPERATION_BUSY' && method!=='GET' && attempt<4) {
        clearTimeout(timer);await new Promise(resolve=>setTimeout(resolve,1500));return api(path,method,body,attempt+1,requestGeneration);
      }
      if(response.status===401 && typeof showAuth==='function') showAuth(null,'Сессия завершилась. Войдите снова.');
      if(!response.ok) {const e=new Error(response.status===401?'Войдите в основную панель.':data.error||`Запрос не выполнен (${response.status}).`);e.status=response.status;throw e;}
      requireGeneration(requestGeneration);
      return data;
    } catch(e) {
      requireGeneration(requestGeneration);
      if(e.name==='AbortError') e=new Error('Ответ не получен. Обновите состояние: запрос мог быть сохранён.');
      const message=requestErrorText(e,mutation);
      if(message!==e.message)e=new Error(message,{cause:e});
      e.authGeneration=requestGeneration;
      throw e;
    } finally {clearTimeout(timer);requests.delete(controller);if(mutation&&typeof root.invalidatePanelReads==='function')root.invalidatePanelReads();}
  }
  function tab(name) {
    if(noticeTransient)dismissNotice();
    const map={overview:'autopilot',services:'managed',sources:'subscription-settings',setup:'onboard'};
    activeTab=Object.hasOwn(map,name)?name:'overview';
    setView(map[activeTab]);
    if(snapshot&&(activeTab==='overview'||activeTab==='services'))renderServices();
    if(activeTab==='sources') void readSources();
    if(activeTab==='setup') setStep(step);
  }
  function setStep(n) {
    const focusedNext=document.activeElement===$('nextStep');
    step=Math.min(3,Math.max(0,n));
    $$('[data-step-page]').forEach(el=>el.hidden=Number(el.dataset.stepPage)!==step);
    $$('[data-step]').forEach(el=>{el.classList.toggle('active',Number(el.dataset.step)===step);el.setAttribute('aria-current',Number(el.dataset.step)===step?'step':'false');});
    $('backStep').disabled=step===0;$('nextStep').hidden=step===3;$('saveWizard').hidden=step!==3;$('stepCounter').textContent=`Шаг ${step+1} / 4`;
    $('wizardError').textContent='';if(step===3) renderReview();
    if(focusedNext&&step===3)$('saveWizard').focus();
  }
  function windowText(w) {return w.mode==='off'?'Выключено':`${w.start}–${w.end}`;}
  function checkedPreferredRoutes() {
    return selectedRouteOrder(preferredRouteOrder,$$('#a1-wizardForm input[name="preferred"]:checked').map(el=>el.value));
  }
  function updateMASQUERegistrationConsent(routes) {
    const enabled=routes.includes('usque');
    $('masqueRegistrationConsentRow').hidden=!enabled;
    const consent=$('masqueRegistrationConsent');
    consent.disabled=!enabled;
    if(!enabled)consent.checked=false;
  }
  function updateWARPRegistrationConsent(routes) {
    const enabled=routes.includes('warp-wg');
    $('warpRegistrationConsentRow').hidden=!enabled;
    const consent=$('warpRegistrationConsent');
    consent.disabled=!enabled;
    if(!enabled)consent.checked=false;
  }
  function policyFromForm() {
    if(!editingPolicy) throw new Error('Сначала загрузите настройки роутера.');
    const p=clone(editingPolicy);
    p.update_channel=$('updateChannel')?.value||'stable';p.setup_complete=true;p.enabled=$('autonomyEnabled').checked;p.inherit_new_services=$('inheritNew').checked;
    p.all_lan=!editingPolicy.setup_complete||$('scopeMode').value==='all';p.default_sources=p.all_lan?[]:splitValues($('scopeAddresses').value);
    p.timezone=$('timezone').value.trim();p.source_ids=[...new Set([...$$('input[name="source"]:checked').map(el=>el.value),...splitValues($('extraSourceIDs').value)])];
    p.preferred_source_ids=(p.preferred_source_ids||[]).filter(id=>p.source_ids.includes(id));
    p.protocols=$$('input[name="protocol"]:checked').map(el=>el.value);p.preferred_routes=checkedPreferredRoutes();
    p.allow_initial_warp_registration=p.preferred_routes.includes('warp-wg')&&$('warpRegistrationConsent').checked;
    p.allow_initial_masque_registration=p.preferred_routes.includes('usque')&&$('masqueRegistrationConsent').checked;
    p.reserve_target=Number($('reserveTargetInput').value);p.candidates_per_round=Number($('candidateLimit').value);p.check_seconds=Number($('checkInterval').value);p.reserve_seconds=Number($('reserveInterval').value);
    p.application={mode:$('appUpdateMode').value,start:$('appWindowStart').value,end:$('appWindowEnd').value,days:$$('#a1-appDays input:checked').map(el=>Number(el.value))};
    p.components={mode:$('engineUpdateMode').value,start:$('engineWindowStart').value,end:$('engineWindowEnd').value,days:$$('#a1-engineDays input:checked').map(el=>Number(el.value))};
    const firstInstall=$('firstInstall')?.value;
    if(firstInstall==='now'||firstInstall==='off') p.install_missing_components=firstInstall==='now';
    if(firstInstall==='saved-window') {
      if(p.install_missing_components==null) delete p.install_missing_components;
      else p.install_missing_components=null;
    }
    const failures=$('publicNodeFailureThreshold')?.value;
    if(failures!==undefined) {
      const count=Number(failures);
      if(count!==3||p.public_node_failure_threshold!==undefined) p.public_node_failure_threshold=count;
    }
    return p;
  }
  function fillWizard(force=false) {
    if(!snapshot||dirty&&!force) return;
    const p=clone(snapshot.policy);editingPolicy=p;preferredRouteOrder=[...(p.preferred_routes||[])];dirty=false;
    // Present a previously saved health-policy permission without writing that
    // policy or asking again. The next explicit save gives Auto its own choice.
    if(p.allow_initial_warp_registration==null&&p.setup_complete&&snapshot.warp_initial_registration_allowed===true) p.allow_initial_warp_registration=true;
    const wholeLAN=!p.setup_complete||p.all_lan;
    $('scopeMode').value=wholeLAN?'all':'selected';$('scopeAddresses').value=(p.default_sources||[]).join('\n');$('scopeAddressesLabel').hidden=wholeLAN;
    $('savedScope').hidden=!p.setup_complete;
    $('initialScope').hidden=p.setup_complete;
    $('firstStepTitle').textContent=p.setup_complete?'Область и способы':'Выберите сервисы';
    $('firstStepName').textContent=p.setup_complete?'Область действия':'Сервисы';
    $('firstStepDescription').textContent=p.setup_complete?'Устройства и способы':'Сервисы и дополнительные настройки';
    $('inheritNew').checked=p.setup_complete?!!p.inherit_new_services:true;
    $('autonomyEnabled').checked=p.setup_complete?!!p.enabled:true;$('confirmConsent').checked=false;$('releaseSafeMode').checked=false;
    if($('updateChannel'))$('updateChannel').value=p.update_channel||'stable';
    const firstInstall=$('firstInstall');
    if(firstInstall){
      const legacy=p.setup_complete&&p.install_missing_components==null;
      const initial=!p.setup_complete&&p.install_missing_components==null;
      const saved=firstInstall.querySelector?.('option[value="saved-window"]');
      if(saved) saved.hidden=!legacy;
      firstInstall.value=legacy?'saved-window':initial||p.install_missing_components===true?'now':'off';
      if($('quickFirstInstall')) $('quickFirstInstall').checked=firstInstall.value==='now';
    }
    if($('publicNodeFailureThreshold')) $('publicNodeFailureThreshold').value=p.public_node_failure_threshold??3;
    $('timezone').value=p.setup_complete?p.timezone:(Intl.DateTimeFormat().resolvedOptions().timeZone||p.timezone);
    $('reserveTargetInput').value=p.reserve_target;$('candidateLimit').value=p.candidates_per_round;$('checkInterval').value=p.check_seconds;$('reserveInterval').value=p.reserve_seconds;
    $$('input[name="protocol"]').forEach(el=>el.checked=p.protocols.includes(el.value));$$('#a1-wizardForm input[name="preferred"]').forEach(el=>el.checked=p.preferred_routes.includes(el.value));
    $('masqueRegistrationConsent').checked=p.allow_initial_masque_registration===true;
    updateMASQUERegistrationConsent(p.preferred_routes);
    $('warpRegistrationConsent').checked=p.allow_initial_warp_registration===true;
    updateWARPRegistrationConsent(p.preferred_routes);
    $('quickWARPRegistration').checked=$('warpRegistrationConsent').checked;
    $('quickMASQUERegistration').checked=$('masqueRegistrationConsent').checked;
    const presets=snapshot.source_presets||[];
    const manualSource=`<label><input type="checkbox" name="source" value="manual" ${p.source_ids.includes('manual')?'checked':''}><span>Личные подключения<small>Профили, которые вы добавили в библиотеку вручную</small></span></label>`;
    $('wizardSources').innerHTML=manualSource+presets.map(s=>`<label><input type="checkbox" name="source" value="${escapeHTML(s.id)}" ${p.source_ids.includes(s.id)?'checked':''}><span>${escapeHTML(s.name)}<small>Пресет: ${Number(s.interval_minutes)} мин · проверка на вашем роутере</small></span></label>`).join('');
    $('extraSourceIDs').value=p.source_ids.filter(id=>id!=='manual'&&!presets.some(s=>s.id===id)).join(', ');
    for(const [prefix,w] of [['app',p.application],['engine',p.components]]) {
      $(`${prefix}UpdateMode`).value=w.mode;$(`${prefix}WindowStart`).value=w.start;$(`${prefix}WindowEnd`).value=w.end;
      $(`${prefix}Days`).innerHTML=dayLabels.map(([id,label])=>`<label><input type="checkbox" value="${id}" ${w.days.includes(id)?'checked':''}><span>${label}</span></label>`).join('');
    }
    $('revisionLabel').textContent=`Редакция ${p.revision}`;
    renderReview();renderQuickStart();
  }
  let starterRenderedHash=null;
  function renderStarterReview(){
    const block=$('starterReview');if(!block||!snapshot)return;
    const r=snapshot.starter,firstSetup=!snapshot.policy.setup_complete;
    block.hidden=!firstSetup||!r?.eligible;
    const hash=block.hidden?'':r.sha256;
    if(starterRenderedHash===hash)return;
    const changed=starterRenderedHash!==null;
    starterRenderedHash=hash;
    const selectedStarter=new Set($$('input[name="initial-starter"]:checked').map(x=>x.value));
    const selected=new Set($$('input[name="initial-extra"]:checked').map(x=>x.value));
    const items=block.hidden?[]:r.items||[],reviewed=new Set(block.hidden?[]:r.optional_ids||[]);
    $('starterItems').innerHTML=items.map(s=>`<label><input type="checkbox" name="initial-starter" value="${escapeHTML(s.id)}" ${selectedStarter.has(s.id)?'checked':''}><span><b>${escapeHTML(s.name)}</b><small>${Number(s.domains)} доменов · NFQWS2</small></span></label>`).join('');
    $('initialExtras').innerHTML=(snapshot.catalog_services||[]).filter(s=>reviewed.has(s.id)).map(s=>`<label><input type="checkbox" name="initial-extra" value="${escapeHTML(s.id)}" ${selected.has(s.id)?'checked':''}/><span>${escapeHTML(s.name)}<small>Подбор по разрешениям мастера</small></span></label>`).join('');
    if(firstSetup&&changed){
      $('confirmConsent').checked=false;$('quickConsent').checked=false;
      const message='Доступный список сервисов изменился. Проверьте выбор и подтвердите настройки.';
      $('wizardError').textContent=message;$('quickError').textContent=message;
    }
  }
  function standardScopeLabel() {
    return snapshot?.network_scope_mode==='selected_devices'?'Устройства, разрешённые общей политикой':'Вся обслуживаемая сеть';
  }
  const initialScopeCopy={
    all:['Стандарт — все устройства','Роутер проверит границы домашней сети и исключения перед применением. В пределах этой сети учитываются все устройства, включая новые.'],
    selected:['Разрешённые устройства','Сохраним область, разрешённую общей политикой или выбранную ранее, и действующие исключения. Роутер проверит её перед применением.'],
    empty:['Список устройств пуст','Выбранные сервисы будут сохранены. Применение будет ждать, пока вы укажете область в настройках сети.'],
    existing:['Действующая область домашней сети','Сохранённая сетевая политика и исключения продолжат действовать. Роутер проверит область перед применением.'],
  };
  function initialScopeMode(){
    const mode=snapshot?.initial_scope_mode;
    if(Object.hasOwn(initialScopeCopy,mode))return mode;
    return snapshot?.network_scope_mode==='selected_devices'||snapshot?.policy?.default_sources?.length?'selected':'existing';
  }
  function renderReview() {
    if(!editingPolicy) return;const p=policyFromForm();
    // One explicit wizard consent covers activation; opening a page never writes.
    const releaseSafeMode = p.enabled && !snapshot?.blocked && !!(snapshot?.safe_mode || snapshot?.manual);
    const consentNeeded = policyConsentRequired(editingPolicy, p, releaseSafeMode);
    const firstScope=editingPolicy.setup_complete?null:initialScopeMode();
    const fingerprint = JSON.stringify([p, releaseSafeMode, firstScope, snapshot?.starter?.sha256,
      $$('input[name="initial-starter"]:checked').map(x => x.value).sort(),
      $$('input[name="initial-extra"]:checked').map(x => x.value).sort()]);
    if (consentReviewFingerprint !== fingerprint) $('confirmConsent').checked = false;
    consentReviewFingerprint = fingerprint;
    const consentRow = $('confirmConsent').closest('.check-row') || $('confirmConsent').closest('label');
    if (consentRow) consentRow.hidden = !consentNeeded;
    if (!consentNeeded) $('confirmConsent').checked = false;
    const firstInstall=p.install_missing_components===true?'Сразу при необходимости':p.install_missing_components===false||p.components.mode!=='install'?'Выключена':'В сохранённое окно';
    const scope=firstScope?initialScopeCopy[firstScope][0]:p.all_lan?standardScopeLabel():p.default_sources.join(', ')||'Не выбраны';
    const rows=[['Канал обновлений',p.update_channel==='preview'?'Предварительные и стабильные':'Стабильные'],['Устройства',scope],['Источники',`${p.source_ids.length} разрешено`],['Предпочитаемые обходы',p.preferred_routes.map(id=>routeLabels[id]||id).join(' → ')||'Подбор узлов'],['Резерв',`${p.reserve_target} профиля, включая основной`],['Сервисы и резерв',`${p.check_seconds} / ${p.reserve_seconds} сек`],['Первая установка компонентов',firstInstall],['Удаление публичного узла',`После ${p.public_node_failure_threshold??3} подтверждённых отказов подряд`],['RAZVILKA',`${windowText(p.application)} · ${maintenanceModeText(p.application.mode)}`],['Движки',`${windowText(p.components)} · ${maintenanceModeText(p.components.mode,true)}`],['Часовой пояс',p.timezone]];
    if(p.preferred_routes.includes('usque'))rows.push(['Первая регистрация MASQUE',p.allow_initial_masque_registration?'Разрешена':'Выключена']);
    if(p.preferred_routes.includes('warp-wg'))rows.push(['Первая регистрация WARP WireGuard',p.allow_initial_warp_registration?'Разрешена':'Выключена']);
    $('reviewSummary').innerHTML=rows.map(([k,v])=>`<div><span>${escapeHTML(k)}</span><b>${escapeHTML(v)}</b></div>`).join('');
  }
  function serviceName(id) { return (snapshot?.catalog_services||[]).find(s=>s.id===id)?.name||id; }
  // Runtime history is not a fresh service proof. Reuse the shared, TTL-aware
  // dashboard result when the unified application has loaded this service.
  function serviceProof(id) {
    const entry=typeof state==='object'&&Array.isArray(state.services)?state.services.find(s=>s.id===id):null;
    return entry&&typeof serviceDashboardSummary==='function'?serviceDashboardSummary(entry):null;
  }
  let definitionReview=null;
  function definitionControls(id, digest) {
    const review=definitionReview;
    if(!review || review.service_id!==id || review.expected_revision!==snapshot.policy.revision || review.expected_definition!==digest) {
      return `<button type="button" class="button small" data-show-definition="${escapeHTML(id)}">Проверить новый состав</button>`;
    }
    const rows=[['Домены',review.domains],['Подсети',review.cidrs],['Варианты маршрута',review.strategy],['Источники списков',review.source_refs],['Проверки',definitionChecks(review)]];
    return `<section aria-label="Новый состав сервиса"><strong>Новый состав сервиса</strong>${rows.map(([label,items])=>`<p><b>${label}</b> · ${escapeHTML(items?.join(', ')||'нет')}</p>`).join('')}<button type="button" class="button small" data-approve-definition="${escapeHTML(id)}" data-definition="${escapeHTML(digest)}" data-revision="${escapeHTML(String(review.expected_revision))}">Подтвердить этот состав</button></section>`;
  }
  async function reviewDefinition(id, approve) {
    if(!presentationFresh) throw new Error('Обновите состояние панели.');
    const revision=snapshot?.policy.revision;
    const digest=snapshot?.catalog_services.find(row=>row.id===id)?.review_definition;
    if(!digest || snapshot.services[id]?.removing) throw new Error('Обновите список сервисов.');
    if(!approve) {
      const view=viewEpoch;
      const next=await api(`/api/v1/autonomy/services?review=${encodeURIComponent(id)}`);
      if(view!==viewEpoch || !presentationFresh)return;
      if(next.service_id!==id || next.expected_revision!==revision || next.expected_definition!==digest || snapshot?.policy.revision!==revision ||
          snapshot?.catalog_services.find(row=>row.id===id)?.review_definition!==digest) throw new Error('Состав сервиса изменился. Обновите список.');
      definitionReview=next;renderServices();return;
    }
    if(definitionReview?.service_id!==id || definitionReview.expected_revision!==revision || definitionReview.expected_definition!==digest ||
        approve.definition!==digest || approve.revision!==String(revision)) throw new Error('Откройте новый состав сервиса ещё раз.');
    await api('/api/v1/autonomy/services','POST',{service_id:id,expected_revision:revision,expected_definition:digest,confirm:'REVIEW_SERVICE_DEFINITION'});
    definitionReview=null;
    notify('Состав подтверждён. Для включённого сервиса автопилот выполнит новую проверку.');
    await refresh(false,true);
  }
  function serviceRow(id,s,compact=false,name=serviceName(id)) {
    const r=snapshot.runtime[id]||{},applied=snapshot.applied_services?.[id],proof=serviceProof(id);
    const historical=['healthy','applied'].includes(r.state);
    const good=presentationFresh&&snapshot.policy.enabled&&s.enabled&&proof?.kind==='good',kind=good?'':'warning';
    const label=!presentationFresh?'Нет свежих данных':!snapshot.policy.enabled?'Автоматика на паузе':!s.enabled?'На паузе':historical?(good?'Доступен · проверено':applied?.enabled?'Применён · нужна проверка':'Нужна свежая проверка'):(stateLabels[r.state]||r.state||'Ожидает проверки');
    const route=applied?.enabled?(applied.route||applied.mode||'Не определён'):'Не применён';
    const short=route.startsWith('sing-box:node-')?`Sing-box · ${route.slice(9,24)}…`:route;
    const count=Array.isArray(r.reserves)?r.reserves.length:0;
    const needsReview=!compact && !s.removing && snapshot.catalog_services?.find(entry=>entry.id===id)?.review_definition;
    const enabledHint=snapshot.policy.enabled?'':' · общая автоматика на паузе';
    const cooldown=candidateCooldownText(r);
    const nextCheck=presentationFresh&&snapshot.policy.enabled&&!snapshot.stopped&&!snapshot.manual&&s.enabled&&Date.parse(r.next_check)>0?formatDate(r.next_check):'';
    const details=[cooldown,nextCheck&&`Следующая попытка — ${nextCheck}.`].filter(Boolean).join(' ');
    const scope=s.all_lan?standardScopeLabel():`${(s.sources||[]).length} адреса / сети`;
    return `<article class="service-card"><span class="service-icon">${typeof consoleServiceIcon === 'function' ? consoleServiceIcon({id, name: serviceName(id)}) : escapeHTML(serviceName(id).slice(0,1).toUpperCase())}</span><div class="service-main"><b>${escapeHTML(name)}</b><p>${escapeHTML(r.message||'Нет результата проверки.')}${escapeHTML(enabledHint)}</p>${details?`<p class="service-meta">${escapeHTML(details)}</p>`:""}<div class="service-route">${escapeHTML(short)}</div>${needsReview?definitionControls(id,needsReview):''}<span class="service-meta">${escapeHTML(scope)} · резерв ${count}/${snapshot.policy.reserve_target} · ${escapeHTML(formatDate(r.checked_at))}</span></div><span class="tag ${kind}">${escapeHTML(label)}</span>${compact?'':`<div class="service-actions"><button class="button small" type="button" data-manage="${escapeHTML(id)}" data-enable="${!s.enabled}" ${s.removing||(!s.enabled&&(!presentationFresh||needsReview))?'disabled':''}>${s.enabled?'Пауза':'Возобновить'}</button><button class="button small danger" type="button" data-remove="${escapeHTML(id)}" ${s.removing||!presentationFresh?'disabled':''}>${s.removing?'Снимается…':'Убрать сервис'}</button></div>`}</article>`;
  }
  function renderServices() {
    const items=Object.entries(snapshot.services||{}),q=$('serviceSearch').value.trim().toLocaleLowerCase('ru');
    const labels=root.RazvilkaInterfaceModel?.serviceLabels(snapshot.catalog_services||[]);
    const visible=items.filter(([id])=>serviceName(id).toLocaleLowerCase('ru').includes(q));
    $('serviceRows').innerHTML=visible.map(([id,s])=>serviceRow(id,s,false,labels?.get(id))).join('')||'<div class="empty"><strong>Здесь пока нет сервисов</strong>Добавьте свой сайт или выберите сервис из каталога. Он получит общие правила проверки.</div>';
    $('overviewServices').innerHTML=items.slice(0,3).map(([id,s])=>serviceRow(id,s,true,labels?.get(id))).join('')||'<div class="empty"><strong>Сначала выберите, что нужно подключить</strong>После мастера достаточно добавлять и убирать сервисы.</div>';
    const selected=$('catalogSelect').value;
    $('catalogSelect').innerHTML=(snapshot.catalog_services||[]).filter(s=>!snapshot.services[s.id]).map(s=>`<option value="${escapeHTML(s.id)}">${escapeHTML(labels?.get(s.id)||s.name)}</option>`).join('')||'<option value="">Все сервисы уже добавлены</option>';
    if([...$('catalogSelect').options].some(o=>o.value===selected)) $('catalogSelect').value=selected;
  }
  function render() {
    const p=snapshot.policy,items=Object.values(snapshot.services||{}),runtimes=Object.entries(snapshot.runtime||{});
    renderQuickStart();
    const capability=capabilityPresentation(snapshot);
    const active=presentationFresh&&capability.state==='requires-service-plan'&&p.enabled&&!snapshot.safe_mode&&!snapshot.manual&&!snapshot.stopped&&!snapshot.blocked;
    $('heroState').textContent=!presentationFresh?'Состояние обновляется':!p.setup_complete?'Нужна первоначальная настройка':active?'Автономный режим разрешён':'Автоматические изменения приостановлены';
    $('heroDot').classList.toggle('inactive',!active);
    $('heroTitle').textContent=!presentationFresh?'Нужны свежие данные':!p.setup_complete?'Настройте автопилот':active?'Автопилот включён':capability.state==='unknown'?'Доступность не подтверждена':'Автопилот приостановлен';
    $('heroDescription').textContent=!presentationFresh?'Показаны последние сохранённые настройки. Текущее состояние автопилота ещё не подтверждено.':!p.setup_complete?'Выберите сервисы для домашней сети с учётом действующих исключений. Подбор начнётся после запуска автопилота.':capability.message;
    // Before the first setup the hero action opens the wizard instead of a disabled pause.
    $('pauseButton').disabled=!!pauseRequest||(p.setup_complete&&!presentationFresh&&!p.enabled);$('pauseButton').textContent=!p.setup_complete?'Начать настройку':p.enabled?'Пауза автоматики':'Возобновить автоматику';
    $('managedCount').textContent=items.length;
    $('healthyCount').textContent=!presentationFresh?'—':Object.entries(snapshot.services||{}).filter(([id,s])=>s.enabled&&serviceProof(id)?.kind==='good').length;
    $('reserveTarget').textContent=p.reserve_target;$('sourceCount').textContent=p.source_ids.length;
    const poolMessage=presentationFresh && p.enabled && !snapshot.stopped && !snapshot.safe_mode && !snapshot.manual && !snapshot.blocked ? snapshot.node_readiness?.message : '';
    $('poolStatus').textContent=poolMessage||'';
    $('poolStatus').hidden=!poolMessage;
    $('windowSummary').innerHTML=[['RAZVILKA',p.application,snapshot.next_application_window],['Движки',p.components,snapshot.next_components_window]].map(([name,w,next])=>`<div class="window-row"><span class="window-icon">◷</span><div><b>${name}</b><small>${maintenanceModeText(w.mode,name==='Движки')} · ${escapeHTML(p.timezone)}</small><small>Ближайшее окно: ${escapeHTML(formatDate(next))}</small></div><time>${escapeHTML(windowText(w))}</time></div>`).join('');
    $('maintenanceMessage').textContent=snapshot.maintenance_message||'Фактический результат появится после обслуживания на роутере.';
    $('connectionLabel').textContent=`${presentationFresh?'Состояние роутера':'Последние настройки'} · ${formatDate(snapshot.server_time)}`;
    // Never rebuild hidden editors on every observation.
    if (activeTab==='services' || activeTab==='overview') renderServices();
    if (activeTab==='setup' || !editingPolicy) {fillWizard();renderStarterReview();}
  }
  async function refresh(force=false, live=force, discardEdit=wizardEdit) {
    // Let the core discover setup/login first. A protected read's early 401
    // must not cancel /auth/status and replace initial setup with login.
    if (state.authenticated !== true) return false;
    const generation=authGeneration;
    // A read that began before a write cannot serve as its readback. Wait for
    // the admitted read, then request a new snapshot without overlapping it.
    if(loading){if(!force&&!live)return false;const pending=refreshRequest;await pending;if(generation!==authGeneration)return false;return refreshRequest&&refreshRequest!==pending?refreshRequest:refresh(force,live,discardEdit);}
    loading=true;
    const request=(async()=>{
    try {
      const value=await api(live?'/api/v1/autonomy':'/api/v1/panel/autonomy');if(generation!==authGeneration)return false;
      const next=live?value:panelAutonomyData(value);
      // A cached poll begun before a mutation/readback must not undo its result.
      // A new process has its own publication instance and resets this ordering.
      const sameInstance=!snapshot?.observation || !next.observation || snapshot.observation.instance_id===next.observation.instance_id;
      if(!live && sameInstance && (Date.parse(next.server_time)<Date.parse(snapshot?.server_time) || next.policy.revision<snapshot?.policy?.revision)){if(next.observation.state==='retained')throw new Error('Нужны свежие данные автопилота.');return false;}
      if(live && snapshot?.observation)next.observation={...snapshot.observation,state:'available',observed_at:next.server_time};
      snapshot=next;presentationFresh=next.observation?.state!=='retained';window.dispatchEvent(new CustomEvent('razvilka:autonomy-state',{detail:next}));
      if(!presentationFresh)window.dispatchEvent(new CustomEvent('razvilka:autonomy-error',{detail:{retained:true,message:'Показаны последние настройки. Состояние обновляется.'}}));
      if(force&&discardEdit===wizardEdit) dirty=false;
      $('authRequired').hidden=true;$('workspace').hidden=false;render();return true;
    } catch(e) {
      if(generation!==authGeneration||e.name==='AuthGenerationChanged')return false;
      presentationFresh=false;if(snapshot&&e.status!==401)render();
      if(e.status===401){$('authRequired').hidden=false;$('workspace').hidden=true;}
      $('connectionLabel').textContent=e.status===401?'Требуется вход':'Нет свежего ответа';window.dispatchEvent(new CustomEvent('razvilka:autonomy-error',{detail:{status:e.status,message:e.message}}));if(activeTab!=='overview'||window.location.hash.includes('autopilot'))notify(e.status===404?'Автопилот недоступен в установленной версии. Обновите приложение; ручные настройки остаются доступны.':e.message,true);return false;
    } finally {if(generation===authGeneration)loading=false;}
    })();
    refreshRequest=request;
    try{return await request;}finally{if(refreshRequest===request)refreshRequest=null;}
  }
  async function readSources() {
    if (state.authenticated !== true) return;
    const generation=authGeneration;
    try {const ticket=++sourceRead,edit=sourceEdit;const next=await api('/api/v1/node-feeds');if(generation!==authGeneration||ticket!==sourceRead||edit!==sourceEdit||sourceDirty)return;feeds=next;renderSources();} catch(e){if(generation===authGeneration)reportError(e);}
  }
  function renderSources() {
    const list=feeds?.sources||[];
    $('sourcesList').innerHTML=list.map(s=>sourceCard(s,snapshot?.policy.timezone||'UTC')).join('')||'<section class="panel empty"><strong>Подписки пока не сохранены</strong>Выбранные в мастере источники сохраняются при завершении настройки. Здесь также можно добавить собственную подписку.</section>';
  }
  async function enroll(id,enabled=true) {
    const generation=authGeneration;
    if(!snapshot?.policy.setup_complete) throw new Error('Сначала завершите мастер.');
    const old=snapshot.services[id],revision=snapshot.policy.revision;
    try {
      await api('/api/v1/autonomy/services','POST',{service_id:id,enabled,use_defaults:!old,all_lan:old?.all_lan||false,sources:old?.sources||[],expected_revision:revision,confirm:'MANAGE_SERVICE'});
    } catch(e) {
      if(e.status!==409)throw e;
      requireGeneration(generation);
      const refreshed=await refresh(false,true);
      requireGeneration(generation);
      if(!refreshed)e.message='Не удалось получить актуальные настройки. Обновите состояние перед повтором.';
      else if(snapshot.policy.revision!==revision)e.message='Настройки автопилота изменились. Проверьте обновлённый список сервисов и при необходимости повторите действие.';
      throw e;
    }
    requireGeneration(generation);
    notify(enabled?'Сервис передан в очередь. Применение ещё не подтверждено.':'Автоподбор сервиса приостановлен; рабочий маршрут сохранён.');await refresh(false,true);
  }
  // Both setup views use the same reviewed service list and save path.
  let quickAdvanced=false,displayedInitialScope=null;
  const componentSelection = new Set();
  let componentTask = null, componentView = -1, componentMessage = '';

  function updateComponentButtons() {
    $('componentInstall').disabled = !!componentTask || !componentSelection.size;
    $('componentRead').disabled = !!componentTask || !root.RazvilkaWizardComponents;
    $('componentStatus').textContent = componentMessage;
  }
  function renderComponentChoices() {
    const api = root.RazvilkaWizardComponents;
    const rows = api?.list() || [];
    const choices = $('componentChoices');
    for (const id of componentSelection) {
      if (!rows.some(row => row.id === id && !row.installed)) componentSelection.delete(id);
    }
    const markup = rows.map(row => {
      const checked = componentSelection.has(row.id);
      const status = row.installed ? 'Уже установлен' : row.reason || (row.canInstall ? 'Можно установить' : 'Сейчас недоступен');
      const disabled = componentTask || row.installed || (!checked && !row.canInstall);
      return `<label><input type="checkbox" data-wizard-component="${escapeHTML(row.id)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}><span><b>${escapeHTML(row.name)}</b><small>${escapeHTML(status)}</small></span></label>`;
    }).join('');
    if (choices.innerHTML !== markup) choices.innerHTML = markup;
    $('componentInstall').hidden = !rows.length;
    if (!rows.length && !componentTask && !componentMessage) componentMessage = 'Нажмите «Проверить доступность», чтобы увидеть обходы для вашего роутера.';
    updateComponentButtons();
  }
  function componentTaskCurrent(task) {
    return componentTask === task && authGeneration === task.auth && viewEpoch === task.view && state.currentView === 'onboard';
  }
  async function prepareComponents(install) {
    const api = root.RazvilkaWizardComponents;
    if (!api || componentTask || saving || state.currentView !== 'onboard' || state.authenticated !== true || !snapshot || snapshot.policy.setup_complete) return;
    const ids = install ? [...componentSelection] : [];
    if (install && !ids.length) return;
    const task = {install, auth:authGeneration, view:viewEpoch};
    componentTask = task;
    componentMessage = install ? 'Проверяем выбранные компоненты…' : 'Читаем состояние компонентов…';
    renderComponentChoices();
    try {
      const refreshed = await api.refresh();
      if (!componentTaskCurrent(task)) return;
      if (refreshed === false) throw new Error('Не удалось прочитать каталог компонентов. Можно повторить проверку или продолжить настройку.');
      componentMessage = '';
      for (const id of ids) {
        const row = api.list().find(item => item.id === id);
        if (row?.installed) { componentSelection.delete(id); continue; }
        if (!row?.canInstall) throw new Error((row?.name || id) + ' — ' + (row?.reason || 'установка сейчас недоступна.'));
        componentMessage = 'Устанавливаем ' + row.name + '…';
        updateComponentButtons();
        $('componentLog').hidden = !root.RazvilkaInstallLog;
        const complete = await api.install(id);
        if (!componentTaskCurrent(task)) return;
        if (complete !== true || !api.list().some(item => item.id === id && item.installed)) {
          throw new Error('Установка ' + row.name + ' не подтверждена. Обновите список перед повторной попыткой.');
        }
        componentSelection.delete(id);
      }
      if (install) componentMessage = 'Все выбранные компоненты установлены.';
    } catch (error) {
      if (componentTaskCurrent(task)) componentMessage = error.message || 'Не удалось проверить компоненты.';
    } finally {
      if (componentTask === task) {
        componentTask = null;
        if (authGeneration === task.auth && state.currentView === 'onboard') {
          if (viewEpoch !== task.view) componentMessage = 'Обновите список для проверки состояния.';
          renderComponentChoices();
        }
      }
    }
  }
  function requireComponentChoiceComplete() {
    if (componentTask?.install) throw new Error('Дождитесь окончания установки компонентов.');
    if (componentSelection.size) throw new Error('Установите выбранные компоненты или снимите отметки, чтобы пропустить установку.');
  }
  function renderQuickStart(){
    const card=$('quickStart'),layout=$('wizardLayout');if(!card||!layout)return;
    const show=!!snapshot&&!snapshot.policy?.setup_complete&&!quickAdvanced;
    const picker=$('starterReview'),serviceTarget=$(show?'quickServices':'advancedServices');
    if(picker&&serviceTarget&&picker.parentNode!==serviceTarget)serviceTarget.append(picker);
    card.hidden=!show;layout.hidden=show;
    const componentPicker=$('componentPicker'),componentHost=$(show?'quickComponents':'fullComponents');
    if(componentPicker&&componentHost){
      componentPicker.hidden=!snapshot||snapshot.policy.setup_complete;
      if(componentPicker.parentNode!==componentHost)componentHost.append(componentPicker);
      if(!componentPicker.hidden&&state.currentView==='onboard'&&componentView!==viewEpoch){
        componentView=viewEpoch;componentMessage='';renderComponentChoices();
      }
    }
    if(!snapshot||snapshot.policy.setup_complete)return;
    const mode=initialScopeMode();
    if(displayedInitialScope!==null&&displayedInitialScope!==mode){
      $('quickConsent').checked=false;
      $('confirmConsent').checked=false;
      if(step===3)renderReview();
    }
    displayedInitialScope=mode;
    const scope=initialScopeCopy[mode].join('. ');
    $('quickScopeHint').textContent=scope;
    $('initialScopeHint').textContent=scope;
  }
  function applyQuickPreparationChoices(){
    if($('firstInstall')) $('firstInstall').value=$('quickFirstInstall')?.checked?'now':'off';
    for(const [id,quick,consent] of [['warp-wg','quickWARPRegistration','warpRegistrationConsent'],['usque','quickMASQUERegistration','masqueRegistrationConsent']]){
      const allowed=$(quick).checked;
      if(allowed){
        const method=$$('#a1-wizardForm input[name="preferred"]').find(input=>input.value===id);
        if(method)method.checked=true;
      }
      $(consent).checked=allowed;
    }
    preferredRouteOrder=checkedPreferredRoutes();
    updateWARPRegistrationConsent(preferredRouteOrder);
    updateMASQUERegistrationConsent(preferredRouteOrder);
  }
  async function runQuickStart(){
    const error=$('quickError');error.textContent='';
    try{
      if(!snapshot||!editingPolicy)throw new Error('Настройки роутера ещё загружаются.');
      if(!$('quickConsent').checked)throw new Error('Отметьте разрешение, чтобы запустить автопилот.');
      $('autonomyEnabled').checked=true;$('inheritNew').checked=true;
      applyQuickPreparationChoices();
      $$('input[name="source"]').forEach(el=>{
        el.checked=el.value==='manual'?!!$('quickManualSources')?.checked:$('quickSources').checked;
      });
      dirty=true;wizardEdit++;renderReview();$('confirmConsent').checked=true;
      $('quickStartButton').disabled=true;
      await saveWizard({preventDefault(){}},error);
    }catch(e){reportError(e,error);}finally{$('quickStartButton').disabled=false;}
  }
  async function saveWizard(event,errorTarget) {
    event.preventDefault();if(saving) return;
    const generation=authGeneration,discardEdit=wizardEdit;
    try {
      if(!snapshot?.policy?.setup_complete)requireComponentChoiceComplete();
      if(!presentationFresh)throw new Error('Сначала обновите состояние автопилота. Несохранённые поля оставлены.');
      const allowSavedEmptyScope=editingPolicy.setup_complete&&!editingPolicy.all_lan&&!editingPolicy.default_sources?.length;
      const p=validatePolicy(policyFromForm(),{allowSavedEmptyScope});
      // Editing after an earlier approval invalidates that approval.
      renderReview();
      const releaseRequested=p.enabled&&!snapshot?.blocked&&!!(snapshot?.safe_mode||snapshot?.manual);
      if(policyConsentRequired(editingPolicy,p,releaseRequested)&&!$('confirmConsent').checked) throw new Error('Подтвердите настройки автопилота.');
      const firstSetup=!editingPolicy.setup_complete;
      const request={expected_revision:editingPolicy.revision,policy:p,confirm:'SAVE_AUTONOMY',release_safe_mode:releaseRequested&&$('confirmConsent').checked};
      if(firstSetup){
        request.use_network_scope=true;
        delete p.all_lan;
        delete p.default_sources;
        if(snapshot?.starter?.eligible){
          request.starter_sha256=snapshot.starter.sha256;
          request.starter_service_ids=$$('input[name="initial-starter"]:checked').map(x=>x.value);
          request.initial_service_ids=$$('input[name="initial-extra"]:checked').map(x=>x.value);
        }
      }
      saving=true;$('saveWizard').disabled=true;
      await api('/api/v1/autonomy','PUT',request);
      requireGeneration(generation);const refreshed=await refresh(true,true,discardEdit);requireGeneration(generation);if(!refreshed)throw new Error('Настройки сохранены, но актуальное состояние не получено. Обновите состояние перед следующими изменениями.');if(discardEdit!==wizardEdit){tab('setup');notify('Отправленные настройки сохранены. Новые изменения ещё не сохранены.');return;}tab('overview');notify('Настройки сохранены на роутере. Успех проверки сервисов показывается отдельно.');
    } catch(e) { reportError(e,errorTarget||$('wizardError')); } finally {if(generation===authGeneration){saving=false;$('saveWizard').disabled=false;}}
  }
  document.addEventListener('click',event=>{
    if(!event.target.closest('[data-autonomy]')) return;
    if(event.target.closest('[data-wizard-home-scope]')){
      setView('exclusions');
      const section=document.getElementById('listScopeContent');
      section?.focus({preventScroll:true});section?.scrollIntoView?.({block:'start'});
      return;
    }
    const nav=event.target.closest('[data-tab]');if(nav){event.preventDefault();tab(nav.dataset.tab);}
    if(event.target.closest('[data-open-setup]')){tab('setup');setStep(0);}
    const stepButton=event.target.closest('[data-step]');if(stepButton)setStep(Number(stepButton.dataset.step));
    if(event.target.closest('[data-close-dialog]'))$('addServiceDialog').close();
    const show=event.target.closest('[data-show-definition]');
    if(show) void reviewDefinition(show.dataset.showDefinition).catch(e=>reportError(e));
    const approve=event.target.closest('[data-approve-definition]');
    if(approve) void reviewDefinition(approve.dataset.approveDefinition,approve.dataset).catch(e=>reportError(e));
    const action=event.target.closest('[data-manage]');if(action) void enroll(action.dataset.manage,action.dataset.enable==='true').catch(e=>reportError(e));
    const remove=event.target.closest('[data-remove]');if(remove) void (async()=>{
      const generation=authGeneration,view=viewEpoch,edit=wizardEdit,source=sourceEdit,id=remove.dataset.remove,revision=snapshot.policy.revision,definition=JSON.stringify(snapshot.catalog_services.find(s=>s.id===id)),custom=snapshot.catalog_services.some(s=>s.id===id&&s.custom);
      if(!await askConfirmation(`Убрать «${serviceName(id)}»?`,`Сначала будут сняты его маршруты. ${custom?'Пользовательская запись удалится после успешного снятия.':'Остальные сервисы останутся без изменений.'}`,'Убрать сервис')) return;
      requireGeneration(generation);
      if(view!==viewEpoch || edit!==wizardEdit || source!==sourceEdit)return;
      if(!presentationFresh || snapshot?.policy.revision!==revision || JSON.stringify(snapshot.catalog_services.find(s=>s.id===id))!==definition)throw new Error('Сервис или настройки изменились. Обновите состояние и подтвердите удаление снова.');
      await api(`/api/v1/autonomy/services/${encodeURIComponent(id)}`,'DELETE',{expected_revision:revision,confirm:'REMOVE_SERVICE',delete_definition:custom});
      requireGeneration(generation);
      if(view!==viewEpoch)return;
      notify('Удаление поставлено в очередь. Оно не считается завершённым до снятия маршрута.');await refresh(false,true);
    })().catch(e=>reportError(e));
    const add=event.target.closest('[data-feed-add]');if(add){
      const source=feeds?.sources?.find(s=>s.source_id===add.dataset.feedAdd);
      if(!source||source.saved===true)return;
      const preset=feeds.presets?.find(p=>source.source_id===`feed-${p.id}`);
      if(preset){
        setView('providers');
        const field=document.getElementById('nodeFeedPreset');
        field.value=preset.id;field.dispatchEvent(new Event('change',{bubbles:true}));
        document.getElementById('nodeSubscriptions').hidden=false;
        document.getElementById('nodeSubscriptions').scrollIntoView({block:'center'});
        document.getElementById('nodeFeedSync').focus();
      }else{
        $('subscriptionName').value=source.name||source.source_id;
        notify('Добавьте полный HTTPS-адрес этого разового источника. Скрытый адрес не восстанавливается из публичных данных; сохранение требует вашей команды.');
        $('subscriptionForm').scrollIntoView({block:'center'});$('subscriptionURL').focus();
      }
      return;
    }
    const sync=event.target.closest('[data-feed-sync]');if(sync) void (async()=>{const generation=authGeneration;await api(`/api/v1/node-feeds/${encodeURIComponent(sync.dataset.feedSync)}/sync`,'POST',{});requireGeneration(generation);notify('Запрос получения поставлен в очередь. Рабочие маршруты не менялись.');await readSources();})().catch(e=>reportError(e));
  });
  $('componentPicker')?.addEventListener('change',event=>{
    const id=event.target?.dataset?.wizardComponent;
    if(!id||componentTask)return;
    if(event.target.checked) {
      if(!root.RazvilkaWizardComponents?.list().some(row=>row.id===id&&row.canInstall&&!row.installed)){renderComponentChoices();return;}
      componentSelection.add(id);
    } else componentSelection.delete(id);
    componentMessage='';updateComponentButtons();
  });
  $('componentLog')?.addEventListener('click',()=>root.RazvilkaInstallLog?.show());
  $('componentRead')?.addEventListener('click',()=>void prepareComponents(false));
  $('componentInstall')?.addEventListener('click',()=>void prepareComponents(true));
  $('wizardForm').addEventListener('input',event=>{if(event?.target?.dataset?.wizardComponent)return;dirty=true;wizardEdit++;});
  $('wizardForm').addEventListener('change',event=>{
    if(event?.target?.dataset?.wizardComponent)return;
    if(event?.target?.name==='preferred'){
      preferredRouteOrder=checkedPreferredRoutes();
      updateMASQUERegistrationConsent(preferredRouteOrder);
      updateWARPRegistrationConsent(preferredRouteOrder);
    }
    dirty=true;wizardEdit++;$('scopeAddressesLabel').hidden=$('scopeMode').value==='all';if(step===3)renderReview();
  });
  $('wizardForm').addEventListener('submit',event=>saveWizard(event));
  $('quickStartButton').addEventListener('click',()=>void runQuickStart());
  $('quickAdvanced').addEventListener('click',()=>{
    quickAdvanced=true;
    applyQuickPreparationChoices();
    dirty=true;
    wizardEdit++;
    if($('quickManualSources')?.checked) {
      const manual=$$('input[name="source"]').find(el=>el.value==='manual');
      if(manual) {
        manual.checked=true;
        dirty=true;
        wizardEdit++;
      }
    }
    renderQuickStart();
    setStep(0);
  });
  $('quickStart').addEventListener('change',event=>{
    if(['initial-starter','initial-extra'].includes(event.target.name)||['quickSources','quickManualSources','quickFirstInstall','quickWARPRegistration','quickMASQUERegistration'].some(id=>event.target===$(id))){
      $('quickConsent').checked=false;
      dirty=true;
      wizardEdit++;
    }
  });
  $('openOptionalCatalog')?.addEventListener('click',()=>{if(typeof openCommunityCatalog==='function')openCommunityCatalog();});
  document.getElementById('communityCatalogDialog')?.addEventListener('close',()=>void refresh());
  $('backStep').addEventListener('click',()=>setStep(step-1));$('nextStep').addEventListener('click',()=>setStep(step+1));
  $('reloadButton').addEventListener('click',()=>void(async()=>{
    const generation=authGeneration,view=viewEpoch,edit=wizardEdit,source=sourceEdit;
    if((dirty||sourceDirty)&&!await askConfirmation('Обновить настройки?','Заменить несохранённые поля актуальными настройками роутера?','Обновить'))return;
    requireGeneration(generation);
    if(view!==viewEpoch)return;
    if(edit!==wizardEdit||source!==sourceEdit){notify('Появились новые правки. Подтвердите обновление ещё раз.',true);return;}
    sourceDirty=false;sourceEdit++;void refresh(true);if(activeTab==='sources')void readSources();
  })().catch(e=>reportError(e)));
  $('reloadSources').addEventListener('click',()=>void(async()=>{
    const generation=authGeneration,view=viewEpoch,edit=sourceEdit;
    if(sourceDirty&&!await askConfirmation('Обновить подписки?','Сбросить несохранённые интервалы подписок?','Обновить'))return;
    requireGeneration(generation);
    if(view!==viewEpoch)return;
    if(edit!==sourceEdit){notify('Появились новые правки. Подтвердите обновление ещё раз.',true);return;}
    sourceDirty=false;sourceEdit++;void readSources();
  })().catch(e=>reportError(e)));
  async function toggleAutonomyPause() {
    if(pauseRequest)return;
    if(!snapshot?.policy?.setup_complete){tab('setup');setStep(0);return;}
    const request=pauseRequest={generation:authGeneration},p=clone(snapshot.policy);p.enabled=!p.enabled;
    $('pauseButton').disabled=true;
    try {
      await api('/api/v1/autonomy','PUT',{expected_revision:p.revision,policy:p,confirm:'SAVE_AUTONOMY',release_safe_mode:false});
      requireGeneration(request.generation);
      const refreshed=await refresh(false,true);requireGeneration(request.generation);
      if(!refreshed)throw new Error('Настройки сохранены, но актуальное состояние не получено. Обновите состояние перед следующим изменением.');
      notify(p.enabled?'Автоматика разрешена. Общий ручной режим и остановка сохраняют свои ограничения.':'Автоматика на паузе; маршруты не удалены.');
    } catch(e) { reportError(e); }
    finally {
      if(pauseRequest===request){pauseRequest=null;if(request.generation===authGeneration)render();}
    }
  }
  $('pauseButton').addEventListener('click',()=>void toggleAutonomyPause());
  $('serviceSearch').addEventListener('input',()=>{if(snapshot)renderServices();});
  $('enrollForm').addEventListener('submit',event=>{event.preventDefault();if($('catalogSelect').value)void enroll($('catalogSelect').value).catch(e=>reportError(e));});
  $('openAddService').addEventListener('click',()=>{if(!snapshot?.policy.setup_complete){notify('Завершите мастер перед добавлением сервиса.',true);tab('setup');return;}$('addServiceError').textContent='';$('addServiceDialog').showModal();$('newServiceName').focus();});
  $('addServiceForm').addEventListener('submit',event=>{event.preventDefault();if(adding)return;adding=true;const generation=authGeneration;void(async()=>{
    const definition=websiteDefinition($('newServiceName').value,$('newServiceURL').value,$('newServiceCategory').value);
    const created=await api('/api/v1/custom-services','POST',definition);requireGeneration(generation);const refreshed=await refresh(false,true);requireGeneration(generation);if(!refreshed) throw new Error('Сервис создан, но состояние не перечитано. Обновите страницу перед повторным действием.');
    // Inheritance may already have enrolled it. An explicit action here supplies
    // the same consent for users who disabled general inheritance.
    if(!snapshot.services[created.id]) await enroll(created.id);
    requireGeneration(generation);$('addServiceDialog').close();$('addServiceForm').reset();if(typeof refreshCoreAfterEdit==='function')await refreshCoreAfterEdit();requireGeneration(generation);notify('Сервис добавлен. Автопилот проверит его на роутере.');await refresh(false,true);
  })().catch(e=>reportError(e,$('addServiceError'))).finally(()=>{if(generation===authGeneration)adding=false;});});
  $('sourcesList').addEventListener('input',()=>{sourceDirty=true;sourceEdit++;});
  $('sourcesList').addEventListener('submit',event=>{const form=event.target.closest('[data-feed-form]');if(!form)return;event.preventDefault();void(async()=>{
    const generation=authGeneration;
    const source=feeds.sources.find(s=>s.source_id===form.dataset.feedForm);if(!source||source.saved!==true)throw new Error('Источник не сохранён или изменился; обновите список.');
    const edit=sourceEdit;
    await api(`/api/v1/node-feeds/${encodeURIComponent(source.source_id)}`,'PUT',{revision:source.revision,confirm:'UPDATE_NODE_FEED',enabled:form.elements.enabled.value==='true',refresh_interval_minutes:Number(form.elements.interval.value),accept_partial:!!source.accept_partial,limit:source.limit||32});
    requireGeneration(generation);
    notify('Интервал подписки сохранён. Применённые узлы не заменялись.');if(edit!==sourceEdit)return;sourceDirty=false;await readSources();
  })().catch(e=>reportError(e));});
  $('subscriptionForm').addEventListener('submit',event=>{event.preventDefault();void(async()=>{
    const generation=authGeneration;
    const url=$('subscriptionURL').value.trim();let parsed;try{parsed=new URL(url);}catch{throw new Error('Укажите HTTPS-ссылку подписки.');}
    if(parsed.protocol!=='https:'||parsed.username||parsed.password)throw new Error('Нужна HTTPS-ссылка без логина в адресе.');
    const result=await api('/api/v1/node-feeds','POST',{name:$('subscriptionName').value.trim(),url,format:'uri-lines',enabled:true,refresh_interval_minutes:Number($('subscriptionInterval').value),limit:32,accept_partial:true,confirm:'SAVE_NODE_FEED'});
    requireGeneration(generation);
    $('subscriptionURL').value='';sourceDirty=false;notify(`Подписка сохранена: ${result.source.source_id}. Добавьте её ID в разрешённые источники мастера.`);await readSources();
  })().catch(e=>reportError(e));});
  document.addEventListener('razvilka:view-change',event=>{viewEpoch++;const name=({overview:'overview',autopilot:'overview',services:'services',managed:'services','subscription-settings':'sources',onboard:'setup'})[event.detail];if(name){activeTab=name;if(snapshot&&(name==='overview'||name==='services'))renderServices();if(name==='sources')void readSources();if(name==='setup'){fillWizard();renderStarterReview();setStep(step);}void refresh();}});
  // Explicit refresh works in background tabs too. Read only the protected
  // publication, coalesce with an in-flight read and keep unfinished form edits.
  document.addEventListener('razvilka:panel-refresh',()=>{void refresh();});
  // Quick settings already obtained an independent GET after their PUT. Share
  // that exact snapshot before another control can construct a revision/CAS.
  window.addEventListener('razvilka:autonomy-policy-readback',event=>{
    if(state.authenticated!==true)return;
    const next=policyReadbackSnapshot(snapshot,event.detail);
    if(!next)return;
    snapshot=next;presentationFresh=true;render();
    window.dispatchEvent(new CustomEvent('razvilka:autonomy-state',{detail:next}));
  });
  window.addEventListener('beforeunload',event=>{if(dirty||sourceDirty){event.preventDefault();event.returnValue='';}});
  document.addEventListener('razvilka:auth-required',()=>{nextAuthGeneration();componentSelection.clear();componentTask=null;componentView=-1;componentMessage='';if($('componentLog'))$('componentLog').hidden=true;definitionReview=null;snapshot=null;presentationFresh=false;feeds=null;editingPolicy=null;dirty=false;sourceDirty=false;$('subscriptionURL').value='';$('newServiceURL').value='';$('newServiceName').value='';$('pauseButton').disabled=true;$('authRequired').hidden=false;$('workspace').hidden=true;$('connectionLabel').textContent='Требуется вход';notify('Войдите для чтения настроек и управления.',true);if($('addServiceDialog').open)$('addServiceDialog').close();window.dispatchEvent(new CustomEvent('razvilka:autonomy-error',{detail:{status:401,message:'Войдите для чтения настроек и управления.'}}));});
  document.addEventListener('razvilka:auth-restored',()=>{nextAuthGeneration();notify('');$('wizardError').textContent='';$('addServiceError').textContent='';$('saveWizard').disabled=false;$('authRequired').hidden=true;$('connectionLabel').textContent='Загружаем настройки…';void refresh();if(activeTab==='sources')void readSources();});
  document.addEventListener('visibilitychange',()=>{if(!document.hidden)void refresh();});
  document.addEventListener('razvilka:source-consent-changed',()=>{void refresh(false,true);});
  setStep(0);void refresh();
  // This only refreshes displayed metadata. Backend jobs never depend on it.
  poll=setInterval(()=>{if(!document.hidden&&!loading&&['autopilot','services','managed','onboard','overview','updates'].includes(state.currentView))void refresh();},15000);
  window.addEventListener('pagehide',()=>{clearInterval(poll);}, {once:true});
})(typeof globalThis!=='undefined'?globalThis:this);
