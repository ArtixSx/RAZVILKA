/* RAZVILKA autonomy UI. Real endpoints only; no fake ping/PASS, browser-side
 * scheduling of router operations, or persistence of keys in browser storage. */
(function(root) {
  'use strict';
  const supportedProtocols = ['vless','hysteria2','tuic','shadowsocks'];
  const supportedRoutes = ['nfqws2','usque','warp-wg'];
  const dayLabels = [[1,'Пн'],[2,'Вт'],[3,'Ср'],[4,'Чт'],[5,'Пт'],[6,'Сб'],[0,'Вс']];
  const clone = v => JSON.parse(JSON.stringify(v));
  const escapeHTML = v => String(v ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const splitValues = v => [...new Set(String(v || '').split(/[\s,;]+/).filter(Boolean))];
  function minutes(text) { if(!/^\d{2}:\d{2}$/.test(text)) return -1; const [h,m]=text.split(':').map(Number); return h<24&&m<60 ? h*60+m : -1; }
  function validateWindow(w, component=false) {
    if(!w || !['off','check',...(component?[]:['prepare'])].includes(w.mode)) throw new Error('Автоустановка не поддерживается этой версией. Выберите проверку или подготовку.');
    if(minutes(w.start)<0||minutes(w.end)<0||w.start===w.end) throw new Error('Укажите разные корректные границы окна обслуживания.');
    if(!Array.isArray(w.days)||!w.days.length||w.days.some(d=>!Number.isInteger(d)||d<0||d>6)||new Set(w.days).size!==w.days.length) throw new Error('Выберите дни обслуживания.');
  }
  function validatePolicy(p) {
    if(!p || !p.timezone || p.timezone==='Local') throw new Error('Укажите часовой пояс IANA.');
    try { new Intl.DateTimeFormat('ru',{timeZone:p.timezone}).format(); } catch { throw new Error('Часовой пояс не распознан.'); }
    if(!Array.isArray(p.default_sources)||p.all_lan&&p.default_sources.length||!p.all_lan&&!p.default_sources.length) throw new Error('Укажите устройства либо явно выберите всю локальную сеть.');
    if(p.default_sources.length>128) throw new Error('Слишком много устройств.');
    for(const v of p.default_sources) {
      if(!/^[0-9a-fA-F:./]+$/.test(v)||/\/0$/.test(v)||v==='0.0.0.0'||v==='::'||v.startsWith('127.')||v.startsWith('::1/')) throw new Error('Нужны IP-адреса или CIDR устройств; не домены и не 0.0.0.0/0.');
    }
    if(!Array.isArray(p.source_ids)||p.source_ids.length>32||p.enabled&&!p.source_ids.length||p.source_ids.some(id=>! /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(id))) throw new Error('Выберите хотя бы один известный источник для автоматического подбора.');
    if(!Array.isArray(p.protocols)||!p.protocols.length||p.protocols.some(x=>!supportedProtocols.includes(x))) throw new Error('Выберите поддержанные протоколы.');
    if(!Array.isArray(p.preferred_routes)||p.preferred_routes.some(x=>!supportedRoutes.includes(x))) throw new Error('Неизвестный предпочтительный обход.');
    const ranges={check_seconds:[60,3600],reserve_seconds:[60,86400],reserve_target:[1,4],candidates_per_round:[1,4],failure_confirm_seconds:[10,300],max_switches_per_hour:[1,20]};
    for(const [key,[lo,hi]] of Object.entries(ranges)) if(!Number.isInteger(p[key])||p[key]<lo||p[key]>hi) throw new Error(`Параметр ${key}: допустимо ${lo}–${hi}.`);
    if(p.reserve_seconds<p.check_seconds) throw new Error('Резерв не должен проверяться чаще основного сервиса.');
    validateWindow(p.application);validateWindow(p.components,true);
    return p;
  }
  function websiteDefinition(name, input) {
    name=String(name||'').trim();input=String(input||'').trim();
    if(!name||name.length>80) throw new Error('Введите название сервиса длиной до 80 символов.');
    let url;try { url=new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input)?input:`https://${input}`); } catch { throw new Error('Проверьте адрес сайта.'); }
    const host=url.hostname.toLowerCase().replace(/\.$/,'');
    if(url.protocol!=='https:'||url.username||url.password||url.port&&url.port!=='443'||!host.includes('.')||host==='localhost'||/\.(localhost|local|invalid)$/.test(host)||/^\[/.test(host)||/^\d+\.\d+\.\d+\.\d+$/.test(host)) throw new Error('Для простого мастера нужен публичный HTTPS-домен без логина и нестандартного порта.');
    return {name,category:'other',domains:[host],strategy:['auto'],probe_url:`https://${host}/`,description:'Пользовательский сервис. Автоматическая базовая веб-проверка.',icon:'◇'};
  }
  const stateLabels={pending:'Ожидает проверки',checking:'Проверяется',healthy:'Проверен',applied:'Применён',searching:'Подбор резерва',unconfirmed:'Нет однозначного результата',paused:'На паузе', 'manual-change':'Ручное изменение', 'network-unknown':'Сеть не определена', 'apply-refused':'Применение отклонено', 'rate-limited':'Лимит переключений', 'requires-review':'Нужна проверка журнала', 'scope-pending':'Область ещё не применена', 'origin-expired':'Истёк источник', 'definition-changed':'Состав изменился', 'unsupported-scenario':'Нет подходящего теста', 'checker-unavailable':'Проверяющий модуль недоступен', 'catalog-unavailable':'Каталог недоступен', 'removal-pending':'Снятие маршрута в очереди', 'removal-blocked':'Снятие приостановлено',removed:'Удалён'};
  const model={validatePolicy,validateWindow,websiteDefinition,minutes,splitValues,escapeHTML,stateLabels};
  if(typeof module==='object'&&module.exports) module.exports=model;
  root.RazvilkaAutonomyModel=model;
  if(typeof document==='undefined') return;
  const $=id=>document.getElementById(id);
  const $$=selector=>Array.from(document.querySelectorAll(selector));
  let snapshot=null,feeds=null,step=0,editingPolicy=null,dirty=false,loading=false,saving=false;
  let activeTab='overview',poll=null,sourceDirty=false,adding=false;
  function notify(message,error=false) { $('notice').textContent=message; $('notice').className=`notice${error?' error':''}`; $('notice').hidden=!message; }
  function formatDate(value,zone) { const n=new Date(value); if(!Number.isFinite(n.getTime())||n.getFullYear()<2000) return 'Ещё нет'; try {return n.toLocaleString('ru-RU',{timeZone:zone||snapshot?.policy.timezone||'UTC',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});} catch {return n.toISOString();} }
  async function api(path,method='GET',body,attempt=0) {
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),20000);
    const headers={Accept:'application/json'};
    let token='';try {token=sessionStorage.getItem('razvilka.adminToken')||'';} catch {}
    if(token) headers.Authorization=`Bearer ${token}`;
    if(body!==undefined) headers['Content-Type']='application/json';
    try {
      const response=await fetch(path,{method,headers,credentials:'same-origin',cache:'no-store',signal:controller.signal,...(body===undefined?{}:{body:JSON.stringify(body)})});
      let data;try {data=await response.json();} catch {data={};}
      if(!response.ok && response.status===409 && data.not_started===true && data.code==='RESTORE_OPERATION_BUSY' && method!=='GET' && attempt<4) {
        clearTimeout(timer);await new Promise(resolve=>setTimeout(resolve,1500));return api(path,method,body,attempt+1);
      }
      if(!response.ok) {const e=new Error(response.status===401?'Войдите в основную панель.':data.error||`Запрос не выполнен (${response.status}).`);e.status=response.status;throw e;}
      return data;
    } catch(e) {
      if(e.name==='AbortError') throw new Error('Ответ не получен. Обновите состояние: запрос мог быть сохранён.');
      throw e;
    } finally {clearTimeout(timer);}
  }
  function tab(name) {
    if(!['overview','services','sources','setup'].includes(name)) name='overview';activeTab=name;
    $$('[data-page]').forEach(el=>el.hidden=el.dataset.page!==name);
    $$('[data-tab]').forEach(el=>{el.classList.toggle('active',el.dataset.tab===name);if(el.closest('nav'))el.setAttribute('aria-current',el.dataset.tab===name?'page':'false');});
    if(location.hash!==`#${name}`) history.replaceState(null,'',`#${name}`);
    if(name==='sources') void readSources();
    if(name==='setup') setStep(step);
  }
  function setStep(n) {
    step=Math.min(3,Math.max(0,n));
    $$('[data-step-page]').forEach(el=>el.hidden=Number(el.dataset.stepPage)!==step);
    $$('[data-step]').forEach(el=>{el.classList.toggle('active',Number(el.dataset.step)===step);el.setAttribute('aria-current',Number(el.dataset.step)===step?'step':'false');});
    $('backStep').disabled=step===0;$('nextStep').hidden=step===3;$('saveWizard').hidden=step!==3;$('stepCounter').textContent=`Шаг ${step+1} / 4`;
    $('wizardError').textContent='';if(step===3) renderReview();
  }
  function windowText(w) {return w.mode==='off'?'Выключено':`${w.start}–${w.end}`;}
  function policyFromForm() {
    if(!editingPolicy) throw new Error('Сначала загрузите настройки роутера.');
    const p=clone(editingPolicy);
    p.setup_complete=true;p.enabled=$('autonomyEnabled').checked;p.inherit_new_services=$('inheritNew').checked;
    p.all_lan=$('scopeMode').value==='all';p.default_sources=p.all_lan?[]:splitValues($('scopeAddresses').value);
    p.timezone=$('timezone').value.trim();p.source_ids=[...new Set([...$$('input[name="source"]:checked').map(el=>el.value),...splitValues($('extraSourceIDs').value)])];
    p.protocols=$$('input[name="protocol"]:checked').map(el=>el.value);p.preferred_routes=$$('input[name="preferred"]:checked').map(el=>el.value);
    p.reserve_target=Number($('reserveTargetInput').value);p.candidates_per_round=Number($('candidateLimit').value);p.check_seconds=Number($('checkInterval').value);p.reserve_seconds=Number($('reserveInterval').value);
    p.application={mode:$('appUpdateMode').value,start:$('appWindowStart').value,end:$('appWindowEnd').value,days:$$('#appDays input:checked').map(el=>Number(el.value))};
    p.components={mode:$('engineUpdateMode').value,start:$('engineWindowStart').value,end:$('engineWindowEnd').value,days:$$('#engineDays input:checked').map(el=>Number(el.value))};
    return p;
  }
  function fillWizard(force=false) {
    if(!snapshot||dirty&&!force) return;
    const p=clone(snapshot.policy);editingPolicy=p;dirty=false;
    $('scopeMode').value=p.all_lan?'all':'selected';$('scopeAddresses').value=(p.default_sources||[]).join('\n');$('scopeAddressesLabel').hidden=p.all_lan;
    $('inheritNew').checked=p.setup_complete?!!p.inherit_new_services:true;
    $('autonomyEnabled').checked=p.setup_complete?!!p.enabled:true;$('confirmConsent').checked=false;$('releaseSafeMode').checked=false;
    $('timezone').value=p.setup_complete?p.timezone:(Intl.DateTimeFormat().resolvedOptions().timeZone||p.timezone);
    $('reserveTargetInput').value=p.reserve_target;$('candidateLimit').value=p.candidates_per_round;$('checkInterval').value=p.check_seconds;$('reserveInterval').value=p.reserve_seconds;
    $$('input[name="protocol"]').forEach(el=>el.checked=p.protocols.includes(el.value));$$('input[name="preferred"]').forEach(el=>el.checked=p.preferred_routes.includes(el.value));
    const presets=snapshot.source_presets||[];
    $('wizardSources').innerHTML=presets.map(s=>`<label><input type="checkbox" name="source" value="${escapeHTML(s.id)}" ${p.source_ids.includes(s.id)?'checked':''}><span>${escapeHTML(s.name)}<small>Пресет: ${Number(s.interval_minutes)} мин · проверка на вашем роутере</small></span></label>`).join('');
    $('extraSourceIDs').value=p.source_ids.filter(id=>!presets.some(s=>s.id===id)).join(', ');
    for(const [prefix,w] of [['app',p.application],['engine',p.components]]) {
      $(`${prefix}UpdateMode`).value=w.mode;$(`${prefix}WindowStart`).value=w.start;$(`${prefix}WindowEnd`).value=w.end;
      $(`${prefix}Days`).innerHTML=dayLabels.map(([id,label])=>`<label><input type="checkbox" value="${id}" ${w.days.includes(id)?'checked':''}><span>${label}</span></label>`).join('');
    }
    $('revisionLabel').textContent=`Редакция ${p.revision}`;
    renderReview();
  }
  function renderReview() {
    if(!editingPolicy) return;const p=policyFromForm();
    const rows=[['Устройства',p.all_lan?'Вся локальная сеть':p.default_sources.join(', ')||'Не выбраны'],['Источники',`${p.source_ids.length} разрешено`],['Предпочитаемые обходы',p.preferred_routes.join(' → ')||'Подбор узлов'],['Резерв',`${p.reserve_target} профиля, включая основной`],['Сервисы и резерв',`${p.check_seconds} / ${p.reserve_seconds} сек`],['RAZVILKA',`${windowText(p.application)} · ${p.application.mode==='prepare'?'Подготовка, не установка':'Проверка'}`],['Движки',`${windowText(p.components)} · Проверка каталога`],['Часовой пояс',p.timezone]];
    $('reviewSummary').innerHTML=rows.map(([k,v])=>`<div><span>${escapeHTML(k)}</span><b>${escapeHTML(v)}</b></div>`).join('');
  }
  function serviceName(id) { return (snapshot?.catalog_services||[]).find(s=>s.id===id)?.name||id; }
  function serviceRow(id,s,compact=false) {
    const r=snapshot.runtime[id]||{},applied=snapshot.applied_services?.[id],label=s.enabled?(stateLabels[r.state]||r.state||'Ожидает проверки'):'На паузе';
    const good=['healthy','applied'].includes(r.state)&&s.enabled,kind=good?'':'warning';
    const route=applied?.enabled?(applied.route||applied.mode||'Не определён'):'Не применён';
    const short=route.startsWith('sing-box:node-')?`Sing-box · ${route.slice(9,24)}…`:route;
    const count=Array.isArray(r.reserves)?r.reserves.length:0;
    const enabledHint=snapshot.policy.enabled?'':' · общая автоматика на паузе';
    return `<article class="service-card"><span class="service-icon">${escapeHTML(serviceName(id).slice(0,1).toUpperCase())}</span><div class="service-main"><b>${escapeHTML(serviceName(id))}</b><p>${escapeHTML(r.message||'Нет результата проверки.')}${escapeHTML(enabledHint)}</p><div class="service-route">${escapeHTML(short)}</div><span class="service-meta">${s.all_lan?'Вся локальная сеть':`${s.sources.length} адреса / сети`} · резерв ${count}/${snapshot.policy.reserve_target} · ${escapeHTML(formatDate(r.checked_at))}</span></div><span class="tag ${kind}">${escapeHTML(label)}</span>${compact?'':`<div class="service-actions"><button class="button small" type="button" data-manage="${escapeHTML(id)}" data-enable="${!s.enabled}" ${s.removing?'disabled':''}>${s.enabled?'Пауза':'Возобновить'}</button><button class="button small danger" type="button" data-remove="${escapeHTML(id)}" ${s.removing?'disabled':''}>${s.removing?'Снимается…':'Убрать сервис'}</button></div>`}</article>`;
  }
  function renderServices() {
    const items=Object.entries(snapshot.services||{}),q=$('serviceSearch').value.trim().toLocaleLowerCase('ru');
    const visible=items.filter(([id])=>serviceName(id).toLocaleLowerCase('ru').includes(q));
    $('serviceRows').innerHTML=visible.map(([id,s])=>serviceRow(id,s)).join('')||'<div class="empty"><strong>Здесь пока нет сервисов</strong>Добавьте свой сайт или выберите сервис из каталога. Он получит общие правила проверки.</div>';
    $('overviewServices').innerHTML=items.slice(0,3).map(([id,s])=>serviceRow(id,s,true)).join('')||'<div class="empty"><strong>Сначала выберите, что нужно подключить</strong>После мастера достаточно добавлять и убирать сервисы.</div>';
    const selected=$('catalogSelect').value;
    $('catalogSelect').innerHTML=(snapshot.catalog_services||[]).filter(s=>!snapshot.services[s.id]).map(s=>`<option value="${escapeHTML(s.id)}">${escapeHTML(s.name)}</option>`).join('')||'<option value="">Все сервисы уже добавлены</option>';
    if([...$('catalogSelect').options].some(o=>o.value===selected)) $('catalogSelect').value=selected;
  }
  function render() {
    const p=snapshot.policy,items=Object.values(snapshot.services||{}),runtimes=Object.entries(snapshot.runtime||{});
    const active=p.enabled&&!snapshot.safe_mode&&!snapshot.manual&&!snapshot.stopped&&!snapshot.blocked;
    $('heroState').textContent=!p.setup_complete?'Нужна первоначальная настройка':active?'Автономный режим разрешён':'Автоматические изменения приостановлены';
    $('heroDot').classList.toggle('inactive',!active);
    $('heroTitle').textContent=!p.setup_complete?'Один мастер. Дальше — сервисы.':active?'Проверяем. Сохраняем. Восстанавливаем.':'Сеть не меняется без разрешения';
    $('heroDescription').textContent=!p.setup_complete?'Выберите устройства, источники и расписания. Подбор начнётся после сохранения вашего согласия.':snapshot.safe_mode?'Safe Mode запрещает применение маршрутов. Снять его можно отдельным согласием в мастере.':snapshot.stopped?'Собственные маршруты остановлены в основной панели. Мастер не снимает эту остановку автоматически.':snapshot.manual?'В основной панели включена ручная настройка. Автоматическое применение приостановлено.':!p.enabled?'Пауза останавливает автоматические изменения, но не удаляет применённые маршруты.':'Для каждого сервиса сохраняется пригодный путь. Новые кандидаты получают разрешение только после точной проверки.';
    $('pauseButton').disabled=!p.setup_complete;$('pauseButton').textContent=p.enabled?'Пауза автоматики':'Возобновить автоматику';
    $('managedCount').textContent=items.length;
    $('healthyCount').textContent=runtimes.filter(([id,r])=>snapshot.services[id]?.enabled&&['healthy','applied'].includes(r.state)).length;
    $('reserveTarget').textContent=p.reserve_target;$('sourceCount').textContent=p.source_ids.length;
    $('windowSummary').innerHTML=[['RAZVILKA',p.application,snapshot.next_application_window],['Движки',p.components,snapshot.next_components_window]].map(([name,w,next])=>`<div class="window-row"><span class="window-icon">◷</span><div><b>${name}</b><small>${w.mode==='off'?'Выключено':w.mode==='prepare'?'Подготовка, без установки':'Проверка обновлений'} · ${escapeHTML(p.timezone)}</small><small>Ближайшее окно: ${escapeHTML(formatDate(next))}</small></div><time>${escapeHTML(windowText(w))}</time></div>`).join('');
    $('maintenanceMessage').textContent=snapshot.maintenance_message||'Фактический результат появится после обслуживания на роутере.';
    $('connectionLabel').textContent=`Состояние роутера · ${formatDate(snapshot.server_time)}`;
    renderServices();fillWizard();
  }
  async function refresh(force=false) {
    if(loading) return;loading=true;
    try {
      const next=await api('/api/v1/autonomy');snapshot=next;
      if(force) dirty=false;
      $('authRequired').hidden=true;$('workspace').hidden=false;render();return true;
    } catch(e) {
      if(e.status===401){$('authRequired').hidden=false;$('workspace').hidden=true;}
      $('connectionLabel').textContent=e.status===401?'Требуется вход':'Нет свежего ответа';notify(e.message,true);return false;
    } finally {loading=false;}
  }
  async function readSources() {
    try {const next=await api('/api/v1/node-feeds');feeds=next;if(sourceDirty)return;renderSources();} catch(e){notify(e.message,true);}
  }
  function renderSources() {
    const list=feeds?.sources||[];
    $('sourcesList').innerHTML=list.map(s=>`<article class="panel source-card" data-source-id="${escapeHTML(s.source_id)}"><div class="section-title"><h2>${escapeHTML(s.name||s.source_id)}</h2><span class="tag ${s.enabled?'':'neutral'}">${s.enabled?'Таймер включён':'Таймер выключен'}</span></div><code>${escapeHTML(s.source_id)}</code><dl><dt>Последняя попытка</dt><dd>${escapeHTML(formatDate(s.last_attempt_at))}</dd><dt>Успешное получение</dt><dd>${escapeHTML(formatDate(s.last_success_at))}</dd><dt>Следующий запрос</dt><dd>${escapeHTML(formatDate(s.next_refresh_at))}</dd><dt>Последний результат</dt><dd>${escapeHTML(s.status||'Ожидается')} · ${Number(s.imported||0)} записей</dd></dl><form class="source-actions" data-feed-form="${escapeHTML(s.source_id)}"><label><span>Интервал, мин</span><input name="interval" type="number" min="15" max="10080" value="${Number(s.refresh_interval_minutes||60)}" required></label><label><span>Таймер</span><select name="enabled"><option value="true" ${s.enabled?'selected':''}>Включён</option><option value="false" ${!s.enabled?'selected':''}>Выключен</option></select></label><button class="button small" type="submit">Сохранить</button><button class="button small" type="button" data-feed-sync="${escapeHTML(s.source_id)}">Получить сейчас</button></form></article>`).join('')||'<section class="panel empty"><strong>Подписки пока не сохранены</strong>Выбранные в мастере пресеты будут сохранены backend после включения режима. Здесь также можно добавить собственную подписку.</section>';
  }
  async function enroll(id,enabled=true) {
    if(!snapshot?.policy.setup_complete) throw new Error('Сначала завершите мастер.');
    const old=snapshot.services[id];
    await api('/api/v1/autonomy/services','POST',{service_id:id,enabled,use_defaults:!old,all_lan:old?.all_lan||false,sources:old?.sources||[],expected_revision:snapshot.policy.revision,confirm:'MANAGE_SERVICE'});
    notify(enabled?'Сервис передан в очередь. Применение ещё не подтверждено.':'Автоподбор сервиса приостановлен; рабочий маршрут сохранён.');await refresh();
  }
  async function saveWizard(event) {
    event.preventDefault();if(saving) return;
    try {
      if(!$('confirmConsent').checked) throw new Error('Подтвердите источники и область устройств.');
      const p=validatePolicy(policyFromForm());
      if($('releaseSafeMode').checked&&!p.enabled) throw new Error('Не снимайте Safe Mode при выключенной автоматике.');
      saving=true;$('saveWizard').disabled=true;
      await api('/api/v1/autonomy','PUT',{expected_revision:editingPolicy.revision,policy:p,confirm:'SAVE_AUTONOMY',release_safe_mode:$('releaseSafeMode').checked});
      dirty=false;await refresh(true);notify('Настройки сохранены на роутере. Успех проверки сервисов показывается отдельно.');tab('overview');
    } catch(e) { $('wizardError').textContent=e.message; } finally {saving=false;$('saveWizard').disabled=false;}
  }
  document.addEventListener('click',event=>{
    const nav=event.target.closest('[data-tab]');if(nav){event.preventDefault();tab(nav.dataset.tab);}
    if(event.target.closest('[data-open-setup]')){tab('setup');setStep(0);}
    const stepButton=event.target.closest('[data-step]');if(stepButton)setStep(Number(stepButton.dataset.step));
    if(event.target.closest('[data-close-dialog]'))$('addServiceDialog').close();
    const action=event.target.closest('[data-manage]');if(action) void enroll(action.dataset.manage,action.dataset.enable==='true').catch(e=>notify(e.message,true));
    const remove=event.target.closest('[data-remove]');if(remove) void (async()=>{
      const id=remove.dataset.remove,custom=snapshot.catalog_services.some(s=>s.id===id&&s.custom);
      if(!confirm(`Убрать «${serviceName(id)}»? Сначала будут сняты его маршруты. ${custom?'Пользовательская запись удалится после успешного снятия.':'Остальные сервисы останутся без изменений.'}`)) return;
      await api(`/api/v1/autonomy/services/${encodeURIComponent(id)}`,'DELETE',{expected_revision:snapshot.policy.revision,confirm:'REMOVE_SERVICE',delete_definition:custom});
      notify('Удаление поставлено в очередь. Оно не считается завершённым до снятия маршрута.');await refresh();
    })().catch(e=>notify(e.message,true));
    const sync=event.target.closest('[data-feed-sync]');if(sync) void (async()=>{await api(`/api/v1/node-feeds/${encodeURIComponent(sync.dataset.feedSync)}/sync`,'POST',{});notify('Запрос получения поставлен в очередь. Рабочие маршруты не менялись.');await readSources();})().catch(e=>notify(e.message,true));
  });
  $('wizardForm').addEventListener('input',()=>{dirty=true;});$('wizardForm').addEventListener('change',()=>{dirty=true;$('scopeAddressesLabel').hidden=$('scopeMode').value==='all';if(step===3)renderReview();});
  $('wizardForm').addEventListener('submit',saveWizard);
  $('backStep').addEventListener('click',()=>setStep(step-1));$('nextStep').addEventListener('click',()=>setStep(step+1));
  $('reloadButton').addEventListener('click',()=>{if(!dirty||confirm('Заменить несохранённые поля актуальными настройками роутера?')){sourceDirty=false;void refresh(true);if(activeTab==='sources')void readSources();}});
  $('reloadSources').addEventListener('click',()=>{if(!sourceDirty||confirm('Сбросить несохранённые интервалы подписок?')){sourceDirty=false;void readSources();}});
  $('pauseButton').addEventListener('click',()=>void(async()=>{const p=clone(snapshot.policy);p.enabled=!p.enabled;await api('/api/v1/autonomy','PUT',{expected_revision:p.revision,policy:p,confirm:'SAVE_AUTONOMY',release_safe_mode:false});await refresh();notify(p.enabled?'Автоматика разрешена. Safe Mode и общий ручной режим сохраняют свои ограничения.':'Автоматика на паузе; маршруты не удалены.');})().catch(e=>notify(e.message,true)));
  $('serviceSearch').addEventListener('input',()=>{if(snapshot)renderServices();});
  $('enrollForm').addEventListener('submit',event=>{event.preventDefault();if($('catalogSelect').value)void enroll($('catalogSelect').value).catch(e=>notify(e.message,true));});
  $('openAddService').addEventListener('click',()=>{if(!snapshot?.policy.setup_complete){notify('Завершите мастер перед добавлением сервиса.',true);tab('setup');return;}$('addServiceError').textContent='';$('addServiceDialog').showModal();$('newServiceName').focus();});
  $('addServiceForm').addEventListener('submit',event=>{event.preventDefault();if(adding)return;adding=true;void(async()=>{
    const definition=websiteDefinition($('newServiceName').value,$('newServiceURL').value);
    const created=await api('/api/v1/custom-services','POST',definition);if(!await refresh()) throw new Error('Сервис создан, но состояние не перечитано. Обновите страницу перед повторным действием.');
    // Inheritance may already have enrolled it. An explicit action here supplies
    // the same consent for users who disabled general inheritance.
    if(!snapshot.services[created.id]) await enroll(created.id);
    $('addServiceDialog').close();$('addServiceForm').reset();notify('Сервис добавлен. Начнётся реальная проверка, а не демонстрационный PASS.');await refresh();
  })().catch(e=>$('addServiceError').textContent=e.message).finally(()=>{adding=false;});});
  $('sourcesList').addEventListener('input',()=>{sourceDirty=true;});
  $('sourcesList').addEventListener('submit',event=>{const form=event.target.closest('[data-feed-form]');if(!form)return;event.preventDefault();void(async()=>{
    const source=feeds.sources.find(s=>s.source_id===form.dataset.feedForm);if(!source)throw new Error('Источник изменился; обновите список.');
    await api(`/api/v1/node-feeds/${encodeURIComponent(source.source_id)}`,'PUT',{revision:source.revision,confirm:'UPDATE_NODE_FEED',enabled:form.elements.enabled.value==='true',refresh_interval_minutes:Number(form.elements.interval.value),accept_partial:!!source.accept_partial,limit:source.limit||32});
    sourceDirty=false;notify('Интервал подписки сохранён. Применённые узлы не заменялись.');await readSources();
  })().catch(e=>notify(e.message,true));});
  $('subscriptionForm').addEventListener('submit',event=>{event.preventDefault();void(async()=>{
    const url=$('subscriptionURL').value.trim();let parsed;try{parsed=new URL(url);}catch{throw new Error('Укажите HTTPS-ссылку подписки.');}
    if(parsed.protocol!=='https:'||parsed.username||parsed.password)throw new Error('Нужна HTTPS-ссылка без логина в адресе.');
    const result=await api('/api/v1/node-feeds','POST',{name:$('subscriptionName').value.trim(),url,format:'uri-lines',enabled:true,refresh_interval_minutes:Number($('subscriptionInterval').value),limit:32,accept_partial:true,confirm:'SAVE_NODE_FEED'});
    $('subscriptionURL').value='';sourceDirty=false;notify(`Подписка сохранена: ${result.source.source_id}. Добавьте её ID в разрешённые источники мастера.`);await readSources();
  })().catch(e=>notify(e.message,true));});
  window.addEventListener('hashchange',()=>tab(location.hash.slice(1)));
  window.addEventListener('beforeunload',event=>{if(dirty||sourceDirty){event.preventDefault();event.returnValue='';}});
  document.addEventListener('visibilitychange',()=>{if(!document.hidden)void refresh();});
  tab(location.hash.slice(1));void refresh();
  // This only refreshes displayed metadata. Backend jobs never depend on it.
  poll=setInterval(()=>{if(!document.hidden&&!loading)void refresh();},15000);
  window.addEventListener('pagehide',()=>{clearInterval(poll);}, {once:true});
})(typeof globalThis!=='undefined'?globalThis:this);
