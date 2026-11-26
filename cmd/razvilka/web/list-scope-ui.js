/* Shared LIST intent. The explicit save reviews the whole policy; reads and
   local edits never apply traffic or grant a provider. */
'use strict';
const listScopeEditor = {epoch:0,base:null,draft:null,dirty:false,conflict:false,unknown:false,pending:null,submitted:null,message:'',query:'',optionsAttempted:false,optionsRead:null};
const listScopeReviewPath = '/api/v1/networkpolicy/review';
const listScopeOptionsPath = '/api/v1/networkpolicy/scope-options';
const listScopeCopy = value => JSON.parse(JSON.stringify(value));
const listScopeComparable = value => Array.isArray(value) ? value.map(listScopeComparable) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key=>[key,listScopeComparable(value[key])])) : value;
const listScopeSame = (a,b) => JSON.stringify(listScopeComparable(a)) === JSON.stringify(listScopeComparable(b));
const listScopeIDs = value => value === null || Array.isArray(value) && value.length <= 128 && value.every(id => typeof id === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(id)) && new Set(value).size === value.length;
const listScopeValues = value => value || [];

function listScopeClientsValid(c) {
  return c && ['lan_except','selected_devices'].includes(c.mode) && ['inherit','base'].includes(c.new_devices)
    && ['segment_ids','device_ids','excluded_device_ids'].every(key => Object.hasOwn(c,key) && listScopeIDs(c[key]))
    && listScopeValues(c.segment_ids).length > 0 && listScopeValues(c.segment_ids).length <= 16
    && Object.hasOwn(c,'excluded_cidrs') && (c.excluded_cidrs === null || Array.isArray(c.excluded_cidrs) && c.excluded_cidrs.length <= 64 && c.excluded_cidrs.every(v => typeof v === 'string'))
    && (c.mode === 'lan_except' ? !listScopeValues(c.device_ids).length : listScopeValues(c.device_ids).length > 0 && c.new_devices === 'base');
}
function listScopeReview(value) {
  if (!value || !Number.isSafeInteger(value.revision) || value.revision < 0 || value.live_applied !== false || !Object.hasOwn(value,'policy') || !Object.hasOwn(value,'consent')) return null;
  const p=value.policy;
  if (p !== null && (!p || ![1,2].includes(p.schema) || !Number.isSafeInteger(p.revision) || p.revision < 1 || !listScopeClientsValid(p.clients) || p.traffic?.mode !== 'selected_services')) return null;
  if (value.consent !== null && (!value.consent || !Object.hasOwn(value.consent,'grants') || value.consent.grants !== null && !Array.isArray(value.consent.grants))) return null;
  return listScopeCopy({revision:value.revision,policy:value.policy,consent:value.consent,live_applied:false});
}
function listScopeOptions(value) {
  const nullable=v => v === null || typeof v === 'string';
  if (!value || value.schema !== 1 || value.ok !== true || value.effect_authorized !== false || value.live_applied !== false
    || !Number.isSafeInteger(value.revision) || value.revision < 0 || !Number.isSafeInteger(value.policy_revision) || value.policy_revision < 0
    || !['available','partial','unavailable'].includes(value.state) || typeof value.code !== 'string' || !nullable(value.observed_at) || !nullable(value.fresh_until)
    || !Array.isArray(value.segments) || value.segments.length > 48 || !Array.isArray(value.devices) || value.devices.length > 1024
    || !Array.isArray(value.retained_segment_ids) || value.retained_segment_ids.length > 32 || !Array.isArray(value.retained_device_ids) || value.retained_device_ids.length > 512) return null;
  for(const [rows,states,fields] of [[value.segments,['observed','unknown','unavailable'],['native_name','interface']], [value.devices,['observed','not_observed','unknown','unavailable'],['segment_id']]]) {
    if(new Set(rows.map(r=>r?.id)).size !== rows.length || rows.some(r=>!r || typeof r.id !== 'string' || typeof r.label !== 'string' || !states.includes(r.state) || typeof r.code !== 'string' || typeof r.selection_candidate !== 'boolean' || fields.some(key=>!Object.hasOwn(r,key)||!nullable(r[key])) || r.selection_candidate && (r.state !== 'observed' || value.state === 'unavailable')))return null;
  }
  if(value.segments.some(row=>Object.hasOwn(row,'exclusion_candidate')))return null;
  for(const row of value.devices) {
    if(!Object.hasOwn(row,'exclusion_candidate'))continue;
    if(typeof row.exclusion_candidate!=='boolean')return null;
    if(!row.exclusion_candidate)continue;
    const segment=value.segments.find(s=>s.id===row.segment_id);
    if(value.state!=='partial' || value.code!=='BINDINGS_IPV6_PREFIX_UNKNOWN'
      || row.state!=='observed' || row.code!=='OBSERVED_HOME_IPV4_EXCLUSION' || row.selection_candidate
      || !/^mac-[0-9a-f][02468ace](?:-[0-9a-f]{2}){5}$/.test(row.id) || row.id==='mac-00-00-00-00-00-00'
      || !segment?.selection_candidate || !row.segment_id)return null;
  }
  return listScopeCopy(value);
}
function acceptListScopeOptions(value) {
  const snapshot=listScopeOptions(value);if(!snapshot)throw new Error('Данные домашних сегментов получены не полностью. Последние ID сохранены.');
  if(state.homeScope && snapshot.revision < state.homeScope.revision)throw new Error('Получены прежние данные домашних сегментов.');
  state.homeScope=snapshot;
}
function listScopeOptionsCurrent() {
  const r=listScopeCurrent(),s=state.homeScope,now=Date.now();
  return r && state.dataLoad?.homeScope?.phase === 'ready' && s && s.state !== 'unavailable' && s.revision === r.revision && s.policy_revision === (r.policy?.revision || 0)
    && Number.isFinite(Date.parse(s.observed_at)) && Date.parse(s.observed_at) <= now+60000 && Date.parse(s.fresh_until) > now;
}
function listScopeReset(snapshot) {
  const e=listScopeEditor;
  e.base=snapshot;e.draft=snapshot?.policy ? listScopeCopy(snapshot.policy.clients) : {mode:'lan_except',segment_ids:[],device_ids:[],excluded_device_ids:[],excluded_cidrs:[],new_devices:'inherit'};
  e.exclusionSegments=new Map();e.dirty=false;e.conflict=false;
}
function acceptListScopeReview(value) {
  const snapshot=listScopeReview(value);
  if (!snapshot) throw new Error('Общая область получена не полностью или режим не поддерживается. Последние данные сохранены.');
  if (state.networkPolicyReview && snapshot.revision < state.networkPolicyReview.revision) throw new Error('Получена прежняя редакция области. Обновите состояние.');
  state.networkPolicyReview=snapshot;wizardScope.consentCurrent=value.scope_consent_current===true;
  const e=listScopeEditor;
  if (!e.dirty && !e.pending && !e.unknown) listScopeReset(snapshot);
  else if (e.base && snapshot.revision !== e.base.revision) e.conflict=true;
}
function listScopePolicy(base, clients) {
  const policy=base.policy ? listScopeCopy(base.policy) : {
    schema:2,revision:1,clients:null,
    traffic:{mode:'selected_services',all_except_allowed:false,auto_hostlist_allowed:false,unavailable:'retain'},
    rules:[],russian:{enabled:false,auto_update_allowed:false,revision:0,service_ids:[],broad_tlds:[]}
  };
  policy.clients=listScopeCopy(clients);
  return policy;
}
function listScopePolicyEqual(a,b,allowInheritedExclusions=false) {
  if (!a || !b) return a === b;
  const left=listScopeCopy(a),right=listScopeCopy(b);delete left.revision;delete right.revision;
  // On first review the server carries an inactive negative document into the
  // new policy. Only that documented server addition is outside this payload.
  if (allowInheritedExclusions && !Object.hasOwn(left,'resource_exclusions')) delete right.resource_exclusions;
  return listScopeSame(left,right);
}
function listScopeCurrent() {
  return state.authenticated === true && state.dataLoad?.networkPolicyReview?.phase === 'ready' ? state.networkPolicyReview : null;
}
const wizardScope = {mode:null, needsRead:false, refreshingPolicy:false, refreshPolicy:null, consentCurrent:false, version:0, displayed:'', message:''};
function wizardScopeActive() {
  return state.authenticated === true && state.currentView === 'onboard' && wizardScope.mode !== null;
}
function wizardScopeHome() {
  if (!listScopeOptionsCurrent()) return null;
  const homes = state.homeScope.segments.filter(s => s.native_name === 'Home' && s.selection_candidate && s.state === 'observed');
  return homes.length === 1 ? homes[0] : null;
}
function wizardScopeState() {
  const r = listScopeCurrent(), e = listScopeEditor;
  if (!r || wizardScope.refreshingPolicy || wizardScope.needsRead || e.optionsRead || e.pending || e.unknown || e.conflict || e.dirty || state.applyRequest) return 'waiting';
  if (r.policy) return wizardScope.consentCurrent ? 'saved' : 'renew';
  if (['empty','selected'].includes(wizardScope.mode)) return 'legacy';
  return wizardScope.mode === 'all' && wizardScopeHome() ? 'home' : 'missing';
}
function renderWizardScope() {
  const text=document.getElementById('a1-homeStatus'), confirm=document.getElementById('a1-homeConfirm'), reload=document.getElementById('a1-homeRead');
  if (!text || !confirm || !reload || !wizardScopeActive()) return;
  const r=listScopeCurrent(), e=listScopeEditor, outcome=wizardScopeState(), home=wizardScopeHome();
  const label=home ? (home.label || home.native_name) + (home.interface ? ' ('+home.interface+')' : '') : '';
  let message='';
  if (r?.policy) {
    const clients=r.policy.clients;
    const segments=listScopeValues(clients.segment_ids).join(', ');
    message=(clients.mode==='selected_devices'?'Только выбранные устройства':'Домашние сегменты') + ' · ' + segments
      + '. Устройств без обхода: ' + listScopeValues(clients.excluded_device_ids).length + '. ';
  }
  switch(outcome) {
    case 'saved': message+='Роутер подтвердил сохранённую область. Действующие исключения сохраняются.'; break;
    case 'renew': message+='Требуется повторное подтверждение с прежними ограничениями и разрешениями.'; break;
    case 'legacy': message+='Сохраним ранее заданное ограничение устройств. Добавлять всю домашнюю сеть не требуется.'; break;
    case 'home': message+='Роутер обнаружил домашний сегмент '+label+'. Новые устройства этой сети будут использовать правила выбранных сервисов. Исключения можно добавить позже.'; break;
    case 'missing': message+='Не удалось однозначно определить домашнюю сеть. Обновите список сетей.'; break;
    default: message+=wizardScope.refreshingPolicy?'Перечитываем список сервисов для этой области…':e.pending?'Сохраняем область и проверяем ответ роутера…':e.optionsRead?'Читаем настройки сети…':e.unknown||e.conflict||e.dirty?'Сохранение области ещё не подтверждено. Проверьте настройки перед запуском.':'Читаем сохранённую область…';
  }
  text.textContent=message+(wizardScope.message?' '+wizardScope.message:'')+((e.unknown||e.conflict)&&e.message?' '+e.message:'');
  confirm.hidden=!['home','renew'].includes(outcome);
  confirm.textContent=outcome==='renew'?'Подтвердить сохранённую область':'Подтвердить Home';
  confirm.disabled=!!(e.optionsRead||e.pending);
  // Keep the displayed candidate identity with the control the owner selects.
  confirm.dataset.homeId=outcome==='home'?home.id:'';
  reload.disabled=!!(e.optionsRead||e.pending);
  const fingerprint=JSON.stringify([wizardScope.mode,r?.policy,r?.consent,wizardScope.consentCurrent,outcome==='home'?home.id:null]);
  if (wizardScope.displayed && wizardScope.displayed!==fingerprint) {
    for(const id of ['a1-quickConsent','a1-confirmConsent']){const node=document.getElementById(id);if(node)node.checked=false;}
  }
  wizardScope.displayed=fingerprint;
}
function openWizardScope(mode, refreshPolicy) {
  if(state.authenticated!==true || state.currentView!=='onboard')return;
  const first=wizardScope.mode===null;
  wizardScope.mode=mode;wizardScope.refreshPolicy=refreshPolicy;
  renderWizardScope();
  if(first)void refreshListScopeOptions(true);
}
async function confirmWizardScope() {
  if(!wizardScopeActive())return;
  const e=listScopeEditor, outcome=wizardScopeState(), home=wizardScopeHome(), button=document.getElementById('a1-homeConfirm');
  if(outcome==='home' && home && button?.dataset.homeId===home.id){
    e.draft.segment_ids=[home.id];
  } else if(outcome!=='renew')return;
  wizardScope.message='';
  e.dirty=true;
  const generation=wizardScope.version;
  await saveListScope(true);
  if(generation===wizardScope.version && !e.dirty && !e.unknown && wizardScope.refreshPolicy){
    wizardScope.refreshingPolicy=true;renderWizardScope();
    try {
      if(!await wizardScope.refreshPolicy())throw new Error('Обновите область и список сервисов перед запуском.');
    } catch(error){
      if(generation===wizardScope.version){wizardScope.needsRead=true;wizardScope.message=error.message;}
    } finally{
      if(generation===wizardScope.version){wizardScope.refreshingPolicy=false;renderWizardScope();}
    }
  }
  if(generation===wizardScope.version && e.dirty && !e.unknown){
    // This draft was created by the button above. Discard only its declined
    // edit. A concurrent policy change must be read before a further attempt.
    wizardScope.message=e.message;
    wizardScope.needsRead=e.conflict;
    listScopeReset(listScopeCurrent() || e.base);
    renderWizardScope();
  }
}
async function verifyWizardScope() {
  if(!wizardScopeActive())throw new Error('Откройте первый шаг и проверьте домашнюю сеть.');
  const kind=wizardScopeState(), before=listScopeCurrent(), version=wizardScope.version,mode=wizardScope.mode;
  if(!['saved','legacy'].includes(kind))throw new Error('Сначала подтвердите область домашней сети на первом шаге.');
  const value=await interfaceRequest(listScopeReviewPath);
  if(!wizardScopeActive() || wizardScope.version!==version || wizardScope.mode!==mode)throw new Error('Настройка прервана. Проверьте область сети ещё раз.');
  const after=listScopeReview(value);
  if(wizardScopeState()!==kind || !listScopeSame(listScopeCurrent()?.policy,before.policy) || !listScopeSame(listScopeCurrent()?.consent,before.consent))throw new Error('Область сети изменилась. Проверьте настройки ещё раз.');
  const allowed=kind==='saved'?value.scope_consent_current===true:after?.policy===null;
  if(!after || !allowed || !listScopeSame(after.policy,before.policy) || !listScopeSame(after.consent,before.consent)){
    if(after)acceptPanelSection('networkPolicyReview',value,Date.now());
    renderWizardScope();
    throw new Error('Область сети изменилась. Проверьте актуальные ограничения и повторите запуск.');
  }
  return after.policy?.revision || 0;
}
globalThis.RazvilkaWizardScope={open:openWizardScope,verify:verifyWizardScope};
function listScopeCanEdit() {
  const e=listScopeEditor;
  return !!listScopeCurrent()
    && state.currentView === 'exclusions' && !e.pending && !e.conflict && !e.unknown && !state.applyRequest;
}
function listScopeChange(key,value) {
  if (!listScopeCanEdit()) return;
  const e=listScopeEditor,c=e.draft;
  if (key === 'mode' && ['lan_except','selected_devices'].includes(value)) {
    c.mode=value;c.new_devices=value === 'selected_devices' ? 'base' : 'inherit';
    if(value === 'lan_except' && listScopeValues(c.device_ids).length)c.device_ids=[];
  } else if (key === 'new_devices' && c.mode === 'lan_except' && ['inherit','base'].includes(value)) c.new_devices=value;
  else return;
  e.dirty=true;e.message='Область изменена в черновике.';renderListScope();
}
function listScopeDeviceInSegments(id,clients) {
  const catalog=state.homeScope,row=catalog?.devices.find(d=>d.id===id);
  const segments=listScopeValues(clients.segment_ids).map(raw=>{
    const exact=catalog?.segments.find(s=>s.id===raw);if(exact)return exact.id;
    const aliases=catalog?.segments.filter(s=>s.native_name===raw)||[];return aliases.length===1?aliases[0].id:null;
  });
  return !!row?.segment_id && segments.includes(row.segment_id);
}
function listScopeCandidate(key,row) {
  return row.selection_candidate===true || (key==='excluded_device_ids' && row.exclusion_candidate===true);
}
function listScopeToggle(key,id,checked) {
  if (!listScopeCanEdit() || !['segment_ids','device_ids','excluded_device_ids'].includes(key)) return;
  const e=listScopeEditor,previous=listScopeValues(e.draft[key]);
  if (checked && !previous.includes(id)) {
    const catalog=state.homeScope,retained=listScopeValues(e.base?.policy?.clients?.[key]).includes(id);
    const rows=key==='segment_ids'?catalog?.segments:catalog?.devices;
    const eligible=retained || listScopeOptionsCurrent() && rows.some(row=>row.id===id && listScopeCandidate(key,row));
    if(!eligible)return;
    if(key==='device_ids' && !retained) {
      if(!listScopeDeviceInSegments(id,e.draft)){e.message='Сначала выберите домашний сегмент этого устройства.';renderListScope();return;}
    }
    if(key==='excluded_device_ids' && !retained)e.exclusionSegments.set(id,rows.find(row=>row.id===id).segment_id);
    e.draft[key]=[...previous,id];
  } else if (!checked && previous.includes(id)) {
    if(key==='excluded_device_ids')e.exclusionSegments.delete(id);
    e.draft[key]=previous.filter(v => v !== id);
  }
  else return;
  e.dirty=true;e.message='Изменение записано в черновик.';renderListScope();
}
function listScopeRemoveCIDR(value) {
  if(!listScopeCanEdit() || !listScopeValues(listScopeEditor.draft.excluded_cidrs).includes(value))return;
  listScopeEditor.draft.excluded_cidrs=listScopeEditor.draft.excluded_cidrs.filter(v => v !== value);
  listScopeEditor.dirty=true;renderListScope();
}
function listScopeAppliedHTML() {
  const s=state.resourceExclusions,r=listScopeCurrent();
  if (!r || state.dataLoad?.resourceExclusions?.phase !== 'ready' || !s || s.revision !== r.revision || s.policy_revision !== (r.policy?.revision || 0)) return '<p class="r5-caption">Состояние применённого плана ещё не обновлено.</p>';
  const c=s.applied_effective.clients;
  return `<p class="r5-caption">${s.desired_matches_applied ? 'Сохранённая область совпадает с применённым планом.' : 'Сохранённая область отличается от применённого плана.'} Это сравнение настроек; доступность сайтов проверяется отдельно.</p><details><summary>Последний применённый план · редакция ${s.applied_revision}</summary><p>${esc(c.mode === 'lan_except' ? 'Домашние сегменты' : c.mode === 'selected_devices' ? 'Выбранные устройства' : 'Общая область не применена')}: ${esc(listScopeValues(c.mode === 'selected_devices' ? c.device_ids : c.segment_ids).join(', ') || '—')}</p><p>Устройства без обхода: ${esc(listScopeValues(c.excluded_device_ids).join(', ') || '—')}</p></details>`;
}
function listScopeChoiceHTML(key,rows) {
  const e=listScopeEditor,selected=listScopeValues(e.draft?.[key]),known=new Set(rows.map(row => row.id));
  // Retained IDs are never intersected with today's discovery result.
  const retained=[...new Set([...selected,...listScopeValues(e.base?.policy?.clients?.[key])])];
  const all=[...rows,...retained.filter(id => !known.has(id)).map(id => {
    const alias=key==='segment_ids' ? rows.filter(r=>r.native_name===id) : [];
    return {id,label:alias.length===1?alias[0].label:id,state:'unknown',selection_candidate:false};
  })];
  const q=e.query.trim().toLocaleLowerCase('ru');
  const filtered=all.filter(row => !q || selected.includes(row.id) || `${row.label} ${row.id}`.toLocaleLowerCase('ru').includes(q));
  const shown=[...filtered.filter(row=>selected.includes(row.id)),...filtered.filter(row=>!selected.includes(row.id)).slice(0,100)];
  return `<div class="check-list">${shown.map(row => `<label><input type="checkbox" data-scope-list="${key}" data-scope-id="${esc(row.id)}" data-scope-focus="${key}:${esc(row.id)}" ${selected.includes(row.id)?'checked':''} ${listScopeCanEdit()&&(selected.includes(row.id)||listScopeValues(e.base?.policy?.clients?.[key]).includes(row.id)||listScopeOptionsCurrent()&&listScopeCandidate(key,row))?'':'disabled'}><span>${esc(row.label || row.id)}<small>${esc(row.id)}${row.exclusion_candidate===true?' · Доступно только для исключения':row.state==='not_observed'?' · Сейчас не наблюдается':row.state!=='observed'?' · Сохранённый ID, наблюдение не подтверждено':''}</small></span></label>`).join('') || '<p class="r5-caption">Нет доступных записей.</p>'}</div>${shown.length<filtered.length?'<p class="r5-caption">Показаны сохранённые ID и первые 100 вариантов. Уточните поиск; остальные записи сохраняются.</p>':''}`;
}
function listScopeDeviceLabels() {
  return (state.homeScope?.devices||[]).map(row=>{
    const cached=(state.devices||[]).find(device=>device.id===row.id);
    // Show what the owner recognizes: a given name, a router-known name, the
    // host name, then an address. The server sends the bare ID when it has none.
    const ips=cached?.ips||[];
    const label=cached?.name||(row.label&&row.label!==row.id?row.label:'')||cached?.hostname||ips.find(ip=>ip.includes('.'))||ips[0];
    return label ? {...row,label} : row;
  });
}
let listScopeLastHTML='';
function renderListScope() {
  renderWizardScope();
  const root=document.getElementById('listScopeContent');if(!root)return;
  const e=listScopeEditor,r=listScopeCurrent(),catalog=state.homeScope,c=e.draft;
  const available=!!listScopeOptionsCurrent();
  const editable=listScopeCanEdit(),disabled=editable?'':'disabled';
  const advancedOpen=root.querySelector?.('[data-scope-advanced]')?.open ?? (c?.mode==='selected_devices');
  const html=`<article class="panel full-panel"><div class="panel-title"><div><h2>Устройства без обхода</h2><p>Отметьте устройства, которые должны пользоваться обычным маршрутом роутера.</p><p class="r5-caption">Список устройств поддерживается экспериментально на Netcraze Ultra (NC-1812) для одного сервиса с IPv4-диапазонами. Для доменных списков NFQWS2 исключайте устройства через политику доступа Keenetic.</p><button class="secondary" type="button" data-resource-nfqws-settings>Открыть настройки NFQWS2</button></div></div>
    ${!r?'<p role="status">Область ещё не получена. Последний черновик сохранён; редактирование недоступно.</p>':''}
    ${!available?`<p role="status">Домашние сегменты не подтверждены свежим чтением. ${esc(catalog?.code || '')} Сохранённые ID видимы; область нельзя расширить по одному имени сети.</p>`:catalog?.code==='BINDINGS_IPV6_PREFIX_UNKNOWN'?'<p role="status">IPv6-префикс не подтверждён. Устройства с отметкой «Доступно только для исключения» можно оставить на обычном маршруте. Для выбора устройства для обхода обновите наблюдение.</p>':catalog?.state==='partial'?'<p role="status">Наблюдение неполное. Для нового выбора доступны только подтверждённые варианты.</p>':''}
    <button class="secondary" type="button" data-scope-refresh ${e.optionsRead||e.pending?'disabled':''}>${e.optionsRead?'Обновляем…':'Обновить устройства и сети'}</button>${catalog?.observed_at?`<p class="r5-caption">Последнее наблюдение: ${esc(catalog.observed_at)}. Оно не подтверждает работающий маршрут.</p>`:''}
    ${r?.policy?`<p class="r5-caption">Сохранённая область · редакция ${r.policy.revision}: ${r.policy.clients.mode==='lan_except'?'Вся домашняя сеть':'Выбранные устройства'}; сегменты ${esc(listScopeValues(r.policy.clients.segment_ids).join(', '))}; устройств без обхода ${listScopeValues(r.policy.clients.excluded_device_ids).length}. Сохранение не применяет маршруты.</p>`:'<p class="r5-caption">Общая область пока не настроена. Для устройств подтверждённого сегмента Home достаточно отметить исключения и сохранить.</p>'}
    ${c?`<h3>${e.dirty?'Изменения устройств':'Список устройств'}</h3>${e.base?.policy?.clients.mode==='selected_devices' ? `<label><span>Область обхода</span><select data-scope-field="mode" data-scope-focus="mode" ${disabled}><option value="lan_except" ${c.mode==='lan_except'?'selected':''}>Вся домашняя сеть</option><option value="selected_devices" ${c.mode==='selected_devices'?'selected':''}>Выбранные устройства</option></select></label>` : ''}
    <label><span>Поиск сегмента или устройства</span><input type="search" data-scope-search data-scope-focus="search" value="${esc(e.query)}"></label>
    <fieldset><legend>Устройства без обхода</legend><p class="r5-caption">Устройство остаётся в списке, даже когда оно отключено.</p>${listScopeChoiceHTML('excluded_device_ids',listScopeDeviceLabels())}</fieldset>
    <details data-scope-advanced ${advancedOpen?'open':''}><summary>Домашние сегменты и ранее заданные ограничения</summary>
    <p class="r5-caption">«Вся домашняя сеть» означает только выбранные ниже домашние сегменты. Новые сегменты сами не добавляются. ${c.mode==='lan_except'&&c.new_devices==='inherit'?'Новые устройства используют тот же список сайтов и IP.':'Новые устройства сохраняют обычную политику роутера.'}</p>
    <fieldset><legend>Домашние сегменты</legend>${listScopeChoiceHTML('segment_ids',catalog?.segments || [])}</fieldset>
    ${c.mode==='lan_except'?`<label><span>Новые устройства в выбранных сегментах</span><select data-scope-field="new_devices" data-scope-focus="new-devices" ${disabled}><option value="inherit" ${c.new_devices==='inherit'?'selected':''}>Используют общий список</option><option value="base" ${c.new_devices==='base'?'selected':''}>Остаются без обхода</option></select></label>`:`<fieldset><legend>Устройства для обхода</legend>${listScopeChoiceHTML('device_ids',listScopeDeviceLabels())}</fieldset>`}

    ${listScopeValues(c.excluded_cidrs).length?`<details><summary>Сохранённые IP-сети без обхода</summary>${c.excluded_cidrs.map(value=>`<p><code>${esc(value)}</code> <button class="secondary" type="button" data-scope-remove-cidr="${esc(value)}" ${disabled}>Убрать исключение</button></p>`).join('')}</details>`:''}
    ${listScopeAppliedHTML()}</details>
    <p role="status">${esc(e.message)}${e.conflict?' Настройки изменились на сервере. Черновик сохранён.':''}${e.unknown?' Результат запроса не подтверждён; повторное сохранение заблокировано.':''}</p>
    <div class="dialog-actions"><button class="primary" type="button" data-scope-save ${editable&&e.dirty?'':'disabled'}>${e.pending?'Сохраняем…':'Сохранить настройки устройств'}</button><button class="secondary" type="button" data-scope-reset ${r&&!e.pending?'':'disabled'}>Показать сохранённое</button></div>`:''}</article>`;
  if(html===listScopeLastHTML)return;
  const focus=root.contains(document.activeElement) ? document.activeElement?.getAttribute('data-scope-focus') : null;
  const selection=focus && typeof document.activeElement.selectionStart==='number' ? [document.activeElement.selectionStart,document.activeElement.selectionEnd] : null;
  root.innerHTML=html;listScopeLastHTML=html;
  if(focus){const input=[...root.querySelectorAll('[data-scope-focus]')].find(el=>el.getAttribute('data-scope-focus')===focus);input?.focus({preventScroll:true});if(selection&&input?.setSelectionRange)input.setSelectionRange(...selection);}
}
function listScopeSubmissionClients() {
  const {base,draft}=listScopeEditor;
  if(base?.policy || listScopeValues(draft.segment_ids).length || draft.mode!=='lan_except' || !listScopeOptionsCurrent())return draft;
  const excluded=listScopeValues(draft.excluded_device_ids);
  const catalog=state.homeScope;
  const homes=catalog.segments.filter(segment=>segment.selection_candidate && segment.native_name==='Home');
  if(homes.length!==1 || !excluded.length)return draft;
  const home=homes[0].id;
  const members=new Set(catalog.devices.filter(row=>listScopeCandidate('excluded_device_ids',row) && row.segment_id===home).map(row=>row.id));
  return excluded.every(id=>members.has(id)) ? {...draft,segment_ids:[home]} : draft;
}
async function saveListScope(fromWizard=false) {
  const e=listScopeEditor;if(e.pending || !e.dirty || !e.base)return;
  if(!(fromWizard ? wizardScopeActive()&&!e.conflict&&!e.unknown&&!state.applyRequest&&listScopeCurrent() : listScopeCanEdit())){e.message='Сохранение недоступно. Обновите устройства и сети; при конфликте сначала сравните сохранённые настройки с черновиком.';renderListScope();return;}
  const clients=listScopeSubmissionClients();
  if(!listScopeClientsValid(clients)){e.message='Не удалось определить домашний сегмент. Выберите подтверждённый сегмент. Для ранее сохранённого списка устройств нужен хотя бы один участник.';renderListScope();return;}
  for(const key of ['segment_ids','device_ids','excluded_device_ids']) {
    const added=listScopeValues(clients[key]).filter(id=>!listScopeValues(e.base.policy?.clients?.[key]).includes(id));
    const rows=key==='segment_ids'?state.homeScope?.segments:state.homeScope?.devices;
    if(added.length&&(!listScopeOptionsCurrent()||added.some(id=>!rows.some(row=>row.id===id&&listScopeCandidate(key,row))))){e.message='Для новых ID обновите устройства и сети и выберите подтверждённые варианты. Сохранённые исключения остаются в черновике.';renderListScope();return;}
    if(key==='device_ids'&&added.some(id=>!listScopeDeviceInSegments(id,clients))){e.message='Выберите домашний сегмент каждого нового устройства.';renderListScope();return;}
    if(key==='excluded_device_ids'&&added.some(id=>!e.exclusionSegments.has(id)||e.exclusionSegments.get(id)!==rows.find(row=>row.id===id).segment_id)){
      e.message='Сегмент устройства изменился. Снимите отметку и выберите устройство по свежим данным.';renderListScope();return;
    }
  }
  const base=e.base,policy=listScopePolicy(base,clients),grants=base.consent ? listScopeCopy(base.consent.grants) : [];
  const ticket={epoch:e.epoch,auth:state.authGeneration || 0},current=()=>e.pending===ticket&&e.epoch===ticket.epoch&&state.authenticated&&(state.authGeneration||0)===ticket.auth;
  e.pending=ticket;e.submitted={policy,grants,expectedRevision:base.revision,allowInheritedExclusions:!base.policy};e.message='Сохраняем выбранную область…';renderListScope();
  let receipt=null;
  try {
    const value=await interfaceRequest(listScopeReviewPath,{method:'POST',body:JSON.stringify({expected_revision:base.revision,expected_policy_revision:base.policy?.revision || 0,policy,grants,confirm:'APPROVE_NETWORK_POLICY'})});
    if(!current())return;
    receipt=listScopeReview(value);
    if(!receipt || value.approved!==true || receipt.revision<=base.revision || receipt.policy?.revision!==(base.policy?.revision||0)+1 || !listScopePolicyEqual(policy,receipt.policy,!base.policy) || !listScopeSame(receipt.consent?.grants,grants))throw new Error('Серверный результат сохранения не подтверждён.');
    if(typeof cancelPanelRefresh==='function')cancelPanelRefresh();
    const readValue=await interfaceRequest(listScopeReviewPath);if(!current())return;
    const read=listScopeReview(readValue);
    if(!read || !listScopeSame(read,receipt))throw new Error('Независимое чтение не подтвердило сохранённую область.');
    acceptPanelSection('networkPolicyReview',readValue,Date.now());listScopeReset(read);e.unknown=false;e.submitted=null;
    e.message='Настройки сохранены — применение ещё не подтверждено.';
    if(typeof panelSectionState==='function')panelSectionState('resourceExclusions','loading');
    if(typeof refreshAfterMutation==='function')void refreshAfterMutation().catch(()=>{});
  } catch(error) {
    if(!current())return;
    if(receipt){e.unknown=true;e.message='Сервер принял область, но независимое чтение не подтвердило результат. Черновик сохранён.';}
    else if(error.status===409){e.conflict=true;e.message='Область не сохранена: настройки изменились. Черновик сохранён.';}
    else if([400,403].includes(error.status)){e.message=`${error.payload?.code || error.message || 'Область не сохранена.'} Черновик сохранён.`;}
    else {e.unknown=true;e.message=`${error.payload?.code || error.message || 'Результат сохранения не подтверждён.'} Черновик сохранён.`;}
  } finally {if(current()){e.pending=null;renderListScope();}}
}
async function refreshListScopeOptions(explicit=false) {
  const e=listScopeEditor;
  if(state.authenticated!==true || (state.currentView!=='exclusions'&&!wizardScopeActive()) || e.optionsRead || e.pending || !explicit&&e.optionsAttempted)return;
  const ticket={epoch:e.epoch,auth:state.authGeneration||0},current=()=>e.optionsRead===ticket&&ticket.epoch===e.epoch&&state.authenticated&&(state.authGeneration||0)===ticket.auth;
  e.optionsAttempted=true;e.optionsRead=ticket;
  if(typeof panelSectionState==='function')panelSectionState('homeScope','loading');
  renderListScope();
  try {
    if(explicit){
      const review=await interfaceRequest(listScopeReviewPath);if(!current())return;
      acceptPanelSection('networkPolicyReview',review,Date.now());
      const read=listScopeReview(review);
      if(wizardScopeActive() && wizardScope.needsRead){wizardScope.needsRead=wizardScope.refreshPolicy ? !await wizardScope.refreshPolicy() : false;if(!current())return;}
      if(e.unknown&&e.submitted&&read.revision>e.submitted.expectedRevision&&listScopePolicyEqual(e.submitted.policy,read.policy,e.submitted.allowInheritedExclusions)&&listScopeSame(read.consent?.grants,e.submitted.grants)) {
        listScopeReset(read);e.unknown=false;e.submitted=null;e.message='Настройки сохранены — применение ещё не подтверждено.';
      }
    }
    const options=await interfaceRequest(listScopeOptionsPath);if(!current())return;
    acceptListScopeOptions(options);if(typeof panelSectionState==='function')panelSectionState('homeScope','ready');
    if(explicit && state.currentView==='exclusions'){
      const exclusions=await interfaceRequest('/api/v1/networkpolicy/exclusions');if(!current())return;
      acceptPanelSection('resourceExclusions',exclusions,Date.now());
    }
  } catch(error) {
    if(!current())return;
    if(typeof panelSectionState==='function')panelSectionState('homeScope','error',error);
    if(wizardScopeActive())wizardScope.message='Не удалось прочитать сведения о сети. Повторите проверку.';
    e.message=`${error.payload?.code || error.message || 'Домашние сегменты не получены.'} Последние ID и черновик сохранены.`;
  } finally {if(current()){e.optionsRead=null;renderListScope();}}
}
function bindListScope() {
  const root=document.getElementById('listScopeContent');if(!root)return;
  document.getElementById('a1-homeConfirm')?.addEventListener('click',()=>void confirmWizardScope());
  document.getElementById('a1-homeRead')?.addEventListener('click',()=>{wizardScope.message='';void refreshListScopeOptions(true);});
  function leaveWizard(){wizardScope.version++;wizardScope.refreshingPolicy=false;wizardScope.needsRead=false;wizardScope.refreshPolicy=null;wizardScope.mode=null;wizardScope.displayed='';wizardScope.message='';}
  document.addEventListener('razvilka:view-change',event=>{if(event.detail!=='onboard')leaveWizard();});
  document.addEventListener('razvilka:auth-restored',leaveWizard);
  document.getElementById('view-exclusions')?.addEventListener('click',event=>{
    const id=event.target.closest('button[data-exclusion-section]')?.dataset.exclusionSection;
    if(id!=='listScopeContent' && id!=='resourceExclusionsContent')return;
    const section=document.getElementById(id);
    section?.focus({preventScroll:true});
    section?.scrollIntoView({block:'start'});
  });
  root.addEventListener('change',event=>{const t=event.target;if(t.dataset.scopeField)listScopeChange(t.dataset.scopeField,t.value);if(t.dataset.scopeList)listScopeToggle(t.dataset.scopeList,t.dataset.scopeId,t.checked);});
  root.addEventListener('input',event=>{if(event.target.hasAttribute('data-scope-search')){listScopeEditor.query=event.target.value;renderListScope();}});
  root.addEventListener('click',event=>{const b=event.target.closest('button');if(!b||b.disabled)return;if(b.hasAttribute('data-scope-save'))void saveListScope();if(b.hasAttribute('data-scope-refresh'))void refreshListScopeOptions(true);if(b.hasAttribute('data-scope-remove-cidr'))listScopeRemoveCIDR(b.dataset.scopeRemoveCidr);if(b.hasAttribute('data-scope-reset')&&listScopeCurrent()&&!listScopeEditor.pending){listScopeReset(listScopeCurrent());listScopeEditor.message='Показаны сохранённые настройки.';renderListScope();}});
  document.addEventListener('razvilka:panel-refresh',()=>{void refreshListScopeOptions();});
  document.addEventListener('razvilka:auth-required',()=>{leaveWizard();wizardScope.consentCurrent=false;const e=listScopeEditor;e.epoch++;e.pending=null;e.optionsRead=null;e.optionsAttempted=false;e.unknown=false;e.submitted=null;e.message='';e.query='';state.networkPolicyReview=null;state.homeScope=null;listScopeReset(null);e.draft=null;renderListScope();});
}
bindListScope();
