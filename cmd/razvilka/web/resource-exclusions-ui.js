/* Explicit saved resource exclusions. Reads share the panel lifecycle; only
   this editor's Save writes. A 200 receipt is never live route evidence. */
'use strict';
const resourceExclusionsEditor = {epoch:0,base:null,draft:[],russianEnabled:false,autoUpdate:false,dirty:false,conflict:false,unknown:false,pending:null,message:'',kind:'suffix',value:'',query:'',page:0,russianPage:0,legacyPage:0,servicesPage:0};
const resourceExclusionsPath = '/api/v1/networkpolicy/exclusions';
const resourceExclusionsHTMLCache = new WeakMap();

function resourceExclusionsCurrent() {
  return state.authenticated === true && state.dataLoad?.resourceExclusions?.phase === 'ready' ? state.resourceExclusions : null;
}
function interfaceExclusionMap() {
  return window.RazvilkaInterfaceModel.resourceServiceExclusions(resourceExclusionsCurrent());
}
function resourceExclusionsReset(snapshot) {
  const e=resourceExclusionsEditor;
  e.base=snapshot;e.draft=(snapshot?.view.manual||[]).map(row=>({kind:row.kind,value:row.value}));
  e.russianEnabled=snapshot?.russian_enabled===true;e.autoUpdate=snapshot?.russian_auto_update_allowed===true;e.dirty=false;e.conflict=false;
}
function acceptResourceExclusions(value) {
  const snapshot=window.RazvilkaInterfaceModel.resourceExclusionSnapshot(value,state.services||[]);
  if (!snapshot) throw new Error('Список исключений получен не полностью. Последние данные сохранены.');
  if (state.resourceExclusions && snapshot.revision < state.resourceExclusions.revision) throw new Error('Получен прежний список исключений. Обновите состояние.');
  state.resourceExclusions=snapshot;
  const e=resourceExclusionsEditor;
  if (!e.dirty && !e.pending && !e.unknown) resourceExclusionsReset(snapshot);
  else if (e.base && ['revision','policy_revision','exclusion_revision'].some(k=>snapshot[k]!==e.base[k])) e.conflict=true;
}
function resourceExclusionsRows(snapshot) {
  return snapshot ? [...snapshot.view.manual,...snapshot.view.russian.rows,...snapshot.legacy] : [];
}
function resourceExclusionsListHTML(rows, query='', page=0, edit=false, list='manual') {
  const q=query.trim().toLocaleLowerCase('ru');
  const found=rows.map((row,index)=>({...row,index})).filter(row=>!q||[row.label,row.value,row.typeLabel,row.originLabel,row.reason].join(' ').toLocaleLowerCase('ru').includes(q));
  const last=Math.max(0,Math.ceil(found.length/100)-1), current=Math.min(Math.max(0,page),last), shown=found.slice(current*100,(current+1)*100);
  return `<p class="r5-caption">Записей: ${found.length}${found.length>100?` · Страница ${current+1} из ${last+1}`:''}</p>${shown.length?`<ul class="exclusion-list resource-exclusion-list">${shown.map(row=>`<li><div><b>${esc(row.label)}</b><small>${esc(row.typeLabel)} · ${esc(row.originLabel)}${row.activeIntent===false?' · выключено':''}</small><span>${esc(row.reason)}${row.deviceIDs?.length?` · Устройства: ${esc(row.deviceIDs.join(', '))}`:''}</span></div>${edit?`<button class="secondary" type="button" data-resource-remove="${row.index}" data-rz-focus="resource-remove-${row.index}">Убрать</button>`:''}</li>`).join('')}</ul>`:'<p class="r5-caption">Записей нет.</p>'}${last?`<div class="resource-pages"><button class="secondary" type="button" data-resource-page="${current-1}" data-resource-list="${list}"${current===0?' disabled':''}>Назад</button><button class="secondary" type="button" data-resource-page="${current+1}" data-resource-list="${list}"${current===last?' disabled':''}>Далее</button></div>`:''}`;
}
function resourceExclusionsServicesHTML(query='') {
  const snapshot=resourceExclusionsCurrent();
  if (!snapshot) return '<p class="r5-caption">Список исключений пока не подтверждён. Обновите состояние.</p>';
  return `<div class="exclusion-head"><h3>Без обхода</h3><button class="secondary" type="button" data-rz-nav="exclusions">Изменить исключения</button></div><p class="r5-caption">Ручные записи и принятый российский каталог. Исключения устройств находятся отдельно. Здесь показана сохранённая политика; применение маршрутов ещё не подтверждено.</p>${resourceExclusionsListHTML(resourceExclusionsRows(snapshot),query,resourceExclusionsEditor.servicesPage,false,'services')}`;
}
function renderResourceExclusions() {
  const root=document.getElementById('resourceExclusionsContent');if(!root)return;
  const e=resourceExclusionsEditor,snapshot=state.authenticated?state.resourceExclusions:null,ready=!!resourceExclusionsCurrent(),writable=ready&&snapshot.policy_revision>0&&!e.pending&&!e.conflict&&!e.unknown;
  const focused=document.activeElement?.closest?.('[data-rz-focus]'), focus=focused?.getAttribute('data-rz-focus'), selection=typeof focused?.selectionStart==='number'?[focused.selectionStart,focused.selectionEnd]:null;
  const open=new Set([...root.querySelectorAll('details[data-resource-section]')].filter(el=>el.open).map(el=>el.dataset.resourceSection));
  const currentKinds={service:'Сервис',exact:'Точный домен',suffix:'Домен и поддомены',ip:'IP-адрес',cidr:'Сеть IP'};
  const draftRows=e.draft.map(row=>({kind:row.kind,value:row.value,label:row.kind==='service'?(state.services||[]).find(s=>s.id===row.value)?.name||row.value:row.value,typeLabel:currentKinds[row.kind],originLabel:'Добавлено вручную',reason:'Ручное исключение ресурса',activeIntent:true}));
  const absent=!snapshot?'<p>Читаем сохранённые исключения ресурсов…</p>':snapshot.policy_revision===0?'<p>Область домашней сети ещё не сохранена. Редактор исключений недоступен.</p>':'';
  const stale=snapshot&&!ready?'<p role="status">Новые данные не получены. Показан последний список; сохранение недоступно.</p>':'';
  const pending=e.pending?'<p role="status">Сохраняем список и сверяем ответ…</p>':'';
  const conflict=e.conflict?'<p role="status">Настройки изменились после начала редактирования. Черновик сохранён. Обновите список и загрузите сохранённые записи перед новым изменением.</p>':'';
  const unknown=e.unknown?'<p role="status">Результат сохранения не подтверждён. Обновите список для сверки. Повторное сохранение в этом окне заблокировано.</p>':'';
  const russian=snapshot?.view.russian;
  const clients=snapshot?.effective.clients;
  const html=`<article class="panel exclusion-panel"><div class="exclusion-head"><h3>Исключения ресурсов</h3><button class="secondary" type="button" data-panel-refresh${e.pending?' disabled':''}>Обновить список</button></div><p>Исключение имеет приоритет перед добавлением сервиса и выбором обхода. Удаляется отдельным действием в этом редакторе.</p>${absent}${stale}${pending}${conflict}${unknown}${e.message?`<p role="status">${esc(e.message)}</p>`:''}${snapshot?`<p class="r5-caption">Сохранено вручную: ${snapshot.view.manual.length} · Российский каталог: ${russian.rows.length}${russian.enabled?' · включён':' · выключен'}. ${snapshot.desired_matches_applied?'Сохранённая политика совпадает с применённым снимком.':'Сохранённая политика отличается от применённого снимка.'} Работа маршрутов этим сравнением не подтверждается.</p>
    <form class="resource-exclusion-add" id="resourceExclusionAddForm"><label>Тип записи<select id="resourceExclusionKind" data-rz-focus="resource-kind"${writable?'':' disabled'}>${Object.entries(currentKinds).map(([kind,label])=>`<option value="${kind}"${e.kind===kind?' selected':''}>${label}</option>`).join('')}</select></label><label>Ресурс${e.kind==='service'?`<select id="resourceExclusionValue" data-rz-focus="resource-value"${writable?'':' disabled'}><option value="">Выберите сервис</option>${(state.services||[]).map(service=>`<option value="${esc(service.id)}"${e.value===service.id?' selected':''}>${esc(service.name||service.id)}</option>`).join('')}</select>`:`<input id="resourceExclusionValue" data-rz-focus="resource-value" value="${esc(e.value)}" maxlength="253" autocomplete="off" placeholder="bank.example или адрес IP"${writable?'':' disabled'}/>`}</label><button class="secondary" type="submit"${writable?'':' disabled'}>Добавить в черновик</button></form>
    <p class="r5-caption">Сервис выбирается из каталога. «Домен и поддомены» задаётся явно. Проверка домена, IP и CIDR выполняется при сохранении.</p>
    <label class="resource-search">Поиск по записям<input id="resourceExclusionSearch" type="search" value="${esc(e.query)}" data-rz-focus="resource-search"/></label><h4>Ручные исключения${e.dirty?' · черновик':''}</h4>${resourceExclusionsListHTML(draftRows,e.query,e.page,writable)}
    <div class="resource-save"><button class="primary" type="button" data-resource-save${writable&&e.dirty?'':' disabled'}>Сохранить исключения</button><button class="secondary" type="button" data-resource-reset${ready&&!e.pending?'':' disabled'}>Загрузить сохранённые</button></div>
    <details class="exclusion-stock" data-resource-section="russian"><summary>Российский каталог · ${russian.rows.length}${russian.enabled?' · включён':' · выключен'}</summary><p class="r5-caption">${russian.present?`Принятый каталог: ${esc(russian.catalogID)} · Ревизия ${russian.revision}. Последний принятый снимок сохраняется при выключении. Обновление каталога само по себе не включает обход.`:'Принятого снимка российского каталога пока нет.'}</p><label class="exclusion-toggle"><input id="resourceRussianEnabled" type="checkbox"${e.russianEnabled?' checked':''}${writable&&(russian.present||snapshot.russian_enabled)?'':' disabled'}/>Использовать принятый российский каталог</label><label class="exclusion-toggle"><input id="resourceRussianAuto" type="checkbox"${e.autoUpdate?' checked':''}${writable&&russian.present&&e.russianEnabled?'':' disabled'}/>Разрешить обновления принятого источника</label>${resourceExclusionsListHTML(russian.rows,e.query,e.russianPage,false,'russian')}</details>
    ${snapshot.legacy.length?`<details class="exclusion-stock" data-resource-section="legacy"><summary>Ранее сохранённые правила · ${snapshot.legacy.length}</summary><p class="r5-caption">Показаны с прежней областью устройств. Этот редактор меняет только новый ручной список.</p>${resourceExclusionsListHTML(snapshot.legacy,e.query,e.legacyPage,false,'legacy')}</details>`:''}
    <details class="exclusion-stock" data-resource-section="devices"><summary>Исключения устройств — отдельно</summary><p>Устройства без обхода: ${clients.excluded_device_ids.length}. Сети IP без обхода: ${clients.excluded_cidrs.length}.</p>${clients.excluded_device_ids.length?`<p>${esc(clients.excluded_device_ids.join(', '))}</p>`:''}${clients.excluded_cidrs.length?`<p>${esc(clients.excluded_cidrs.join(', '))}</p>`:''}<p class="r5-caption">Сохранённая область: домашних сегментов ${clients.segment_ids.length}, выбранных устройств ${clients.device_ids.length}. Эти данные не подтверждают действующий маршрут.</p><button class="secondary" type="button" data-rz-nav="devices">Открыть устройства</button></details>`:''}</article>`;
  if(resourceExclusionsHTMLCache.get(root)===html)return;
  root.innerHTML=html;
  resourceExclusionsHTMLCache.set(root,html);
  root.querySelectorAll('details[data-resource-section]').forEach(el=>{el.open=open.has(el.dataset.resourceSection);});
  if(focus){const target=[...root.querySelectorAll('[data-rz-focus]')].find(el=>el.getAttribute('data-rz-focus')===focus);target?.focus({preventScroll:true});if(selection&&target?.setSelectionRange)target.setSelectionRange(...selection);}
}
function resourceExclusionsCanEdit() {
  const e=resourceExclusionsEditor,snapshot=resourceExclusionsCurrent();
  return !!snapshot && snapshot.policy_revision>0 && state.currentView==='exclusions' && !e.pending && !e.conflict && !e.unknown;
}
function resourceExclusionsAdd() {
  if(!resourceExclusionsCanEdit())return;
  const e=resourceExclusionsEditor,value=e.value.trim();
  if(!value){e.message='Укажите ресурс.';renderResourceExclusions();return;}
  if(e.kind==='service'&&!(state.services||[]).some(s=>s.id===value)){e.message='Такой идентификатор сервиса не найден в полученном каталоге.';renderResourceExclusions();return;}
  if(e.draft.some(row=>row.kind===e.kind&&row.value===value)){e.message='Эта запись уже есть в ручном списке.';renderResourceExclusions();return;}
  e.draft.push({kind:e.kind,value});e.value='';e.dirty=true;e.message='Запись добавлена в черновик. Нажмите «Сохранить исключения».';renderResourceExclusions();
}
function resourceExclusionsReceiptMatches(a,b) {
  return ['policy_revision','exclusion_revision','russian_enabled','russian_auto_update_allowed'].every(k=>a[k]===b[k]) && b.revision>=a.revision
    && JSON.stringify(a.view)===JSON.stringify(b.view) && a.effective.digest===b.effective.digest;
}
async function saveResourceExclusions() {
  const e=resourceExclusionsEditor;if(!resourceExclusionsCanEdit()||!e.dirty||!e.base)return;
  const base=e.base,ticket={epoch:e.epoch,auth:state.authGeneration||0};
  const current=()=>e.pending===ticket&&e.epoch===ticket.epoch&&state.authenticated&&(state.authGeneration||0)===ticket.auth;
  const body={expected_revision:base.revision,expected_policy_revision:base.policy_revision,expected_exclusion_revision:base.exclusion_revision,manual:e.draft.map(row=>({kind:row.kind,value:row.value}))};
  if(e.russianEnabled!==base.russian_enabled)body.russian_enabled=e.russianEnabled;
  if(e.autoUpdate!==base.russian_auto_update_allowed)body.russian_auto_update_allowed=e.autoUpdate;
  e.pending=ticket;e.message='';renderResourceExclusions();
  let receipt=null;
  try {
    const result=await interfaceRequest(resourceExclusionsPath,{method:'POST',body:JSON.stringify(body)});if(!current())return;
    receipt=window.RazvilkaInterfaceModel.resourceExclusionSnapshot(result,state.services||[]);
    if(!receipt || receipt.revision<=base.revision || receipt.policy_revision<=base.policy_revision || receipt.exclusion_revision<=base.exclusion_revision)throw new Error('Ответ сохранения не подтверждён.');
    // A separate uncached GET verifies stored data; no mutation is replayed.
    if(typeof cancelPanelRefresh==='function')cancelPanelRefresh();
    const value=await interfaceRequest(resourceExclusionsPath);if(!current())return;
    const read=window.RazvilkaInterfaceModel.resourceExclusionSnapshot(value,state.services||[]);
    if(!read||!resourceExclusionsReceiptMatches(receipt,read))throw new Error('Сохранённый список ещё не подтверждён независимым чтением.');
    acceptPanelSection('resourceExclusions',value,Date.now());
    resourceExclusionsReset(read);e.unknown=false;e.message='Исключения сохранены. Применение маршрутов ещё не подтверждено.';
  } catch(error) {
    if(!current())return;
    const code=error.payload?.code||'';
    if(receipt){e.unknown=true;e.message='Сервер принял список, но независимое чтение не подтвердило результат. Черновик сохранён.';}
    else if(error.status===409){e.conflict=true;e.message='Список не сохранён: настройки изменились. Черновик сохранён.';}
    else if(code==='NETWORK_POLICY_SCOPE_REQUIRED'){e.message='Сначала должна быть сохранена область домашней сети. Список не изменён.';}
    else if(code==='NETWORK_POLICY_LIST_REQUIRED'){e.message='Редактирование доступно только для режима выбранных ресурсов. Список не изменён.';}
    else if([400,403].includes(error.status)){e.message=code==='NETWORK_POLICY_EXCLUSIONS_INVALID'?'Проверьте записи и разрешение обновлений каталога. Черновик сохранён.':error.message||'Список не сохранён.';}
    else {e.unknown=true;e.message=error.message||'Результат сохранения не подтверждён.';}
  } finally {
    if(current()){e.pending=null;renderResourceExclusions();if(typeof renderInterface==='function')renderInterface();}
  }
}
function bindResourceExclusions() {
  const root=document.getElementById('resourceExclusionsContent');if(!root)return;
  root.addEventListener('submit',event=>{if(event.target.id==='resourceExclusionAddForm'){event.preventDefault();resourceExclusionsAdd();}});
  root.addEventListener('input',event=>{const e=resourceExclusionsEditor;if(event.target.id==='resourceExclusionValue')e.value=event.target.value;if(event.target.id==='resourceExclusionSearch'){e.query=event.target.value;e.page=e.russianPage=e.legacyPage=0;renderResourceExclusions();}});
  root.addEventListener('change',event=>{
    if(!resourceExclusionsCanEdit())return;const e=resourceExclusionsEditor;
    if(event.target.id==='resourceExclusionKind'){e.kind=event.target.value;e.value='';renderResourceExclusions();}
    if(event.target.id==='resourceExclusionValue')e.value=event.target.value;
    if(event.target.id==='resourceRussianEnabled'){e.russianEnabled=event.target.checked;if(!e.russianEnabled)e.autoUpdate=false;e.dirty=true;renderResourceExclusions();}
    if(event.target.id==='resourceRussianAuto'){e.autoUpdate=event.target.checked;e.dirty=true;renderResourceExclusions();}
  });
  document.addEventListener('click',event=>{
    const button=event.target.closest('button');if(!button||button.disabled)return;const e=resourceExclusionsEditor;
    if(button.hasAttribute('data-resource-page')){const page=Number(button.dataset.resourcePage);if(!Number.isSafeInteger(page)||page<0)return;if(state.currentView==='services'&&button.dataset.resourceList==='services'){e.servicesPage=page;renderInterfaceServices(interfaceSummaries());}else if(state.currentView==='exclusions'&&root.contains(button)){const key={manual:'page',russian:'russianPage',legacy:'legacyPage'}[button.dataset.resourceList];if(!key)return;e[key]=page;renderResourceExclusions();}}
    if(button.hasAttribute('data-resource-remove')&&root.contains(button)&&resourceExclusionsCanEdit()){const index=Number(button.dataset.resourceRemove);if(Number.isSafeInteger(index)&&index>=0&&index<e.draft.length){e.draft.splice(index,1);e.dirty=true;e.message='Удаление записано в черновик. Нажмите «Сохранить исключения».';renderResourceExclusions();}}
    if(button.hasAttribute('data-resource-save')&&root.contains(button))void saveResourceExclusions();
    if(button.hasAttribute('data-resource-reset')&&root.contains(button)&&resourceExclusionsCurrent()&&!e.pending){resourceExclusionsReset(resourceExclusionsCurrent());e.message=e.unknown?'Показаны сохранённые записи. Результат прежнего запроса остаётся неподтверждённым.':'Загружены сохранённые записи.';renderResourceExclusions();}
  });
  document.addEventListener('razvilka:auth-required',()=>{resourceExclusionsEditor.epoch++;resourceExclusionsEditor.pending=null;resourceExclusionsEditor.unknown=false;resourceExclusionsEditor.message='';resourceExclusionsEditor.value='';resourceExclusionsEditor.query='';state.resourceExclusions=null;resourceExclusionsReset(null);renderResourceExclusions();});
}
bindResourceExclusions();
