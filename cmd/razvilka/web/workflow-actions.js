/* R4: task-oriented controls using the router's existing checker and catalog.
   No timers execute checks in the browser. No URI or token is persisted here. */
'use strict';
const workflowState = { bulkBusy:false, epoch:0, controllers:new Set(), fetchBusy:false, fetchSeq:0, deleteBusy:false, deletion:null, deleteSeq:0, probe:null, lastProbe:null, communitySeq:0, communityImport:false };
const workflowViews = ['nodes','providers','engineconfig','services','managed'];
function workflowSession(epoch){return epoch===workflowState.epoch && $('#authScreen').hidden;}
async function workflowRequest(path, options={}, milliseconds=25000){
  const epoch=workflowState.epoch, controller=options.controller||new AbortController();
  workflowState.controllers.add(controller);const timer=setTimeout(()=>controller.abort(),milliseconds);
  try{const result=await api(path,{...options,signal:controller.signal});if(!workflowSession(epoch))throw new Error('Сессия изменилась. Обновите состояние.');return result;}
  catch(error){if(error.status===401)showAuth({...state.status,authenticated:false,auth_required:true},'Сессия завершилась. Войдите снова.');throw error;}
  finally{clearTimeout(timer);workflowState.controllers.delete(controller);}
}
function workflowError(error){
  if(error.name==='AbortError')return 'Ожидание остановлено. Результат записи не подтверждён; обновите состояние перед повтором.';
  if(error.status===404||error.status===501)return 'Этот backend ещё не содержит необходимую операцию. Обновите backend; отсутствие операции не подменяется успехом.';
  return error.message || 'Не удалось выполнить действие.';
}
function workflowServiceOptions(id,preferred=''){
  const el=$('#'+id);if(!el)return;
  const prev=preferred||el.value, services=(state.services||[]).filter(s=>s.probe_url||(s.probes||[]).some(p=>p.required&&p.url));
  const markup=services.length?services.map(s=>`<option value="${esc(s.id)}">${esc(s.name)} · веб</option>`).join(''):'<option value="">Нет сервиса с проверяемой целью</option>';
  if(el.innerHTML!==markup)el.innerHTML=markup;
  if(services.some(s=>s.id===prev))el.value=prev;
}
function renderWorkflowControls(){
  workflowBulkControls();
  for(const id of ['r4ProbeService','r4CatalogService'])workflowServiceOptions(id);
  const engine=typeof selectedEngineView==='function'?selectedEngineView():null;
  const running=['queued','interrupted','running','canceling'].includes(nodeBrowser.job?.state);
  const job=nodeBrowser.job;
  if($('#r4JobResults')){
    $('#r4JobResults').innerHTML=job?.mode==='service'?(job.results||[]).slice(-8).map(r=>`<div><b>${esc(nodeByID(r.node_id)?.name||'Узел · '+String(r.node_id||'').slice(-8))}</b><span>${esc(r.verdict||'Нет результата')}</span><small>${esc(r.message||'Проверка не завершена.')}</small></div>`).join(''):'';
  }
  $('#r4DeleteSelected').disabled=workflowState.deleteBusy||running||nodeBrowser.selected.size===0;
  $('#r4DeleteSelected').textContent=`Удалить выбранные${nodeBrowser.selected.size?' · '+nodeBrowser.selected.size:''}`;
  $('#r4DeleteFailed').disabled=workflowState.deleteBusy||running||!(state.nodes?.nodes||[]).length;
  $('#r4FetchOpen').disabled=workflowState.fetchBusy||running;
  $('#r4ProbeStart').disabled=!!workflowState.probe||!engine?.installed||!$('#r4ProbeService').value;
  $('#r4ProbeStart').textContent=workflowState.probe?'Проверяем…':`Проверить через ${engine?.name||'обход'}`;
  $('#r4Validate').disabled=!!state.engineIntent||!engine||!selectedEngineFile()||!!workflowState.probe;
  $('#r4ProbeCancel').hidden=!workflowState.probe;$('#r4ProbeCancel').disabled=!!workflowState.probe?.controller.signal.aborted;
  $('#r4ProbeService').disabled=!!workflowState.probe;
  const scope=engine?.id==='nfqws2'?'Временное правило только для одного тестового потока в активную очередь NFQWS2. Очистка — после теста. Рабочие списки не меняются.':'Тест через поддержанный изолированный SOCKS-путь или привязку к интерфейсу. Если такой путь недоступен, backend вернёт отказ, а не обычную прямую проверку.';
  $('#r4ProbeScope').textContent=(state.engineEditorDirty?'Есть несохранённый черновик: тест ниже использует установленную конфигурацию, не эти правки. ':'')+scope;
  if(!workflowState.probe&&!workflowState.lastProbe)$('#r4ProbeStatus').textContent=engine?.installed?'Выберите сервис. Запрос выполняется на роутере. Отдельно проверяются прямой путь и выбранный обход.':'Сначала установите и настройте компонент. Проверка сайтов не имитируется отсутствующим движком.';
  if(!workflowState.probe&&workflowState.lastProbe && workflowState.lastProbe.engine!==engine?.id){$('#r4ProbeResults').replaceChildren();$('#r4ProbeStatus').textContent='Для этого обхода тест ещё не запускался.';}
  else if(workflowState.lastProbe && !workflowState.probe)workflowRenderProbe(workflowState.lastProbe);
}
function workflowRenderProbe(test){
  if(test.engine!==state.selectedEngine)return;
  $('#r4ProbeStatus').textContent=test.message;
  $('#r4ProbeResults').innerHTML=(test.rows||[]).map(row=>{
    const fresh=Date.parse(row.checked_at)<=Date.now()&&Date.parse(row.evidence_fresh_until)>Date.now();
    const exact=row.route_confirmed===true&&!row.route_proof_error&&!row.negative_control_matched;
    const good=fresh&&exact&&row.status==='pass'&&row.verdict==='PASS';
    const bad=['BLOCKED','MISROUTED'].includes(row.verdict)||row.status==='fail';
    const name=row.route==='direct'?'Прямой путь · контроль':routeLabel(row.route);
    const text=good?'Сценарий подтверждён':row.status==='not-ready'?'Проверочный путь недоступен':bad?'Проверка не пройдена':'Нет однозначного результата';
    return `<article class="r4-result"><div class="r4-section-head"><h4>${esc(name)}</h4><span class="ui3-status ${good?'good':bad?'bad':'unknown'}">${esc(text)}</span></div><p>${esc(row.scenario_label||test.serviceName+' · веб')}</p><dl><dt>Путь</dt><dd>${exact?'Подтверждён тестом':'Не подтверждён'}</dd><dt>HTTP</dt><dd>${row.http_status?esc(row.http_status):'—'}</dd><dt>Время проверки</dt><dd>${row.latency_ms?esc(row.latency_ms)+' мс':'—'}</dd></dl><p class="r4-note">${esc(row.detail||row.error_code||'Нет дополнительных данных.')}</p></article>`;
  }).join('');
}
async function workflowRunProbe(){
  if(workflowState.probe)return;
  const engine=state.selectedEngine,serviceID=$('#r4ProbeService').value,service=state.services.find(s=>s.id===serviceID);
  if(!engine||!service)return;
  const epoch=workflowState.epoch,controller=new AbortController();
  const test={engine,serviceName:service.name,controller};workflowState.probe=test;workflowState.lastProbe=null;
  $('#r4ProbeResults').replaceChildren();$('#r4ProbeStatus').textContent=`Проверяем ${service.name} через ${routeLabel(engine)} и напрямую. До 90 секунд, включая очистку.`;renderWorkflowControls();
  try{
    const result=await workflowRequest('/api/v1/testlab/routes',{method:'POST',controller,body:JSON.stringify({services:[serviceID],routes:[engine]})},100000);
    if(!workflowSession(epoch))return;
    const rows=(result.results||[]).filter(r=>r.service_id===serviceID&&[engine,'direct'].includes(r.route));
    if(!rows.length)throw new Error('Backend не вернул результаты выбранного теста. Успех не подтверждён.');
    workflowState.lastProbe={...test,rows,message:'Проверка завершена. Результаты относятся к указанному веб-сценарию и моменту теста. Маршрут не применялся.'};
  }catch(error){if(workflowSession(epoch))workflowState.lastProbe={...test,rows:[],message:error.name==='AbortError'?'Тест остановлен. Дождитесь очистки временных ресурсов на роутере; статус успеха не присваивается.':workflowError(error)};}
  finally{if(workflowState.probe===test)workflowState.probe=null;if(workflowSession(epoch))renderWorkflowControls();}
}
function workflowOpenFetch(preset='',url=''){
  if(workflowState.fetchBusy||['queued','interrupted','running','canceling'].includes(nodeBrowser.job?.state)){interfaceToast('Дождитесь текущей проверки или остановите её.');return;}
  workflowServiceOptions('r4FetchService',state.currentView==='providers'?$('#r4CatalogService').value:$('#nodeBrowserService').value);
  const el=$('#r4FetchSource'),presets=state.nodeFeeds?.presets||[],saved=(state.nodeFeeds?.sources||[]).filter(s=>s.saved);
  el.innerHTML=presets.map(s=>`<option value="preset:${esc(s.id)}">${esc(s.name)}</option>`).join('')+saved.map(s=>`<option value="saved:${esc(s.source_id)}">Моя подписка · ${esc(s.name)}</option>`).join('')+'<option value="custom">Свой HTTPS-адрес</option>';
  if(preset)el.value=preset==='custom'?'custom':'preset:'+preset;
  if(!el.value)el.value='custom';
  $('#r4FetchURL').value=url;$('#r4FetchConsent').checked=false;$('#r4FetchPartial').checked=false;$('#r4FetchStatus').textContent='';$('#r4FetchSubmit').disabled=false;
  workflowSourceChanged();$('#r4FetchDialog').showModal();$('#r4FetchService').focus();
}
function workflowSourceChanged(){const custom=$('#r4FetchSource').value==='custom';$('#r4PrivateSource').hidden=!custom;$('#r4FetchURL').required=custom;}
async function workflowFetch(event){
  event.preventDefault();if(workflowState.fetchBusy)return;
  const serviceID=$('#r4FetchService').value,source=$('#r4FetchSource').value,limit=Number($('#r4FetchLimit').value);
  if(!serviceID||!Number.isInteger(limit)||limit<1||limit>64||!$('#r4FetchConsent').checked){$('#r4FetchStatus').textContent='Выберите сервис, от 1 до 64 проверок и подтвердите разрешение.';return;}
  const body={mode:'service',service_id:serviceID,confirm:'FETCH_AND_CHECK_NODES'};
  if(source.startsWith('saved:')){body.feed_id=source.slice(6);body.limit=limit;}
  else{body.feed={limit,accept_partial:$('#r4FetchPartial').checked};if(source.startsWith('preset:'))body.feed.preset_id=source.slice(7);else{let url;try{url=new URL($('#r4FetchURL').value.trim());}catch{}if(!url||url.protocol!=='https:'||url.username||url.password){$('#r4FetchStatus').textContent='Нужен HTTPS-адрес без логина и пароля в адресной части.';return;}body.feed.url=url.href;body.feed.format=$('#r4FetchFormat').value;}}
  const epoch=workflowState.epoch,seq=++workflowState.fetchSeq;workflowState.fetchBusy=true;$('#r4FetchSubmit').disabled=true;$('#r4FetchStatus').textContent='Проверяем возможность запуска…';
  try{
    const status=await workflowRequest('/api/v1/node-checks/current');
    if(status.fetch_and_check!==true)throw new Error('Backend не поддерживает «Загрузить и проверить». Установите проверенную сборку R5. Отдельная загрузка не выдаётся за сетевую проверку.');
    if(['queued','interrupted','running','canceling'].includes(status.job?.state))throw new Error('На роутере уже выполняется проверка. Дождитесь завершения.');
    const result=await workflowRequest('/api/v1/node-checks',{method:'POST',body:JSON.stringify(body)});
    if(!workflowSession(epoch))return;
    if(!result.job?.id)throw new Error('Роутер не подтвердил создание задачи. Проверьте её состояние перед повтором.');
    nodeBrowser.job=result.job;nodeBrowser.selected.clear();nodeBrowser.source='';nodeBrowser.page=0;
    $('#r4FetchURL').value='';$('#r4FetchDialog').close();setView('nodes');setNodeBrowserTab('all');$('#nodeBrowserService').value=serviceID;renderNodes();
    interfaceToast('Задача принята роутером. Получение и проверки продолжатся при закрытой странице. Apply не запускался.');scheduleNodeBrowserRefresh(500);
  }catch(error){if(workflowSession(epoch))$('#r4FetchStatus').textContent=workflowError(error);}
  finally{if(seq===workflowState.fetchSeq)workflowState.fetchBusy=false;if(workflowSession(epoch)&&seq===workflowState.fetchSeq){$('#r4FetchSubmit').disabled=false;renderWorkflowControls();}}
}
async function workflowDelete(ids,mode='selected'){
  if(workflowState.deleteBusy)return;
  const isAllVLESS=mode==='all-vless';
  const all=isAllVLESS?workflowAllVLESS().map(n=>n.id):[...new Set(ids)],chosen=isAllVLESS?[]:all.slice(0,64),seq=++workflowState.deleteSeq,epoch=workflowState.epoch;
  if(!all.length){interfaceToast('Нет записей для удаления.');return;}
  if(mode==='selected'&&all.length>64){interfaceToast('За один раз удаляется до 64 узлов. Сократите выбор.');return;}
  const request=isAllVLESS?{generation:state.nodes?.generation,mode,preview:true,confirm:'DELETE_ALL_VLESS'}:{node_ids:chosen,generation:state.nodes?.generation,mode,service_id:$('#nodeBrowserService').value,network_profile:state.nodes?.network_profile||'',preview:true,confirm:'DELETE_NODES'};
  workflowState.deletion=null;workflowState.deleteBusy=true;$('#r4DeleteCommit').disabled=true;
  $('#r4DeleteSummary').textContent=isAllVLESS?'Предпросмотр ВСЕХ VLESS во всём каталоге. Фильтры и страницы не ограничивают удаление. Проверяем маршруты, группы и резерв.':`Сверяем ссылки на ${chosen.length} узлов${all.length>64?' из '+all.length+' (первая партия)':''}. Проверяем маршруты, группы, закрепления и резерв.`;
  $('#r4DeleteItems').replaceChildren();$('#r4DeleteStatus').textContent='';$('#r4DeleteDialog').showModal();renderWorkflowControls();
  try{
    const result=await workflowRequest('/api/v1/nodes/delete-batch',{method:'POST',body:JSON.stringify(request)});
    if(!workflowSession(epoch)||seq!==workflowState.deleteSeq||!$('#r4DeleteDialog').open)return;
    if(result.preview!==true||!Array.isArray(result.candidates)||!Array.isArray(result.skipped))throw new Error('Backend не вернул проверенный состав удаления.');
    if(isAllVLESS && (result.scope!=='all-vless'||result.generation!==request.generation||!/^([a-f0-9]{64})$/.test(result.review||'')))throw new Error('Backend не подтвердил весь VLESS-каталог. Удаление не разрешено.');
    workflowState.deletion={request,result,seq};
    $('#r4DeleteSummary').textContent=`${isAllVLESS?'Все VLESS, все источники и страницы. ':''}Можно удалить: ${result.candidates.length}. Сохраняем: ${result.skipped.length}.${!isAllVLESS&&all.length>64?' Обработаны первые 64 записи текущей выборки.':''}${isAllVLESS?' Другие протоколы не затрагиваются. Подписки могут загрузить удалённые ссылки снова.':''}`;
    $('#r4DeleteItems').innerHTML=[...result.candidates.map(n=>({...n,allowed:true})),...result.skipped].map(n=>`<div class="r4-delete-row"><span class="ui3-status ${n.allowed?'warn':'unknown'}">${n.allowed?'Удаление':'Сохранить'}</span><div><b>${esc(n.name||'Узел')}</b><small>${esc(n.reason||'Локальная запись не используется.')}</small></div></div>`).join('');
    $('#r4DeleteCommit').textContent='Удалить '+result.candidates.length+' узлов';$('#r4DeleteCommit').disabled=!result.candidates.length;
  }catch(error){if(workflowSession(epoch)&&seq===workflowState.deleteSeq)$('#r4DeleteStatus').textContent=workflowError(error);}
  finally{if(workflowSession(epoch)){workflowState.deleteBusy=false;renderWorkflowControls();}}
}
async function workflowCommitDelete(){
  const intent=workflowState.deletion;if(!intent||workflowState.deleteBusy)return;
  const epoch=workflowState.epoch;workflowState.deleteBusy=true;$('#r4DeleteCommit').disabled=true;
  $('#r4DeleteStatus').textContent='Повторно проверяем редакцию, использование и результаты перед удалением…';
  try{
    const result=await workflowRequest('/api/v1/nodes/delete-batch',{method:'POST',body:JSON.stringify({...intent.request,generation:intent.result.generation,preview:false,...(intent.request.mode==='all-vless'?{review:intent.result.review}:{})})});
    if(!workflowSession(epoch))return;
    if(!Array.isArray(result.deleted))throw new Error('Состав удалённых записей не подтверждён. Обновите каталог.');
    for(const id of result.deleted)nodeBrowser.selected.delete(id);
    $('#r4DeleteStatus').textContent=`Удалено: ${result.deleted.length}. Сохранено: ${(result.skipped||[]).length}. ${result.complete===false?result.error||'Частичный результат.':result.note||'Рабочие маршруты не изменялись.'}`;
    workflowState.deletion=null;
    try{state.nodes=await workflowRequest('/api/v1/nodes');renderNodes();}catch(error){$('#r4DeleteStatus').textContent+=' Не удалось обновить список: '+workflowError(error);}
  }catch(error){if(workflowSession(epoch)){$('#r4DeleteStatus').textContent=workflowError(error);workflowState.deletion=null;}}
  finally{if(workflowSession(epoch)){workflowState.deleteBusy=false;renderWorkflowControls();}}
}
$('#r4ProbeStart').addEventListener('click',workflowRunProbe);
$('#r4ProbeCancel').addEventListener('click',()=>{workflowState.probe?.controller.abort();$('#r4ProbeCancel').disabled=true;});
$('#r4ProbeService').addEventListener('change',()=>{workflowState.lastProbe=null;$('#r4ProbeResults').replaceChildren();renderWorkflowControls();});
$('#r4Validate').addEventListener('click',async()=>{try{await validateEngineFile();}catch(error){$('#engineCheckOutput').textContent=workflowError(error);}finally{renderWorkflowControls();}});
$('#r4FetchOpen').addEventListener('click',()=>workflowOpenFetch());
$('#r4FetchSource').addEventListener('change',()=>{if($('#r4FetchSource').value!=='custom')$('#r4FetchURL').value='';workflowSourceChanged();});
$('#r4FetchForm').addEventListener('submit',workflowFetch);
$('#r4DeleteSelected').addEventListener('click',()=>workflowDelete([...nodeBrowser.selected]));
$('#r4DeleteFailed').addEventListener('click',()=>workflowDelete(nodeFilteredList().map(n=>n.id),'failed'));
$('#r4DeleteCommit').addEventListener('click',workflowCommitDelete);
$('#r4FetchDialog').addEventListener('close',()=>{$('#r4FetchURL').value='';$('#r4FetchConsent').checked=false;});
$('#r4DeleteDialog').addEventListener('close',()=>{workflowState.deleteSeq++;workflowState.deletion=null;});
document.addEventListener('click',e=>{
  const el=e.target.closest('[data-r4-fetch],[data-r4-delete],[data-r4-community],[data-r4-close]');if(!el||el.disabled)return;
  if(el.hasAttribute('data-r4-close')){document.getElementById(el.dataset.r4Close)?.close();return;}
  if(el.hasAttribute('data-r4-community')){openCommunityCatalog();return;}
  if(el.hasAttribute('data-r4-fetch')){workflowOpenFetch(el.dataset.r4Fetch,el.dataset.r4Url||'');return;}
  if(el.hasAttribute('data-r4-delete'))workflowDelete([el.dataset.r4Delete]);
});
document.addEventListener('razvilka:auth-required',()=>{
  workflowState.epoch++;workflowState.communitySeq++;workflowState.deleteSeq++;workflowState.fetchSeq++;
  for(const c of workflowState.controllers)c.abort();workflowState.controllers.clear();
  workflowState.probe=null;workflowState.lastProbe=null;workflowState.deletion=null;
  workflowState.bulkBusy=workflowState.fetchBusy=workflowState.deleteBusy=workflowState.communityImport=false;
  $('#r4FetchURL').value='';state.communityPreview=null;$('#communityPreview').replaceChildren();
  for(const id of ['r4FetchDialog','r4DeleteDialog','communityCatalogDialog'])$('#'+id).close();
});
// The two catalogue actions deliberately ignore source/search/country/page filters.
function workflowAllVLESS(){return (state.nodes?.nodes||[]).filter(n=>String(n.protocol||'').trim().toLowerCase()==='vless');}
function workflowBulkControls(){
  for(const [id,anchor,kind,handler] of [
    ['nodeCheckAllVLESS','nodeCheckSelected','primary',workflowCheckAllVLESS],
    ['nodeDeleteAllVLESS','r4DeleteFailed','danger-button',()=>workflowDelete([],'all-vless')]
  ]){
    if(!$('#'+id)&&$('#'+anchor)){
      const button=document.createElement('button');button.id=id;button.type='button';button.className=kind;
      button.title='Весь VLESS-каталог: все страницы и источники, независимо от фильтров';
      button.addEventListener('click',handler);$('#'+anchor).insertAdjacentElement('afterend',button);
    }
  }
  const all=workflowAllVLESS(),eligible=all.filter(nodeCanCheck),running=['queued','interrupted','running','canceling'].includes(nodeBrowser.job?.state);
  const check=$('#nodeCheckAllVLESS'),remove=$('#nodeDeleteAllVLESS');
  if(check){check.textContent=`Проверить все VLESS · ${eligible.length}`;check.disabled=workflowState.bulkBusy||workflowState.deleteBusy||running||!$('#nodeBrowserService').value||!eligible.length||state.nodes?.available===false;}
  if(remove){remove.textContent=`Удалить все VLESS… · ${all.length}`;remove.disabled=workflowState.bulkBusy||workflowState.deleteBusy||running||!all.length||state.nodes?.available===false;}
  const hint=$('.node-check-hint');
  if(hint)hint.textContent='Проверка — выбранный веб-сценарий через узел, не только пинг. «Проверить все VLESS» создаёт одну очередь всего каталога, независимо от страниц и фильтров. Отключённые/истёкшие узлы пропускаются. Между узлами ресурс освобождается для восстановления. Обычная выборка ограничена 64 узлами; массовая проверка не применяет маршруты.';
}
async function workflowCheckAllVLESS(){
  if(workflowState.bulkBusy||['queued','interrupted','running','canceling'].includes(nodeBrowser.job?.state))return;
  const epoch=workflowState.epoch,serviceID=$('#nodeBrowserService').value;
  if(!serviceID)return;
  workflowState.bulkBusy=true;renderWorkflowControls();
  let submitted=false;
  try{
    const status=await workflowRequest('/api/v1/node-checks/current');
    if(status.durable_all_vless!==true)throw new Error('Обновите RAZVILKA для сохраняемой проверки всего VLESS-каталога.');
    if(['queued','interrupted','running','canceling'].includes(status.job?.state))throw new Error('На роутере уже выполняется проверка.');
    let snapshot,retained=false;
    try{snapshot=await workflowRequest('/api/v1/nodes');}
    catch(error){
      // A busy worker must not prevent read-only queue admission. The server
      // compares this exact catalogue generation before freezing any IDs.
      if(error.status!==409||error.payload?.code!=='RESTORE_OPERATION_BUSY'||!Array.isArray(state.nodes?.nodes)||state.nodes.available===false||!Number.isSafeInteger(state.nodes.generation)||state.nodes.generation<1)throw error;
      snapshot=state.nodes;retained=true;
    }
    const all=(snapshot.nodes||[]).filter(n=>String(n.protocol||'').trim().toLowerCase()==='vless'),eligible=all.filter(nodeCanCheck);
    if(!eligible.length||!Number.isSafeInteger(snapshot.generation)||snapshot.generation<1)throw new Error('Нет доступных VLESS для проверки. Обновите каталог.');
    const service=(state.services||[]).find(s=>s.id===serviceID);
    const yes=await askConfirmation('Проверить все VLESS?',`${retained?'Показан ранее полученный список. Перед приёмом роутер проверит его актуальность; задание дождётся освобождения сети. ':''}В очереди: ${eligible.length} из ${all.length} VLESS. Сервис: ${service?.name||serviceID} (веб). Все источники и страницы, фильтры не учитываются. Отключённые и истёкшие записи пропускаются. Состав фиксируется при приёме; новые импорты не добавляются. Задание сохранится на роутере. После перезапуска тот же список проверяется заново для текущей сети. Маршруты не изменяются.`,'Проверить все');
    if(!yes||!workflowSession(epoch))return;
    submitted=true;
    const selection=/^[a-f0-9]{64}$/.test(snapshot.check_catalog_digest||'')?{catalog_digest:snapshot.check_catalog_digest}:{};
    const response=await submitNodeCheckRequest({scope:'all-vless',generation:snapshot.generation,...selection,mode:'service',service_id:serviceID,confirm:'CHECK_ALL_VLESS'});
    if(!workflowSession(epoch))return;
    if(!response.job?.id||response.job.scope!=='all-vless'||response.job.service_id!==serviceID)throw new Error('Создание очереди не подтверждено. Обновите состояние; повторный запуск автоматически не отправляется.');
    nodeBrowser.job=response.job;renderNodes();scheduleNodeBrowserRefresh(500);
    interfaceToast('Очередь всех VLESS принята роутером. Отмена — у общего индикатора проверки.');
  }catch(error){
    if(workflowSession(epoch)){
      interfaceToast(workflowError(error));
      // GET only after a lost reply. Never replay a destructive or long-running POST.
      if(submitted)try{const current=await workflowRequest('/api/v1/node-checks/current');if(workflowSession(epoch)){nodeBrowser.job=current.job||null;renderNodeBatchStatus();scheduleNodeBrowserRefresh(500);}}catch(_){}
    }
  }finally{if(workflowSession(epoch)){workflowState.bulkBusy=false;renderWorkflowControls();}}
}
renderWorkflowControls();
