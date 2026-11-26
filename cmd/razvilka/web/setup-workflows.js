/* UX1: repaired setup/catalog/installation flows. No automatic network mutation
   during rendering; all writes retain the existing auth and server gates. */
'use strict';
const setupRepairState={installBusy:false,warpSaving:false,sourceController:null,sourceSerial:0};
function renderSetupRepairControls(){
 const e=selectedEngineView(),c=(state.components||[]).find(x=>x.id===e?.id),b=$('#openComponentCatalog');
 if(b){b.disabled=setupRepairState.installBusy;
  b.textContent=setupRepairState.installBusy?'Проверяем условия…':c?.external_owner?'Внешний компонент':c?.provider==='platform'&&!c?.installed?'Проверить совместимость':c?.installed?(c.update_available?'Обновить компонент':'Компонент установлен'):'Установить компонент';
  b.title=c?.provider==='platform'?'Загрузка kernel-модуля требует совместимого пакета для модели и ядра. Самовольная установка не выполняется.':'';
 }
 const badge=$('#engineSafeBadge');if(badge)badge.textContent=state.status?.safe_mode?'SAFE MODE · БЕЗ ИЗМЕНЕНИЙ':'ИЗМЕНЕНИЯ РАЗРЕШЕНЫ';
 if(!$('#warpPolicyGuide')){const guide=document.createElement('div');guide.id='warpPolicyGuide';guide.className='inline-note';guide.setAttribute('role','status');$('#warpSaveHealth')?.parentElement?.before(guide);}
 const enabled=$('#warpHealthEnabled')?.value==='true';
 const assigned=(state.services||[]).filter(s=>s.enabled&&(s.route==='warp-wg'||s.resolved_route==='warp-wg')).length;
 const threshold=Number($('#warpMinFailedServices')?.value||2);
 const text=!enabled?'Автоконтроль выключен. Сначала включите политику выше. Выбор восстановления также включит её в черновике, но запросы начнутся только после сохранения.':!assigned?'Политика включена в форме, но ни один сервис не назначен WARP WireGuard. WARP MASQUE и AmneziaWG — другие маршруты.':threshold>assigned?`Для WARP выбрано ${assigned} сервисов, порог отказов — ${threshold}. С таким порогом восстановление не начнётся. Уменьшите порог «Сервисов недоступно» или добавьте сервисы.`:'Автоконтроль использует только сохранённую политику. Сначала проверяются прежние ключи; новый аккаунт требует отдельного согласия.';
 if($('#warpPolicyGuide'))$('#warpPolicyGuide').textContent=text;
 // Old deep links remain readable, but never render the generator under AWG.
 $('#awgSelectWarp').hidden=true;$('#awgSelectProfile').hidden=true;
}
async function openEngineInstallation(id){
 if(setupRepairState.installBusy||!id)return;
 const epoch=workflowState.epoch;setupRepairState.installBusy=true;renderSetupRepairControls();
 try{
  if(!(state.components||[]).some(c=>c.id===id))await refreshComponents(false);
  if(!workflowSession(epoch))return;
  const c=(state.components||[]).find(c=>c.id===id);
  if(!c){showDetails({message:'Сведения о компоненте ещё не получены. Обновите версии и повторите.',component_id:id},'Установка недоступна');return;}
  if(c.external_owner){showDetails({message:'Компонент управляется вне RAZVILKA. Перезапуск и перехват владения не выполняются.',component:c},c.name);return;}
  if(c.installed&&!c.update_available){showDetails({message:'Компонент уже установлен. Настройте профиль и назначьте сервис. Повторная установка не запускалась.',component:c},c.name);return;}
  if(!c.available || c.provider==='platform'){
   const plan=await workflowRequest(`/api/v1/components/${encodeURIComponent(id)}/plan?action=install`);
   if(!workflowSession(epoch))return;
   showDetails({message:'Автоматическая установка этого компонента сейчас недоступна. Нужен совместимый пакет/runtime для этой модели и ядра. Произвольный скрипт и kernel-модуль не запускаются.',plan,component:c},`${c.name}: условия установки`);return;
  }
  await manageComponent(id,c.update_available?'update':'install');
 }catch(error){if(workflowSession(epoch))showDetails({message:workflowError(error)},'Установка не началась');}
 finally{setupRepairState.installBusy=false;if(workflowSession(epoch))renderSetupRepairControls();}
}
function repairWarpDependencies(target){
 const enabled=$('#warpHealthEnabled'),prepare=$('#warpAutoCandidate'),apply=$('#warpAutoApply'),account=$('#warpAllowAccountRefresh');
 if(target===enabled&&enabled.value!=='true'){prepare.checked=apply.checked=account.checked=false;}
 if((target===prepare||target===apply||target===account)&&target.checked){enabled.value='true';if(target!==prepare)prepare.checked=true;}
 if(target===prepare&&!prepare.checked){apply.checked=account.checked=false;}
 // Never check accept_tos on the user's behalf.
 state.warpPolicyDirty=true;$('#warpPolicyFeedback').textContent='Изменён черновик. Сохраните автоконтроль.';renderSetupRepairControls();
}
for(const id of ['warpHealthEnabled','warpAutoCandidate','warpAutoApply','warpAllowAccountRefresh','warpMinFailedServices'])$('#'+id)?.addEventListener('change',e=>repairWarpDependencies(e.target));
function cancelCustomSource(){setupRepairState.sourceSerial++;setupRepairState.sourceController?.abort();setupRepairState.sourceController=null;$('#communityOwnPreview').disabled=false;$('#communityOwnCancel').hidden=true;}
function invalidateCustomSource(){
 cancelCustomSource();workflowState.communitySeq++;
 if(state.communityPreview?.entry?.id?.startsWith('adhoc-')){state.communityPreview=null;$('#communityPreview').innerHTML='<div class="community-empty">Источник изменён. Повторите разбор перед импортом.</div>';}
}
$('#communityOwnCancel').addEventListener('click',()=>{cancelCustomSource();$('#communityOwnStatus').textContent='Загрузка отменена. Сервис не добавлен.';});
for(const id of ['communityOwnName','communityOwnProbe','communityOwnURL','communityOwnText','communityOwnFormat'])$('#'+id).addEventListener('input',invalidateCustomSource);
$('#communityOwnFile').addEventListener('change',async()=>{
 invalidateCustomSource();const file=$('#communityOwnFile').files?.[0],seq=setupRepairState.sourceSerial,epoch=workflowState.epoch;if(!file)return;
 if(file.size>256*1024){$('#communityOwnStatus').textContent='Файл больше 256 КиБ. Выберите меньший доменный список.';return;}
 try{const text=await file.text();if(!workflowSession(epoch)||seq!==setupRepairState.sourceSerial||!$('#communityCatalogDialog').open)return;$('#communityOwnText').value=text;$('#communityOwnURL').value='';$('#communityOwnStatus').textContent='Файл прочитан локально. Нажмите «Разобрать и показать».';}
 catch{if(workflowSession(epoch))$('#communityOwnStatus').textContent='Файл не прочитан. Вставьте текст вручную.';}
});
$('#communityOwnForm').addEventListener('submit',async e=>{
 e.preventDefault();if(setupRepairState.sourceController||workflowState.communityImport)return;
 const epoch=workflowState.epoch,seq=++setupRepairState.sourceSerial,cseq=++workflowState.communitySeq,controller=new AbortController();
 const name=$('#communityOwnName').value.trim(),url=$('#communityOwnURL').value.trim(),content=$('#communityOwnText').value.trim();
 if(!name||!!url===!!content){$('#communityOwnStatus').textContent='Укажите название и только один источник: GitHub-ссылку либо текст/файл.';return;}
 if(new TextEncoder().encode(content).length>256*1024){$('#communityOwnStatus').textContent='Список превышает 256 КиБ.';return;}
 const revision=state.status?.revision;
 if(!Number.isSafeInteger(revision)){ $('#communityOwnStatus').textContent='Настройки роутера ещё не загружены. Обновите состояние.';return; }
 setupRepairState.sourceController=controller;state.communityPreview=null;$('#communityPreview').replaceChildren();$('#communityOwnPreview').disabled=true;$('#communityOwnCancel').hidden=false;$('#communityOwnStatus').textContent='Разбираем источник. Маршруты не меняются…';
 try{
  const preview=await workflowRequest('/api/v1/community/source-preview',{method:'POST',controller,body:JSON.stringify({name,category:'Мои сервисы',probe_url:$('#communityOwnProbe').value.trim(),url,content,format:$('#communityOwnFormat').value,expected_revision:revision,confirm:'PREVIEW_SERVICE_SOURCE'})},35000);
  if(!workflowSession(epoch)||seq!==setupRepairState.sourceSerial||cseq!==workflowState.communitySeq||!$('#communityCatalogDialog').open)return;
  if(preview.import_guard!=='source-sha256'||!/^[a-f0-9]{64}$/.test(preview.source_sha256||''))throw new Error('Не получен проверенный состав источника.');
  state.communityPreview=preview;renderCommunityPreview();$('#communityOwnStatus').textContent='Предпросмотр готов. Проверьте состав и нажмите «Добавить в мои сервисы». Это ещё не применение маршрута.';
 }catch(error){if(workflowSession(epoch)&&seq===setupRepairState.sourceSerial)$('#communityOwnStatus').textContent=workflowError(error);}
 finally{if(workflowSession(epoch)&&seq===setupRepairState.sourceSerial){setupRepairState.sourceController=null;$('#communityOwnPreview').disabled=false;$('#communityOwnCancel').hidden=true;}}
});
$('#communityCatalogDialog').addEventListener('close',()=>{cancelCustomSource();workflowState.communitySeq++;});
document.addEventListener('razvilka:auth-required',()=>{
 cancelCustomSource();setupRepairState.installBusy=setupRepairState.warpSaving=false;
 for(const id of ['communityOwnName','communityOwnProbe','communityOwnURL','communityOwnText','communityOwnFile'])$('#'+id).value='';
});
renderSetupRepairControls();
