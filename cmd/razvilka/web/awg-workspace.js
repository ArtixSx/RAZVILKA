/* Local AWG/WARP workspace. All writes use existing authenticated router API.
   No registration, timers or third-party generator runs in this browser. */
'use strict';
const awgUI = { epoch:0, snapshot:null, fetched:0, loading:false, importPreview:null, importBusy:false, probe:null, serial:0, message:'', proof:null };
function awgCurrent(epoch){return epoch===awgUI.epoch && $('#authScreen')?.hidden!==false;}
function awgMessage(error){const p=error?.payload||{};return p.issue?.message||(p.blockers||[]).map(x=>x.message).join(' ')||workflowError(error);}
function awgProofKey(d,service){return JSON.stringify([d?.base_sha256,service,d?.capabilities?.loaded_module_version,d?.capabilities?.tool_version]);}
function awgIssuesHTML(items){return (items||[]).map(x=>`<div class="awg-issue"><b>${esc(x.field||x.code||'Проверка')}</b><span>${esc(x.message||'Нет подтверждения')}</span></div>`).join('');}
function renderAWGWorkspace(){
 const box=$('#awgWorkspace');if(!box)return;
 const visible=state.selectedEngine==='amneziawg';box.hidden=!visible;
 const warpPane=false;$('#view-engineconfig').classList.toggle('awg-warp-active',warpPane);
 if(!visible)return;
 $('#awgProfilePane').hidden=warpPane;$('#awgWarpIntro').hidden=!warpPane;
 $('#awgSelectProfile').setAttribute('aria-pressed',String(!warpPane));$('#awgSelectWarp').setAttribute('aria-pressed',String(warpPane));
 workflowServiceOptions('awgCanaryService');
 const d=awgUI.snapshot,p=d?.profile,c=d?.capabilities;
 $('#awgProfileVersion').textContent=p?.version? p.version.toUpperCase().replace('AWG','AWG '): d?.source==='missing'?'Не добавлен':d?.syntax_valid===false?'Нужна проверка':'Нет данных';
 $('#awgProfileSource').textContent=p?`${d.source==='staged'?'Черновик':'Сохранённый профиль'} · Header Protection ${p.has_header_protection?'есть':'нет'}`:'Импортируйте конфигурацию своего сервера';
 $('#awgModuleVersion').textContent=c?.loaded_module_version|| (d?'Не найден':'Не проверен');
 $('#awgToolVersion').textContent=c?.tool_version?`Утилита ${c.tool_version}`:'Утилита awg не подтверждена';
 $('#awgCompatibilityLabel').textContent=d?.syntax_valid?(d.blockers?.length?'Есть ограничения':'Параметры прошли предварительную проверку'):'Сначала проверьте профиль';
 $('#awgCompatibility').innerHTML=awgIssuesHTML(d?.issue?[d.issue]:[])+awgIssuesHTML(d?.blockers)+awgIssuesHTML(p?.warnings)+`<dl><dt>Ядро</dt><dd>${esc(c?.kernel||'Нет сведений')}</dd><dt>Исполнитель</dt><dd>${esc(c?.backend||'Не определён')}</dd><dt>Аппаратная приёмка</dt><dd>Не подтверждается этим экраном</dd></dl>`;
 $('#awgWorkspaceMessage').textContent=awgUI.message||(d?.syntax_valid?'Конфигурация разобрана. Сетевой доступ проверяется отдельно; настройки маршрутов находятся в сервисах.':'Добавьте профиль или обновите сведения. Безопасная установка kernel-компонентов требует совместимой сборки.');
 const proofCurrent=awgUI.proof&&awgUI.proof.key===awgProofKey(d,$('#awgCanaryService').value)&&Date.now()<awgUI.proof.until&&!state.engineEditorDirty;
 $('#awgProofState').textContent=awgUI.probe?'Проверяем…':proofCurrent?(awgUI.proof.ok?'Веб-сценарий подтверждён':'Не подтверждено'):'Не запускалась';
 $('#awgCanary').disabled=!!awgUI.probe||!d?.syntax_valid||!!d?.blockers?.length||!$('#awgCanaryService').value||!!state.status?.safe_mode||!!state.engineEditorDirty;
 $('#awgCanary').textContent=awgUI.probe?'Проверяем…':'Проверить без применения';
 $('#awgCancelCanary').hidden=!awgUI.probe;$('#awgCancelCanary').disabled=!!awgUI.probe?.signal.aborted;$('#awgCanaryService').disabled=!!awgUI.probe;
 $('#awgOpenImport').disabled=awgUI.importBusy||!!awgUI.probe;
 if(!awgUI.loading && !awgUI.snapshot && Date.now()-awgUI.fetched>30000 && awgCurrent(awgUI.epoch)) void refreshAWGWorkspace();
}
async function refreshAWGWorkspace(){
 if(awgUI.loading)return;
 const epoch=awgUI.epoch;awgUI.loading=true;awgUI.fetched=Date.now();
 try{const d=await workflowRequest('/api/v1/amneziawg');if(!awgCurrent(epoch))return;awgUI.snapshot=d;awgUI.message='';}
 catch(error){if(awgCurrent(epoch)){awgUI.snapshot=null;awgUI.message=awgMessage(error);}}
 finally{if(awgCurrent(epoch)){awgUI.loading=false;renderAWGWorkspace();}}
}
function awgSetPane(pane){if(pane==='warp'){void selectEngine('warp-wg');return;}state.awgPane='profile';renderAWGWorkspace();renderWarpManager();}
$('#awgSelectProfile').addEventListener('click',()=>awgSetPane('profile'));
$('#awgSelectWarp').addEventListener('click',()=>{awgSetPane('warp');void refreshWarp().catch(e=>interfaceToast(workflowError(e)));});
$('#awgOpenWarpEditor').addEventListener('click',()=>selectEngine('warp-wg'));
$('#awgReload').addEventListener('click',()=>void refreshAWGWorkspace());
$('#awgCanaryService').addEventListener('change',()=>{if(!awgUI.probe)awgUI.proof=null;renderAWGWorkspace();});
function awgInvalidateImport(){awgUI.importPreview=null;$('#awgStageImport').disabled=true;$('#awgImportPreview').hidden=true;$('#awgImportConsent').checked=false;}
$('#awgOpenImport').addEventListener('click',()=>{
 if(state.engineEditorDirty){interfaceToast('Сначала сохраните или отмените изменения открытого редактора.');return;}
 awgInvalidateImport();$('#awgImportMessage').textContent='';$('#awgImportDialog').showModal();$('#awgImportText').focus();
});
$('#awgImportText').addEventListener('input',awgInvalidateImport);
$('#awgImportFile').addEventListener('change',async()=>{
 const file=$('#awgImportFile').files?.[0],epoch=awgUI.epoch,seq=++awgUI.serial;
 awgInvalidateImport();if(!file)return;
 if(file.size>256*1024){$('#awgImportMessage').textContent='Профиль превышает 256 КиБ.';return;}
 const value=await file.text();if(awgCurrent(epoch)&&seq===awgUI.serial&&$('#awgImportDialog').open){$('#awgImportText').value=value;$('#awgImportMessage').textContent='Файл прочитан локально. Нажмите «Проверить файл».';}
});
$('#awgImportConsent').addEventListener('change',()=>$('#awgStageImport').disabled=!awgUI.importPreview||!$('#awgImportConsent').checked||awgUI.importBusy);
$('#awgImportClose').addEventListener('click',()=>$('#awgImportDialog').close());
$('#awgImportDialog').addEventListener('close',()=>{
 awgUI.serial++;awgUI.importPreview=null;$('#awgImportText').value='';$('#awgImportFile').value='';$('#awgImportConsent').checked=false;$('#awgImportPreview').replaceChildren();$('#awgStageImport').disabled=true;$('#awgOpenImport').focus();
});
$('#awgPreviewImport').addEventListener('click',async()=>{
 if(awgUI.importBusy)return;
 const text=$('#awgImportText').value,epoch=awgUI.epoch,seq=++awgUI.serial;
 if(!text.trim()){ $('#awgImportMessage').textContent='Добавьте конфигурацию.';return;}
 awgInvalidateImport();awgUI.importBusy=true;$('#awgPreviewImport').disabled=true;$('#awgImportText').readOnly=true;$('#awgImportMessage').textContent='Проверяем формат на роутере. Сетевой профиль не запускается…';
 try{
  const result=await workflowRequest('/api/v1/amneziawg/preview',{method:'POST',body:JSON.stringify({content:text})});
  if(!awgCurrent(epoch)||seq!==awgUI.serial||!$('#awgImportDialog').open)return;
  if(!result.preview?.sha256)throw new Error('Не получен проверенный отпечаток профиля.');
  awgUI.importPreview={result,text};
  $('#awgImportPreview').innerHTML=`<h4>${esc(result.preview.version.toUpperCase())} · только черновик</h4><p>Endpoint: ${esc(result.preview.endpoint)} · адресов интерфейса ${esc(result.preview.address_count)} · сетей AllowedIPs ${esc(result.preview.allowed_ip_count)}</p><p>Header Protection: ${result.preview.has_header_protection?'есть':'нет'} · RandomTrailers: ${result.preview.random_trailers?'on':'off'}</p>${awgIssuesHTML(result.blockers)}${awgIssuesHTML(result.preview.warnings)}`;
  $('#awgImportPreview').hidden=false;$('#awgImportMessage').textContent=result.blockers?.length?'Черновик можно сохранить, но запуск заблокирован до устранения несовместимости.':'Формат проверен. Сохранение ещё не применяет маршрут.';
 }catch(error){if(awgCurrent(epoch)&&seq===awgUI.serial)$('#awgImportMessage').textContent=awgMessage(error);}
 finally{if(awgCurrent(epoch)){awgUI.importBusy=false;$('#awgPreviewImport').disabled=false;$('#awgImportText').readOnly=false;renderAWGWorkspace();}}
});
$('#awgStageImport').addEventListener('click',async()=>{
 const intent=awgUI.importPreview;if(!intent||awgUI.importBusy||!$('#awgImportConsent').checked)return;
 const epoch=awgUI.epoch,seq=awgUI.serial;awgUI.importBusy=true;$('#awgStageImport').disabled=true;
 try{
  const result=await workflowRequest('/api/v1/amneziawg/import',{method:'POST',body:JSON.stringify({content:intent.text,expected_sha256:intent.result.preview.sha256,base_sha256:intent.result.base_sha256,confirm:'STAGE_AWG_PROFILE'})});
  if(!awgCurrent(epoch))return;
  if(!result.staged||result.live_applied)throw new Error('Backend не подтвердил ожидаемое сохранение черновика.');
  if(seq===awgUI.serial)$('#awgImportDialog').close();
  state.engineLoaded=null;state.engineGuided=null;state.engineValidation=null;
  await refreshEngineConfigs();await refreshAWGWorkspace();interfaceToast('Черновик AWG сохранён. Сеть и удалённый сервер не изменены.');
 }catch(error){if(awgCurrent(epoch)&&seq===awgUI.serial){awgInvalidateImport();$('#awgImportMessage').textContent=awgMessage(error);}}
 finally{if(awgCurrent(epoch)){awgUI.importBusy=false;renderAWGWorkspace();}}
});
$('#awgCanary').addEventListener('click',async()=>{
 if(awgUI.probe||!awgUI.snapshot?.syntax_valid)return;
 const controller=new AbortController(),epoch=awgUI.epoch,service=$('#awgCanaryService').value,key=awgProofKey(awgUI.snapshot,service);
 awgUI.proof=null;
 awgUI.probe=controller;$('#awgProofState').textContent='Проверяем…';awgUI.message='Создаётся только временный проверочный интерфейс. До 110 секунд с очисткой.';renderAWGWorkspace();
 try{
  const result=await workflowRequest('/api/v1/amneziawg/canary',{method:'POST',controller,body:JSON.stringify({service_id:service,base_sha256:awgUI.snapshot.base_sha256,confirm:'PROBE_AWG_PROFILE'})},125000);
  if(!awgCurrent(epoch))return;
  awgUI.proof={key,ok:result.ok===true,until:Date.now()+120000};awgUI.message=result.note||'Проверка завершена; маршрут не применялся.';
 }catch(error){if(awgCurrent(epoch)){awgUI.proof={key,ok:false,until:Date.now()+120000};awgUI.message=awgMessage(error);}}
 finally{if(awgCurrent(epoch)){awgUI.probe=null;renderAWGWorkspace();}}
});
$('#awgCancelCanary').addEventListener('click',()=>{awgUI.probe?.abort();$('#awgCancelCanary').disabled=true;});
document.addEventListener('razvilka:auth-required',()=>{
 awgUI.epoch++;awgUI.serial++;awgUI.probe?.abort();awgUI.probe=null;awgUI.snapshot=null;awgUI.importPreview=null;awgUI.loading=false;awgUI.importBusy=false;awgUI.fetched=0;awgUI.message='';awgUI.proof=null;
 $('#awgImportDialog').close();$('#awgImportText').value='';$('#awgImportFile').value='';$('#awgImportPreview').replaceChildren();$('#awgCompatibility').replaceChildren();$('#awgProofState').textContent='Не запускалась';
});
renderAWGWorkspace();
