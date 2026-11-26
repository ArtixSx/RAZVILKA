'use strict';

// Public catalog metadata only. Private configs stay in the visible form and
// the request body; CRUD never starts a probe, assigns a route or runs Apply.
const wgProfiles = {epoch:0,visible:false,read:null,mutation:null,loaded:false,profiles:[],revision:null,editing:null,needsRead:false,message:'',fileSerial:0};
const wgProfilesPath = '/api/v1/wireguard/profiles';
function wgProfilesCurrent(ticket) {
 return ticket.epoch===wgProfiles.epoch&&!ticket.controller?.signal.aborted&&state.authenticated!==false&&$('#authScreen').hidden&&state.currentView==='engineconfig'&&state.selectedEngine==='wireguard';
}
function wgProfilesMetadata(view) {
 const profile=view?.profile;
 if(!profile||profile.engine!=='wireguard'||profile.verification!=='syntax-only'||typeof profile.id!=='string'||!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(profile.id)||profile.id==='main'
   ||typeof profile.name!=='string'||!profile.name.trim()||new TextEncoder().encode(profile.name).length>160||!/^[a-f0-9]{64}$/.test(profile.revision||'')||view.route!=='wireguard:'+profile.id||typeof view.reserve!=='boolean'||!Array.isArray(view.references))throw new Error('invalid-public-metadata');
 return {profile:{id:profile.id,name:profile.name,revision:profile.revision,engine:'wireguard',verification:'syntax-only'},route:view.route,reserve:view.reserve,
   references:view.references.map(ref=>({kind:typeof ref?.kind==='string'?ref.kind:'unknown',service_id:typeof ref?.service_id==='string'?ref.service_id:''}))};
}
function wgProfilesReferences(refs) {
 const labels={'draft':'настройки','applied':'рабочий маршрут','suspended':'приостановленные настройки','suspended-route':'приостановленный маршрут','network-draft':'общая политика','network-applied':'рабочая общая политика','dataplane-pending':'подготовленный план','dataplane-committed':'сохранённый рабочий план'};
 return refs.map(ref=>{const service=(state.services||[]).find(service=>service.id===ref.service_id);return (labels[ref.kind]||'сохранённая ссылка')+(ref.service_id?' · '+(service?.name||ref.service_id):'');}).join('; ');
}
function wgProfilesError(error) {
 if(error?.status===401)return 'Сессия завершена. Войдите снова.';
 if(error?.payload?.outcome==='unconfirmed')return 'Результат записи не подтверждён. '+(error.payload.restoration_confirmed===true?'Backend подтвердил возврат предыдущей редакции. ':'')+'Перечитайте каталог перед новым действием.';
 if(error?.status===404||error?.status===501)return 'Операция профилей WireGuard отсутствует в этой версии backend. Обновите приложение целиком.';
 if(error?.status===409){const refs=error.payload?.references;return Array.isArray(refs)&&refs.length?'Профиль используется: '+wgProfilesReferences(refs)+'. Сначала снимите ссылки и перечитайте каталог.':'Редакция, ссылки или состояние операции изменились. Перечитайте каталог.';}
 if(error?.status===400)return 'Имя или конфигурация отклонены. Проверьте полный файл WireGuard и перечитайте каталог.';
 return 'Результат операции не подтверждён. Перечитайте каталог перед новым действием.';
}
function wgProfilesClearForm() {
 wgProfiles.fileSerial++;wgProfiles.editing=null;
 for(const id of ['wgProfileID','wgProfileName','wgProfileContent','wgProfileFile'])$('#'+id).value='';
}
function wgProfilesLeave(clearMetadata=false) {
 wgProfiles.epoch++;wgProfiles.read?.controller.abort();wgProfiles.read=null;
 if(wgProfiles.loaded){wgProfiles.needsRead=true;wgProfiles.message='Показан прежний каталог. Перечитайте его перед изменениями.';}
 if(wgProfiles.mutation){wgProfiles.mutation.controller.abort();wgProfiles.needsRead=true;wgProfiles.message='Результат записи не подтверждён. Перечитайте каталог перед новым действием.';}
 wgProfilesClearForm();wgProfiles.visible=false;
 if(clearMetadata){wgProfiles.mutation=null;wgProfiles.loaded=false;wgProfiles.profiles=[];wgProfiles.revision=null;wgProfiles.needsRead=false;wgProfiles.message='';$('#wgProfileList').replaceChildren();}
}
function renderWireGuardProfiles() {
 const visible=state.authenticated!==false&&$('#authScreen').hidden&&state.currentView==='engineconfig'&&state.selectedEngine==='wireguard';
 $('#wgProfilesWorkspace').hidden=!visible;
 $('#wgProfilesLegacyHint').hidden=!visible;
 if(!visible){if(wgProfiles.visible)wgProfilesLeave();return;}
 wgProfiles.visible=true;
 const busy=!!wgProfiles.read||!!wgProfiles.mutation,ready=wgProfiles.loaded&&!wgProfiles.needsRead&&!busy;
 $('#wgProfilesRefresh').disabled=busy;
 $('#wgProfileID').disabled=busy||!!wgProfiles.editing;
 for(const id of ['wgProfileName','wgProfileContent','wgProfileFile','wgProfileReset'])$('#'+id).disabled=busy;
 $('#wgProfileSave').disabled=!ready;
 $('#wgProfileSave').textContent=wgProfiles.mutation?'Сохраняем…':wgProfiles.editing?'Сохранить замену':'Сохранить профиль';
 $('#wgProfileFormTitle').textContent=wgProfiles.editing?'Заменить файл «'+wgProfiles.editing.profile.name+'»':'Добавить профиль';
 $('#wgProfilesStatus').textContent=wgProfiles.read?'Читаем каталог…':wgProfiles.message||(wgProfiles.loaded?'Сохранение проверяет синтаксис. Проверка сервиса и применение выполняются отдельно.':'Каталог ещё не прочитан.');
 $('#wgProfileList').innerHTML=wgProfiles.profiles.map(view=>`<article class="wg-profile-card"><div><b>${esc(view.profile.name)}</b><small>${esc(view.route)} · формат принят</small><p>${view.references.length?'Используется: '+esc(wgProfilesReferences(view.references)):view.reserve?'Сохранён без назначений':'Назначения не подтверждены'}</p></div><div class="wg-profile-actions"><button type="button" class="secondary" data-wg-replace="${esc(view.profile.id)}" ${ready?'':'disabled'}>Заменить файл</button><button type="button" class="danger-button" data-wg-delete="${esc(view.profile.id)}" ${ready&&!view.references.length?'':'disabled'}>Удалить</button></div></article>`).join('')||(wgProfiles.loaded?'<p class="r4-note">Сохранённых профилей пока нет.</p>':'');
 if(!wgProfiles.loaded&&!wgProfiles.needsRead&&!busy)void refreshWireGuardProfiles();
}
async function refreshWireGuardProfiles() {
 if(wgProfiles.read||wgProfiles.mutation)return false;
 const ticket={epoch:wgProfiles.epoch,controller:new AbortController()};
 if(!wgProfilesCurrent(ticket)||document.hidden)return false;
 wgProfiles.read=ticket;renderWireGuardProfiles();
 try{
  const result=await api(wgProfilesPath,{signal:ticket.controller.signal});
  if(!wgProfilesCurrent(ticket))return false;
  if(!Array.isArray(result?.profiles)||!Number.isSafeInteger(result.config_revision)||result.config_revision<0)throw new Error('invalid-public-catalog');
  const profiles=result.profiles.map(wgProfilesMetadata);
  if(new Set(profiles.map(view=>view.profile.id)).size!==profiles.length)throw new Error('duplicate-profile');
  wgProfiles.profiles=profiles;wgProfiles.revision=result.config_revision;wgProfiles.loaded=true;wgProfiles.needsRead=false;
  wgProfiles.message=wgProfiles.editing&&profiles.find(view=>view.profile.id===wgProfiles.editing.profile.id)?.profile.revision!==wgProfiles.editing.profile.revision?'Редакция профиля изменилась. Выберите «Заменить файл» заново перед сохранением.':'';
  return true;
 }catch(error){if(wgProfilesCurrent(ticket)){wgProfiles.needsRead=true;wgProfiles.message=wgProfilesError(error);}return false;}
 finally{if(wgProfiles.read===ticket)wgProfiles.read=null;if(wgProfilesCurrent(ticket))renderWireGuardProfiles();}
}
function wgProfilesEdit(id) {
 if(!wgProfiles.loaded||wgProfiles.needsRead||wgProfiles.read||wgProfiles.mutation)return;
 const view=wgProfiles.profiles.find(view=>view.profile.id===id);if(!view)return;
 wgProfilesClearForm();wgProfiles.editing=view;
 $('#wgProfileID').value=id;$('#wgProfileName').value=view.profile.name;
 wgProfiles.message='Вставьте полный новый файл. Сохранённый приватный файл не возвращается в браузер.';
 $('#wgProfileFormDisclosure').open=true;
 renderWireGuardProfiles();$('#wgProfileContent').focus();
}
async function wgProfilesSave() {
 if(!wgProfiles.loaded||wgProfiles.needsRead||wgProfiles.read||wgProfiles.mutation)return;
 const editing=wgProfiles.editing,id=$('#wgProfileID').value.trim(),name=$('#wgProfileName').value.trim(),content=$('#wgProfileContent').value;
 if(!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(id)||id==='main'||!name||new TextEncoder().encode(name).length>160||!content.trim()||new TextEncoder().encode(content).length>131072){wgProfiles.message='Укажите короткое имя латиницей, название до 160 байт и полный файл до 128 КиБ.';renderWireGuardProfiles();return;}
 if(editing?editing.profile.id!==id||wgProfiles.profiles.find(view=>view.profile.id===id)?.profile.revision!==editing.profile.revision:wgProfiles.profiles.some(view=>view.profile.id===id)){wgProfiles.message='Профиль уже существует или его редакция изменилась. Выберите «Заменить файл» в текущем каталоге.';renderWireGuardProfiles();return;}
 const body=editing?{name,content,expected_revision:editing.profile.revision}:{id,name,content};
 await wgProfilesMutate(editing?'PUT':'POST',editing?id:'',body);
}
async function wgProfilesDelete(id) {
 if(!wgProfiles.loaded||wgProfiles.needsRead||wgProfiles.read||wgProfiles.mutation)return;
 const view=wgProfiles.profiles.find(view=>view.profile.id===id);if(!view||view.references.length)return;
 const ticket={epoch:wgProfiles.epoch};
 const yes=await askConfirmation('Удалить профиль «'+view.profile.name+'»?','Будет удалён сохранённый файл WireGuard. Роутер повторно проверит редакцию и все ссылки.','Удалить профиль');
 const current=wgProfiles.profiles.find(view=>view.profile.id===id);
 if(!yes||!wgProfilesCurrent(ticket)||wgProfiles.read||wgProfiles.mutation||wgProfiles.needsRead||current?.profile.revision!==view.profile.revision||current.references.length)return;
 await wgProfilesMutate('DELETE',id,{expected_revision:view.profile.revision});
}
async function wgProfilesMutate(method,id,body) {
 const ticket={epoch:wgProfiles.epoch,controller:new AbortController()};
 if(!wgProfilesCurrent(ticket))return;
 wgProfiles.mutation=ticket;wgProfiles.needsRead=true;wgProfiles.message=method==='DELETE'?'Удаляем профиль…':'Сохраняем профиль…';renderWireGuardProfiles();
 if(typeof invalidateEngineProgress==='function')invalidateEngineProgress('wireguard');
 let saved=false;
 try{
  const result=await api(wgProfilesPath+(id?'/'+encodeURIComponent(id):''),{method,body:JSON.stringify(body),signal:ticket.controller.signal});
  if(!wgProfilesCurrent(ticket))return;
  if(result?.live_applied!==false||result.error||result.outcome==='unconfirmed'||(method==='DELETE'?result.deleted!==true:result.saved!==true))throw new Error('unconfirmed-receipt');
  if(method!=='DELETE'){const view=wgProfilesMetadata(result.profile);if(view.profile.id!==(id||body.id)||view.profile.name!==body.name)throw new Error('foreign-profile-receipt');}
  saved=true;wgProfilesClearForm();wgProfiles.message=method==='DELETE'?'Профиль удалён.':'Профиль сохранён. Проверен только синтаксис; маршрут не применялся.';
 }catch(error){if(wgProfilesCurrent(ticket))wgProfiles.message=wgProfilesError(error);}
 finally{body.content=null;if(wgProfiles.mutation===ticket)wgProfiles.mutation=null;}
 if(!wgProfilesCurrent(ticket))return;
 const message=wgProfiles.message;
 if(saved){const read=await refreshWireGuardProfiles();if(wgProfilesCurrent(ticket)){wgProfiles.message=read?message:message+' Каталог не перечитан; дальнейшие изменения заблокированы.';}}
 renderWireGuardProfiles();
}
$('#wgProfilesRefresh').addEventListener('click',()=>refreshWireGuardProfiles());
$('#wgProfileForm').addEventListener('submit',event=>{event.preventDefault();void wgProfilesSave();});
$('#wgProfileReset').addEventListener('click',()=>{if(wgProfiles.mutation)return;wgProfilesClearForm();renderWireGuardProfiles();});
$('#wgProfileList').addEventListener('click',event=>{const replace=event.target.closest('[data-wg-replace]'),remove=event.target.closest('[data-wg-delete]');if(replace)wgProfilesEdit(replace.dataset.wgReplace);if(remove)void wgProfilesDelete(remove.dataset.wgDelete);});
$('#wgProfileFile').addEventListener('change',async()=>{
 const file=$('#wgProfileFile').files?.[0],ticket={epoch:wgProfiles.epoch},serial=++wgProfiles.fileSerial;if(!file)return;
 if(file.size>131072){wgProfiles.message='Файл больше 128 КиБ.';renderWireGuardProfiles();return;}
 try{const content=await file.text();if(wgProfilesCurrent(ticket)&&serial===wgProfiles.fileSerial&&!wgProfiles.mutation)$('#wgProfileContent').value=content;}
 catch(_){if(wgProfilesCurrent(ticket)){wgProfiles.message='Файл не прочитан. Вставьте его содержимое вручную.';renderWireGuardProfiles();}}
});
document.addEventListener('razvilka:auth-required',()=>{wgProfilesLeave(true);$('#wgProfilesWorkspace').hidden=true;});
document.addEventListener('razvilka:view-change',event=>{if(event.detail!=='engineconfig'&&wgProfiles.visible)wgProfilesLeave();});
renderWireGuardProfiles();
