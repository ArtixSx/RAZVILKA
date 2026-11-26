/* Explicit next-boot backend intent. No installation, restart or Apply here. */
(function(root){
 'use strict';
 const ids=['sing-box','hev'];
 function validSnapshot(v){return !!v&&v.schema===1&&Number.isSafeInteger(v.revision)&&v.revision>=0&&ids.includes(v.backend)&&ids.includes(v.boot_backend)&&typeof v.restart_required==='boolean'&&v.restart_required===(v.backend!==v.boot_backend)&&v.live_applied===false&&v.available===null&&Array.isArray(v.backends)&&v.backends.length===2&&v.backends.every((e,i)=>e&&e.id===ids[i]&&typeof e.name==='string');}
 root.RazvilkaProxySidecarUI={validSnapshot};
 if(typeof document==='undefined')return;
 const $=id=>document.getElementById(id),read=$('proxySidecarRead'),select=$('proxySidecarSelect'),save=$('proxySidecarSave'),status=$('proxySidecarStatus');
 if(!read||!select||!save||!status)return;
 let snapshot=null,busy=false,epoch=0,sequence=0;
 function message(text,error=false){status.textContent=text;status.setAttribute('role',error?'alert':'status');}
 function render(){read.disabled=busy;select.disabled=busy||!snapshot;save.disabled=busy||!snapshot||select.value===snapshot.backend;}
 function accept(v){
  if(!validSnapshot(v))throw new Error('Выбор TUN backend не подтверждён. Прочитайте настройки повторно.');
  snapshot=v;select.replaceChildren();for(const e of v.backends){const option=document.createElement('option');option.value=e.id;option.textContent=e.name;select.appendChild(option);}select.value=v.backend;
  const boot=v.backends.find(e=>e.id===v.boot_backend).name;
  message((v.restart_required?'Выбор сохранён для следующего запуска приложения. Требуется отдельный перезапуск. ':'Выбор совпадает с текущим запуском. ')+`Текущий backend: ${boot}. `+'Для изменения сервисы должны быть остановлены или ещё не настроены; сервер проверит отсутствие исходных процессов и ресурсов. Установка и выбор не подтверждают доступность сервисов.');
 }
 async function request(mutation){
  if(busy||mutation&&(!snapshot||save.disabled))return;
  const generation=epoch,ticket=++sequence,options=mutation?{method:'PUT',body:JSON.stringify({backend:select.value,expected_revision:snapshot.revision})}:{};
  busy=true;render();message(mutation?'Проверяем отсутствие ресурсов и сохраняем выбор для следующего запуска…':'Читаем сохранённый и текущий backend…');
  try{
   const value=await interfaceRequest('/api/v1/runtime/proxy-sidecar',options);if(generation!==epoch||ticket!==sequence)return;accept(value);
   if(mutation){if(typeof root.refreshAfterMutation==='function')void root.refreshAfterMutation().catch(()=>{if(generation===epoch&&ticket===sequence)message('Выбор сохранён для следующего запуска. Обновите состояние панели перед дальнейшими действиями.',true);});else document.dispatchEvent(new CustomEvent('razvilka:panel-refresh'));}
  }catch(error){if(generation!==epoch||error.name==='AuthGenerationChanged')return;snapshot=null;const human=root.RazvilkaAutonomyModel?.requestErrorText(error,mutation)||error.message;message((human||'Ответ не получен.')+' Прочитайте текущий выбор перед повтором.',true);}
  finally{if(generation===epoch&&ticket===sequence){busy=false;render();}}
 }
 read.addEventListener('click',()=>request(false));save.addEventListener('click',()=>request(true));select.addEventListener('change',e=>{e.stopPropagation();render();});
 document.addEventListener('razvilka:auth-required',()=>{epoch++;sequence++;busy=false;snapshot=null;select.replaceChildren();message('Войдите и прочитайте сохранённый выбор.');render();});render();
})(globalThis);
