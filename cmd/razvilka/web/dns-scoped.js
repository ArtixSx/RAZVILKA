/* Scoped DNS uses the shared router job queue and the panel session lifetime. */
(function(root){
'use strict';
const pending=['queued','running','canceling','interrupted'];
const id=value=>typeof value==='string'&&/^[a-zA-Z0-9_.-]{1,128}$/.test(value);
const ipv4=value=>typeof value==='string'&&value.split('.').length===4&&value.split('.').every(p=>/^(0|[1-9]\d{0,2})$/.test(p)&&Number(p)<256);
function requestFor(view,service,profile,listener,ingress,action='apply'){
 if(!view?.available||!Number.isSafeInteger(view.config_revision)||view.config_revision<0||!id(service))throw Error('Обновите состояние DNS и выберите сервис.');
 let spec;
 if(action==='remove'){
  if(!['configured','stopped'].includes(view.state)||view.service_id!==service)throw Error('Нет сохранённой привязки для удаления.');
  spec={action};
 }else{
  const candidate=view.candidates?.find(c=>c.service_id===service);
  const endpoint=String(listener).split(':');
  if(action!=='apply'||!candidate||!ipv4(candidate.client)||!view.profile_ids?.includes(profile)||!id(profile)||endpoint.length!==2||!ipv4(endpoint[0])||!/^\d+$/.test(endpoint[1])||Number(endpoint[1])<1024||Number(endpoint[1])>65535||Number(endpoint[1])===8787||!/^[a-zA-Z0-9_.-]{1,15}$/.test(ingress))throw Error('Выберите применённый прямой маршрут для одного устройства, DNS и адрес роутера.');
  spec={action,profile_id:profile,client:candidate.client,listener,ingress};
 }
 return {service_id:service,expected_revision:view.config_revision,dns_apply:spec};
}
function acceptReview(response,body,revision){
 if(response?.ok!==true||response.live_applied!==false||response.review?.expected_revision!==body.expected_revision||revision!==body.expected_revision||!/^[a-f0-9]{64}$/.test(response.review?.reviewed_digest)||response.plan?.ready!==true)throw Error('План устарел или не подтверждён. Повторите просмотр.');
 const policy=response.plan.scoped_dns;
 if(body.dns_apply.action==='remove'){
  if(policy||!response.plan.retiring_adapters?.includes('dns-scoped'))throw Error('Удаление DNS не подтверждено планом.');
 }else{
  const spec=body.dns_apply,bindings=policy?.bindings;
  if(policy?.listener!==spec.listener||policy?.ingress!==spec.ingress||!Array.isArray(bindings)||bindings.length<1||bindings.length>32||bindings.some(b=>b.service_id!==body.service_id||b.profile_id!==spec.profile_id||b.client!==spec.client))throw Error('Область DNS в плане отличается от выбранной.');
 }
 return {...body,dns_apply:{...body.dns_apply,reviewed_digest:response.review.reviewed_digest},confirm:'APPLY_SCOPED_DNS'};
}
function validJob(job){return job?.mode==='service-dns-apply'&&Number.isSafeInteger(job.id)&&job.id>0&&id(job.service_id)&&['apply','remove'].includes(job.dns_apply_action)&&[...pending,'completed','failed','canceled'].includes(job.state);}
function configuredText(view,names={}){
 if(!view?.available)return 'Применение DNS для устройства недоступно в этой сборке.';
 if(view.state==='unknown')return 'Состояние DNS уточняется. Сначала проверьте применённые маршруты.';
 if(!view.service_id)return 'Отдельный DNS пока не настроен.';
 return `${names[view.service_id]||view.service_id} · ${names[view.profile_id]||view.profile_id} · ${view.client}. ${view.state==='stopped'?'Сохранён, проект выключен.':'Настройка применена. Доступность сервиса проверяется отдельно.'}`;
}
const model={requestFor,acceptReview,validJob,configuredText};
if(typeof module!=='undefined'&&module.exports)module.exports=model;
root.RazvilkaScopedDNSModel=model;
if(typeof document==='undefined'||!document.getElementById('dnsScopedForm'))return;
const el=id=>document.getElementById(id),escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let active=null,review=null,job=null,lastJob='',lastView='',saved=null,cancelBusy=false,readSerial=0;
function clearReview(){review=null;el('dnsScopedReview').replaceChildren();controls();}
function controls(){
 const view=state.dns?.scoped,busy=!!active||!!job,available=!!view?.available;
 el('dnsScopedFields').disabled=busy||!available;
 el('dnsScopedPreview').disabled=busy||!available||!view.candidates?.length||!view.profile_ids?.length;
 el('dnsScopedRemove').disabled=busy||!available||!['configured','stopped'].includes(view.state)||!view.service_id;
 el('dnsScopedConfirm').hidden=!review;el('dnsScopedConfirm').disabled=busy||!review;
 el('dnsScopedCancel').hidden=!job;el('dnsScopedCancel').disabled=cancelBusy||job?.state==='canceling';
}
function render(){
 const view=state.dns?.scoped,names=Object.fromEntries([...(state.services||[]),...(state.dns?.profiles||[])].map(s=>[s.id,s.name]));
 el('dnsScopedCurrent').textContent=configuredText(view,names);
 if(active||job){controls();return;}
 const signature=JSON.stringify([view,state.dns?.service_drafts,state.status?.revision]);
 if(lastView!==signature){
  if(review){clearReview();el('dnsScopedStatus').textContent='Состояние изменилось. Повторите просмотр перед применением.';}
  lastView=signature;
  const selected=el('dnsScopedService').value,profile=el('dnsScopedProfile').value;
  el('dnsScopedService').innerHTML=(view?.candidates||[]).map(c=>`<option value="${escape(c.service_id)}">${escape(names[c.service_id]||c.service_id)} · ${escape(c.client)}</option>`).join('');
  if(view?.candidates?.some(c=>c.service_id===selected))el('dnsScopedService').value=selected;
  el('dnsScopedProfile').innerHTML=(view?.profile_ids||[]).map(id=>`<option value="${escape(id)}">${escape(names[id]||id)}</option>`).join('');
  if(view?.profile_ids?.includes(profile))el('dnsScopedProfile').value=profile;
  if(!el('dnsScopedListener').value)el('dnsScopedListener').value=view?.listener||'';
  if(!el('dnsScopedIngress').value)el('dnsScopedIngress').value=view?.ingress||'';
 }
 el('dnsScopedEligibility').textContent=view?.available&&!(view.candidates||[]).length?'Для применения откройте «Сервисы»: выберите прямое подключение и одно устройство, затем примените маршрут. Выключенную привязку можно удалить здесь.':'DNS действует для точных доменов сервиса на одном устройстве. Запросы должны идти к DNS роутера; собственный DNS браузера и IPv6-подключение устройства этим правилом не охвачены.';
 controls();
}
function tokenFor(body){
 const signature=JSON.stringify(body);try{saved||=JSON.parse(sessionStorage.getItem('razvilka.dns-apply-request')||'null');}catch(_){}
 if(!saved||saved.signature!==signature||!/^[a-f0-9]{32}$/.test(saved.key)||!Number.isFinite(saved.at)||Date.now()<saved.at||Date.now()-saved.at>=86400000){
  const bytes=new Uint8Array(16);root.crypto.getRandomValues(bytes);
  saved={signature,key:Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join(''),at:Date.now()};
 }
 try{sessionStorage.setItem('razvilka.dns-apply-request',JSON.stringify(saved));}catch(_){}return saved.key;
}
function refresh(){if(typeof scheduleWorkspaceControl==='function')scheduleWorkspaceControl(0);}
async function reloadDNS(epoch){
 const serial=++readSerial;
 try{const snapshot=await workflowRequest('/api/v1/dns',{},12000);if(serial===readSerial&&!active&&workflowSession(epoch)){state.dns=snapshot;renderDNS();}}catch(error){if(serial===readSerial&&workflowSession(epoch))el('dnsScopedStatus').textContent+=' Текущее состояние не получено: '+workflowError(error);}
}
root.refreshScopedDNS=function(){clearReview();void reloadDNS(workflowState.epoch);};
root.acceptDNSApplyJobs=function(control){
 const jobs=(control?.durable_jobs||[]).filter(validJob),current=(job&&jobs.find(j=>j.id===job.id))||jobs.find(j=>pending.includes(j.state))||jobs.at(-1);
 if(active)return !!job||!!current&&pending.includes(current.state);
 if(!current)return !!job;
 const signature=JSON.stringify([current.id,current.state,current.error_code,current.phase]);
 if(lastJob===signature)return !!job;
 // A late history read is not a newer operation and must not dismiss a plan
 // the user has just reviewed. Running work from another tab still wins.
 if(review&&!job&&!pending.includes(current.state)){lastJob=signature;return false;}
 const wasPending=!!job;lastJob=signature;job=pending.includes(current.state)?current:null;
 clearReview();el('dnsScopedStatus').textContent=current.message||'Состояние задания обновлено.';
 if(!job&&(wasPending||current.state==='completed'))void reloadDNS(workflowState.epoch);
 controls();return !!job;
};
async function preview(action){
 if(active||job)return;
 let body;try{const view=state.dns?.scoped;body=requestFor(view,action==='remove'?view?.service_id:el('dnsScopedService').value,el('dnsScopedProfile').value,el('dnsScopedListener').value.trim(),el('dnsScopedIngress').value.trim(),action);}catch(error){el('dnsScopedStatus').textContent=error.message;return;}
 const op={controller:new AbortController(),epoch:workflowState.epoch};active=op;readSerial++;clearReview();el('dnsScopedStatus').textContent='Проверяем текущую область и готовим план…';
 try{
  if(action==='apply'){
   const snapshot=await workflowRequest('/api/v1/dns/service-draft',{method:'PUT',controller:op.controller,body:JSON.stringify({service_id:body.service_id,profile_id:body.dns_apply.profile_id})},12000);
   if(!workflowSession(op.epoch)||op.controller.signal.aborted)return;state.dns=snapshot;
  }
  const response=await workflowRequest('/api/v1/dns/scoped/preview',{method:'POST',controller:op.controller,body:JSON.stringify(body)},35000);
  if(!workflowSession(op.epoch)||op.controller.signal.aborted)return;
  review=acceptReview(response,body,Math.max(Number(state.status?.revision)||0,Number(state.serviceControl?.config_revision)||0));lastView=JSON.stringify([state.dns?.scoped,state.dns?.service_drafts,state.status?.revision]);
  const policy=response.plan.scoped_dns;
  el('dnsScopedReview').textContent=action==='remove'?'Будет удалена отдельная привязка DNS. Маршруты и ожидающие изменения останутся прежними.':`Устройство: ${body.dns_apply.client}. Домены: ${policy.bindings.map(b=>b.domain).join(', ')}. Подключение: напрямую. ${state.dns?.scoped?.service_id?'Прежняя отдельная привязка DNS будет заменена. ':''}Перед применением роутер проверит DNS и HTTPS; при ошибке вернёт прежнюю настройку.`;
  el('dnsScopedStatus').textContent='План готов. Сеть пока не изменена.';
  el('dnsScopedConfirm').textContent=action==='remove'?'Удалить привязку':'Проверить и применить';
 }catch(error){if(workflowSession(op.epoch))el('dnsScopedStatus').textContent=workflowError(error);}
 finally{if(active===op){active=null;if(workflowSession(op.epoch))controls();}}
}
el('dnsScopedForm').addEventListener('submit',event=>{event.preventDefault();void preview('apply');});
el('dnsScopedRemove').addEventListener('click',()=>void preview('remove'));
for(const id of ['dnsScopedService','dnsScopedProfile','dnsScopedListener','dnsScopedIngress'])el(id).addEventListener('input',()=>{clearReview();el('dnsScopedStatus').textContent='';});
el('dnsScopedConfirm').addEventListener('click',async()=>{
 if(active||job||!review)return;
 const body=review,op={controller:new AbortController(),epoch:workflowState.epoch};active=op;controls();
 try{
  const response=await workflowRequest('/api/v1/dns/scoped/apply',{method:'POST',controller:op.controller,body:JSON.stringify({...body,idempotency_key:tokenFor(body)})},12000);
  if(!workflowSession(op.epoch)||op.controller.signal.aborted)return;
  if(response?.persistent!==true||!validJob(response.job)||response.job.service_id!==body.service_id||response.job.dns_apply_action!==body.dns_apply.action)throw Error('Сохранение задания не подтверждено.');
  job=response.job;lastJob='';review=null;el('dnsScopedStatus').textContent=response.job.message;
 }catch(error){if(workflowSession(op.epoch))el('dnsScopedStatus').textContent='Ответ не получен: '+workflowError(error)+'. Состояние проверяется; повтор этой кнопки использует тот же запрос.';}
 finally{if(active===op){active=null;if(workflowSession(op.epoch)){controls();refresh();}}}
});
el('dnsScopedCancel').addEventListener('click',async()=>{
 if(!job||cancelBusy)return;const epoch=workflowState.epoch,id=job.id;cancelBusy=true;controls();
 try{const response=await workflowRequest('/api/v1/service-control/current?job_id='+id,{method:'DELETE'},12000);if(workflowSession(epoch))root.acceptDNSApplyJobs(response);}
 catch(error){if(workflowSession(epoch))el('dnsScopedStatus').textContent='Отмена не подтверждена: '+workflowError(error);}
 finally{if(workflowSession(epoch)){cancelBusy=false;controls();refresh();}}
});
for(const name of ['renderDNS','renderStatus']){
 const previous=root[name];if(typeof previous==='function')root[name]=function(...args){previous.apply(this,args);render();};
}
const oldAuth=showAuth;
showAuth=function(...args){
 active?.controller.abort();active=null;review=null;job=null;saved=null;lastJob=lastView='';cancelBusy=false;readSerial++;
 try{sessionStorage.removeItem('razvilka.dns-apply-request');}catch(_){}
 for(const id of ['dnsScopedService','dnsScopedProfile','dnsScopedReview'])el(id).replaceChildren();
 for(const id of ['dnsScopedListener','dnsScopedIngress'])el(id).value='';
 el('dnsScopedStatus').textContent='';el('dnsScopedCurrent').textContent='Войдите для просмотра DNS.';controls();
 return oldAuth.apply(this,args);
};
render();
})(typeof globalThis!=='undefined'?globalThis:this);
