/* Read-only DNS diagnostics in the router's existing durable job queue. */
(function(root){
'use strict';
const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function profilesForLab(snapshot){
 const providers=new Map((snapshot?.providers||[]).map(p=>[p.id,p]));
 return (snapshot?.profiles||[]).flatMap(p=>{
  const provider=providers.get(p.provider_id);
  return provider?.configured&&provider.doh&&!provider.trusted_local&&provider.scope!=='negative-control'?[{id:p.id,name:p.name,provider,kind:provider.kind||'unknown'}]:[];
 });
}
function requestFor(serviceID,ids,revision,consent,verifyService=false){
 if(!/^[a-z0-9][a-z0-9-]{0,63}$/.test(serviceID)||!Number.isSafeInteger(revision)||revision<0||!consent||!Array.isArray(ids)||ids.length<1||ids.length>3||new Set(ids).size!==ids.length)throw Error('Выберите сервис, 1–3 профиля и разрешите DNS-запросы.');
 if(ids.some(id=>! /^[a-z0-9][a-z0-9-]{0,63}$/.test(id)))throw Error('Неверный профиль.');
 if(verifyService&&ids.length>2)throw Error('Для проверки сайта выберите не более двух DNS-профилей.');
 return {service_id:serviceID,profile_ids:ids,config_revision:revision,confirm:verifyService?'COMPARE_SERVICE_DNS_AND_HTTPS':'COMPARE_SERVICE_DNS',...(verifyService?{verify_service:true}:{})};
}
function resultMarkup(result){
 if(result?.service_verified!==false||result?.route_verified!==false||result?.eligible_for_apply!==false||!Array.isArray(result?.results))throw Error('Backend вернул неподдерживаемый уровень доказательства. Результат не принят.');
 const statuses={resolved:'Адрес получен',error:'Запрос не завершён',rejected:'Ответ отклонён','no-address':'Нет адреса этой семьи',unknown:'Нет результата'};
 const errors={DNS_BOOTSTRAP_FAILED:'Локальный DNS не смог найти адрес провайдера',DNS_TLS_FAILED:'Не удалось подтвердить сертификат DNS-провайдера',DNS_HTTP_REJECTED:'DNS-провайдер отклонил HTTPS-запрос',DNS_QUERY_TIMEOUT:'DNS-провайдер не ответил вовремя',DNS_QUERY_FAILED:'Не удалось соединиться с DNS-провайдером',DNS_INTEGRITY_FAILED:'DNS-ответ не прошёл проверку',DNS_UNSAFE_ANSWER:'Получен непубличный адрес'};
 return '<div class="dc1-result-note">Это DNS-ответы, не подтверждение работы сервиса на ваших устройствах.</div>'+result.results.map(row=>`<div class="dc1-answer"><div><strong>${escape(row.provider_id)}</strong><small>${escape(row.family)} · DoH</small></div><div><b>${escape(statuses[row.status]||'Неизвестный статус')}</b><small>${escape((row.addresses||[]).slice(0,8).join(', ')||errors[row.error_code]||row.error_code||'—')}</small>${Number.isInteger(row.ttl_seconds)?`<small>Срок DNS-ответа: ${escape(row.ttl_seconds)} с</small>`:''}</div></div>`).join('');
}
function addressChecksMarkup(checks,rows){
 if(!Array.isArray(checks)||checks.length>4)throw Error('Неполный результат проверки сайта.');
 const expected=rows.filter(row=>row.status==='resolved'&&row.addresses?.length);
 if(checks.length!==expected.length)throw Error('Получены не все результаты проверки адресов.');
 const seen=new Set();
 return '<div class="dc1-result-note">HTTPS с роутера: проверен один адрес каждой доступной семьи. Подключение ваших устройств и выбранный обход ещё не подтверждены.</div>'+checks.map(check=>{
  const row=expected.find(r=>r.profile_id===check.profile_id&&r.family===check.family),r=check.result,key=check.profile_id+':'+check.family;
  if(!row||seen.has(key)||!r||r.address!==row.addresses[0]||check.answer_fingerprint!==row.answer_fingerprint||check.address_count!==row.addresses.length||r.route_verified!==false||r.application_path!=='system-routing-unverified')throw Error('Проверка не соответствует DNS-ответу.');
  seen.add(key);
  if(r.service_verified&&(!r.tls_verified||r.status!=='pass'))throw Error('Работа сайта не подтверждена сертификатом и ответом.');
  const title=r.service_verified?'Сайт ответил':r.status==='not-checked'?'Не проверен':'Проверка не пройдена';
  const timing=(label,value)=>Number.isFinite(value)&&value>=0?`${label}: ${Math.round(value)} мс`:`${label}: —`;
  return `<div class="dc1-answer"><div><strong>${escape(check.profile_id)}</strong><small>${escape(check.family)} · 1 из ${escape(check.address_count)} адресов</small></div><div><b>${title}</b><small>${escape(r.address)}${r.http_status?' · HTTP '+escape(r.http_status):''}</small><small>${escape([timing('Соединение',r.tcp_ms),timing('TLS',r.tls_ms),timing('Ответ',r.ttfb_ms)].join(' · '))}</small>${r.error_code?`<small>${escape(r.error_code==='DNS_ANSWER_EXPIRED'?'Срок DNS-ответа истёк; повторите проверку':r.error_code)}</small>`:''}</div></div>`;
 }).join('');
}
function acceptResponse(response,body,revision){
 if(response?.ok!==true||response.live_applied!==false||response.service_id!==body.service_id)throw Error('Ответ не соответствует выбранному сервису.');
 if(!Number.isSafeInteger(revision)||response.config_revision!==body.config_revision||revision!==body.config_revision)throw Error('Настройки изменились во время сравнения. Обновите состояние и повторите запрос.');
 const rows=response.result?.results,seen=new Set();
 if(!Array.isArray(rows)||rows.length!==body.profile_ids.length*2)throw Error('Получен неполный набор DNS-ответов. Повторите сравнение.');
 for(const row of rows){
  const key=row.profile_id+':'+row.family;
  if(!body.profile_ids.includes(row.profile_id)||!['ipv4','ipv6'].includes(row.family)||seen.has(key))throw Error('Ответ не соответствует выбранным DNS-профилям.');
  seen.add(key);
 }
 return resultMarkup(response.result)+(body.verify_service?addressChecksMarkup(response.address_checks,rows):'');
}
const pendingStates=['queued','running','canceling','interrupted'];
function requestFromJob(job){
 if(job?.mode!=='service-dns-compare'||!Number.isSafeInteger(job.id)||job.id<1||![...pendingStates,'completed','failed','canceled'].includes(job.state))throw Error('Не получено корректное состояние DNS-проверки.');
 const q=job.dns_request;
 return requestFor(q?.service_id,q?.profile_ids,q?.config_revision,true,q?.verify_service===true);
}
function sameRequest(a,b){return a.service_id===b.service_id&&a.config_revision===b.config_revision&&!!a.verify_service===!!b.verify_service&&JSON.stringify(a.profile_ids)===JSON.stringify(b.profile_ids);}
const model={profilesForLab,requestFor,resultMarkup,acceptResponse,addressChecksMarkup,requestFromJob,sameRequest};
if(typeof module!=='undefined'&&module.exports)module.exports=model;
root.RazvilkaDNSLabModel=model;
if(typeof document==='undefined'||!document.getElementById('dc1Form'))return;
const el=id=>document.getElementById(id);let active=null,pendingJob=null,lastJob='',serviceKey='',profileKey='',resultRevision=null,savedRequest=null,cancelBusy=false;
function tokenFor(body){
 const signature=JSON.stringify(body);let saved=savedRequest;
 try{saved||=JSON.parse(sessionStorage.getItem('razvilka.dns-request')||'null');}catch(_){}
 if(!saved||saved.signature!==signature||!/^[a-f0-9]{32}$/.test(saved.key)||!Number.isFinite(saved.at)||Date.now()<saved.at||Date.now()-saved.at>=86400000){
  const bytes=new Uint8Array(16);root.crypto.getRandomValues(bytes);
  saved={signature,key:Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join(''),at:Date.now()};
 }
 savedRequest=saved;try{sessionStorage.setItem('razvilka.dns-request',JSON.stringify(saved));}catch(_){}return saved.key;
}
function forgetToken(body){
 if(savedRequest?.signature!==JSON.stringify(body))return;
 savedRequest=null;try{sessionStorage.removeItem('razvilka.dns-request');}catch(_){}
}
function controls(){
 const busy=!!active||!!pendingJob;
 el('dc1Inputs').disabled=busy;el('dc1Submit').disabled=busy||!state.services?.length||!state.dns;
 el('dc1Cancel').hidden=!pendingJob;el('dc1Cancel').disabled=cancelBusy||pendingJob?.state==='canceling';
}
function refreshJobs(){if(typeof scheduleWorkspaceControl==='function')scheduleWorkspaceControl(0);}
function render(){
 if(active||pendingJob){controls();return;}
 if(resultRevision!==null&&resultRevision!==Number(state.status?.revision)){clear();el('dc1Status').textContent='Настройки изменились. Для текущего состояния повторите сравнение DNS.';}
 const services=(state.services||[]).filter(s=>s.probe_url||(s.probes||[]).some(p=>p.required&&p.url));
 const selected=el('dc1Service').value;
 const options=services.map(s=>`<option value="${escape(s.id)}">${escape(s.name)}</option>`).join('');
 if(serviceKey!==options){serviceKey=options;el('dc1Service').innerHTML=options;if(services.some(s=>s.id===selected))el('dc1Service').value=selected;}
 const checked=new Set([...el('dc1Profiles').querySelectorAll('input:checked')].map(i=>i.value));
 const available=profilesForLab(state.dns),key=JSON.stringify(available.map(p=>[p.id,p.name,p.kind]));
 const markup=available.map(p=>`<label class="dc1-provider"><input type="checkbox" name="profile" value="${escape(p.id)}" ${checked.has(p.id)?'checked':''}><span><b>${escape(p.name)}</b><small>${p.kind==='smart-dns-gateway'?'Smart DNS · сторонний шлюз':'DNS-резолвер'} · только после локальной проверки</small></span></label>`).join('');
 if(profileKey!==key){profileKey=key;el('dc1Profiles').innerHTML=markup;}
 controls();
}
const oldRenderDNS=renderDNS;
renderDNS=function(){oldRenderDNS();render();};
function clear(){resultRevision=null;el('dc1Results').replaceChildren();el('dc1Status').textContent='';}
el('dc1Service').addEventListener('change',clear);el('dc1Profiles').addEventListener('change',clear);
el('dc1VerifyService')?.addEventListener('change',()=>{clear();el('dc1Submit').textContent=el('dc1VerifyService').checked?'Проверить DNS и сайт':'Сравнить DNS-ответы';});
// Status uses the panel's shared reader. Opening this page never submits a job.
root.acceptDNSLabJobs=function(control){
 const jobs=(control?.durable_jobs||[]).filter(j=>j.mode==='service-dns-compare');
 const job=(pendingJob&&jobs.find(j=>j.id===pendingJob.id))||jobs.find(j=>pendingStates.includes(j.state))||jobs.at(-1);
 if(!job)return !!pendingJob;
 let body;try{body=requestFromJob(job);}catch(error){el('dc1Status').textContent=error.message;return !!pendingJob;}
 const signature=JSON.stringify([job.id,job.state,job.error_code,!!job.dns_result]);
 if(active)return pendingStates.includes(job.state)||!!pendingJob;
 if(signature===lastJob)return !!pendingJob;
 lastJob=signature;clear();pendingJob=pendingStates.includes(job.state)?job:null;
 el('dc1Service').value=body.service_id;
 for(const input of el('dc1Profiles').querySelectorAll('input'))input.checked=body.profile_ids.includes(input.value);
 if(el('dc1VerifyService'))el('dc1VerifyService').checked=!!body.verify_service;
 el('dc1Status').textContent=job.message||'Состояние проверки получено.';
 if(!pendingJob){
  forgetToken(body);
  if(job.state==='completed'){
   if(!job.dns_result)el('dc1Status').textContent='Проверка была завершена, но её подробности уже недоступны. Повторите для текущей сети.';
   else try{el('dc1Results').innerHTML=acceptResponse(job.dns_result,body,Number(state.status?.revision));resultRevision=body.config_revision;
    el('dc1Status').textContent='Проверка завершена: '+String(job.dns_result.result?.checked_at||job.finished_at||'время не получено')+'. Это результат на момент проверки. Маршруты не менялись.';
   }catch(error){el('dc1Status').textContent=error.message;}
  }
 }
 controls();return !!pendingJob;
};
el('dc1Cancel').addEventListener('click',async()=>{
 if(!pendingJob||cancelBusy)return;
 const id=pendingJob.id,epoch=workflowState.epoch;cancelBusy=true;controls();
 try{
  const response=await workflowRequest('/api/v1/service-control/current?job_id='+id,{method:'DELETE'},12000);
  if(!workflowSession(epoch))return;
  root.acceptDNSLabJobs(response);
 }catch(error){if(workflowSession(epoch))el('dc1Status').textContent='Отмена не подтверждена: '+workflowError(error);}
 finally{if(workflowSession(epoch)){cancelBusy=false;controls();refreshJobs();}}
});
el('dc1Form').addEventListener('submit',async event=>{
 event.preventDefault();if(active||pendingJob)return;
 let body;try{body=requestFor(el('dc1Service').value,[...el('dc1Profiles').querySelectorAll('input:checked')].map(i=>i.value),Number(state.status?.revision),el('dc1Consent').checked,el('dc1VerifyService')?.checked===true);}catch(error){el('dc1Status').textContent=error.message;return;}
 const op={controller:new AbortController(),epoch:workflowState.epoch};active=op;
 clear();el('dc1Status').textContent='Сохраняем DNS-проверку на роутере…';controls();
 try{
  const response=await workflowRequest('/api/v1/dns/service-compare',{method:'POST',controller:op.controller,body:JSON.stringify({...body,idempotency_key:tokenFor(body)})},12000);
  if(op.controller.signal.aborted||!workflowSession(op.epoch))return;
  if(response.persistent!==true||!sameRequest(requestFromJob(response.job),body))throw Error('Сохранение задания не подтверждено. Обновите состояние.');
  pendingJob=response.job;lastJob='';
  el('dc1Status').textContent='Задание сохранено на роутере. Вкладку можно закрыть; результат появится здесь после проверки.';
 }catch(error){if(workflowSession(op.epoch))el('dc1Status').textContent='Ответ не получен: '+workflowError(error)+'. Проверьте состояние; повторный запрос не создаст копию задания.';}
 finally{if(active===op){active=null;if(workflowSession(op.epoch)){controls();refreshJobs();}}}
});
const oldAuth=showAuth;
showAuth=function(...args){active?.controller.abort();active=null;pendingJob=null;lastJob='';cancelBusy=false;clear();controls();el('dc1Consent').checked=false;return oldAuth.apply(this,args);};
render();
})(typeof globalThis!=='undefined'?globalThis:this);
