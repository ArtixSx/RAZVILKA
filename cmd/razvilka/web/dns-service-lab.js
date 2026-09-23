/* DC1: read-only service DNS comparison; no background scheduler or auto-apply. */
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
 return '<div class="dc1-result-note">Это DNS-ответы, не подтверждение работы сервиса на ваших устройствах.</div>'+result.results.map(row=>`<div class="dc1-answer"><div><strong>${escape(row.provider_id)}</strong><small>${escape(row.family)} · DoH</small></div><div><b>${escape(statuses[row.status]||'Неизвестный статус')}</b><small>${escape((row.addresses||[]).slice(0,8).join(', ')||row.error_code||'—')}</small>${Number.isInteger(row.ttl_seconds)?`<small>Срок DNS-ответа: ${escape(row.ttl_seconds)} с</small>`:''}</div></div>`).join('');
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
const model={profilesForLab,requestFor,resultMarkup,acceptResponse,addressChecksMarkup};
if(typeof module!=='undefined'&&module.exports)module.exports=model;
root.RazvilkaDNSLabModel=model;
if(typeof document==='undefined'||!document.getElementById('dc1Form'))return;
const el=id=>document.getElementById(id);let active=null,serviceKey='',profileKey='',resultRevision=null;
function render(){
 if(active)return;
 if(resultRevision!==null&&resultRevision!==Number(state.status?.revision)){clear();el('dc1Status').textContent='Настройки изменились. Для текущего состояния повторите сравнение DNS.';}
 const services=(state.services||[]).filter(s=>s.probe_url||(s.probes||[]).some(p=>p.required&&p.url));
 const selected=el('dc1Service').value;
 const options=services.map(s=>`<option value="${escape(s.id)}">${escape(s.name)}</option>`).join('');
 if(serviceKey!==options){serviceKey=options;el('dc1Service').innerHTML=options;if(services.some(s=>s.id===selected))el('dc1Service').value=selected;}
 const checked=new Set([...el('dc1Profiles').querySelectorAll('input:checked')].map(i=>i.value));
 const available=profilesForLab(state.dns),key=JSON.stringify(available.map(p=>[p.id,p.name,p.kind]));
 const markup=available.map(p=>`<label class="dc1-provider"><input type="checkbox" name="profile" value="${escape(p.id)}" ${checked.has(p.id)?'checked':''}><span><b>${escape(p.name)}</b><small>${p.kind==='smart-dns-gateway'?'Smart DNS · сторонний шлюз':'DNS-резолвер'} · только после локальной проверки</small></span></label>`).join('');
 if(profileKey!==key){profileKey=key;el('dc1Profiles').innerHTML=markup;}
 el('dc1Submit').disabled=!services.length||!state.dns;
}
const oldRenderDNS=renderDNS;
renderDNS=function(){oldRenderDNS();render();};
function clear(){resultRevision=null;el('dc1Results').replaceChildren();el('dc1Status').textContent='';}
el('dc1Service').addEventListener('change',clear);el('dc1Profiles').addEventListener('change',clear);
el('dc1VerifyService')?.addEventListener('change',()=>{clear();el('dc1Submit').textContent=el('dc1VerifyService').checked?'Проверить DNS и сайт':'Сравнить DNS-ответы';});
el('dc1Cancel').addEventListener('click',()=>{if(active){active.controller.abort();el('dc1Status').textContent='Сравнение отменено. Завершённого результата нет.';}});
el('dc1Form').addEventListener('submit',async event=>{
 event.preventDefault();if(active)return;
 let body;try{body=requestFor(el('dc1Service').value,[...el('dc1Profiles').querySelectorAll('input:checked')].map(i=>i.value),Number(state.status?.revision),el('dc1Consent').checked,el('dc1VerifyService')?.checked===true);}catch(error){el('dc1Status').textContent=error.message;return;}
 const op={controller:new AbortController(),epoch:workflowState.epoch};active=op;
 clear();el('dc1Status').textContent=body.verify_service?'Проверяем DNS, сертификат и ответ сайта. До 70 секунд…':'Сравниваем DNS на роутере. До 32 секунд, без изменения маршрутов…';
 el('dc1Submit').disabled=true;el('dc1Inputs').disabled=true;el('dc1Cancel').hidden=false;
 try{
  const response=await workflowRequest('/api/v1/dns/service-compare',{method:'POST',controller:op.controller,body:JSON.stringify(body)},body.verify_service?75000:38000);
  if(op.controller.signal.aborted||!workflowSession(op.epoch))return;
  el('dc1Results').innerHTML=acceptResponse(response,body,Number(state.status?.revision));
  resultRevision=body.config_revision;
  el('dc1Status').textContent='DNS-сравнение завершено. Рабочие DNS, маршруты и аккаунты не менялись.';
 }catch(error){if(workflowSession(op.epoch))el('dc1Status').textContent=error.name==='AbortError'?'Сравнение отменено или истекло время ожидания. Успех не подтверждён.':workflowError(error);}
 finally{if(active===op){active=null;el('dc1Inputs').disabled=false;el('dc1Cancel').hidden=true;if(workflowSession(op.epoch))render();}}
});
const oldAuth=showAuth;
showAuth=function(...args){active?.controller.abort();clear();el('dc1Consent').checked=false;return oldAuth.apply(this,args);};
render();
})(typeof globalThis!=='undefined'?globalThis:this);
