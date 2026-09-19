/* AUTO3: normal API consumers; no polling, secrets, automatic apply or remote code. */
(function(root){
'use strict';
const model={
 proxySummary(protocols,sources){
  if(!Array.isArray(protocols)||!protocols.length)return 'В черновике не выбран ни один протокол подключения.';
  const n=new Set((sources||[]).filter(Boolean)).size;
  return n?`В черновике: ${protocols.join(', ')} · ${n} разрешённых источников. После сохранения — локальная проверка, резерв и пополнение.`:'Источники пока не выбраны. Локальные методы остаются доступны; получение новых VLESS не разрешено.';
 },
 modeRequest(view,mode,consent,revision){
  if(!view?.available||!/^[a-f0-9]{64}$/.test(view.review||'')||!Number.isSafeInteger(revision)||revision<0)throw new Error('Сначала прочитайте актуальную конфигурацию.');
  if(!['auto','user-list'].includes(mode)||(mode==='auto'&&!view.can_auto)||(mode==='user-list'&&!view.can_list))throw new Error('Этот режим не поддерживается текущей конфигурацией.');
  if(mode==='auto'&&!consent)throw new Error('Подтвердите область действия автохостлиста.');
  return {mode,review:view.review,allow_discovery:mode==='auto'&&consent,config_revision:revision,confirm:'STAGE_NFQWS_MODE'};
 }
};
if(typeof module==='object'&&module.exports)module.exports=model;
root.RazvilkaAutomationSetup=model;
if(typeof document==='undefined')return;
const el=id=>document.getElementById(id);
let view=null,busy=false,serial=0,controller=null;
const status=text=>{el('auto3NFQStatus').textContent=text;};
function buttons(){el('auto3NFQRead').disabled=busy;el('auto3NFQMode').disabled=busy||!view?.available;el('auto3NFQSave').disabled=busy||!view?.available||el('auto3NFQMode').value==='keep';el('auto3NFQCancel').hidden=!busy;}
function summary(){
 const checked=name=>Array.from(document.querySelectorAll(`#a1-wizardForm input[name="${name}"]:checked`)).map(x=>x.value);
 const sources=checked('source').concat((el('a1-extraSourceIDs')?.value||'').split(/[\s,]+/));
 el('auto3ProxySummary').textContent=model.proxySummary(checked('protocol'),sources);
}
function invalidate(){serial++;controller?.abort();controller=null;busy=false;view=null;el('auto3NFQMode').value='keep';el('auto3DiscoveryConsent').checked=false;buttons();}
async function request(save){
 if(busy)return;
 const epoch=workflowState.epoch,seq=++serial;let options={};
 try{if(save)options={method:'PUT',body:JSON.stringify(model.modeRequest(view,el('auto3NFQMode').value,el('auto3DiscoveryConsent').checked,state.status?.revision))};}
 catch(e){status(e.message);return;}
 controller=new AbortController();options.controller=controller;busy=true;buttons();status(save?'Сохраняем только черновик режима…':'Читаем текущую конфигурацию…');
 try{
  const response=await workflowRequest('/api/v1/nfqws2/setup-mode',options,15000);
  if(seq!==serial||!workflowSession(epoch))return;
  view=save?response.mode:response;
  if(save&&response.live_applied!==false)throw new Error('Сервер вернул неизвестный результат. Перечитайте конфигурацию.');
  el('auto3NFQMode').value='keep';
  el('auto3NativeAdaptive').textContent=view.native_adaptive?'В конфигурации объявлен circular/autocircular. Это не доказательство успешного подбора и не разрешение заменять весь конфиг.':'Circular/autocircular в прочитанных аргументах не найден. Стратегия настраивается отдельно в лаборатории.';
  status(save?'Черновик сохранён. Действующие маршруты не менялись. Откройте «Списки и применение», проверьте изменения и примените их.':view.available?`Прочитан ${view.source==='staged'?'черновик':'конфиг'}; режим: ${view.mode}. Остальные аргументы и списки сохраняются.`:'Конфигурация NFQWS2 не найдена. Сначала настройте компонент.');
 }catch(e){if(seq===serial&&workflowSession(epoch)){view=null;status(workflowError(e));}}
 finally{if(seq===serial&&workflowSession(epoch)){busy=false;controller=null;buttons();}}
}
el('auto3NFQRead').addEventListener('click',()=>request(false));
el('auto3NFQSave').addEventListener('click',()=>request(true));
el('auto3NFQMode').addEventListener('change',buttons);
el('auto3NFQCancel').addEventListener('click',()=>{invalidate();status('Запрос отменён. При потерянном ответе перечитайте черновик; сохранение могло завершиться.');});
el('auto3OpenSources').addEventListener('click',()=>document.querySelector('[data-autonomy] [data-step="1"]')?.click());
el('auto3NFQLab').addEventListener('click',()=>setView('strategylab'));
el('auto3OwnSites').addEventListener('click',()=>openCommunityCatalog());
el('auto3NFQEditor').addEventListener('click',()=>{consoleNavigate('engineconfig','nfqws2');});
el('a1-wizardForm').addEventListener('change',summary);
el('a1-extraSourceIDs').addEventListener('input',summary);
window.addEventListener('razvilka:autonomy-state',()=>{queueMicrotask(summary);});
document.addEventListener('razvilka:auth-required',()=>{invalidate();el('auto3NativeAdaptive').textContent='Требуется вход.';el('auto3ProxySummary').textContent='Требуется вход.';status('Сеанс завершён.');});
document.addEventListener('razvilka:auth-restored',()=>{invalidate();el('auto3NativeAdaptive').textContent='Конфигурация ещё не прочитана.';summary();status('Нажмите «Прочитать конфигурацию», чтобы увидеть доступные режимы NFQWS2.');});
summary();buttons();
})(typeof globalThis!=='undefined'?globalThis:this);
