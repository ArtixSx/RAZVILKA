/* EXT5 local configuration/pack tools. No external URL, polling or implicit Apply. */
(function(root){
'use strict';
const apiModel={
 mihomo(content,index,port,action='preview',review=''){
  if(typeof content!=='string'||!content.trim()||new TextEncoder().encode(content).length>262144)throw new Error('Вставьте профиль до 256 КиБ.');
  if(!Number.isSafeInteger(index)||index<1||index>512||!Number.isSafeInteger(port)||port<1024||port>65535)throw new Error('Проверьте номер узла и локальный порт.');
  if(!['preview','export'].includes(action)||(action==='export'&&!/^[a-f0-9]{64}$/.test(review)))throw new Error('Сначала получите актуальный предпросмотр.');
  return {content,options:{index:index-1,socks_port:port},action,review,confirm:'BUILD_MIHOMO_CONFIG'};
 },
 pack(content,signed,action='preview',review=''){
  if(typeof content!=='string'||!content.trim()||new TextEncoder().encode(content).length>262144)throw new Error('Вставьте JSON-пакет до 256 КиБ.');
  if(!['preview','import'].includes(action)||(action==='import'&&!/^[a-f0-9]{64}$/.test(review)))throw new Error('Повторите предпросмотр пакета.');
  return {content,signed:!!signed,action,review,confirm:action==='import'?'IMPORT_STRATEGY_CANDIDATES':''};
 },
 safeResult(reply){if(!reply||reply.live_applied!==false||reply.service_verified===true||reply.native_validated===true)throw new Error('Неизвестный результат сервера. Изменение сети не подтверждено.');return reply;}
};
if(typeof module==='object'&&module.exports)module.exports=apiModel;
root.RazvilkaExtensionLab=apiModel;
if(typeof document==='undefined')return;
const el=id=>document.getElementById(id),dialog=el('extensionLabDialog');if(!dialog)return;
let serial=0,controller=null,mReview='',pReview='';
const status=text=>{el('ext5Status').textContent=text;};
function buttons(){const busy=!!controller;dialog.querySelectorAll('button:not(#ext5Close):not(#ext5Cancel)').forEach(b=>b.disabled=busy);el('ext5MExport').disabled=busy||!mReview;el('ext5PImport').disabled=busy||!pReview;el('ext5Cancel').hidden=!busy;}
function cancel(){serial++;controller?.abort();controller=null;buttons();}
function invalidate(kind){cancel();if(kind==='mihomo'){mReview='';el('ext5MResult').textContent='Ввод изменён. Нужен новый предпросмотр.';}if(kind==='packs'){pReview='';el('ext5PResult').textContent='Пакет изменён. Нужен новый предпросмотр.';}buttons();}
function clear(){cancel();mReview=pReview='';for(const id of ['ext5MText','ext5MFile','ext5PText','ext5PFile'])el(id).value='';el('ext5PCandidates').replaceChildren();el('ext5MResult').textContent='Нет результата.';el('ext5PResult').textContent='Нет результата.';buttons();}
function pane(name){if(!['mihomo','hev','packs'].includes(name))return;cancel();for(const id of ['mihomo','hev','packs']){el('ext5Pane'+id[0].toUpperCase()+id.slice(1)).hidden=id!==name;dialog.querySelector(`[data-extension-pane="${id}"]`).setAttribute('aria-pressed',String(id===name));}status('Формирование файлов не включает новый обход.');}
async function run(path,body,accept){if(controller)return;const epoch=workflowState.epoch,seq=++serial,c=new AbortController();controller=c;buttons();status('Обрабатываем запрос на роутере…');try{const out=await workflowRequest(path,body===null?{controller:c}:{method:'POST',body:JSON.stringify(body),controller:c},30000);if(seq!==serial||!workflowSession(epoch)||!dialog.open)return;accept(out);}catch(error){if(seq===serial&&workflowSession(epoch)&&dialog.open)status(workflowError(error));}finally{if(seq===serial){controller=null;buttons();}}}
function download(text,name){const blob=new Blob([text],{type:'text/plain;charset=utf-8'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function guarded(fn){try{fn();}catch(error){status(error.message);}}
document.querySelectorAll('[data-extension-open]').forEach(b=>b.addEventListener('click',()=>{if(!dialog.open)dialog.showModal();pane(b.dataset.extensionOpen);}));
dialog.querySelectorAll('[data-extension-pane]').forEach(b=>b.addEventListener('click',()=>pane(b.dataset.extensionPane)));
el('ext5Close').addEventListener('click',()=>dialog.close());dialog.addEventListener('close',clear);dialog.addEventListener('cancel',cancel);
el('ext5Cancel').addEventListener('click',()=>{cancel();status('Запрос отменён. Если импорт уже сохранился, перечитайте кандидатов; автоматического повтора записи нет.');});
for(const id of ['ext5MText','ext5MIndex','ext5MPort'])el(id).addEventListener('input',()=>invalidate('mihomo'));
for(const id of ['ext5PText','ext5PSigned'])el(id).addEventListener('input',()=>invalidate('packs'));
for(const id of ['ext5HInterface','ext5HAddress','ext5HPort','ext5HMTU','ext5HSessions'])el(id).addEventListener('input',cancel);
function loadFile(id,target,kind){el(id).addEventListener('change',async()=>{invalidate(kind);const file=el(id).files?.[0],seq=serial,epoch=workflowState.epoch;if(!file)return;if(file.size>262144){status('Файл превышает 256 КиБ.');return;}try{const text=await file.text();if(seq===serial&&workflowSession(epoch)&&dialog.open){el(target).value=text;status('Файл прочитан локально. Выполните предпросмотр.');}}catch{if(seq===serial&&dialog.open)status('Не удалось прочитать файл.');}});}
loadFile('ext5MFile','ext5MText','mihomo');loadFile('ext5PFile','ext5PText','packs');
function mBody(action){return apiModel.mihomo(el('ext5MText').value,Number(el('ext5MIndex').value),Number(el('ext5MPort').value),action,mReview);}
el('ext5MPreview').addEventListener('click',()=>guarded(()=>{mReview='';run('/api/v1/extension-lab/mihomo',mBody('preview'),out=>{apiModel.safeResult(out);apiModel.safeResult(out.result);if(!/^[a-f0-9]{64}$/.test(out.review)||out.result.config)throw new Error('Предпросмотр не прошёл проверку.');mReview=out.review;el('ext5MResult').textContent=JSON.stringify(out.result,null,2);status('Профиль разобран. YAML содержит ключ; скачивание — отдельное действие. Запуск не выполнялся.');});}));
el('ext5MExport').addEventListener('click',()=>guarded(()=>run('/api/v1/extension-lab/mihomo',mBody('export'),out=>{apiModel.safeResult(out);apiModel.safeResult(out.result);if(out.review!==mReview||typeof out.result.config!=='string'||!out.result.config)throw new Error('Профиль изменился.');download(out.result.config,'razvilka-mihomo.yaml');status('YAML передан браузеру. Не публикуйте ключ. Нужны нативная проверка и испытание сервиса.');})));
el('ext5HBuild').addEventListener('click',()=>guarded(()=>run('/api/v1/extension-lab/hev',{options:{interface:el('ext5HInterface').value.trim(),address:el('ext5HAddress').value.trim(),socks_port:Number(el('ext5HPort').value),mtu:Number(el('ext5HMTU').value),max_sessions:Number(el('ext5HSessions').value)},confirm:'BUILD_HEV_CONFIG'},out=>{apiModel.safeResult(out);if(typeof out.config!=='string'||!out.config)throw new Error('Нет профиля.');download(out.config,'razvilka-hev.json');status(out.note);}))); 
el('ext5PBuiltin').addEventListener('click',()=>{invalidate('packs');run('/api/v1/strategy-lab/builtin-pack',null,out=>{apiModel.safeResult(out);el('ext5PText').value=out.content;el('ext5PSigned').checked=false;status('Встроенные TCP/QUIC-примеры загружены в форму. Проверьте состав перед импортом. Это не подтверждённые рабочие стратегии.');});});
function pBody(action){return apiModel.pack(el('ext5PText').value,el('ext5PSigned').checked,action,pReview);}
el('ext5PPreview').addEventListener('click',()=>guarded(()=>{pReview='';run('/api/v1/strategy-lab/packs',pBody('preview'),out=>{apiModel.safeResult(out);if(!/^[a-f0-9]{64}$/.test(out.sha256)||out.native_required!==true)throw new Error('Пакет не прошёл проверку.');pReview=out.sha256;el('ext5PResult').textContent=JSON.stringify(out,null,2);status('Состав прочитан. Импорт сохранит кандидатов, но не включит стратегии.');});}));
el('ext5PImport').addEventListener('click',()=>guarded(()=>run('/api/v1/strategy-lab/packs',pBody('import'),out=>{apiModel.safeResult(out);pReview='';status(`Добавлено: ${Number(out.added)||0}. Сохранено существующих: ${Number(out.preserved)||0}. Рабочая конфигурация не менялась.`);})));
el('ext5PList').addEventListener('click',()=>run('/api/v1/strategy-lab',null,out=>{const values=out.candidates;if(!Array.isArray(values))throw new Error('Нет списка кандидатов.');const box=el('ext5PCandidates');box.replaceChildren();for(const c of values){const label=document.createElement('label'),check=document.createElement('input'),text=document.createElement('span');check.type='checkbox';check.value=c.id;check.name='ext5-candidate';text.textContent=c.name+' · '+c.pool_id;label.append(check,text);box.append(label);}status(`Прочитано кандидатов: ${values.length}. Выберите до 64 для экспорта.`);}));
el('ext5PExport').addEventListener('click',()=>guarded(()=>{const ids=Array.from(dialog.querySelectorAll('[name="ext5-candidate"]:checked')).map(e=>e.value);if(!ids.length||ids.length>64)throw new Error('Выберите 1–64 кандидата.');run('/api/v1/strategy-lab/packs',{action:'export',candidate_ids:ids,confirm:'EXPORT_STRATEGIES'},out=>{apiModel.safeResult(out);download(out.content,'razvilka-strategies.json');status('Файл передан браузеру. Проверьте названия и SNI перед передачей другим людям. Публикация не выполнялась.');});}));
document.addEventListener('razvilka:auth-required',()=>{clear();if(dialog.open)dialog.close();status('Требуется вход.');});
buttons();
})(typeof globalThis!=='undefined'?globalThis:this);
