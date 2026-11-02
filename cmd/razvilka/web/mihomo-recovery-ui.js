(function(root){
 'use strict';
 const path='/api/v1/components/mihomo/recovery';
 function valid(v){return !!v&&typeof v.recovery_required==='boolean'&&typeof v.repair_available==='boolean'&&v.live_applied===false&&Number.isSafeInteger(v.revision)&&v.revision>=0&&typeof v.review?.pending==='boolean'&&v.review.pending===v.recovery_required&&(v.review.identity===''||/^[a-f0-9]{64}$/.test(v.review.identity))&&v.repair_available===(v.review.pending&&v.review.identity!=='');}
 root.RazvilkaMihomoRecovery={valid};
 if(typeof document==='undefined')return;
 const read=document.getElementById('mihomoRecoveryRead'),repair=document.getElementById('mihomoRecoveryRepair'),status=document.getElementById('mihomoRecoveryStatus');
 if(!read||!repair||!status)return;
 let epoch=0,busy=false,review=null,received=0;
 function render(){read.disabled=busy;repair.disabled=busy||!review?.repair_available;}
 async function run(write){
  if(busy||write&&(!review?.repair_available||Date.now()-received>60000)){if(write){review=null;status.textContent='Прочитайте журнал заново перед восстановлением.';render();}return;}
  const ticket=epoch,snapshot=review;busy=true;render();
  status.textContent=write?'Проверяем и восстанавливаем показанную установку…':'Читаем журнал установки…';
  try{
   const value=await interfaceRequest(path,write?{method:'POST',body:JSON.stringify({expected_identity:snapshot.review.identity,expected_revision:snapshot.revision})}:{});
   if(ticket!==epoch)return;
   if(write){review=null;received=0;status.textContent='Запрос завершён. Прочитайте журнал повторно. Запуск и маршрутизация проверяются отдельно.';}
   else{if(!valid(value))throw new Error('Не удалось подтвердить состояние журнала.');review=value;received=Date.now();status.textContent=value.recovery_required?'Найдена незавершённая установка. Можно восстановить показанную транзакцию.':'Незавершённой установки Mihomo нет. Доступ сервисов проверяется отдельно.';}
  }catch(e){if(ticket!==epoch)return;review=null;received=0;status.textContent=(e.message||'Ответ не получен.')+' Прочитайте журнал перед новым действием.';}
  finally{if(ticket===epoch){busy=false;render();}}
 }
 read.addEventListener('click',()=>run(false));repair.addEventListener('click',()=>run(true));
 document.addEventListener('razvilka:auth-required',()=>{epoch++;busy=false;review=null;received=0;status.textContent='Войдите и прочитайте журнал.';render();});
 render();
})(globalThis);
