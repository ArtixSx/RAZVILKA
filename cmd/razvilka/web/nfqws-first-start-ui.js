/* Closed recipe intent only. Reading/selecting never starts a live operation. */
(function(root) {
  'use strict';
  const ids=['','stock-tls-circular-v1'];
  function validSnapshot(value) {
    return value && Number.isSafeInteger(value.revision) && value.revision>=0 && ids.includes(value.recipe) && ids.includes(value.applied_recipe) &&
      Array.isArray(value.recipes) && value.recipes.length===ids.length && value.recipes.every((entry,index)=>entry.id===ids[index]&&typeof entry.name==='string');
  }
  root.RazvilkaNFQWSFirstStartUI={validSnapshot};
  if(typeof document==='undefined')return;
  const $=id=>document.getElementById(id),read=$('nfqFirstRecipeRead'),select=$('nfqFirstRecipeSelect'),save=$('nfqFirstRecipeSave'),status=$('nfqFirstRecipeStatus');
  if(!read||!select||!save||!status)return;
  let snapshot=null,busy=false,epoch=0,sequence=0;
  function message(text,error=false){status.textContent=text;status.setAttribute('role',error?'alert':'status');}
  function render(){read.disabled=busy;select.disabled=busy||!snapshot;save.disabled=busy||!snapshot||select.value===snapshot.recipe;}
  function accept(value){
    if(!validSnapshot(value))throw new Error('Рецепт ещё не подтверждён. Прочитайте настройки повторно.');
    snapshot=value;select.replaceChildren();
    for(const entry of value.recipes){const option=document.createElement('option');option.value=entry.id;option.textContent=entry.name;select.appendChild(option);}
    select.value=value.recipe;
    const current=value.recipes.find(entry=>entry.id===value.applied_recipe).name;
    message(value.recipe!==value.applied_recipe?`Выбор сохранён в черновике. Последний применённый рецепт: ${current}. Проверьте план и примените изменения на странице «Сервисы».`:`Сохранённый рецепт: ${current}. Его выбор сам по себе не подтверждает доступность сервисов.`);
  }
  async function request(mutation){
    if(busy||mutation&&(!snapshot||save.disabled))return;
    const generation=epoch,ticket=++sequence;
    const options=mutation?{method:'PUT',body:JSON.stringify({recipe:select.value,expected_revision:snapshot.revision})}:{};
    busy=true;render();message(mutation?'Сохраняем выбор в черновике…':'Читаем сохранённый выбор…');
    try{
      const value=await interfaceRequest('/api/v1/nfqws2/first-start-recipe',options);
      if(generation!==epoch)return;
      accept(value);
      if(mutation){
        // Core readback invalidates snapshots admitted before this CAS and
        // refreshes the shared pending-changes banner. It performs no Apply.
        if(typeof root.refreshAfterMutation==='function')void root.refreshAfterMutation().catch(()=>{if(generation===epoch&&ticket===sequence)message('Выбор сохранён в черновике. Сводку панели обновить не удалось; обновите состояние перед Apply.',true);});
        else document.dispatchEvent(new CustomEvent('razvilka:panel-refresh'));
      }
    }catch(error){
      if(generation!==epoch||error.name==='AuthGenerationChanged')return;
      // Re-read after any refusal or lost reply, never replay a draft write.
      snapshot=null;
      const human=root.RazvilkaAutonomyModel?.requestErrorText(error,mutation)||error.message;
      message((human||'Ответ панели не получен.')+' Прочитайте настройки перед повторным сохранением.',true);
    }finally{if(generation===epoch){busy=false;render();}}
  }
  read.addEventListener('click',()=>request(false));save.addEventListener('click',()=>request(true));
  select.addEventListener('change',event=>{event.stopPropagation();render();});
  document.addEventListener('razvilka:auth-required',()=>{epoch++;busy=false;snapshot=null;select.replaceChildren();message('Для выбора сначала прочитайте сохранённые настройки.');render();});
  render();
})(globalThis);
