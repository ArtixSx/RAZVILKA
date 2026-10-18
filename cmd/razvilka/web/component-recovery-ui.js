/* Matching component recovery. GET is observation; every POST is explicitly
 * reviewed. A process/candidate/202 never supplies live acceptance. */
(function (root) {
  'use strict';
  const stages = {
    prepared: ['Подготовлено', 'Пакет ещё не устанавливался. Можно отменить подготовку.', ['abandon-prepared']],
    'upgrade-started': ['Исход установки неизвестен', 'Нет подтверждения завершения установки и её дочерних процессов. Нужно независимое восстановление; повтор команды запрещён.', []],
    'upgrade-finished': ['Пакет установлен; принятие не подтверждено', 'Рабочий процесс ещё не подтвердил новую версию. Прежняя версия сохранена.', ['rollback']],
    'awaiting-live-acceptance': ['Ожидает принятия рабочим процессом', 'Изолированная проверка кандидата завершена. Для принятия нужен настоящий рабочий путь; LKG сохраняется.', ['accept-live','rollback']],
    'rollback-config-before': ['Откат не завершён', 'Восстанавливается конфигурация. Итог ещё не подтверждён.', ['rollback']],
    'rollback-ready': ['Откат подготовлен', 'Установка прежнего пакета ещё не подтверждена.', ['rollback']],
    'rollback-started': ['Исход отката неизвестен', 'Установку пакета нельзя повторить. Нужны независимые доказательства завершения всех её процессов; обычная кнопка подтверждения их не заменяет.', []],
    'rollback-installed': ['Прежний пакет установлен', 'Конфигурация и принятие прежней версии ещё требуют проверки.', ['rollback']],
    'rollback-config-after': ['Конфигурация возвращается', 'Откат ещё не подтверждён рабочим процессом.', ['rollback']],
    'awaiting-rollback-acceptance': ['Откат ожидает проверки', 'Проверка наблюдает прежнюю версию и конфигурацию; пакетная команда повторно не запускается.', ['verify-rollback']],
    accepted: ['Обновление завершено по журналу', 'Принятие рабочим процессом отдельно от установки и наличия процесса.', []],
    'accepted-installed-idle': ['Неактивная версия принята по журналу', 'Версия и конфигурация приняты для неактивного компонента. Рабочий путь и доступ сервисов ещё не подтверждены.', []],
    'rolled-back': ['Откат записан в журнале', 'Прежняя версия возвращена. Доступ конкретного сервиса проверяется отдельно.', []],
    abandoned: ['Подготовка отменена', 'Установка пакета в этой транзакции не выполнялась.', []],
  };
  const supported = ['nfqws2','sing-box','xray','usque','warp-wg','wireguard'];
  const managedStages = {
    prepared: ['Установка управляемого пакета подготовлена', 'Файлы ещё требуют завершения установки.', ['resume','rollback']],
    'upgrade-started': ['Исход установки управляемого пакета уточняется', 'Продолжение и откат повторно проверяются сервером по этой транзакции.', ['resume','rollback']],
    'upgrade-finished': ['Управляемый пакет установлен; итог уточняется', 'Проверка файлов и неактивного состояния ещё не завершена.', ['resume','rollback']],
    'awaiting-live-acceptance': ['Неактивная установка ожидает проверки', 'Проверяется управляемый пакет без запуска рабочих маршрутов.', ['resume','rollback']],
    'accepted-installed-idle': ['Неактивная установка подтверждена журналом', 'Рабочие маршруты и доступ сервисов проверяются отдельно.', []],
    'rollback-started': ['Исход отката управляемого пакета уточняется', 'Продолжение и откат повторно проверяются сервером по этой транзакции.', ['resume','rollback']],
    'rolled-back': ['Установка управляемого пакета отменена', 'Состояние файлов возвращено по журналу. Доступ сервисов этим не подтверждается.', []],
    abandoned: ['Подготовка управляемого пакета отменена', 'Установка файлов в этой транзакции не выполнялась.', []],
  };
  const labels = {'resume':'Продолжить установку','accept-live':'Проверить принятие версии','accept-installed-idle':'Принять неактивную версию','rollback':'Вернуть прежнюю версию','verify-rollback':'Проверить результат отката','abandon-prepared':'Отменить подготовку'};
  const actionLabel = (action, managed) => managed && action==='rollback' ? 'Отменить установку пакета' : labels[action];
  function validCapabilities(c) {
    const list=value=>Array.isArray(value) && value.length<=16 && value.every(a=>typeof a==='string' && a.length<=64) && new Set(value).size===value.length;
    return list(c?.supported_actions) && list(c.available_actions) && c.available_actions.every(a=>c.supported_actions.includes(a))
      && ['quiescence_confirmed','inactivity_confirmed','installed_idle_accepted','live_proof_required'].every(key=>typeof c[key]==='boolean');
  }
  function valid(value) {
    if (typeof value?.recovery_required !== 'boolean' || !Number.isSafeInteger(value.revision) || value.revision < 0) return false;
    if(value.capabilities!=null && !validCapabilities(value.capabilities))return false;
    const t=value.transaction;
    if (!value.recovery_required && !t?.transaction_id) return true;
    const managed=t?.schema_version===3;
    if(managed && value.capabilities && (value.capabilities.live_proof_required!==false || value.capabilities.supported_actions.some(a=>!['resume','rollback'].includes(a))))return false;
    return [1,2,3].includes(t?.schema_version) && (t.phase!=='accepted-installed-idle' || t.schema_version!==1) && /^[a-f0-9]{32}$/.test(t.transaction_id) && (managed?t.component==='nfqws2':supported.includes(t.component))
      && Object.hasOwn(managed?managedStages:stages,t.phase) && typeof t.before_version==='string' && t.before_version.length>0 && t.before_version.length<=256
      && (managed?typeof t.after_version==='string' && t.after_version.length>0 && t.after_version.length<=256:t.after_version==null || typeof t.after_version==='string' && t.after_version.length<=256)
      && Number.isFinite(Date.parse(t.updated_at))
      && value.recovery_required===!['accepted','accepted-installed-idle','rolled-back','abandoned'].includes(t.phase);
  }
  function summary(value, receipt) {
    if (!valid(value)) return {label:'Журнал не прочитан',detail:'Изменения компонентов недоступны до свежего чтения.',actions:[],tone:'unknown'};
    const t=value.transaction;
    if (!t?.transaction_id) return {label:'Незавершённых обновлений нет',detail:'Установка, процесс и доступ сервиса проверяются отдельно.',actions:[],tone:'unknown'};
    const managed=t.schema_version===3;
    const [label,detail,knownActions]=(managed?managedStages:stages)[t.phase],c=value.capabilities;
    const eligible=[...knownActions];
    if(t.schema_version===2 && t.phase==='awaiting-live-acceptance' && c?.quiescence_confirmed===true && c.inactivity_confirmed===true)eligible.push('accept-installed-idle');
    const actions=value.recovery_required && c?eligible.filter(action=>c.available_actions.includes(action) && c.supported_actions.includes(action)):[];
    const live=!managed && t.phase==='accepted' && receipt?.transaction_id===t.transaction_id && receipt.component===t.component && receipt.live_accepted===true;
    return {label:live?'Рабочий процесс принял версию':label,detail:detail+(!c&&value.recovery_required?' Сервер не сообщил доступные действия; панель работает только для чтения.':''),actions,tone:live?'good':'unknown',transaction:t};
  }
  root.RazvilkaComponentRecovery=Object.freeze({valid,summary});
  if (typeof document==='undefined') return;
  const views=new Set(['engines','engineconfig','updates']);
  const recovery={epoch:0,read:null,action:null,data:null,received:0,error:'',unknownWrite:false,receipt:null,autoBlocked:false};
  const active=()=>state.authenticated && views.has(state.currentView) && !document.hidden;
  const fresh=()=>recovery.data && !recovery.error && recovery.received>0 && Date.now()-recovery.received<60000;
  const permissionFor=value=>state.status?.revision===value?.revision && (value?.transaction?.schema_version===3 || state.status?.safe_mode===false && state.serviceControl?.stopped!==true);
  function fence() {return !fresh() || recovery.data.recovery_required || recovery.unknownWrite || !!recovery.action;}
  function paint() {
    const model=summary(recovery.data,recovery.receipt),t=model.transaction;
    const busy=!!recovery.read || !!recovery.action;
    const permission=permissionFor(recovery.data);
    const unknownNote='Результат действия не подтверждён. Нажмите «Прочитать состояние». Повторная запись заблокирована.';
    const note=recovery.unknownWrite?[recovery.error,unknownNote].filter(Boolean).join(' '):recovery.error || (!fresh()?'Нужно свежее чтение журнала. Изменения компонентов приостановлены.':model.detail);
    const buttons=(fresh() && !recovery.unknownWrite?model.actions:[]).map(action=>`<button class="secondary" type="button" data-component-repair="${action}" data-component-recovery-focus="${action}" ${busy||!permission?'disabled':''}>${actionLabel(action,t?.schema_version===3)}</button>`).join('');
    for (const panel of document.querySelectorAll('[data-component-recovery-panel]')) {
      const focus=panel.contains(document.activeElement)?document.activeElement?.getAttribute('data-component-recovery-focus'):null;
      const permissionNote=t?.schema_version===3?'Прочитайте текущую ревизию настроек перед восстановлением.':'Восстановление требует текущей ревизии и разрешения после Stop. Панель эти запреты не снимает.';
      panel.innerHTML=`<div class="ui3-section-heading"><h3>${esc(model.label)}</h3><button class="secondary" type="button" data-component-recovery-read data-component-recovery-focus="read" ${busy?'disabled':''}>${recovery.read?'Читаем…':'Прочитать состояние'}</button></div><p role="status">${esc(note)}</p>${t?`<p>Компонент: <b>${esc(typeof routeLabel==='function'?routeLabel(t.component):t.component)}</b> · прежняя версия <b>${esc(t.before_version)}</b>${t.after_version?` · новая <b>${esc(t.after_version)}</b>`:''}</p><details><summary>Транзакция и этап</summary><p><code>${esc(t.transaction_id)}</code> · ${esc(t.phase)}</p></details>`:''}${buttons?`<div class="ui3-engine-actions">${buttons}</div>${!permission?`<p>${permissionNote}</p>`:''}`:''}`;
      if(focus)panel.querySelector(`[data-component-recovery-focus="${focus}"]`)?.focus({preventScroll:true});
    }
  }
  function render() {
    paint();
    if (typeof renderInterfaceEngines==='function' && views.has(state.currentView)) renderInterfaceEngines();
    if (typeof renderComponents==='function' && state.currentView==='engines') renderComponents();
  }
  function waitRead(ticket,pending,delay=0) {
    return new Promise((resolve,reject)=>{
      let timer=null,settled=false;
      const done=(error,value)=>{
        if(settled)return;settled=true;
        clearTimeout(timer);ticket.controller.signal.removeEventListener('abort',abort);
        if(error)reject(error);else resolve(value);
      };
      const abort=()=>done(new Error('Чтение журнала остановлено. Повторите чтение состояния.'));
      if(ticket.controller.signal.aborted){abort();return;}
      ticket.controller.signal.addEventListener('abort',abort,{once:true});
      if(pending)Promise.resolve(pending).then(value=>done(null,value),error=>done(error));
      else timer=setTimeout(()=>done(),delay);
    });
  }
  async function read(force=false) {
    if (!active()) return false;
    if (recovery.read) return recovery.read.promise;
    if (!force && recovery.autoBlocked) return false;
    if (!force && fresh()) return true;
    const ticket={epoch:recovery.epoch,controller:new AbortController(),promise:null,timedOut:false};
    recovery.read=ticket;
    const current=()=>ticket.epoch===recovery.epoch && recovery.read===ticket && active();
    const deadline=setTimeout(()=>{ticket.timedOut=true;ticket.controller.abort();},20000);
    ticket.promise=Promise.resolve().then(async()=>{
      try {
        for(let attempt=0;attempt<4;attempt++){
          // Navigation and panel-refresh can start this reader before the
          // metadata batch. Wait for its genuine single-flight completion;
          // never change the backend's exclusive recovery admission.
          let previous=null;
          while(current()){
            const pending=typeof panelLoad==='undefined'?null:panelLoad.request;
            if(!pending || pending===previous)break;
            previous=pending;await waitRead(ticket,pending);
          }
          if(!current())return false;
          if(ticket.controller.signal.aborted)throw new Error('Чтение журнала остановлено.');
          try{
            const data=await waitRead(ticket,api('/api/v1/components/recovery',{signal:ticket.controller.signal,readTimeoutMs:5000,cache:'no-store'}));
            if(!current())return false;
            if(!valid(data))throw new Error('Получен неполный журнал. Изменения компонентов остаются заблокированы.');
            recovery.data=data;recovery.received=Date.now();recovery.error='';recovery.unknownWrite=false;recovery.autoBlocked=false;
            if(recovery.receipt?.transaction_id!==data.transaction?.transaction_id)recovery.receipt=null;
            return true;
          }catch(error){
            if(!current())return false;
            const busy=error?.status===409 && error.payload?.code==='RESTORE_OPERATION_BUSY' && error.payload.not_started===true && error.payload.recovery_required===false;
            if(!busy)throw error;
            recovery.received=0;
            if(attempt===3)throw new Error('Журнал остаётся занят. Автоматическое чтение остановлено; повторите чтение состояния. Изменения компонентов заблокированы.');
            recovery.error='Журнал временно занят. Повторяем чтение после завершения других запросов; изменения компонентов заблокированы.';paint();
            await waitRead(ticket,null,[2000,3000,4000][attempt]);
          }
        }
      } catch(error) {
        if(!current())return false;
        recovery.received=0;recovery.autoBlocked=true;
        recovery.error=ticket.timedOut?'Журнал не прочитан за отведённое время. Автоматическое чтение остановлено; повторите чтение состояния. Изменения компонентов заблокированы.':error.message || 'Журнал не прочитан. Повторите чтение.';
        if(error.status===401)showAuth({...state.status,authenticated:false},error.message);
        return false;
      } finally {
        clearTimeout(deadline);
        if(recovery.read===ticket){recovery.read=null;render();}
      }
    });
    paint();return ticket.promise;
  }
  async function repair(action) {
    if (!active() || recovery.action || recovery.read) return;
    if(recovery.unknownWrite){render();return;}
    if(!fresh()){
      recovery.error='Сведения устарели. Читаем журнал перед новым действием; запись не отправляется.';render();
      const epoch=recovery.epoch;await read(true);
      if(epoch===recovery.epoch && fresh())showNotice('review','Журнал обновлён','Просмотрите текущее состояние и выберите действие заново. Запись не отправлялась.');
      return;
    }
    const observed=recovery.data,t=observed.transaction,model=summary(observed,recovery.receipt);
    if (!model.actions.includes(action) || !permissionFor(observed)) return;
    const ticket={epoch:recovery.epoch,transaction:t.transaction_id,sent:false,controller:new AbortController(),timedOut:false};recovery.action=ticket;render();
    let deadline=null;
    const current=()=>ticket.epoch===recovery.epoch && recovery.action===ticket && state.authenticated;
    try {
      const managed=t.schema_version===3;
      const detail=managed?'Сервер проверит текущую транзакцию и файлы управляемого пакета без запуска рабочих маршрутов.':action==='accept-installed-idle'?'Сервер проверит точную версию, конфигурацию, завершение всех процессов установки и неактивность компонента. Рабочий маршрут этим действием не запускается.':model.detail;
      const text=`${typeof routeLabel==='function'?routeLabel(t.component):t.component}: ${t.before_version}${t.after_version?' → '+t.after_version:''}. ${detail} Сервер повторно проверит транзакцию и разрешения. Доступ сервиса не считается подтверждённым по установке пакета.`;
      if(!await askConfirmation(actionLabel(action,managed),text,actionLabel(action,managed)) || !current())return;
      if(recovery.data!==observed || !fresh() || !permissionFor(observed))throw new Error('Журнал или разрешения изменились. Прочитайте состояние перед действием.');
      recovery.unknownWrite=true;
      ticket.sent=true;
      // The server allows six minutes. A lost response must release the UI
      // into uncertain read-only recovery, never replay the mutation.
      deadline=setTimeout(()=>{ticket.timedOut=true;ticket.controller.abort();},370000);
      const result=await waitRead(ticket,api('/api/v1/components/recovery',{method:'POST',signal:ticket.controller.signal,body:JSON.stringify({transaction_id:t.transaction_id,component:t.component,action,expected_revision:observed.revision,confirm:'REPAIR_COMPONENT_TRANSACTION'})}));
      clearTimeout(deadline);deadline=null;
      if(!current())return;
      const acknowledged=managed?result?.ok===true && typeof result.installed_idle==='boolean' && typeof result.compatibility_ready==='boolean' && result.working_routes_changed===false && (result.recovery_required===undefined || result.recovery_required===false):result?.recovery_required===false;
      if(!acknowledged)throw new Error('Сервер ещё не подтвердил завершение восстановления. Прочитайте состояние; запись не повторяется.');
      if(action==='accept-installed-idle' && (result.installed_idle_accepted!==true || result.live_accepted!==false))throw new Error('Принятие неактивной версии не подтверждено. Прочитайте состояние; запись не повторяется.');
      recovery.receipt={transaction_id:t.transaction_id,component:t.component,live_accepted:action==='accept-live' && result.live_accepted===true,installed_idle_accepted:action==='accept-installed-idle' && result.installed_idle_accepted===true};
      // The journal read, not the POST alone, determines whether the fence settled.
      await read(true);
      if(!current())return;
      if(!fresh() || recovery.data.transaction?.transaction_id!==t.transaction_id || recovery.data.recovery_required)throw new Error('Итог журнала ещё не подтверждён. Повторите чтение состояния.');
      if(managed && (recovery.data.transaction.schema_version!==3 || !['accepted-installed-idle','rolled-back','abandoned'].includes(recovery.data.transaction.phase)))throw new Error('Журнал ещё не подтвердил завершение операции с управляемым пакетом. Повторите чтение состояния.');
      if(action==='accept-installed-idle' && (recovery.data.transaction.phase!=='accepted-installed-idle' || recovery.data.capabilities?.installed_idle_accepted!==true))throw new Error('Журнал ещё не подтвердил принятие неактивной версии. Повторите чтение состояния.');
      if(managed && (typeof refreshManagedNFQBundle!=='function' || !await refreshManagedNFQBundle(recovery.data,result.receipt || null)))throw new Error('Журнал завершён, но независимое чтение управляемого пакета и квитанции ещё не подтверждено. Повторите чтение состояния.');
      if(!current())return;
      showNotice('review',summary(recovery.data,recovery.receipt).label,'Итог прочитан из журнала. Доступ каждого сервиса проверяется отдельно.');
    } catch(error) {
      if(!current())return;
      recovery.error=ticket.timedOut?'Ответ о восстановлении не получен за отведённое время. Исход неизвестен; прочитайте журнал. Повторная запись не отправлялась.':error.message;recovery.received=0;
      if(ticket.timedOut)recovery.autoBlocked=true;
      if(error.status===401)showAuth({...state.status,authenticated:false},error.message);
    } finally {clearTimeout(deadline);if(recovery.action===ticket){recovery.action=null;render();}}
  }
  root.componentRecoveryFence=fence;
  root.componentRecoverySummary=id=>{
    const model=summary(recovery.data,recovery.receipt);
    if(model.transaction?.component!==id)return null;
    return {...model,label:recovery.unknownWrite?'Результат восстановления неизвестен':!fresh()?'Состояние обновления уточняется':model.label,tone:!fresh()||recovery.unknownWrite?'unknown':model.tone};
  };
  root.renderComponentRecovery=paint;
  root.refreshComponentRecovery=()=>read(true);
  root.componentUpdatePending=()=>{recovery.received=0;recovery.receipt=null;void read(true);render();};
  document.addEventListener('click',event=>{
    if(event.target.closest?.('[data-component-recovery-read]'))void read(true);
    const button=event.target.closest?.('[data-component-repair]');if(button && !button.disabled)void repair(button.dataset.componentRepair);
  });
  document.addEventListener('razvilka:auth-required',()=>{recovery.epoch++;recovery.read?.controller.abort();recovery.action?.controller.abort();recovery.read=null;recovery.action=null;recovery.data=null;recovery.received=0;recovery.error='';recovery.unknownWrite=false;recovery.receipt=null;recovery.autoBlocked=false;paint();});
  document.addEventListener('razvilka:view-change',event=>{
    if(!views.has(event.detail) || recovery.action && event.detail!==state.currentView){
      const sent=recovery.action?.sent;recovery.epoch++;recovery.read?.controller.abort();recovery.action?.controller.abort();recovery.read=null;recovery.action=null;
      if(sent){recovery.unknownWrite=true;recovery.received=0;recovery.error='Результат действия ещё не прочитан. Можно обновить состояние без повторной записи.';}
    }
    if(views.has(event.detail)){
      if(event.detail!==state.currentView)recovery.autoBlocked=false;
      void Promise.resolve().then(()=>read());
    }
  });
  document.addEventListener('razvilka:panel-refresh',()=>{void read();});
  document.addEventListener('razvilka:auth-restored',()=>{recovery.autoBlocked=false;void read();});
  if(active())void read();
})(typeof globalThis==='undefined'?window:globalThis);
