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
    'rolled-back': ['Откат записан в журнале', 'Прежняя версия возвращена. Доступ конкретного сервиса проверяется отдельно.', []],
    abandoned: ['Подготовка отменена', 'Установка пакета в этой транзакции не выполнялась.', []],
  };
  const supported = ['nfqws2','sing-box','xray','usque','warp-wg','wireguard'];
  const labels = {'accept-live':'Проверить принятие версии','rollback':'Вернуть прежнюю версию','verify-rollback':'Проверить результат отката','abandon-prepared':'Отменить подготовку'};
  function valid(value) {
    if (typeof value?.recovery_required !== 'boolean' || !Number.isSafeInteger(value.revision) || value.revision < 0) return false;
    const t=value.transaction;
    if (!value.recovery_required && !t?.transaction_id) return true;
    return t?.schema_version===1 && /^[a-f0-9]{32}$/.test(t.transaction_id) && supported.includes(t.component)
      && Object.hasOwn(stages,t.phase) && typeof t.before_version==='string' && t.before_version.length>0 && t.before_version.length<=256
      && (t.after_version==null || typeof t.after_version==='string' && t.after_version.length<=256)
      && Number.isFinite(Date.parse(t.updated_at))
      && value.recovery_required===!['accepted','rolled-back','abandoned'].includes(t.phase);
  }
  function summary(value, receipt) {
    if (!valid(value)) return {label:'Журнал не прочитан',detail:'Изменения компонентов недоступны до свежего чтения.',actions:[],tone:'unknown'};
    const t=value.transaction;
    if (!t?.transaction_id) return {label:'Незавершённых обновлений нет',detail:'Установка, процесс и доступ сервиса проверяются отдельно.',actions:[],tone:'unknown'};
    const [label,detail,actions]=stages[t.phase];
    const live=t.phase==='accepted' && receipt?.transaction_id===t.transaction_id && receipt.component===t.component && receipt.live_accepted===true;
    return {label:live?'Рабочий процесс принял версию':label,detail,actions:value.recovery_required?actions:[],tone:live?'good':'unknown',transaction:t};
  }
  root.RazvilkaComponentRecovery=Object.freeze({valid,summary});
  if (typeof document==='undefined') return;
  const views=new Set(['engines','engineconfig','updates']);
  const recovery={epoch:0,read:null,action:null,data:null,received:0,error:'',unknownWrite:false,receipt:null};
  const active=()=>state.authenticated && views.has(state.currentView) && !document.hidden;
  const fresh=()=>recovery.data && !recovery.error && recovery.received>0 && Date.now()-recovery.received<60000;
  function fence() {return !fresh() || recovery.data.recovery_required || recovery.unknownWrite || !!recovery.action;}
  function paint() {
    const model=summary(recovery.data,recovery.receipt),t=model.transaction;
    const busy=!!recovery.read || !!recovery.action;
    const permission=state.status?.safe_mode===false && state.status.revision===recovery.data?.revision && state.serviceControl?.stopped!==true;
    const note=recovery.error || (recovery.unknownWrite?'Результат действия не подтверждён. Нажмите «Прочитать состояние». Повторная запись заблокирована.':!fresh()?'Нужно свежее чтение журнала. Изменения компонентов приостановлены.':model.detail);
    const buttons=(fresh() && !recovery.unknownWrite?model.actions:[]).map(action=>`<button class="secondary" type="button" data-component-repair="${action}" data-component-recovery-focus="${action}" ${busy||!permission?'disabled':''}>${labels[action]}</button>`).join('');
    for (const panel of document.querySelectorAll('[data-component-recovery-panel]')) {
      const focus=panel.contains(document.activeElement)?document.activeElement?.getAttribute('data-component-recovery-focus'):null;
      panel.innerHTML=`<div class="ui3-section-heading"><h3>${esc(model.label)}</h3><button class="secondary" type="button" data-component-recovery-read data-component-recovery-focus="read" ${busy?'disabled':''}>${recovery.read?'Читаем…':'Прочитать состояние'}</button></div><p role="status">${esc(note)}</p>${t?`<p>Компонент: <b>${esc(typeof routeLabel==='function'?routeLabel(t.component):t.component)}</b> · прежняя версия <b>${esc(t.before_version)}</b>${t.after_version?` · новая <b>${esc(t.after_version)}</b>`:''}</p><details><summary>Транзакция и этап</summary><p><code>${esc(t.transaction_id)}</code> · ${esc(t.phase)}</p></details>`:''}${buttons?`<div class="ui3-engine-actions">${buttons}</div>${!permission?'<p>Восстановление требует текущей ревизии, выключенного Safe Mode и разрешения после Stop. Панель эти запреты не снимает.</p>':''}`:''}`;
      if(focus)panel.querySelector(`[data-component-recovery-focus="${focus}"]`)?.focus({preventScroll:true});
    }
  }
  function render() {
    paint();
    if (typeof renderInterfaceEngines==='function' && views.has(state.currentView)) renderInterfaceEngines();
    if (typeof renderComponents==='function' && state.currentView==='engines') renderComponents();
  }
  async function read(force=false) {
    if (!active()) return false;
    if (recovery.read) return recovery.read.promise;
    if (!force && fresh()) return true;
    const ticket={epoch:recovery.epoch,controller:new AbortController(),promise:null};
    recovery.read=ticket;
    ticket.promise=Promise.resolve().then(async()=>{
      try {
        const data=await api('/api/v1/components/recovery',{signal:ticket.controller.signal,readTimeoutMs:5000});
        if(ticket.epoch!==recovery.epoch || recovery.read!==ticket || !active())return false;
        if(!valid(data))throw new Error('Получен неполный журнал. Изменения компонентов остаются заблокированы.');
        recovery.data=data;recovery.received=Date.now();recovery.error='';recovery.unknownWrite=false;
        if(recovery.receipt?.transaction_id!==data.transaction?.transaction_id)recovery.receipt=null;
        return true;
      } catch(error) {
        if(ticket.epoch!==recovery.epoch || recovery.read!==ticket)return false;
        recovery.received=0;recovery.error=error.message || 'Журнал не прочитан. Повторите чтение.';
        if(error.status===401)showAuth({...state.status,authenticated:false},error.message);
        return false;
      } finally {
        if(recovery.read===ticket){recovery.read=null;render();}
      }
    });
    paint();return ticket.promise;
  }
  async function repair(action) {
    if (!active() || recovery.action || recovery.read || !fresh() || recovery.unknownWrite) return;
    const observed=recovery.data,t=observed.transaction,model=summary(observed,recovery.receipt);
    if (!model.actions.includes(action) || state.status?.safe_mode!==false || state.status.revision!==observed.revision || state.serviceControl?.stopped===true) return;
    const ticket={epoch:recovery.epoch,transaction:t.transaction_id};recovery.action=ticket;render();
    const current=()=>ticket.epoch===recovery.epoch && recovery.action===ticket && state.authenticated;
    try {
      const text=`${typeof routeLabel==='function'?routeLabel(t.component):t.component}: ${t.before_version}${t.after_version?' → '+t.after_version:''}. ${model.detail} Сервер повторно проверит транзакцию и разрешения. Доступ сервиса не считается подтверждённым по установке пакета.`;
      if(!await askConfirmation(labels[action],text,labels[action]) || !current())return;
      if(recovery.data!==observed || !fresh() || state.status?.safe_mode!==false || state.status.revision!==observed.revision || state.serviceControl?.stopped===true)throw new Error('Журнал или разрешения изменились. Прочитайте состояние перед действием.');
      recovery.unknownWrite=true;
      const result=await api('/api/v1/components/recovery',{method:'POST',body:JSON.stringify({transaction_id:t.transaction_id,component:t.component,action,expected_revision:observed.revision,confirm:'REPAIR_COMPONENT_TRANSACTION'})});
      if(!current())return;
      if(result?.recovery_required!==false)throw new Error('Сервер ещё не подтвердил завершение восстановления. Прочитайте состояние; запись не повторяется.');
      recovery.receipt={transaction_id:t.transaction_id,component:t.component,live_accepted:action==='accept-live' && result.live_accepted===true};
      // The journal read, not the POST alone, determines whether the fence settled.
      await read(true);
      if(!current())return;
      if(!fresh() || recovery.data.transaction?.transaction_id!==t.transaction_id || recovery.data.recovery_required)throw new Error('Итог журнала ещё не подтверждён. Повторите чтение состояния.');
      showNotice('review',summary(recovery.data,recovery.receipt).label,'Итог прочитан из журнала. Доступ каждого сервиса проверяется отдельно.');
    } catch(error) {
      if(!current())return;
      recovery.error=error.message;recovery.received=0;
      if(error.status===401)showAuth({...state.status,authenticated:false},error.message);
    } finally {if(recovery.action===ticket){recovery.action=null;render();}}
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
  document.addEventListener('razvilka:auth-required',()=>{recovery.epoch++;recovery.read?.controller.abort();recovery.read=null;recovery.action=null;recovery.data=null;recovery.received=0;recovery.error='';recovery.unknownWrite=false;recovery.receipt=null;paint();});
  document.addEventListener('razvilka:view-change',event=>{
    if(!views.has(event.detail)){recovery.epoch++;recovery.read?.controller.abort();recovery.read=null;}
    else void Promise.resolve().then(()=>read());
  });
  document.addEventListener('razvilka:panel-refresh',()=>{void read();});
  document.addEventListener('razvilka:auth-restored',()=>{void read();});
  if(active())void read();
})(typeof globalThis==='undefined'?window:globalThis);
