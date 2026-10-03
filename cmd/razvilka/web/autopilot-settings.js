/* Ordinary policy edits, not a second scheduler. No writes on page entry. */
(function (root) {
  'use strict';
  const fields = Object.freeze({check_seconds:'autoQuickCheck', reserve_seconds:'autoQuickReserve', reserve_target:'autoQuickTarget', candidates_per_round:'autoQuickCandidates'});
  function draft(policy, values) {
    if (!policy?.setup_complete || !Number.isSafeInteger(policy.revision)) throw new Error('Сначала завершите первоначальную настройку.');
    const next = JSON.parse(JSON.stringify(policy));
    for (const field of Object.keys(fields)) {
      const raw = values[field];
      if (typeof raw !== 'number' && (typeof raw !== 'string' || !/^\d+$/.test(raw.trim()))) throw new Error('Введите целые числа в допустимых пределах.');
      const n = Number(raw);
      if (!Number.isSafeInteger(n)) throw new Error('Введите целые числа в допустимых пределах.');
      next[field] = n;
    }
    if (next.check_seconds < 60 || next.check_seconds > 3600) throw new Error('Интервал проверки: от 60 до 3600 секунд.');
    if (next.reserve_seconds < next.check_seconds || next.reserve_seconds > 86400) throw new Error('Резерв проверяется не чаще сервисов и не реже одного раза в сутки.');
    if (next.reserve_target < 1 || next.reserve_target > 4 || next.candidates_per_round < 1 || next.candidates_per_round > 4) throw new Error('Количество подключений и кандидатов: от 1 до 4.');
    return next;
  }
  function current(snapshot, received, now = Date.now()) {
    const time = Date.parse(snapshot?.server_time || '');
    return !!snapshot?.policy && Number.isSafeInteger(snapshot.policy.revision) &&
      Number.isFinite(time) && Number.isFinite(received) && now >= received && now - received < 60000 &&
      snapshot.observation?.state !== 'retained' && !snapshot.blocked;
  }
  root.RazvilkaQuickPolicy = Object.freeze({fields, draft, current});
  if (typeof module !== 'undefined' && module.exports) module.exports = root.RazvilkaQuickPolicy;
  if (typeof document === 'undefined') return;
  const form = document.getElementById('autoQuickForm'); if (!form) return;
  const byID = id => document.getElementById(id);
  const message = byID('autoQuickMessage'), save = byID('autoQuickSave');
  let latest = null, base = null, received = 0, dirty = false, busy = false, epoch = 0, unknownWrite = false;
  function render() {
    const usable = current(latest,received) && !!latest?.policy?.setup_complete;
    for (const id of Object.values(fields)) byID(id).disabled=busy;
    save.disabled = busy || !usable || unknownWrite || !base || latest.policy.revision !== base.revision;
    byID('autoQuickReset').disabled = busy || !latest;
    byID('autoQuickRevision').textContent = latest?.policy ? `Редакция ${latest.policy.revision}${dirty?' · есть правки':''}` : 'Ожидаем состояние роутера';
    if (!latest?.policy?.setup_complete) message.textContent = 'Сначала выберите область, источники и разрешённые подключения. Потом обычные параметры можно менять здесь.';
    else if (base && latest.policy.revision !== base.revision && dirty) message.textContent = 'Настройки изменились в другой операции. Ваши поля сохранены. Нажмите «Отменить правки», чтобы загрузить новую редакцию.';
    else if (!usable) message.textContent = 'Нужно свежее состояние роутера. Поля не сброшены.';
  }
  function load() {
    if (!latest?.policy) return;
    base = JSON.parse(JSON.stringify(latest.policy));
    for (const [field,id] of Object.entries(fields)) byID(id).value = base[field];
    dirty = false; message.textContent = ''; render();
  }
  function accept(snapshot) {
    if (!snapshot?.policy || !Number.isSafeInteger(snapshot.policy.revision) || !Number.isFinite(Date.parse(snapshot.server_time))) return false;
    // Preserve pending drafts even across a process restart or stale poll.
    if (latest && Date.parse(snapshot.server_time) < Date.parse(latest.server_time)) return false;
    latest = snapshot; received = Date.now();
    if (!dirty && !busy) load(); else render();
    return true;
  }
  root.addEventListener('razvilka:autonomy-state', event => accept(event.detail));
  root.addEventListener('razvilka:autonomy-error', () => {received=0;render();});
  document.addEventListener('razvilka:auth-required', () => {epoch++;latest=base=null;received=0;dirty=false;busy=false;unknownWrite=false;for(const id of Object.values(fields))byID(id).value='';render();});
  form.addEventListener('input', () => {dirty=true;render();});
  byID('autoQuickReset').addEventListener('click', () => {if(!busy)load();});
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (busy) return; const token=epoch;
    try {
      if (!base || !current(latest,received) || base.revision!==latest.policy.revision || unknownWrite) throw new Error('Обновите состояние перед сохранением. Несохранённые поля оставлены.');
      const policy=draft(base,Object.fromEntries(Object.entries(fields).map(([field,id])=>[field,byID(id).value])));
      busy=true;render();message.textContent='Сохраняем параметры…';
      try {
        await interfaceRequest('/api/v1/autonomy',{method:'PUT',body:JSON.stringify({expected_revision:base.revision,policy,confirm:'SAVE_AUTONOMY',release_safe_mode:false})});
      } catch (error) {
        // No blind write replay if transport lost its response.
        if (token===epoch && (!error.status || error.status >= 500)) unknownWrite=true;
        throw error;
      }
      if (token!==epoch) return;
      // An independent live read after the completed write, not the passive cache.
      unknownWrite=true;
      const next=await interfaceRequest('/api/v1/autonomy');
      if(token!==epoch)return;
      if(!current(next,Date.now()) || !next.policy.setup_complete || next.policy.revision<=base.revision || !accept(next)) throw new Error('Сохранение принято, но новая редакция ещё не прочитана. Обновите состояние.');
      dirty=false;unknownWrite=false;load();
      document.dispatchEvent(new CustomEvent('razvilka:panel-refresh'));
      message.textContent='Параметры сохранены. Разрешения, устройства и текущие маршруты не изменялись.';
    } catch(error) {
      if(token===epoch)message.textContent=error.message||'Сохранение не подтверждено. Обновите состояние.';
    } finally {if(token===epoch){busy=false;render();}}
  });
  // The explicit existing refresh button reconciles unknown writes; never resubmit.
  byID('a1-reloadButton')?.addEventListener('click', async () => {
    const token=epoch;if(busy||!unknownWrite)return;
    busy=true;render();
    try{
      const next=await interfaceRequest('/api/v1/autonomy');if(token!==epoch)return;
      // Only an accepted live read can resolve an unknown write. A passive
      // publication or an invalid/older response must not admit another PUT.
      if(!current(next,Date.now()) || !next.policy.setup_complete || !accept(next)) throw new Error('Состояние ещё не подтверждено. Повторите обновление перед сохранением.');
      unknownWrite=false;
      message.textContent='Состояние прочитано. Сравните сохранённые параметры с вашими полями.';
    }catch(error){if(token===epoch)message.textContent=error.message||'Состояние не прочитано. Повторите обновление.';}
    finally{if(token===epoch){busy=false;render();}}
  });
  render();
})(typeof globalThis === 'undefined' ? window : globalThis);
