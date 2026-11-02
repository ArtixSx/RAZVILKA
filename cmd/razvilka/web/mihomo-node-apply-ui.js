(function(root) {
  'use strict';
  const hex = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
  const nodeID = v => typeof v === 'string' && /^node-[a-f0-9]{64}$/.test(v);
  function selection(v) {
    if(v?.version !== 1) return false;
    return !!v && Number.isSafeInteger(v.revision) && v.revision >= 0 && typeof v.runtime_registered === 'boolean' && typeof v.live_apply_available === 'boolean' && (!v.live_apply_available || v.runtime_registered) && v.live_applied === false && v.service_verified === false && Array.isArray(v.services) && v.services.every(s => /^[a-z0-9][a-z0-9-]{0,63}$/.test(s?.id || '') && typeof s.name === 'string' && typeof s.enabled === 'boolean' && Array.isArray(s.applied_sources) && s.applied_sources.every(x => typeof x === 'string'));
  }
  function canApply(v, id, service, now = Date.now()) {
    if(v?.version !== 1) return false;
    const r = v?.review, p = v?.transaction, end = Date.parse(r?.expires_at);
    return !!v && v.ok === true && v.ready === true && v.engine === 'mihomo' && v.live_applied === false && v.service_verified === false && nodeID(id) && r?.engine === 'mihomo' && r.node_id === id && r.service_id === service && r.scope_selection === 'selected' && hex(r.review_token) && hex(r.reviewed_digest) && Number.isSafeInteger(r.revision) && r.revision >= 0 && Number.isSafeInteger(r.generation) && r.generation > 0 && Number.isFinite(end) && end > now && end - now <= 120000 && p?.ready === true && p.digest === r.reviewed_digest && p.revision === r.revision + 1 && p.network_profile_id === r.network_profile && typeof r.network_profile === 'string' && r.network_profile !== '';
  }
  root.RazvilkaMihomoNode = {selection, canApply};
  if (typeof document === 'undefined') return;
  let epoch = 0, dialog = null, review = null, busy = false;
  const auth = () => typeof state === 'object' ? state.authGeneration || 0 : 0;
  const invalidate = () => { epoch++; review = null; if (dialog) dialog.querySelector('[data-mh-apply]').disabled = true; };
  document.addEventListener('razvilka:auth-required', () => { invalidate(); dialog?.close(); });
  root.openMihomoNodeApply = async function(id) {
    if (!nodeID(id) || busy) return;
    if (dialog) { dialog.close(); dialog.remove(); }
    invalidate();
    dialog = document.createElement('dialog');
    dialog.setAttribute('aria-label', 'Маршрут через Mihomo');
    dialog.innerHTML = '<form><h2>Маршрут через Mihomo</h2><p>Один узел VLESS/TCP/TLS, один сервис с публичными IPv4-сетями и явно выбранные устройства. Проверки других движков не подтверждают этот маршрут.</p><label>Сервис <select data-mh-service></select></label><label>IPv4 устройств или частные сети <textarea data-mh-sources placeholder="192.168.1.42/32" required></textarea></label><p data-mh-status role="status">Читаем текущий каталог…</p><button type="button" data-mh-preview disabled>Просмотреть план</button><button type="button" data-mh-apply disabled>Применить просмотренный маршрут</button><button type="button" data-mh-close>Закрыть</button></form>';
    document.body.appendChild(dialog);
    const current = dialog, select = current.querySelector('[data-mh-service]'), sources = current.querySelector('[data-mh-sources]'), status = current.querySelector('[data-mh-status]'), preview = current.querySelector('[data-mh-preview]'), apply = current.querySelector('[data-mh-apply]');
    let inventory = null;
    select.disabled = true; sources.disabled = true;
    const valid = (ticket, generation) => ticket === epoch && dialog === current && current.open && auth() === generation;
    current.querySelector('form').addEventListener('submit', e => e.preventDefault());
    current.querySelector('[data-mh-close]').onclick = () => { if (!busy) current.close(); };
    current.addEventListener('cancel', e => { if (busy) e.preventDefault(); });
    current.addEventListener('close', invalidate);
    sources.oninput = () => { invalidate(); };
    select.onchange = () => { invalidate(); sources.value = (inventory?.services.find(s => s.id === select.value)?.applied_sources || []).join('\n'); };
    current.showModal();
    const ticket = epoch, generation = auth();
    try {
      const value = await api('/api/v1/mihomo/selection');
      if (!valid(ticket, generation)) return;
      if (!selection(value)) throw new Error('Не удалось подтвердить актуальный каталог и регистрацию runtime.');
      inventory = value;
      for (const item of value.services) { const option = document.createElement('option'); option.value = item.id; option.textContent = item.name + (item.enabled ? '' : ' — сначала включите сервис'); select.appendChild(option); }
      sources.value = (value.services[0]?.applied_sources || []).join('\n');
      select.disabled = false; sources.disabled = false;
      preview.disabled = !value.runtime_registered || !value.services.length;
      status.textContent = !value.runtime_registered ? 'Исходный runtime Mihomo не зарегистрирован.' : !value.live_apply_available ? 'Полный цикл применения ещё не разрешён. Можно просмотреть ограничения; проверка сервиса этим не выполняется.' : 'Выберите сервис и устройства, затем просмотрите план. Автоматической остановки действующего маршрута нет.';
    } catch (e) { if (valid(ticket,generation)) status.textContent = e.message || 'Каталог сейчас недоступен.'; }
    preview.onclick = async () => {
      if (busy || !inventory) return;
      invalidate(); const ticket = epoch, generation = auth(); busy = true; preview.disabled = true;
      status.textContent = 'Проверяем исходные данные и состав плана…';
      try {
        const value = await api(`/api/v1/mihomo/nodes/${encodeURIComponent(id)}/preview`, {method:'POST', body:JSON.stringify({service_id:select.value, sources:sources.value.split(/[\s,;]+/).filter(Boolean), expected_revision:inventory.revision})});
        if (!valid(ticket,generation)) return;
        review = value;
        apply.disabled = !canApply(value,id,select.value);
        const effective = value.effective_scope?.sources;
        status.textContent = `${apply.disabled ? 'Применение недоступно. Откройте актуальные настройки и проверьте ограничения runtime.' : 'План готов к явному подтверждению. Все обязательные проверки будут выполнены заново.'}${Array.isArray(effective) ? ' Устройства: '+effective.join(', ')+'.' : ''}`;
      } catch(e) { if(valid(ticket,generation)) status.textContent=e.message || 'Не удалось просмотреть план.'; }
      finally { busy=false; if(dialog===current && current.open && auth()===generation) preview.disabled=false; }
    };
    apply.onclick = async () => {
      if (busy || !canApply(review,id,select.value)) { invalidate(); return; }
      const snapshot=review, ticket=epoch, generation=auth(); review=null; busy=true; apply.disabled=true; preview.disabled=true; select.disabled=true; sources.disabled=true;
      status.textContent='Применяем и проверяем сервис через Mihomo и TUN. Закрытие окна не подтверждает завершение.';
      try {
        const r=snapshot.review;
        const value=await api(`/api/v1/mihomo/nodes/${encodeURIComponent(id)}/apply`,{method:'POST',body:JSON.stringify({engine:'mihomo',service_id:r.service_id,review_token:r.review_token,reviewed_digest:r.reviewed_digest,revision:r.revision,generation:r.generation,confirm:'APPLY_MIHOMO_NODE_ROUTE'})});
        if(!valid(ticket,generation))return;
        status.textContent=value?.version===1 && value.ok===true && value.live_applied===true ? 'Маршрут применён после обязательных проверок. Обновите состояние панели перед следующим действием.' : 'Подтверждение рабочего маршрута не получено. Обновите состояние панели.';
      } catch(e) { if(valid(ticket,generation))status.textContent=(e.message||'Результат не получен.')+' Обновите состояние панели; повторного автоматического применения не будет.'; }
      finally { busy=false; if(valid(ticket,generation)){select.disabled=false;sources.disabled=false;} }
    };
  };
})(globalThis);
