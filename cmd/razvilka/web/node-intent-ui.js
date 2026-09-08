'use strict';

function nodeScopeText(sources) {
  if (!sources?.length) return 'Вся локальная сеть';
  return sources.map(source => {
    const device = (state.devices || []).find(item => (item.ips || []).some(ip => source === ip || source === `${ip}/${ip.includes(':') ? 128 : 32}`));
    return device ? `${device.name || device.hostname || source} (${source})` : source;
  }).join(', ');
}

function renderNodeIntentScope(reset = false) {
  const service = state.services.find(item => item.id === $('#nodeCheckService').value);
  const select = $('#nodeIntentScope');
  if (reset) {
    select.innerHTML = `<option value="">Выберите устройства…</option><option value="applied">Устройства действующего маршрута</option>${service?.sources_dirty ? '<option value="draft">Устройства из сохранённого черновика</option>' : ''}<option value="selected">Выбрать устройства</option><option value="all">Вся локальная сеть</option>`;
    select.value = service?.applied_enabled ? 'applied' : '';
    $('#nodeIntentSources').value = '';
    $('#nodeIntentDevices').innerHTML = (state.devices || []).filter(device => device.ips?.length).map(device => `<label><input type="checkbox" data-intent-device="${esc(device.id)}"><span>${esc(device.name || device.hostname || device.ips[0])}<small>${esc(device.ips.join(', '))}</small></span></label>`).join('') || '<p>Устройства ещё не обнаружены. Можно ввести адрес вручную.</p>';
  }
  const selected = select.value === 'selected';
  $('#nodeIntentDevices').hidden = !selected;
  $('#nodeIntentAdvanced').hidden = !selected;
  const scope = nodeIntentScopeValue();
  const sources = scope.mode === 'applied' ? service?.applied_sources : scope.mode === 'draft' ? service?.sources : scope.sources;
  if (state.nodeFlow) state.nodeFlow.intent = { revision: state.status?.revision, serviceID: service?.id, nodeID: $('#nodeCheckID').value, scope, sources: nodeIntentCanonicalSources(sources) };
  $('#nodeIntentScopeSummary').textContent = !scope.mode ? 'Укажите, кому будет назначен маршрут.' : selected && !sources?.length ? 'Отметьте хотя бы одно устройство или введите адрес.' : `Будет включено: ${nodeScopeText(sources)}.${scope.mode === 'applied' && service?.sources_dirty ? ' Изменения устройств из черновика останутся неприменёнными.' : ''}`;
  const fresh = typeof nodeServiceHealth === 'function' && nodeServiceHealth(nodeByID($('#nodeCheckID').value) || {}, service?.id).state === 'available';
  $('#nodeIntentApply').textContent = fresh ? 'Применить подключение' : 'Проверить и применить';
  $('#nodeIntentApply').disabled = !service || !scope.mode || selected && !sources?.length || state.status?.safe_mode === true;
  if (state.status?.safe_mode) $('#nodeIntentScopeSummary').textContent += ' Изменение маршрутов заблокировано в настройках; проверка доступна.';
  else if (state.serviceControl?.runtime_state === 'stopped') $('#nodeIntentScopeSummary').textContent += ' Маршруты остановлены. Применение включит этот сервис; остальные останутся остановлены.';
}

// Compare the displayed addresses with the server's normalized scope. Unusual
// textual normalization asks for a reviewed plan rather than broadening intent.
function nodeIntentCanonicalSources(sources) {
  return [...new Set((sources || []).map(value => { const source = value.trim().toLowerCase(); return source.includes('/') ? source : `${source}/${source.includes(':') ? 128 : 32}`; }))].sort();
}

function nodeIntentScopeValue() {
  const mode = $('#nodeIntentScope').value;
  if (mode !== 'selected') return { mode };
  const ids = $$('#nodeIntentDevices [data-intent-device]:checked').map(input => input.dataset.intentDevice);
  const addresses = (state.devices || []).filter(device => ids.includes(device.id)).flatMap(device => device.ips || []);
  return { mode, sources: [...new Set([...addresses, ...$('#nodeIntentSources').value.split(/[\n,]/)].map(value => value.trim()).filter(Boolean))] };
}

function setNodeIntentBusy(busy) {
  for (const id of ['nodeCheckService', 'nodeIntentScope', 'nodeIntentSources', 'nodeIntentApply', 'nodeCheckRun', 'nodeCheckPreview']) $(`#${id}`).disabled = busy;
  for (const input of $$('#nodeIntentDevices input')) input.disabled = busy;
}

async function runNodeIntent() {
  const flow = state.nodeFlow;
  const id = $('#nodeCheckID').value;
  const serviceID = $('#nodeCheckService').value;
  const intent = flow?.intent;
  const scope = intent?.scope || {};
  const revision = intent?.revision;
  if (!flow || flow.busy || flow.id !== id || !serviceID || !scope.mode || scope.mode === 'selected' && !scope.sources?.length) return;
  if (!Number.isSafeInteger(revision)) { $('#nodeCheckResult').textContent = 'Обновите страницу, чтобы получить текущие настройки.'; return; }
  if (revision !== state.status?.revision || intent.serviceID !== serviceID || intent.nodeID !== id) { renderNodeIntentScope(true); $('#nodeCheckResult').textContent = 'Настройки изменились. Сверьте устройства и повторите действие.'; return; }
  flow.busy = true;
  flow.controller = new AbortController();
  const controller = flow.controller;
  const current = () => state.nodeFlow === flow && !controller.signal.aborted && $('#nodeCheckID').value === id && $('#nodeCheckService').value === serviceID;
  setNodeIntentBusy(true);
  $('#nodeCheckPreview').hidden = true;
  $('#nodeCheckCancel').textContent = 'Отменить операцию';
  $('#nodeCheckResult').textContent = 'Проверяем доступ через выбранное подключение…';
  try {
    const node = nodeByID(id);
    if (nodeServiceHealth(node || {}, serviceID).state !== 'available') {
      const checked = await api(`/api/v1/nodes/${encodeURIComponent(id)}/check`, { method: 'POST', signal: controller.signal, body: JSON.stringify({ service_id: serviceID, confirm: 'CHECK_NODE' }) });
      if (!current()) return;
      if (!(checked.ok === true && checked.result?.available === true && checked.result.node_id === id && checked.result.service_id === serviceID)) throw new Error(checked.result?.message || 'Доступ не подтверждён. Маршрут не применён.');
    }
    $('#nodeCheckResult').textContent = 'Доступ подтверждён. Сверяем выбранные устройства и текущие настройки…';
    const preview = await api(`/api/v1/nodes/${encodeURIComponent(id)}/preview`, { method: 'POST', signal: controller.signal, body: JSON.stringify({ service_id: serviceID, scope, expected_revision: revision }) });
    if (!current()) return;
    const review = preview.review;
    if (review?.node_id !== id || review?.service_id !== serviceID || review?.revision !== revision) throw new Error('Настройки или выбор изменились. Обновите страницу и повторите.');
    if (preview.scope_selection !== scope.mode || !preview.effective_scope || JSON.stringify(nodeIntentCanonicalSources(preview.effective_scope.sources)) !== JSON.stringify(intent.sources)) throw new Error('Область устройств отличается от показанной. Просмотрите план перед применением.');
    if (!preview.ready || !review.review_token || !Number.isFinite(Date.parse(review.expires_at)) || Date.parse(review.expires_at) <= Date.now()) throw new Error((preview.transaction?.blockers || []).map(item => item.message).join(' · ') || 'Маршрут пока нельзя применить. Проверьте настройки и повторите.');
    $('#nodeCheckResult').textContent = `Применяем для: ${nodeScopeText(preview.effective_scope.sources)}. Проверяем маршрут; при ошибке вернём предыдущий.`;
    const applied = await api(`/api/v1/nodes/${encodeURIComponent(id)}/apply`, { method: 'POST', signal: controller.signal, body: JSON.stringify({ service_id: serviceID, review_token: review.review_token, reviewed_digest: review.reviewed_digest, revision: review.revision, generation: review.generation, confirm: 'APPLY_NODE_ROUTE' }) });
    if (!current()) return;
    $('#nodeCheckResult').textContent = applied.live_applied === true ? 'Подключение включено и прошло проверку веб-доступа. Теперь проверьте нужное приложение на выбранном устройстве.' : 'Применение не подтверждено. Обновите панель перед повтором.';
    await refreshAll();
  } catch (error) {
    if (current()) $('#nodeCheckResult').textContent = error.message;
  } finally {
    if (state.nodeFlow === flow) {
      flow.busy = false; flow.controller = null;
      setNodeIntentBusy(false);
      $('#nodeCheckCancel').textContent = 'Закрыть';
      $('#nodeIntentApply').disabled = true;
      $('#nodeIntentApply').textContent = 'Откройте подключение заново';
    }
  }
}

function bindNodeIntent() {
  $('#nodeIntentScope').addEventListener('change', () => renderNodeIntentScope());
  $('#nodeIntentDevices').addEventListener('change', () => renderNodeIntentScope());
  $('#nodeIntentSources').addEventListener('input', () => renderNodeIntentScope());
  $('#nodeIntentApply').addEventListener('click', runNodeIntent);
}
