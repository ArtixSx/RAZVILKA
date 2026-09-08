'use strict';

let nodePolicyEditor = null;

async function openNodePolicy(serviceID) {
  closeNodePolicy();
  const editor = { serviceID, controller: new AbortController(), data: null, busy: true };
  nodePolicyEditor = editor;
  $('#nodePolicyTitle').textContent = `${state.services.find(service => service.id === serviceID)?.name || serviceID}: автоподбор`;
  $('#nodePolicyStatus').textContent = 'Получаем действующее правило…';
  $('#nodePolicySave').disabled = true;
  $('#nodePolicyFields').hidden = true;
  $('#nodePolicyDialog').showModal();
  for (const field of $$('#nodePolicyFields input, #nodePolicyFields select')) field.disabled = false;
  try {
    const [data, inventory, services] = await Promise.all([api('/api/v1/service-policies', { signal: editor.controller.signal }), api('/api/v1/nodes', { signal: editor.controller.signal }), api('/api/v1/services', { signal: editor.controller.signal })]);
    if (nodePolicyEditor !== editor || editor.controller.signal.aborted) return;
    const view = data.policies?.[serviceID];
    if (!view) throw new Error('Для сервиса пока нет правила автоподбора.');
    editor.data = data; editor.view = view; editor.inventory = inventory;
    const service = services.find(service => service.id === serviceID);
    const group = inventory.groups?.find(group => service?.applied_enabled && `sing-box:${group.id}` === service.applied_route && group.mode === 'fallback');
    const policy = { ...view.policy, group_id: group?.id || '', device_sources: service?.applied_sources || [] };
    editor.basePolicy = policy;
    editor.group = group;
    $('#nodePolicyFields').hidden = false;
    $('#nodePolicyMode').value = policy.mode === 'manual' ? 'manual' : !policy.enabled || policy.mode === 'paused' ? 'paused' : policy.mode;
    $('#nodePolicyGroup').textContent = group ? `${group.name} · ${nodeScopeText(policy.device_sources)}` : 'Сначала создайте резервную группу и примените её к сервису.';
    $('#nodePolicyInterval').value = String(policy.check_interval_seconds / 60);
    $('#nodePolicyHold').value = String(policy.hold_down_seconds / 60);
    $('#nodePolicyBudget').value = String(policy.max_switches_per_hour);
    const members = inventory.nodes?.filter(node => group?.node_ids?.includes(node.id)) || [];
    $('#nodePolicyMembers').innerHTML = members.map(node => {
      const origins = [...new Set((node.origins || []).map(origin => (inventory.sources || []).find(source => source.id === origin.source_id)?.kind).filter(Boolean))];
      const publicNode = origins.some(kind => ['subscription', 'community'].includes(kind));
      const sourceNames = [...new Set((node.origins || []).map(origin => nodeBrowserSourceName(origin.source_id)))].join(', ');
      return `<label><input type="checkbox" data-policy-node="${esc(node.id)}" ${policy.allowed_node_ids?.includes(node.id) ? 'checked' : ''}><span>${esc(nodeDisplayName(node))}<small>${publicNode ? 'Публичный источник / подписка' : 'Моё сохранённое подключение'} · ${esc(sourceNames)}</small></span></label>`;
    }).join('') || '<p>В применённой группе пока нет подключений.</p>';
    $('#nodePolicyStatus').textContent = view.reason;
    $('#nodePolicySave').disabled = false;
    updateNodePolicyMode();
  } catch (error) { if (nodePolicyEditor === editor && !editor.controller.signal.aborted) $('#nodePolicyStatus').textContent = error.message; }
  finally { if (nodePolicyEditor === editor) editor.busy = false; }
}

function updateNodePolicyMode() {
  const auto = $('#nodePolicyMode').value === 'auto';
  $('#nodePolicySave').textContent = auto ? 'Включить автоподбор' : 'Применить правило';
  $('#nodePolicySave').disabled = !nodePolicyEditor?.data || auto && !nodePolicyEditor.group;
}

async function saveNodePolicy(event) {
  event.preventDefault();
  const editor = nodePolicyEditor;
  if (!editor?.data || editor.busy) return;
  const mode = $('#nodePolicyMode').value;
  const policy = { ...editor.basePolicy, mode, enabled: mode === 'auto', check_interval_seconds: Number($('#nodePolicyInterval').value) * 60, hold_down_seconds: Number($('#nodePolicyHold').value) * 60, max_switches_per_hour: Number($('#nodePolicyBudget').value) };
  if (mode === 'auto') {
    const ids = $$('#nodePolicyMembers [data-policy-node]:checked').map(input => input.dataset.policyNode);
    if (!editor.group || !ids.length) { $('#nodePolicyStatus').textContent = 'Отметьте хотя бы одно разрешённое подключение.'; return; }
    const members = editor.inventory.nodes.filter(node => ids.includes(node.id));
    const sources = new Set(members.flatMap(node => (node.origins || []).map(origin => origin.source_id)));
    policy.allowed_node_ids = ids;
    policy.allowed_source_ids = [...sources];
    policy.trust_classes = [...new Set(editor.inventory.sources.filter(source => sources.has(source.id)).map(source => source.kind))];
    policy.allowed_engines = ['sing-box'];
    policy.scenario = { kind: 'web', require_udp: false, require_ipv6: false };
    policy.terminal_action = 'retain';
    policy.allow_credential_generation = false;
    if (policy.pinned_node_id && !ids.includes(policy.pinned_node_id)) { $('#nodePolicyStatus').textContent = 'Закреплённое подключение исключено. Сначала измените ручной выбор.'; return; }
  }
  editor.busy = true;
  for (const field of $$('#nodePolicyFields input, #nodePolicyFields select')) field.disabled = true;
  $('#nodePolicySave').disabled = true;
  $('#nodePolicyStatus').textContent = 'Применяем правило автоподбора…';
  try {
    const result = await api(`/api/v1/service-policies/${encodeURIComponent(editor.serviceID)}`, { method: 'PUT', signal: editor.controller.signal, body: JSON.stringify({ config_revision: editor.data.config_revision, expected_revision: editor.view.policy.revision, policy, confirm: 'SAVE_SERVICE_POLICY' }) });
    if (nodePolicyEditor !== editor || editor.controller.signal.aborted) return;
    $('#nodePolicyStatus').textContent = result.reason;
    editor.data = null;
    await refreshAll();
  } catch (error) { if (nodePolicyEditor === editor && !editor.controller.signal.aborted) { $('#nodePolicyStatus').textContent = `${error.message} Закройте правило и откройте заново.`; editor.data = null; } }
  finally { if (nodePolicyEditor === editor) { editor.busy = false; $('#nodePolicySave').disabled = true; $('#nodePolicySave').textContent = 'Откройте правило заново'; } }
}

function closeNodePolicy() {
  nodePolicyEditor?.controller.abort(); nodePolicyEditor = null;
  $('#nodePolicyDialog').close(); $('#nodePolicyMembers').innerHTML = ''; $('#nodePolicyStatus').textContent = '';
}

function bindNodePolicy() {
  $('#nodePolicyForm').addEventListener('submit', saveNodePolicy);
  $('#nodePolicyClose').addEventListener('click', closeNodePolicy);
  $('#nodePolicyMode').addEventListener('change', updateNodePolicyMode);
  $('#nodePolicyDialog').addEventListener('cancel', event => { event.preventDefault(); closeNodePolicy(); });
  document.addEventListener('razvilka:auth-required', closeNodePolicy);
}
