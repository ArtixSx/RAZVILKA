'use strict';

const nodeServiceView = { open: new Set(), added: new Set(), initialized: false };

function nodeServiceCandidates(service) {
  const nodes = state.nodes?.nodes || [];
  const preferred = new Set([service.route, service.applied_route].filter(Boolean).map(route => route.replace(/^sing-box:/, '')));
  const groupMembers = new Set((state.nodes?.groups || []).filter(group => preferred.has(group.id)).flatMap(group => group.node_ids || []));
  return nodes.filter(node => nodeCanCheck(node) || preferred.has(node.id)).sort((a, b) => {
    const rank = node => preferred.has(node.id) ? 0 : nodeServiceHealth(node, service.id).state === 'available' ? 1 : groupMembers.has(node.id) ? 2 : 3;
    return rank(a) - rank(b) || nodeDisplayName(a).localeCompare(nodeDisplayName(b), 'ru') || a.id.localeCompare(b.id);
  }).slice(0, 8);
}

function renderNodeServiceCard(node, service) {
  const country = nodeCountry(node), health = nodeServiceHealth(node, service.id);
  const route = `sing-box:${node.id}`;
  const selected = service.enabled && service.route === route;
  const applied = service.applied_enabled && service.applied_route === route;
  return `<button class="node-service-card ${applied ? 'applied' : selected ? 'selected' : ''}" type="button" data-service-node="${esc(node.id)}" data-service-id="${esc(service.id)}" ${nodeCanCheck(node) ? '' : 'disabled'}><b><span title="Страна по данным источника">${esc(country.flag)}</span> ${esc(nodeDisplayName(node))}</b><span>${esc(String(node.protocol || '').toUpperCase())} · ${esc(nodeTransportLabel(node))}</span><small class="${health.kind}">${esc(health.label)}${selected ? ' · Выбран' : ''}${applied ? ' · Применён' : ''}</small></button>`;
}

function renderNodeServices() {
  const panel = $('#nodeServiceSelectors');
  if (!panel || panel.hidden) return;
  const active = document.activeElement;
  const focusService = active?.dataset?.serviceId, focusNode = active?.dataset?.serviceNode;
  const openBefore = $$('#nodeServiceSelectors details[data-node-service]').filter(details => details.open).map(details => details.dataset.nodeService);
  if (nodeServiceView.initialized) nodeServiceView.open = new Set(openBefore);
  const services = state.services.filter(service => service.probe_url || (service.probes || []).some(probe => probe.required && probe.url));
  const featured = new Set(['telegram', 'youtube', 'discord', 'chatgpt', 'twitch']);
  const shown = services.filter(service => service.enabled || service.applied_enabled || featured.has(service.id) || nodeServiceView.added.has(service.id));
  if (!nodeServiceView.initialized && shown.length) { nodeServiceView.open.add(shown.find(service => service.applied_enabled)?.id || shown.find(service => service.enabled)?.id || shown[0].id); nodeServiceView.initialized = true; }
  const remaining = services.filter(service => !shown.includes(service));
  panel.innerHTML = `<div class="node-services-heading"><div><h3>Подключения по сервисам</h3><p>Выберите подключение в карточке сервиса. Перед включением можно указать устройства.</p></div>${remaining.length ? `<label><span>Добавить сервис в обзор</span><select id="nodeServiceAdd"><option value="">Выберите сервис…</option>${remaining.map(service => `<option value="${esc(service.id)}">${esc(service.name)}</option>`).join('')}</select></label>` : ''}</div>` + shown.map(service => {
    const candidates = nodeServiceCandidates(service);
    const currentGroup = (state.nodes?.groups || []).find(group => `sing-box:${group.id}` === service.applied_route);
    const fallback = (state.nodeAutofallback?.services || []).find(item => item.service_id === service.id && item.group_id === currentGroup?.id);
    const groups = (state.nodes?.groups || []).filter(group => (state.routeOptions || []).some(option => option.id === `sing-box:${group.id}` && option.selectable && option.services?.includes(service.id)));
    const policyAction = `<button type="button" class="secondary" data-service-policy="${esc(service.id)}">Автоподбор</button>`;
    return `<details class="node-service-section" data-node-service="${esc(service.id)}" ${nodeServiceView.open.has(service.id) ? 'open' : ''}><summary><span class="node-service-icon">${esc(service.icon || '◇')}</span><span><b>${esc(service.name)}</b><small>${service.applied_enabled ? `Применено: ${esc(routeLabel(service.applied_route))}` : 'Подключение ещё не включено'}</small></span><span class="node-service-chevron">⌄</span></summary><div class="node-service-body"><div class="node-service-state"><span><small>Выбрано</small><b>${service.enabled ? esc(routeLabel(service.route)) : 'Не выбрано'}</b></span><span><small>Устройства действующего маршрута</small><b>${service.applied_enabled ? esc(nodeScopeText(service.applied_sources)) : 'Укажите перед включением'}</b></span></div>${service.dirty ? '<p class="node-service-pending">Изменения ожидают применения.</p>' : ''}${fallback ? `<p class="node-service-note">${esc(fallback.message)}</p>` : ''}<div class="node-service-check-title"><b>${esc(nodeServiceScenario(service))}</b><span>Проверка веб-страницы; приложения, звонки и видео проверяются отдельно.</span></div><div class="node-service-grid">${candidates.map(node => renderNodeServiceCard(node, service)).join('')}</div>${!candidates.length ? '<p class="node-service-note">Добавьте свои подключения или подписку, затем проверьте их для этого сервиса.</p>' : ''}<div class="node-service-tools">${policyAction}<button type="button" class="secondary" data-service-catalog="${esc(service.id)}">Открыть весь каталог</button><button type="button" class="secondary" data-service-devices="${esc(service.id)}">Устройства</button>${groups.length ? `<label><span>Проверенная резервная группа</span><select data-service-group="${esc(service.id)}"><option value="">Выбрать группу…</option>${groups.map(group => `<option value="${esc(group.id)}">${esc(group.name)}</option>`).join('')}</select></label>` : ''}</div></div></details>`;
  }).join('') || '<p>Добавьте сервис с веб-проверкой в разделе «Сервисы».</p>';
  if (focusService && focusNode) $$('#nodeServiceSelectors [data-service-node]').find(button => button.dataset.serviceId === focusService && button.dataset.serviceNode === focusNode)?.focus({ preventScroll: true });
}

function bindNodeServices() {
  $('#nodeServiceSelectors').addEventListener('click', event => {
    const node = event.target.closest('[data-service-node]');
    const catalog = event.target.closest('[data-service-catalog]');
    const devices = event.target.closest('[data-service-devices]');
    const policy = event.target.closest('[data-service-policy]');
    if (node) openNodeCheck(node.dataset.serviceNode, node.dataset.serviceId);
    else if (catalog) { setNodeBrowserTab('all'); $('#nodeBrowserService').value = catalog.dataset.serviceCatalog; nodeBrowser.selected.clear(); $('#nodeSearch').value = ''; $('#nodeStateFilter').value = ''; renderNodes(); }
    else if (devices) openServiceScope(devices.dataset.serviceDevices);
    else if (policy) openNodePolicy(policy.dataset.servicePolicy);
  });
  $('#nodeServiceSelectors').addEventListener('change', event => {
    if (event.target.id === 'nodeServiceAdd' && event.target.value) { const id = event.target.value; nodeServiceView.added.add(id); nodeServiceView.open.add(id); nodeServiceView.initialized = false; renderNodeServices(); }
    else if (event.target.matches('[data-service-group]') && event.target.value) { openNodeGroupUse(event.target.value, event.target.dataset.serviceGroup); event.target.value = ''; }
  });
  document.addEventListener('razvilka:auth-required', () => { nodeServiceView.open.clear(); nodeServiceView.added.clear(); nodeServiceView.initialized = false; $('#nodeServiceSelectors').innerHTML = ''; });
}
