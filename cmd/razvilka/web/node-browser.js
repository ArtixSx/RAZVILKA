'use strict';

// BEGIN NODE MEASUREMENT MODEL — diagnostic only, no route authority.
const nodeMeasurementModel = (() => {
  const date = value => { const n = typeof value === 'string' ? Date.parse(value) : NaN; return Number.isFinite(n) ? n : null; };
  const number = value => Number.isSafeInteger(value) && value >= 0 && value <= 600000 ? value : null;
  function freshRecord(record, now) {
    const at = date(record?.checked_at), end = date(record?.expires_at);
    return at !== null && end !== null && at <= now && end > now && end > at && end - at <= 86400000;
  }
  function latestCheck(node, service, network) {
    return [...(node?.health?.history || [])].filter(c => c.service_id === service && c.network_profile === network && ['sing-box','xray'].some(engine => c.route_path_id === `${engine}:${node.id}`))
      .sort((a, b) => (date(b.checked_at) ?? -Infinity) - (date(a.checked_at) ?? -Infinity))[0] || null;
  }
  function measurement(node, service, network, records, now = Date.now()) {
    if (!node || node.disabled || node.state === 'expired' || !service || !network || !Array.isArray(records)) return null;
    const check = latestCheck(node, service, network);
    if (!check?.probe_id || !freshRecord(check, now)) return null;
    const m = records.find(r => r?.version === 1 && r.node_id === node.id && r.service_id === service && r.network_profile === network && r.route_path_id === check.route_path_id && r.probe_id === check.probe_id && date(r.checked_at) === date(check.checked_at) && date(r.expires_at) <= date(check.expires_at) && freshRecord(r, now));
    if (!m) return null;
    return { ...m, tcp_connect_ms: number(m.tcp_connect_ms),
      proxy_response_ms: check.verdict === 'PASS' && check.test_level === 'service' && check.state === 'available' && !check.direct_leak ? number(m.proxy_response_ms) : null,
      total_check_ms: number(m.total_check_ms) };
  }
  function tcp(nodeID, network, pings, m, now = Date.now()) {
    const candidates = (Array.isArray(pings) ? pings : []).filter(p => p.node_id === nodeID && p.network_profile === network && date(p.checked_at) !== null && date(p.checked_at) <= now && now - date(p.checked_at) < 600000 && (p.reachable === false || p.reachable === true && number(p.latency_ms) !== null));
    if (m && number(m.tcp_connect_ms) !== null && now - date(m.checked_at) < 600000) candidates.push({ node_id: nodeID, network_profile: network, checked_at: m.checked_at, reachable: true, latency_ms: m.tcp_connect_ms });
    candidates.sort((a,b) => date(b.checked_at)-date(a.checked_at));
    return candidates[0] || null;
  }
  function label(value) { const n=number(value); return n===null?'—':n===0?'<1 мс':`${n} мс`; }
  async function readStatus(api, acceptCurrent) {
    const current=Promise.resolve(api('/api/v1/node-checks/current')).then(response=>{acceptCurrent?.(response);return response;});
    const fallback=Promise.resolve(api('/api/v1/node-autofallback'));
    const results=await Promise.allSettled([current, fallback]);
    const unauthorized=results.find(r=>r.status==='rejected'&&r.reason?.status===401);
    if(unauthorized) throw unauthorized.reason;
    if(results[0].status==='rejected') throw results[0].reason;
    return {response:results[0].value, fallback:results[1].status==='fulfilled'?results[1].value:null, partial:results[1].status==='rejected'};
  }
  return Object.freeze({measurement,tcp,label,readStatus});
})();
// END NODE MEASUREMENT MODEL

// Passive browser state never grants permission to change a route.
const nodeBrowser = { tab: 'all', source: '', country: '', page: 0, pageSize: 24, selected: new Set(), visible: [], pings: [], connectivity: [], measurements: [], job: null, timer: null, feedTimers: new Map(), viewActive: null, epoch: 0, feedWrite:null, feedUnknown:false, feedEdit:0, polling: null, authRequired: false, ordinals: new Map() };

// General HTTPS readiness is diagnostic only: it never supplies service health.
function nodeConnectivityState(node, now = Date.now()) {
  const unknown = {label: 'Не проверен', kind: 'unknown'};
  const network = state.nodes?.network_profile;
  if (!node || !nodeCanCheck(node) || !network) return unknown;
  const records = nodeBrowser.connectivity || [];
  const row = records.filter(r => r.node_id === node.id && r.network_profile === network && r.test_level === 'connectivity')
    .sort((a, b) => Date.parse(b.checked_at) - Date.parse(a.checked_at))[0];
  if (!row) return unknown;
  const at = Date.parse(row.checked_at), end = Date.parse(row.expires_at);
  if (!Number.isFinite(at) || !Number.isFinite(end) || at > now || end <= now || end <= at || end - at > 300000) return {label: 'Нужно перепроверить', kind: 'unknown'};
  return row.connectivity_ready === true && row.cleanup_verified === true && row.verdict === 'PASS' && !row.error_code
    ? {label: 'HTTPS доступен', kind: 'ok'}
    : {label: 'Не подтверждён', kind: 'unknown'};
}

function acceptNodeConnectivity(response) {
  // The server clears this read-only memory on restart. Do not resurrect a
  // browser-side result after the server has discarded its observation.
  nodeBrowser.connectivity = Array.isArray(response.connectivity) ? response.connectivity : [];
}

function nodeBrowserActive() {
  return !nodeBrowser.authRequired && (nodeBrowser.viewActive ?? ['nodes','providers'].includes(state.currentView)) && $('#authScreen').hidden && !document.hidden;
}

function scheduleNodeBrowserRefresh(delay = 15000) {
  clearTimeout(nodeBrowser.timer);
  nodeBrowser.timer = null;
  if (nodeBrowserActive()) nodeBrowser.timer = setTimeout(pollNodeBrowserChecks, delay);
}

function stopNodeBrowserRefresh(clearSession = false) {
  nodeBrowser.epoch++;
  const write=nodeBrowser.feedWrite;
  if(write){nodeBrowser.feedWrite=null;state.nodeFeedBusy=false;if(write.sent)nodeBrowser.feedUnknown=true;write.controller.abort();}
  if(clearSession)state.nodeGroupSave?.controller?.abort();
  clearTimeout(nodeBrowser.timer);
  nodeBrowser.timer = null;
  for (const timer of nodeBrowser.feedTimers.values()) clearTimeout(timer);
  nodeBrowser.feedTimers.clear();
  if (clearSession) {
	clearNodeCheckRequest();
    nodeBrowser.authRequired = true;
    nodeBrowser.job = null;
    nodeBrowser.pings = [];
    nodeBrowser.connectivity = [];
    nodeBrowser.measurements = [];
    $('#nodeBrowserReadNotice').textContent = '';
    $('#nodeBrowserReadNotice').hidden = true;
    $('#nodeFeedURL').value = '';
    $('#nodeQuickImportText').value = '';
    $('#nodeQuickImportDialog').close();
    closeNodeCheck();
    clearNodeReveal();
    state.nodeRouteReview?.controller?.abort();
    clearTimeout(state.nodeReviewTimer);
    state.nodeRouteReview = null;
    $('#nodeRouteDialog').close();
    $('#nodeRouteSummary').textContent = '';
  }
}

function captureNodeBrowserInteraction() {
  const cards = $$('#nodeList [data-node-card]');
  const expanded = cards.filter(card => card.querySelector('details')?.open).map(card => card.dataset.nodeCard);
  const active = document.activeElement;
  if (!active || !$('#view-nodes').contains(active)) return { expanded };
  const attribute = [...active.attributes].find(item => /^data-(node|feed)-/.test(item.name));
  return { expanded, active, id: active.id, attribute: attribute && { name: attribute.name, value: attribute.value }, summary: active.tagName === 'SUMMARY' ? active.closest('[data-node-card]')?.dataset.nodeCard : null };
}

function restoreNodeBrowserInteraction(saved) {
  for (const card of $$('#nodeList [data-node-card]')) if (saved.expanded.includes(card.dataset.nodeCard)) card.querySelector('details').open = true;
  if (!saved.active || saved.active.isConnected) return;
  let target = saved.id ? document.getElementById(saved.id) : null;
  if (!target && saved.attribute) target = $$(`[${saved.attribute.name}]`).find(item => item.getAttribute(saved.attribute.name) === saved.attribute.value);
  if (!target && saved.summary) target = $$('#nodeList [data-node-card]').find(card => card.dataset.nodeCard === saved.summary)?.querySelector('summary');
  (target || $('#nodeSearch')).focus({ preventScroll: true });
}

function nodeCountry(node) {
  const code = state.nodes?.country_metadata?.[node.id]?.country_code || node.country_code || '';
  if (!/^[A-Z]{2}$/.test(code)) return { code: '', name: 'Страна не указана', flag: '◇' };
  let name = code;
  try { name = new Intl.DisplayNames(['ru'], { type: 'region' }).of(code) || code; } catch (_) { /* locale fallback */ }
  return { code, name, flag: [...code].map(char => String.fromCodePoint(127397 + char.charCodeAt(0))).join('') };
}

// Windows shows regional-indicator emoji as two letters; prefer the bundled flag.
function nodeFlagHTML(country) {
  return globalThis.RazvilkaIcons?.flag(country.code, country.name) || esc(country.flag);
}

function nodeCanCheck(node) {
  return Boolean(node && !node.disabled && node.state !== 'expired');
}

function nodeTransportLabel(node) {
  const protocol = String(node.protocol || '').toLowerCase();
  if (protocol === 'wireguard') return 'UDP';
  if (['hysteria', 'hysteria2', 'tuic'].includes(protocol)) return 'QUIC';
  return String(node.transport || 'TCP').toUpperCase();
}

function nodeSupportsTCPPing(node) {
  return !['UDP', 'QUIC'].includes(nodeTransportLabel(node));
}

function nodeDisplayName(node) {
  if (node.name && !/^Узел [a-f0-9]+$/i.test(node.name)) return node.name;
  const country = nodeCountry(node);
  if (!nodeBrowser.ordinals.has(node.id)) nodeBrowser.ordinals.set(node.id, nodeBrowser.ordinals.size + 1);
  return `${country.name} [${nodeTransportLabel(node)}] · ${nodeBrowser.ordinals.get(node.id)}`;
}

function nodeDate(value) {
  const date = new Date(value || '');
  return Number.isFinite(date.getTime()) && date.getFullYear() > 2000 ? date : null;
}

function nodeTime(value) {
  return nodeDate(value)?.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) || '—';
}

function nodeBrowserSourceName(id) {
  return (state.nodeFeeds?.sources || []).find(source => source.source_id === id)?.name || ({ manual: 'Мои ссылки', file: 'Из файла', subscription: 'Подписка', community: 'Публичный каталог', legacy: 'Импорт' })[(state.nodes?.sources || []).find(source => source.id === id)?.kind] || 'Мои подключения';
}

function nodeServiceScenario(service) {
  return service ? `${service.name}: веб` : 'Веб-доступ';
}

function nodeServiceHealth(node, serviceID) {
  if (node.disabled) return { label: 'Отключён', kind: 'unknown', state: 'disabled' };
  if (node.state === 'expired') return { label: 'Истёк срок', kind: 'unknown', state: 'expired' };
  const health = [...(node.health?.history || []), ...(node.health?.service_id ? [node.health] : [])].filter(check => check.service_id === serviceID).sort((a,b)=>Date.parse(b.checked_at)-Date.parse(a.checked_at))[0];
  if (!health || !nodeDate(health.checked_at)) return { label: 'Не проверен', kind: 'unknown', state: 'quarantined' };
  const currentNetwork = state.nodes?.network_profile;
  if (!currentNetwork || health.network_profile !== currentNetwork || Date.parse(health.checked_at) > Date.now() || !nodeDate(health.expires_at) || Date.parse(health.expires_at) <= Date.now()) return { label: 'Перепроверить', kind: 'unknown', state: 'stale', health };
  const engine=['sing-box','xray'].find(engine=>health.route_path_id===`${engine}:${node.id}`);
  const works = health.state === 'available' && health.test_level === 'service' && health.verdict === 'PASS' && !!engine && !health.direct_leak;
  if (works) return { label: 'Работает', kind: 'ok', state: 'available', engine, health };
  const failed = ['FAIL','BLOCKED','MISROUTED'].includes(health.verdict) || health.direct_leak === true;
  if (health.verdict === 'ERROR') return {label:'Ошибка проверки',kind:'warn',state:'inconclusive',health};
  return { label: failed ? 'Не подходит сервису' : 'Нет однозначного результата', kind: failed ? 'bad' : 'unknown', state: failed ? 'degraded' : 'inconclusive', health };
}

function nodeMeasurement(node, serviceID) {
  return nodeMeasurementModel.measurement(node, serviceID, state.nodes?.network_profile, nodeBrowser.measurements);
}

function nodePassivePing(nodeID) {
  const node = (state.nodes?.nodes || []).find(item => item.id === nodeID);
  const measurement = nodeMeasurement(node, $('#nodeBrowserService')?.value || '');
  return nodeMeasurementModel.tcp(nodeID, state.nodes?.network_profile, nodeBrowser.pings, measurement);
}

function nodeFilteredList() {
  const query = ($('#nodeSearch')?.value || '').trim().toLocaleLowerCase('ru');
  const wantedState = $('#nodeStateFilter')?.value || '';
  const service = $('#nodeBrowserService')?.value || '';
  const publicSources = new Set((state.nodes?.sources || []).filter(source => ['subscription', 'community'].includes(source.kind)).map(source => source.id));
  const nodes = (state.nodes?.nodes || []).filter(node => {
    if (nodeBrowser.protocol && ({hy2:'hysteria2',ss:'shadowsocks'}[node.protocol] || node.protocol) !== nodeBrowser.protocol) return false;
    const origins = node.origins || [];
    if (nodeBrowser.tab === 'public' && !origins.some(origin => publicSources.has(origin.source_id))) return false;
    if (nodeBrowser.source && !origins.some(origin => origin.source_id === nodeBrowser.source)) return false;
    if (nodeBrowser.country && (nodeCountry(node).code || 'unknown') !== nodeBrowser.country) return false;
    if (wantedState && nodeServiceHealth(node, service).state !== wantedState) return false;
    return !query || [nodeDisplayName(node), nodeCountry(node).name, nodeCountry(node).code, node.protocol, node.transport, ...origins.map(origin => nodeBrowserSourceName(origin.source_id))].join(' ').toLocaleLowerCase('ru').includes(query);
  });
  const sort = $('#nodeSort')?.value || 'status';
  const rank = { available: 0, quarantined: 1, stale: 2, inconclusive: 3, degraded: 4, expired: 5, disabled: 6 };
  nodes.sort((a, b) => {
    let difference = 0;
    if (sort === 'latency') difference = (nodePassivePing(a.id)?.reachable ? nodePassivePing(a.id).latency_ms : Infinity) - (nodePassivePing(b.id)?.reachable ? nodePassivePing(b.id).latency_ms : Infinity);
    else if (sort === 'country') difference = nodeCountry(a).name.localeCompare(nodeCountry(b).name, 'ru');
    else if (sort === 'status') difference = rank[nodeServiceHealth(a, service).state] - rank[nodeServiceHealth(b, service).state];
    return (Number.isNaN(difference) ? 0 : difference) || nodeDisplayName(a).localeCompare(nodeDisplayName(b), 'ru') || a.id.localeCompare(b.id);
  });
  return nodes;
}

function renderNodeBrowser() {
  const interaction = captureNodeBrowserInteraction();
  renderNodeFeeds();
  const payload = state.nodes || {};
  const nodes = payload.nodes || [];
  for (const id of nodes.map(node => node.id).sort()) if (!nodeBrowser.ordinals.has(id)) nodeBrowser.ordinals.set(id, nodeBrowser.ordinals.size + 1);
  const nodeIDs = new Set(nodes.map(node => node.id));
  nodeBrowser.selected = new Set([...nodeBrowser.selected].filter(id => nodeIDs.has(id)));
  const selector = $('#nodeBrowserService');
  const previous = selector.value;
  const services = state.services.filter(service => service.probe_url || (service.probes || []).some(probe => probe.required && probe.url));
  selector.innerHTML = services.map(service => `<option value="${esc(service.id)}">${esc(nodeServiceScenario(service))}</option>`).join('');
  selector.value = services.some(service => service.id === previous) ? previous : (services.find(service => service.id === 'telegram')?.id || services[0]?.id || '');
  $('#nodeGroupCheckService').innerHTML = selector.innerHTML;
  $('#nodeGroupCheckService').value = selector.value;
  const working = nodes.filter(node => nodeServiceHealth(node, selector.value).state === 'available').length;
  $('#nodeNavCount').textContent = nodes.length;
  $('#nodeSummary').hidden = nodeBrowser.tab === 'services';
  $('#nodeSummary').innerHTML = `<div><span>Подключений</span><b>${nodes.length}</b></div><div><span>Работают для ${esc(services.find(service => service.id === selector.value)?.name || 'сервиса')}</span><b class="ok">${working}</b></div><div><span>Источников</span><b>${(payload.sources || []).length}</b></div>`;
  const banner = nodeRecoveryBanner(payload.node_recovery);
  $('#nodeTruthBanner').hidden = payload.available !== false && !banner;
  $('#nodeTruthBanner').querySelector('div').innerHTML = payload.available === false ? '<b>Подключения пока недоступны</b><span>Откройте диагностику хранилища.</span>' : banner;
  $('#nodeSubscriptions').hidden = state.currentView !== 'providers';
  $('#nodeGroupsPanel').hidden = nodeBrowser.tab !== 'groups';
  $('#nodeServiceSelectors').hidden = nodeBrowser.tab !== 'services';
  $('#nodeBrowserContent').hidden = ['subscriptions', 'groups', 'services'].includes(nodeBrowser.tab);
  $$('[data-node-tab]').forEach(button => { const selected = button.dataset.nodeTab === nodeBrowser.tab; button.setAttribute('aria-selected', String(selected)); button.tabIndex = selected ? 0 : -1; });
  if (typeof renderNodeServices === 'function') renderNodeServices();
  renderNodeGroups(payload.groups || [], nodes);
  renderNodeAutofallback();
  renderNodeBrowserFilters(nodes);
  const filtered = nodeFilteredList();
  const pageCount = Math.max(1, Math.ceil(filtered.length / nodeBrowser.pageSize));
  nodeBrowser.page = Math.max(0, Math.min(nodeBrowser.page, pageCount - 1));
  const visible = filtered.slice(nodeBrowser.page * nodeBrowser.pageSize, (nodeBrowser.page + 1) * nodeBrowser.pageSize);
  nodeBrowser.visible = visible.map(node => node.id);
  $('#nodeList').innerHTML = visible.map(node => renderNodeBrowserCard(node, selector.value)).join('');
  $('#nodeEmpty').style.display = filtered.length ? 'none' : 'grid';
  $('#nodeEmpty').querySelector('span').textContent = nodes.length ? 'Измените поиск или фильтры.' : 'Добавьте свои ссылки или откройте публичный каталог.';
  const hiddenSelected = [...nodeBrowser.selected].filter(id => !nodeBrowser.visible.includes(id)).length;
  $('#nodeVisibleCount').textContent = `${filtered.length} из ${nodes.length}${nodeBrowser.selected.size ? ` · выбрано ${nodeBrowser.selected.size}${hiddenSelected ? ` (${hiddenSelected} вне страницы)` : ''}` : ''}`;
  $('#nodeClearSelection').hidden = !nodeBrowser.selected.size;
  $('#nodePageLabel').textContent = `${nodeBrowser.page + 1} / ${pageCount}`;
  $('#nodePagePrevious').disabled = nodeBrowser.page === 0;
  $('#nodePageNext').disabled = nodeBrowser.page >= pageCount - 1;
  const selectable = visible;
  $('#nodeSelectAll').checked = selectable.length > 0 && selectable.every(node => nodeBrowser.selected.has(node.id));
  $('#nodeSelectAll').indeterminate = selectable.some(node => nodeBrowser.selected.has(node.id)) && !$('#nodeSelectAll').checked;
  renderNodeBatchStatus();
  restoreNodeBrowserInteraction(interaction);
  if (typeof captureLiveNodeBrowser === 'function') captureLiveNodeBrowser(nodes);
  if (!nodeBrowser.timer && !nodeBrowser.polling) scheduleNodeBrowserRefresh();
}


// This projection is presentation only. It is never installed in state.nodes,
// node options, selections or requests, and intentionally omits all health data.
function captureLiveNodeBrowser(nodes) {
  if (typeof nodeBrowse === 'undefined' || !nodeBrowseActionsAllowed() || state.dataLoad?.nodes?.phase !== 'ready'
    || !Array.isArray(nodes) || nodes.length > 512) return;
  const rows = nodes.map(node => {
    const country = nodeCountry(node);
    return { name:String(nodeDisplayName(node)).slice(0,320), protocol:String(node.protocol || '').toLowerCase().slice(0,32),
      transport:String(nodeTransportLabel(node)).slice(0,64), country:String(country.name || '').slice(0,120),
      countryCode:String(country.code || 'unknown').slice(0,16),
      sources:(node.origins || []).slice(0,32).map(origin => ({id:String(origin.source_id || '').slice(0,160),name:String(nodeBrowserSourceName(origin.source_id)).slice(0,320)})) };
  });
  if (JSON.stringify(rows).length > 262144) { nodeBrowse.full=null; return; }
  const at=state.dataLoad.nodes.updatedAt;
  if (!Number.isFinite(at) || at > Date.now()) { nodeBrowse.full=null; return; }
  nodeBrowse.full = {rows, at, auth:state.authGeneration || 0, instance:nodeBrowse.instance,
    process:state.status?.process_id || null, receipt:nodeBrowse.liveReceipt};
}

function renderHistoricalNodeBrowser(snapshot, elapsed) {
  const hide = element => { if (element && !nodeBrowse.hidden.has(element)) nodeBrowse.hidden.set(element,element.hidden); if (element) element.hidden=true; };
  for (const element of $$('#view-nodes .node-tabs, #view-nodes > .console-tabs, #nodeServiceSelectors, #nodeGroupsPanel, #nodeSubscriptions, #nodeOpenImport, #view-nodes .r4-discovery-head, #view-nodes .node-batch-toolbar, #nodeAllVLESSDetails, #nodeCleanupDetails, #view-nodes .node-check-hint')) hide(element);
  for (const id of ['nodeBrowserContent','nodeSummary','nodeBrowserReadNotice']) $('#'+id).hidden=false;
  $('#nodeBrowserReadNotice').textContent=`Сведения временно обновляются. Последний прочитанный список · ${Math.floor(elapsed/1000)} сек назад. Только просмотр; доступность подключений сейчас не подтверждена. Фильтр состояния и сортировка временно приостановлены.`;
  // State/latency are deliberately unavailable: no old PASS or timing is
  // reinterpreted as current readiness. Preserve the user's chosen values.
  for (const id of ['nodeStateFilter','nodeSort']) { const element=$('#'+id); if (!nodeBrowse.disabled.has(element)) nodeBrowse.disabled.set(element,element.disabled); element.disabled=true; }
  const query=($('#nodeSearch').value || '').trim().toLocaleLowerCase('ru');
  const rows=snapshot.rows.filter(row => (!nodeBrowser.protocol || ({hy2:'hysteria2',ss:'shadowsocks'}[row.protocol] || row.protocol)===nodeBrowser.protocol)
    && (!nodeBrowser.source || row.sources.some(source=>source.id===nodeBrowser.source))
    && (!nodeBrowser.country || row.countryCode===nodeBrowser.country)
    && (!query || [row.name,row.protocol,row.transport,row.country,...row.sources.map(source=>source.name)].join(' ').toLocaleLowerCase('ru').includes(query)));
  $('#nodeSummary').innerHTML=`<div><span>В последнем списке</span><b>${snapshot.rows.length}</b></div><div><span>Доступность</span><b>Нужна свежая проверка</b></div>`;
  const sources=new Map(),countries=new Map();
  for (const row of snapshot.rows) { for (const source of row.sources) sources.set(source.id,source.name); countries.set(row.countryCode,row.country); }
  $('#nodeSourceFilters').innerHTML='<button type="button" data-node-source="">Все источники</button>'+[...sources].map(([id,name])=>`<button type="button" data-node-source="${esc(id)}" class="${nodeBrowser.source===id?'active':''}">${esc(name)}</button>`).join('');
  $('#nodeCountryFilters').innerHTML='<button type="button" data-node-country="">Все страны</button>'+[...countries].map(([code,name])=>`<button type="button" data-node-country="${esc(code)}" class="${nodeBrowser.country===code?'active':''}">${esc(name)}</button>`).join('');
  const pages=Math.max(1,Math.ceil(rows.length/nodeBrowser.pageSize));nodeBrowser.page=Math.max(0,Math.min(nodeBrowser.page,pages-1));
  const visible=rows.slice(nodeBrowser.page*nodeBrowser.pageSize,(nodeBrowser.page+1)*nodeBrowser.pageSize);
  nodeBrowser.visible=[];nodeBrowser.selected.clear();
  $('#nodeList').innerHTML=visible.map(row=>`<article class="node-card"><div class="node-card-head"><div class="node-heading"><div><h3>${esc(row.name)}</h3><span class="node-protocol">${esc(row.protocol)} · ${esc(row.transport)}</span></div></div></div><div class="node-card-caption"><span>${esc(row.country)}</span><span>Сохранённое описание</span></div><p>Доступность сейчас не подтверждена</p></article>`).join('');
  $('#nodeVisibleCount').textContent=`${rows.length} из ${snapshot.rows.length} · только просмотр`;
  $('#nodePageLabel').textContent=`${nodeBrowser.page+1} / ${pages}`;$('#nodePagePrevious').disabled=nodeBrowser.page===0;$('#nodePageNext').disabled=nodeBrowser.page>=pages-1;
  $('#nodeEmpty').style.display=rows.length?'none':'grid';$('#nodeEmpty').querySelector('span').textContent='В последнем списке совпадений нет. Измените поиск или фильтры.';
}

function renderNodeBrowserCard(node, serviceID) {
  const country = nodeCountry(node);
  const service = state.services.find(item => item.id === serviceID);
  const status = nodeServiceHealth(node, serviceID);
  const connectivity = nodeConnectivityState(node);
  const tcp = nodeSupportsTCPPing(node);
  const ping = tcp ? nodePassivePing(node.id) : null;
  const pingText = !tcp ? 'Не применяется' : !ping ? '—' : ping.reachable ? nodeMeasurementModel.label(ping.latency_ms) : 'Нет ответа';
  const measurement = nodeMeasurement(node, serviceID);
  const responseText = nodeMeasurementModel.label(measurement?.proxy_response_ms);
  const health = status.health || node.health || {};
  const sources = [...new Set((node.origins || []).map(origin => nodeBrowserSourceName(origin.source_id)))].join(', ');
  const assigned = state.services.filter(item => item.enabled && ['sing-box','xray'].some(engine => item.route === `${engine}:${node.id}`)).map(item => item.name).join(', ');
  return `<article data-node-card="${esc(node.id)}" class="node-card ${nodeCanCheck(node) ? '' : 'disabled'} ${nodeBrowser.selected.has(node.id) ? 'selected' : ''}">
    <div class="node-card-head"><div class="node-heading"><span class="node-flag" title="${esc(country.name)} · данные источника">${nodeFlagHTML(country)}</span><div><h3>${esc(nodeDisplayName(node))}</h3><span class="node-protocol">${esc(String(node.protocol || 'VPN').toUpperCase())} · ${esc(nodeTransportLabel(node))}${node.tls ? ' · TLS' : ''}</span></div></div><button class="icon-button r4-node-trash" type="button" data-r4-delete="${esc(node.id)}" aria-label="Удалить ${esc(nodeDisplayName(node))}" title="Удалить локальную запись"><svg class="ui-icon" aria-hidden="true"><use href="#i-trash"></use></svg></button><input class="node-pick" type="checkbox" data-node-select="${esc(node.id)}" aria-label="Выбрать ${esc(nodeDisplayName(node))}" ${nodeBrowser.selected.has(node.id) ? 'checked' : ''} ></div>
    <div class="node-metrics"><div class="node-metric"><small>${tcp ? 'TCP до сервера' : 'TCP для UDP-узла'}</small><b class="${ping?.reachable ? 'ok' : ping ? 'bad' : 'unknown'}">${esc(pingText)}</b></div><div class="node-metric"><small title="Защищённый запрос через узел до заголовков ответа; не ICMP-пинг и не запуск ядра">Ответ через узел</small><b class="${measurement?.proxy_response_ms != null ? 'ok' : 'unknown'}">${esc(responseText)}</b></div><div class="node-metric"><small>Общий HTTPS-тест</small><b class="${connectivity.kind}">${esc(connectivity.label)}</b></div><div class="node-metric"><small>${esc(nodeServiceScenario(service))}</small><b class="${status.kind}">${esc(status.label)}</b></div></div>
    <div class="node-card-caption"><span>${esc(sources || 'Мои подключения')}</span><span title="Последняя проверка доступа">${esc(nodeTime(health.checked_at))}</span></div>
    <div class="node-actions"><button class="secondary" type="button" data-node-connectivity="${esc(node.id)}" ${nodeCanCheck(node) ? '' : 'disabled'}>Общий тест</button><button class="secondary" type="button" data-node-service-test="${esc(node.id)}" ${nodeCanCheck(node) && serviceID ? '' : 'disabled'}>Тест сервиса</button><button class="primary" type="button" data-node-check="${esc(node.id)}" ${nodeCanCheck(node) ? '' : 'disabled'}>${status.state === 'available' ? 'Подключить' : 'Проверить и подключить'}</button></div>
    <details><summary>Подробнее</summary><div class="node-card-details"><dl><div><dt>Источник</dt><dd>${esc(sources)}</dd></div><div><dt>Назначено</dt><dd>${esc(assigned || 'Не назначено')}</dd></div><div><dt>Страна</dt><dd>${esc(country.name)}</dd></div><div><dt>Последняя проверка</dt><dd>${esc(nodeTime(health.checked_at))}</dd></div><div><dt>Проверка узла (без очереди)</dt><dd>${health.latency_ms > 0 ? `${(health.latency_ms / 1000).toFixed(1)} с` : '—'}</dd></div></dl><p>${esc(nodeExpiryText(node))}</p>${health.message && nodeDate(health.checked_at) ? `<p>${esc(health.message)}</p>` : ''}<div class="node-detail-actions"><button class="secondary" type="button" data-node-ping="${esc(node.id)}" ${nodeCanCheck(node) && tcp ? '' : 'disabled'}>TCP-пинг</button><button class="secondary" type="button" data-node-edit="${esc(node.id)}">Переименовать</button><button class="secondary" type="button" data-node-disable="${esc(node.id)}" data-disabled="${node.disabled ? 'true' : 'false'}">${node.disabled ? 'Включить' : 'Отключить'}</button><button class="secondary" type="button" data-node-reveal="${esc(node.id)}">Конфигурация</button><button class="danger-button" type="button" data-node-delete="${esc(node.id)}">Удалить</button></div></div></details>
  </article>`;
}

function renderNodeBrowserFilters(nodes) {
  const sources = (state.nodes?.sources || []).filter(source => nodes.some(node => (node.origins || []).some(origin => origin.source_id === source.id)));
  $('#nodeSourceFilters').innerHTML = `<button type="button" data-node-source="" class="${!nodeBrowser.source ? 'active' : ''}">Все источники <small>${nodes.length}</small></button>` + sources.map(source => `<button type="button" data-node-source="${esc(source.id)}" class="${nodeBrowser.source === source.id ? 'active' : ''}">${esc(nodeBrowserSourceName(source.id))}<small>${nodes.filter(node => (node.origins || []).some(origin => origin.source_id === source.id)).length}</small></button>`).join('');
  const countries = new Map();
  for (const node of nodes) { const country = nodeCountry(node); const key = country.code || 'unknown'; const existing = countries.get(key); countries.set(key, { ...country, count: (existing?.count || 0) + 1 }); }
  $('#nodeCountryFilters').innerHTML = `<button type="button" data-node-country="" class="${!nodeBrowser.country ? 'active' : ''}">Все страны <small>${nodes.length}</small></button>` + [...countries].sort((a, b) => a[1].name.localeCompare(b[1].name, 'ru')).map(([code, country]) => `<button type="button" data-node-country="${esc(code)}" class="${nodeBrowser.country === code ? 'active' : ''}"><span>${nodeFlagHTML(country)} ${esc(country.name)}</span><small>${country.count}</small></button>`).join('');
}

function setNodeBrowserTab(tab) {
  if(['public','subscriptions'].includes(tab)){setView('providers');renderNodes();return;}
  if (!['all', 'public', 'subscriptions', 'groups', 'services'].includes(tab)) return;
  nodeBrowser.tab = tab; nodeBrowser.page = 0; nodeBrowser.source = ''; nodeBrowser.country = '';
  renderNodes();
  if (tab === 'groups') refreshNodeAutofallback();
}

function renderNodeBatchStatus() {
  const job = nodeBrowser.job;
  const running = ['queued', 'interrupted', 'running', 'canceling'].includes(job?.state);
  $('#nodeBatchStatus').hidden = !job;
  $('#nodeBatchCancel').hidden = !running;
  $('#nodeBatchCancel').disabled = job?.state === 'canceling';
  $('#nodePingSelected').disabled = running || state.nodes?.available === false;
  $('#nodeConnectivitySelected').disabled = running || state.nodes?.available === false;
  $('#nodeCheckSelected').disabled = running || !$('#nodeBrowserService').value || state.nodes?.available === false;
  const selection = nodeBrowser.selected.size ? [...nodeBrowser.selected] : nodeBrowser.visible;
  const selectedLabel = nodeBrowser.selected.size ? 'выбранные' : 'видимые';
  const count = selection.filter(id => nodeCanCheck(nodeByID(id))).length;
  const tcpCount = selection.filter(id => nodeCanCheck(nodeByID(id)) && nodeSupportsTCPPing(nodeByID(id))).length;
  $('#nodeCheckSelected').textContent = `Тест сервиса · ${count}`;
  $('#nodeCheckSelected').title = `Проверить ${selectedLabel} через выбранный сервис, без изменения маршрутов`;
  $('#nodeConnectivitySelected').textContent = `Общий тест · ${count}`;
  $('#nodePingSelected').textContent = `TCP-пинг · ${tcpCount}`;
  $('#nodeCheckSelected').disabled ||= !count;
  $('#nodePingSelected').disabled ||= !tcpCount;
  $('#nodeConnectivitySelected').disabled ||= !count;
  if(typeof renderWorkflowControls==='function')renderWorkflowControls();
  if (!job) return;
  $('#nodeBatchProgress').max = Math.max(1, job.total || 1);
  $('#nodeBatchProgress').value = job.completed || 0;
  const label = job.scope==='all-vless' && job.phase==='waiting' && running ? 'Очередь ожидает' : job.phase === 'fetching' && running ? 'Получаем источник' : ({ queued: 'В очереди', interrupted: 'Восстанавливаем проверку', running: 'Проверяем', canceling: 'Останавливаем', completed: 'Проверка завершена', canceled: 'Проверка остановлена', failed: 'Проверка не завершена' })[job.state] || 'Проверка';
  const scenario = job.mode === 'service' ? ` · ${nodeServiceScenario(state.services.find(item => item.id === job.service_id))}`
    : job.mode === 'tcp' ? ' · TCP'
    : job.mode === 'connectivity' ? ' · Общий HTTPS-тест'
    : job.mode === 'service-check' ? ' · Проверка сервисов'
    : job.mode === 'service-select' ? ' · Подбор подключений'
    : '';
  const summary=job.result_state==='not-retained'?' · Подробные результаты прежнего запуска не сохранены. Для оценки доступности нужна новая проверка.'
    :job.mode==='service'?` · ${job.scope==='all-vless'?'Весь VLESS-каталог · ':''}подходят: ${job.passed||0} · отказ: ${job.failed||0} · не подтверждены: ${job.inconclusive||0} · пропущено: ${job.skipped||0} · осталось: ${Math.max(0,(job.total||0)-(job.completed||0))}`
    :job.mode==='connectivity'?` · HTTPS подтверждён: ${job.passed||0} · не подтверждено: ${(job.failed||0)+(job.inconclusive||0)} · пропущено: ${job.skipped||0}`:'';
  const historical=job.earlier_network_completed>0?` · В прежней сети: ${job.earlier_network_completed} (устарели); оценки выше относятся к текущей сети`:'';
  const reason=job.state==='completed'&&job.mode==='service'&&job.result_state!=='not-retained'&&!job.earlier_network_completed?(job.results||[]).find(row=>row.error_code&&row.message)?.message:'';
  $('#nodeBatchMessage').textContent = `${label}: ${job.completed || 0} / ${job.total || 0}${scenario}${summary}${historical}${job.message ? ` · ${job.message}` : ''}${reason?` · Первый отказ: ${reason}`:''}`;
}

async function startNodeBrowserCheck(mode, explicitIDs) {
  if (typeof nodeBrowseActionsAllowed === 'function' && !nodeBrowseActionsAllowed()) return;
  if (['queued', 'interrupted', 'running', 'canceling'].includes(nodeBrowser.job?.state)) return;
  const nodes = state.nodes?.nodes || [];
  const selected = explicitIDs || (nodeBrowser.selected.size ? [...nodeBrowser.selected] : nodeBrowser.visible);
  const ids = selected.filter(id => nodes.some(node => node.id === id && nodeCanCheck(node) && (mode !== 'tcp' || nodeSupportsTCPPing(node))));
  if (!ids.length && mode === 'tcp' && selected.some(id => nodes.some(node => node.id === id && nodeCanCheck(node) && !nodeSupportsTCPPing(node)))) return showDetails({ message: 'Эти подключения используют UDP. Нажмите «Проверить доступ», чтобы проверить их через выбранный сервис.' }, 'Проверка UDP-подключений');
  if (!ids.length) return showDetails({ error: 'Выберите подключения для проверки.' }, 'Проверка подключений');
  if (ids.length > 64) return showDetails({ error: 'За один раз можно проверить до 64 подключений. Уменьшите выборку.' }, 'Проверка подключений');
  const epoch = nodeBrowser.epoch;
  try {
    // Mark locally before awaiting to reject double clicks.
    nodeBrowser.job = { state: 'running', total: ids.length, completed: 0 };
    renderNodeBatchStatus();
    const response = await submitSelectedNodeCheck({ node_ids: ids, mode, service_id: mode === 'service' ? $('#nodeBrowserService').value : '' });
    if (epoch !== nodeBrowser.epoch || nodeBrowser.authRequired) return;
    nodeBrowser.job = response.job; nodeBrowser.pings = response.pings || nodeBrowser.pings; nodeBrowser.measurements = response.node_measurements || [];
    acceptNodeConnectivity(response);
    await pollNodeBrowserChecks();
  } catch (error) {
    if (epoch !== nodeBrowser.epoch || nodeBrowser.authRequired) return;
    nodeBrowser.job = { state: 'failed', total: ids.length, completed: 0, message: error.message };
    renderNodeBatchStatus();
  }
}

// Retry a lost response with the same intent, including after a page reload.
// This storage contains references only; logout clears it with other UI state.
let nodeCheckPendingRequest = null;
function clearNodeCheckRequest() {
  nodeCheckPendingRequest = null;
  try { sessionStorage.removeItem('razvilka.node-check-request'); } catch (_) {}
}
async function submitSelectedNodeCheck(request, options = {}) {
  return submitNodeCheckRequest(request, options);
}
async function submitNodeCheckRequest(request, options = {}) {
  const expected_revision = state.status?.revision;
  if (!Number.isSafeInteger(expected_revision) || expected_revision < 0) throw new Error('Обновите состояние роутера перед проверкой подключений.');
  const intent = { ...request, expected_revision };
  if (request.node_ids) intent.node_ids = [...request.node_ids].sort();
  const signature = JSON.stringify(intent);
  let pending = nodeCheckPendingRequest;
  try { pending ||= JSON.parse(sessionStorage.getItem('razvilka.node-check-request') || 'null'); } catch (_) {}
  if (!pending || pending.signature !== signature || !/^[a-f0-9]{32}$/.test(pending.key) || !Number.isFinite(pending.at) || Date.now() < pending.at || Date.now()-pending.at >= 86400000) {
    const bytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(bytes);
    pending = { signature, key: Array.from(bytes, x => x.toString(16).padStart(2,'0')).join(''), at: Date.now() };
  }
  nodeCheckPendingRequest = pending;
  try { sessionStorage.setItem('razvilka.node-check-request', JSON.stringify(pending)); } catch (_) {}
  try {
    const response = await api('/api/v1/node-checks', { ...options, method: 'POST', body: JSON.stringify({ ...intent, idempotency_key: pending.key }) });
    if (nodeCheckPendingRequest === pending) clearNodeCheckRequest();
    return response;
  } catch (error) {
    if (nodeCheckPendingRequest === pending && error.status >= 400 && error.status < 500) clearNodeCheckRequest();
    throw error;
  }
}

async function pollNodeBrowserChecks() {
  clearTimeout(nodeBrowser.timer);
  nodeBrowser.timer = null;
  if (!nodeBrowserActive()) return;
  if (nodeBrowser.polling) return nodeBrowser.polling;
  const epoch = nodeBrowser.epoch;
  const context = typeof panelReadContext === 'function' ? panelReadContext() : null;
  const current = () => epoch === nodeBrowser.epoch && nodeBrowserActive() && (context === null || panelReadContextCurrent(context));
  nodeBrowser.polling = (async () => {
    let delay = 15000;
    try {
      const read = typeof readPanelResource === 'function' ? readPanelResource : api;
      const reading = await nodeMeasurementModel.readStatus(read, response => {
        if (!current()) return;
        nodeBrowser.job = response.job || null; nodeBrowser.pings = response.pings || [];nodeBrowser.fetchAndCheck=response.fetch_and_check===true; nodeBrowser.measurements = response.node_measurements || [];
        acceptNodeConnectivity(response);
        // Publish completed checks before unrelated fallback/catalog reads.
        // Their later failures cannot turn this observation into a failed job.
        renderNodes();
      });
      const fallback = reading.fallback || {};
      if (!current()) return;
      if (reading.fallback) state.nodeAutofallback = fallback;
      const running = ['queued', 'interrupted', 'running', 'canceling'].includes(nodeBrowser.job?.state);
      if (running || fallback.active) delay = 1500;
      $('#nodeBrowserReadNotice').hidden = !reading.partial;
      $('#nodeBrowserReadNotice').textContent = reading.partial ? 'Состояние резервирования временно недоступно. Результаты проверки подключений показаны отдельно.' : '';
      // A service checker owns exclusive admission until cleanup completes.
      if (!fallback.active && (!running || !['service', 'connectivity'].includes(nodeBrowser.job.mode))) {
        const reads = await Promise.allSettled([read('/api/v1/nodes'), read('/api/v1/routes/options'), read('/api/v1/node-feeds')]);
        if (!current()) return;
        const failed = reads.filter(row => row.status === 'rejected');
        const unauthorized = failed.find(row => row.reason?.status === 401);
        if (unauthorized) throw unauthorized.reason;
        // Failure of catalog metadata must not overwrite an accepted job's
        // progress. Keep prior data for failed parts; expiry still advances.
        ['nodes','routeOptions','nodeFeeds'].forEach((key,index) => {
          if (reads[index].status === 'fulfilled') {
            if (key === 'nodes' && typeof acceptPanelSection === 'function') acceptPanelSection(key, reads[index].value, Date.now());
            else state[key] = reads[index].value;
          } else if (key === 'nodes' && typeof panelSectionState === 'function') {
            const error = reads[index].reason;
            panelSectionState(key, typeof panelBusy === 'function' && panelBusy(error) ? 'busy' : 'error', error);
            if (typeof loadSavedNodeBrowse === 'function' && typeof panelLoad !== 'undefined') void loadSavedNodeBrowse(panelLoad.generation);
          }
        });
        if (failed.length) {
          const busy = failed.every(row => row.reason?.status === 409 && row.reason?.payload?.code === 'RESTORE_OPERATION_BUSY');
          $('#nodeBrowserReadNotice').textContent = busy ? 'Список подключений обновится после текущей операции. Состояние задания показано отдельно.' : 'Часть списка подключений не обновилась. Сохранённые данные показаны до следующей попытки.';
          $('#nodeBrowserReadNotice').hidden = false;
          delay = 4000;
        }
      }
      renderNodes();
    } catch (error) {
      if (!current()) return;
      if (error.status === 401 || error.status === 403) { stopNodeBrowserRefresh(true); showAuth({ ...state.status, authenticated: false, auth_required: true }, 'Сессия завершилась. Войдите снова.'); return; }
      // An ordinary job-status failure cannot revoke a successful node list.
      // A shared admission fence does make the protected list unavailable.
      if (typeof panelSectionState === 'function' && (error.status === 409 && error.payload?.code === 'RESTORE_OPERATION_BUSY' || error.status === 503 && ['DATAPLANE_RECOVERY_REQUIRED','PRIVATE_BACKUP_RECOVERY_REQUIRED'].includes(error.payload?.code))) {
        panelSectionState('nodes', 'busy', error);
        if (typeof loadSavedNodeBrowse === 'function' && typeof panelLoad !== 'undefined') void loadSavedNodeBrowse(panelLoad.generation);
      }
      renderNodes(); // Local expiry still advances when the router is busy.
      $('#nodeBatchMessage').textContent = `Не удалось обновить проверку: ${error.message}`;
      delay = 4000;
    } finally {
      nodeBrowser.polling = null;
      scheduleNodeBrowserRefresh(delay);
    }
  })();
  return nodeBrowser.polling;
}

async function cancelNodeBrowserCheck() {
  try {
    const response = await api('/api/v1/node-checks/current'+(nodeBrowser.job?.id?'?job_id='+encodeURIComponent(nodeBrowser.job.id):''), { method: 'DELETE' });
    nodeBrowser.job = response.job || nodeBrowser.job;
    renderNodeBatchStatus();
  } catch (error) { showDetails({ error: error.message }, 'Проверка не остановлена'); }
}

function renderNodeSubscriptions() {
  const feeds = state.nodeFeeds || {};
  const preset = $('#nodeFeedPreset').value;
  if (feeds.presets?.length) {
    $('#nodeFeedPreset').innerHTML = feeds.presets.map(item => `<option value="${esc(item.id)}">${esc(item.name)}</option>`).join('') + '<option value="custom">Своя HTTPS-подписка</option>';
    $('#nodeFeedPreset').value = preset === 'custom' || feeds.presets.some(item => item.id === preset) ? preset : feeds.presets[0].id;
  }
  $('#nodeFeedSync').disabled = feeds.available === false || Boolean(state.nodeFeedBusy);
  $('#nodeFeedSources').innerHTML = (feeds.sources || []).map(source => {
    const label = ({ saved: 'Ожидает обновления', synced: 'Обновлён', fetched: 'Обновлён', unchanged: 'Без изменений', not_modified: 'Без изменений', quarantined: 'Подключения получены', stale: 'Пора обновить', failed: 'Не удалось обновить', needs_acceptance: 'Нужно разрешить частичный импорт', capacity: 'Каталог заполнен', running: 'Обновляется', fetching: 'Получаем подписку', interrupted: 'Обновление прервано — прежние подключения сохранены', queued: 'В очереди', canceled: 'Остановлен' })[source.status] || 'Ожидает обновления';
    const progress = Number.isInteger(source.cursor) && Number.isInteger(source.snapshot_entries) && source.snapshot_entries > 0 && source.cursor >= 0 && source.cursor <= source.snapshot_entries ? `<p>Просмотрено ${source.cursor} из ${source.snapshot_entries} записей${source.cursor < source.snapshot_entries ? ' · следующий запрос продолжит список' : ' · текущий список просмотрен'}. Работа подключений проверяется отдельно.</p>` : '';
    const partialAction = source.saved && source.status === 'needs_acceptance' ? `<button class="primary" type="button" data-feed-accept="${esc(source.source_id)}">Разрешить частичный импорт</button>` : Number(source.imported) > 0 ? `<button class="primary" type="button" data-feed-show="${esc(source.source_id)}">Открыть подключения · ${Number(source.imported)}</button>` : '';
    return `<article class="node-subscription-card"><div><h4>${esc(source.name || 'Подписка')}</h4><p>${esc(label)} · ${Number(source.imported || 0)} подключений${source.omitted ? ` · ещё ${Number(source.omitted)} за пределами выборки` : ''}</p>${progress}<p>${source.enabled ? `Автообновление: каждые ${Number(source.refresh_interval_minutes || 360)} мин` : 'Обновление вручную'}${source.next_refresh_at ? ` · следующее ${esc(nodeTime(source.next_refresh_at))}` : ''}</p></div><div class="node-subscription-actions">${partialAction}${source.job_id ? `<button class="secondary" type="button" data-feed-cancel="${esc(source.job_id)}">Остановить обновление</button>` : ''}<button class="secondary" type="button" data-feed-refresh="${esc(source.source_id)}">Обновить</button>${source.saved ? `<button class="secondary" type="button" data-feed-toggle="${esc(source.source_id)}">${source.enabled ? 'Пауза' : 'Автообновление'}</button><button class="danger-button" type="button" data-feed-delete="${esc(source.source_id)}">Удалить подписку</button>` : ''}</div></article>`;
  }).join('') || '<p>Сохранённых подписок пока нет.</p>';
}

async function nodeFeedDataWrite(path,options) {
  if(nodeBrowser.feedWrite)throw new Error('Изменение подписки ещё выполняется.');
  const ticket={epoch:nodeBrowser.epoch,controller:new AbortController(),sent:false};
  nodeBrowser.feedWrite=ticket;state.nodeFeedBusy=true;renderNodeSubscriptions();
  const current=()=>nodeBrowser.feedWrite===ticket && ticket.epoch===nodeBrowser.epoch && nodeBrowserActive();
  try {
    if(nodeBrowser.feedUnknown){
      if(!await askConfirmation('Результат предыдущего действия неизвестен','Проверьте список подписок и задач. Повторная отправка может повторить получение. Вы проверили состояние и хотите отправить запрос ещё раз?','Отправить повторно'))throw new Error('Повторная отправка отменена. Прочитайте список подписок.');
    }
    if(!current())throw Object.assign(new Error('Контекст подписки изменился.'),{name:'AuthGenerationChanged'});
    ticket.sent=true;
    const result=await apiDataMutation(path,{...options,signal:ticket.controller.signal});
    if(!current())throw Object.assign(new Error('Контекст подписки изменился.'),{name:'AuthGenerationChanged'});
    nodeBrowser.feedUnknown=false;
    return result;
  } catch(error){
    if(current() && error.writeMayHaveSucceeded)nodeBrowser.feedUnknown=true;
    throw error;
  } finally {
    if(nodeBrowser.feedWrite===ticket){nodeBrowser.feedWrite=null;state.nodeFeedBusy=false;if(nodeBrowserActive())renderNodeSubscriptions();}
  }
}

async function saveNodeSubscription(event) {
  event?.preventDefault();
  if (state.nodeFeedBusy) return;
  const epoch = nodeBrowser.epoch;
  const preset = $('#nodeFeedPreset').value;
  const limit = Number($('#nodeFeedLimit').value);
  if (!Number.isInteger(limit) || limit < 1 || limit > 128) { $('#nodeFeedStatus').textContent = 'Выберите от 1 до 128 подключений.'; return; }
  const interval = Number($('#nodeFeedInterval').value);
  const body = { name: $('#nodeFeedName').value.trim(), limit, accept_partial: $('#nodeFeedPartial').checked, enabled: interval > 0, refresh_interval_minutes: interval || 360, confirm: 'SAVE_NODE_FEED' };
  if (preset === 'custom') { body.url = $('#nodeFeedURL').value.trim(); body.format = $('#nodeFeedFormat').value; } else body.preset_id = preset;
  const edit=nodeBrowser.feedEdit, name=$('#nodeFeedName').value, url=$('#nodeFeedURL').value;
  try {
    const response = await nodeFeedDataWrite('/api/v1/node-feeds', { method: 'POST', body: JSON.stringify(body) });
    if (epoch !== nodeBrowser.epoch || !nodeBrowserActive()) return;
    const unchanged=edit===nodeBrowser.feedEdit && name===$('#nodeFeedName').value && url===$('#nodeFeedURL').value;
    if(unchanged){$('#nodeFeedURL').value = ''; $('#nodeFeedName').value = '';}
    $('#nodeFeedStatus').textContent = unchanged?'Подписка сохранена. Получаем подключения…':'Отправленная подписка сохранена. Новые поля ещё не сохранены.';
    await refreshNodeSubscription(response.source.source_id);
  } catch (error) { if (epoch === nodeBrowser.epoch && nodeBrowserActive()) $('#nodeFeedStatus').textContent = error.message; }
  finally { if (epoch === nodeBrowser.epoch && nodeBrowserActive()) renderNodes(); }
}

async function refreshNodeSubscription(id) {
  if (!nodeBrowserActive()) return;
  const epoch = nodeBrowser.epoch;
  try {
    const response = await nodeFeedDataWrite(`/api/v1/node-feeds/${encodeURIComponent(id)}/sync`, { method: 'POST', body: '{}' });
    if (epoch !== nodeBrowser.epoch || !nodeBrowserActive()) return;
    const jobID = response.job?.id;
    if (jobID) await pollNodeFeedJob(jobID);
    if (epoch === nodeBrowser.epoch && nodeBrowserActive()) await pollNodeBrowserChecks();
  } catch (error) { if (epoch === nodeBrowser.epoch && nodeBrowserActive()) $('#nodeFeedStatus').textContent = error.message; }
}

async function pollNodeFeedJob(id) {
  if (!nodeBrowserActive()) return;
  const epoch = nodeBrowser.epoch;
  const response = await api(`/api/v1/node-feeds/jobs/${encodeURIComponent(id)}`);
  if (epoch !== nodeBrowser.epoch || !nodeBrowserActive()) return;
  const job = response.job || response;
  const status = job.status || job.state;
  if (['running', 'queued', 'canceling'].includes(status)) {
    $('#nodeFeedStatus').textContent = 'Обновляем подписку…';
    clearTimeout(nodeBrowser.feedTimers.get(id));
    nodeBrowser.feedTimers.set(id, setTimeout(async () => {
      try { await pollNodeFeedJob(id); } catch (error) { if (epoch === nodeBrowser.epoch && nodeBrowserActive()) $('#nodeFeedStatus').textContent = error.message; }
    }, 1500));
    return;
  }
  nodeBrowser.feedTimers.delete(id);
  $('#nodeFeedStatus').textContent = job.message || (status === 'completed' ? `Подписка обновлена: ${Number(job.result?.imported || 0)} подключений. Выберите подключения для проверки.` : status === 'canceled' ? 'Обновление остановлено.' : 'Не удалось обновить подписку. Сохранённые подключения доступны в каталоге.');
  await pollNodeBrowserChecks();
}

async function changeNodeSubscription(id, remove) {
  const source = (state.nodeFeeds?.sources || []).find(item => item.source_id === id);
  if (!source || !nodeBrowserActive()) return;
  const epoch = nodeBrowser.epoch;
  if (remove && !await askConfirmation('Удалить подписку?', 'Источник будет исключён из автоподбора, его обновление остановится. Полученные подключения и действующие маршруты сохранятся. Если это последний разрешённый источник и других обходов нет, автопилот встанет на паузу.', 'Удалить подписку')) return;
  if (epoch !== nodeBrowser.epoch || !nodeBrowserActive()) return;
  try {
    const body = remove ? { revision: source.revision, confirm: 'DELETE_NODE_FEED' } : { revision: source.revision, name: source.name, enabled: !source.enabled, refresh_interval_minutes: source.refresh_interval_minutes || 360, limit: source.limit || 64, accept_partial: Boolean(source.accept_partial), confirm: 'UPDATE_NODE_FEED' };
    const result = await (remove?api:nodeFeedDataWrite)(`/api/v1/node-feeds/${encodeURIComponent(id)}`, { method: remove ? 'DELETE' : 'PUT', body: JSON.stringify(body) });
    if (epoch !== nodeBrowser.epoch || !nodeBrowserActive()) return;
    if (remove) document.dispatchEvent(new CustomEvent('razvilka:source-consent-changed'));
    const feeds = await api('/api/v1/node-feeds');
    if (epoch !== nodeBrowser.epoch || !nodeBrowserActive()) return;
    state.nodeFeeds = feeds; renderNodes();
    if (remove) $('#nodeFeedStatus').textContent = result.autonomy_paused
      ? 'Подписка удалена. Автопилот на паузе: разрешённых источников и обходов больше нет. Действующие маршруты сохранены.'
      : 'Подписка удалена. Источник больше не используется автопилотом. Полученные подключения и действующие маршруты сохранены.';
  } catch (error) { if (epoch === nodeBrowser.epoch && nodeBrowserActive()) $('#nodeFeedStatus').textContent = error.message; }
}

async function cancelNodeSubscriptionJob(id) {
  try {
    await api(`/api/v1/node-feeds/jobs/${encodeURIComponent(id)}`, { method: 'DELETE' });
    await pollNodeFeedJob(id);
  } catch (error) { $('#nodeFeedStatus').textContent = error.message; }
}

async function acceptNodeSubscriptionPartial(id) {
  const source = (state.nodeFeeds?.sources || []).find(item => item.source_id === id);
  if (!source?.saved || source.status !== 'needs_acceptance' || !nodeBrowserActive()) return;
  const epoch = nodeBrowser.epoch;
  if (!await askConfirmation('Сохранить поддерживаемые подключения?', 'Часть записей этого источника не поддерживается. RAZVILKA пропустит их и сохранит остальные. Проверка доступа и выбор маршрута выполняются отдельно.', 'Разрешить')) return;
  if (epoch !== nodeBrowser.epoch || !nodeBrowserActive()) return;
  try {
    await nodeFeedDataWrite(`/api/v1/node-feeds/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify({ revision: source.revision, name: source.name, enabled: source.enabled, refresh_interval_minutes: source.refresh_interval_minutes || 360, limit: source.limit || 64, accept_partial: true, confirm: 'UPDATE_NODE_FEED' }) });
    if (epoch === nodeBrowser.epoch && nodeBrowserActive()) await refreshNodeSubscription(id);
  } catch (error) { if (epoch === nodeBrowser.epoch && nodeBrowserActive()) $('#nodeFeedStatus').textContent = error.message; }
}

function renderWorkspaceNavigation(view) {
  const settings = ['settings', 'dns', 'sources'];
  const bypass = ['engineconfig', 'engines'];
  const diagnostics = ['diagnostics', 'connections', 'testlab', 'strategylab'];
  const group = settings.includes(view) ? settings : bypass.includes(view) ? bypass : diagnostics.includes(view) ? diagnostics : [];
  const labels = { settings: 'Общие', engineconfig: 'Мои обходы', engines: 'Установка и обновления', dns: 'DNS-серверы', sources: 'Списки сайтов', diagnostics: 'Состояние', connections: 'Соединения', testlab: 'Проверка сервисов', strategylab: 'Подбор NFQWS2' };
  const nav = $('#contextNavigation');
  nav.hidden = !group.length;
  nav.innerHTML = group.map(name => `<button type="button" data-context-view="${name}" class="${view === name ? 'active' : ''}">${labels[name]}</button>`).join('');
  const parent = settings.includes(view) ? 'settings' : bypass.includes(view) ? 'engineconfig' : diagnostics.includes(view) ? 'diagnostics' : view;
  if (['settings', 'diagnostics'].includes(parent)) $('#sidebarTools').open = true;
  $$('.nav[data-view]').forEach(button => button.classList.toggle('active', button.dataset.view === parent));
}

function bindNodeBrowser() {
  if (typeof bindNodePolicy === 'function') bindNodePolicy();
  $('#nodeMobileFilters').addEventListener('click', () => { const expanded = $('#nodeMobileFilters').getAttribute('aria-expanded') !== 'true'; $('#nodeMobileFilters').setAttribute('aria-expanded', String(expanded)); $('#nodeFilters').classList.toggle('mobile-open', expanded); });
  $('#serviceScopeMode').addEventListener('change', renderServiceScopeDevices);
  $('#serviceScopeDevices').addEventListener('change', changeServiceScopeDevice);
  $('#serviceScopeSources').addEventListener('input', renderServiceScopeDevices);
  if (typeof bindNodeIntent === 'function') bindNodeIntent();
  if (typeof bindNodeServices === 'function') bindNodeServices();
  $('#nodeClearSelection').addEventListener('click', () => { nodeBrowser.selected.clear(); renderNodes(); });
  $('#nodeGroupCheckService').addEventListener('change', event => { $('#nodeBrowserService').value = event.target.value; renderNodes(); });
  $('.node-tabs').addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key) || !event.target.matches('[data-node-tab]')) return;
    const tabs = $$('[data-node-tab]'); const index = tabs.indexOf(event.target);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
    event.preventDefault(); setNodeBrowserTab(tabs[next].dataset.nodeTab); tabs[next].focus();
  });
  $('#nodeGroupUseClose').addEventListener('click', () => $('#nodeGroupUseDialog').close());
  $('#nodeGroupUseForm').addEventListener('submit', chooseNodeGroupForService);
  $('#nodeGroupList').addEventListener('click', event => { const check = event.target.closest('[data-node-group-check]'); const use = event.target.closest('[data-node-group-use]'); if (check) { const group = (state.nodes?.groups || []).find(item => item.id === check.dataset.nodeGroupCheck); if (group) { setNodeBrowserTab('all'); startNodeBrowserCheck('service', group.node_ids); } } else if (use) openNodeGroupUse(use.dataset.nodeGroupUse); });
  $('#nodeQuickImportForm').addEventListener('submit', importQuickNodes);
  $('#nodeQuickImportFile').addEventListener('change', loadQuickNodeFile);
  $('#nodeQuickImportClose').addEventListener('click', () => $('#nodeQuickImportDialog').close());
  $('#nodeQuickImportDialog').addEventListener('close', () => { $('#nodeQuickImportText').value = ''; $('#nodeQuickImportFile').value = ''; $('#nodeQuickImportStatus').textContent = ''; });
  $('#nodeQuickImportSubscription').addEventListener('click', () => { $('#nodeQuickImportDialog').close(); setNodeBrowserTab('subscriptions'); $('#nodeFeedPreset').value = 'custom'; $('#nodeFeedCustom').hidden = false; $('#nodeFeedURL').focus(); });
  $$('[data-node-tab]').forEach(button => button.addEventListener('click', () => setNodeBrowserTab(button.dataset.nodeTab)));
  $('#contextNavigation').addEventListener('click', event => { const button = event.target.closest('[data-context-view]'); if (button) setView(button.dataset.contextView); });
  for (const id of ['nodeSort', 'nodeBrowserService']) $(`#${id}`).addEventListener('change', () => { nodeBrowser.page = 0; renderNodes(); });
  $('#nodeSourceFilters').addEventListener('click', event => { const button = event.target.closest('[data-node-source]'); if (button) { nodeBrowser.source = button.dataset.nodeSource; nodeBrowser.page = 0; renderNodes(); } });
  $('#nodeCountryFilters').addEventListener('click', event => { const button = event.target.closest('[data-node-country]'); if (button) { nodeBrowser.country = button.dataset.nodeCountry; nodeBrowser.page = 0; renderNodes(); } });
  $('#nodeList').addEventListener('change', event => { if (event.target.matches('[data-node-select]')) { const id = event.target.dataset.nodeSelect; event.target.checked ? nodeBrowser.selected.add(id) : nodeBrowser.selected.delete(id); renderNodes(); } });
  $('#nodeList').addEventListener('click', event => { const button = event.target.closest('[data-node-ping]'); if (button) startNodeBrowserCheck('tcp', [button.dataset.nodePing]); });
  $('#nodeList').addEventListener('click', event => { const common = event.target.closest('[data-node-connectivity]'); const service = event.target.closest('[data-node-service-test]'); if (common) startNodeBrowserCheck('connectivity', [common.dataset.nodeConnectivity]); else if (service) startNodeBrowserCheck('service', [service.dataset.nodeServiceTest]); });
  $('#nodeSelectAll').addEventListener('change', event => { for (const id of nodeBrowser.visible) { event.target.checked ? nodeBrowser.selected.add(id) : nodeBrowser.selected.delete(id); } renderNodes(); });
  $('#nodePagePrevious').addEventListener('click', () => { nodeBrowser.page--; renderNodes(); });
  $('#nodePageNext').addEventListener('click', () => { nodeBrowser.page++; renderNodes(); });
  $('#nodePingSelected').addEventListener('click', () => startNodeBrowserCheck('tcp'));
  $('#nodeConnectivitySelected').addEventListener('click', () => startNodeBrowserCheck('connectivity'));
  $('#nodeCheckSelected').addEventListener('click', () => startNodeBrowserCheck('service'));
  $('#nodeBatchCancel').addEventListener('click', cancelNodeBrowserCheck);
  $('#nodeFeedPreset').addEventListener('change', event => { if (event.target.value !== 'custom') $('#nodeFeedInterval').value = String((state.nodeFeeds?.presets || []).find(preset => preset.id === event.target.value)?.default_refresh_interval_minutes || 360); });
  $('#nodeFeedSources').addEventListener('click', event => { const show = event.target.closest('[data-feed-show]'); const accept = event.target.closest('[data-feed-accept]'); const cancel = event.target.closest('[data-feed-cancel]'); const refresh = event.target.closest('[data-feed-refresh]'); const toggle = event.target.closest('[data-feed-toggle]'); const remove = event.target.closest('[data-feed-delete]'); if (show) { setNodeBrowserTab('all'); nodeBrowser.source = show.dataset.feedShow; nodeBrowser.selected.clear(); $('#nodeSearch').value = ''; $('#nodeStateFilter').value = ''; renderNodes(); $('#nodeBrowserService').focus(); } else if (accept) acceptNodeSubscriptionPartial(accept.dataset.feedAccept); else if (cancel) cancelNodeSubscriptionJob(cancel.dataset.feedCancel); else if (refresh) refreshNodeSubscription(refresh.dataset.feedRefresh); else if (toggle) changeNodeSubscription(toggle.dataset.feedToggle, false); else if (remove) changeNodeSubscription(remove.dataset.feedDelete, true); });
  document.addEventListener('razvilka:view-change', event => { renderWorkspaceNavigation(event.detail); nodeBrowser.viewActive = ['nodes','providers'].includes(event.detail); if (nodeBrowser.viewActive) pollNodeBrowserChecks(); else stopNodeBrowserRefresh(); });
  document.addEventListener('visibilitychange', () => { if (document.hidden) stopNodeBrowserRefresh(); else if (nodeBrowserActive()) pollNodeBrowserChecks(); });
  document.addEventListener('razvilka:auth-required', () => stopNodeBrowserRefresh(true));
  document.addEventListener('razvilka:auth-restored', () => { nodeBrowser.authRequired = false; scheduleNodeBrowserRefresh(); });
}

function openQuickNodeImport() {
  if (typeof nodeBrowseActionsAllowed === 'function' && !nodeBrowseActionsAllowed()) return;
  $('#nodeQuickImportStatus').textContent = '';
  $('#nodeQuickImportDialog').showModal();
  $('#nodeQuickImportText').focus();
}

async function loadQuickNodeFile(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  const epoch = nodeBrowser.epoch;
  if (file.size > 1024 * 1024) { $('#nodeQuickImportStatus').textContent = 'Файл больше 1 МБ. Выберите меньшую подборку или добавьте URL подписки.'; event.target.value = ''; return; }
  try {
    const content = await file.text();
    if (epoch !== nodeBrowser.epoch || !$('#nodeQuickImportDialog').open || event.target.files?.[0] !== file) return;
    $('#nodeQuickImportText').value = content;
    $('#nodeQuickImportStatus').textContent = 'Файл прочитан. Нажмите «Добавить в каталог».';
  } catch (_) { if (epoch === nodeBrowser.epoch) $('#nodeQuickImportStatus').textContent = 'Не удалось прочитать файл.'; }
}

async function importQuickNodes(event) {
  event.preventDefault();
  if (typeof nodeBrowseActionsAllowed === 'function' && !nodeBrowseActionsAllowed()) return;
  if ($('#nodeQuickImportSubmit').disabled) return;
  const profile = $('#nodeQuickImportText').value.trim();
  const epoch = nodeBrowser.epoch;
  if (!profile) return;
  if (/^https:\/\/\S+$/.test(profile)) {
    $('#nodeQuickImportDialog').close(); setNodeBrowserTab('subscriptions');
    $('#nodeFeedPreset').value = 'custom'; $('#nodeFeedCustom').hidden = false; $('#nodeFeedURL').value = profile;
    return;
  }
  $('#nodeQuickImportSubmit').disabled = true;
  $('#nodeQuickImportStatus').textContent = 'Проверяем формат подключений…';
  try {
    const result = await api('/api/v1/nodes/import', { method: 'POST', body: JSON.stringify({ profile, accept_partial: $('#nodeQuickImportPartial').checked, confirm: 'STORE_REMOTE_NODES' }) });
    if (epoch !== nodeBrowser.epoch || !$('#nodeQuickImportDialog').open || $('#nodeQuickImportText').value.trim() !== profile) return;
    $('#nodeQuickImportText').value = '';
    $('#nodeQuickImportFile').value = '';
    $('#nodeQuickImportStatus').textContent = `Принято подключений: ${Number(result.accepted_nodes || 0)}. Всего в каталоге: ${Number(result.total_nodes || 0)}. Повторные ссылки не создают дубликаты. ${result.note || 'Теперь можно проверить доступ.'}`;
    setNodeBrowserTab('all');
    $('#nodeSearch').value = ''; $('#nodeStateFilter').value = ''; nodeBrowser.selected.clear();
    await refreshNodes();
  } catch (error) { if (epoch === nodeBrowser.epoch && $('#nodeQuickImportDialog').open) $('#nodeQuickImportStatus').textContent = error.message; }
  finally { $('#nodeQuickImportSubmit').disabled = false; }
}

async function refreshNodeAutofallback() {
  try { state.nodeAutofallback = await api('/api/v1/node-autofallback'); renderNodeAutofallback(); }
  catch (_) { $('#nodeAutopilot').textContent = 'Состояние автозамены временно недоступно.'; }
}

function renderNodeAutofallback() {
  const statuses = state.nodeAutofallback?.services || [];
  $('#nodeAutopilot').innerHTML = statuses.length ? statuses.map(item => `<div class="node-autofallback-status"><b>${esc(state.services.find(service => service.id === item.service_id)?.name || item.service_id)}</b><span>${esc(item.message || 'Ожидает проверки')}</span><small>${item.checked_at ? `Проверено ${esc(nodeTime(item.checked_at))}` : 'Проверка ещё не выполнялась'}</small></div>`).join('') : '<p class="node-check-hint">Чтобы включить автозамену, создайте резервную группу, проверьте её и выберите для сервиса. После применения RAZVILKA будет искать замену внутри этой группы при подтверждённом отказе.</p>';
}

function openNodeGroupUse(id, serviceHint) {
  if (typeof nodeBrowseActionsAllowed === 'function' && !nodeBrowseActionsAllowed()) return;
  const group = (state.nodes?.groups || []).find(item => item.id === id);
  const services = (state.routeOptions || []).find(option => option.id === `sing-box:${id}`)?.services || [];
  if (!group || !services.length) return showDetails({ error: 'Сначала проверьте группу для нужного сервиса.' }, 'Выбор группы');
  $('#nodeGroupUseID').value = id;
  $('#nodeGroupUseService').innerHTML = services.map(serviceID => `<option value="${esc(serviceID)}">${esc(state.services.find(service => service.id === serviceID)?.name || serviceID)}</option>`).join('');
  if (services.includes(serviceHint)) $('#nodeGroupUseService').value = serviceHint;
  $('#nodeGroupUseStatus').textContent = `Группа: ${group.name}`;
  $('#nodeGroupUseDialog').showModal();
}

async function chooseNodeGroupForService(event) {
  event.preventDefault();
  if (typeof nodeBrowseActionsAllowed === 'function' && !nodeBrowseActionsAllowed()) return;
  if ($('#nodeGroupUseSave').disabled) return;
  const id = $('#nodeGroupUseID').value;
  const service = state.services.find(item => item.id === $('#nodeGroupUseService').value);
  const allowed = (state.routeOptions || []).find(option => option.id === `sing-box:${id}`)?.services || [];
  if (!service || !allowed.includes(service.id)) return;
  $('#nodeGroupUseSave').disabled = true;
  try {
    await saveService({ ...service, enabled: true, route: `sing-box:${id}` });
    await refreshCoreAfterEdit();
    $('#nodeGroupUseDialog').close(); setView('services');
  } catch (error) { $('#nodeGroupUseStatus').textContent = error.message; }
  finally { $('#nodeGroupUseSave').disabled = false; }
}
