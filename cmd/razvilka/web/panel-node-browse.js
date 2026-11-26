'use strict';

// Never merge this historical display DTO into state.nodes or route options.
const nodeBrowse = { saved:null, full:null, fullShowing:false, epoch:0, action:0, request:0, invalidatedAt:0, instance:null, revision:-1, blocked:false, showing:false, liveReadable:false, liveReceipt:0, timer:null, hidden:new Map(), disabled:new Map() };

function validSavedNodeBrowse(value) {
  if (value?.schema !== 1 || value.dataplane !== 'not-checked' || value.max_age_seconds !== 900
    || !Number.isSafeInteger(value.revision) || value.revision < 0
    || !['empty','retained','expired'].includes(value.state)
    || !Number.isFinite(value.data_age_ms) || value.data_age_ms < 0 || !Number.isFinite(Date.parse(value.observed_at))) return false;
  if (value.state === 'empty') return value.instance_id === '' && value.revision === 0 && value.generated_at === null && value.data == null;
  if (!/^[a-f0-9]{32}$/.test(value.instance_id || '') || value.revision < 1) return false;
  if (value.state === 'expired') return value.data == null;
  const at = Date.parse(value.generated_at), observed = Date.parse(value.observed_at), ids = new Set();
  return Number.isFinite(at) && at <= observed + 1000 && value.data_age_ms < 900000
    && Math.abs(Math.max(0, observed-at)-value.data_age_ms) <= 1000
    && value.data && Object.keys(value.data).length === 1 && Array.isArray(value.data.nodes) && value.data.nodes.length <= 512
    && JSON.stringify(value.data).length <= 262144 && value.data.nodes.every(row => {
      if (!row || Object.keys(row).length !== 4 || !Object.keys(row).every(key => ['id','name','protocol','transport'].includes(key))
        || !/^node-[a-f0-9]{64}$/.test(row.id || '') || ids.has(row.id)
        || typeof row.name !== 'string' || !row.name.length || row.name.length > 320
        || !['protocol','transport'].every(key => typeof row[key] === 'string' && /^[A-Za-z0-9_-]{0,32}$/.test(row[key]))) return false;
      ids.add(row.id); return true;
    });
}

function nodeBrowseActionsAllowed() { return state.authenticated === true && !nodeBrowse.blocked && !nodeBrowse.showing; }
function nodeBrowseActionToken() { return { epoch:nodeBrowse.action, auth:state.authGeneration || 0 }; }
function nodeBrowseActionCurrent(token) {
  return token && nodeBrowseActionsAllowed() && token.epoch === nodeBrowse.action && token.auth === (state.authGeneration || 0);
}
function nodeBrowseGuardRequest(url, method) {
  // Stopping an already accepted job remains available independently.
  if (method === 'GET' || method === 'HEAD' || method === 'DELETE' && /^\/api\/v1\/node-checks\/current(?:\?|$)/.test(url)) return;
  if (/^\/api\/v1\/(?:nodes|node-groups|node-checks)(?:[/?]|$)/.test(url) && !nodeBrowseActionsAllowed()) {
    throw Object.assign(new Error('Сохранённый список доступен только для просмотра. Сначала обновите подключения.'), {status:409});
  }
}

function closeSavedNodeEditors() {
  nodeBrowse.action++;
  if (typeof closeNodeCheck === 'function') closeNodeCheck();
  if (typeof closeNodeRoute === 'function') closeNodeRoute();
  if (typeof clearNodeReveal === 'function') clearNodeReveal();
  if (typeof closeNodePolicy === 'function') closeNodePolicy();
  for (const id of ['nodeEditDialog','nodeGroupDialog','nodeGroupUseDialog','nodeQuickImportDialog','r4DeleteDialog','r4FetchDialog']) {
    const dialog = $('#'+id); if (dialog?.open) dialog.close();
  }
  for (const id of ['nodeEditID','nodeEditAlias','nodeGroupID','nodeGroupUseID','nodeQuickImportText','nodeQuickImportFile','r4FetchURL']) {
    const field = $('#'+id); if (field) field.value = '';
  }
  if (typeof nodeBrowser !== 'undefined') { nodeBrowser.selected.clear(); nodeBrowser.visible = []; }
  if (typeof workflowState !== 'undefined') { workflowState.deleteSeq++; workflowState.fetchSeq++; workflowState.deletion = null; }
}

function nodeBrowseSectionChanged(phase) {
  nodeBrowse.blocked = phase !== 'ready' || state.nodes?.available !== true || !Array.isArray(state.nodes?.nodes);
  if (phase === 'loading') nodeBrowse.action++; // Preserve typed forms during ordinary refresh.
  else if (nodeBrowse.blocked) { if (phase !== 'busy') nodeBrowse.full = null; nodeBrowse.liveReadable = false; closeSavedNodeEditors(); }
  else { nodeBrowse.liveReadable = true; nodeBrowse.liveReceipt++; nodeBrowse.showing = false; }
  for (const id of ['nodeEditForm','nodeGroupForm','nodeGroupUseForm']) {
    const button = $('#'+id)?.querySelector?.('button[type="submit"]'); if (button) button.disabled = nodeBrowse.blocked;
  }
}

function invalidateSavedNodeBrowse(mutation = false) {
  nodeBrowse.epoch++; nodeBrowse.request++; nodeBrowse.saved = null; nodeBrowse.full = null;
  if (mutation) nodeBrowse.invalidatedAt = Date.now();
  clearTimeout(nodeBrowse.timer);
  if (!state.authenticated) {
    nodeBrowse.blocked = true; nodeBrowse.liveReadable = false; closeSavedNodeEditors();
    $('#nodeSavedList').innerHTML = ''; $('#nodeSavedNotice').textContent = ''; $('#nodeSavedSearch').value = '';
    $('#nodeList').innerHTML=''; $('#nodeSummary').innerHTML=''; $('#nodeBrowserReadNotice').textContent=''; $('#nodeBrowserReadNotice').hidden=true;
    nodeBrowse.instance = null; nodeBrowse.revision = -1; nodeBrowse.invalidatedAt = 0;
  }
  if (state.currentView === 'nodes') renderNodes();
}

async function loadSavedNodeBrowse(generation, options = {}) {
  if (!state.authenticated) return;
  const request = ++nodeBrowse.request, epoch = nodeBrowse.epoch, auth = state.authGeneration || 0, started = Date.now(), liveReceipt = nodeBrowse.liveReceipt;
  const current = () => state.authenticated && epoch === nodeBrowse.epoch && request === nodeBrowse.request
    && auth === (state.authGeneration || 0) && panelSnapshotCurrent(generation);
  try {
    const value = await api('/api/v1/panel/nodes', {...options, readTimeoutMs:3000});
    if (!current() || !validSavedNodeBrowse(value)) return;
    if (nodeBrowse.instance === value.instance_id && nodeBrowse.revision > value.revision) return;
    if (started-value.data_age_ms < nodeBrowse.invalidatedAt) return;
    if (nodeBrowse.instance && nodeBrowse.instance !== value.instance_id && liveReceipt === nodeBrowse.liveReceipt) {
      closeSavedNodeEditors(); nodeBrowse.full = null; nodeBrowse.liveReadable = false; nodeBrowse.blocked = true;
      if (state.dataLoad?.nodes) state.dataLoad.nodes = {...state.dataLoad.nodes, phase:'error'};
    }
    nodeBrowse.instance = value.instance_id; nodeBrowse.revision = value.revision;
    nodeBrowse.saved = value.state === 'empty' ? null : {value,receivedAt:Date.now()};
    if (state.currentView === 'nodes') renderNodes();
  } catch (error) {
    if (!current()) return;
    if (error.status === 401 || error.status === 403) { cancelPanelRefresh(); showAuth({authenticated:false}, 'Сессия завершилась. Войдите снова.'); }
  }
}

function renderSavedNodeBrowse() {
  if (state.currentView !== 'nodes') return false;
  clearTimeout(nodeBrowse.timer);
  for (const [element, disabled] of nodeBrowse.disabled) element.disabled = disabled;
  nodeBrowse.disabled.clear();
  const panel = $('#nodeSavedBrowse'), phase = state.dataLoad?.nodes?.phase;
  const live = state.authenticated && state.nodes?.available === true && (phase === 'ready' && !nodeBrowse.blocked || phase === 'loading' && nodeBrowse.liveReadable);
  if (live) {
    for (const [element, hidden] of nodeBrowse.hidden) element.hidden = hidden;
    nodeBrowse.hidden.clear(); panel.hidden = true; if (nodeBrowse.fullShowing) { $('#nodeBrowserReadNotice').textContent=''; $('#nodeBrowserReadNotice').hidden=true; } nodeBrowse.fullShowing=false; nodeBrowse.showing = false;
    return false;
  }
  if (phase === 'busy' && nodeBrowse.full) nodeBrowse.full.busy = true;
  const full = nodeBrowse.full, elapsedFull = full ? Date.now()-full.at : -1;
  const temporaryFull = state.authenticated === true && (phase === 'busy' || phase === 'loading' && full?.busy === true) && full
    && (full.instance || full.process) && full.auth === (state.authGeneration || 0) && elapsedFull >= 0 && elapsedFull < 120000
    && full.receipt === nodeBrowse.liveReceipt && (!full.instance || full.instance === nodeBrowse.instance)
    && full.process === (state.status?.process_id || null) && typeof renderHistoricalNodeBrowser === 'function';
  if (!temporaryFull) nodeBrowse.full = null;
  if (!nodeBrowse.showing) closeSavedNodeEditors();
  nodeBrowse.showing = true; nodeBrowse.blocked = true;
  if (temporaryFull) {
    nodeBrowse.fullShowing=true;
    for (const [element, hidden] of nodeBrowse.hidden) element.hidden = hidden;
    nodeBrowse.hidden.clear(); panel.hidden = true;
    renderHistoricalNodeBrowser(full, elapsedFull);
    if (!document.hidden) nodeBrowse.timer = setTimeout(renderNodes, Math.min(1000,120000-elapsedFull));
    return true;
  }
  // Keep the saved workspace separate. It contains no source forms, check
  // controls, selections, operational results or mutation-bearing IDs.
  for (const element of $$('#view-nodes .node-workspace > :not(.node-workspace-head):not(#nodeSavedBrowse), #view-nodes > .console-tabs, #nodeOpenImport')) {
    if (!nodeBrowse.hidden.has(element)) nodeBrowse.hidden.set(element, element.hidden);
    element.hidden = true;
  }
  panel.hidden = false;
  const saved = nodeBrowse.saved, elapsed = saved ? Date.now()-saved.receivedAt : -1;
  const age = elapsed >= 0 ? saved.value.data_age_ms+elapsed : Infinity;
  const usable = state.authenticated && saved?.value.data && saved.value.state === 'retained' && age < 900000;
  if (!usable) nodeBrowse.saved = null;
  const query = ($('#nodeSavedSearch')?.value || '').trim().toLocaleLowerCase('ru');
  const rows = usable ? saved.value.data.nodes.filter(row => [row.name,row.protocol,row.transport].join(' ').toLocaleLowerCase('ru').includes(query)) : [];
  $('#nodeSavedNotice').textContent = !state.authenticated ? '' : usable
    ? `Снимок сохранённых данных · последний успешный список получен ${Math.floor(age/1000)} сек назад. Только просмотр. Доступность подключений сейчас не проверена.`
    : 'Сохранённый список подключений недоступен. Он появится после успешного чтения списка. Это не означает, что подключения удалены.';
  $('#nodeSavedList').innerHTML = rows.map(row => `<article class="node-card"><h3>${esc(row.name)}</h3><p>${esc(row.protocol)}${row.transport ? ' · '+esc(row.transport) : ''}</p><p>Сохранённое описание · доступность не проверена</p></article>`).join('');
  $('#nodeSavedEmpty').hidden = rows.length > 0;
  $('#nodeSavedEmpty').textContent = usable && query ? 'В сохранённом списке совпадений нет. Попробуйте другое название или протокол.' : usable ? 'Последний полученный список был пуст.' : '';
  if (usable && !document.hidden) nodeBrowse.timer = setTimeout(renderNodes, Math.min(1000,900000-age));
  return true;
}

document.addEventListener('razvilka:auth-required', () => invalidateSavedNodeBrowse());
document.addEventListener('visibilitychange', () => { if (state.currentView === 'nodes') renderNodes(); });
document.addEventListener('razvilka:view-change', () => clearTimeout(nodeBrowse.timer));
