'use strict';

// These endpoints read job memory and remain available during a network operation.
const nodeActivity = { generation: 0, timer: null, pending: null, checks: null, fallback: null, canceling: false, authRequired: false };

function nodeActivityVisible() {
  return !nodeActivity.authRequired && $('#authScreen').hidden && !document.hidden;
}

function nodeActivityActive() {
  return Boolean(nodeActivity.fallback?.active || (nodeActivity.checks?.mode === 'service' && ['queued', 'interrupted', 'running', 'canceling'].includes(nodeActivity.checks.state)));
}

function renderNodeActivity() {
  const active = nodeActivityActive();
  const paused = Date.parse(nodeActivity.fallback?.paused_until || '') > Date.now();
  $('#nodeActivityNotice').hidden = !active && !paused;
  $('#nodeActivityCancel').hidden = !active;
  $('#nodeActivityCancel').disabled = nodeActivity.canceling;
  const batch = nodeActivity.checks?.mode === 'service' && ['queued', 'interrupted', 'running', 'canceling'].includes(nodeActivity.checks.state);
  $('#nodeActivityTitle').textContent = active ? batch ? 'Проверяем подключения' : 'Проверяем резервный маршрут' : 'Автопроверка приостановлена';
  $('#nodeActivityMessage').textContent = active
    ? nodeActivity.canceling ? 'Останавливаем проверку и завершаем очистку…' : batch ? `Готово ${nodeActivity.checks.completed || 0} из ${nodeActivity.checks.total || 0}. Настройки станут доступны после проверки или её остановки.` : 'Изменение маршрутов временно занято. Проверку можно остановить, чтобы перейти к настройкам.'
    : 'Есть минута для изменения настроек. Затем проверки выбранных резервных групп продолжатся.';
  if (typeof renderInterfaceHome === 'function' && state.currentView === 'overview') renderInterfaceHome(interfaceSummaries());
}

async function refreshNodeActivity() {
  if (!nodeActivityVisible()) return false;
  if (nodeActivity.pending) return nodeActivity.pending;
  const generation = nodeActivity.generation;
  const request = (async () => {
    const [checks, fallback] = await Promise.all([api('/api/v1/node-checks/current'), api('/api/v1/node-autofallback')]);
    if (generation !== nodeActivity.generation || !nodeActivityVisible()) return false;
    nodeActivity.checks = checks.job || null;
    nodeActivity.fallback = fallback;
    state.nodeAutofallback = fallback;
    renderNodeActivity();
    return nodeActivityActive();
  })();
  nodeActivity.pending = request;
  try { return await request; }
  finally { if (nodeActivity.pending === request) nodeActivity.pending = null; }
}

function scheduleNodeActivity(delay = 15000) {
  clearTimeout(nodeActivity.timer);
  nodeActivity.timer = null;
  if (!nodeActivityVisible()) return;
  nodeActivity.timer = setTimeout(async () => {
    nodeActivity.timer = null;
    if (!nodeActivityVisible()) return;
    const generation = nodeActivity.generation;
    const wasActive = nodeActivityActive();
    try {
      const active = await refreshNodeActivity();
      if (generation !== nodeActivity.generation) return;
      if (wasActive && !active) await refreshAll();
    } catch (error) {
      if (error.status === 401 && generation === nodeActivity.generation && nodeActivityVisible()) {
        const authentication = await api('/api/v1/auth/status').catch(() => ({ auth_required: true, authenticated: false }));
        if (generation === nodeActivity.generation) showAuth(authentication, 'Сессия завершилась. Войдите снова.');
      }
    } finally {
      if (generation === nodeActivity.generation) scheduleNodeActivity(nodeActivityActive() ? 1500 : 15000);
    }
  }, delay);
}

async function cancelNodeActivity() {
  if (!nodeActivityVisible() || nodeActivity.canceling || !nodeActivityActive()) return;
  const generation = nodeActivity.generation;
  let failure = '';
  nodeActivity.canceling = true;
  renderNodeActivity();
  try {
    const endpoint = nodeActivity.fallback?.active ? '/api/v1/node-autofallback' : '/api/v1/node-checks/current?job_id='+encodeURIComponent(nodeActivity.checks.id);
    await api(endpoint, { method: 'DELETE' });
    if (generation !== nodeActivity.generation || !nodeActivityVisible()) return;
    await refreshNodeActivity();
    scheduleNodeActivity(500);
  } catch (error) { failure = error.message; }
  finally { if (generation === nodeActivity.generation) { nodeActivity.canceling = false; renderNodeActivity(); if (failure && nodeActivityVisible()) $('#nodeActivityMessage').textContent = failure; } }
}

function resetNodeActivity() {
  nodeActivity.generation++;
  clearTimeout(nodeActivity.timer);
  nodeActivity.timer = null;
  nodeActivity.pending = null;
  nodeActivity.checks = nodeActivity.fallback = null;
  nodeActivity.canceling = false;
  nodeActivity.authRequired = true;
  state.nodeAutofallback = null;
  $('#nodeActivityNotice').hidden = true;
}

document.getElementById('nodeActivityCancel').addEventListener('click', cancelNodeActivity);
document.addEventListener('razvilka:auth-required', resetNodeActivity);
document.addEventListener('razvilka:auth-restored', () => { nodeActivity.authRequired = false; scheduleNodeActivity(); });
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { nodeActivity.generation++; clearTimeout(nodeActivity.timer); nodeActivity.timer = null; nodeActivity.pending = null; nodeActivity.canceling = false; }
  else scheduleNodeActivity(0);
});
