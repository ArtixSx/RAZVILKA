(() => {
  'use strict';
  const names = new Map([
    ['nfqws2', 'NFQWS2'], ['sing-box', 'Sing-box'], ['xray', 'Xray'],
    ['usque', 'WARP · MASQUE'], ['warp-wg', 'WARP · WireGuard'],
    ['wireguard', 'WireGuard'], ['amneziawg', 'AmneziaWG']
  ]);
  let catalog = [], epoch = 0, loading, observedAt = 0;
  const active = () => state.authenticated && state.currentView === 'onboard';

  function clear() {
    epoch++;
    catalog = [];
    observedAt = 0;
    loading = null;
  }
  document.addEventListener('razvilka:auth-required', clear);
  document.addEventListener('razvilka:view-change', event => { if (event.detail !== 'onboard') clear(); });

  async function refresh() {
    if (!active()) return false;
    if (loading) return loading;
    const generation = epoch;
    const request = (async () => {
      // Read the package catalog before the managed plan: both use the router's metadata gate.
      const rows = await api('/api/v1/components?refresh=true', { readTimeoutMs: 110000 });
      if (generation !== epoch || !active() || !Array.isArray(rows)) return false;
      catalog = rows;
      state.components = rows;
      observedAt = Date.now();
      await globalThis.wizardManagedNFQ.refresh();
      if (generation !== epoch || !active()) return false;
      await refreshComponentRecovery();
      return generation === epoch && active();
    })();
    loading = request;
    try { return await request; }
    catch { if (generation === epoch) { catalog = []; observedAt = 0; } return false; }
    finally { if (request === loading) loading = null; }
  }
  function list() {
    if (!observedAt || !active()) return [];
    const available = active() && observedAt > 0 && Date.now() - observedAt < 120000;
    const busy = !!state.componentOperation || !!state.componentRefreshRequest;
    const fenced = componentRecoveryFence();
    return Array.from(names, ([id, name]) => {
      const item = catalog.find(c => c.id === id);
      const managed = id === 'nfqws2' ? globalThis.wizardManagedNFQ.status() : null;
      const installed = available && ((item?.installed === true && !item.inventory_error) || managed?.installed === true);
      const protectedPackage = item?.external_owner || item?.lifecycle_block_reason || item?.running;
      const canInstall = available && !installed && !busy && !fenced && !protectedPackage && (managed ? managed.canInstall :
        item?.installed === false && item.can_install === true && !item.inventory_error && !item.update_check_error && !item.catalog_stale);
      const reason = installed ? 'Уже установлен' : !available ? 'Проверьте доступность для вашего роутера.'
        : busy ? 'Дождитесь завершения операции.' : fenced ? 'Проверьте журнал восстановления в разделе «Обновления».' : managed?.reason || item?.lifecycle_block_reason ||
          (item?.external_owner ? 'Управляется другой программой.' : 'Сейчас установка недоступна для этого роутера.');
      return { id, name, installed, canInstall: !!canInstall, reason: canInstall ? '' : reason };
    });
  }
  async function install(id) {
    if (!active() || !list().some(row => row.id === id && row.canInstall)) return false;
    const generation = epoch;
    const stillHere = () => generation === epoch && active();
    const result = id === 'nfqws2' ? await globalThis.wizardManagedNFQ.install(stillHere) : await manageComponent(id, 'install', stillHere);
    if (generation !== epoch || !active()) return false;
    // Confirm current files without repeating installation or refreshing upstream feeds.
    const rows = await api('/api/v1/components', { cache: 'no-store', readTimeoutMs: 110000 });
    if (generation !== epoch || !active() || !Array.isArray(rows)) return false;
    catalog = rows;
    observedAt = Date.now();
    const verified = id === 'nfqws2' ? globalThis.wizardManagedNFQ.status().installed === true :
      rows.some(c => c.id === id && c.installed === true && !c.inventory_error);
    if (result === true && verified) {
      await globalThis.wizardManagedNFQ.refresh();
      if (generation !== epoch || !active()) return false;
      await refreshComponentRecovery();
    }
    return generation === epoch && active() && result === true && verified;
  }
  globalThis.RazvilkaWizardComponents = { list, refresh, install };
})();
