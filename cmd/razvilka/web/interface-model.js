/* Pure presentation model. Categories never become route IDs or shared health.
   No networking, timers, storage or route mutations in this module. */
(function (root) {
  'use strict';
  const text = x => typeof x === 'string' ? x : '';
  function category(service) {
    const raw = text(service?.category).trim();
    return /^(ai|ии|ии-сервисы|искусственный интеллект)$/i.test(raw) ? 'ИИ-сервисы' : /^(other|другое|другие)$/i.test(raw) ? 'Мои сервисы' : raw || 'Мои сервисы';
  }
  // A saved management intent must remain visible while application is queued.
  // Return presentation copies; never mutate server-provided desired/applied data.
  function selectedView(services, managed = {}) {
    return services.map(s => ({...s, enabled: s.enabled === true || Object.hasOwn(managed, s.id)}));
  }
  function selection(services) {
    const total = services.length, selected = services.filter(s => s.enabled === true).length;
    return { total, selected, checked: total > 0 && selected === total, mixed: selected > 0 && selected < total };
  }
  function aggregate(services, summaries) {
    const enabled = services.filter(s => s.enabled === true);
    let good = 0, failed = 0, pending = 0;
    for (const s of enabled) {
      const kind = summaries[s.id]?.kind;
      if (kind === 'good') good++;
      else if (kind === 'bad') failed++;
      else pending++;
    }
    const routes = [...new Set(enabled.map(s => summaries[s.id]?.route).filter(Boolean))];
    return { ...selection(services), good, failed, pending, routes,
      kind: !enabled.length ? 'unknown' : failed ? 'bad' : pending ? 'warn' : 'good',
      route: routes.length > 1 ? 'Разные маршруты' : routes[0] || '',
    };
  }
  function filterServices(services, { query = '', scope = 'selected', category: wanted = '' } = {}, summaries = {}) {
    const q = text(query).trim().toLocaleLowerCase('ru');
    return services.filter(s => {
      if (scope === 'selected' && !s.enabled) return false;
      if (scope === 'attention' && (!s.enabled || summaries[s.id]?.kind === 'good')) return false;
      if (wanted && category(s) !== wanted) return false;
      return !q || [s.name, category(s), ...(s.domains || [])].map(text).join(' ').toLocaleLowerCase('ru').includes(q);
    });
  }
  function groupServices(services, allServices = services, summaries = {}) {
    const groups = new Map();
    for (const s of services) {
      const key = category(s);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(s);
    }
    return [...groups].map(([name, members]) => {
      const allMembers = allServices.filter(s => category(s) === name);
      return { name, members, allMembers, summary: aggregate(allMembers, summaries), grouped: name === 'ИИ-сервисы' };
    }).sort((a, b) => (a.name === 'ИИ-сервисы' ? -1 : b.name === 'ИИ-сервисы' ? 1 : a.name.localeCompare(b.name, 'ru')));
  }
  function finitePercent(value) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100 ? value : null;
  }
  function freshEvidence(value, now = Date.now()) {
    if (!value || value.status === 'stale') return false;
    const checked = Date.parse(value.checked_at || ''), until = Date.parse(value.fresh_until || value.valid_until || '');
    return Number.isFinite(checked) && Number.isFinite(until) && checked <= now && until > now && checked < until;
  }
  function protocol(value) { return ({hy2:'hysteria2',ss:'shadowsocks'})[value] || text(value); }
  const model = Object.freeze({ category, selectedView, selection, aggregate, filterServices, groupServices, finitePercent, freshEvidence, protocol });
  root.RazvilkaInterfaceModel = model;
  if (typeof module !== 'undefined' && module.exports) module.exports = model;
})(typeof globalThis === 'undefined' ? window : globalThis);
