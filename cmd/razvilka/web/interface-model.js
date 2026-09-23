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
      if (scope === 'selected' && !s.enabled && !s.applied_enabled && !s.applied_state?.enabled && !serviceChanged(s)) return false;
      if (scope === 'changed' && !serviceChanged(s)) return false;
      if (scope === 'attention' && (Object.hasOwn(summaries[s.id] || {}, 'actionable') ? summaries[s.id].actionable !== true : ((!s.enabled && !s.applied_enabled && !s.applied_state?.enabled && !serviceChanged(s)) || summaries[s.id]?.kind === 'good'))) return false;
      if (wanted && category(s) !== wanted) return false;
      return !q || [s.name, category(s), ...(s.domains || [])].map(text).join(' ').toLocaleLowerCase('ru').includes(q);
    });
  }
  function serviceChanged(service) {
    return service.dirty === true || service.route_dirty === true || service.sources_dirty === true;
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
  function homeSnapshot(services, summaries) {
    const selected = services.filter(s => s.enabled === true);
    const counts = aggregate(selected, summaries);
    const order = { bad: 0, warn: 1, unknown: 2 };
    const attention = selected.filter(s => summaries[s.id]?.kind !== 'good')
      .slice().sort((a, b) => (order[summaries[a.id]?.kind] ?? 2) - (order[summaries[b.id]?.kind] ?? 2) || text(a.name).localeCompare(text(b.name), 'ru'));
    const routes = new Map();
    let appliedCount = 0;
    // Include still-applied routes even when a new draft has deselected them.
    // A draft is not a completed removal; route counts never use desired/plan.
    for (const s of services) {
      const applied = s.applied_state || { enabled: s.applied_enabled === true, route: s.applied_route };
      if (applied.enabled !== true) continue;
      appliedCount++;
      const raw = text(applied.route), type = raw === 'direct' ? 'direct'
        : /^(nfqws2|usque|warp-wg|sing-box|xray|amneziawg)(:|$)/.test(raw) ? raw.split(':')[0]
        : raw && raw !== 'auto' ? 'other' : 'unknown';
      routes.set(type, (routes.get(type) || 0) + 1);
    }
    return { counts, attention, appliedCount,
      routes: [...routes].map(([id, count]) => ({ id, count }))
        .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id)),
    };
  }
  // Human-facing state is still presentation only. A saved intention is not
  // evidence; a paused selector is not a stopped connection.
  function humanAuto(snapshot, status = {}, available = true) {
    const make = (state, title, detail, action, target, tone = 'unknown') => ({state,title,detail,action,target,tone});
    if (!available || !snapshot?.policy) return make('unknown','Состояние автопилота не получено','Панель пока не получила актуальные данные. Это не означает, что подключения остановлены.','Обновить состояние','refresh');
    const p = snapshot.policy;
    if (snapshot.blocked) return make('recovery','Автопилоту нужно восстановление','Изменения приостановлены. Сначала проверьте причину; существующее подключение не считается отключённым.','Посмотреть причину','diagnostics','warn');
    if (!p.setup_complete) return make('setup','Автопилот ещё не настроен','Выберите устройства и разрешённые способы подключения один раз. Уже настроенные вручную сервисы останутся без изменений.','Настроить автопилот','onboard');
    if (snapshot.safe_mode || status.safe_mode) return make('safe','Изменение сети запрещено','Автопилот не может применять подключения, пока включена защита сети.','Открыть настройки защиты','settings','warn');
    if (snapshot.stopped) return make('stopped','Подключения RAZVILKA остановлены','Настройки сохранены. Возобновление подключений и пауза автоподбора — разные действия.','Открыть управление','settings','warn');
    if (snapshot.manual) return make('manual','Выбран ручной режим','Вы сами назначаете подключения. Для автоматического подбора измените режим управления.','Изменить режим','settings');
    if (!p.enabled) return make('paused','Автопилот на паузе','Автоподбор приостановлен. Уже применённые подключения этим действием не отключаются.','Настроить автопилот','onboard');
    return make('enabled','Автопилот включён','Подбирает и проверяет разрешённые подключения. Результат для каждого сервиса показан отдельно.','Настройки автопилота','onboard','good');
  }
  function appliedView(s) {
    return s?.applied_state || {enabled:s?.applied_enabled === true,route:s?.applied_route,sources:s?.applied_sources};
  }
  function humanService(s, summary = {}, managed = null, runtime = {}, available = true) {
    s=s&&typeof s==='object'?s:{};summary=summary&&typeof summary==='object'?summary:{};runtime=runtime&&typeof runtime==='object'?runtime:{};
    const applied=appliedView(s);
    const changed=serviceChanged(s)||(typeof s.enabled==='boolean'&&typeof applied.enabled==='boolean'&&s.enabled!==applied.enabled);
    const member=s.enabled===true||!!managed||applied.enabled===true||changed;
    const result={member,changed,applied:applied.enabled===true,route:applied.enabled===true?text(applied.route):'',control:managed?managed.enabled?'Автоподбор включён':'Автоподбор на паузе':'Ручная настройка',kind:'unknown',actionable:false,label:'Не добавлен',detail:'Добавьте сервис, чтобы настроить доступ.'};
    if(!available)return {...result,label:'Нет свежих данных',detail:'Последние настройки сохранены. Работа сервиса сейчас не подтверждена.'};
    if(!member)return result;
    if(managed?.removing)return {...result,kind:'warn',label:'Отключение в очереди',detail:'Отключение ещё не завершено. Действующее подключение может сохраняться.'};
    if(changed){result.pendingLabel='Есть неприменённые изменения';result.actionable=true;}
    const blockers={'requires-review':'Нужно восстановление журнала','definition-changed':'Изменился состав сервиса','manual-change':'Есть ручное изменение','checker-unavailable':'Проверка временно недоступна','catalog-unavailable':'Источник подключений недоступен','component-unavailable':'Нужный компонент не готов','unsupported-scenario':'Для этого сценария нет проверки','apply-refused':'Применение не завершено','removal-blocked':'Снятие подключения приостановлено'};
    const blocked=managed?.enabled&&Object.hasOwn(blockers,runtime.state);
    if(blocked){result.actionable=true;result.pendingLabel=result.pendingLabel||blockers[runtime.state];}
    const progressing=['checking','applying','searching','pending'].includes(runtime.state)&&managed?.enabled===true;
    const matched=typeof summary.route==='string'&&summary.route!==''&&summary.route===result.route;
    if(result.applied&&summary.kind==='good'&&matched)return {...result,kind:'good',label:'Работает',detail:'Доступ подтверждён для проверенного сценария. Другие функции приложения могут требовать отдельной проверки.'};
    if(summary.kind==='bad'&&matched)return {...result,kind:'bad',actionable:result.actionable||!progressing,label:'Проверка не пройдена',detail:text(summary.detail)||'Откройте сервис, чтобы посмотреть причину.'};
    if(blocked)return {...result,kind:'warn',label:blockers[runtime.state],detail:text(runtime.message)||'Откройте причину. Остальные сервисы продолжают управляться отдельно.'};
    if(progressing){const labels={checking:'Проверяется',applying:'Подключение применяется',searching:'Подбирается подключение',pending:'Ожидает настройки'};return {...result,kind:'warn',actionable:changed,label:labels[runtime.state],detail:text(runtime.message)||'Дождитесь результата задачи на роутере.'};}
    if(!result.applied)return {...result,label:managed?.enabled?'Ожидает настройки':changed||s.enabled?'Ожидает применения':'Подключение не назначено',detail:managed?.enabled?'Сервис добавлен в автопилот. Применение подключения ещё не подтверждено.':'Настройки и применённое подключение показываются отдельно.'};
    return {...result,kind:'warn',actionable:changed,label:'Нужна проверка',detail:matched?text(summary.detail)||'Подключение назначено, но свежего подтверждения доступа нет.':'Результат не подтверждает это подключение. Дождитесь новой проверки.'};
  }

  function humanCounts(services, summaries = {}, managed = {}, runtime = {}, available = true) {
    const rows=services.map(s=>({service:s,...humanService(s,summaries[s.id],managed[s.id],runtime[s.id],available)}));
    const selected=rows.filter(s=>s.member);
    return {rows,selected:selected.length,good:selected.filter(s=>s.kind==='good').length,
      attention:selected.filter(s=>s.actionable).length,unconfirmed:selected.filter(s=>s.kind!=='good').length,changed:selected.filter(s=>s.changed).length};
  }
  // Exactly one navigation owner for each route, including legacy deep links.
  const taskSections = Object.freeze({
    overview:{title:'Главная',children:[['overview','Главная']]},
    services:{title:'Сервисы',children:[['services','Сервисы'],['managed','Подробности автоподбора']]},
    nodes:{title:'Подключения',children:[['nodes','Мои подключения'],['providers','Добавить из источника'],['subscription-settings','Обновление подписок'],['connections','Текущий трафик']]},
    devices:{title:'Устройства',children:[['devices','Устройства и группы']]},
    activity:{title:'События',children:[['activity','События']]},
    settings:{title:'Настройки',children:[['settings','Все настройки'],['onboard','Правила автопилота'],['autopilot','Подробности автоматики'],['engines','Способы обхода'],['engineconfig','Настройки обхода'],['updates','Обновления'],['diagnostics','Диагностика'],['dns','DNS'],['sources','Списки сайтов'],['strategylab','Подбор стратегий NFQWS2'],['testlab','Проверки подключений']]}
  });
  const settingsTasks = Object.freeze([
    {target:'onboard',title:'Автопилот',detail:'Устройства, разрешённые способы подключения, интервалы и резерв.',icon:'route'},
    {target:'engines',title:'Способы обхода',detail:'Установка и настройка NFQWS2, WARP, Sing-box и других компонентов.',icon:'layers'},
    {target:'updates',title:'Обновления',detail:'Версия программы, обновления компонентов и результаты обслуживания.',icon:'download'},
    {target:'diagnostics',title:'Проблемы с подключением',detail:'Что мешает работе и какие действия уже выполнены.',icon:'activity'}
  ]);
  function navigation(view = 'overview') {
    for (const [owner,section] of Object.entries(taskSections)) {
      const entry=section.children.find(([id])=>id===view);
      if(entry)return {owner,title:section.title,pageTitle:entry[1]};
    }
    return {owner:'overview',title:'Главная',pageTitle:'Главная'};
  }

  const model = Object.freeze({ category, selectedView, selection, aggregate, filterServices, groupServices, finitePercent, freshEvidence, protocol, homeSnapshot, humanAuto, appliedView, humanService, humanCounts, taskSections, settingsTasks, navigation });
  root.RazvilkaInterfaceModel = model;
  if (typeof module !== 'undefined' && module.exports) module.exports = model;
})(typeof globalThis === 'undefined' ? window : globalThis);
