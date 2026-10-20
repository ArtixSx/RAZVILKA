/* Pure presentation model. Categories never become route IDs or shared health.
   No networking, timers, storage or route mutations in this module. */
(function (root) {
  'use strict';
  const text = x => typeof x === 'string' ? x : '';
  // Detached display of CORE's persisted resource_exclusions only. This does
  // not match traffic, prove live application or grant a positive assignment.
  function resourceExclusionView(exclusions, russianEnabled = false, services = []) {
    const empty = (available, declared = false) => ({available,declared,revision:0,manual:[],russian:{present:false,enabled:russianEnabled===true,catalogID:'',revision:0,digest:'',rows:[]}});
    if (exclusions == null) return empty(true);
    const kinds = {service:'Сервис',exact:'Точный домен',suffix:'Домен и поддомены',ip:'IP-адрес',cidr:'Сеть IP'};
    const matches = entries => Array.isArray(entries) && entries.every(entry => entry && Object.hasOwn(kinds,entry.kind) && typeof entry.value === 'string' && entry.value.trim().length > 0);
    const manual = exclusions.manual == null ? [] : exclusions.manual, snapshot = exclusions.russian_snapshot;
    if (exclusions.schema !== 1 || !Number.isSafeInteger(exclusions.revision) || exclusions.revision < 0 || !matches(manual)) return empty(false,true);
    if (snapshot != null && (typeof snapshot.catalog_id !== 'string' || !snapshot.catalog_id.trim()
      || !Number.isSafeInteger(snapshot.revision) || snapshot.revision < 0 || !/^[a-f0-9]{64}$/.test(snapshot.digest || '')
      || !matches(snapshot.entries) || snapshot.entries.length === 0)) return empty(false,true);
    const names = new Map(services.filter(service => service && typeof service.id === 'string' && typeof service.name === 'string').map(service => [service.id,service.name]));
    const rows = (entries, origin) => entries.map(entry => ({kind:entry.kind,value:entry.value,
      label:entry.kind === 'service' ? names.get(entry.value) || entry.value : entry.value,typeLabel:kinds[entry.kind],origin,
      originLabel:origin === 'manual' ? 'Добавлено вручную' : 'Российский каталог',
      reason:origin === 'manual' ? 'Ручное исключение ресурса' : 'Запись принятого российского каталога',
      activeIntent:origin === 'manual' || russianEnabled === true}));
    return {available:true,declared:true,revision:exclusions.revision,manual:rows(manual,'manual'),
      russian:{present:snapshot != null,enabled:russianEnabled===true,catalogID:snapshot?.catalog_id || '',revision:snapshot?.revision || 0,digest:snapshot?.digest || '',rows:rows(snapshot?.entries || [],'russian')}};
  }
  // Validate the actual GET/POST DTO before using its revisions for an edit.
  // These are saved policy images, never runtime admission or route evidence.
  function resourceExclusionSnapshot(value, services = []) {
    const revision = n => Number.isSafeInteger(n) && n >= 0;
    const strings = a => a == null || Array.isArray(a) && a.every(v => typeof v === 'string');
    const matches = a => Array.isArray(a) && a.every(m => m && ['service','exact','suffix','ip','cidr'].includes(m.kind) && typeof m.value === 'string' && m.value.trim());
    const copyMatches = a => a.map(m => ({kind:m.kind,value:m.value}));
    const sameMatches = (a,b) => JSON.stringify(copyMatches(a).sort((x,y)=>(x.kind+'\n'+x.value).localeCompare(y.kind+'\n'+y.value))) === JSON.stringify(copyMatches(b).sort((x,y)=>(x.kind+'\n'+x.value).localeCompare(y.kind+'\n'+y.value)));
    const effective = e => {
      if (!e || !revision(e.policy_revision) || !revision(e.revision) || typeof e.russian_enabled !== 'boolean' || !/^[a-f0-9]{64}$/.test(e.digest || '')
        || !matches(e.manual) || !matches(e.russian) || !Array.isArray(e.legacy_rules) || !strings(e.broad_tlds)) return null;
      const c=e.clients, r=e.legacy_russian;
      if (!c || !['','selected_devices','lan_except'].includes(c.mode) || !['','inherit','base'].includes(c.new_devices)
        || !['segment_ids','device_ids','excluded_device_ids','excluded_cidrs'].every(k=>Object.hasOwn(c,k)&&strings(c[k]))
        || !r || typeof r.enabled !== 'boolean' || typeof r.auto_update_allowed !== 'boolean' || !revision(r.revision)
        || !Object.hasOwn(r,'service_ids') || !Object.hasOwn(r,'broad_tlds') || !strings(r.service_ids) || !strings(r.broad_tlds)
        || e.legacy_rules.some(rule=>!rule || typeof rule.id !== 'string' || !revision(rule.revision) || rule.action !== 'direct' || typeof rule.mandatory !== 'boolean' || !strings(rule.device_ids) || !matches([rule]))) return null;
      if (e.russian_snapshot != null && !resourceExclusionView({schema:1,revision:e.revision,manual:[],russian_snapshot:e.russian_snapshot},e.russian_enabled).available) return null;
      return {policy_revision:e.policy_revision,revision:e.revision,russian_enabled:e.russian_enabled,digest:e.digest,
        clients:{mode:c.mode,new_devices:c.new_devices,...Object.fromEntries(['segment_ids','device_ids','excluded_device_ids','excluded_cidrs'].map(k=>[k,[...(c[k]||[])]]))},
        manual:copyMatches(e.manual),russian:copyMatches(e.russian),broad_tlds:[...(e.broad_tlds||[])],
        legacy_russian:{enabled:r.enabled,auto_update_allowed:r.auto_update_allowed,catalog_id:text(r.catalog_id),revision:r.revision,digest:text(r.digest),service_ids:[...(r.service_ids||[])],broad_tlds:[...(r.broad_tlds||[])]},
        legacy_rules:e.legacy_rules.map(rule=>({id:rule.id,revision:rule.revision,kind:rule.kind,value:rule.value,action:'direct',mandatory:rule.mandatory,device_ids:[...(rule.device_ids||[])]})),
        russian_snapshot:e.russian_snapshot == null?null:{catalog_id:e.russian_snapshot.catalog_id,revision:e.russian_snapshot.revision,digest:e.russian_snapshot.digest,entries:copyMatches(e.russian_snapshot.entries)}};
    };
    if (!value || value.ok !== true || value.live_applied !== false || !Object.hasOwn(value,'resource_exclusions') || !['revision','policy_revision','exclusion_revision','applied_revision'].every(k=>revision(value[k]))
      || !['russian_enabled','russian_auto_update_allowed','desired_matches_applied'].every(k=>typeof value[k] === 'boolean')) return null;
    const view=resourceExclusionView(value.resource_exclusions,value.russian_enabled,services), desired=effective(value.effective), applied=effective(value.applied_effective);
    if (!view.available || !desired || !applied || desired.policy_revision !== value.policy_revision || desired.revision !== value.exclusion_revision
      || desired.russian_enabled !== value.russian_enabled || view.revision !== value.exclusion_revision || !sameMatches(view.manual,desired.manual)
      || value.russian_auto_update_allowed && !value.russian_enabled) return null;
    const explicitStorage=Object.hasOwn(value,'scope_configured')||Object.hasOwn(value,'storage_state');
    if(explicitStorage&&(typeof value.scope_configured!=='boolean'||!['inactive','configured'].includes(value.storage_state)
      || value.scope_configured!==(value.storage_state==='configured')))return null;
    const scopeConfigured=explicitStorage?value.scope_configured:value.policy_revision>0;
    const storageState=explicitStorage?value.storage_state:scopeConfigured?'configured':'unavailable';
    if(explicitStorage&&!scopeConfigured&&(value.policy_revision!==0||value.russian_enabled||value.russian_auto_update_allowed
      || desired.clients.mode!==''||desired.clients.new_devices!==''||['segment_ids','device_ids','excluded_device_ids','excluded_cidrs'].some(k=>desired.clients[k].length)
      || desired.legacy_rules.length))return null;
    if(explicitStorage&&scopeConfigured&&!['selected_devices','lan_except'].includes(desired.clients.mode))return null;
    const expectedRussian=value.russian_enabled?[...view.russian.rows,...desired.legacy_russian.service_ids.map(value=>({kind:'service',value}))]:[];
    const uniqueRussian=[...new Map(expectedRussian.map(row=>[row.kind+'\n'+row.value,row])).values()];
    if(!sameMatches(uniqueRussian,desired.russian)
      || desired.legacy_russian.enabled!==value.russian_enabled
      || desired.legacy_russian.auto_update_allowed!==value.russian_auto_update_allowed
      || !value.russian_enabled && (desired.russian_snapshot || desired.broad_tlds.length || desired.legacy_russian.service_ids.length)) return null;
    if(value.russian_enabled&&view.russian.present&&(!desired.russian_snapshot || desired.russian_snapshot.catalog_id!==view.russian.catalogID || desired.russian_snapshot.revision!==view.russian.revision || desired.russian_snapshot.digest!==view.russian.digest || !sameMatches(desired.russian_snapshot.entries,view.russian.rows)))return null;
    const kinds={service:'Сервис',exact:'Точный домен',suffix:'Домен и поддомены',ip:'IP-адрес',cidr:'Сеть IP'};
    const names=new Map(services.map(s=>[s.id,s.name]));
    const legacy=desired.legacy_rules.map(rule=>({kind:rule.kind,value:rule.value,label:rule.kind==='service'?names.get(rule.value)||rule.value:rule.value,typeLabel:kinds[rule.kind],origin:'legacy',originLabel:'Сохранённое правило',reason:rule.device_ids.length?'Без обхода только для указанных устройств':'Без обхода в сохранённой области',deviceIDs:rule.device_ids,activeIntent:true}));
    // Historical explicit service/TLD entries remain visible with their real
    // provenance. They are not invented members of the accepted RU snapshot.
    for (const id of desired.legacy_russian.service_ids) if (!view.russian.rows.some(row=>row.kind==='service'&&row.value===id)) legacy.push({kind:'service',value:id,label:names.get(id)||id,typeLabel:'Сервис',origin:'legacy',originLabel:'Ранее сохранённое исключение',reason:'Явная запись прежней политики',deviceIDs:[],activeIntent:true});
    for (const tld of desired.broad_tlds) legacy.push({kind:'tld',value:tld,label:'.'+tld,typeLabel:'Явное правило зоны',origin:'legacy',originLabel:'Ранее сохранённое исключение',reason:'Явно выбранная зона прежней политики',deviceIDs:[],activeIntent:true});
    return {revision:value.revision,policy_revision:value.policy_revision,exclusion_revision:value.exclusion_revision,applied_revision:value.applied_revision,
      scopeConfigured,storageState,manualEditable:scopeConfigured||storageState==='inactive',
      russian_enabled:value.russian_enabled,russian_auto_update_allowed:value.russian_auto_update_allowed,desired_matches_applied:value.desired_matches_applied,site_exclusions_pending:value.site_exclusions_pending===true,project_stopped:value.project_stopped===true,live_applied:false,
      view, effective:desired,applied_effective:applied,legacy};
  }
  function resourceServiceExclusions(snapshot) {
    const out=Object.create(null);
    if (!snapshot) return out;
    for (const row of [...snapshot.view.manual,...snapshot.view.russian.rows,...snapshot.legacy]) {
      if (row.kind !== 'service' || !row.activeIntent || row.deviceIDs?.length) continue;
      (out[row.value] ||= []).push({...row});
    }
    return out;
  }
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
        : /^(nfqws2|usque|warp-wg|sing-box|xray|amneziawg|wireguard)(:|$)/.test(raw) ? raw.split(':')[0]
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
    if (snapshot.safe_mode || status.safe_mode) return make('safe','Изменение сети запрещено','Автопилот не может применять подключения, пока включена защита сети.','Открыть восстановление','diagnostics','warn');
    if (snapshot.stopped) return make('stopped','Подключения RAZVILKA остановлены','Настройки сохранены. Возобновление подключений и пауза автоподбора — разные действия.','Открыть управление','settings','warn');
    if (snapshot.manual) return make('manual','Выбран ручной режим','Вы сами назначаете подключения. Для автоматического подбора измените режим управления.','Изменить режим','settings');
    if (!p.enabled) return make('paused','Автопилот на паузе','Автоподбор приостановлен. Уже применённые подключения этим действием не отключаются.','Настроить автопилот','autopilot');
    return make('enabled','Автопилот включён','Подбирает и проверяет разрешённые подключения. Результат для каждого сервиса показан отдельно.','Настройки автопилота','autopilot','good');
  }
  function appliedView(s) {
    return s?.applied_state || {enabled:s?.applied_enabled === true,route:s?.applied_route,sources:s?.applied_sources};
  }
  function humanService(s, summary = {}, managed = null, runtime = {}, available = true, exclusions = []) {
    s=s&&typeof s==='object'?s:{};summary=summary&&typeof summary==='object'?summary:{};runtime=runtime&&typeof runtime==='object'?runtime:{};
    const applied=appliedView(s);
    const changed=serviceChanged(s)||(!s.suspended&&typeof s.dirty!=='boolean'&&typeof s.enabled==='boolean'&&typeof applied.enabled==='boolean'&&s.enabled!==applied.enabled);
    const member=s.enabled===true||!!managed||applied.enabled===true||changed;
    const result={member,changed,applied:applied.enabled===true,route:applied.enabled===true?text(applied.route):'',control:managed?managed.enabled?'Автоподбор включён':'Автоподбор на паузе':'Ручная настройка',kind:'unknown',actionable:false,label:'Не добавлен',detail:'Добавьте сервис, чтобы настроить доступ.'};
    if(!available||s.presentation_only)return {...result,label:'Нет свежих данных',detail:'Последние настройки сохранены. Работа сервиса сейчас не подтверждена.'};
    if(exclusions.length)return {...result,excluded:true,label:'Исключение сохранено',control:exclusions.map(row=>row.originLabel).join(' · '),detail:'Сервис указан без обхода в сохранённой политике. Применение исключения и снятие прежнего маршрута ещё не подтверждены.',pendingLabel:'Применение исключения не подтверждено'};
    if(!member)return result;
    if(managed?.removing)return {...result,kind:'warn',label:'Отключение в очереди',detail:'Отключение ещё не завершено. Действующее подключение может сохраняться.'};
    if(changed){result.pendingLabel='Есть неприменённые изменения';result.actionable=true;}
    if(s.suspended===true&&!result.applied)return {...result,label:'Остановлен',detail:'Настройки сохранены. Включите проект общей кнопкой.'};
    const blockers={'domain-route-unavailable':'Нет подтверждённого обхода для доменного сервиса','requires-review':'Нужно восстановление журнала','definition-changed':'Изменился состав сервиса','manual-change':'Есть ручное изменение','checker-unavailable':'Проверка временно недоступна','catalog-unavailable':'Источник подключений недоступен','component-unavailable':'Нужный компонент не готов','component-stopped':'Нужный компонент не запущен','unsupported-scenario':'Для этого сценария нет проверки','apply-refused':'Применение не завершено','capability-refused':'Недоступно в текущем режиме','excluded':'Не разрешён списком или исключениями','removal-blocked':'Снятие подключения приостановлено'};
    const blocked=managed?.enabled&&Object.hasOwn(blockers,runtime.state);
    // The autopilot's own message names the real blocker (for example, another
    // service whose route prevents the shared transaction).
    if(blocked){result.actionable=true;result.pendingLabel=result.pendingLabel||blockers[runtime.state];result.pendingDetail=text(runtime.message);}
    const progressing=['checking','applying','searching','pending'].includes(runtime.state)&&managed?.enabled===true;
    const matched=typeof summary.route==='string'&&summary.route!==''&&summary.route===result.route;
    // A runtime label has no current route/network/revision proof. Only the
    // shared freshness-checked summary can confirm the applied assignment.
    if(result.applied&&summary.kind==='good'&&matched)return {...result,kind:'good',label:'Работает',detail:blocked?`Проверка сервиса прошла, но автопилот не завершил применение: ${text(runtime.message)||blockers[runtime.state]}`:'Доступ подтверждён для проверенного сценария. Другие функции приложения могут требовать отдельной проверки.'};
    if(summary.kind==='bad'&&matched)return {...result,kind:'bad',actionable:result.actionable||!progressing,label:'Проверка не пройдена',detail:text(summary.detail)||'Откройте сервис, чтобы посмотреть причину.'};
    if(blocked)return {...result,kind:'warn',domainRouteUnavailable:runtime.state==='domain-route-unavailable',label:blockers[runtime.state],detail:text(runtime.message)||'Откройте причину. Остальные сервисы продолжают управляться отдельно.'};
    if(progressing){const labels={checking:'Проверяется',applying:'Подключение применяется',searching:'Подбирается подключение',pending:result.applied?'Включён · перепроверяется':'Ожидает настройки'};return {...result,kind:'warn',progress:true,actionable:changed,label:labels[runtime.state],detail:text(runtime.message)||'Дождитесь результата задачи на роутере.'};}
    if(!result.applied)return {...result,label:managed?.enabled?'Ожидает настройки':changed||s.enabled?'Ожидает применения':'Подключение не назначено',detail:managed?.enabled?'Сервис добавлен в автопилот. Применение подключения ещё не подтверждено.':'Настройки и применённое подключение показываются отдельно.'};
    return {...result,kind:'warn',actionable:changed,label:'Нужна проверка',detail:matched?text(summary.detail)||'Подключение назначено, но свежего подтверждения доступа нет.':'Результат не подтверждает это подключение. Дождитесь новой проверки.'};
  }

  function humanCounts(services, summaries = {}, managed = {}, runtime = {}, available = true, exclusions = {}) {
    const rows=services.map(s=>({service:s,...humanService(s,summaries[s.id],managed[s.id],runtime[s.id],available,exclusions[s.id]||[])}));
    const selected=rows.filter(s=>s.member&&!s.excluded);
    return {rows,selected:selected.length,good:selected.filter(s=>s.kind==='good').length,
      excluded:rows.filter(s=>s.excluded).length,attention:selected.filter(s=>s.actionable).length,unconfirmed:selected.filter(s=>s.kind!=='good').length,changed:rows.filter(s=>s.changed).length};
  }
  // Only a freshness-checked summary for the applied route is verification.
  function engineUsage(services, summaries = {}, managed = {}, runtime = {}) {
    const counts = {};
    for (const service of services || []) {
      const applied = appliedView(service);
      if (applied.enabled !== true || !text(applied.route) || applied.route === 'auto') continue;
      const id = applied.route.split(':')[0];
      const row = counts[id] ||= {assigned:0, verified:0};
      row.assigned++;
      const tested = summaries[service.id]?.kind === 'good' && summaries[service.id]?.route === applied.route;
      if (tested) row.verified++;
    }
    return counts;
  }
  // Exactly one navigation owner for each route, including legacy deep links.
  const taskSections = Object.freeze({
    overview:{title:'Главная',children:[['overview','Главная']]},
    autopilot:{title:'Автопилот',children:[['autopilot','Автопилот'],['managed','Сервисы автопилота'],['onboard','Область и разрешения']]},
    services:{title:'Сервисы',children:[['services','Мои сервисы']]},
    nodes:{title:'Подключения',children:[['nodes','Мои подключения'],['providers','Источники'],['subscription-settings','Расписания подписок'],['connections','Трафик']]},
    engines:{title:'Обходы',children:[['engines','Обходы'],['engineconfig','Настройка обхода']]},
    devices:{title:'Устройства',children:[['devices','Домашняя сеть'],['exclusions','Исключения устройств и сайтов']]},
    activity:{title:'События',children:[['activity','События']]},
    settings:{title:'Настройки',children:[['settings','Настройки'],['updates','Обновления'],['diagnostics','Диагностика'],['dns','DNS'],['sources','Списки сайтов'],['strategylab','Стратегии NFQWS2'],['testlab','Проверки подключений']]}
  });
  const settingsTasks = Object.freeze([
    {target:'autopilot',title:'Автопилот',detail:'Проверки, резерв и разрешённые способы подключения.',icon:'route'},
    {target:'dns',title:'DNS',detail:'Разрешение имён и правила для отдельных сервисов.',icon:'globe'},
    {target:'updates',title:'Обновления',detail:'Программа, компоненты и окно обслуживания.',icon:'download'},
    {target:'diagnostics',title:'Диагностика',detail:'Причины отказов и восстановление.',icon:'activity'}
  ]);
  function navigation(view = 'overview') {
    for (const [owner,section] of Object.entries(taskSections)) {
      const entry=section.children.find(([id])=>id===view);
      if(entry)return {owner,title:section.title,pageTitle:entry[1]};
    }
    return {owner:'overview',title:'Главная',pageTitle:'Главная'};
  }

  const model = Object.freeze({ resourceExclusionView, resourceExclusionSnapshot, resourceServiceExclusions, category, selectedView, selection, aggregate, filterServices, groupServices, finitePercent, freshEvidence, protocol, homeSnapshot, humanAuto, appliedView, humanService, humanCounts, taskSections, settingsTasks, navigation, engineUsage });
  root.RazvilkaInterfaceModel = model;
  if (typeof module !== 'undefined' && module.exports) module.exports = model;
})(typeof globalThis === 'undefined' ? window : globalThis);
