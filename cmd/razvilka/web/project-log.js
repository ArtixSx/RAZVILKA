'use strict';

// The page and drawer share request semantics: HTTP 202 is acceptance,
// never evidence that the queued router transaction completed.
function renderProjectAuditRow(event) {
  const result = projectLogEventResult(event);
  const tone = result.tone === 'fail' ? 'failed' : result.tone === 'pass' ? 'ok' : 'pending';
  const duration = Number(event.duration_ms);
  return `<div class="audit-row ${tone}"><span class="audit-outcome" title="${esc(result.detail || '')}">${esc(result.label)}</span><div><b>${esc(projectLogAction(event))}</b><code>${esc(event.path || '—')}</code></div><small>${esc(event.actor || 'локально')} · ${esc(event.remote_ip || '—')} · ${esc(timeAgo(event.timestamp))}</small><em>${Number.isFinite(duration) && duration >= 0 ? duration : '—'} мс</em></div>`;
}

function projectLogSectionName(key) {
  return ({ status: 'Состояние проекта', activity: 'События', system: 'Роутер', metrics: 'Нагрузка роутера', services: 'Сервисы', engines: 'Обходы', engineConfigs: 'Настройки обходов', components: 'Установка и обновления', warp: 'WARP', sources: 'Списки сервисов', nodes: 'Подключения', nodeFeeds: 'Подписки', nodeAutofallback: 'Резерв подключений', routeOptions: 'Доступные маршруты', connections: 'Соединения', devices: 'Устройства', testlab: 'Проверки', engineLab: 'Проверка обходов', audit: 'Журнал действий', strategyLab: 'Стратегии NFQWS2', z2kPreview: 'Импорт стратегий', smartRoute: 'Подбор маршрутов', serviceControl: 'Управление проектом', dns: 'DNS', dnsPlan: 'Изменения DNS', sessions: 'Сеансы входа' })[key] || String(key || 'Раздел панели');
}

function projectLogAction(event) {
  const path = String(event.path || '').split('?')[0];
  if (event.action === 'SCHEDULE' && path.startsWith('/runtime/scheduler/')) return 'Фоновые проверки остановлены';
  if (projectLogNFQWS2Restore(event)) return 'Восстановление правил NFQWS2';
  if (event.action === 'BOOT_RECOVERY') return 'Восстановление маршрутов после запуска';
  if (event.action === 'ROLLBACK_RETRY') return 'Повтор незавершённого отката после запуска';
  const component = path.match(/^\/api\/v1\/components\/([^/]+)\/(install|update|remove)$/);
  if (component) {
    const name = ({ nfqws2: 'NFQWS2', usque: 'WARP · MASQUE', 'sing-box': 'Sing-box', xray: 'Xray', amneziawg: 'AmneziaWG' })[component[1]] || component[1];
    return `${({ install: 'Установка', update: 'Обновление', remove: 'Удаление' })[component[2]]}: ${name}`;
  }
  const names = {
    '/api/v1/auth/login': 'Вход в панель', '/api/v1/auth/logout': 'Выход из панели', '/api/v1/auth/setup': 'Создание доступа к панели', '/api/v1/auth/password': 'Изменение пароля', '/api/v1/auth/recover': 'Восстановление доступа',
    '/api/v1/service-control': 'Выбор Автопилота или ручной настройки', '/api/v1/service-control/runtime': 'Включение или остановка обходов', '/api/v1/service-control/jobs': 'Запуск проверки сервисов',
    '/api/v1/apply': 'Проверка и применение маршрутов', '/api/v1/discard': 'Отмена изменений', '/api/v1/settings/safe-mode': 'Изменение безопасного режима',
    '/api/v1/nodes/import': 'Импорт подключений', '/api/v1/nodes/delete-batch': 'Удаление подключений', '/api/v1/node-checks': 'Проверка подключений', '/api/v1/node-feeds/sync': 'Обновление подписок',
    '/api/v1/testlab/current': 'Проверка текущих маршрутов', '/api/v1/testlab/routes': 'Сравнение маршрутов', '/api/v1/self-update/prepare': 'Подготовка обновления RAZVILKA', '/api/v1/self-update/apply': 'Установка обновления RAZVILKA',
    '/api/v1/dns/apply': 'Применение настроек DNS', '/api/v1/dns/test': 'Проверка DNS', '/runtime/forwarding': 'Восстановление сетевых настроек',
  };
  if (Object.hasOwn(names, path)) return names[path];
  const sections = [
    ['node-feeds', 'Управление подпиской'], ['node-groups', 'Изменение группы подключений'], ['nodes', 'Управление подключением'], ['service-policies', 'Настройка резерва сервиса'], ['services', 'Настройка сервиса'], ['custom-services', 'Управление своим сервисом'],
    ['engine-configs', 'Настройка обхода'], ['autonomy', 'Настройка Автопилота'], ['strategy-lab', 'Работа со стратегиями NFQWS2'], ['devices', 'Настройка устройства'], ['sources', 'Обновление списков сервисов'], ['community', 'Работа с каталогом сервисов'],
    ['cloudflare', 'Настройка Cloudflare'], ['warp', 'Настройка WARP'], ['amneziawg', 'Настройка AmneziaWG'], ['dns', 'Настройка DNS'], ['private-backups', 'Работа с резервной копией'], ['profiles', 'Работа с профилем'], ['diagnostics', 'Диагностика подключения'], ['extension-lab', 'Подготовка дополнительного компонента'],
  ];
  const section = sections.find(([prefix]) => path === `/api/v1/${prefix}` || path.startsWith(`/api/v1/${prefix}/`));
  return section?.[1] || ({ POST: 'Запрос действия', PUT: 'Изменение настроек', PATCH: 'Изменение настроек', DELETE: 'Удаление', RESTORE: 'Восстановление' })[event.action] || 'Действие панели';
}

// The router restores only its own NFQWS2 rules after the firmware rewrote
// a table; a refusal or failure carries one fixed reason code in the path.
function projectLogNFQWS2Restore(event) {
  return event?.action === 'RESTORE' ? String(event.path || '').match(/^\/runtime\/nfqws2(?:\/([a-z-]{1,32}))?$/) : null;
}

function projectLogEventResult(event) {
  const nfqws2 = projectLogNFQWS2Restore(event);
  if (nfqws2 && event.outcome === 'ok' && !nfqws2[1]) return { label: 'Правила восстановлены', tone: 'pass', detail: 'Роутер перестроил таблицу правил. RAZVILKA вернула свои правила NFQWS2 без перезапуска обхода.' };
  if (nfqws2 && event.outcome === 'failed') {
    const reasons = {
      'repeated-loss': 'Роутер снова удалял правила сразу после восстановления. Следующая попытка — через 30 минут.',
      'cleanup-uncertain': 'После неудачной попытки не удалось подтвердить уборку. Чужие правила не тронуты; нужна проверка журнала.',
      'kernel-other': 'Правила NFQWS2 изменены не так, как при перестройке таблицы роутером. RAZVILKA их не трогает.',
      'kernel-changed': 'Таблицы правил менялись во время каждой попытки. Попытки продолжаются реже.',
      'kernel-unreadable': 'Не удалось прочитать таблицы правил роутера. Попытка будет повторена.',
      'write-failed': 'Команда добавления правила не выполнена. Изменения этой попытки отменены.',
      'verify-failed': 'Восстановленные правила не подтвердились. Изменения этой попытки отменены.',
      timeout: 'Восстановление не завершилось вовремя. Изменения этой попытки отменены.',
      'queue-binding': 'Очередь NFQWS2 не принадлежит запущенному процессу. Правила не добавлены.',
      'process-identity': 'Процесс NFQWS2 не совпадает с запущенным RAZVILKA. Правила не добавлены.',
      'scope-changed': 'Интернет-подключение роутера изменилось. Правила для прежнего подключения не добавлены.',
      'files-changed': 'Файлы настроек NFQWS2 изменились. Правила не добавлены.',
      'transaction-binding': 'Запуск NFQWS2 не связан с применёнными настройками. Правила не добавлены.',
      'native-review': 'Установленный пакет NFQWS2 не прошёл проверку. Правила не добавлены.',
      'source-unavailable': 'Проверенные инструменты чтения правил недоступны. Правила не добавлены.',
      'graph-outside-scope': 'Эти настройки NFQWS2 не восстанавливаются автоматически.',
    };
    return { label: 'Правила не восстановлены', tone: 'fail', detail: (nfqws2[1] && Object.hasOwn(reasons, nfqws2[1]) && reasons[nfqws2[1]]) || 'Правила NFQWS2 не восстановлены; причина требует проверки.' };
  }
  if (event.action === 'SCHEDULE' && event.outcome === 'failed') {
    const reason = String(event.path || '').replace(/^\/runtime\/scheduler\//, '');
    const reasons = {
      'journal-changed': 'Журнал расписания изменён другим действием. Автоматика остановлена, чтобы не повторить устаревшие команды.',
      'writer-busy': 'Не удалось получить доступ к записи журнала расписания. Проверьте параллельное восстановление и хранилище.',
      'journal-invalid': 'Журнал расписания повреждён или имеет неподдерживаемый формат. Нужна проверка журнала.',
      'write-unconfirmed': 'Запись журнала расписания не подтверждена. Автоматика остановлена до проверки хранилища.',
      'storage-unavailable': 'Хранилище журнала расписания недоступно. Проверьте подключение накопителя и свободное место.',
    };
    return { label: 'Автоматика остановлена', tone: 'fail', detail: reasons[reason] || 'Расписание остановлено; причина требует проверки.' };
  }
  const code = Number(event.status_code);
  const denied = event.outcome === 'denied' || code === 401 || code === 403;
  if (denied || event.outcome === 'failed' || code >= 400) {
    const reasons = { 400: 'Панель не приняла параметры запроса.', 401: 'Для действия нужен вход в панель.', 403: 'Панель не разрешила это действие.', 404: 'Запрошенный объект не найден.', 409: 'Действие конфликтует с текущим состоянием. Обновите данные перед повтором.', 422: 'Не удалось проверить введённые параметры.', 429: 'Слишком много запросов. Повторите позже.', 502: 'Не удалось получить ответ от внешнего источника.', 503: 'Действие временно недоступно.', 504: 'Ответ не получен за отведённое время.' };
    return { label: denied ? 'Доступ отклонён' : 'Ошибка запроса', tone: 'fail', detail: reasons[code] || 'Панель сообщила об ошибке. Причина этого запроса не записана в журнале.' };
  }
  if (code === 202) return { label: 'Принято в работу', tone: 'partial', detail: 'Запрос принят. Завершение задачи и её результат проверяются отдельно.' };
  if (event.outcome === 'ok') return { label: code >= 200 && code < 400 ? 'Запрос обработан' : 'Действие зарегистрировано', tone: 'pass', detail: '' };
  return { label: 'Результат не указан', tone: 'not-ready', detail: 'Данных для вывода об успешном завершении нет.' };
}

function renderProjectNodeCheck(job, error) {
  const heading = '<section class="detail-section"><h4>Последняя ручная проверка каталога подключений</h4>';
  if (error) return `${heading}<p>${esc(error)}</p></section>`;
  if (!job || typeof job !== 'object' || Array.isArray(job)) return `${heading}<p>Отдельная ручная проверка каталога ещё не запускалась. Автопилот проверяет сервисы и подбирает подключения независимо; его состояние показано выше.</p></section>`;
  const number = value => Number.isSafeInteger(value) && value >= 0 ? String(value) : '—';
  const mode = ({ tcp: 'TCP-пинг', service: 'Проверка подключения к сервису', 'service-node-check': 'Проверка подключений', 'service-check': 'Проверка сервисов', 'service-select': 'Подбор подключений' })[job.mode] || 'Режим не указан';
  const status = ({ queued: 'В очереди', running: 'Выполняется', interrupted: 'Проверяем после перезапуска', canceling: 'Останавливается', completed: 'Проверка завершена', canceled: 'Проверка остановлена', failed: 'Проверка не завершена' })[job.state] || 'Результат не подтверждён';
  const historical = job.result_state === 'not-retained' || job.earlier_network_completed > 0;
  const timestamp = Date.parse(job.finished_at || job.started_at || '');
  const time = Number.isFinite(timestamp) ? new Date(timestamp).toLocaleString('ru-RU') : 'Время не указано';
  const rows = Array.isArray(job.results) ? job.results.filter(row => row && typeof row === 'object' && !Array.isArray(row)) : [];
  const failure = rows.find(row => row.error_code && row.message);
  const verdicts = { PASS: 'Проверка пройдена', FAIL: 'Проверка не пройдена', BLOCKED: 'Проверка заблокирована', MISROUTED: 'Не тот маршрут', ERROR: 'Ошибка проверки', INCONCLUSIVE: 'Не удалось проверить' };
  const levels = { service: 'проверка сервиса', tcp: 'TCP', 'tcp-connect': 'TCP' };
  // Only public typed results are summarized; endpoint/configuration fields
  // and node labels/IDs are never copied into the visible project log.
  const reason = failure ? `${verdicts[failure.verdict] || 'Отказ проверки'}${levels[failure.test_level] ? ` · ${levels[failure.test_level]}` : ''}: ${failure.message}` : '';
  return `${heading}<article class="route-result-card status-${job.state === 'failed' ? 'fail' : 'partial'}"><div class="route-result-head"><strong>${esc(mode)}</strong><span>${esc(status)}</span></div><small>${esc(time)}</small><p>${job.scope === 'all-vless' ? 'Весь VLESS-каталог · ' : ''}${job.phase === 'fetching' ? 'Получаем источник · ' : ''}Обработано: ${number(job.completed)} / ${number(job.total)}</p><p>Пройдены: ${number(job.passed)} · Отказ: ${number(job.failed)} · Не подтверждены: ${number(job.inconclusive)} · Пропущены: ${number(job.skipped)}</p>${job.message ? `<p>${esc(job.message)}</p>` : ''}${historical ? '<p>Результаты прежнего запуска или сети не подтверждают текущую доступность. Нужна новая проверка.</p>' : ''}${reason ? `<p>Первый отказ${historical ? ' прежней проверки' : ' этой проверки'}: ${esc(reason)}</p>` : ''}<p class="detail-footnote">Это результат указанной проверки, а не подтверждение, что обход сейчас работает.</p></article></section>`;
}

function renderProjectAutonomy(snapshot, error) {
  const heading = '<section class="detail-section"><h4>Проверки и подбор Автопилота</h4>';
  if (error) return `${heading}<p>Состояние Автопилота недоступно: ${esc(error)}</p></section>`;
  const object = value => value && typeof value === 'object' && !Array.isArray(value);
  const valid = object(snapshot) && snapshot.schema === 1 && /^[a-f0-9]{32}$/.test(snapshot.instance_id || '') && Number.isSafeInteger(snapshot.revision) && snapshot.revision > 0 && snapshot.dataplane === 'not-checked' && ['available', 'retained'].includes(snapshot.state) && Number.isFinite(snapshot.data_age_ms) && snapshot.data_age_ms >= 0 && snapshot.data_age_ms < 120000 && (snapshot.state !== 'available' || snapshot.data_age_ms < 15000) && Number.isFinite(Date.parse(snapshot.observed_at)) && object(snapshot.data) && object(snapshot.data.policy) && object(snapshot.data.services) && object(snapshot.data.runtime);
  if (!valid) return `${heading}<p>Свежий снимок Автопилота не получен. Обновите лог; отсутствие снимка не означает, что проверки не запускались.</p></section>`;
  const data = snapshot.data;
  const labels = { pending: 'Ожидает проверки', checking: 'Проверяется', searching: 'Подбор подключения', applying: 'Применяется', healthy: 'Проверен ранее', applied: 'Применён ранее', unconfirmed: 'Результат не подтверждён', 'service-unconfirmed': 'Сервис отказал через несколько узлов', paused: 'На паузе', 'manual-change': 'Ручное изменение', 'network-unknown': 'Сеть не определена', 'apply-refused': 'Применение отклонено', 'capability-refused': 'Недоступно в текущем режиме', 'domain-route-unavailable': 'Доменный маршрут не подтверждён', excluded: 'Исключён из проверок', 'component-unavailable': 'Компонент не готов', 'component-stopped': 'Компонент не запущен', 'rate-limited': 'Лимит применений', 'requires-review': 'Нужна проверка журнала', 'scope-pending': 'Область не применена', 'origin-expired': 'Истёк источник', 'definition-changed': 'Состав изменился', 'unsupported-scenario': 'Сценарий не поддержан', 'checker-unavailable': 'Проверка недоступна', 'catalog-unavailable': 'Каталог недоступен', 'removal-pending': 'Снятие маршрута в очереди', 'removal-blocked': 'Снятие приостановлено', removed: 'Снят с управления' };
  const names = new Map((Array.isArray(data.catalog_services) ? data.catalog_services : []).filter(object).map(service => [service.id, service.name]));
  const services = Object.entries(data.services).filter(([, service]) => object(service));
  const time = value => Number.isFinite(Date.parse(value || '')) && new Date(value).getFullYear() >= 2000 ? new Date(value).toLocaleString('ru-RU') : '';
  const status = data.blocked === true ? 'Автоматика приостановлена: требуется проверка журнала.' : data.safe_mode === true ? 'Применение запрещено безопасным режимом.' : data.stopped === true ? 'Проект остановлен пользователем.' : data.manual === true ? 'Выбран ручной режим.' : data.policy.enabled === false ? 'Автоматика на паузе.' : data.policy.enabled === true ? 'Автоматика разрешена сохранёнными настройками.' : 'Разрешение автоматики не подтверждено.';
  const rows = services.slice(0, 20).map(([id, service]) => {
    const runtime = object(data.runtime[id]) ? data.runtime[id] : {};
    const checked = time(runtime.checked_at), next = time(runtime.next_check);
    return `<article class="route-result-card status-partial"><div class="route-result-head"><strong>${esc(String(names.get(id) || id).slice(0, 160))}</strong><span>${esc(labels[runtime.state] || 'Нет записанного результата')}</span></div>${runtime.message ? `<p>${esc(String(runtime.message).slice(0, 1200))}</p>` : ''}${checked ? `<small>Последняя проверка: ${esc(checked)}</small>` : ''}${next ? `<p class="detail-footnote">Следующая попытка по расписанию: ${esc(next)}</p>` : ''}${service.enabled === false ? '<p>Автоматика сервиса отключена.</p>' : ''}</article>`;
  }).join('');
  return `${heading}<p>${snapshot.state === 'retained' ? 'Показан сохранённый снимок; текущее состояние обновляется.' : 'Снимок состояния получен с роутера.'} ${esc(time(snapshot.observed_at))}</p><p>${snapshot.state === 'retained' ? 'На момент снимка: ' : ''}${esc(status)}</p>${data.maintenance_message ? `<p>${esc(String(data.maintenance_message).slice(0, 1200))}</p>` : ''}<p>Сервисов в управлении: ${services.length}.</p>${rows || '<p>Сервисов в управлении пока нет.</p>'}${services.length > 20 ? '<p class="detail-footnote">Показаны первые 20 сервисов. Полный список — в разделе Автопилота.</p>' : ''}<p class="detail-footnote">Это записанные состояния проверок и подбора. Они не подтверждают текущую доступность сервиса.</p></section>`;
}

function renderProjectLogDetails(value) {
  const data = value && typeof value === 'object' ? value : {};
  const records = items => Array.isArray(items) ? items.filter(item => item && typeof item === 'object' && !Array.isArray(item)) : [];
  const problems = records(data.load_issues).map(issue => ({ name: projectLogSectionName(issue.section), message: String(issue.message || 'Не удалось получить данные раздела.') }));
  problems.push(...records(data.component_issues).map(issue => ({ name: `Обход: ${String(issue.id || 'компонент')}`, message: String(issue.message || 'Состояние компонента не получено.') })));
  if (data.last_action_error) problems.push({ name: 'Последняя ошибка управления', message: String(data.last_action_error) });
  if (data.jobs_error) problems.push({ name: 'Задания роутера', message: String(data.jobs_error) });
  const audit = data.audit && typeof data.audit === 'object' ? data.audit : {};
  if (audit.memory_only === true && audit.history_complete === false) problems.push({ name: 'История журнала', message: 'Показаны действия текущего запуска. Предыдущую историю пока не удалось прочитать.' });
  if (audit.available !== true || audit.last_error) problems.push({ name: 'Журнал действий', message: String(audit.last_error || 'Актуальный журнал не получен. Доступная история может быть неполной.') });
  const control = data.control && typeof data.control === 'object' ? data.control : {};
  const receipt = data.stop_receipt;
  const stopPending = receipt?.stop_requested === true && receipt.authority_revoked === true && receipt.stopped_confirmed === false && receipt.cleanup_pending === true;
  if (stopPending) problems.push({ name: 'Остановка запрошена', message: 'Запрос сохранён на роутере. Продолжение обновления заблокировано; очистка маршрутов ещё не подтверждена.' });
  const ready = Number.isSafeInteger(control.config_revision);
  const runtime = stopPending ? 'Остановка запрошена · результат ещё не подтверждён' : !ready || control.runtime_state === 'unknown' ? 'Состояние не получено' : control.running === true ? 'Обходы включены' : control.runtime_state === 'stopped' ? 'Обходы выключены' : 'Нужна настройка';
  if (!ready || control.runtime_state === 'unknown') problems.push({ name: 'Управление проектом', message: String(control.runtime_issue?.message || 'Состояние обходов не подтверждено. Обновите данные панели.') });
  const uniqueProblems = problems.filter((item, index) => problems.findIndex(other => other.name === item.name && other.message === item.message) === index);
  const allEvents = records(audit.events).sort((a, b) => (Date.parse(b.timestamp) || 0) - (Date.parse(a.timestamp) || 0));
  const events = allEvents.slice(0, 40);
  const failures = events.filter(event => projectLogEventResult(event).tone === 'fail').length;
  const headline = uniqueProblems.length ? 'Есть сообщения, требующие внимания' : failures ? 'В последних действиях есть ошибки' : 'Состояние и последние действия';
  const summary = uniqueProblems.length ? 'Ниже указаны причины. Последняя ошибка может относиться к предыдущему действию; текущее состояние показано отдельно.' : failures ? 'Ошибки в истории не означают, что обходы сейчас выключены. Сверьте их время и текущее состояние.' : 'Этот журнал показывает состояние панели и ответы на действия. Работу сервиса подтверждает отдельная проверка подключения.';
  const issueHTML = uniqueProblems.length ? `<section class="detail-section"><h4>Что требует внимания</h4>${uniqueProblems.map(issue => `<div class="detail-note"><b>${esc(issue.name)}</b><p>${esc(issue.message)}</p></div>`).join('')}</section>` : '';
  const mode = ready ? ({ auto: 'Автопилот', manual: 'Ручная настройка' })[control.mode] || 'Не определено' : 'Не определено';
  const safeMode = !ready || typeof control.safe_mode !== 'boolean' ? 'Не определено' : control.safe_mode ? 'Безопасный режим: применение маршрутов запрещено' : 'Применение разрешено после проверки';
  const eventHTML = events.map(event => {
    const result = projectLogEventResult(event);
    const timestamp = Date.parse(event.timestamp);
    const time = Number.isFinite(timestamp) ? new Date(timestamp).toLocaleString('ru-RU') : 'Время не указано';
    const code = Number(event.status_code);
    const duration = Number(event.duration_ms);
    const metrics = [time, Number.isInteger(code) && code >= 100 && code <= 599 ? `Ответ ${code}` : '', Number.isFinite(duration) && duration >= 0 && event.duration_ms != null ? `${duration} мс` : ''].filter(Boolean);
    return `<article class="route-result-card status-${result.tone}"><div class="route-result-head"><strong>${esc(projectLogAction(event))}</strong><span>${esc(result.label)}</span></div><div class="route-result-metrics">${metrics.map(text => `<b>${esc(text)}</b>`).join('')}</div>${result.detail ? `<p>${esc(result.detail)}</p>` : ''}</article>`;
  }).join('');
  const jobs = records(data.jobs ?? control.durable_jobs).slice(-12).reverse();
  const jobHTML = jobs.length ? `<section class="detail-section"><h4>Задания на роутере</h4><p class="detail-footnote">Завершение действия показано отдельно от ответа на запрос. Оно не заменяет проверку доступности сервиса.</p>${jobs.map(job => {
    const name = ({ 'service-stop': 'Остановка проекта', 'service-resume': 'Включение проекта', 'service-check': 'Проверка сервисов', 'service-select': 'Подбор подключения', 'service-dns-compare': 'Проверка DNS и сайта', 'service-node-apply': 'Применение подключения', 'node-check': 'Проверка подключений', 'service-node-check': 'Проверка подключений' })[job.mode] || 'Действие проекта';
    const status = ({ queued: 'В очереди', running: 'Выполняется', canceling: 'Завершаем очистку', interrupted: 'Проверяем после перезапуска', completed: 'Завершено', failed: 'Не выполнено', canceled: 'Отменено' })[job.state] || 'Нет подтверждения';
    const timestamp = Date.parse(job.finished_at || job.started_at || '');
    const time = Number.isFinite(timestamp) ? new Date(timestamp).toLocaleString('ru-RU') : 'Время не указано';
    return `<article class="route-result-card status-${job.state === 'failed' ? 'fail' : job.state === 'completed' ? 'pass' : 'partial'}"><div class="route-result-head"><strong>${esc(name)}</strong><span>${esc(status)}</span></div><small>${esc(time)}</small><p>${esc(job.message || '')}</p></article>`;
  }).join('')}</section>` : '';
  return `<div class="detail-hero${uniqueProblems.length || failures ? ' warn' : ''}"><span>Лог проекта</span><h4>${esc(headline)}</h4><p>${esc(summary)}</p></div><section class="detail-section"><h4>Текущее состояние</h4><dl class="detail-kv"><div><dt>Обходы</dt><dd>${esc(runtime)}</dd></div><div><dt>Управление</dt><dd>${esc(mode)}</dd></div><div><dt>Применение</dt><dd>${esc(safeMode)}</dd></div></dl></section>${issueHTML}${renderProjectAutonomy(data.autonomy, data.autonomy_error)}${renderProjectNodeCheck(data.node_job, data.node_job_error)}${jobHTML}<section class="detail-section"><h4>Последние действия (${events.length})</h4><p class="detail-footnote">Результат запроса не доказывает доступность сервиса. Для задач, принятых в работу, итог смотрите в соответствующем разделе панели.</p><div class="route-result-list">${eventHTML || `<div class="detail-empty">${audit.available === true ? 'Записанных действий пока нет.' : 'История действий недоступна.'}</div>`}</div>${allEvents.length > events.length ? '<p class="detail-footnote">Показаны 40 последних записей.</p>' : ''}</section>${technicalDetails(data)}`;
}
