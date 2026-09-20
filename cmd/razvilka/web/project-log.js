'use strict';

function projectLogSectionName(key) {
  return ({ status: 'Состояние проекта', activity: 'События', system: 'Роутер', metrics: 'Нагрузка роутера', services: 'Сервисы', engines: 'Обходы', engineConfigs: 'Настройки обходов', components: 'Установка и обновления', warp: 'WARP', sources: 'Списки сервисов', nodes: 'Подключения', nodeFeeds: 'Подписки', nodeAutofallback: 'Резерв подключений', routeOptions: 'Доступные маршруты', connections: 'Соединения', devices: 'Устройства', testlab: 'Проверки', engineLab: 'Проверка обходов', audit: 'Журнал действий', strategyLab: 'Стратегии NFQWS2', z2kPreview: 'Импорт стратегий', smartRoute: 'Подбор маршрутов', serviceControl: 'Управление проектом', dns: 'DNS', dnsPlan: 'Изменения DNS', sessions: 'Сеансы входа' })[key] || String(key || 'Раздел панели');
}

function projectLogAction(event) {
  const path = String(event.path || '').split('?')[0];
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

function projectLogEventResult(event) {
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

function renderProjectLogDetails(value) {
  const data = value && typeof value === 'object' ? value : {};
  const records = items => Array.isArray(items) ? items.filter(item => item && typeof item === 'object' && !Array.isArray(item)) : [];
  const problems = records(data.load_issues).map(issue => ({ name: projectLogSectionName(issue.section), message: String(issue.message || 'Не удалось получить данные раздела.') }));
  problems.push(...records(data.component_issues).map(issue => ({ name: `Обход: ${String(issue.id || 'компонент')}`, message: String(issue.message || 'Состояние компонента не получено.') })));
  if (data.last_action_error) problems.push({ name: 'Последняя ошибка управления', message: String(data.last_action_error) });
  const audit = data.audit && typeof data.audit === 'object' ? data.audit : {};
  if (audit.available !== true || audit.last_error) problems.push({ name: 'Журнал действий', message: String(audit.last_error || 'Актуальный журнал не получен. Доступная история может быть неполной.') });
  const control = data.control && typeof data.control === 'object' ? data.control : {};
  const ready = Number.isSafeInteger(control.config_revision);
  const runtime = !ready || control.runtime_state === 'unknown' ? 'Состояние не получено' : control.running === true ? 'Обходы включены' : control.runtime_state === 'stopped' ? 'Обходы выключены' : 'Нужна настройка';
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
  return `<div class="detail-hero${uniqueProblems.length || failures ? ' warn' : ''}"><span>Лог проекта</span><h4>${esc(headline)}</h4><p>${esc(summary)}</p></div><section class="detail-section"><h4>Текущее состояние</h4><dl class="detail-kv"><div><dt>Обходы</dt><dd>${esc(runtime)}</dd></div><div><dt>Управление</dt><dd>${esc(mode)}</dd></div><div><dt>Применение</dt><dd>${esc(safeMode)}</dd></div></dl></section>${issueHTML}<section class="detail-section"><h4>Последние действия (${events.length})</h4><p class="detail-footnote">Результат запроса не доказывает доступность сервиса. Для задач, принятых в работу, итог смотрите в соответствующем разделе панели.</p><div class="route-result-list">${eventHTML || `<div class="detail-empty">${audit.available === true ? 'Записанных действий пока нет.' : 'История действий недоступна.'}</div>`}</div>${allEvents.length > events.length ? '<p class="detail-footnote">Показаны 40 последних записей.</p>' : ''}</section>${technicalDetails(data)}`;
}
