import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const read = file => readFileSync(new URL('../' + file, import.meta.url), 'utf8');
const app = read('cmd/razvilka/web/app.js');
const source = read('cmd/razvilka/web/project-log.js');
const html = read('cmd/razvilka/web/index.html');
const esc = value => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
const context = vm.createContext({ esc, timeAgo: () => 'сейчас', technicalDetails: value => `<details class="technical-details"><pre>${esc(JSON.stringify(value))}</pre></details>` });
vm.runInContext(source, context);
const healthy = { detail_kind: 'project-log', control: { config_revision: 2, runtime_state: 'running', running: true, safe_mode: false, mode: 'auto' }, audit: { available: true, events: [] } };
const render = value => context.renderProjectLogDetails(value);
const visible = value => render(value).split('<details class="technical-details">')[0];

let out = visible(healthy);
assert.match(out, /Обходы включены/);
assert.match(out, /Автопилот/);
assert.match(out, /Записанных действий пока нет/);
assert.doesNotMatch(out, /Операция завершена|Что требует внимания/);
assert.match(visible({ ...healthy, control: { ...healthy.control, running: false, runtime_state: 'stopped', safe_mode: true, mode: 'manual' } }), /Обходы выключены[\s\S]*Ручная настройка[\s\S]*применение маршрутов запрещено/);
assert.match(visible({ ...healthy, control: { ...healthy.control, runtime_state: 'unknown' } }), /Состояние не получено/);
assert.doesNotMatch(visible({ ...healthy, control: { ...healthy.control, runtime_state: 'unknown' } }), /Обходы включены/);
out = visible({ ...healthy, control: { ...healthy.control, running: false, runtime_state: 'unknown', runtime_issue: { code: 'TIMEOUT', message: 'Проверка состояния не завершилась вовремя.' } } });
assert.match(out, /Проверка состояния не завершилась вовремя/);
assert.doesNotMatch(out, /Обходы включены/);
out = visible({ ...healthy, control: { runtime_state: 'unknown', runtime_issue: { message: '<script>unsafe()</script>' } } });
assert.doesNotMatch(out, /<script>/);
assert.match(out, /&lt;script&gt;/);

out = visible({ ...healthy, load_issues: [{ section: 'engineConfigs', message: 'Настройки не загрузились' }], component_issues: [{ id: 'Sing-box', message: 'Источник пакетов недоступен' }], last_action_error: 'Маршрут не подтверждён' });
for (const text of ['Есть сообщения, требующие внимания', 'Настройки обходов', 'Настройки не загрузились', 'Обход: Sing-box', 'Источник пакетов недоступен', 'Маршрут не подтверждён']) assert.ok(out.includes(text), text);
assert.doesNotMatch(out, /Операция завершена|detail-hero pass/);

out = visible({ ...healthy, audit: { available: false, last_error: 'Журнал не читается', events: [{ path: '/api/v1/auth/login', action: 'POST', outcome: 'ok', status_code: 200 }] } });
assert.match(out, /Журнал не читается/);
assert.match(out, /Вход в панель/);
assert.doesNotMatch(out, /Записанных действий пока нет/);

const failed = { timestamp: '2026-09-20T13:01:00Z', path: '/api/v1/components/usque/update', action: 'POST', outcome: 'failed', status_code: 502 };
const accepted = { timestamp: '2026-09-20T13:02:00Z', path: '/api/v1/node-checks', action: 'POST', outcome: 'ok', status_code: 202, duration_ms: 23 };
assert.match(context.renderProjectAuditRow(accepted), /Принято в работу/);
assert.doesNotMatch(context.renderProjectAuditRow(accepted), /audit-row ok|выполнено/);
assert.match(context.renderProjectAuditRow(failed), /audit-row failed/);
assert.doesNotMatch(context.renderProjectAuditRow({ ...accepted, actor: '<script>x</script>' }), /<script>/);
assert.match(visible({ ...healthy, audit: { available: true, memory_only: true, history_complete: false, events: [] } }), /Предыдущую историю пока не удалось прочитать/);
const logged = { ...healthy, audit: { available: true, events: [failed, accepted] } };
out = visible(logged);
assert.match(out, /В последних действиях есть ошибки/);
assert.match(out, /Обновление: WARP · MASQUE/);
assert.match(out, /Принято в работу/);
assert.match(out, /Завершение задачи и её результат проверяются отдельно/);
assert.ok(out.indexOf('Проверка подключений') < out.indexOf('Обновление: WARP'), 'events must be newest first');
assert.equal(logged.audit.events[0], failed, 'rendering must not reorder the caller snapshot');
assert.equal(context.projectLogEventResult({ outcome: 'ok', status_code: 500 }).tone, 'fail', 'HTTP failure wins over a conflicting outcome');
assert.equal(context.projectLogEventResult({ outcome: 'failed', status_code: 202 }).tone, 'fail', 'failure wins over accepted');
assert.equal(context.projectLogEventResult({ outcome: 'denied', status_code: 403 }).label, 'Доступ отклонён');
assert.equal(context.projectLogEventResult({ outcome: 'unknown', status_code: 200 }).label, 'Результат не указан');
assert.equal(context.projectLogAction({ path: '/api/v1/service-control/runtime' }), 'Включение или остановка обходов');

const payload = '<img src=x onerror="alert(1)">';
out = render({ ...healthy, load_issues: [{ section: payload, message: payload }], component_issues: [{ id: payload, message: payload }], last_action_error: payload, audit: { available: false, last_error: payload, events: [{ path: `/api/v1/components/${payload}/remove`, action: payload, outcome: payload, timestamp: payload, status_code: payload, duration_ms: payload }] } });
assert.doesNotMatch(out, /<img|<script|class="[^">]*onerror/);
assert.ok(out.includes('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;'));
assert.doesNotMatch(out, /Invalid Date|NaN мс/);
for (const malformed of [null, {}, { load_issues: 'bad', component_issues: [null, 2, []], audit: { events: [null, false, []] } }]) {
  out = visible(malformed);
  assert.match(out, /Состояние не получено/);
  assert.doesNotMatch(out, /Операция завершена/);
}
out = visible({ ...healthy, audit: { available: true, events: Array.from({ length: 60 }, (_, i) => ({ ...accepted, timestamp: new Date(100000 + i * 1000).toISOString() })) } });
assert.equal((out.match(/<article /g) || []).length, 40);
assert.match(out, /Показаны 40 последних записей/);

out = visible({ ...healthy, jobs: [
  { id: 1, mode: 'service-stop', state: 'queued', message: 'Ждём очистки' },
  { id: 2, mode: 'service-resume', state: 'failed', message: 'Настройки изменились', finished_at: '2026-09-23T12:00:00Z' },
  { id: 3, mode: 'service-check', state: 'completed', message: payload },
] });
assert.match(out, /Задания на роутере/);
assert.match(out, /Остановка проекта/); assert.match(out, /В очереди/);
assert.match(out, /Включение проекта/); assert.match(out, /Настройки изменились/);
assert.doesNotMatch(out, /<img|Invalid Date/);
out = visible({ ...healthy, jobs: Array.from({ length: 64 }, () => ({ mode: 'service-stop', state: 'completed', message: 'done' })) });
assert.equal((out.match(/<article /g) || []).length, 12, 'job history is bounded');

const slice = (start, end) => {
  const from = app.indexOf(start), to = app.indexOf(end, from + start.length);
  assert.ok(from >= 0 && to > from);
  return app.slice(from, to);
};
const nodes = new Map();
const element = selector => {
  if (selector === '#details [data-open-strategy-lab]') return null;
  if (!nodes.has(selector)) nodes.set(selector, { innerHTML: '', textContent: '', classList: { add() {} } });
  return nodes.get(selector);
};
context.$ = element;
context.renderGenericDetails = () => 'generic';
vm.runInContext(slice('function showDetails(', 'function showNotice('), context);
context.showDetails(logged, 'Лог проекта');
assert.match(element('#details').innerHTML, /Принято в работу/);
assert.equal(element('.drawer-head h3').textContent, 'Лог проекта');
assert.match(element('#detailsSubtitle').textContent, /причины ошибок/);
context.showDetails('ordinary result');
assert.equal(element('#details').innerHTML, 'generic');
assert.ok(html.indexOf('/project-log.js?') < html.indexOf('/app.js?'), 'renderer loads before app can call it');
assert.ok(html.includes('/project-log.js?v=' + read('VERSION').trim()), 'renderer asset must use the current release version');

// Escape on a reused confirmation dialog must never repeat an earlier approval.
const dialog = Object.assign(new EventTarget(), {
  returnValue: 'confirm', open: false,
  showModal() { this.open = true; },
  closeListener() { this.open = false; this.dispatchEvent(new Event('close')); },
  close(value = '') { this.returnValue = value; this.closeListener(); }
});
const confirmation = vm.createContext({ document: new EventTarget(), $: selector => selector === '#actionDialog' ? dialog : { textContent: '' } });
vm.runInContext(slice('function askConfirmation(', 'function applyStateText('), confirmation);
const confirmed = confirmation.askConfirmation('Удаление', 'Проверить', 'Удалить');
assert.equal(dialog.returnValue, '');
dialog.returnValue = 'confirm'; dialog.closeListener();
assert.equal(await confirmed, true);
const cancelled = confirmation.askConfirmation('Удаление', 'Проверить', 'Удалить');
assert.equal(dialog.returnValue, '');
dialog.closeListener(); // Native Escape closes without changing returnValue.
assert.equal(await cancelled, false);

console.log('PASS project log: readable issues/events, honest request outcomes, ordering/bounds, escaping, drawer integration and confirmation reuse');
