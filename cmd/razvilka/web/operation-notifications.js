'use strict';

// Only callers that have confirmed completion use this success presentation.
// Errors, unknown writes and recovery keep their existing persistent notices.
const operationNotifications = { items: [], history: [], container: null, stack: null, historyButton: null, historyPanel: null };

function clearOperationNotifications() {
  for (const item of [...operationNotifications.items]) item.dismiss();
  operationNotifications.history = [];
  if (operationNotifications.historyButton) {
    operationNotifications.historyButton.hidden = true;
    operationNotifications.historyButton.setAttribute('aria-expanded', 'false');
    operationNotifications.historyPanel.hidden = true;
    operationNotifications.historyPanel.replaceChildren();
  }
}

function renderOperationNotificationHistory() {
  const { history, historyButton, historyPanel } = operationNotifications;
  historyButton.hidden = history.length === 0;
  historyButton.textContent = `Последние действия (${history.length})`;
  historyPanel.replaceChildren();
  for (const record of [...history].reverse()) {
    const row = document.createElement(record.details == null ? 'p' : 'button');
    row.className = 'operation-notification-history-row';
    row.textContent = record.title;
    if (record.details != null) {
      row.type = 'button';
      row.setAttribute('aria-label', `${record.title}: подробнее`);
      row.addEventListener('click', () => {
        if (!state.authenticated || record.auth !== (state.authGeneration || 0) || !operationNotifications.history.includes(record)) return;
        historyPanel.hidden = true;
        historyButton.setAttribute('aria-expanded', 'false');
        showDetails(record.details, record.title);
      });
    }
    historyPanel.append(row);
  }
}

function notifyOperationSuccess(title, message, details = null) {
  if (!state.authenticated) return false;
  const auth = state.authGeneration || 0;
  if (!operationNotifications.container) {
    const container = document.createElement('section');
    container.className = 'operation-notifications';
    container.setAttribute('aria-label', 'Завершённые действия');
    const stack = document.createElement('div');
    stack.className = 'operation-toast-stack';
    const historyButton = document.createElement('button');
    historyButton.type = 'button';
    historyButton.className = 'secondary operation-notification-history-toggle';
    historyButton.setAttribute('aria-expanded', 'false');
    historyButton.setAttribute('aria-controls', 'operationNotificationHistory');
    const historyPanel = document.createElement('div');
    historyPanel.id = 'operationNotificationHistory';
    historyPanel.className = 'operation-notification-history';
    historyPanel.hidden = true;
    historyButton.addEventListener('click', () => {
      if (!state.authenticated || !operationNotifications.history.length) return;
      historyPanel.hidden = !historyPanel.hidden;
      historyButton.setAttribute('aria-expanded', String(!historyPanel.hidden));
    });
    container.append(stack, historyPanel, historyButton);
    document.body.append(container);
    operationNotifications.container = container;
    Object.assign(operationNotifications, { stack, historyButton, historyPanel });
  }
  operationNotifications.history.push({ title, message, details, auth });
  while (operationNotifications.history.length > 6) operationNotifications.history.shift();
  renderOperationNotificationHistory();
  const element = document.createElement('article');
  element.className = 'operation-toast';
  const copy = document.createElement('div');
  copy.className = 'operation-toast-copy';
  copy.setAttribute('role', 'status');
  copy.setAttribute('aria-atomic', 'true');
  const heading = document.createElement('strong');
  heading.textContent = title;
  const text = document.createElement('p');
  text.textContent = message;
  copy.append(heading, text);
  const actions = document.createElement('div');
  actions.className = 'operation-toast-actions';
  const item = { element, timer: null, hovered: false, focused: false, dismissed: false };
  item.dismiss = () => {
    clearTimeout(item.timer);
    item.dismissed = true;
    element.remove();
    operationNotifications.items = operationNotifications.items.filter(row => row !== item);
  };
  const schedule = () => {
    clearTimeout(item.timer);
    if (!item.dismissed && !item.hovered && !item.focused) item.timer = setTimeout(item.dismiss, 6500);
  };
  if (details != null) {
    const more = document.createElement('button');
    more.type = 'button';
    more.className = 'secondary';
    more.textContent = 'Подробнее';
    more.addEventListener('click', () => {
      if (item.dismissed || !state.authenticated || auth !== (state.authGeneration || 0)) return;
      item.dismiss();
      showDetails(details, title);
    });
    actions.append(more);
  }
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'operation-toast-close';
  close.textContent = '×';
  close.setAttribute('aria-label', `Закрыть уведомление: ${title}`);
  close.addEventListener('click', item.dismiss);
  actions.append(close);
  element.append(copy, actions);
  element.addEventListener('mouseenter', () => { item.hovered = true; clearTimeout(item.timer); });
  element.addEventListener('mouseleave', () => { item.hovered = false; schedule(); });
  element.addEventListener('focusin', () => { item.focused = true; clearTimeout(item.timer); });
  element.addEventListener('focusout', event => {
    if (element.contains(event.relatedTarget)) return;
    item.focused = false; schedule();
  });
  operationNotifications.items.push(item);
  operationNotifications.stack.append(element);
  while (operationNotifications.items.length > 3) operationNotifications.items[0].dismiss();
  schedule();
  return true;
}

document.addEventListener('razvilka:auth-required', clearOperationNotifications);
