(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const dialog = byId('installLogDialog');
  const reopen = byId('installLogOpen');
  let current;

  function show() {
    if (current && !dialog.open) dialog.showModal();
  }
  reopen.addEventListener('click', show);
  function reset() {
    const previous = current;
    current = null;
    clearInterval(previous?.timer);
    previous?.controller.abort();
    if (dialog.open) dialog.close();
    reopen.hidden = true;
    for (const id of ['installLogTitle', 'installLogLines', 'installLogTime', 'installLogStatus']) byId(id).textContent = '';
  }
  document.addEventListener('razvilka:auth-required', reset);

  function begin(name, initialMessage = 'Читаем план установки на роутере…') {
    reset();
    const started = Date.now();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    const headers = { 'X-Razvilka-Install-ID': Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('') };
    const op = { controller: new AbortController(), timer: null };
    current = op;
    let sent = 0, ended = 0, pending = null, lastReply = 0;
    let stage = initialMessage, events = [], notes = [];
    function render() {
      if (current !== op) return;
      const now = ended || Date.now();
      byId('installLogTime').textContent = 'Прошло: ' + Math.floor((now - started) / 1000) + ' с';
      let status = stage;
      if (sent && !ended && !notes.length && now - (lastReply || sent) >= 7000)
        status = 'Давно нет ответа от роутера. Ожидаем результат установки…';
      else if (sent && !ended && !notes.length && lastReply)
        status = 'Роутер отвечает. Ожидаем следующий этап установки…';
      if (byId('installLogStatus').textContent !== status) byId('installLogStatus').textContent = status;
      const lines = [{ at: started, message: initialMessage }, ...events, ...notes];
      const output = lines.map(e => new Date(e.at).toLocaleTimeString('ru-RU') + '  ' + e.message).join('\n');
      const pre = byId('installLogLines');
      if (pre.textContent !== output) {
        const atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 4;
        pre.textContent = output;
        if (atBottom) pre.scrollTop = pre.scrollHeight;
      }
    }
    function poll() {
      if (pending || current !== op) return pending;
      pending = api('/api/v1/components/install-progress', { headers, cache: 'no-store', readTimeoutMs: 3500, signal: op.controller.signal })
        .then(report => {
          if (current !== op || !Array.isArray(report?.events)) return;
          events = report.events.slice(-32).filter(e => Number.isFinite(Date.parse(e?.at)) && typeof e.message === 'string' && e.message.length <= 512);
          lastReply = Date.now();
          render();
        }).catch(() => {}).finally(() => { pending = null; });
      return pending;
    }
    byId('installLogTitle').textContent = 'Установка · ' + name;
    reopen.hidden = false;
    op.timer = setInterval(() => { render(); if (sent && !ended) void poll(); }, 1500);
    render();
    show();
    return {
      headers,
      sent() { sent = Date.now(); stage = 'Запрос отправлен. Ждём сообщения установщика…'; render(); },
      note(message) {
        if (ended) return;
        stage = message;
        notes.push({ at: Date.now(), message });
        render();
      },
      finish(message) {
        if (ended || current !== op) return;
        ended = Date.now();
        notes.push({ at: ended, message });
        stage = message;
        clearInterval(op.timer);
        render();
        if (sent) void Promise.resolve(pending).then(() => { if (current === op) void poll(); });
      }
    };
  }
  globalThis.RazvilkaInstallLog = { begin, show };
})();
