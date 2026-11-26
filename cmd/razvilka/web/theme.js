/* Apply the saved appearance before styles paint. No network or account data. */
(function () {
  'use strict';
  const key = 'razvilka.interface.theme';
  const normalize = value => value === 'light' ? 'light' : 'dark';
  function apply(value, persist = false) {
    const theme = normalize(value);
    document.documentElement.dataset.theme = theme;
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', theme === 'dark' ? '#0c121b' : '#f5f6f8');
    if (persist) {
      try { localStorage.setItem(key, theme); } catch (_) { /* Private browsing may forbid storage. */ }
    }
    return theme;
  }
  let saved;
  try { saved = localStorage.getItem(key); } catch (_) { /* Dark is also the offline fallback. */ }
  apply(saved);
  window.RazvilkaTheme = Object.freeze({ apply });
})();
