// Only this non-sensitive preference is persisted. Tokens and evidence never enter storage.
(() => {
  'use strict';
  const key = 'kan.theme';
  const valid = value => ['system', 'light', 'dark'].includes(value);
  const platform = window.matchMedia('(prefers-color-scheme: dark)');
  let choice = 'system';
  try { const saved = localStorage.getItem(key); if (valid(saved)) choice = saved; } catch (_) { /* storage may be disabled */ }
  function apply() {
    document.documentElement.dataset.theme = choice === 'system' ? (platform.matches ? 'dark' : 'light') : choice;
    const control = document.getElementById('theme');
    if (control) control.value = choice;
  }
  apply();
  platform.addEventListener('change', apply);
  window.addEventListener('storage', event => {
    if (event.key === key || event.key === null) {
      choice = valid(event.newValue) ? event.newValue : 'system';
      apply();
    }
  });
  document.addEventListener('DOMContentLoaded', () => {
    const control = document.getElementById('theme');
    if (!control) return;
    control.value = choice;
    control.addEventListener('change', () => {
      choice = valid(control.value) ? control.value : 'system';
      try { if (choice === 'system') localStorage.removeItem(key); else localStorage.setItem(key, choice); } catch (_) { /* tab-local fallback */ }
      apply();
    });
  });
})();
