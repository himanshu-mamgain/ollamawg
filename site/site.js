'use strict';
// Install tabs (preselected for the visitor's OS) and copy buttons.

const tabs = [...document.querySelectorAll('#hero-install [data-os]')];
function pick(os) {
  tabs.forEach(t => t.setAttribute('aria-selected', String(t.dataset.os === os)));
  document.querySelectorAll('#hero-install .cmd').forEach(c => { c.hidden = c.dataset.for !== os; });
}
tabs.forEach(t => t.addEventListener('click', () => pick(t.dataset.os)));
if (/Windows/i.test(navigator.userAgent)) pick('win');

document.addEventListener('click', async e => {
  const b = e.target.closest('.copy');
  if (!b) return;
  const text = b.parentElement.querySelector('code').textContent;
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch { /* insecure context or denied */ }
  b.textContent = ok ? 'Copied' : 'Select and copy';
  setTimeout(() => { b.textContent = 'Copy'; }, 1600);
});
