/* Minimal progressive enhancement. Never sends demo tokens off origin. */
'use strict';
document.addEventListener('click', async function (event) {
  const button = event.target.closest('button[data-copy]');
  if (!button) return;
  const value = button.dataset.copy;
  if (!value || value.length > 200) return;
  try {
    await navigator.clipboard.writeText(value);
    const previous = button.textContent;
    button.textContent = 'Copied!';
    window.setTimeout(() => { button.textContent = previous; }, 1400);
  } catch (_error) {
    button.textContent = 'Select text';
  }
});
