/* A small page transition for the two local workflows. Native navigation remains the fallback. */
(() => {
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  let leaving = false;

  document.addEventListener('click', event => {
    const link = event.target.closest('a[href]');
    if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey
        || event.ctrlKey || event.shiftKey || event.altKey || reducedMotion.matches
        || link.hasAttribute('download') || link.target === '_blank') return;
    const destination = new URL(link.href);
    if (destination.origin !== location.origin || destination.pathname === location.pathname) return;
    event.preventDefault();
    if (leaving) return;
    leaving = true;
    document.body.classList.add('page-leaving');
    window.setTimeout(() => location.assign(destination.href), 190);
  });

  window.addEventListener('pageshow', () => {
    leaving = false;
    document.body.classList.remove('page-leaving');
  });
})();
