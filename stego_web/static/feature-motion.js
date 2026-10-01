/* Reveal the four protocol diagrams when they enter the viewport. */
(() => {
  const diagrams = document.querySelectorAll('.feature-grid .feature');
  if (!diagrams.length) return;

  if (!('IntersectionObserver' in window) || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    diagrams.forEach(diagram => diagram.classList.add('is-in-view'));
    return;
  }

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add('is-in-view');
      observer.unobserve(entry.target);
    });
  }, {threshold: 0.2});

  diagrams.forEach(diagram => observer.observe(diagram));
})();
