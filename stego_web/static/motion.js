/* Progressive motion layer. The app remains fully usable if GSAP is unavailable. */
(() => {
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const available = () => Boolean(window.gsap) && !reducedMotion.matches;

  function reveal(targets, options = {}) {
    if (!available() || !targets) return;
    const nodes = typeof targets === 'string' ? document.querySelectorAll(targets) : targets;
    window.gsap.fromTo(nodes,
      {autoAlpha: 0, y: options.y ?? 18},
      {autoAlpha: 1, y: 0, duration: options.duration ?? 0.65,
        stagger: options.stagger ?? 0, ease: options.ease ?? 'power3.out', clearProps: 'transform,opacity,visibility'});
  }

  function transitionCard(previous, next, activate, direction = 1) {
    if (!available() || !previous || previous === next) {
      activate();
      reveal(next, {y: 12, duration: 0.4});
      return Promise.resolve();
    }
    return new Promise(resolve => {
      const timeline = window.gsap.timeline({onComplete: resolve});
      timeline.to(previous, {autoAlpha: 0, x: -24 * direction, duration: 0.2, ease: 'power2.in'})
        .add(() => {
          activate();
          window.gsap.set(next, {autoAlpha: 0, x: 30 * direction});
        })
        .to(next, {autoAlpha: 1, x: 0, duration: 0.48, ease: 'power3.out'})
        .set(next, {clearProps: 'transform,opacity,visibility'});
    });
  }

  function progress(element, percent) {
    if (!available()) {
      element.style.width = `${percent}%`;
      return;
    }
    window.gsap.to(element, {width: `${percent}%`, duration: 0.55, ease: 'power2.out', overwrite: true});
  }

  function pulse(element) {
    if (!available() || !element) return;
    window.gsap.fromTo(element, {scale: 0.985}, {scale: 1, duration: 0.5, ease: 'back.out(2)', clearProps: 'transform'});
  }

  function success(container) {
    if (!available() || !container) return;
    const timeline = window.gsap.timeline();
    timeline.fromTo(container.querySelector('.success-mark'), {autoAlpha: 0, scale: 0.4, rotate: -12},
      {autoAlpha: 1, scale: 1, rotate: 0, duration: 0.6, ease: 'back.out(2.2)'})
      .from(container.querySelectorAll('.comparison figure, .download-links a, #start-over'),
        {autoAlpha: 0, y: 16, duration: 0.42, stagger: 0.08, ease: 'power2.out'}, '-=0.25');
  }

  function stagger(targets) {
    if (!available()) return;
    window.gsap.from(targets, {autoAlpha: 0, y: 10, duration: 0.42, stagger: 0.045, ease: 'power2.out'});
  }

  function intro() {
    if (!available()) return;
    const timeline = window.gsap.timeline({defaults: {ease: 'power3.out'}});
    timeline.from('.brand-row', {autoAlpha: 0, y: -12, duration: 0.45})
      .from('.hero-copy > *', {autoAlpha: 0, y: 24, duration: 0.6, stagger: 0.08}, '-=0.15')
      .from('.wizard-shell', {autoAlpha: 0, y: 28, duration: 0.7}, '-=0.25')
      .from('.decode-panel', {autoAlpha: 0, y: 18, duration: 0.5}, '-=0.4');
  }

  window.StegoMotion = {available, intro, progress, pulse, reveal, stagger, success, transitionCard};
  intro();
})();
