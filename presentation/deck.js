/* Initialise the offline Reveal.js technical-design deck. */
const deck = new Reveal({
  hash: true,
  history: true,
  controls: true,
  controlsTutorial: false,
  progress: true,
  center: false,
  slideNumber: 'c/t',
  showSlideNumber: 'all',
  transition: 'fade',
  backgroundTransition: 'fade',
  width: 1440,
  height: 810,
  margin: 0,
  minScale: 0.2,
  maxScale: 1.6,
  pdfSeparateFragments: false,
  plugins: [RevealNotes],
});

function updateChrome(slide = deck.getCurrentSlide()) {
  document.body.dataset.slideTheme = slide?.classList.contains('light') ? 'light' : 'dark';
}

deck.on('ready', event => updateChrome(event.currentSlide));
deck.on('slidechanged', event => updateChrome(event.currentSlide));
deck.initialize();

const packetBits = 448 * 8;
const footprintValue = document.querySelector('#footprint-value');
const preservedValue = document.querySelector('#preserved-value');
const preservedCaption = document.querySelector('#preserved-caption');
const footprintFill = document.querySelector('#footprint-fill');
const buttons = [...document.querySelectorAll('[data-k]')];

function setDepth(k) {
  const footprint = Math.ceil(packetBits / k);
  const preserved = ((8 - k) / 8) * 100;
  footprintValue.textContent = footprint.toLocaleString();
  preservedValue.textContent = `${preserved.toFixed(1)}%`;
  preservedCaption.textContent = `${8 - k} of 8 bits`;
  footprintFill.style.width = `${Math.max(12.5, 100 / k)}%`;
  buttons.forEach(button => {
    const active = Number(button.dataset.k) === k;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  });
}

buttons.forEach(button => button.addEventListener('click', event => {
  event.stopPropagation();
  setDepth(Number(button.dataset.k));
}));

setDepth(1);
