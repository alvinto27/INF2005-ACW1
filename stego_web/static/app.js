/* Encoding wizard for the receiver-gated protocol. Processing remains server-side. */
const encodeForm = document.querySelector('#encode-form');
const cards = [...document.querySelectorAll('.wizard-card')];
const stepMarkers = [...document.querySelectorAll('[data-step-marker]')];
const progress = document.querySelector('.progress');
const progressBar = document.querySelector('#progress-bar');
const stepCount = document.querySelector('#step-count');
const coverInput = document.querySelector('#cover-input');
const coverDrop = document.querySelector('#cover-drop');
const coverName = document.querySelector('#cover-name');
const coverMeta = document.querySelector('#cover-meta');
const payloadFile = document.querySelector('#payload-file');
const secretMessage = document.querySelector('#secret-message');
const payloadMime = document.querySelector('#payload-mime');
const payloadName = document.querySelector('#payload-name');
const motion = window.StegoMotion;
let currentStep = 0;
let transitionPending = false;

function activateStep(step) {
  cards.forEach((card, index) => {
    const active = index === step;
    card.hidden = !active;
    card.classList.toggle('is-active', active);
  });
}

function updateStepChrome(step) {
  const humanStep = step + 1;
  stepCount.textContent = `Step ${humanStep} of ${cards.length}`;
  progress.setAttribute('aria-valuenow', String(humanStep));
  progress.setAttribute('aria-valuetext', `Step ${humanStep} of ${cards.length}`);
  motion.progress(progressBar, (humanStep / cards.length) * 100);
  stepMarkers.forEach((marker, index) => {
    marker.classList.toggle('is-active', index === step);
    marker.classList.toggle('is-complete', index < step);
    if (index === step) marker.setAttribute('aria-current', 'step');
    else marker.removeAttribute('aria-current');
  });
}

async function showStep(nextStep, {initial = false} = {}) {
  const targetStep = Math.min(cards.length - 1, Math.max(0, nextStep));
  if (transitionPending || (!initial && targetStep === currentStep)) return;
  transitionPending = true;
  const previousStep = currentStep;
  const previous = cards[previousStep];
  const next = cards[targetStep];
  currentStep = targetStep;
  updateStepChrome(targetStep);
  if (initial) {
    activateStep(targetStep);
    motion.reveal(next, {y: 12, duration: 0.4});
  } else {
    await motion.transitionCard(previous, next, () => activateStep(targetStep), targetStep > previousStep ? 1 : -1);
  }
  transitionPending = false;
  next.querySelector('[tabindex="0"], input, textarea, button')?.focus({preventScroll: true});
  if (targetStep === cards.length - 1) motion.success(next);
}

function validCurrentCard() {
  for (const field of cards[currentStep].querySelectorAll('[required]')) {
    if (!field.checkValidity()) {
      field.reportValidity();
      motion.pulse(field.closest('label') || field);
      return false;
    }
  }
  if (currentStep === 0) {
    const hasMessage = Boolean(secretMessage.value.trim());
    const hasFile = Boolean(payloadFile.files[0]);
    if (hasMessage === hasFile) {
      const message = hasMessage
        ? 'Choose either a secret message or a payload file, not both.'
        : 'Enter a secret message or choose a payload file.';
      secretMessage.setCustomValidity(message);
      secretMessage.reportValidity();
      motion.pulse(secretMessage.closest('label'));
      return false;
    }
  }
  secretMessage.setCustomValidity('');
  return true;
}

document.querySelectorAll('.next').forEach(button => button.addEventListener('click', async () => {
  if (!validCurrentCard() || transitionPending) return;
  if (currentStep === 4) {
    const card = cards[4];
    const status = document.querySelector('#hash-status');
    const detail = document.querySelector('#hash-detail');
    button.disabled = true;
    card.classList.add('is-busy');
    status.textContent = 'Preparing integrity context...';
    detail.textContent = 'The server will bind the layout and all declared media sample bytes during encoding.';
    await new Promise(resolve => setTimeout(resolve, 450));
    status.textContent = 'Integrity inputs ready';
    detail.textContent = 'The full media SHA-256 hash will be encrypted inside the signed record.';
    card.classList.remove('is-busy');
    button.disabled = false;
    motion.pulse(card.querySelector('.process-box'));
  }
  await showStep(currentStep + 1);
}));

document.querySelectorAll('.back').forEach(button => button.addEventListener('click', async () => {
  await showStep(currentStep - 1);
}));

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}

function handleCoverFile(file) {
  if (!file) {
    coverInput.setCustomValidity('');
    coverName.textContent = 'Drop an image or audio file here';
    coverMeta.textContent = 'Maximum request size is controlled by the local server.';
    coverDrop.classList.remove('has-file', 'has-error');
    return;
  }
  coverInput.setCustomValidity('');
  coverDrop.classList.add('has-file');
  coverDrop.classList.remove('has-error');
  coverName.textContent = file.name;
  coverMeta.textContent = `${formatBytes(file.size)} - ${file.type || 'type detected by server'}`;
  const audioSource = /\.(wav|mp3|aac|m4a|flac|ogg|oga|opus)$/i.test(file.name);
  const previewMime = file.type || (audioSource ? 'audio/wav' : 'image/png');
  renderMedia(document.querySelector('#cover-preview'), URL.createObjectURL(file), previewMime);
  motion.pulse(coverDrop);
}

coverInput.addEventListener('change', event => handleCoverFile(event.target.files[0]));
coverDrop.addEventListener('keydown', event => {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    coverInput.click();
  }
});
['dragenter', 'dragover'].forEach(name => coverDrop.addEventListener(name, event => {
  event.preventDefault();
  coverDrop.classList.add('is-dragging');
}));
['dragleave', 'drop'].forEach(name => coverDrop.addEventListener(name, event => {
  event.preventDefault();
  coverDrop.classList.remove('is-dragging');
}));
coverDrop.addEventListener('drop', event => {
  const file = event.dataTransfer.files[0];
  if (!file) return;
  const transfer = new DataTransfer();
  transfer.items.add(file);
  coverInput.files = transfer.files;
  handleCoverFile(file);
});

const payloadMimeByExtension = {
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
  webp: 'image/webp', avif: 'image/avif', bmp: 'image/bmp', wav: 'audio/wav',
  wave: 'audio/wav', mp3: 'audio/mpeg', flac: 'audio/flac', opus: 'audio/ogg', m4a: 'audio/mp4',
  m4b: 'audio/mp4', aac: 'audio/mp4', mp4: 'video/mp4', m4v: 'video/mp4',
  ogv: 'video/ogg', mkv: 'video/x-matroska', svg: 'image/svg+xml', pdf: 'application/pdf',
};

function safePayloadName(name) {
  const basename = name.replace(/\\/g, '/').split('/').pop().trim();
  return basename.replace(/[^A-Za-z0-9._ -]/g, '_').replace(/^[. ]+/, '').slice(0, 120)
    || 'recovered-payload.bin';
}

function updatePayloadClaims() {
  const file = payloadFile.files[0];
  if (secretMessage.value.trim()) {
    payloadMime.value = 'text/plain';
    payloadName.value = 'message.txt';
  } else if (file) {
    const extension = file.name.split('.').pop().toLowerCase();
    const suppliedMime = file.type.toLowerCase();
    const ambiguousMime = {
      ogg: ['audio/ogg', 'video/ogg'], oga: ['audio/ogg'],
      webm: ['audio/webm', 'video/webm'],
    };
    const fallbackMime = extension === 'webm' ? 'video/webm'
      : ['ogg', 'oga'].includes(extension) ? 'audio/ogg'
        : payloadMimeByExtension[extension] || suppliedMime || 'application/octet-stream';
    const mime = ambiguousMime[extension]?.includes(suppliedMime)
      ? suppliedMime
      : fallbackMime;
    payloadMime.value = mime;
    payloadName.value = safePayloadName(file.name);
  } else {
    payloadMime.value = '';
    payloadName.value = '';
  }
}

payloadFile.addEventListener('change', () => {
  secretMessage.setCustomValidity('');
  updatePayloadClaims();
});
secretMessage.addEventListener('input', () => {
  secretMessage.setCustomValidity('');
  updatePayloadClaims();
});

const lsb = document.querySelector('#encode-lsb');
const lsbDescriptions = [
  ['Lowest visual impact', 'Best first choice when the cover has enough capacity.'],
  ['Very subtle', 'A small capacity boost with limited media changes.'],
  ['Balanced', 'More capacity while retaining relatively low distortion.'],
  ['Moderate', 'Useful for larger payloads; changes may become measurable.'],
  ['High capacity', 'Prefer only when lower settings cannot fit the packet.'],
  ['Visible risk', 'Media quality can be noticeably affected.'],
  ['Very high risk', 'Use cautiously; substantial sample or colour changes.'],
  ['Maximum capacity', 'Replaces every bit in each packet-region carrier unit.'],
];
function updateLsb() {
  const value = Number(lsb.value);
  document.querySelector('#encode-lsb-output').value = String(value);
  document.querySelector('#lsb-impact').textContent = lsbDescriptions[value - 1][0];
  document.querySelector('#lsb-guidance').textContent = lsbDescriptions[value - 1][1];
  lsb.style.setProperty('--range-progress', `${((value - 1) / 7) * 100}%`);
  lsb.setAttribute('aria-valuetext', `${value} least significant bit${value === 1 ? '' : 's'}: ${lsbDescriptions[value - 1][0]}`);
}
lsb.addEventListener('input', updateLsb);

document.querySelectorAll('.generate-keys').forEach(button => button.addEventListener('click', async () => {
  const role = button.dataset.role;
  const password = document.querySelector(`#${button.dataset.password}`);
  const resultBox = document.querySelector(`#${button.dataset.result}`);
  if (!password.value || password.value.length < 8) {
    password.setCustomValidity('Use at least 8 characters to encrypt the generated private key.');
    password.reportValidity();
    return;
  }
  password.setCustomValidity('');
  button.disabled = true;
  resultBox.className = 'result operation-status is-loading';
  resultBox.textContent = `Generating ${role} RSA keys...`;
  try {
    const body = new FormData();
    body.set('role', role); body.set('key_password', password.value);
    const response = await fetch('/keys/generate', {method: 'POST', body});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error ?? 'Key generation failed');
    resultBox.className = 'result key-downloads';
    resultBox.replaceChildren(
      downloadLink(textUrl(data.private_key_pem), `${role}-private-key.pem`, `Download ${role} private key`),
      downloadLink(textUrl(data.public_key_pem), `${role}-public-key.pem`, `Download ${role} public key`),
      document.createTextNode(` Keep the ${role} private key confidential.`),
    );
    motion.stagger(resultBox.children);
  } catch (error) {
    resultBox.className = 'result verdict-error'; resultBox.textContent = `Error: ${error.message}`;
  } finally { button.disabled = false; }
}));

encodeForm.addEventListener('submit', async event => {
  event.preventDefault();
  const resultBox = document.querySelector('#encode-result');
  const button = encodeForm.querySelector("[type='submit']");
  button.disabled = true;
  button.classList.add('is-loading');
  resultBox.className = 'result operation-status is-loading';
  resultBox.textContent = 'Hashing, encrypting, signing, and embedding payload...';
  try {
    const response = await fetch('/encode', {method: 'POST', body: new FormData(encodeForm)});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error ?? 'Encode failed');
    const stegoUrl = data.stego_url;
    renderMedia(document.querySelector('#stego-preview'), stegoUrl, data.mime_type);
    const preserved = (data.preserved_ratio * 100).toFixed(4);
    const formatLabels = {
      jpeg: 'JPEG', webp: 'WebP', avif: 'AVIF', bmp: 'BMP', tiff: 'TIFF', gif: 'GIF',
      png: 'PNG', wav: 'WAV', mp3: 'MP3', aac: 'AAC', m4a: 'M4A', flac: 'FLAC',
      alac: 'ALAC', 'ogg-vorbis': 'Ogg Vorbis', 'ogg-opus': 'Ogg Opus',
    };
    const sourceNote = data.source_converted
      ? ` Your ${formatLabels[data.source_format] || data.source_format.toUpperCase()} source was converted to a lossless ${data.media_type === 'image' ? 'PNG' : 'WAV'} before embedding.`
      : '';
    const sealedClaim = ` Sealed payload claim: ${data.payload.name} (${data.payload.mime}).`;
    document.querySelector('#success-summary').textContent = `Protocol v${data.protocol_version}: packet starts at unit ${data.start_location}, uses ${data.lsb_bits} LSB, and preserves ${preserved}% of carrier bits.${sealedClaim}${sourceNote}`;
    document.querySelector('#download-links').replaceChildren(
      downloadLink(stegoUrl, data.filename, 'Download stego media'),
      downloadLink(textUrl(data.sender_public_key_pem), 'sender-public-key.pem', 'Download sender public key'),
    );
    resultBox.textContent = '';
    await showStep(6);
  } catch (error) {
    resultBox.className = 'result verdict-error'; resultBox.textContent = `Error: ${error.message}`;
    motion.pulse(resultBox);
  } finally {
    button.disabled = false;
    button.classList.remove('is-loading');
  }
});

document.querySelector('#start-over').addEventListener('click', async () => {
  encodeForm.reset();
  updatePayloadClaims();
  handleCoverFile(null);
  document.querySelector('#stego-preview').textContent = 'Awaiting encode';
  document.querySelector('#download-links').replaceChildren();
  document.querySelector('#start-unit').value = '2048';
  updateLsb();
  await showStep(0);
});

function renderMedia(container, url, mime) {
  const isAudio = mime.startsWith('audio/');
  const element = document.createElement(isAudio ? 'audio' : 'img');
  element.src = url;
  element.controls = isAudio;
  element.alt = 'Media preview';
  container.replaceChildren(element);
}
function textUrl(value) { return URL.createObjectURL(new Blob([value], {type: 'application/x-pem-file'})); }
function downloadLink(url, filename, label) {
  const link = document.createElement('a'); link.href = url; link.download = filename; link.textContent = label; return link;
}

updateLsb();
showStep(0, {initial: true});
