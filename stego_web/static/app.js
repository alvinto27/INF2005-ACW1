/* Encoding wizard controller. Cryptography and media processing remain server-side. */
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
  return true;
}

async function simulate(card, status, detail, completeStatus, completeDetail) {
  const next = card.querySelector('.next');
  next.disabled = true;
  card.classList.add('is-busy');
  status.textContent = 'Working…';
  detail.textContent = 'Preparing a secure request for the backend.';
  await new Promise(resolve => setTimeout(resolve, 650));
  status.textContent = completeStatus;
  detail.textContent = completeDetail;
  card.classList.remove('is-busy');
  next.disabled = false;
  motion.pulse(card.querySelector('.process-box'));
}

document.querySelectorAll('.next').forEach(button => button.addEventListener('click', async () => {
  if (!validCurrentCard() || transitionPending) return;
  if (currentStep === 1) await simulate(cards[1], document.querySelector('#hash-status'), document.querySelector('#hash-detail'), 'Hash initialized', 'The validated cover is ready for authoritative SHA-256 hashing.');
  if (currentStep === 2) await simulate(cards[2], document.querySelector('#payload-status'), document.querySelector('#payload-detail'), 'Payload ready', 'Required fields and custom metadata are ready for canonical serialization.');
  if (currentStep === 3) await simulate(cards[3], document.querySelector('#signature-status'), document.querySelector('#signature-detail'), 'Existing key ready', 'The backend will load this key and sign the exact payload bytes.');
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
    coverName.textContent = 'Drop a PNG or WAV here';
    coverMeta.textContent = 'Maximum size is controlled by the local server.';
    coverDrop.classList.remove('has-file', 'has-error');
    return;
  }
  const supported = /\.(png|wav)$/i.test(file.name);
  coverInput.setCustomValidity(supported ? '' : 'Choose a PNG or WAV file.');
  coverDrop.classList.toggle('has-file', supported);
  coverDrop.classList.toggle('has-error', !supported);
  coverName.textContent = file.name;
  coverMeta.textContent = supported ? `${formatBytes(file.size)} · ${file.type || 'type detected by server'}` : 'Choose a file ending in .png or .wav.';
  if (supported) {
    renderMedia(document.querySelector('#cover-preview'), URL.createObjectURL(file), file.type || (file.name.toLowerCase().endsWith('.wav') ? 'audio/wav' : 'image/png'));
    motion.pulse(coverDrop);
  }
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

const lsb = document.querySelector('#encode-lsb');
const lsbDescriptions = [
  ['Lowest visual impact', 'Best first choice when the cover has enough capacity.'],
  ['Very subtle', 'A small capacity boost with limited media changes.'],
  ['Balanced', 'More capacity while retaining relatively low distortion.'],
  ['Moderate', 'Useful for larger payloads; changes may become measurable.'],
  ['High capacity', 'Prefer only when lower settings cannot fit the packet.'],
  ['Visible risk', 'Media quality can be noticeably affected.'],
  ['Very high risk', 'Use cautiously; substantial sample or colour changes.'],
  ['Maximum capacity', 'Replaces every bit in each selected carrier unit.'],
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

document.querySelector('#derive-location').addEventListener('click', async event => {
  const button = event.currentTarget;
  const secret = document.querySelector('#start-secret');
  const status = document.querySelector('#location-status');
  if (!secret.checkValidity()) { secret.reportValidity(); return; }
  const file = coverInput.files[0];
  if (!file) { coverInput.reportValidity(); return; }
  button.disabled = true;
  status.className = 'status-box is-loading';
  status.textContent = 'Deriving with PBKDF2-HMAC-SHA256…';
  try {
    const body = new FormData();
    body.set('cover', file); body.set('start_secret', secret.value); body.set('lsb_bits', lsb.value);
    const response = await fetch('/location/derive', {method: 'POST', body});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error ?? 'Location derivation failed');
    status.className = 'status-box status-ready';
    status.textContent = `${data.algorithm}: ${data.media_type} unit ${data.start_location} of ${data.carrier_units.toLocaleString()} units.`;
    document.querySelector("[data-step='4'] .next").disabled = false;
    motion.pulse(status);
  } catch (error) {
    status.className = 'status-box verdict-error';
    status.textContent = `Error: ${error.message}`;
  } finally { button.disabled = false; }
});

document.querySelector('#generate-keys').addEventListener('click', async event => {
  const button = event.currentTarget;
  const password = encodeForm.elements.key_password;
  const resultBox = document.querySelector('#key-result');
  if (!password.checkValidity()) { password.reportValidity(); return; }
  button.disabled = true;
  resultBox.className = 'result operation-status is-loading';
  resultBox.textContent = 'Generating RSA demo keys…';
  try {
    const body = new FormData(); body.set('key_password', password.value);
    const response = await fetch('/keys/generate', {method: 'POST', body});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error ?? 'Key generation failed');
    resultBox.className = 'result key-downloads';
    resultBox.replaceChildren(downloadLink(textUrl(data.private_key_pem), 'private-key.pem', 'Download encrypted private key'), downloadLink(textUrl(data.public_key_pem), 'public-key.pem', 'Download public key'), document.createTextNode('Download the private key, then select it above.'));
    motion.stagger(resultBox.children);
  } catch (error) {
    resultBox.className = 'result verdict-error'; resultBox.textContent = `Error: ${error.message}`;
  } finally { button.disabled = false; }
});

encodeForm.addEventListener('submit', async event => {
  event.preventDefault();
  if (!validCurrentCard()) return;
  const resultBox = document.querySelector('#encode-result');
  const button = encodeForm.querySelector("[type='submit']");
  button.disabled = true;
  button.classList.add('is-loading');
  resultBox.className = 'result operation-status is-loading';
  resultBox.textContent = 'Signing payload and embedding media…';
  try {
    const response = await fetch('/encode', {method: 'POST', body: new FormData(encodeForm)});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error ?? 'Encode failed');
    const stegoUrl = base64Url(data.stego_base64, data.mime_type);
    renderMedia(document.querySelector('#stego-preview'), stegoUrl, data.mime_type);
    document.querySelector('#success-summary').textContent = `Embedded at unit ${data.start_location}; capacity ${data.capacity_bytes.toLocaleString()} bytes.`;
    document.querySelector('#download-links').replaceChildren(downloadLink(stegoUrl, data.filename, 'Download stego media'), downloadLink(textUrl(data.public_key_pem), 'public-key.pem', 'Download public key'));
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
  handleCoverFile(null);
  document.querySelector('#location-status').textContent = 'No location derived yet.';
  document.querySelector('#location-status').className = 'status-box';
  document.querySelector("[data-step='4'] .next").disabled = true;
  document.querySelector('#stego-preview').textContent = 'Awaiting encode';
  document.querySelector('#download-links').replaceChildren();
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
function base64Url(value, mime) {
  const bytes = Uint8Array.from(atob(value), character => character.charCodeAt(0));
  return URL.createObjectURL(new Blob([bytes], {type: mime}));
}
function textUrl(value) { return URL.createObjectURL(new Blob([value], {type: 'application/x-pem-file'})); }
function downloadLink(url, filename, label) {
  const link = document.createElement('a'); link.href = url; link.download = filename; link.textContent = label; return link;
}

updateLsb();
showStep(0, {initial: true});
