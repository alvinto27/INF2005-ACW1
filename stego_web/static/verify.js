/* Verify/Decode UI. Cryptography, extraction, and verdicts stay in Python. */
(() => {
  const form = document.querySelector('#decode-form');
  const panel = document.querySelector('#verify-panel');
  const progress = document.querySelector('#decode-progress');
  const result = document.querySelector('#decode-result');
  const submit = form.querySelector('button[type="submit"]');
  const motion = window.StegoMotion;

  function openPanel() {
    panel.open = true;
    document.querySelectorAll('.workflow-nav a').forEach(link => link.classList.toggle('is-current', link.id === 'open-verify'));
    window.requestAnimationFrame(() => motion.reveal([panel.querySelector('.decode-intro'), form], {y: 14, stagger: .08}));
  }
  document.querySelector('#open-verify').addEventListener('click', openPanel);
  document.querySelector('.brand-mark').addEventListener('click', () => {
    document.querySelectorAll('.workflow-nav a').forEach(link => link.classList.toggle('is-current', link.id !== 'open-verify'));
  });
  document.querySelector('.workflow-nav a[href="#encode-title"]').addEventListener('click', () => {
    document.querySelectorAll('.workflow-nav a').forEach(link => link.classList.toggle('is-current', link.id !== 'open-verify'));
  });
  if (location.hash === '#verify-panel') openPanel();

  form.elements.media_type.addEventListener('change', () => {
    form.elements.stego.accept = {image: '.png,image/png', audio: '.wav,audio/wav',
      auto: '.png,.wav,image/png,audio/wav'}[form.elements.media_type.value];
  });
  form.addEventListener('input', () => { result.hidden = true; progress.textContent = ''; });

  function element(tag, text) {
    const node = document.createElement(tag);
    node.textContent = text;
    return node;
  }

  function fields(entries) {
    const list = document.createElement('dl');
    list.className = 'verification-fields';
    for (const [name, value] of entries) {
      list.append(element('dt', name), element('dd', value ?? 'Not available'));
    }
    return list;
  }

  const check = (value, yes, no) => value === true ? yes : value === false ? no : 'Not checked';

  function render(data) {
    const verdict = data.verdict || 'Cannot Verify';
    result.className = 'result verification-result';
    result.dataset.verdict = verdict;
    result.hidden = false;
    result.replaceChildren(element('h3', `Status: ${verdict}`),
      element('p', data.message || data.error || 'The server could not complete verification.'));
    result.append(fields([
      ['Payload', data.payload_extracted ? 'Successfully extracted' : 'Not extracted'],
      ['Signature', check(data.signature_valid, 'Valid', 'Invalid')],
      ['Integrity', check(data.integrity_valid, 'Match', 'Mismatch')],
      ['Media ID', data.payload?.media_id], ['Timestamp (UTC)', data.payload?.timestamp],
      ['LSB used', data.lsb_bits], ['Recovered start location', data.start_location],
      ['Stored original-cover hash', data.stored_hash],
      ['Computed original-cover hash', data.computed_hash],
    ]));

    const technical = document.createElement('details');
    technical.append(element('summary', 'Technical details'), fields([
      ['File name', data.filename], ['File size (bytes)', data.file_size],
      ['Media type', data.media_type], ['Frame version', data.frame_version],
      ['Carrier units', data.carrier_units], ['Location unit', data.location_unit],
      ['Extraction capacity (bytes)', data.capacity_bytes],
      ['Packet size (bytes)', data.packet_size], ['Payload size (bytes)', data.payload_size],
      ['Signature size (bytes)', data.signature_size], ['Nonce', data.payload?.nonce],
      ['Original-cover hash', check(data.media_hash_valid, 'Match', 'Mismatch')],
      ['Received pixels / PCM data', check(data.received_media_valid, 'Match', 'Mismatch')],
      ['Expected decoded-media hash', data.expected_media_hash],
      ['Received decoded-media hash', data.received_media_hash],
      ['Final verdict', verdict], ['Explanation', data.message || data.error],
    ]));
    if (data.payload) {
      technical.append(element('h4', 'Authenticated payload'),
        element('pre', JSON.stringify(data.payload, null, 2)));
    }
    result.append(technical);
    motion.stagger([result.querySelector('h3'), result.querySelector('p'), ...result.querySelectorAll('.verification-fields > *'), technical]);
    result.focus();
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!form.reportValidity() || submit.disabled) return;
    const body = new FormData(form);
    const filename = form.elements.stego.files[0]?.name;
    result.hidden = true;
    progress.textContent = 'Recovering parameters, extracting the packet, and verifying signature and integrity...';
    progress.className = 'result operation-status is-loading';
    submit.classList.add('is-loading');
    form.setAttribute('aria-busy', 'true');
    for (const control of form.elements) control.disabled = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120000);
    try {
      const response = await fetch('/decode', {method: 'POST', body, signal: controller.signal});
      if (!response.headers.get('content-type')?.includes('application/json')) {
        throw new Error(`Verification failed (HTTP ${response.status}).`);
      }
      const data = await response.json();
      render({...data, filename: data.filename || filename});
    } catch (error) {
      render({verdict: 'Cannot Verify', filename, message: error.name === 'AbortError'
        ? 'Verification timed out. Try again with a smaller file.'
        : `Unable to complete verification: ${error.message}`});
    } finally {
      clearTimeout(timeout);
      progress.textContent = '';
      progress.className = 'result';
      submit.classList.remove('is-loading');
      form.removeAttribute('aria-busy');
      for (const control of form.elements) control.disabled = false;
    }
  });
})();
