/* Verify/decode UI for the receiver-gated protocol. */
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

  function check(value, yes, no) {
    return value === true ? yes : value === false ? no : 'Not checked';
  }

  function payloadBytes(value) {
    return Uint8Array.from(atob(value), character => character.charCodeAt(0));
  }

  function payloadSection(payload) {
    const section = document.createElement('section');
    section.className = 'decoded-payload';
    section.append(element('h4', 'Authenticated decrypted payload'));
    const bytes = payloadBytes(payload.user_payload_base64);
    const mime = payload.declared_mime || 'application/octet-stream';
    const url = URL.createObjectURL(new Blob([bytes], {type: mime}));
    const download = document.createElement('a');
    download.href = url;
    download.download = payload.download_name || 'recovered-payload.bin';
    download.textContent = `Download ${download.download}`;
    section.append(download);
    if (!payload.type_agrees) {
      section.append(element('p', 'The authenticated MIME claim does not match the recovered bytes. The payload is available for download but will not be rendered.'));
      return section;
    }
    if (!payload.preview_allowed) {
      section.append(element('p', `Preview is disabled for ${mime}; download the authenticated bytes to inspect them safely.`));
      return section;
    }
    if (mime === 'text/plain') {
      const pre = element('pre', new TextDecoder('utf-8', {fatal: false}).decode(bytes));
      section.append(pre);
    } else if (mime.startsWith('image/')) {
      const image = document.createElement('img');
      image.src = url; image.alt = 'Recovered authenticated payload';
      section.append(image);
    } else if (mime.startsWith('audio/')) {
      const audio = document.createElement('audio');
      audio.src = url; audio.controls = true;
      section.append(audio);
    }
    return section;
  }

  function render(data) {
    const verdict = data.verdict || 'Cannot Verify';
    result.className = 'result verification-result';
    result.dataset.verdict = verdict;
    result.hidden = false;
    result.replaceChildren(
      element('h3', `Status: ${verdict}`),
      element('p', data.message || data.error || 'The server could not complete verification.'),
    );
    result.append(fields([
      ['Bootstrap', data.start_location == null ? 'Not opened' : 'Opened for this receiver'],
      ['Signature', check(data.signature_valid, 'Valid', 'Invalid')],
      ['Masked-media integrity', check(data.integrity_valid, 'Match', 'Mismatch')],
      ['Media ID', data.payload?.media_id],
      ['Timestamp (UTC)', data.payload?.timestamp_utc],
      ['Recovered LSB count', data.lsb_bits],
      ['Recovered start unit', data.start_location],
      ['Sender key fingerprint', data.sender_key_fingerprint],
    ]));

    if (data.ok && data.payload?.user_payload_base64) result.append(payloadSection(data.payload));

    const technical = document.createElement('details');
    technical.append(element('summary', 'Technical details'), fields([
      ['File name', data.filename], ['File size (bytes)', data.file_size],
      ['Carrier type', data.media_type], ['Protocol version', data.frame_version],
      ['Payload extracted', data.payload_extracted ? 'Yes' : 'No'],
      ['Payload size (bytes)', data.payload?.user_payload_size],
      ['Declared payload MIME', data.payload?.declared_mime],
      ['Sniffed payload MIME', data.payload?.sniffed_mime],
      ['MIME claim agrees', check(data.payload?.type_agrees, 'Yes', 'No')],
      ['Preserved carrier bits', data.preserved_bits],
      ['Preserved ratio', data.preserved_ratio == null ? null : `${(data.preserved_ratio * 100).toFixed(4)}%`],
      ['Stored masked-media hash', data.payload?.media_hash],
      ['Nonce', data.payload?.nonce],
      ['Final verdict', verdict], ['Explanation', data.message || data.error],
    ]));
    if (data.payload) {
      technical.append(
        element('h4', 'Authenticated metadata'),
        element('pre', JSON.stringify(data.payload.metadata, null, 2)),
      );
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
    progress.textContent = 'Opening the receiver bootstrap, recovering geometry, verifying the signature, and checking masked-media integrity...';
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
