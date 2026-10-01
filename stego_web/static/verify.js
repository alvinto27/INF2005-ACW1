/* Verify/decode UI for the receiver-gated protocol. */
(() => {
  const form = document.querySelector('#decode-form');
  const progress = document.querySelector('#decode-progress');
  const result = document.querySelector('#decode-result');
  const submit = form.querySelector('button[type="submit"]');
  const motion = window.StegoMotion;
  const api = window.StegoApi;
  const verdicts = new Set(['Authentic', 'Tampered', 'Signature Invalid', 'Payload Missing',
    'Wrong Start Location', 'Cannot Decrypt', 'Cannot Verify']);
  const previewMimes = new Set(['text/plain', 'image/png', 'image/jpeg', 'image/gif',
    'image/webp', 'image/avif', 'image/bmp', 'audio/wav', 'audio/mpeg', 'audio/ogg',
    'audio/flac', 'audio/mp4', 'audio/webm', 'video/mp4', 'video/webm', 'video/ogg']);

  function validReport(data) {
    if (!api.record(data) || typeof data.ok !== 'boolean'
        || typeof data.verdict !== 'string' || !verdicts.has(data.verdict)
        || (data.payload != null && !api.record(data.payload))
        || (data.preserved_ratio != null && (!Number.isFinite(data.preserved_ratio)
          || data.preserved_ratio < 0 || data.preserved_ratio > 1))) throw api.malformed();
    if (data.verdict === 'Authentic') {
      if (data.ok !== true || !api.record(data.payload)
          || typeof data.payload.download_name !== 'string'
          || typeof data.payload.declared_mime !== 'string') throw api.malformed();
      api.localUrl(data.payload.payload_url, '/payload/');
    } else if (data.ok === true || data.payload != null) throw api.malformed();
    return data;
  }

  const receiverKeyPassword = form.elements.receiver_key_password;
  receiverKeyPassword.addEventListener('input', () => receiverKeyPassword.setCustomValidity(''));
  form.addEventListener('input', () => { result.hidden = true; progress.textContent = ''; });

  function element(tag, text) {
    const node = document.createElement(tag);
    node.textContent = text;
    if (tag === 'pre') node.tabIndex = 0;
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

  function noPreviewMessage(fileName, mime) {
    const basename = typeof fileName === 'string'
      ? fileName.replace(/\\/g, '/').split('/').pop() : '';
    const dot = basename.lastIndexOf('.');
    const extension = dot > 0 ? basename.slice(dot + 1).trim() : '';
    const mediaType = typeof mime === 'string' ? mime.split(';', 1)[0].trim() : '';
    const subtype = mediaType.includes('/') ? mediaType.slice(mediaType.indexOf('/') + 1) : '';
    const type = (extension || subtype).trim().toUpperCase();
    return type
      ? `No preview available for ${type} files.`
      : 'No preview available for this file type.';
  }

  function payloadSection(payload) {
    const section = document.createElement('section');
    section.className = 'decoded-payload';
    section.append(element('h4', 'Authenticated decrypted payload'));
    const mime = payload.declared_mime || 'application/octet-stream';
    const url = api.localUrl(payload.payload_url, '/payload/');
    const download = document.createElement('a');
    download.href = url;
    download.download = payload.download_name || 'recovered-payload.bin';
    download.textContent = `Download ${download.download}`;
    section.append(download);
    if (!payload.type_agrees) {
      section.append(element('p', 'The authenticated MIME claim does not match the recovered bytes. The payload is available for download but will not be rendered.'));
      return section;
    }
    if (payload.preview_allowed !== true) {
      section.append(element('p', `Preview is disabled for ${mime}; download the authenticated bytes to inspect them safely.`));
      return section;
    }
    if (!previewMimes.has(mime)) {
      section.append(element('p', `${noPreviewMessage(payload.download_name, mime)} Download the authenticated bytes to inspect them safely.`));
      return section;
    }
    if (mime === 'text/plain') {
      const pre = element('pre', 'Loading authenticated text...');
      const retry = element('button', 'Retry preview');
      retry.type = 'button';
      retry.className = 'secondary';
      retry.hidden = true;
      async function loadPreview() {
        retry.hidden = true;
        pre.textContent = 'Loading authenticated text...';
        try { pre.textContent = await api.getText(url); }
        catch (error) { pre.textContent = error.message; retry.hidden = false; }
      }
      retry.addEventListener('click', loadPreview);
      section.append(pre, retry);
      loadPreview();
    } else if (mime.startsWith('image/')) {
      const image = document.createElement('img');
      image.src = url; image.alt = 'Recovered authenticated payload';
      image.addEventListener('error', () => { image.replaceWith(element('p', 'Preview could not load. Use the download link instead.')); }, {once: true});
      section.append(image);
    } else if (mime.startsWith('audio/')) {
      const audio = document.createElement('audio');
      audio.src = url; audio.controls = true;
      audio.addEventListener('error', () => { audio.replaceWith(element('p', 'Preview could not load. Use the download link instead.')); }, {once: true});
      section.append(audio);
    } else if (mime.startsWith('video/')) {
      const video = document.createElement('video');
      video.src = url; video.controls = true;
      video.addEventListener('error', () => { video.replaceWith(element('p', 'Preview could not load. Use the download link instead.')); }, {once: true});
      section.append(video);
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
      ['Bootstrap', data.frame_version == null ? 'Not opened' : 'Opened for this receiver'],
      ['Signature', check(data.signature_valid, 'Valid', 'Invalid')],
      ['Full-media integrity', check(data.integrity_valid, 'Match', 'Mismatch')],
      ['Media ID', data.payload?.media_id],
      ['Timestamp (UTC)', data.payload?.timestamp_utc],
      ['Recovered LSB count', data.lsb_bits],
      ['Recovered start unit', data.start_location],
      ['Sender key fingerprint', data.sender_key_fingerprint],
    ]));

    if (data.ok && data.payload?.payload_url) result.append(payloadSection(data.payload));

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
      ['Stored full media hash', data.payload?.media_hash],
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
    if (receiverKeyPassword.value
        && receiverKeyPassword.value.length < receiverKeyPassword.minLength) {
      receiverKeyPassword.setCustomValidity(
        'Use at least 8 characters, or leave empty for an unencrypted key.',
      );
      receiverKeyPassword.reportValidity();
      return;
    }
    receiverKeyPassword.setCustomValidity('');
    if (!form.reportValidity() || submit.disabled) return;
    const body = new FormData(form);
    const filename = form.elements.stego.files[0]?.name;
    result.hidden = true;
    const stegoFile = form.elements.stego.files[0];
    const isVideo = Boolean(stegoFile && /\.mkv$/i.test(stegoFile.name));
    progress.textContent = isVideo
      ? 'Processing video; this can take a while...'
      : 'Opening the receiver bootstrap, recovering geometry, verifying the signature, and checking the full media hash...';
    progress.className = 'result operation-status is-loading';
    submit.classList.add('is-loading');
    form.setAttribute('aria-busy', 'true');
    for (const control of form.elements) control.disabled = true;
    try {
      const data = validReport(await api.post('/decode', body,
        isVideo ? 30 * 60 * 1000 : 120000, {allowStatuses: [422]}));
      render({...data, filename: typeof data.filename === 'string' ? data.filename : filename});
    } catch (error) {
      render({ok: false, verdict: 'Cannot Verify', filename,
        message: `Unable to complete verification: ${error.message}`});
    } finally {
      progress.textContent = '';
      progress.className = 'result';
      submit.classList.remove('is-loading');
      form.removeAttribute('aria-busy');
      for (const control of form.elements) control.disabled = false;
    }
  });
})();
