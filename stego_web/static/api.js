/* Small, predictable boundary for the local JSON endpoints. No automatic POST retries. */
(() => {
  class ApiError extends Error {
    constructor(message, kind, status = null) {
      super(message);
      this.name = 'ApiError';
      this.kind = kind;
      this.status = status;
    }
  }

  const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const malformed = () => new ApiError('The server returned an unexpected response. Please try again.', 'response');

  function localUrl(value, prefix) {
    if (typeof value !== 'string' || !value.startsWith('/')) throw malformed();
    let url;
    try { url = new URL(value, location.origin); } catch { throw malformed(); }
    if (url.origin !== location.origin || !url.pathname.startsWith(prefix)
        || url.username || url.password || url.search || url.hash) throw malformed();
    if (prefix === '/payload/' && !/^\/payload\/[A-Za-z0-9_-]{22}$/.test(url.pathname)) throw malformed();
    if (prefix === '/download/' && !/^\/download\/[A-Za-z0-9_-]{22}\.(png|wav|mkv)$/.test(url.pathname)) throw malformed();
    return url.pathname;
  }

  function httpError(status, data) {
    const detail = record(data) && typeof data.error === 'string' && data.error.length <= 400
      ? data.error : null;
    if (status === 400 || status === 411 || status === 413 || status === 422) {
      return new ApiError(detail || 'Check the supplied fields and files, then try again.', 'validation', status);
    }
    if (status === 401 || status === 403) return new ApiError('Access was denied. Check your credentials and try again.', 'access', status);
    if (status === 404) return new ApiError('The requested service was not found. Reload the page and try again.', 'not-found', status);
    if (status === 409) return new ApiError('This request conflicts with a newer change. Review your inputs and try again.', 'conflict', status);
    if (status === 429) return new ApiError('Too many requests. Wait a moment and try again.', 'rate-limit', status);
    if (status >= 500) return new ApiError('The server could not complete the request. Please try again.', 'server', status);
    return new ApiError(`The request failed (HTTP ${status}). Please try again.`, 'http', status);
  }

  async function post(path, body, timeoutMs, {allowStatuses = []} = {}) {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
    try {
      const response = await fetch(path, {method: 'POST', body, signal: controller.signal});
      let data;
      try { data = await response.json(); }
      catch { throw response.ok ? malformed() : httpError(response.status, null); }
      if (!response.ok && !allowStatuses.includes(response.status)) throw httpError(response.status, data);
      if (!record(data)) throw malformed();
      return data;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      if (timedOut || error?.name === 'AbortError') {
        throw new ApiError('The request timed out. Your server may still be processing it; check before retrying.', 'timeout');
      }
      if (error instanceof TypeError) throw new ApiError('Could not connect to the server. Check the connection and try again.', 'network');
      throw malformed();
    } finally { clearTimeout(timer); }
  }

  async function getText(url, maxBytes = 1024 * 1024) {
    const path = localUrl(url, '/payload/');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(path, {signal: controller.signal});
      if (!response.ok) throw httpError(response.status, null);
      if (!response.body) throw malformed();
      const reader = response.body.getReader();
      const chunks = [];
      let size = 0;
      try {
        while (true) {
          const {done, value} = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > maxBytes) throw new ApiError('The text is too large to preview. Download it instead.', 'size');
          chunks.push(value);
        }
      } catch (error) {
        try { await reader.cancel(); }
        catch (cancelError) { console.warn('Could not cancel the failed preview stream', cancelError); }
        throw error;
      } finally { reader.releaseLock(); }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      return new TextDecoder('utf-8', {fatal: true}).decode(bytes);
    } catch (error) {
      if (error instanceof ApiError) throw error;
      if (error?.name === 'AbortError') throw new ApiError('The preview timed out. You can retry or download the file.', 'timeout');
      if (error instanceof TypeError) throw new ApiError('Could not load the preview. You can retry or download the file.', 'network');
      throw malformed();
    } finally { clearTimeout(timer); }
  }

  window.StegoApi = {ApiError, getText, localUrl, malformed, post, record};
})();
