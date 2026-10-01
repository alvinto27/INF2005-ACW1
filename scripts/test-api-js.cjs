/* Optional Node built-in tests for the browser JSON boundary. No npm install needed. */
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = readFileSync(path.join(__dirname, '..', 'stego_web', 'static', 'api.js'), 'utf8');

function apiWith(fetch) {
  const window = {};
  const context = {
    window, fetch, AbortController, URL, TextDecoder, Uint8Array, TypeError, DOMException,
    setTimeout, clearTimeout,
    location: {origin: 'http://127.0.0.1:5000'},
  };
  vm.runInNewContext(source, context, {filename: 'api.js'});
  return window.StegoApi;
}

function response(status, body) {
  return {ok: status >= 200 && status < 300, status, json: async () => body};
}

test('classifies validation, access, conflict, rate-limit and server failures', async () => {
  for (const [status, kind] of [
    [400, 'validation'], [401, 'access'], [403, 'access'], [404, 'not-found'],
    [409, 'conflict'], [413, 'validation'], [422, 'validation'], [429, 'rate-limit'],
    [500, 'server'], [502, 'server'], [503, 'server'], [504, 'server'],
  ]) {
    const api = apiWith(async () => response(status, {error: 'safe field detail'}));
    await assert.rejects(api.post('/encode', {}, 1000), error => error.kind === kind);
  }
});

test('rejects empty, malformed and wrong-shaped success responses', async () => {
  for (const body of [null, [], 'text', 7]) {
    const api = apiWith(async () => response(200, body));
    await assert.rejects(api.post('/encode', {}, 1000), error => error.kind === 'response');
  }
  const api = apiWith(async () => ({ok: true, status: 200, json: async () => {throw new SyntaxError('bad JSON');}}));
  await assert.rejects(api.post('/encode', {}, 1000), error => error.kind === 'response');
});

test('distinguishes connection loss from a timed-out request', async () => {
  const offline = apiWith(async () => {throw new TypeError('fetch failed');});
  await assert.rejects(offline.post('/encode', {}, 1000), error => error.kind === 'network');
  const stalled = apiWith((_path, options) => new Promise((resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
  }));
  await assert.rejects(stalled.post('/encode', {}, 5), error => error.kind === 'timeout');
});

test('accepts only local download paths and never silently retries a POST', async () => {
  let calls = 0;
  const api = apiWith(async () => {calls += 1; return response(503, {error: 'private detail'});});
  await assert.rejects(api.post('/encode', {}, 1000), error =>
    error.kind === 'server' && !error.message.includes('private detail'));
  assert.equal(calls, 1);
  assert.equal(api.localUrl('/download/aaaaaaaaaaaaaaaaaaaaaa.png', '/download/'), '/download/aaaaaaaaaaaaaaaaaaaaaa.png');
  for (const url of ['javascript:alert(1)', '//example.com/payload/x', '/payload/x?next=1']) {
    assert.throws(() => api.localUrl(url, '/payload/'), error => error.kind === 'response');
  }
});
