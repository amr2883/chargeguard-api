'use strict';

// CF-TIMEOUT + CF-RETRY (Batch C4) - src/lib/cloudflareRanges.js
// Pins: 30s socket timeout, fetched ranges replace the fallback, a failed or
// empty fetch keeps the previous cache, startup retries until the first
// success (and gives up after maxAttempts), and nothing runs at import time
// under jest. https is mocked, so no request ever leaves the machine.

jest.mock('https', () => ({ get: jest.fn() }));
jest.mock('../../src/lib/logger', () => ({
  debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn(),
}));

const V4 = '173.245.48.0/20\n103.21.244.0/22\n';
const V6 = '2606:4700::/32\n';

// result: 'timeout' | Error | { status, body } | (url) => one of those
function fakeGet(result) {
  return (url, opts, cb) => {
    const handlers = {};
    const req = {
      on(ev, fn) { handlers[ev] = fn; return req; },
      destroy(err) { if (handlers.error) handlers.error(err); },
    };
    process.nextTick(() => {
      const r = typeof result === 'function' ? result(url) : result;
      if (r === 'timeout') { if (handlers.timeout) handlers.timeout(); return; }
      if (r instanceof Error) { if (handlers.error) handlers.error(r); return; }
      const res = {
        statusCode: r.status,
        resume() {},
        on(ev, fn) { res['h_' + ev] = fn; return res; },
      };
      cb(res);
      if (r.status === 200) { res.h_data(r.body); res.h_end(); }
    });
    return req;
  };
}

const okResult = (url) => ({ status: 200, body: url.endsWith('ips-v4') ? V4 : V6 });

function load() {
  jest.resetModules();
  const httpsMock = require('https');
  const mod = require('../../src/lib/cloudflareRanges');
  return { httpsMock, mod };
}

async function withKeepAlive(fn) {
  const t = setInterval(() => {}, 50);
  try { return await fn(); } finally { clearInterval(t); }
}

describe('cloudflareRanges', () => {
  test('uses a 30s socket timeout for both fetches', async () => {
    const { httpsMock, mod } = load();
    httpsMock.get.mockImplementation(fakeGet(okResult));
    await mod.refreshCloudflareRanges();
    expect(httpsMock.get.mock.calls.map((c) => c[0])).toEqual([
      'https://www.cloudflare.com/ips-v4',
      'https://www.cloudflare.com/ips-v6',
    ]);
    expect(httpsMock.get.mock.calls.map((c) => c[1])).toEqual([{ timeout: 30000 }, { timeout: 30000 }]);
  });

  test('replaces the fallback with the fetched ranges on success', async () => {
    const { httpsMock, mod } = load();
    httpsMock.get.mockImplementation(fakeGet(okResult));
    await mod.refreshCloudflareRanges();
    expect(mod.getCloudflareRanges()).toEqual(['173.245.48.0/20', '103.21.244.0/22', '2606:4700::/32']);
    const meta = mod.getCloudflareRangesMeta();
    expect(meta.lastFetchSucceeded).toBe(true);
    expect(meta.count).toBe(3);
    expect(meta.lastFetchedAt).toBeInstanceOf(Date);
  });

  test.each([
    ['a network error', new Error('boom')],
    ['a timeout', 'timeout'],
    ['an HTTP 503', { status: 503 }],
  ])('keeps the previous cache after %s', async (_label, result) => {
    const { httpsMock, mod } = load();
    const before = mod.getCloudflareRanges();
    httpsMock.get.mockImplementation(fakeGet(result));
    await mod.refreshCloudflareRanges();
    expect(mod.getCloudflareRanges()).toBe(before);
    const meta = mod.getCloudflareRangesMeta();
    expect(meta.lastFetchSucceeded).toBe(false);
    expect(meta.lastFetchedAt).toBeNull();
  });

  test('keeps the cache when both lists come back empty', async () => {
    const { httpsMock, mod } = load();
    const before = mod.getCloudflareRanges();
    httpsMock.get.mockImplementation(fakeGet({ status: 200, body: '' }));
    await mod.refreshCloudflareRanges();
    expect(mod.getCloudflareRanges()).toBe(before);
    expect(mod.getCloudflareRangesMeta().lastFetchSucceeded).toBe(false);
  });

  describe('bootRefresh', () => {
    test('retries after a failed first attempt and stops once it succeeds', async () => {
      const { httpsMock, mod } = load();
      httpsMock.get.mockImplementationOnce(fakeGet(new Error('net down')));
      httpsMock.get.mockImplementationOnce(fakeGet(new Error('net down')));
      httpsMock.get.mockImplementation(fakeGet(okResult));
      const ok = await withKeepAlive(() => mod.bootRefresh({ retryDelayMs: 5, maxAttempts: 3 }));
      expect(ok).toBe(true);
      expect(httpsMock.get).toHaveBeenCalledTimes(4);
      expect(mod.getCloudflareRanges()).toContain('2606:4700::/32');
    });

    test('gives up after maxAttempts when every attempt fails', async () => {
      const { httpsMock, mod } = load();
      httpsMock.get.mockImplementation(fakeGet(new Error('net down')));
      const ok = await withKeepAlive(() => mod.bootRefresh({ retryDelayMs: 5, maxAttempts: 3 }));
      expect(ok).toBe(false);
      expect(httpsMock.get).toHaveBeenCalledTimes(6);
      expect(mod.getCloudflareRangesMeta().lastFetchSucceeded).toBe(false);
    });

    test('does not retry when the first attempt succeeds', async () => {
      const { httpsMock, mod } = load();
      httpsMock.get.mockImplementation(fakeGet(okResult));
      const ok = await mod.bootRefresh({ retryDelayMs: 5, maxAttempts: 3 });
      expect(ok).toBe(true);
      expect(httpsMock.get).toHaveBeenCalledTimes(2);
    });
  });

  test('makes no request at import time under jest', () => {
    const { httpsMock, mod } = load();
    expect(httpsMock.get).not.toHaveBeenCalled();
    expect(typeof mod.startCloudflareRangesRefresh).toBe('function');
  });
});