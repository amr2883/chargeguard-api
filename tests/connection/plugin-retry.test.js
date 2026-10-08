// Plugin retry test: drives the REAL ChargeGuard_API_Client::request_with_breaker() (PHP) with a
// fake wp_remote_request, then feeds every attempt it made to the REAL verifyHmac middleware.
// No DB, no network: logger/db/replayGuard are mocked (same pattern as plugin-hmac-parity.test.js).
const { spawnSync } = require('child_process');
const path = require('path');

jest.mock('../../src/lib/logger', () => ({
  warn: jest.fn(), error: jest.fn(), info: jest.fn(), debug: jest.fn(),
}));
jest.mock('../../src/lib/db', () => ({ store: { findMany: jest.fn(async () => []) } }));
jest.mock('../../src/lib/replayGuard', () => ({
  claimRequestOnce: jest.fn(async () => ({ claimed: true, claimId: 'stub' })),
  completeRequest: jest.fn(async () => {}),
  releaseRequest: jest.fn(async () => {}),
}));

const verifyHmac = require('../../src/middleware/verifyHmac');
const { claimRequestOnce } = require('../../src/lib/replayGuard');

const HELPER = path.join(__dirname, 'helpers', 'php-retry.php');
const SECRET = 'test-secret-123'; // must match the stub in helpers/php-retry.php
const RID_RE = /^00000000-0000-4000-8000-\d{12}$/;
const BODY = '{"orderId":"123","note":"caf\\u00e9"}';

const probe = spawnSync('php', ['-v'], { encoding: 'utf8' });
const hasPhp = !probe.error && probe.status === 0;
if (!hasPhp && process.env.CI) throw new Error('php is required for plugin retry tests in CI');
const suite = hasPhp ? describe : describe.skip;

function drive(scenario, method, timeout, body) {
  const r = spawnSync('php', ['-d', 'display_errors=stderr', HELPER, scenario, method, String(timeout)], {
    input: Buffer.from(body, 'utf8'),
    encoding: 'utf8',
  });
  if (r.error || r.status !== 0 || !r.stdout) {
    throw new Error('php helper failed: status=' + r.status + ' stderr=' + r.stderr);
  }
  const data = JSON.parse(r.stdout.trim());
  data.calls = data.calls.map((c) => {
    const h = {};
    for (const k of Object.keys(c.headers || {})) h[k.toLowerCase()] = c.headers[k];
    return { ...c, headers: h };
  });
  return data;
}

async function runVerify(headers, body) {
  const req = {
    headers,
    body: Buffer.from(body, 'utf8'),
    tenant: { id: 't1', webhookSecret: SECRET },
    method: 'POST',
    path: '/x',
  };
  const out = { code: null, next: false };
  const res = {
    statusCode: 200,
    status(c) { out.code = c; this.statusCode = c; return this; },
    json() { return this; },
    send() { return this; },
    set() { return this; },
    end() { return this; },
  };
  await verifyHmac(req, res, () => { out.next = true; });
  return out;
}

suite('plugin request_with_breaker: retry behavior (real PHP -> real verifyHmac)', () => {
  beforeEach(() => { jest.clearAllMocks(); });

  test.each([['retry_503'], ['retry_wperror']])(
    '%s: exactly one retry, SAME request-id, rebuilt timestamp+signature, both attempts verify',
    async (scenario) => {
      const d = drive(scenario, 'POST', 5, BODY);
      expect(d.calls).toHaveLength(2);
      const [a, b] = d.calls;
      const rid = a.headers['x-chargeguard-request-id'];
      expect(rid).toMatch(RID_RE);
      expect(b.headers['x-chargeguard-request-id']).toBe(rid);
      expect(Number(b.headers['x-chargeguard-timestamp'])).toBeGreaterThan(Number(a.headers['x-chargeguard-timestamp']));
      expect(b.headers['x-chargeguard-signature']).not.toBe(a.headers['x-chargeguard-signature']);
      for (const c of d.calls) {
        expect(c.method).toBe('POST');
        expect(c.body).toBe(BODY);
        expect(c.timeout).toBe(5);
        const out = await runVerify(c.headers, c.body);
        expect(out.next).toBe(true);
        expect(out.code).toBeNull();
      }
      expect(claimRequestOnce.mock.calls.map((x) => x[1])).toEqual([rid, rid]);
      expect(d.wp_error).toBe(false);
      expect(d.code).toBe(200);
    },
    20000
  );

  test('success on the first attempt: no retry (GET, empty body, method and timeout pass through)', async () => {
    const d = drive('ok', 'GET', 10, '');
    expect(d.calls).toHaveLength(1);
    expect(d.calls[0].method).toBe('GET');
    expect(d.calls[0].body).toBe('');
    expect(d.calls[0].timeout).toBe(10);
    const out = await runVerify(d.calls[0].headers, d.calls[0].body);
    expect(out.next).toBe(true);
    expect(d.code).toBe(200);
  }, 20000);

  test('4xx response: no retry (DELETE)', async () => {
    const d = drive('client_error', 'DELETE', 15, '');
    expect(d.calls).toHaveLength(1);
    expect(d.calls[0].method).toBe('DELETE');
    expect(d.calls[0].timeout).toBe(15);
    expect(d.code).toBe(400);
  }, 20000);

  test('5xx on both attempts: stops after ONE retry (no loop), same request-id', async () => {
    const d = drive('both_503', 'PUT', 15, BODY);
    expect(d.calls).toHaveLength(2);
    expect(d.calls[0].method).toBe('PUT');
    expect(d.calls[1].headers['x-chargeguard-request-id']).toBe(d.calls[0].headers['x-chargeguard-request-id']);
    expect(d.code).toBe(503);
    expect(d.calls[0].timeout).toBe(15);
    expect(d.calls[1].timeout).toBe(15);
  }, 20000);

  test('HTTP 500 (not only 503) is retried exactly once, same request-id, retry succeeds', async () => {
    const d = drive('retry_500', 'POST', 5, BODY);
    expect(d.calls).toHaveLength(2);
    expect(d.calls[1].headers['x-chargeguard-request-id']).toBe(d.calls[0].headers['x-chargeguard-request-id']);
    expect(d.wp_error).toBe(false);
    expect(d.code).toBe(200);
  }, 20000);

  test('flaky: fail, fail, SUCCESS, fail, fail -> the success resets the failure counter (circuit stays closed)', async () => {
    const d = drive('flaky', 'POST', 5, BODY);
    expect(d.results).toHaveLength(5);
    expect(d.results.map((r) => r.calls_total)).toEqual([2, 4, 5, 7, 9]);
    expect(d.results.every((r) => r.wp_error === false)).toBe(true);
  }, 20000);

  test('circuit opens after 3 failed requests; the 4th makes NO HTTP call and returns chargeguard_circuit_open', async () => {
    const d = drive('circuit', 'POST', 5, BODY);
    expect(d.results).toHaveLength(4);
    expect(d.results.map((r) => r.calls_total)).toEqual([2, 4, 6, 6]);
    expect(d.results.slice(0, 3).every((r) => r.wp_error === false)).toBe(true);
    expect(d.results[3].wp_error).toBe(true);
    expect(d.results[3].error_code).toBe('chargeguard_circuit_open');
  }, 20000);
});
// END-OF-FILE-MARKER