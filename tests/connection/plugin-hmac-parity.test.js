// Parity test: a request signed by the REAL WordPress plugin code (PHP) must be
// accepted by the REAL verifyHmac middleware, and any tampering must be rejected
// as a signature mismatch. No DB and no network: logger/db/replayGuard are mocked.
const { spawnSync, execFileSync } = require('child_process');
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
const logger = require('../../src/lib/logger');
const { claimRequestOnce } = require('../../src/lib/replayGuard');

const HELPER = path.join(__dirname, 'helpers', 'php-sign.php');
const SECRET = 'test-secret-123'; // must match the stub in helpers/php-sign.php
const RID = '11111111-2222-4333-8444-555555555555';

const probe = spawnSync('php', ['-v'], { encoding: 'utf8' });
const hasPhp = !probe.error && probe.status === 0;
if (!hasPhp && process.env.CI) throw new Error('php is required for plugin parity tests in CI');
const suite = hasPhp ? describe : describe.skip;

const BODY_ESCAPED = '{"orderId":"123","note":"caf\\u00e9 \\"q\\" \\/ ok"}';
const BODY_UTF8 = '{"note":"caf\u00e9 \u0627\u0644 \u{1F600}"}';

function signWithPlugin(body, rid) {
  const out = execFileSync('php', ['-d', 'display_errors=0', HELPER, rid], {
    input: Buffer.from(body, 'utf8'),
    encoding: 'utf8',
  });
  const headers = JSON.parse(out.trim()).headers;
  const h = {};
  for (const k of Object.keys(headers)) h[k.toLowerCase()] = headers[k];
  return h;
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
  return { out, req };
}

const warnCodes = () => logger.warn.mock.calls.map((c) => c[1]);

suite('plugin (PHP) <-> verifyHmac parity (v3)', () => {
  beforeEach(() => { jest.clearAllMocks(); });

  test.each([
    ['escaped ASCII JSON, as json_encode emits', BODY_ESCAPED],
    ['raw UTF-8 JSON (accent, Arabic, emoji)', BODY_UTF8],
  ])('accepts the plugin signature: %s', async (_name, body) => {
    const headers = signWithPlugin(body, RID);
    expect(headers['x-chargeguard-signature']).toMatch(/^v3=[0-9a-f]{64}$/);
    const { out, req } = await runVerify(headers, body);
    expect(out.next).toBe(true);
    expect(out.code).toBeNull();
    expect(req.hmacSignatureVersion).toBe('v3');
    expect(req.body).toEqual(JSON.parse(body));
    expect(claimRequestOnce).toHaveBeenCalledWith('t1', RID);
    expect(warnCodes()).toEqual([]);
  });

  test('accepts an empty body (bodyless GET/DELETE)', async () => {
    const headers = signWithPlugin('', RID);
    const { out, req } = await runVerify(headers, '');
    expect(out.next).toBe(true);
    expect(req.body).toEqual({});
  });

  test.each([
    ['body changed by one char', (h, b) => [h, b.replace('123', '124')]],
    ['store domain lowercased', (h, b) => { expect(h['x-store-domain']).toMatch(/[A-Z]/); h['x-store-domain'] = h['x-store-domain'].toLowerCase(); return [h, b]; }],
    ['request-id changed', (h, b) => { h['x-chargeguard-request-id'] = h['x-chargeguard-request-id'].replace('1111', '2222'); return [h, b]; }],
    ['timestamp shifted by 1s', (h, b) => { h['x-chargeguard-timestamp'] = String(Number(h['x-chargeguard-timestamp']) + 1); return [h, b]; }],
  ])('rejects: %s (as signature mismatch, not another check)', async (_name, mutate) => {
    const headers = signWithPlugin(BODY_ESCAPED, RID);
    const [h, b] = mutate(headers, BODY_ESCAPED);
    const { out } = await runVerify(h, b);
    expect(out.next).toBe(false);
    expect(out.code).toBe(401);
    expect(warnCodes()).toContain('HMAC_SIGNATURE_MISMATCH');
    expect(claimRequestOnce).not.toHaveBeenCalled();
  });
});