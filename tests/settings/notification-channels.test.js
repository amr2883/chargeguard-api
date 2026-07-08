'use strict';

// ══════════════════════════════════════════════════════════════════════════════
// SCOPE: src/routes/settings.js — Notification Channels (Webhooks)
//   - GET  /webhook
//   - POST /webhook
//   - POST /webhook/test
//   - Shared SETTINGS_RATE rate limiter (module-level Map, applies to every
//     route in this router file, not just the ones tested here)
//   - src/lib/webhook.js (validateWebhookUrl, sendWebhookAlert) — tested BOTH
//     mocked (for route-level control) AND unmocked via jest.requireActual
//     (for real SSRF/payload/retry coverage)
//
// MOCKING STRATEGY:
//   - db.js mocked (manual factory) — only tenant.update is used by these routes.
//   - logger.js mocked to silence output; asserted on for error-path coverage.
//   - lib/apiKeyAuth.js: only resolveTenantByApiKey mocked. middleware/authenticate.js
//     (requireAuth) is NOT mocked — we run the real middleware, same as T2/T6.
//   - lib/domainAuth.js mocked with a benign stub — settings.js imports
//     domainAuthMiddleware but NEVER references it in this file (dead import,
//     confirmed by reading the source). Mocked purely to avoid pulling in
//     whatever domainAuth.js's real dependencies are; it is never invoked here.
//   - middleware/verifyHmac.js is NOT mocked — it's pure crypto + req.tenant.webhookSecret,
//     so we compute real, valid HMAC signatures in tests (see signRequest() below),
//     exactly like the T2 HMAC convention.
//   - src/lib/webhook.js is jest.mock()'d at the top for all ROUTE-level tests
//     (full control over validateWebhookUrl/sendWebhookAlert return values).
//     A separate `real webhook.js implementation (unmocked)` describe block
//     uses jest.requireActual('../../src/lib/webhook') to bypass that mock and
//     test the genuine SSRF blocklist + payload builders + retry logic directly.
//
// QUIRKS DISCOVERED (documented inline at point of relevance too):
//   1. verifyHmacSignature is required on POST /webhook AND POST /webhook/test,
//      not just geo-overrides as the original brief implied — confirmed by
//      reading settings.js line-by-line.
//   2. SETTINGS_RATE is ONE shared Map across every route in settings.js. We
//      give every functional test a fresh, unique x-api-key so 20-req-per-key
//      exhaustion never bleeds across unrelated tests; only the dedicated
//      "rate limiting" describe block deliberately reuses a single key.
//      (Module state resets per TEST FILE — Jest gives each file its own
//      module registry — but persists across tests WITHIN this file.)
//   3. Dead imports in settings.js: calculateCountryRiskPenalty, resolveTenantByApiKey,
//      domainAuthMiddleware are imported but never called/used in that file.
//   4. GET /webhook's try/catch 500 branch is unreachable under normal inputs
//      (every operation inside is a synchronous property read) — we force it
//      via a Proxy that throws when a specific tenant field is read.
//   5. SECURITY GAP: the IPv6 entries in SSRF_BLOCKLIST (`::1`, `fc00:`, `fd00:`)
//      never match in practice because Node's URL parser serializes IPv6
//      hostnames WITH brackets (e.g. "[::1]"), and the regexes have no bracket
//      handling. Pinned as current (buggy) behavior, not asserted as "safe".
//   6. QUIRK: settings.js's POST /webhook/test calls sendWebhookAlert(..., {
//      alertType: 'test', isTest: true }) — an OBJECT. sendWebhookAlert's own
//      test-detection is `extraContext === true` (strict), which is false for
//      any object. The "[TEST]" prefix / attack_detected_test event name never
//      actually fires; the test webhook is indistinguishable from a real alert.
//   7. QUIRK: in sendWebhookAlert's retry loop, a generic thrown error with no
//      `.response` property and name !== 'AbortError' hits
//      `!RETRYABLE_CODES.has(undefined)` → true → breaks after ONE attempt,
//      despite RETRIES = 3. Only HTTP-status retryable failures and AbortError
//      (timeout) actually retry across multiple attempts.
// ══════════════════════════════════════════════════════════════════════════════

jest.mock('../../src/lib/db', () => ({
  tenant: {
    update: jest.fn(),
  },
}));

jest.mock('../../src/lib/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

jest.mock('../../src/lib/apiKeyAuth', () => ({
  resolveTenantByApiKey: jest.fn(),
}));

jest.mock('../../src/lib/domainAuth', () => ({
  domainAuthMiddleware: jest.fn((req, res, next) => next()),
}));

jest.mock('../../src/lib/webhook', () => ({
  validateWebhookUrl: jest.fn(),
  sendWebhookAlert: jest.fn(),
}));

const crypto = require('crypto');
const db = require('../../src/lib/db');
const logger = require('../../src/lib/logger');
const { resolveTenantByApiKey } = require('../../src/lib/apiKeyAuth');
const { validateWebhookUrl, sendWebhookAlert } = require('../../src/lib/webhook');
const settingsRouter = require('../../src/routes/settings');

// ── Route-stack extraction helpers (T6/T7 convention) ───────────────────────
function getRouteHandlers(method, path) {
  const layer = settingsRouter.stack.find(
    (l) => l.route && l.route.path === path && l.route.methods[method.toLowerCase()]
  );
  if (!layer) throw new Error(`Route not found: ${method.toUpperCase()} ${path}`);
  return layer.route.stack.map((s) => s.handle);
}

// NOTE (quirk #8 — test-infrastructure, not an app bug): none of the
// middlewares in settings.js (rateLimit, verifyHmacSignature, authenticate)
// `return next()` — they call it as a bare statement, which is normal for
// real Express but means the recursive dispatch(...) promise it creates is
// never propagated back up through each `await handler(...)`. Left as-is,
// the outer dispatch() call only waits for the FIRST middleware's own
// (synchronous) settlement, not the full chain beneath it — a race that
// stays invisible for shallow handlers but surfaces as "assertion runs one
// tick early" for handlers with 2+ chained awaits (e.g. POST /webhook/test's
// `await sendWebhookAlert()` then `await db.tenant.update()`). We capture
// the recursive promise via closure and explicitly await it ourselves,
// regardless of what the middleware does with next()'s return value.
async function dispatch(handlers, req, res, i = 0) {
  if (i >= handlers.length) return;
  const handler = handlers[i];
  let nextPromise = Promise.resolve();
  await handler(req, res, (err) => {
    if (err) throw err;
    nextPromise = dispatch(handlers, req, res, i + 1);
    return nextPromise;
  });
  await nextPromise;
}

// ── Factories ─────────────────────────────────────────────────────────────
// Quirk #2: unique api key per test avoids cross-test 429 bleed from the
// single shared SETTINGS_RATE Map.
let apiKeyCounter = 0;
function uniqueApiKey() {
  apiKeyCounter += 1;
  return `test-api-key-${apiKeyCounter}`;
}

function makeReq({ headers = {}, body = {}, params = {} } = {}) {
  return {
    headers: { 'x-api-key': uniqueApiKey(), ...headers },
    body,
    params,
  };
}

function makeRes() {
  const res = {};
  res.statusCode = 200;
  res.status = jest.fn((code) => {
    res.statusCode = code;
    return res;
  });
  res.json = jest.fn((body) => {
    res.body = body;
    return res;
  });
  res.set = jest.fn(() => res);
  return res;
}

function makeTenant(overrides = {}) {
  return {
    id: 'tenant_1',
    email: 'merchant@example.com',
    isActive: true,
    emailVerified: true,
    plan: 'pro',
    webhookSecret: 'test-webhook-secret-123',
    webhookUrl: null,
    webhookType: null,
    webhookLastStatus: null,
    webhookLastSentAt: null,
    webhookFailureCount: 0,
    storeUrl: null,
    ...overrides,
  };
}

function mockAuthenticatedTenant(tenant) {
  resolveTenantByApiKey.mockResolvedValue({ tenant, usedPreviousKey: false });
}

// Real HMAC signer — mirrors middleware/verifyHmac.js exactly:
// signedStr = `${timestamp}.${JSON.stringify(body)}`, sig = 'v1=' + HMAC-SHA256 hex.
function signRequest(secret, bodyObj, timestamp = Math.floor(Date.now() / 1000).toString()) {
  const rawBody = Buffer.from(JSON.stringify(bodyObj));
  const signedStr = `${timestamp}.${rawBody.toString('utf8')}`;
  const sig = 'v1=' + crypto.createHmac('sha256', secret).update(signedStr).digest('hex');
  return { 'x-chargeguard-signature': sig, 'x-chargeguard-timestamp': timestamp };
}

function applyPersistentDefaults() {
  validateWebhookUrl.mockReturnValue({ valid: true });
  sendWebhookAlert.mockResolvedValue(undefined);
}

beforeAll(() => {
  process.env.EMAIL_VERIFICATION_DISABLED = 'false';
});

beforeEach(() => {
  jest.resetAllMocks();
  applyPersistentDefaults();
});

// ══════════════════════════════════════════════════════════════════════════════
describe('GET /webhook', () => {
  const handlers = () => getRouteHandlers('get', '/webhook');

  test('returns configured webhook settings', async () => {
    const sentAt = new Date('2026-07-01T00:00:00.000Z');
    const tenant = makeTenant({
      webhookUrl: 'https://hooks.slack.com/services/x',
      webhookType: 'slack',
      webhookLastStatus: 'success',
      webhookLastSentAt: sentAt,
      webhookFailureCount: 2,
    });
    mockAuthenticatedTenant(tenant);
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith({
      success: true,
      webhookUrl: 'https://hooks.slack.com/services/x',
      webhookType: 'slack',
      webhookLastStatus: 'success',
      webhookLastSentAt: sentAt,
      webhookFailureCount: 2,
    });
  });

  test('defaults when fields are null/unset', async () => {
    const tenant = makeTenant({
      webhookUrl: null,
      webhookType: null,
      webhookLastStatus: null,
      webhookLastSentAt: null,
      webhookFailureCount: 0,
    });
    mockAuthenticatedTenant(tenant);
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith({
      success: true,
      webhookUrl: '',
      webhookType: '',
      webhookLastStatus: '',
      webhookLastSentAt: null,
      webhookFailureCount: 0,
    });
  });

  // Quirk #4: forcing the catch(err) branch requires an artificial throw,
  // since every statement in the try block is a plain synchronous property read.
  test('unexpected error reading tenant field → 500', async () => {
    const throwingTenant = new Proxy(makeTenant(), {
      get(target, prop) {
        if (prop === 'webhookUrl') throw new Error('boom');
        return target[prop];
      },
    });
    mockAuthenticatedTenant(throwingTenant);
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
    expect(logger.error).toHaveBeenCalled();
  });

  test('missing API key → 401 (real requireAuth)', async () => {
    const req = makeReq({ headers: { 'x-api-key': undefined } });
    delete req.headers['x-api-key'];
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'API key is required' });
  });

  test('unverified tenant (real requireAuth) → 403 EMAIL_NOT_VERIFIED', async () => {
    mockAuthenticatedTenant(makeTenant({ emailVerified: false }));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'EMAIL_NOT_VERIFIED' }));
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('POST /webhook', () => {
  const handlers = () => getRouteHandlers('post', '/webhook');

  test('missing webhookUrl → 400', async () => {
    const tenant = makeTenant();
    mockAuthenticatedTenant(tenant);
    const body = { webhookType: 'slack' };
    const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'webhookUrl is required.' });
    expect(db.tenant.update).not.toHaveBeenCalled();
  });

  test('non-string webhookUrl → 400', async () => {
    const tenant = makeTenant();
    mockAuthenticatedTenant(tenant);
    const body = { webhookUrl: 12345, webhookType: 'slack' };
    const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'webhookUrl is required.' });
  });

  test('invalid webhookType → 400', async () => {
    const tenant = makeTenant();
    mockAuthenticatedTenant(tenant);
    const body = { webhookUrl: 'https://hooks.slack.com/x', webhookType: 'teams' };
    const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      error: 'webhookType must be slack, discord, or custom.',
    });
    expect(validateWebhookUrl).not.toHaveBeenCalled();
  });

  test('validateWebhookUrl rejects → 400 with returned error', async () => {
    validateWebhookUrl.mockReturnValue({ valid: false, error: 'Internal or private IPs are not allowed' });
    const tenant = makeTenant();
    mockAuthenticatedTenant(tenant);
    const body = { webhookUrl: 'https://169.254.169.254/hook', webhookType: 'custom' };
    const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Internal or private IPs are not allowed' });
    expect(db.tenant.update).not.toHaveBeenCalled();
  });

  test('validateWebhookUrl rejects with no error message → falls back to generic text', async () => {
    validateWebhookUrl.mockReturnValue({ valid: false });
    const tenant = makeTenant();
    mockAuthenticatedTenant(tenant);
    const body = { webhookUrl: 'https://bad.example.com/hook', webhookType: 'custom' };
    const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid webhook URL.' });
  });

  test('valid input → saves webhook settings and resets status fields', async () => {
    const tenant = makeTenant();
    mockAuthenticatedTenant(tenant);
    db.tenant.update.mockResolvedValue({});
    const body = { webhookUrl: 'https://hooks.slack.com/services/x', webhookType: 'slack' };
    const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(db.tenant.update).toHaveBeenCalledWith({
      where: { id: 'tenant_1' },
      data: {
        webhookUrl: 'https://hooks.slack.com/services/x',
        webhookType: 'slack',
        webhookLastStatus: null,
        webhookLastSentAt: null,
        webhookFailureCount: 0,
      },
    });
    expect(res.json).toHaveBeenCalledWith({ success: true });
    expect(logger.info).toHaveBeenCalled();
  });

  // Quirk #1: HMAC is required here even though the brief only mentioned it
  // for geo-overrides.
  test('missing HMAC headers → 401, handler never reached', async () => {
    const tenant = makeTenant();
    mockAuthenticatedTenant(tenant);
    const body = { webhookUrl: 'https://hooks.slack.com/x', webhookType: 'slack' };
    const req = makeReq({ body });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
    expect(validateWebhookUrl).not.toHaveBeenCalled();
    expect(db.tenant.update).not.toHaveBeenCalled();
  });

  test('invalid HMAC signature (wrong secret) → 401', async () => {
    const tenant = makeTenant();
    mockAuthenticatedTenant(tenant);
    const body = { webhookUrl: 'https://hooks.slack.com/x', webhookType: 'slack' };
    const req = makeReq({ body, headers: signRequest('wrong-secret', body) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
  });

  test('expired HMAC timestamp (> 300s) → 401', async () => {
    const tenant = makeTenant();
    mockAuthenticatedTenant(tenant);
    const body = { webhookUrl: 'https://hooks.slack.com/x', webhookType: 'slack' };
    const staleTs = String(Math.floor(Date.now() / 1000) - 400);
    const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body, staleTs) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(401);
  });

  test('no webhookSecret configured on tenant → 401', async () => {
    const tenant = makeTenant({ webhookSecret: null });
    mockAuthenticatedTenant(tenant);
    const body = { webhookUrl: 'https://hooks.slack.com/x', webhookType: 'slack' };
    const req = makeReq({
      body,
      headers: { 'x-chargeguard-signature': 'v1=whatever', 'x-chargeguard-timestamp': String(Math.floor(Date.now() / 1000)) },
    });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(401);
  });

  test('db.tenant.update throws → 500', async () => {
    const tenant = makeTenant();
    mockAuthenticatedTenant(tenant);
    db.tenant.update.mockRejectedValue(new Error('db down'));
    const body = { webhookUrl: 'https://hooks.slack.com/x', webhookType: 'slack' };
    const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(logger.error).toHaveBeenCalled();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('POST /webhook/test', () => {
  const handlers = () => getRouteHandlers('post', '/webhook/test');

  test('no webhook URL configured → 400', async () => {
    const tenant = makeTenant({ webhookUrl: null });
    mockAuthenticatedTenant(tenant);
    const body = {};
    const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'No webhook URL configured. Save one first.' });
    expect(sendWebhookAlert).not.toHaveBeenCalled();
  });

  test('success → calls sendWebhookAlert with hardcoded testTenant shape, updates status', async () => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-07-08T00:00:00.000Z'));

    const tenant = makeTenant({
      webhookUrl: 'https://hooks.slack.com/services/x',
      webhookType: 'slack',
      storeUrl: 'https://real-store-should-not-be-sent.example.com',
    });
    mockAuthenticatedTenant(tenant);
    db.tenant.update.mockResolvedValue({});
    const body = {};
    const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    // Quirk-adjacent: storeUrl is hardcoded to null in testTenant regardless
    // of the real tenant's storeUrl.
    expect(sendWebhookAlert).toHaveBeenCalledWith(
      {
        id: 'tenant_1',
        email: 'merchant@example.com',
        storeUrl: null,
        webhookUrl: 'https://hooks.slack.com/services/x',
        webhookType: 'slack',
      },
      1,
      0.30,
      0,
      { alertType: 'test', isTest: true }
    );
    expect(db.tenant.update).toHaveBeenCalledWith({
      where: { id: 'tenant_1' },
      data: { webhookLastStatus: 'success', webhookLastSentAt: new Date('2026-07-08T00:00:00.000Z') },
    });
    expect(res.json).toHaveBeenCalledWith({ success: true });

    jest.useRealTimers();
  });

  test('webhookType defaults to "custom" when tenant.webhookType is falsy', async () => {
    const tenant = makeTenant({ webhookUrl: 'https://example.com/hook', webhookType: null });
    mockAuthenticatedTenant(tenant);
    db.tenant.update.mockResolvedValue({});
    const body = {};
    const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(sendWebhookAlert).toHaveBeenCalledWith(
      expect.objectContaining({ webhookType: 'custom' }),
      1,
      0.30,
      0,
      expect.anything()
    );
  });

  test('sendWebhookAlert rejects → failure count incremented, 500 with err.message', async () => {
    const tenant = makeTenant({ webhookUrl: 'https://example.com/hook', webhookType: 'custom' });
    mockAuthenticatedTenant(tenant);
    sendWebhookAlert.mockRejectedValue(new Error('ECONNREFUSED'));
    db.tenant.update.mockResolvedValue({});
    const body = {};
    const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(db.tenant.update).toHaveBeenCalledWith({
      where: { id: 'tenant_1' },
      data: { webhookLastStatus: 'failed', webhookFailureCount: { increment: 1 } },
    });
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'ECONNREFUSED' });
  });

  test('sendWebhookAlert rejects with no .message → falls back to generic text', async () => {
    const tenant = makeTenant({ webhookUrl: 'https://example.com/hook', webhookType: 'custom' });
    mockAuthenticatedTenant(tenant);
    sendWebhookAlert.mockRejectedValue({});
    db.tenant.update.mockResolvedValue({});
    const body = {};
    const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Test failed. Check your webhook URL.' });
  });

  test('missing HMAC headers → 401, sendWebhookAlert never called', async () => {
    const tenant = makeTenant({ webhookUrl: 'https://example.com/hook' });
    mockAuthenticatedTenant(tenant);
    const req = makeReq({ body: {} });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(sendWebhookAlert).not.toHaveBeenCalled();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Quirk #2: SETTINGS_RATE is one Map shared by every route in settings.js.
// Isolated here with its own dedicated key so it can't interfere with (or be
// interfered with by) the functional tests above, which all use unique keys.
describe('rate limiting (shared SETTINGS_RATE map across all /api/settings routes)', () => {
  test('20 requests pass, 21st with the same key → 429', async () => {
    const rateLimiter = getRouteHandlers('get', '/webhook')[0];
    const key = 'rate-limit-dedicated-key';

    for (let i = 0; i < 20; i++) {
      const req = makeReq({ headers: { 'x-api-key': key } });
      const res = makeRes();
      const next = jest.fn();
      await rateLimiter(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(res.status).not.toHaveBeenCalledWith(429);
    }

    const req21 = makeReq({ headers: { 'x-api-key': key } });
    const res21 = makeRes();
    const next21 = jest.fn();
    await rateLimiter(req21, res21, next21);

    expect(next21).not.toHaveBeenCalled();
    expect(res21.status).toHaveBeenCalledWith(429);
    expect(res21.json).toHaveBeenCalledWith({ error: 'Too Many Requests' });
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Real, unmocked src/lib/webhook.js — bypasses the top-level jest.mock() above
// via jest.requireActual, giving genuine coverage of SSRF blocking, payload
// construction, and retry/backoff behavior.
describe('real webhook.js implementation (unmocked)', () => {
  const realWebhook = jest.requireActual('../../src/lib/webhook');

  describe('validateWebhookUrl — SSRF & format checks', () => {
    test('valid https URL → valid', () => {
      expect(realWebhook.validateWebhookUrl('https://hooks.slack.com/services/x')).toEqual({ valid: true });
    });

    test('missing url → invalid', () => {
      expect(realWebhook.validateWebhookUrl()).toEqual({ valid: false, error: 'URL is required' });
    });

    test('non-string url → invalid', () => {
      expect(realWebhook.validateWebhookUrl(12345)).toEqual({ valid: false, error: 'URL is required' });
    });

    test('malformed url → invalid format', () => {
      expect(realWebhook.validateWebhookUrl('not a url')).toEqual({ valid: false, error: 'Invalid URL format' });
    });

    test('http (non-https) → rejected', () => {
      expect(realWebhook.validateWebhookUrl('http://example.com/hook')).toEqual({
        valid: false,
        error: 'Only HTTPS URLs are allowed',
      });
    });

    test.each([
      ['localhost', 'https://localhost/hook'],
      ['127.x loopback', 'https://127.0.0.1/hook'],
      ['0.0.0.0', 'https://0.0.0.0/hook'],
      ['10.x private', 'https://10.0.0.5/hook'],
      ['172.16.x private (lower bound)', 'https://172.16.0.1/hook'],
      ['172.31.x private (upper bound)', 'https://172.31.255.254/hook'],
      ['192.168.x private', 'https://192.168.1.1/hook'],
      ['169.254.x link-local', 'https://169.254.169.254/hook'],
    ])('%s is blocked', (_label, url) => {
      const result = realWebhook.validateWebhookUrl(url);
      expect(result).toEqual({ valid: false, error: 'Internal or private IPs are not allowed' });
    });

    test('172.15.x (just below the private range) is NOT blocked — regex boundary is exact', () => {
      expect(realWebhook.validateWebhookUrl('https://172.15.255.255/hook')).toEqual({ valid: true });
    });

    test('172.32.x (just above the private range) is NOT blocked — regex boundary is exact', () => {
      expect(realWebhook.validateWebhookUrl('https://172.32.0.1/hook')).toEqual({ valid: true });
    });

    // Quirk #5 (SECURITY GAP): Node's URL parser serializes IPv6 hostnames
    // WITH brackets (e.g. "[::1]"), but SSRF_BLOCKLIST's IPv6 patterns
    // (/^::1$/, /^fc00:/i, /^fd00:/i) have no bracket handling, so they never
    // match against the real .hostname value. These entries are effectively
    // dead code. Pinning CURRENT behavior (valid: true) so a future fix shows
    // up as an intentional test change rather than a silent regression.
    test('SECURITY GAP: [::1] IPv6 loopback is NOT actually blocked', () => {
      const result = realWebhook.validateWebhookUrl('https://[::1]/hook');
      expect(result.valid).toBe(true);
    });

    test('SECURITY GAP: [fc00::1] IPv6 ULA is NOT actually blocked', () => {
      const result = realWebhook.validateWebhookUrl('https://[fc00::1]/hook');
      expect(result.valid).toBe(true);
    });

    test('SECURITY GAP: [fd00::1] IPv6 ULA is NOT actually blocked', () => {
      const result = realWebhook.validateWebhookUrl('https://[fd00::1]/hook');
      expect(result.valid).toBe(true);
    });
  });

  describe('sendWebhookAlert — payload building & retry logic', () => {
    beforeEach(() => {
      jest.spyOn(global, 'setTimeout').mockImplementation((cb) => {
        cb();
        return 0;
      });
    });

    afterEach(() => {
      jest.restoreAllMocks();
      delete global.fetch;
    });

    test('no webhookUrl → returns immediately, fetch never called', async () => {
      global.fetch = jest.fn();
      await realWebhook.sendWebhookAlert({ id: 'tenant_1', webhookUrl: null }, 1, 10);
      expect(global.fetch).not.toHaveBeenCalled();
    });

    test('slack payload shape', async () => {
      global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
      const tenant = {
        id: 'tenant_abcdefgh',
        webhookUrl: 'https://hooks.slack.com/x',
        webhookType: 'slack',
        storeUrl: 'https://mystore.com',
      };

      await realWebhook.sendWebhookAlert(tenant, 5, 123.456, 10, false);

      const [url, options] = global.fetch.mock.calls[0];
      expect(url).toBe('https://hooks.slack.com/x');
      const payload = JSON.parse(options.body);
      expect(payload.attachments[0].blocks[0].text.text).toContain('mystore.com');
      expect(payload.attachments[0].blocks[1].fields[0].text).toContain('5 attempts');
    });

    test('discord payload shape (storeUrl null → "your store" fallback)', async () => {
      global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
      const tenant = {
        id: 'tenant_2',
        webhookUrl: 'https://discord.com/api/webhooks/x',
        webhookType: 'discord',
        storeUrl: null,
      };

      await realWebhook.sendWebhookAlert(tenant, 3, 50, 15, false);

      const payload = JSON.parse(global.fetch.mock.calls[0][1].body);
      expect(payload.username).toBe('ChargeGuard');
      expect(payload.embeds[0].fields[0].value).toBe('3 attempts');
      expect(payload.embeds[0].description).toContain('your store');
    });

    test('custom payload shape (default type), savedAmount rounded to 2 decimals', async () => {
      global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
      const tenant = {
        id: 'tenant_3',
        webhookUrl: 'https://example.com/hook',
        webhookType: 'custom',
        storeUrl: 'https://x.com',
      };

      await realWebhook.sendWebhookAlert(tenant, 2, 19.999, 10, false);

      const payload = JSON.parse(global.fetch.mock.calls[0][1].body);
      expect(payload.event).toBe('attack_detected');
      expect(payload.data.savedAmount).toBe(20);
      expect(payload.data.isTest).toBe(false);
    });

    // Quirk #6: settings.js's /webhook/test passes an OBJECT as extraContext,
    // but sendWebhookAlert's isTest detection is strict `extraContext === true`.
    test('QUIRK: object extraContext with isTest:true does NOT actually mark the payload as a test', async () => {
      global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
      const tenant = { id: 'tenant_4', webhookUrl: 'https://example.com/hook', webhookType: 'custom', storeUrl: null };

      await realWebhook.sendWebhookAlert(tenant, 1, 0.30, 0, { alertType: 'test', isTest: true });

      const payload = JSON.parse(global.fetch.mock.calls[0][1].body);
      expect(payload.event).toBe('attack_detected'); // NOT 'attack_detected_test'
      expect(payload.data.isTest).toBe(false); // NOT true
    });

    test('retries on 503 then succeeds', async () => {
      global.fetch = jest
        .fn()
        .mockResolvedValueOnce({ ok: false, status: 503, text: async () => 'unavailable' })
        .mockResolvedValueOnce({ ok: true, status: 200 });
      const tenant = { id: 'tenant_5', webhookUrl: 'https://example.com/hook', webhookType: 'custom' };

      await expect(realWebhook.sendWebhookAlert(tenant, 1, 10)).resolves.toBeUndefined();
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    test('429 is retryable', async () => {
      global.fetch = jest
        .fn()
        .mockResolvedValueOnce({ ok: false, status: 429, text: async () => 'rate limited' })
        .mockResolvedValueOnce({ ok: true, status: 200 });
      const tenant = { id: 'tenant_7', webhookUrl: 'https://example.com/hook', webhookType: 'custom' };

      await expect(realWebhook.sendWebhookAlert(tenant, 1, 10)).resolves.toBeUndefined();
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    test('non-retryable 4xx (404) throws immediately, no retry', async () => {
      global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 404, text: async () => 'not found' });
      const tenant = { id: 'tenant_6', webhookUrl: 'https://example.com/hook', webhookType: 'custom' };

      await expect(realWebhook.sendWebhookAlert(tenant, 1, 10)).rejects.toThrow('HTTP 404');
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    test('exhausts all 3 retries on persistent 500 → throws last error', async () => {
      global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 500, text: async () => 'server error' });
      const tenant = { id: 'tenant_8', webhookUrl: 'https://example.com/hook', webhookType: 'custom' };

      await expect(realWebhook.sendWebhookAlert(tenant, 1, 10)).rejects.toThrow('HTTP 500');
      expect(global.fetch).toHaveBeenCalledTimes(3);
    });

    test('AbortError (timeout) retries up to RETRIES then throws', async () => {
      const abortErr = new Error('The operation was aborted');
      abortErr.name = 'AbortError';
      global.fetch = jest.fn().mockRejectedValue(abortErr);
      const tenant = { id: 'tenant_10', webhookUrl: 'https://example.com/hook', webhookType: 'custom' };

      await expect(realWebhook.sendWebhookAlert(tenant, 1, 10)).rejects.toThrow('aborted');
      expect(global.fetch).toHaveBeenCalledTimes(3);
    });

    // Quirk #7: a generic thrown error (no .response, not AbortError) breaks
    // the retry loop after a single attempt.
    test('QUIRK: generic network error (no .response) is NOT retried despite RETRIES=3', async () => {
      global.fetch = jest.fn().mockRejectedValue(new Error('getaddrinfo ENOTFOUND'));
      const tenant = { id: 'tenant_11', webhookUrl: 'https://example.com/hook', webhookType: 'custom' };

      await expect(realWebhook.sendWebhookAlert(tenant, 1, 10)).rejects.toThrow('ENOTFOUND');
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });
  });
});