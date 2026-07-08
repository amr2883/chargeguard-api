'use strict';

// ══════════════════════════════════════════════════════════════════════════════
// SCOPE:
//   - src/routes/settings.js — Geo Risk Overrides
//       - GET /country-overrides
//       - PUT /country-overrides
//   - src/lib/binIntelligence.js — calculateBINPenalty (real, unmocked)
//   - src/lib/countryRisk.js — getAvailableCountries, calculateCountryRiskPenalty
//     (real, unmocked throughout this entire file — it's pure/self-contained
//     and IS the actual integration point exercised by the live checkout path,
//     so faking it would test nothing real)
//
// MOCKING STRATEGY:
//   - db.js mocked (manual factory) — only tenant.update is used by the PUT route.
//     binIntelligence.js also imports db.js at module scope (for getBINIntelligence,
//     which we never call here) — mocked purely so requiring binIntelligence.js
//     doesn't pull in a real Prisma client.
//   - lib/metrics.js and lib/prometheus.js mocked as inert stubs for the same
//     reason (only used by getBINIntelligence, not by calculateBINPenalty).
//   - logger.js mocked to silence output.
//   - lib/apiKeyAuth.js: only resolveTenantByApiKey mocked; middleware/authenticate.js
//     (requireAuth) runs for real, per T2/T6 convention.
//   - lib/domainAuth.js mocked with a benign stub (dead import in settings.js).
//   - middleware/verifyHmac.js NOT mocked — real HMAC computed via signRequest().
//   - lib/countryRisk.js is NEVER mocked in this file (see above).
//
// KNOWN REAL COUNTRY DATA (src/lib/countryRisk.js — pinned here for reference,
// tests are coupled to this table; update both together if tiers ever change):
//   critical {NG, CM, GH} basePenalty=15  severity=high
//   high     {PK, BD}     basePenalty=10  severity=high
//   medium   {VN, ID, PH} basePenalty=6   severity=medium
//   elevated {RO, UA}     basePenalty=3   severity=medium
//   → getAvailableCountries() returns exactly 10 countries.
//
// QUIRKS DISCOVERED (documented inline at point of relevance too):
//   - settings.js's local getEffectivePenalty() (GET display only) does NOT
//     apply countryRisk.js's amount-based scaling (full vs. halved base) — it
//     always uses the raw basePenalty. It is a simplified PREVIEW for the UI,
//     not the actual per-checkout penalty, which only calculateBINPenalty /
//     calculateCountryRiskPenalty (with a real order amount) compute.
//   - calculateCountryRiskPenalty scales BEFORE applying the escalate
//     multiplier: for amount<=100, scaledPenalty = floor(basePenalty/2), and
//     ONLY THEN is escalate's x2 applied to that already-halved value — NOT
//     to the raw basePenalty. A $75 NG (critical, base 15) order with
//     'escalate' therefore yields floor(15/2)*2 = 14, not 15*2 = 30.
//   - calculateBINPenalty's Signal 4 gate (`amount > 50`) is a SEPARATE,
//     stricter threshold than countryRisk.js's own internal full/half-scaling
//     gate (`amount > 100`). At exactly $50, country risk is skipped
//     entirely regardless of tier or override; it only engages above $50,
//     and only gets the FULL (non-halved) base once amount also exceeds $100.
//   - PUT /country-overrides HMAC-signs the exact JSON body sent to the route
//     (see signRequest()), same as the webhook routes.
// ══════════════════════════════════════════════════════════════════════════════

jest.mock('../../src/lib/db', () => ({
  tenant: {
    update: jest.fn(),
  },
  binRecord: {
    findUnique: jest.fn(),
    update: jest.fn(),
    upsert: jest.fn(),
  },
}));

jest.mock('../../src/lib/metrics', () => ({
  recordBIN: jest.fn(),
  checkBINLimit: jest.fn(() => true),
  binlistGlobalBucket: { consume: jest.fn(() => true), available: 100 },
}));

jest.mock('../../src/lib/prometheus', () => ({
  recordBINIntel: jest.fn(),
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

const crypto = require('crypto');
const db = require('../../src/lib/db');
const logger = require('../../src/lib/logger');
const { resolveTenantByApiKey } = require('../../src/lib/apiKeyAuth');
const settingsRouter = require('../../src/routes/settings');
const { calculateBINPenalty } = require('../../src/lib/binIntelligence');

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
let apiKeyCounter = 0;
function uniqueApiKey() {
  apiKeyCounter += 1;
  return `test-api-key-geo-${apiKeyCounter}`;
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
    countryOverrides: {},
    ...overrides,
  };
}

function mockAuthenticatedTenant(tenant) {
  resolveTenantByApiKey.mockResolvedValue({ tenant, usedPreviousKey: false });
}

function signRequest(secret, bodyObj, timestamp = Math.floor(Date.now() / 1000).toString()) {
  const rawBody = Buffer.from(JSON.stringify(bodyObj));
  const signedStr = `${timestamp}.${rawBody.toString('utf8')}`;
  const sig = 'v1=' + crypto.createHmac('sha256', secret).update(signedStr).digest('hex');
  return { 'x-chargeguard-signature': sig, 'x-chargeguard-timestamp': timestamp };
}

function applyPersistentDefaults() {
  db.tenant.update.mockResolvedValue({});
}

beforeAll(() => {
  process.env.EMAIL_VERIFICATION_DISABLED = 'false';
});

beforeEach(() => {
  jest.resetAllMocks();
  applyPersistentDefaults();
});

// ══════════════════════════════════════════════════════════════════════════════
describe('GET /country-overrides', () => {
  const handlers = () => getRouteHandlers('get', '/country-overrides');

  test('no overrides set → every country defaults to "smart", nothing modified', async () => {
    mockAuthenticatedTenant(makeTenant({ countryOverrides: {} }));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    const payload = res.json.mock.calls[0][0];
    expect(payload.success).toBe(true);
    expect(payload.availableCountries).toHaveLength(10);
    expect(payload.availableCountries.every((c) => c.currentOverride === 'smart')).toBe(true);
    expect(payload.availableCountries.every((c) => c.isModified === false)).toBe(true);
    expect(payload.summary).toEqual({
      totalCountries: 10,
      modifiedCount: 0,
      allowCount: 0,
      escalateCount: 0,
    });
    // smart/default → effectivePenalty === raw basePenalty, unscaled
    const ng = payload.availableCountries.find((c) => c.code === 'NG');
    expect(ng.effectivePenalty).toBe(15);
  });

  test('null/undefined countryOverrides on tenant → same defaults as {}', async () => {
    mockAuthenticatedTenant(makeTenant({ countryOverrides: null }));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    const payload = res.json.mock.calls[0][0];
    expect(payload.countryOverrides).toEqual({});
    expect(payload.summary.modifiedCount).toBe(0);
  });

  test('mixed overrides: escalate (capped) + allow, correct effectivePenalty and summary counts', async () => {
    mockAuthenticatedTenant(makeTenant({ countryOverrides: { NG: 'escalate', PH: 'allow' } }));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    const payload = res.json.mock.calls[0][0];
    const ng = payload.availableCountries.find((c) => c.code === 'NG');
    const ph = payload.availableCountries.find((c) => c.code === 'PH');
    const ro = payload.availableCountries.find((c) => c.code === 'RO');

    // NG base 15, escalate → min(15*2, 20) = 20 (capped)
    expect(ng.currentOverride).toBe('escalate');
    expect(ng.effectivePenalty).toBe(20);
    expect(ng.isModified).toBe(true);

    // PH allow → suppressed to 0
    expect(ph.currentOverride).toBe('allow');
    expect(ph.effectivePenalty).toBe(0);
    expect(ph.isModified).toBe(true);

    // untouched country stays default
    expect(ro.currentOverride).toBe('smart');
    expect(ro.isModified).toBe(false);

    expect(payload.summary).toEqual({
      totalCountries: 10,
      modifiedCount: 2,
      allowCount: 1,
      escalateCount: 1,
    });
  });

  test('escalate on a low-base country doubles cleanly without hitting the cap', async () => {
    mockAuthenticatedTenant(makeTenant({ countryOverrides: { RO: 'escalate' } }));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    const payload = res.json.mock.calls[0][0];
    const ro = payload.availableCountries.find((c) => c.code === 'RO');
    // RO base 3 → 3*2 = 6, well under the cap of 20
    expect(ro.effectivePenalty).toBe(6);
  });

  test('stale/unknown country code in raw overrides is preserved in the raw map but ignored in availableCountries', async () => {
    mockAuthenticatedTenant(makeTenant({ countryOverrides: { XX: 'escalate', NG: 'allow' } }));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    const payload = res.json.mock.calls[0][0];
    expect(payload.countryOverrides).toEqual({ XX: 'escalate', NG: 'allow' });
    expect(payload.availableCountries.some((c) => c.code === 'XX')).toBe(false);
    // summary counts are derived from availableCountries (the known list), so
    // the stale 'XX' entry does not inflate modifiedCount/escalateCount.
    expect(payload.summary.modifiedCount).toBe(1);
    expect(payload.summary.allowCount).toBe(1);
    expect(payload.summary.escalateCount).toBe(0);
  });

  test('unexpected error reading tenant field → 500', async () => {
    const throwingTenant = new Proxy(makeTenant(), {
      get(target, prop) {
        if (prop === 'countryOverrides') throw new Error('boom');
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
  });

  test('unverified tenant → 403 EMAIL_NOT_VERIFIED', async () => {
    mockAuthenticatedTenant(makeTenant({ emailVerified: false }));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'EMAIL_NOT_VERIFIED' }));
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('PUT /country-overrides', () => {
  const handlers = () => getRouteHandlers('put', '/country-overrides');

  function putReq(tenant, updates) {
    const body = { updates };
    return makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
  }

  describe('validation', () => {
    test('missing updates key → 400', async () => {
      const tenant = makeTenant();
      mockAuthenticatedTenant(tenant);
      const body = {};
      const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'updates must be a non-empty array' });
    });

    test('empty updates array → 400', async () => {
      const tenant = makeTenant();
      mockAuthenticatedTenant(tenant);
      const req = putReq(tenant, []);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'updates must be a non-empty array' });
    });

    test('updates not an array → 400', async () => {
      const tenant = makeTenant();
      mockAuthenticatedTenant(tenant);
      const body = { updates: 'NG:escalate' };
      const req = makeReq({ body, headers: signRequest(tenant.webhookSecret, body) });
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'updates must be a non-empty array' });
    });

    test('update missing countryCode or override → 400 with details', async () => {
      const tenant = makeTenant();
      mockAuthenticatedTenant(tenant);
      const req = putReq(tenant, [{ countryCode: 'NG' }, { override: 'allow' }]);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      const payload = res.json.mock.calls[0][0];
      expect(payload.error).toBe('Validation failed');
      expect(payload.details).toEqual([
        'Each update must have countryCode and override',
        'Each update must have countryCode and override',
      ]);
    });

    test('unsupported country code → 400 with details', async () => {
      const tenant = makeTenant();
      mockAuthenticatedTenant(tenant);
      const req = putReq(tenant, [{ countryCode: 'ZZ', override: 'escalate' }]);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Validation failed',
        details: ['Unsupported country code: ZZ'],
      });
    });

    test('invalid override value → 400 with details', async () => {
      const tenant = makeTenant();
      mockAuthenticatedTenant(tenant);
      const req = putReq(tenant, [{ countryCode: 'NG', override: 'block' }]);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Validation failed',
        details: ['Invalid override value for NG: must be allow, escalate, or smart'],
      });
    });

    test('multiple validation errors across multiple updates all accumulate', async () => {
      const tenant = makeTenant();
      mockAuthenticatedTenant(tenant);
      const req = putReq(tenant, [
        { countryCode: 'ZZ', override: 'escalate' },
        { countryCode: 'NG', override: 'block' },
        { override: 'allow' },
      ]);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const payload = res.json.mock.calls[0][0];
      expect(payload.details).toEqual([
        'Unsupported country code: ZZ',
        'Invalid override value for NG: must be allow, escalate, or smart',
        'Each update must have countryCode and override',
      ]);
      expect(db.tenant.update).not.toHaveBeenCalled();
    });

    test('lowercase country code is accepted (validation is case-insensitive)', async () => {
      const tenant = makeTenant();
      mockAuthenticatedTenant(tenant);
      const req = putReq(tenant, [{ countryCode: 'ng', override: 'escalate' }]);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).not.toHaveBeenCalledWith(400);
      expect(db.tenant.update).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ countryOverrides: { NG: 'escalate' } }) })
      );
    });
  });

  describe('handler logic', () => {
    test('escalate applied and persisted, no warning for non-critical tier', async () => {
      const tenant = makeTenant({ countryOverrides: {} });
      mockAuthenticatedTenant(tenant);
      const req = putReq(tenant, [{ countryCode: 'VN', override: 'escalate' }]);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(db.tenant.update).toHaveBeenCalledWith({
        where: { id: 'tenant_1' },
        data: {
          countryOverrides: { VN: 'escalate' },
          countryOverridesUpdatedAt: expect.any(Date),
        },
      });
      const payload = res.json.mock.calls[0][0];
      expect(payload.success).toBe(true);
      expect(payload.countryOverrides).toEqual({ VN: 'escalate' });
      expect(payload.warnings).toEqual([]);
      expect(payload.updatedAt).toEqual(expect.any(String));
    });

    test('allow on a critical-tier country produces a warning with the exact country name', async () => {
      const tenant = makeTenant({ countryOverrides: {} });
      mockAuthenticatedTenant(tenant);
      const req = putReq(tenant, [{ countryCode: 'NG', override: 'allow' }]);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const payload = res.json.mock.calls[0][0];
      expect(payload.warnings).toEqual([
        {
          countryCode: 'NG',
          message:
            'Nigeria is a critical-risk region with high fraud rates — allowing may increase chargebacks',
        },
      ]);
    });

    test('allow on a non-critical-tier country produces no warning', async () => {
      const tenant = makeTenant({ countryOverrides: {} });
      mockAuthenticatedTenant(tenant);
      const req = putReq(tenant, [{ countryCode: 'PH', override: 'allow' }]);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const payload = res.json.mock.calls[0][0];
      expect(payload.warnings).toEqual([]);
    });

    test('smart deletes an existing override key', async () => {
      const tenant = makeTenant({ countryOverrides: { NG: 'escalate', PH: 'allow' } });
      mockAuthenticatedTenant(tenant);
      const req = putReq(tenant, [{ countryCode: 'NG', override: 'smart' }]);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(db.tenant.update).toHaveBeenCalledWith({
        where: { id: 'tenant_1' },
        data: {
          countryOverrides: { PH: 'allow' },
          countryOverridesUpdatedAt: expect.any(Date),
        },
      });
    });

    test('smart on a country with no existing override is a safe no-op', async () => {
      const tenant = makeTenant({ countryOverrides: { PH: 'allow' } });
      mockAuthenticatedTenant(tenant);
      const req = putReq(tenant, [{ countryCode: 'NG', override: 'smart' }]);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(db.tenant.update).toHaveBeenCalledWith({
        where: { id: 'tenant_1' },
        data: {
          countryOverrides: { PH: 'allow' },
          countryOverridesUpdatedAt: expect.any(Date),
        },
      });
    });

    test('multiple updates in one request are applied together atomically', async () => {
      const tenant = makeTenant({ countryOverrides: { RO: 'escalate' } });
      mockAuthenticatedTenant(tenant);
      const req = putReq(tenant, [
        { countryCode: 'NG', override: 'escalate' },
        { countryCode: 'PH', override: 'allow' },
        { countryCode: 'RO', override: 'smart' },
      ]);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(db.tenant.update).toHaveBeenCalledTimes(1);
      expect(db.tenant.update).toHaveBeenCalledWith({
        where: { id: 'tenant_1' },
        data: {
          countryOverrides: { NG: 'escalate', PH: 'allow' },
          countryOverridesUpdatedAt: expect.any(Date),
        },
      });
    });

    test('pre-existing overrides not mentioned in this request are preserved', async () => {
      const tenant = makeTenant({ countryOverrides: { BD: 'escalate' } });
      mockAuthenticatedTenant(tenant);
      const req = putReq(tenant, [{ countryCode: 'NG', override: 'allow' }]);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(db.tenant.update).toHaveBeenCalledWith({
        where: { id: 'tenant_1' },
        data: {
          countryOverrides: { BD: 'escalate', NG: 'allow' },
          countryOverridesUpdatedAt: expect.any(Date),
        },
      });
    });

    test('db.tenant.update throws → 500', async () => {
      const tenant = makeTenant();
      mockAuthenticatedTenant(tenant);
      db.tenant.update.mockRejectedValue(new Error('db down'));
      const req = putReq(tenant, [{ countryCode: 'NG', override: 'escalate' }]);
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(logger.error).toHaveBeenCalled();
    });

    test('missing HMAC headers → 401, handler never reached', async () => {
      const tenant = makeTenant();
      mockAuthenticatedTenant(tenant);
      const req = makeReq({ body: { updates: [{ countryCode: 'NG', override: 'escalate' }] } });
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(db.tenant.update).not.toHaveBeenCalled();
    });

    test('invalid HMAC signature → 401', async () => {
      const tenant = makeTenant();
      mockAuthenticatedTenant(tenant);
      const body = { updates: [{ countryCode: 'NG', override: 'escalate' }] };
      const req = makeReq({ body, headers: signRequest('wrong-secret', body) });
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(db.tenant.update).not.toHaveBeenCalled();
    });
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Real, unmocked integration point: calculateBINPenalty (binIntelligence.js)
// calling into calculateCountryRiskPenalty (countryRisk.js). This is the
// actual code path exercised on a live checkout via calculateRiskScore — the
// settings routes above only ever read/write the override VALUE, they never
// apply it. Full calculateRiskScore orchestration (identity graph, pattern
// sharing, email/IP intel, etc.) is out of scope for Test 8 and already
// covered by the T3d-6/T3d-7 phases; this suite verifies the override
// actually changes the penalty/flags at the seam where it's consumed.
describe('calculateBINPenalty × countryRisk integration (real, unmocked)', () => {
  function baseBinIntel(overrides = {}) {
    return {
      source: 'local_db',
      isPrepaid: false,
      isCommercial: false,
      brand: 'VISA',
      cardType: 'credit',
      issuerCountry: 'NG',
      ...overrides,
    };
  }

  // billingAddress.country matches issuerCountry throughout most of these
  // tests specifically to keep Signal 2 (country mismatch) OUT of the way,
  // isolating Signal 4 (country risk) so the numbers are unambiguous.
  function baseOrder(amount, country = 'NG') {
    return { amount, billingAddress: { country } };
  }

  test('escalate doubles the country-risk penalty and caps at 20', () => {
    const merchantConfig = { countryOverrides: { NG: 'escalate' } };
    const result = calculateBINPenalty(baseBinIntel(), baseOrder(150), false, null, merchantConfig);

    // NG critical base=15, amount>100 → full scale (15), escalate → min(15*2,20)=20
    expect(result.penalty).toBeCloseTo(20);
    expect(result.flags).toEqual([
      { severity: 'high', text: 'Card issued in critical-risk region (NG)' },
    ]);
  });

  test('allow suppresses the country-risk penalty entirely', () => {
    const merchantConfig = { countryOverrides: { NG: 'allow' } };
    const result = calculateBINPenalty(baseBinIntel(), baseOrder(150), false, null, merchantConfig);

    expect(result.penalty).toBeCloseTo(0);
    expect(result.flags).toEqual([]);
  });

  test('no override (undefined merchantConfig) applies the unescalated default tier penalty', () => {
    const result = calculateBINPenalty(baseBinIntel(), baseOrder(150), false, null, null);

    expect(result.penalty).toBeCloseTo(15);
    expect(result.flags).toHaveLength(1);
  });

  test('no override for this specific country (other overrides present) still applies default', () => {
    const merchantConfig = { countryOverrides: { PH: 'allow' } };
    const result = calculateBINPenalty(baseBinIntel(), baseOrder(150), false, null, merchantConfig);

    expect(result.penalty).toBeCloseTo(15);
  });

  test('amount <= 100 with no override halves the base penalty', () => {
    const result = calculateBINPenalty(baseBinIntel(), baseOrder(80), false, null, null);

    // floor(15/2) = 7
    expect(result.penalty).toBeCloseTo(7);
  });

  test('QUIRK: escalate multiplies the already-halved scaled penalty, not the raw base', () => {
    const merchantConfig = { countryOverrides: { NG: 'escalate' } };
    const result = calculateBINPenalty(baseBinIntel(), baseOrder(80), false, null, merchantConfig);

    // scaledPenalty = floor(15/2) = 7, THEN escalate doubles the scaled value: min(7*2,20)=14
    // (NOT 15*2=30 — escalate never sees the raw basePenalty at this amount)
    expect(result.penalty).toBeCloseTo(14);
  });

  test('cap boundary: high-tier base doubled lands exactly at the cap with no distortion', () => {
    const merchantConfig = { countryOverrides: { PK: 'escalate' } };
    const result = calculateBINPenalty(
      baseBinIntel({ issuerCountry: 'PK' }),
      baseOrder(150, 'PK'),
      false,
      null,
      merchantConfig
    );

    // PK high base=10, amount>100 → full scale 10, escalate → min(10*2,20)=20 exactly
    expect(result.penalty).toBeCloseTo(20);
  });

  test('QUIRK boundary: amount === 50 skips country risk entirely (outer gate is amount > 50)', () => {
    const result = calculateBINPenalty(baseBinIntel(), baseOrder(50), false, null, null);
    expect(result.penalty).toBeCloseTo(0);
    expect(result.flags).toEqual([]);
  });

  test('amount === 51 engages country risk at the halved (amount<=100) scale', () => {
    const result = calculateBINPenalty(baseBinIntel(), baseOrder(51), false, null, null);
    expect(result.penalty).toBeCloseTo(7); // floor(15/2)
  });

  test('amount === 100 still uses the halved scale (full scale requires amount > 100)', () => {
    const result = calculateBINPenalty(baseBinIntel(), baseOrder(100), false, null, null);
    expect(result.penalty).toBeCloseTo(7);
  });

  test('amount === 101 engages the full (unhalved) base penalty', () => {
    const result = calculateBINPenalty(baseBinIntel(), baseOrder(101), false, null, null);
    expect(result.penalty).toBeCloseTo(15);
  });

  test('country not present in any tier → no penalty regardless of override', () => {
    const merchantConfig = { countryOverrides: { US: 'escalate' } };
    const result = calculateBINPenalty(
      baseBinIntel({ issuerCountry: 'US' }),
      baseOrder(150, 'US'),
      false,
      null,
      merchantConfig
    );

    expect(result.penalty).toBeCloseTo(0);
    expect(result.flags).toEqual([]);
  });

  test('clean two-signal probabilistic combination (no cap interference)', () => {
    // Signal 1 (prepaid, amount<=200 → base 10) + Signal 4 (NG default, amount>100 → 15)
    // addPenalty formula: penalty = penalty + p - (penalty*p)/100
    //   10 -> 10
    //   +15 -> 10 + 15 - (10*15)/100 = 25 - 1.5 = 23.5
    const binIntel = baseBinIntel({ isPrepaid: true });
    const result = calculateBINPenalty(binIntel, baseOrder(150), false, null, null);

    expect(result.penalty).toBeCloseTo(23.5);
    expect(result.flags).toHaveLength(2);
  });

  test('cap at 40 enforced when stacked signals (prepaid + new-customer combo + escalated country) exceed it', () => {
    // Signal 1: prepaid, amount>200 -> base 20 -> penalty=20
    // Signal 1 combo: isNewCustomer && amount>=150 -> +20 -> 20+20-(20*20)/100=36
    // Signal 4: NG escalate, amount>100 -> +20 -> 36+20-(36*20)/100=48.8 -> capped to 40
    const binIntel = baseBinIntel({ isPrepaid: true });
    const merchantConfig = { countryOverrides: { NG: 'escalate' } };
    const result = calculateBINPenalty(binIntel, baseOrder(250), true, null, merchantConfig);

    expect(result.penalty).toBeCloseTo(40);
    expect(result.flags).toHaveLength(3);
  });
});