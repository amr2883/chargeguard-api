'use strict';

// ══════════════════════════════════════════════════════════════════════════════
// SCOPE: src/routes/payments.js
//   - POST /create-checkout-session
//   - GET  /checkout-session/:sessionId
//   - POST /paypal-webhook
//   - GET  /subscription-status
//
// MOCKING STRATEGY:
//   - db.js fully mocked (manual factory — Prisma client isn't statically
//     analyzable for jest.mock automock, so every model method used by
//     payments.js is stubbed explicitly).
//   - logger.js mocked to silence output; not asserted on unless useful.
//   - email.js mocked — only sendSubscriptionConfirmationEmail is used here.
//   - global.fetch mocked via jest.spyOn for the two outbound PayPal calls
//     (OAuth token + webhook signature verification). Restored in afterEach.
//   - middleware/authenticate.js is NOT mocked. We run the REAL requireAuth
//     middleware by extracting the full route stack (auth + handler) off the
//     Express Router instance and dispatching it ourselves, exactly like
//     Express would. Only `resolveTenantByApiKey` (lib/apiKeyAuth.js) is
//     mocked, so the emailVerified / isActive branches inside requireAuth get
//     real coverage.
//   - express.raw() body-parser middleware on /paypal-webhook is SKIPPED —
//     we only extract the final async handler and hand it a pre-built
//     Buffer as req.body, exactly what express.raw() would have produced.
//
// QUIRKS DISCOVERED (documented inline where relevant):
//   - /paypal-webhook sends res.status(200) BEFORE any DB reads/writes and
//     BEFORE the event_type check. Every "downstream" test below (duplicate,
//     session-not-found, amount-mismatch, happy path, etc.) sees 200 already
//     sent; we assert on DB/email side effects separately.
//   - The confirmation email fires via a real 2s setTimeout (fire-and-forget,
//     not awaited by the handler). We spy on global.setTimeout and invoke the
//     callback synchronously so tests don't block for 2 real seconds — this
//     matches the "real timers" strategy (as opposed to jest fake timers,
//     which are reserved for the scheduler test file).
// ══════════════════════════════════════════════════════════════════════════════

jest.mock('../../src/lib/db', () => ({
  tenant: {
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  checkoutSession: {
    findFirst: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  },
  payment: {
    findUnique: jest.fn(),
    create: jest.fn(),
  },
  $transaction: jest.fn(),
}));

jest.mock('../../src/lib/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

jest.mock('../../src/lib/email', () => ({
  sendSubscriptionConfirmationEmail: jest.fn().mockResolvedValue(undefined),
}));

// Only resolveTenantByApiKey is mocked — middleware/authenticate.js runs for real.
jest.mock('../../src/lib/apiKeyAuth', () => ({
  resolveTenantByApiKey: jest.fn(),
}));

const db = require('../../src/lib/db');
const logger = require('../../src/lib/logger');
const { sendSubscriptionConfirmationEmail } = require('../../src/lib/email');
const { resolveTenantByApiKey } = require('../../src/lib/apiKeyAuth');
const paymentsRouter = require('../../src/routes/payments');

// ── Route-stack extraction helpers ──────────────────────────────────────────
// Pulls the real middleware chain (e.g. [apiKeyAuth, handler]) off the
// Express Router instance so we exercise the actual requireAuth logic
// instead of re-implementing/mocking it.
function getRouteHandlers(method, path) {
  const layer = paymentsRouter.stack.find(
    (l) => l.route && l.route.path === path && l.route.methods[method.toLowerCase()]
  );
  if (!layer) throw new Error(`Route not found: ${method.toUpperCase()} ${path}`);
  return layer.route.stack.map((s) => s.handle);
}

async function dispatch(handlers, req, res, i = 0) {
  if (i >= handlers.length) return;
  const handler = handlers[i];
  await handler(req, res, (err) => {
    if (err) throw err;
    return dispatch(handlers, req, res, i + 1);
  });
}

// ── Factories ────────────────────────────────────────────────────────────────
function makeReq(overrides = {}) {
  return {
    headers: { 'x-api-key': 'test-api-key' },
    body: {},
    params: {},
    ...overrides,
  };
}

function makeRes() {
  const res = {};
  res._ended = false;
  res.statusCode = 200;
  res.status = jest.fn((code) => {
    res.statusCode = code;
    return res;
  });
  res.json = jest.fn((body) => {
    res._ended = true;
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
    plan: 'early_access',
    subscriptionStatus: 'free',
    subscriptionEndDate: null,
    ...overrides,
  };
}

function makeSession(overrides = {}) {
  return {
    id: 'sess_123',
    tenantId: 'tenant_1',
    planId: 'pro_monthly',
    amount: 19,
    billingCycle: 'monthly',
    status: 'pending',
    expiresAt: new Date(Date.now() + 30 * 60 * 1000),
    ...overrides,
  };
}

// Sets up resolveTenantByApiKey so the REAL requireAuth middleware passes
// through cleanly and attaches req.tenant.
function mockAuthenticatedTenant(tenant) {
  resolveTenantByApiKey.mockResolvedValue({ tenant, usedPreviousKey: false });
}

beforeAll(() => {
  process.env.EMAIL_VERIFICATION_DISABLED = 'false';
  process.env.PAYPAL_CLIENT_ID = 'test-client-id';
  process.env.PAYPAL_CLIENT_SECRET = 'test-client-secret';
  process.env.PAYPAL_MODE = 'sandbox';
});

beforeEach(() => {
  jest.clearAllMocks();
  process.env.PAYPAL_WEBHOOK_ID = 'test-webhook-id';
});

// ══════════════════════════════════════════════════════════════════════════════
describe('POST /create-checkout-session', () => {
  const handlers = () => getRouteHandlers('post', '/create-checkout-session');

  test('missing/unknown planId → 400 with valid-plans message', async () => {
    mockAuthenticatedTenant(makeTenant());
    const req = makeReq({ body: { planId: 'not_a_real_plan' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      error:
        'Invalid planId. Must be one of: pro_monthly, pro_annual, agency_monthly, agency_annual',
    });
    expect(db.checkoutSession.findFirst).not.toHaveBeenCalled();
  });

  test('unverified tenant (real requireAuth) → 403 EMAIL_NOT_VERIFIED, no session created', async () => {
    mockAuthenticatedTenant(makeTenant({ emailVerified: false }));
    const req = makeReq({ body: { planId: 'pro_monthly' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ code: 'EMAIL_NOT_VERIFIED' })
    );
    // Route handler itself never ran — requireAuth short-circuited.
    expect(db.checkoutSession.findFirst).not.toHaveBeenCalled();
    expect(db.checkoutSession.create).not.toHaveBeenCalled();
  });

  test('existing pending unexpired session for tenant+plan → returns existing, create NOT called', async () => {
    mockAuthenticatedTenant(makeTenant());
    const existing = makeSession({ id: 'sess_existing' });
    db.checkoutSession.findFirst.mockResolvedValue(existing);

    const req = makeReq({ body: { planId: 'pro_monthly' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        sessionId: 'sess_existing',
        planLabel: 'Pro Monthly',
        amount: 19,
        billingCycle: 'monthly',
      })
    );
    expect(db.checkoutSession.create).not.toHaveBeenCalled();
  });

  test('no existing session → creates new, expiresAt = now+30min', async () => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-07-07T00:00:00.000Z'));

    mockAuthenticatedTenant(makeTenant());
    db.checkoutSession.findFirst.mockResolvedValue(null);
    db.checkoutSession.create.mockResolvedValue({ id: 'sess_new' });

    const req = makeReq({ body: { planId: 'agency_annual' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    const expectedExpiresAt = new Date('2026-07-07T00:30:00.000Z');

    expect(db.checkoutSession.create).toHaveBeenCalledWith({
      data: {
        tenantId: 'tenant_1',
        planId: 'agency_annual',
        amount: 399,
        billingCycle: 'annual',
        status: 'pending',
        expiresAt: expectedExpiresAt,
      },
    });
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        sessionId: 'sess_new',
        planLabel: 'Agency Annual',
        amount: 399,
        billingCycle: 'annual',
        expiresAt: expectedExpiresAt,
      })
    );

    jest.useRealTimers();
  });

  test('DB throws → 500', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.checkoutSession.findFirst.mockRejectedValue(new Error('db down'));

    const req = makeReq({ body: { planId: 'pro_monthly' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(logger.error).toHaveBeenCalled();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('GET /checkout-session/:sessionId', () => {
  // No auth middleware on this route — single handler.
  const handler = () => getRouteHandlers('get', '/checkout-session/:sessionId')[0];

  test('not found → 404', async () => {
    db.checkoutSession.findUnique.mockResolvedValue(null);
    const req = makeReq({ params: { sessionId: 'missing' } });
    const res = makeRes();

    await handler()(req, res);

    expect(res.status).toHaveBeenCalledWith(404);
  });

  test('status !== pending → 410 + status', async () => {
    db.checkoutSession.findUnique.mockResolvedValue(
      makeSession({ status: 'completed', tenant: { email: 'a@b.com' } })
    );
    const req = makeReq({ params: { sessionId: 'sess_123' } });
    const res = makeRes();

    await handler()(req, res);

    expect(res.status).toHaveBeenCalledWith(410);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'completed' })
    );
  });

  test('expired by time → updates status→expired, 410', async () => {
    const pastExpiry = new Date(Date.now() - 1000);
    db.checkoutSession.findUnique.mockResolvedValue(
      makeSession({ status: 'pending', expiresAt: pastExpiry, tenant: { email: 'a@b.com' } })
    );
    const req = makeReq({ params: { sessionId: 'sess_123' } });
    const res = makeRes();

    await handler()(req, res);

    expect(db.checkoutSession.update).toHaveBeenCalledWith({
      where: { id: 'sess_123' },
      data: { status: 'expired' },
    });
    expect(res.status).toHaveBeenCalledWith(410);
    // NOTE: this branch's error body does NOT include a `status` field
    // (unlike the "already used" 410 above) — different shape, documented here.
    expect(res.json).not.toHaveBeenCalledWith(expect.objectContaining({ status: expect.anything() }));
  });

  test('valid pending → 200, correct fields, email from tenant.email', async () => {
    const future = new Date(Date.now() + 60000);
    db.checkoutSession.findUnique.mockResolvedValue(
      makeSession({
        status: 'pending',
        expiresAt: future,
        planId: 'pro_monthly',
        tenant: { email: 'merchant@example.com' },
      })
    );
    const req = makeReq({ params: { sessionId: 'sess_123' } });
    const res = makeRes();

    await handler()(req, res);

    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        sessionId: 'sess_123',
        planId: 'pro_monthly',
        planLabel: 'Pro Monthly',
        amount: 19,
        billingCycle: 'monthly',
        tenantEmail: 'merchant@example.com',
        expiresAt: future,
      })
    );
  });

  test('planId not in PLAN_CONFIG → planLabel falls back to raw planId', async () => {
    const future = new Date(Date.now() + 60000);
    db.checkoutSession.findUnique.mockResolvedValue(
      makeSession({
        status: 'pending',
        expiresAt: future,
        planId: 'legacy_custom_plan',
        tenant: { email: 'a@b.com' },
      })
    );
    const req = makeReq({ params: { sessionId: 'sess_123' } });
    const res = makeRes();

    await handler()(req, res);

    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ planLabel: 'legacy_custom_plan' })
    );
  });

  test('DB throws → 500', async () => {
    db.checkoutSession.findUnique.mockRejectedValue(new Error('db down'));
    const req = makeReq({ params: { sessionId: 'sess_123' } });
    const res = makeRes();

    await handler()(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('POST /paypal-webhook', () => {
  // Route stack is [express.raw(), handler] — we skip the raw body-parser
  // middleware entirely and only invoke the real handler, feeding it a
  // pre-built Buffer as req.body (exactly what express.raw() would produce).
  const handler = () => {
    const all = getRouteHandlers('post', '/paypal-webhook');
    return all[all.length - 1];
  };

  const validHeaders = () => ({
    'paypal-transmission-id': 'txn-id-1',
    'paypal-transmission-time': '2026-07-07T00:00:00Z',
    'paypal-cert-url': 'https://api.sandbox.paypal.com/cert',
    'paypal-auth-algo': 'SHA256withRSA',
    'paypal-transmission-sig': 'sig-abc',
  });

  function makeWebhookReq(eventBody, headerOverrides = {}) {
    // IMPORTANT: Pass body as a JSON STRING, not a Buffer.
    // The real handler checks `typeof req.body === 'string'` to decide
    // whether to JSON.parse. Since we skipped the express.raw() middleware
    // (which would normally produce a Buffer), we must supply a string so
    // that the handler's JSON.parse branch is taken and eventBody is
    // correctly parsed into an object with resource.id, custom_id, etc.
    return makeReq({
      headers: { ...validHeaders(), ...headerOverrides },
      body: JSON.stringify(eventBody),
    });
  }

  function makeCaptureEvent(overrides = {}) {
    // Separate resource overrides from top-level overrides to prevent
    // ...overrides from REPLACING the entire carefully-merged `resource`
    // object (JavaScript object spread: later properties win).
    const { resource: resourceOverrides, ...topLevelOverrides } = overrides;
    return {
      event_type: 'PAYMENT.CAPTURE.COMPLETED',
      resource: {
        id: 'capture_1',
        custom_id: 'sess_123',
        amount: { value: '19.00', currency_code: 'USD' },
        supplementary_data: { related_ids: { order_id: 'order_1' } },
        payer: { payer_id: 'payer_1' },
        ...resourceOverrides,
      },
      ...topLevelOverrides,
    };
  }

  function mockSuccessfulVerification() {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ json: async () => ({ access_token: 'tok_abc' }) }) // OAuth token
      .mockResolvedValueOnce({ json: async () => ({ verification_status: 'SUCCESS' }) }); // Verify
  }

  afterEach(() => {
    jest.restoreAllMocks();
    delete global.fetch;
  });

  test('empty body → 400', async () => {
    const req = makeReq({ headers: validHeaders(), body: null });
    const res = makeRes();

    await handler()(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Empty body' });
  });

  test('missing verification headers → 401', async () => {
    const req = makeWebhookReq(makeCaptureEvent(), { 'paypal-transmission-sig': undefined });
    delete req.headers['paypal-transmission-sig'];
    const res = makeRes();

    await handler()(req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Missing PayPal verification headers' });
  });

  test('missing PAYPAL_WEBHOOK_ID env → 401', async () => {
    delete process.env.PAYPAL_WEBHOOK_ID;
    const req = makeWebhookReq(makeCaptureEvent());
    const res = makeRes();

    await handler()(req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Missing PayPal verification headers' });
  });

  test('OAuth token fetch returns no access_token → 401', async () => {
    global.fetch = jest.fn().mockResolvedValueOnce({ json: async () => ({}) });
    const req = makeWebhookReq(makeCaptureEvent());
    const res = makeRes();

    await handler()(req, res);

    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Could not obtain PayPal access token' });
  });

  test('signature verification fails → 401', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ json: async () => ({ access_token: 'tok_abc' }) })
      .mockResolvedValueOnce({ json: async () => ({ verification_status: 'FAILURE' }) });
    const req = makeWebhookReq(makeCaptureEvent());
    const res = makeRes();

    await handler()(req, res);

    expect(global.fetch).toHaveBeenCalledTimes(2);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid webhook signature' });
  });

  test('verification request throws → 500', async () => {
    global.fetch = jest.fn().mockRejectedValueOnce(new Error('network error'));
    const req = makeWebhookReq(makeCaptureEvent());
    const res = makeRes();

    await handler()(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Webhook verification failed' });
  });

  // ── Below this point, verification always succeeds. res.status(200) is
  // sent immediately after verification/parsing — before the event_type
  // check and all DB work — so every test below asserts 200 plus the
  // *absence or presence* of DB side effects, not the HTTP status branching.
  describe('post-verification processing (200 already sent)', () => {
    beforeEach(() => {
      mockSuccessfulVerification();
    });

    test('non-PAYMENT.CAPTURE.COMPLETED event → 200 sent, no DB writes', async () => {
      const req = makeWebhookReq(makeCaptureEvent({ event_type: 'PAYMENT.CAPTURE.DENIED' }));
      const res = makeRes();

      await handler()(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(db.payment.findUnique).not.toHaveBeenCalled();
      expect(db.checkoutSession.findUnique).not.toHaveBeenCalled();
    });

    test('missing captureId/custom_id → 200 sent, no DB writes', async () => {
      const req = makeWebhookReq(
        makeCaptureEvent({ resource: { id: undefined, custom_id: undefined, amount: { value: '19.00' } } })
      );
      const res = makeRes();

      await handler()(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(db.payment.findUnique).not.toHaveBeenCalled();
    });

    test('duplicate captureId (idempotency) → 200 sent, no tenant/payment writes', async () => {
      db.payment.findUnique.mockResolvedValue({ id: 'existing_payment', captureId: 'capture_1' });
      const req = makeWebhookReq(makeCaptureEvent());
      const res = makeRes();

      await handler()(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(db.checkoutSession.findUnique).not.toHaveBeenCalled();
      expect(db.$transaction).not.toHaveBeenCalled();
    });

    test('session not found → 200 sent, no writes', async () => {
      db.payment.findUnique.mockResolvedValue(null);
      db.checkoutSession.findUnique.mockResolvedValue(null);
      const req = makeWebhookReq(makeCaptureEvent());
      const res = makeRes();

      await handler()(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(db.$transaction).not.toHaveBeenCalled();
    });

    test('session not pending → 200 sent, no writes', async () => {
      db.payment.findUnique.mockResolvedValue(null);
      db.checkoutSession.findUnique.mockResolvedValue(
        makeSession({ status: 'completed', tenant: { email: 'a@b.com' } })
      );
      const req = makeWebhookReq(makeCaptureEvent());
      const res = makeRes();

      await handler()(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(db.$transaction).not.toHaveBeenCalled();
    });

    test('amount mismatch (tolerance 0.01) → session marked failed, no tenant/payment writes', async () => {
      db.payment.findUnique.mockResolvedValue(null);
      db.checkoutSession.findUnique.mockResolvedValue(
        makeSession({ status: 'pending', amount: 19, tenantId: 'tenant_1', tenant: { email: 'a@b.com' } })
      );
      const req = makeWebhookReq(
        makeCaptureEvent({ resource: { amount: { value: '25.00', currency_code: 'USD' } } })
      );
      const res = makeRes();

      await handler()(req, res);

      expect(db.checkoutSession.update).toHaveBeenCalledWith({
        where: { id: 'sess_123' },
        data: { status: 'failed' },
      });
      expect(db.$transaction).not.toHaveBeenCalled();
    });

    test('happy path (monthly) → tenant updated, payment created, session completed, confirmation email after 2s delay', async () => {
      db.payment.findUnique.mockResolvedValue(null);
      db.checkoutSession.findUnique.mockResolvedValue(
        makeSession({
          id: 'sess_123',
          tenantId: 'tenant_1',
          planId: 'pro_monthly',
          amount: 19,
          billingCycle: 'monthly',
          status: 'pending',
          tenant: { email: 'merchant@example.com' },
        })
      );

      let capturedTx;
      db.$transaction.mockImplementation(async (cb) => {
        capturedTx = {
          tenant: { update: jest.fn() },
          payment: { create: jest.fn() },
          checkoutSession: { update: jest.fn() },
        };
        await cb(capturedTx);
        return capturedTx;
      });

      // Fire the 2s fire-and-forget setTimeout immediately (real-timer style,
      // just short-circuited so the test doesn't block for 2 real seconds).
      jest.spyOn(global, 'setTimeout').mockImplementation((cb) => {
        cb();
        return 0;
      });

      const req = makeWebhookReq(makeCaptureEvent());
      const res = makeRes();

      await handler()(req, res);

      expect(capturedTx.tenant.update).toHaveBeenCalledWith({
        where: { id: 'tenant_1' },
        data: expect.objectContaining({
          plan: 'pro',
          subscriptionStatus: 'active',
          billingCycle: 'monthly',
          lastPaymentAmount: 19,
          lastCaptureId: 'capture_1',
        }),
      });
      expect(capturedTx.payment.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            tenantId: 'tenant_1',
            checkoutSessionId: 'sess_123',
            captureId: 'capture_1',
            amount: 19,
            expectedAmount: 19,
            status: 'completed',
          }),
        })
      );
      expect(capturedTx.checkoutSession.update).toHaveBeenCalledWith({
        where: { id: 'sess_123' },
        data: { status: 'completed' },
      });
      expect(sendSubscriptionConfirmationEmail).toHaveBeenCalledWith(
        'merchant@example.com',
        expect.objectContaining({ planName: 'pro', billingCycle: 'monthly', amount: 19, captureId: 'capture_1' })
      );
    });

    test('happy path (annual) → endDate = +365d', async () => {
      jest.useFakeTimers();
      jest.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

      db.payment.findUnique.mockResolvedValue(null);
      db.checkoutSession.findUnique.mockResolvedValue(
        makeSession({
          id: 'sess_123',
          tenantId: 'tenant_1',
          planId: 'agency_annual',
          amount: 399,
          billingCycle: 'annual',
          status: 'pending',
          tenant: { email: 'merchant@example.com' },
        })
      );

      let capturedTx;
      db.$transaction.mockImplementation(async (cb) => {
        capturedTx = {
          tenant: { update: jest.fn() },
          payment: { create: jest.fn() },
          checkoutSession: { update: jest.fn() },
        };
        await cb(capturedTx);
        return capturedTx;
      });
      jest.spyOn(global, 'setTimeout').mockImplementation((cb) => {
        cb();
        return 0;
      });

      const req = makeWebhookReq(
        makeCaptureEvent({ resource: { amount: { value: '399.00', currency_code: 'USD' } } })
      );
      const res = makeRes();

      await handler()(req, res);

      const expectedEndDate = new Date('2027-01-01T00:00:00.000Z');
      expect(capturedTx.tenant.update).toHaveBeenCalledWith({
        where: { id: 'tenant_1' },
        data: expect.objectContaining({ subscriptionEndDate: expectedEndDate }),
      });

      jest.useRealTimers();
    });

    test('transaction throws → caught, logged, no crash', async () => {
      db.payment.findUnique.mockResolvedValue(null);
      db.checkoutSession.findUnique.mockResolvedValue(
        makeSession({ status: 'pending', tenant: { email: 'a@b.com' } })
      );
      db.$transaction.mockRejectedValue(new Error('tx failed'));

      const req = makeWebhookReq(makeCaptureEvent());
      const res = makeRes();

      await expect(handler()(req, res)).resolves.not.toThrow();

      expect(res.status).toHaveBeenCalledWith(200);
      expect(logger.error).toHaveBeenCalled();
    });
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('GET /subscription-status', () => {
  const handlers = () => getRouteHandlers('get', '/subscription-status');

  test('tenant not found → 404', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.tenant.findUnique.mockResolvedValue(null);

    const req = makeReq();
    const res = makeRes();
    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(404);
  });

  test('daysRemaining computed correctly (fake system time) → 200', async () => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

    mockAuthenticatedTenant(makeTenant());
    db.tenant.findUnique.mockResolvedValue({
      plan: 'pro',
      subscriptionStatus: 'active',
      subscriptionEndDate: new Date('2026-01-08T00:00:00.000Z'),
      billingCycle: 'monthly',
      lastPaymentDate: new Date('2025-12-08T00:00:00.000Z'),
      lastPaymentAmount: 19,
    });

    const req = makeReq();
    const res = makeRes();
    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ daysRemaining: 7 }));

    jest.useRealTimers();
  });

  test.each(['active', 'grace_period'])('isActive true for %s status', async (status) => {
    mockAuthenticatedTenant(makeTenant());
    db.tenant.findUnique.mockResolvedValue({
      plan: 'pro',
      subscriptionStatus: status,
      subscriptionEndDate: new Date(Date.now() + 86400000),
      billingCycle: 'monthly',
      lastPaymentDate: null,
      lastPaymentAmount: null,
    });

    const req = makeReq();
    const res = makeRes();
    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ isActive: true }));
  });

  test('DB throws → 500', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.tenant.findUnique.mockRejectedValue(new Error('db down'));

    const req = makeReq();
    const res = makeRes();
    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(500);
  });
});