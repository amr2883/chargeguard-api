'use strict';

// ════════════════════════════════════════════════════════════════════════════
// SCOPE: src/routes/dashboard.js — JSON endpoints only
//   - GET  /                          (dashboard data, JSON)
//   - GET  /monthly-report-preview
//   - POST /rotate-key
//   - GET  /bin-sequence-alerts
//   - Shared: auth (real requireAuth) + in-process rate limiter
//
// GET /page (HTML) and buildReportsArchiveSection's HTML output are covered
// in the sibling file tests/dashboard/dashboard-page-html.test.js.
//
// MOCKING STRATEGY — DEVIATIONS FROM THE T6 PATTERN, READ BEFORE EDITING:
//
//   1. dashboard.js does NOT import the shared src/lib/db.js singleton used
//      by payments.js. It instantiates its own client directly:
//        const { PrismaClient } = require('@prisma/client');
//        const prisma = new PrismaClient();
//      jest.mock('../../src/lib/db') would therefore mock NOTHING here.
//      Instead we mock '@prisma/client' itself, with PrismaClient a jest.fn()
//      that always returns the SAME mockPrisma object — so dashboard.js's
//      internal `new PrismaClient()` call and our own `new PrismaClient()`
//      call in this file resolve to the identical mock instance.
//
//   2. jest.resetAllMocks() (NOT jest.clearAllMocks()) is used in beforeEach.
//      getDashboardData() fires a single Promise.all of ~10 positional calls,
//      several of which hit the SAME model method twice per request
//      (blockedAttempt.count is called for both totalBlocked AND attacks24h;
//      blockedAttempt.findMany for both recentAttempts AND lastEight;
//      blockedAttempt.groupBy three times for reasonData/binAttackData/
//      topBinsForOrigin). We rely on chained .mockResolvedValueOnce() calls,
//      applied in the exact call order the source code issues them, to give
//      each positional call its own answer. clearAllMocks() resets call
//      history but NOT unconsumed mockResolvedValueOnce queues — meaning a
//      queued-but-unused Once value (e.g. binRecord.findMany's Once is never
//      consumed when topBinValues is empty, since the ternary short-circuits
//      to `[]` without ever calling prisma) would silently leak into the
//      NEXT test's first call to that method. resetAllMocks() wipes queued
//      implementations entirely every beforeEach, eliminating that leak.
//      Because of this, persistent baseline defaults (.mockResolvedValue)
//      are re-applied fresh in every beforeEach via applyPersistentDefaults()
//      rather than being set once at module scope.
//
//   3. Route handler extraction + manual dispatch follows the exact
//      getRouteHandlers/dispatch pattern established in
//      tests/subscription/payments-subscription.test.js. middleware/
//      authenticate.js is NOT mocked — only lib/apiKeyAuth's
//      resolveTenantByApiKey is, so the real requireAuth (isActive /
//      emailVerified / previous-key-deprecation branches) gets real coverage.
//
//   4. The dashboard rate limiter (DASHBOARD_RATE, an in-memory Map keyed by
//      req.ip, module-scoped and never reset between requests) is a shared,
//      mutable, cross-test hazard: unless given deliberately distinct IPs,
//      a later test in this file could silently start receiving 429s meant
//      for the rate-limiter test. Every req built by makeReq() gets a fresh,
//      unique `ip` (an incrementing counter, not a real IP format — the
//      limiter only uses it as a Map key) UNLESS a test is specifically
//      exercising the limiter itself, in which case that describe block
//      deliberately reuses one fixed IP across its own requests only.
//
//   5. planAccess.js's isProOrAbove() is NOT mocked — it's a two-line pure
//      function and using the real implementation gives true behavioral
//      coverage of the Starter/Pro gating boundary rather than a mocked
//      stand-in that could silently drift from the real gating logic.
//
//   6. src/lib/constants.js's SAVINGS_PER_ATTACK is NOT mocked — feesSaved
//      assertions use the real 0.30 constant so a future change to that
//      constant is caught here rather than masked by a stale mock value.
//
// QUIRKS DISCOVERED (documented inline at point of use too):
//   - GET / and GET /bin-sequence-alerts / GET /monthly-report-preview all
//     return HTTP 200 for non-Pro tenants with a `locked:true` teaser body,
//     never 403 — a deliberate choice (see source comments) so existing
//     polling/rendering code doesn't need new error branches. Tests assert
//     on the locked-teaser SHAPE, not on a 4xx status.
//   - POST /rotate-key reads tenant.apiKey / tenant.apiKeyHash from a FRESH
//     prisma.tenant.findUnique call inside the handler, not from req.tenant
//     (which only carries the fields requireAuth's `select` requested).
//     Tests must mock this second findUnique call distinctly from the first
//     (lastConnectVerifiedAt) recency-check call — same mock function, two
//     positional answers.
// ════════════════════════════════════════════════════════════════════════════

// ── Hoisted mocks — NOT scoped to isolateModules ─────────────────────────
// ROOT CAUSE OF THE PRIOR 54 FAILURES: src/routes/dashboard.js does NOT
// import src/lib/email at module top level. Inside POST /rotate-key it does
// a LAZY, per-request require:
//     const { sendRotatedKeyEmail } = require('../lib/email');
// jest.isolateModules() only sandboxes requires made SYNCHRONOUSLY inside
// its own callback. dashboard.js's module-scope `new PrismaClient()` runs
// while that sandbox is still alive (during the initial
// `require('../../src/routes/dashboard')` call), so the Prisma mock is
// captured correctly and forever, via closure. But the email require above
// only executes later — when a test calls dispatch() to invoke the route
// handler — long AFTER the isolateModules callback has returned and its
// private module registry has been discarded. At that point require('../lib/email')
// resolves against Jest's normal, file-scoped module registry, which never
// saw our jest.doMock('../../src/lib/email', ...) call — so it loads the
// REAL email.js (googleapis/nodemailer/OAuth2 client construction), which is
// what produced "Cannot read properties of undefined (reading 'catch')" and
// the 241s runtime / leaked-handle warning.
//
// FIX: use plain, hoisted jest.mock() calls instead of jest.doMock() +
// jest.isolateModules(). jest.mock() patches Jest's module registry for the
// ENTIRE test file's lifetime (not just one synchronous callback), so a
// lazy, later-executed require() — like the one inside the rotate-key
// handler — still resolves to our mock no matter when it runs. All requires
// below happen once, at module load, at the top level of this test file.
jest.mock('@prisma/client', () => {
  const mp = {
    blockedAttempt: {
      count: jest.fn(),
      findMany: jest.fn(),
      findFirst: jest.fn(),
      aggregate: jest.fn(),
      groupBy: jest.fn(),
    },
    tenant: {
      count: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    binRecord: { findMany: jest.fn() },
    alertLog: { findMany: jest.fn(), aggregate: jest.fn() },
    monthlyReport: { findFirst: jest.fn(), findMany: jest.fn() },
    binSequenceAlert: { findFirst: jest.fn(), findMany: jest.fn() },
  };
  return { PrismaClient: jest.fn(() => mp) };
});

jest.mock('../../src/lib/binSequenceDetector', () => ({
  getBINStats: jest.fn(),
  THRESHOLDS: { UNIQUE_BINS_PER_PREFIX: 8 },
}));
jest.mock('../../src/lib/apiKeyAuth', () => ({
  resolveTenantByApiKey: jest.fn(),
}));
jest.mock('../../src/lib/apiKeyHash', () => ({
  hashApiKey: jest.fn(),
}));
jest.mock('../../src/lib/email', () => ({
  sendRotatedKeyEmail: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../../src/lib/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

const { PrismaClient } = require('@prisma/client');
const mockPrisma = new PrismaClient();
const { getBINStats } = require('../../src/lib/binSequenceDetector');
const { resolveTenantByApiKey } = require('../../src/lib/apiKeyAuth');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { sendRotatedKeyEmail } = require('../../src/lib/email');
const dashboardRouter = require('../../src/routes/dashboard');

// Fail loudly and immediately, instead of tests failing later with cryptic
// "0 calls" / "Cannot read properties of undefined" errors, if mocking
// somehow didn't take (e.g. a root __mocks__/@prisma/client.js override, or
// a global resetMocks/restoreMocks config wiping the factory).
if (!jest.isMockFunction(PrismaClient)) {
  throw new Error(
    '[dashboard-data.test.js] PrismaClient is not mocked — ' +
    'check for a root __mocks__/@prisma/client.js, a setupFiles entry that ' +
    'requires app.js unmocked, or a global resetMocks/restoreMocks config.'
  );
}

// ── Route-stack extraction helpers (same pattern as payments-subscription.test.js) ──
function getRouteHandlers(method, path) {
  const layer = dashboardRouter.stack.find(
    (l) => l.route && l.route.path === path && l.route.methods[method.toLowerCase()]
  );
  if (!layer) throw new Error(`Route not found: ${method.toUpperCase()} ${path}`);
  return layer.route.stack.map((s) => s.handle);
}

// dispatch() must NOT rely on each middleware awaiting/returning next()'s
// promise — real Express middleware (see src/middleware/authenticate.js's
// requireAuth) intentionally calls `next();` fire-and-forget, exactly as
// Express itself expects. The prior version of dispatch() awaited only
// `handler(req, res, next)` — i.e. authenticate()'s OWN returned promise —
// which resolves the instant `next()` is invoked, not when the chain it
// triggers (the actual route handler's `await getDashboardData(...)`, etc.)
// finishes. That's what produced widespread "0 calls" / "Cannot read
// properties of undefined" failures: assertions ran before the real handler
// had gotten anywhere.
//
// Fix: capture the promise `next()` produces (the recursive dispatch call)
// in a closure variable regardless of whether the middleware awaits it, then
// chain onto that promise AFTER the middleware's own promise resolves. This
// correctly waits for the entire remaining handler chain to settle even
// when an earlier middleware discards next()'s return value.
function dispatch(handlers, req, res, i = 0) {
  if (i >= handlers.length) return Promise.resolve();
  const handler = handlers[i];
  let nextPromise;
  const next = (err) => {
    if (err) throw err;
    nextPromise = dispatch(handlers, req, res, i + 1);
    return nextPromise;
  };
  return Promise.resolve(handler(req, res, next)).then(() => nextPromise || Promise.resolve());
}

// ── Unique-IP counter (see mocking-strategy note #4 above) ──────────────────
let ipCounter = 0;
function nextIp() {
  ipCounter += 1;
  return `test-ip-${ipCounter}`;
}

// ── Factories ────────────────────────────────────────────────────────────────
function makeReq(overrides = {}) {
  return {
    headers: { 'x-api-key': 'test-api-key' },
    body: {},
    params: {},
    query: {},
    ip: nextIp(),
    ...overrides,
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
  res.send = jest.fn((body) => {
    res.body = body;
    return res;
  });
  res.set = jest.fn(() => res);
  res.setHeader = jest.fn(() => res);
  return res;
}

function makeTenant(overrides = {}) {
  return {
    id: 'tenant_1',
    email: 'merchant@example.com',
    plan: 'pro',
    isActive: true,
    emailVerified: true,
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    keyRotatedAt: null,
    ...overrides,
  };
}

function mockAuthenticatedTenant(tenant) {
  resolveTenantByApiKey.mockResolvedValue({ tenant, usedPreviousKey: false });
}

// ── getDashboardData scenario builder ───────────────────────────────────────
// Queues .mockResolvedValueOnce() answers in the EXACT positional order
// getDashboardData's Promise.all issues them (see header note #2). Only
// queues binRecord.findMany when topBinsForOrigin is non-empty, since the
// source code skips that call entirely otherwise (ternary short-circuit).
function setupDashboardScenario(overrides = {}) {
  const {
    totalBlocked = 0,
    recentAttempts = [],
    lastEight = [],
    lastActivity = null,
    amountSum = 0,
    reasonData = [],
    attacks24h = 0,
    binAttackData = [],
    topBinsForOrigin = [],
    totalTenants = 0,
    binRecords = [],
    paypalWeeklyLogs = [],
    paypalAllTimeAttackCount = 0,
    paypalAllTimeSavedAmount = 0,
    paypalReportCount = 0,
    lastPaypalAlertAt = null,
    binStats = { activePrefixes: 0, blockedPrefixes: 0, totalActiveBINs: 0 },
  } = overrides;

  mockPrisma.blockedAttempt.count
    .mockResolvedValueOnce(totalBlocked) // index0: totalBlocked
    .mockResolvedValueOnce(attacks24h); // index6: attacks24h

  mockPrisma.blockedAttempt.findMany
    .mockResolvedValueOnce(recentAttempts) // index1: recentAttempts (7-day)
    .mockResolvedValueOnce(lastEight); // index2: lastEight (take 8)

  mockPrisma.blockedAttempt.findFirst.mockResolvedValueOnce(lastActivity); // index3

  mockPrisma.blockedAttempt.aggregate.mockResolvedValueOnce({
    _sum: { amountAttempted: amountSum },
  }); // index4: amountData

  mockPrisma.blockedAttempt.groupBy
    .mockResolvedValueOnce(reasonData) // index5: reasonData
    .mockResolvedValueOnce(binAttackData) // index7: binAttackData (1hr window)
    .mockResolvedValueOnce(topBinsForOrigin); // index8: topBinsForOrigin (all-time top10)

  mockPrisma.tenant.count.mockResolvedValueOnce(totalTenants); // index9

  if (topBinsForOrigin.some((b) => b.cardBin)) {
    mockPrisma.binRecord.findMany.mockResolvedValueOnce(binRecords);
  }

  getBINStats.mockReturnValue(binStats);

  mockPrisma.alertLog.findMany.mockResolvedValueOnce(paypalWeeklyLogs);
  mockPrisma.alertLog.aggregate.mockResolvedValueOnce({
    _sum: { attackCount: paypalAllTimeAttackCount, savedAmount: paypalAllTimeSavedAmount },
    _count: { id: paypalReportCount },
  });
  mockPrisma.tenant.findUnique.mockResolvedValueOnce({ lastPaypalAlertAt });
}

function applyPersistentDefaults() {
  mockPrisma.blockedAttempt.count.mockResolvedValue(0);
  mockPrisma.blockedAttempt.findMany.mockResolvedValue([]);
  mockPrisma.blockedAttempt.findFirst.mockResolvedValue(null);
  mockPrisma.blockedAttempt.aggregate.mockResolvedValue({ _sum: { amountAttempted: 0 } });
  mockPrisma.blockedAttempt.groupBy.mockResolvedValue([]);
  mockPrisma.tenant.count.mockResolvedValue(0);
  mockPrisma.tenant.findUnique.mockResolvedValue({
    lastPaypalAlertAt: null,
    lastConnectVerifiedAt: new Date(Date.now() - 5 * 60 * 1000),
    apiKeyHash: 'old_hash_default',
    apiKey: null,
  });
  mockPrisma.tenant.update.mockResolvedValue({});
  mockPrisma.binRecord.findMany.mockResolvedValue([]);
  mockPrisma.alertLog.findMany.mockResolvedValue([]);
  mockPrisma.alertLog.aggregate.mockResolvedValue({
    _sum: { attackCount: 0, savedAmount: 0 },
    _count: { id: 0 },
  });
  mockPrisma.monthlyReport.findFirst.mockResolvedValue(null);
  mockPrisma.monthlyReport.findMany.mockResolvedValue([]);
  mockPrisma.binSequenceAlert.findFirst.mockResolvedValue(null);
  mockPrisma.binSequenceAlert.findMany.mockResolvedValue([]);

  getBINStats.mockReturnValue({ activePrefixes: 0, blockedPrefixes: 0, totalActiveBINs: 0 });
  hashApiKey.mockImplementation((key) => `hashed_${key}`);
  resolveTenantByApiKey.mockResolvedValue({ tenant: makeTenant(), usedPreviousKey: false });
  sendRotatedKeyEmail.mockResolvedValue(undefined);
}

beforeAll(() => {
  process.env.API_KEY_HASH_SECRET = 'test-secret';
  process.env.EMAIL_VERIFICATION_DISABLED = 'false';
});

beforeEach(() => {
  jest.resetAllMocks();
  applyPersistentDefaults();
});

afterEach(() => {
  jest.useRealTimers();
  delete process.env.KEY_ROTATION_GRACE_HOURS;
});

// ══════════════════════════════════════════════════════════════════════════════
describe('Auth (real requireAuth) — shared across all dashboard routes', () => {
  const handlers = () => getRouteHandlers('get', '/');

  test('missing X-Api-Key header → 401, no DB calls', async () => {
    const req = makeReq({ headers: {} });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'API key is required' });
    expect(mockPrisma.blockedAttempt.count).not.toHaveBeenCalled();
  });

  test('resolveTenantByApiKey finds no tenant → 401 invalid/inactive', async () => {
    resolveTenantByApiKey.mockResolvedValue({ tenant: null, usedPreviousKey: false });
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);
    // authenticate.js's invalid/inactive-tenant branch responds via
    // delayedJson() — a raw 200ms setTimeout, not a Promise, and no next()
    // call for dispatch() to chain onto. Real timers are in effect in this
    // describe block, so we wait out the real delay before asserting.
    await new Promise((resolve) => setTimeout(resolve, 250));

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid or inactive API key' });
  });

  test('inactive tenant → 401', async () => {
    mockAuthenticatedTenant(makeTenant({ isActive: false }));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);
    // Same delayedJson() real-timer path as above.
    await new Promise((resolve) => setTimeout(resolve, 250));

    expect(res.status).toHaveBeenCalledWith(401);
  });

  test('unverified tenant → 403 EMAIL_NOT_VERIFIED, no dashboard data built', async () => {
    mockAuthenticatedTenant(makeTenant({ emailVerified: false }));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'EMAIL_NOT_VERIFIED' }));
    expect(mockPrisma.blockedAttempt.count).not.toHaveBeenCalled();
  });

  test('auth error (DB throws inside resolveTenantByApiKey) → 500', async () => {
    resolveTenantByApiKey.mockRejectedValue(new Error('db down'));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(500);
  });

  test('previous (grace-period) key used → X-ChargeGuard-Key-Deprecated header set, request still succeeds', async () => {
    setupDashboardScenario({});
    resolveTenantByApiKey.mockResolvedValue({ tenant: makeTenant(), usedPreviousKey: true });
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.set).toHaveBeenCalledWith('X-ChargeGuard-Key-Deprecated', 'true');
    expect(res.json).toHaveBeenCalled();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('Rate limiter (DASHBOARD_RATE) — deliberately reuses ONE fixed IP', () => {
  // This is the ONLY describe block in the file that reuses a single req.ip
  // across multiple requests, and it does so on purpose: MAX_REQ (30) is
  // only reachable by hammering the exact same IP key repeatedly. Every
  // other test in this file uses makeReq()'s auto-incrementing IP specifically
  // to stay OUT of this limiter's way (see header note #4).
  const FIXED_IP = 'rate-limit-fixed-ip';
  const handlers = () => getRouteHandlers('get', '/');

  test('first 30 requests on one IP succeed, the 31st gets 429', async () => {
    mockAuthenticatedTenant(makeTenant());

    for (let i = 1; i <= 30; i++) {
      setupDashboardScenario({});
      const req = makeReq({ ip: FIXED_IP });
      const res = makeRes();
      await dispatch(handlers(), req, res);
      expect(res.status).not.toHaveBeenCalledWith(429);
    }

    const req31 = makeReq({ ip: FIXED_IP });
    const res31 = makeRes();
    await dispatch(handlers(), req31, res31);

    expect(res31.status).toHaveBeenCalledWith(429);
    expect(res31.json).toHaveBeenCalledWith({ error: 'Too Many Requests' });
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('GET / — dashboard data engine', () => {
  const handlers = () => getRouteHandlers('get', '/');

  describe('security score (calculateSecurityScore)', () => {
    test('baseline: zero attacks, zero week, no reasons, brand-new tenant → 100', async () => {
      mockAuthenticatedTenant(makeTenant({ createdAt: new Date() }));
      setupDashboardScenario({ attacks24h: 0, recentAttempts: [], reasonData: [] });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ securityScore: 100 }));
    });

    test('heavy attack volume clamps the floor at 52, never lower', async () => {
      mockAuthenticatedTenant(makeTenant({ createdAt: new Date() }));
      // intensity maxes at 30 (attacks24h >= 37.5), weekPressure maxes at 15
      // (weekTotal >= 100), diversity maxes at 8 (>=3 reasons), longevity 0
      // (brand new tenant) → raw = 100-30-15-8+0 = 47 → clamped to 52.
      const recentAttempts = Array.from({ length: 100 }, () => ({ blockedAt: new Date() }));
      setupDashboardScenario({
        attacks24h: 50,
        recentAttempts,
        reasonData: [
          { reason: 'card_testing', _count: { reason: 10 } },
          { reason: 'velocity', _count: { reason: 10 } },
          { reason: 'blacklist', _count: { reason: 10 } },
        ],
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ securityScore: 52 }));
    });

    test('diversity bonus scales with distinct reason count (0 → 2 → 3 reasons)', async () => {
      mockAuthenticatedTenant(makeTenant({ createdAt: new Date() }));

      // 0 reasons, attacks24h=5 (intensity=4) → raw = 100-4-0-0+0 = 96
      setupDashboardScenario({ attacks24h: 5, reasonData: [] });
      let req = makeReq();
      let res = makeRes();
      await dispatch(handlers(), req, res);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ securityScore: 96 }));

      // 2 reasons, attacks24h=5 (intensity=4, diversity=4) → raw = 92
      setupDashboardScenario({
        attacks24h: 5,
        reasonData: [
          { reason: 'card_testing', _count: { reason: 3 } },
          { reason: 'velocity', _count: { reason: 2 } },
        ],
      });
      req = makeReq();
      res = makeRes();
      await dispatch(handlers(), req, res);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ securityScore: 92 }));

      // 3 reasons, attacks24h=5 (intensity=4, diversity=8) → raw = 88
      setupDashboardScenario({
        attacks24h: 5,
        reasonData: [
          { reason: 'card_testing', _count: { reason: 3 } },
          { reason: 'velocity', _count: { reason: 2 } },
          { reason: 'blacklist', _count: { reason: 1 } },
        ],
      });
      req = makeReq();
      res = makeRes();
      await dispatch(handlers(), req, res);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ securityScore: 88 }));
    });

    test('longevity bonus offsets the intensity penalty for older tenants', async () => {
      jest.useFakeTimers();
      jest.setSystemTime(new Date('2026-07-07T12:00:00.000Z'));

      // attacks24h=10 (intensity=8) in both cases; only daysSinceJoined differs.
      mockAuthenticatedTenant(makeTenant({ createdAt: new Date('2026-07-07T12:00:00.000Z') })); // daysSinceJoined=0
      setupDashboardScenario({ attacks24h: 10, reasonData: [] });
      let req = makeReq();
      let res = makeRes();
      await dispatch(handlers(), req, res);
      // raw = 100 - 8 - 0 - 0 + 0 = 92
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ securityScore: 92 }));

      // 250 days old → longevity = min(250*0.04, 8) = 8 (capped)
      const longAgo = new Date('2026-07-07T12:00:00.000Z' - 250 * 86400000);
      mockAuthenticatedTenant(makeTenant({ createdAt: new Date(Date.parse('2026-07-07T12:00:00.000Z') - 250 * 86400000) }));
      setupDashboardScenario({ attacks24h: 10, reasonData: [] });
      req = makeReq();
      res = makeRes();
      await dispatch(handlers(), req, res);
      // raw = 100 - 8 - 0 - 0 + 8 = 100
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ securityScore: 100 }));
    });
  });

  describe('connection status (getConnectionStatus)', () => {
    beforeEach(() => {
      jest.useFakeTimers();
      jest.setSystemTime(new Date('2026-07-07T12:00:00.000Z'));
    });

    test('no prior blocked attempts → gray, "No activity recorded yet"', async () => {
      mockAuthenticatedTenant(makeTenant());
      setupDashboardScenario({ lastActivity: null });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        connectionStatus: { label: 'No activity recorded yet', color: 'gray', minutes: null },
      }));
    });

    test('< 10 minutes ago → green', async () => {
      mockAuthenticatedTenant(makeTenant());
      setupDashboardScenario({
        lastActivity: { blockedAt: new Date('2026-07-07T11:55:00.000Z') }, // 5 min ago
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        connectionStatus: expect.objectContaining({ color: 'green', minutes: 5, label: '5m ago' }),
      }));
    });

    test('10–59 minutes ago → yellow', async () => {
      mockAuthenticatedTenant(makeTenant());
      setupDashboardScenario({
        lastActivity: { blockedAt: new Date('2026-07-07T11:30:00.000Z') }, // 30 min ago
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        connectionStatus: expect.objectContaining({ color: 'yellow', minutes: 30 }),
      }));
    });

    test('1–24 hours ago → gray, label in hours', async () => {
      mockAuthenticatedTenant(makeTenant());
      setupDashboardScenario({
        lastActivity: { blockedAt: new Date('2026-07-07T03:40:00.000Z') }, // 500 min ago (~8h20m)
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        connectionStatus: expect.objectContaining({ color: 'gray', minutes: 500, label: '8h ago' }),
      }));
    });

    test('> 24 hours ago → red, label in days', async () => {
      mockAuthenticatedTenant(makeTenant());
      setupDashboardScenario({
        lastActivity: { blockedAt: new Date('2026-07-05T12:00:00.000Z') }, // 2880 min ago (2 days)
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        connectionStatus: expect.objectContaining({ color: 'red', minutes: 2880, label: '2d ago' }),
      }));
    });
  });

  describe('7-day chart bucketing (dayMap) and weekTotal', () => {
    test('buckets attempts into correct UTC day keys and sums weekTotal', async () => {
      jest.useFakeTimers();
      jest.setSystemTime(new Date('2026-07-07T12:00:00.000Z'));
      mockAuthenticatedTenant(makeTenant());

      const recentAttempts = [
        { blockedAt: new Date('2026-07-07T01:00:00.000Z') }, // today
        { blockedAt: new Date('2026-07-07T02:00:00.000Z') }, // today
        { blockedAt: new Date('2026-07-04T10:00:00.000Z') }, // 3 days ago
      ];
      setupDashboardScenario({ recentAttempts });

      const req = makeReq();
      const res = makeRes();
      await dispatch(handlers(), req, res);

      const call = res.json.mock.calls[0][0];
      const todayEntry = call.chartData.find((d) => d.date === '2026-07-07');
      const threeDaysAgoEntry = call.chartData.find((d) => d.date === '2026-07-04');

      expect(todayEntry.count).toBe(2);
      expect(threeDaysAgoEntry.count).toBe(1);
      expect(call.chartData).toHaveLength(7);

      const weekTotal = call.chartData.reduce((s, d) => s + d.count, 0);
      expect(weekTotal).toBe(3);
    });
  });

  describe('BIN activity summary (binActivity)', () => {
    test('active attack detected when a BIN has 3+ hits in the 1hr window', async () => {
      mockAuthenticatedTenant(makeTenant()); // pro plan — no gating applied
      setupDashboardScenario({
        binAttackData: [
          { cardBin: '411111', _count: { cardBin: 5 } },
          { cardBin: '400000', _count: { cardBin: 1 } },
        ],
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        binActivity: expect.objectContaining({
          hasActiveAttack: true,
          topBin: '411111',
          topBinCount: 5,
          totalBinPatterns: 1, // only the 5-count bin qualifies (>=2); the 1-count bin doesn't
        }),
      }));
    });

    test('no active attack when no BIN reaches the 3-hit threshold', async () => {
      mockAuthenticatedTenant(makeTenant());
      setupDashboardScenario({
        binAttackData: [{ cardBin: '411111', _count: { cardBin: 2 } }],
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        binActivity: expect.objectContaining({ hasActiveAttack: false, topBin: null, topBinCount: 0 }),
      }));
    });
  });

  describe('threat origins (BIN → country lookup)', () => {
    test('aggregates counts by country, drops BINs with no country match, merges same-country entries', async () => {
      mockAuthenticatedTenant(makeTenant());
      setupDashboardScenario({
        topBinsForOrigin: [
          { cardBin: '411111', _count: { cardBin: 10 } },
          { cardBin: '400000', _count: { cardBin: 5 } },
          { cardBin: '999999', _count: { cardBin: 20 } }, // no BinRecord — should be dropped
        ],
        binRecords: [
          { bin: '411111', issuerCountry: 'US', brand: 'Visa' },
          { bin: '400000', issuerCountry: 'US', brand: 'Visa' }, // same country — should merge
        ],
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const call = res.json.mock.calls[0][0];
      expect(call.threatOrigins).toEqual([{ country: 'US', count: 15, brand: 'Visa' }]);
    });

    test('binRecord.findMany is never called when there are no top BINs', async () => {
      mockAuthenticatedTenant(makeTenant());
      setupDashboardScenario({ topBinsForOrigin: [] });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(mockPrisma.binRecord.findMany).not.toHaveBeenCalled();
    });
  });

  describe('PayPal Shield stats', () => {
    test('isActive is false and all counters zero when no PayPal AlertLogs exist', async () => {
      mockAuthenticatedTenant(makeTenant());
      setupDashboardScenario({ paypalReportCount: 0 });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        paypalStats: expect.objectContaining({
          isActive: false, weekSuspicious: 0, weekSaved: 0,
          allTimeSuspicious: 0, allTimeSaved: 0, reportCount: 0,
        }),
      }));
    });

    test('weekly sums come from the 7-day AlertLog rows; all-time sums come from the aggregate', async () => {
      mockAuthenticatedTenant(makeTenant());
      setupDashboardScenario({
        paypalWeeklyLogs: [
          { attackCount: 3, savedAmount: 10.5 },
          { attackCount: 2, savedAmount: 5.5 },
        ],
        paypalAllTimeAttackCount: 50,
        paypalAllTimeSavedAmount: 200,
        paypalReportCount: 8,
        lastPaypalAlertAt: new Date('2026-07-01T00:00:00.000Z'),
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        paypalStats: {
          isActive: true,
          weekSuspicious: 5,
          weekSaved: 16,
          allTimeSuspicious: 50,
          allTimeSaved: 200,
          reportCount: 8,
          lastAlertAt: new Date('2026-07-01T00:00:00.000Z'),
        },
      }));
    });
  });

  describe('feesSaved / amountProtected formatting', () => {
    test('feesSaved = totalBlocked * SAVINGS_PER_ATTACK (real constant 0.30), fixed to 2 decimals', async () => {
      mockAuthenticatedTenant(makeTenant());
      setupDashboardScenario({ totalBlocked: 10, amountSum: 123.456 });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        feesSaved: '3.00', // 10 * 0.30
        amountProtected: '123.46', // toFixed(2) rounding
      }));
    });

    test('amountProtected defaults to "0.00" when the aggregate sum is null', async () => {
      mockAuthenticatedTenant(makeTenant());
      setupDashboardScenario({ amountSum: null });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ amountProtected: '0.00' }));
    });
  });

  describe('Plan gating (OWASP API1:2023 fix — enforced on raw JSON, not just HTML)', () => {
    test('Starter tenant: binActivity, binSequenceStats, threatOrigins are all replaced with a locked teaser', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'starter' }));
      setupDashboardScenario({
        binAttackData: [{ cardBin: '411111', _count: { cardBin: 5 } }],
        topBinsForOrigin: [{ cardBin: '411111', _count: { cardBin: 5 } }],
        binRecords: [{ bin: '411111', issuerCountry: 'US', brand: 'Visa' }],
        binStats: { activePrefixes: 2, blockedPrefixes: 1, totalActiveBINs: 4 },
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const locked = { locked: true, upgradeRequired: true, message: 'Upgrade to Pro to unlock this feature.' };
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        binActivity: locked,
        binSequenceStats: locked,
        threatOrigins: locked,
      }));
    });

    test.each(['pro', 'agency'])('%s tenant: real BIN/threat-origin data passes through unmodified', async (plan) => {
      mockAuthenticatedTenant(makeTenant({ plan }));
      setupDashboardScenario({
        binAttackData: [{ cardBin: '411111', _count: { cardBin: 5 } }],
        topBinsForOrigin: [{ cardBin: '411111', _count: { cardBin: 5 } }],
        binRecords: [{ bin: '411111', issuerCountry: 'US', brand: 'Visa' }],
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const call = res.json.mock.calls[0][0];
      expect(call.binActivity.hasActiveAttack).toBe(true);
      expect(call.threatOrigins).toEqual([{ country: 'US', count: 5, brand: 'Visa' }]);
    });

    test.each(['starter', 'early_access'])('%s plan is treated as free-tier (not Pro)', async (plan) => {
      mockAuthenticatedTenant(makeTenant({ plan }));
      setupDashboardScenario({});
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const call = res.json.mock.calls[0][0];
      expect(call.binActivity.locked).toBe(true);
    });
  });

  describe('error handling', () => {
    test('DB failure inside getDashboardData → 500', async () => {
      mockAuthenticatedTenant(makeTenant());
      mockPrisma.blockedAttempt.count.mockRejectedValueOnce(new Error('db down'));
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
    });
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('GET /monthly-report-preview', () => {
  const handlers = () => getRouteHandlers('get', '/monthly-report-preview');

  test('missing X-Api-Key header → 401 (auth applies identically on this route)', async () => {
    const req = makeReq({ headers: {} });
    const res = makeRes();
    await dispatch(handlers(), req, res);
    expect(res.status).toHaveBeenCalledWith(401);
  });

  test.each(['starter', 'early_access'])('%s plan → 200 locked teaser, monthlyReport never queried', async (plan) => {
    mockAuthenticatedTenant(makeTenant({ plan }));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith({
      available: false,
      locked: true,
      upgradeRequired: true,
      message: 'Monthly reports are a Pro feature. Upgrade to unlock.',
    });
    expect(mockPrisma.monthlyReport.findFirst).not.toHaveBeenCalled();
  });

  test.each(['pro', 'agency'])('%s plan, no query params → fetches most recent ready report', async (plan) => {
    mockAuthenticatedTenant(makeTenant({ plan }));
    mockPrisma.monthlyReport.findFirst.mockResolvedValueOnce({
      reportMonth: 6, reportYear: 2026,
      totalAttacks: 120, totalProtected: 500, totalFeesSaved: 36,
      securityScore: 88, topCountry: 'US', topReason: 'card_testing',
      prevMonthAttacks: 100,
    });
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(mockPrisma.monthlyReport.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({ where: { tenantId: 'tenant_1', status: 'ready' } })
    );
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      available: true,
      reportMonth: 6,
      reportYear: 2026,
      monthOverMonthPct: 20, // (120-100)/100 = 20%
      downloadUrl: '/api/dashboard/monthly-report-preview?month=6&year=2026',
    }));
  });

  test('valid ?month=&year= query scopes the findFirst to that specific report', async () => {
    mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
    mockPrisma.monthlyReport.findFirst.mockResolvedValueOnce({
      reportMonth: 3, reportYear: 2026,
      totalAttacks: 10, totalProtected: 50, totalFeesSaved: 3,
      securityScore: 95, topCountry: null, topReason: null,
      prevMonthAttacks: null,
    });
    const req = makeReq({ query: { month: '3', year: '2026' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(mockPrisma.monthlyReport.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { tenantId: 'tenant_1', status: 'ready', reportMonth: 3, reportYear: 2026 },
      })
    );
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ monthOverMonthPct: null }));
  });

  test('invalid (non-integer) month query falls back to the "latest" lookup instead of erroring', async () => {
    mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
    mockPrisma.monthlyReport.findFirst.mockResolvedValueOnce(null);
    const req = makeReq({ query: { month: 'not-a-number', year: '2026' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(mockPrisma.monthlyReport.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({ where: { tenantId: 'tenant_1', status: 'ready' } })
    );
  });

  test('no report exists for a valid query → available:false with the "no report for that month" message', async () => {
    mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
    mockPrisma.monthlyReport.findFirst.mockResolvedValueOnce(null);
    const req = makeReq({ query: { month: '2', year: '2026' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith({
      available: false,
      message: 'No report found for that month.',
    });
  });

  test('no report exists with no query params → "first report generates" message', async () => {
    mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
    mockPrisma.monthlyReport.findFirst.mockResolvedValueOnce(null);
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith({
      available: false,
      message: 'First report generates on the 1st of next month.',
    });
  });

  test('DB throws → 500', async () => {
    mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
    mockPrisma.monthlyReport.findFirst.mockRejectedValueOnce(new Error('db down'));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(500);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('POST /rotate-key', () => {
  const handlers = () => getRouteHandlers('post', '/rotate-key');

  test('missing X-Api-Key header → 401 (auth applies identically on this route)', async () => {
    const req = makeReq({ headers: {} });
    const res = makeRes();
    await dispatch(handlers(), req, res);
    expect(res.status).toHaveBeenCalledWith(401);
  });

  test('no lastConnectVerifiedAt on record → 403 RECENT_VERIFICATION_REQUIRED', async () => {
    mockAuthenticatedTenant(makeTenant());
    mockPrisma.tenant.findUnique.mockResolvedValueOnce({ lastConnectVerifiedAt: null });
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'RECENT_VERIFICATION_REQUIRED' }));
    expect(mockPrisma.tenant.update).not.toHaveBeenCalled();
  });

  test('lastConnectVerifiedAt older than 15 minutes → 403 RECENT_VERIFICATION_REQUIRED', async () => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-07-07T12:00:00.000Z'));
    mockAuthenticatedTenant(makeTenant());
    mockPrisma.tenant.findUnique.mockResolvedValueOnce({
      lastConnectVerifiedAt: new Date('2026-07-07T11:40:00.000Z'), // 20 min ago
    });
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'RECENT_VERIFICATION_REQUIRED' }));
  });

  test('verified within the last 15 minutes but rotated less than 5 minutes ago → 429 cooldown', async () => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-07-07T12:00:00.000Z'));
    mockAuthenticatedTenant(makeTenant({
      keyRotatedAt: new Date('2026-07-07T11:58:00.000Z'), // 2 min ago
    }));
    mockPrisma.tenant.findUnique.mockResolvedValueOnce({
      lastConnectVerifiedAt: new Date('2026-07-07T11:55:00.000Z'), // 5 min ago — within window
    });
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(429);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ retryAfter: expect.any(Number) }));
    expect(mockPrisma.tenant.update).not.toHaveBeenCalled();
  });

  test('happy path: rotates key, hashes it, carries forward grace-period previous key (default 24h)', async () => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-07-07T12:00:00.000Z'));

    mockAuthenticatedTenant(makeTenant({ keyRotatedAt: null }));
    mockPrisma.tenant.findUnique
      .mockResolvedValueOnce({ lastConnectVerifiedAt: new Date('2026-07-07T11:50:00.000Z') }) // recency check
      .mockResolvedValueOnce({ apiKeyHash: 'current_hash_abc', apiKey: null }); // current key snapshot

    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(mockPrisma.tenant.update).toHaveBeenCalledWith({
      where: { id: 'tenant_1' },
      data: expect.objectContaining({
        previousApiKey: null,
        previousApiKeyHash: 'current_hash_abc',
        previousApiKeyExpiresAt: new Date('2026-07-08T12:00:00.000Z'), // +24h default
        apiKey: null,
        apiKeyHash: expect.stringMatching(/^hashed_/),
        keyRotatedAt: new Date('2026-07-07T12:00:00.000Z'),
      }),
    });

    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      success: true,
      newApiKey: expect.any(String),
      graceExpiresAt: new Date('2026-07-08T12:00:00.000Z').toISOString(),
    }));
    expect(sendRotatedKeyEmail).toHaveBeenCalledWith('merchant@example.com', expect.any(String));
  });

  test('respects a custom KEY_ROTATION_GRACE_HOURS override', async () => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-07-07T12:00:00.000Z'));
    process.env.KEY_ROTATION_GRACE_HOURS = '2';

    mockAuthenticatedTenant(makeTenant({ keyRotatedAt: null }));
    mockPrisma.tenant.findUnique
      .mockResolvedValueOnce({ lastConnectVerifiedAt: new Date('2026-07-07T11:50:00.000Z') })
      .mockResolvedValueOnce({ apiKeyHash: 'h', apiKey: null });

    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(mockPrisma.tenant.update).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        previousApiKeyExpiresAt: new Date('2026-07-07T14:00:00.000Z'), // +2h
      }),
    }));
  });

  test('email failure is caught and does not fail the request (fire-and-forget)', async () => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-07-07T12:00:00.000Z'));
    mockAuthenticatedTenant(makeTenant({ keyRotatedAt: null }));
    mockPrisma.tenant.findUnique
      .mockResolvedValueOnce({ lastConnectVerifiedAt: new Date('2026-07-07T11:50:00.000Z') })
      .mockResolvedValueOnce({ apiKeyHash: 'h', apiKey: null });
    sendRotatedKeyEmail.mockRejectedValueOnce(new Error('smtp down'));

    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ success: true }));
  });

  test('DB throws during rotation → 500', async () => {
    mockAuthenticatedTenant(makeTenant());
    mockPrisma.tenant.findUnique.mockRejectedValueOnce(new Error('db down'));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(500);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('GET /bin-sequence-alerts', () => {
  const handlers = () => getRouteHandlers('get', '/bin-sequence-alerts');

  test('missing X-Api-Key header → 401 (auth applies identically on this route)', async () => {
    const req = makeReq({ headers: {} });
    const res = makeRes();
    await dispatch(handlers(), req, res);
    expect(res.status).toHaveBeenCalledWith(401);
  });

  test.each(['starter', 'early_access'])('%s plan → 200 locked teaser with real THRESHOLDS value, no BIN queries run', async (plan) => {
    mockAuthenticatedTenant(makeTenant({ plan }));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      success: true,
      locked: true,
      activeAlert: null,
      liveStats: expect.objectContaining({
        activePrefixes: 0, blockedPrefixes: 0, totalActiveBINs: 0,
        thresholdForAlert: 8,
        progressPercent: 0, progressColor: 'blue',
      }),
      recentAlerts: [],
    }));
    expect(mockPrisma.binSequenceAlert.findFirst).not.toHaveBeenCalled();
  });

  test('Pro tenant with an active alert → activeForSeconds computed, layerName mapped, isBlocked true', async () => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-07-07T12:05:00.000Z'));
    mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));

    mockPrisma.binSequenceAlert.findFirst.mockResolvedValueOnce({
      id: 'alert_1', binPrefix: '4111', layer: 1, cardsCount: 12, entitiesCount: 3,
      riskAddition: 40, status: 'active',
      detectedAt: new Date('2026-07-07T12:00:00.000Z'), // 5 min ago = 300s
      resolvedAt: null,
    });
    mockPrisma.binSequenceAlert.findMany.mockResolvedValueOnce([]);
    getBINStats.mockReturnValue({ activePrefixes: 1, blockedPrefixes: 1, totalActiveBINs: 8 });

    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      success: true,
      activeAlert: expect.objectContaining({
        binPrefix: '4111',
        layerName: 'Rapid BIN Velocity Attack',
        activeForSeconds: 300,
        isBlocked: true,
      }),
      metadata: expect.objectContaining({ nextRefreshSeconds: 15 }),
    }));
  });

  test('Pro tenant, unknown layer number → layerName falls back to "Unknown Attack"', async () => {
    mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
    mockPrisma.binSequenceAlert.findFirst.mockResolvedValueOnce({
      id: 'alert_2', binPrefix: '5500', layer: 99, cardsCount: 4, entitiesCount: 2,
      riskAddition: 10, status: 'active', detectedAt: new Date(), resolvedAt: null,
    });
    mockPrisma.binSequenceAlert.findMany.mockResolvedValueOnce([]);

    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      activeAlert: expect.objectContaining({ layerName: 'Unknown Attack' }),
    }));
  });

  test.each([
    [3, 'blue'],
    [5, 'yellow'],
    [7, 'red'],
  ])('Pro tenant, no active alert, totalActiveBINs=%i of threshold 8 → progressColor %s', async (totalActiveBINs, expectedColor) => {
    mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
    mockPrisma.binSequenceAlert.findFirst.mockResolvedValueOnce(null);
    mockPrisma.binSequenceAlert.findMany.mockResolvedValueOnce([]);
    getBINStats.mockReturnValue({ activePrefixes: 1, blockedPrefixes: 0, totalActiveBINs });

    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    const call = res.json.mock.calls[0][0];
    expect(call.liveStats.progressColor).toBe(expectedColor);
    expect(call.metadata.nextRefreshSeconds).toBe(30);
  });

  test('DB throws → 500', async () => {
    mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
    mockPrisma.binSequenceAlert.findFirst.mockRejectedValueOnce(new Error('db down'));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(500);
  });
});