'use strict';

// ════════════════════════════════════════════════════════════════════════════
// SCOPE: src/routes/dashboard.js — HTML rendering path only
//   - GET /page                        (full HTML dashboard page)
//   - buildDashboardHtml (unexported, only reachable via GET /page)
//   - buildReportsArchiveSection (unexported, only reachable via
//     buildDashboardHtml, at the very end of the page body)
//
// All JSON endpoints (GET /, GET /monthly-report-preview, POST /rotate-key,
// GET /bin-sequence-alerts) are covered in the sibling file
// tests/dashboard/dashboard-data.test.js — this file does NOT re-test them.
//
// MOCKING STRATEGY — IDENTICAL TO FILE 1, READ BEFORE EDITING:
//
//   1. dashboard.js instantiates its own `new PrismaClient()` rather than
//      using the shared src/lib/db.js singleton, so we mock '@prisma/client'
//      itself (PrismaClient as a jest.fn() returning one shared mock
//      instance) exactly as File 1 does.
//
//   2. jest.resetAllMocks() (NOT jest.clearAllMocks()) is used in beforeEach,
//      for the same reason documented at length in File 1: getDashboardData
//      issues several positional .mockResolvedValueOnce() calls per request,
//      and clearAllMocks() would leak unconsumed queued values across tests.
//      Persistent baseline defaults are re-applied fresh every beforeEach via
//      applyPersistentDefaults() (copied verbatim from File 1).
//
//   3. setupDashboardScenario() is copied verbatim from File 1 — GET /page
//      calls the exact same getDashboardData() function GET / does, so it
//      issues the identical positional Promise.all sequence.
//
//   4. Route handler extraction + manual dispatch uses the same
//      getRouteHandlers/dispatch pattern as File 1 and
//      tests/subscription/payments-subscription.test.js. requireAuth runs
//      for real; only resolveTenantByApiKey is mocked.
//
//   5. The DASHBOARD_RATE limiter is shared, in-memory, and keyed by req.ip
//      — every makeReq() gets a fresh unique IP (see nextIp()) so no test in
//      this file can accidentally trip another test's rate limit.
//
//   6. isProOrAbove() (planAccess.js) is NOT mocked — real two-line pure
//      function, same as File 1, for true behavioral coverage of the
//      Starter/Pro gating boundary rendered into the HTML.
//
// DEVIATIONS FROM FILE 1 / IMPORTANT BEHAVIORAL NOTES:
//
//   - QUIRK: Unlike GET / (JSON), the GET /page handler does NOT apply the
//     OWASP API1:2023 pro-lock data-swap (the `proLocked` object assignment
//     to data.binActivity/binSequenceStats/threatOrigins) before calling
//     buildDashboardHtml(). getDashboardData() returns REAL, unlocked stats
//     to the HTML builder regardless of plan — buildDashboardHtml and
//     buildReportsArchiveSection each independently call isProOrAbove()
//     themselves and gate the *rendered markup* at render time. This means
//     setupDashboardScenario() overrides for binAttackData/topBinsForOrigin/
//     binStats etc. always reflect real data in `data`, and the tests below
//     assert on the HTML *markers* (locked vs. unlocked), not on locked
//     placeholder objects the way File 1's JSON gating tests do.
//
//   - QUIRK: res.setHeader('X-Robots-Tag', 'noindex') sets ONLY 'noindex' —
//     NOT 'noindex, nofollow'. The stricter 'noindex,nofollow' directive
//     only appears inside the in-HTML <meta name="robots"> tag, never on
//     the actual response header. Tests assert the header's real value.
//
//   - QUIRK: the /page catch block responds with res.status(500).send(
//     'Internal Server Error') — plain text, NOT the JSON { error: ... }
//     shape GET / uses on the same underlying getDashboardData() failure.
//
//   - QUIRK: buildReportsArchiveSection() issues its OWN separate
//     prisma.monthlyReport.findMany() call, fired only after the full
//     getDashboardData() Promise.all chain resolves (it's awaited inline
//     near the bottom of the page body). This is NOT part of
//     setupDashboardScenario()'s positional queue — applyPersistentDefaults()
//     gives it a persistent `mockResolvedValue([])` default (matching
//     File 1's default), and tests that care about the reports archive
//     override it per-test with .mockResolvedValueOnce(reports).
//
//   - ASSERTION STRATEGY: per the approved plan, we assert on stable HTML
//     markers via expect(res.send).toHaveBeenCalledWith(expect.stringContaining(...))
//     and, where finer-grained counting is needed (e.g. "exactly one
//     unlocked row"), we pull the raw string via res.send.mock.calls[0][0]
//     and run a simple regex match count against it — never a full-document
//     snapshot.
// ════════════════════════════════════════════════════════════════════════════

// ── Hardened isolation — identical rationale/pattern as File 1 ─────────────
let PrismaClient;
let mockPrisma;
let getBINStats;
let resolveTenantByApiKey;
let hashApiKey;
let sendRotatedKeyEmail;
let dashboardRouter;

beforeAll(() => {
  jest.isolateModules(() => {
    jest.doMock('@prisma/client', () => {
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

    jest.doMock('../../src/lib/binSequenceDetector', () => ({
      getBINStats: jest.fn(),
      THRESHOLDS: { UNIQUE_BINS_PER_PREFIX: 8 },
    }));
    jest.doMock('../../src/lib/apiKeyAuth', () => ({
      resolveTenantByApiKey: jest.fn(),
    }));
    jest.doMock('../../src/lib/apiKeyHash', () => ({
      hashApiKey: jest.fn(),
    }));
    jest.doMock('../../src/lib/email', () => ({
      sendRotatedKeyEmail: jest.fn().mockResolvedValue(undefined),
    }));
    jest.doMock('../../src/lib/logger', () => ({
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    }));

    PrismaClient = require('@prisma/client').PrismaClient;
    mockPrisma = new PrismaClient();
    getBINStats = require('../../src/lib/binSequenceDetector').getBINStats;
    resolveTenantByApiKey = require('../../src/lib/apiKeyAuth').resolveTenantByApiKey;
    hashApiKey = require('../../src/lib/apiKeyHash').hashApiKey;
    sendRotatedKeyEmail = require('../../src/lib/email').sendRotatedKeyEmail;
    dashboardRouter = require('../../src/routes/dashboard');
  });

  if (!jest.isMockFunction(PrismaClient)) {
    throw new Error(
      '[dashboard-page-html.test.js] PrismaClient is not mocked after isolateModules — ' +
      'check for a root __mocks__/@prisma/client.js, a setupFiles entry that ' +
      'requires app.js unmocked, or a global resetMocks/restoreMocks config.'
    );
  }
});

// ── Route-stack extraction helpers (identical to File 1) ────────────────────
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

// ── Unique-IP counter (see mocking-strategy note #5 above) ──────────────────
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

function makeMonthlyReport(overrides = {}) {
  return {
    id: 'rep_1',
    reportMonth: 6,
    reportYear: 2026,
    totalAttacks: 10,
    totalProtected: 100,
    totalFeesSaved: 5,
    ...overrides,
  };
}

function mockAuthenticatedTenant(tenant) {
  resolveTenantByApiKey.mockResolvedValue({ tenant, usedPreviousKey: false });
}

// ── getDashboardData scenario builder (copied verbatim from File 1) ─────────
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
  mockPrisma.monthlyReport.findMany.mockResolvedValue([]); // buildReportsArchiveSection default
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
});

// ══════════════════════════════════════════════════════════════════════════════
describe('GET /page — HTML dashboard rendering', () => {
  const handlers = () => getRouteHandlers('get', '/page');

  describe('Auth, headers, and error handling', () => {
    test('missing X-Api-Key header → 401, no DB calls, no HTML sent', async () => {
      const req = makeReq({ headers: {} });
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.send).not.toHaveBeenCalled();
      expect(mockPrisma.blockedAttempt.count).not.toHaveBeenCalled();
    });

    test('unverified tenant → 403 JSON EMAIL_NOT_VERIFIED (real requireAuth short-circuits before the HTML branch), no dashboard data built', async () => {
      mockAuthenticatedTenant(makeTenant({ emailVerified: false }));
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'EMAIL_NOT_VERIFIED' }));
      expect(res.send).not.toHaveBeenCalled();
      expect(mockPrisma.blockedAttempt.count).not.toHaveBeenCalled();
    });

    test('success → 200 with correct Content-Type, Cache-Control, and X-Robots-Tag headers', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
      setupDashboardScenario({});
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'text/html; charset=utf-8');
      expect(res.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
      // Real header value is 'noindex' only — 'noindex,nofollow' only appears
      // in the <meta name="robots"> tag inside the HTML body, not the header.
      expect(res.setHeader).toHaveBeenCalledWith('X-Robots-Tag', 'noindex');
      expect(res.send).toHaveBeenCalledWith(
        expect.stringContaining('<title>ChargeGuard — Protection Dashboard</title>')
      );
    });

    test('DB failure inside getDashboardData → 500 with plain-text body (NOT JSON, unlike GET /)', async () => {
      mockAuthenticatedTenant(makeTenant());
      mockPrisma.blockedAttempt.count.mockRejectedValueOnce(new Error('db down'));
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.send).toHaveBeenCalledWith('Internal Server Error');
      expect(res.json).not.toHaveBeenCalled();
    });
  });

  describe('Plan gating — BIN Intelligence Panel (always renders, gated by isProOrAbove)', () => {
    test('Starter tenant: locked with Pro Feature / pro-lock / Unlock BIN Intelligence markers, no unlocked content', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'starter' }));
      setupDashboardScenario({});
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.send).toHaveBeenCalledWith(expect.stringContaining('Pro Feature'));
      expect(res.send).toHaveBeenCalledWith(expect.stringContaining('pro-lock'));
      expect(res.send).toHaveBeenCalledWith(expect.stringContaining('Unlock BIN Intelligence'));

      const html = res.send.mock.calls[0][0];
      expect(html).not.toContain('All Clear');
      expect(html).not.toContain('Active BIN Sequence Attack Detected');
    });

    test('Pro tenant, no active BIN attack: full "All Clear" panel renders, no lock markers', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
      setupDashboardScenario({});
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const html = res.send.mock.calls[0][0];
      expect(html).toContain('All Clear');
      expect(html).not.toContain('Unlock BIN Intelligence');
      expect(html).not.toContain('Pro Feature');
    });

    test('Pro tenant, active BIN attack: real masked BIN + count render unlocked', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
      setupDashboardScenario({
        binAttackData: [{ cardBin: '411111', _count: { cardBin: 5 } }],
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const html = res.send.mock.calls[0][0];
      expect(html).toContain('Active BIN Sequence Attack Detected');
      expect(html).toContain('4111••');
      expect(html).not.toContain('Unlock BIN Intelligence');
    });
  });

  describe('Plan gating — BIN Sequence Alert Panel (#cg-bin-seq-panel, gated + conditional on activity)', () => {
    test('Starter tenant with active/blocked prefixes: locked panel renders', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'starter' }));
      setupDashboardScenario({
        binStats: { activePrefixes: 0, blockedPrefixes: 1, totalActiveBINs: 2 },
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.send).toHaveBeenCalledWith(expect.stringContaining('Unlock BIN Sequence Monitoring'));
    });

    test('Starter tenant with no prefix activity: panel omitted entirely', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'starter' }));
      setupDashboardScenario({}); // binStats defaults to all-zero
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const html = res.send.mock.calls[0][0];
      expect(html).not.toContain('Unlock BIN Sequence Monitoring');
      expect(html).not.toContain('BIN Sequence Monitoring');
    });

    test('Pro tenant with active prefixes: progress-bar panel renders unlocked', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
      setupDashboardScenario({
        binStats: { activePrefixes: 1, blockedPrefixes: 0, totalActiveBINs: 4 },
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const html = res.send.mock.calls[0][0];
      expect(html).toContain('BIN Sequence — Under Watch');
      expect(html).toContain('BINs to alert threshold');
      expect(html).not.toContain('Unlock BIN Sequence Monitoring');
    });

    test('Pro tenant with no prefix activity: panel omitted entirely', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
      setupDashboardScenario({});
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const html = res.send.mock.calls[0][0];
      // NOTE: the client-side <script> block always emits the literal string
      // 'BIN Sequence — Under Watch' as part of updateBINPanel()'s reusable
      // polling-render code (used later, client-side, after a live
      // /bin-sequence-alerts fetch) — completely independent of the
      // server-rendered initial state we're asserting on here. A blanket
      // html.not.toContain() check therefore always fails, even when the
      // panel is correctly omitted server-side. Slice off everything from
      // the first <script> tag onward so we only assert against the
      // server-rendered markup, not the embedded client JS template strings.
      const serverRenderedHtml = html.split('<script>')[0];
      expect(serverRenderedHtml).not.toContain('BIN Sequence — Under Watch');
      expect(serverRenderedHtml).not.toContain('Unlock BIN Sequence Monitoring');
    });
  });

  describe('Plan gating — Threat Origins section (gated + conditional on totalBlocked)', () => {
    test('Starter tenant with totalBlocked>0: locked section renders', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'starter' }));
      setupDashboardScenario({ totalBlocked: 5 });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(res.send).toHaveBeenCalledWith(expect.stringContaining('Unlock Threat Origins'));
    });

    test('Starter tenant with totalBlocked===0: section omitted entirely', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'starter' }));
      setupDashboardScenario({ totalBlocked: 0 });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const html = res.send.mock.calls[0][0];
      expect(html).not.toContain('Card Issuer Origins');
    });

    test('Pro tenant with real origin data: unlocked country rows render', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
      setupDashboardScenario({
        totalBlocked: 5,
        topBinsForOrigin: [{ cardBin: '411111', _count: { cardBin: 5 } }],
        binRecords: [{ bin: '411111', issuerCountry: 'US', brand: 'Visa' }],
      });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const html = res.send.mock.calls[0][0];
      expect(html).toContain('Card Issuer Origins');
      expect(html).toContain('United States');
      expect(html).not.toContain('Unlock Threat Origins');
      expect(html).not.toContain('Pro Feature');
    });

    test('Pro tenant, no origin data yet but totalBlocked>0: "Building data" placeholder renders', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
      setupDashboardScenario({ totalBlocked: 3, topBinsForOrigin: [] });
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const html = res.send.mock.calls[0][0];
      expect(html).toContain('Building data');
    });

    test('Pro tenant, no origin data and totalBlocked===0: section omitted entirely', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
      setupDashboardScenario({});
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      const html = res.send.mock.calls[0][0];
      expect(html).not.toContain('Card Issuer Origins');
    });
  });

  describe('buildReportsArchiveSection — Monthly Security Reports archive', () => {
    test('Starter tenant: findMany called with take:3; only the latest row is unlocked, older rows blurred with no View Report link', async () => {
      mockAuthenticatedTenant(makeTenant({ plan: 'starter' }));
      setupDashboardScenario({});
      const reports = [
        makeMonthlyReport({ id: 'r1', reportMonth: 6, reportYear: 2026 }),
        makeMonthlyReport({ id: 'r2', reportMonth: 5, reportYear: 2026 }),
        makeMonthlyReport({ id: 'r3', reportMonth: 4, reportYear: 2026 }),
      ];
      mockPrisma.monthlyReport.findMany.mockResolvedValueOnce(reports);
      const req = makeReq();
      const res = makeRes();

      await dispatch(handlers(), req, res);

      expect(mockPrisma.monthlyReport.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ take: 3 })
      );

      const html = res.send.mock.calls[0][0];
      const viewReportCount = (html.match(/View Report/g) || []).length;
      expect(viewReportCount).toBe(1); // only index 0 (latest) is unlocked
      expect(html).toContain('filter:blur(2px);pointer-events:none;user-select:none;');
      expect(html).toContain('Access full archive — Upgrade to Pro');
    });

    test.each(['pro', 'agency'])(
      '%s tenant: findMany called with take:24; no row blurred, every report has a View Report link',
      async (plan) => {
        mockAuthenticatedTenant(makeTenant({ plan }));
        setupDashboardScenario({});
        const reports = [
          makeMonthlyReport({ id: 'r1', reportMonth: 6, reportYear: 2026 }),
          makeMonthlyReport({ id: 'r2', reportMonth: 5, reportYear: 2026 }),
          makeMonthlyReport({ id: 'r3', reportMonth: 4, reportYear: 2026 }),
        ];
        mockPrisma.monthlyReport.findMany.mockResolvedValueOnce(reports);
        const req = makeReq();
        const res = makeRes();

        await dispatch(handlers(), req, res);

        expect(mockPrisma.monthlyReport.findMany).toHaveBeenCalledWith(
          expect.objectContaining({ take: 24 })
        );

        const html = res.send.mock.calls[0][0];
        const viewReportCount = (html.match(/View Report/g) || []).length;
        expect(viewReportCount).toBe(3);
        expect(html).not.toContain('filter:blur(2px);pointer-events:none;user-select:none;');
        expect(html).not.toContain('Access full archive — Upgrade to Pro');
      }
    );

    test.each(['starter', 'pro'])(
      '%s tenant, empty reports array: archive section omitted entirely',
      async (plan) => {
        mockAuthenticatedTenant(makeTenant({ plan }));
        setupDashboardScenario({});
        mockPrisma.monthlyReport.findMany.mockResolvedValueOnce([]);
        const req = makeReq();
        const res = makeRes();

        await dispatch(handlers(), req, res);

        const html = res.send.mock.calls[0][0];
        expect(html).not.toContain('Monthly Security Reports');
      }
    );
  });
});