'use strict';

// CSV-NO-TEST (Batch A2): GET /orders/export.csv in src/routes/dashboard.js.
// Pins: formula-injection guard, numeric values untouched, CSV quoting,
// Pro gating, tenant scoping, store validation, error path, rate limit.
// Mocking pattern follows tests/dashboard/dashboard-data.test.js.

jest.mock('@prisma/client', () => {
  const mp = {
    order: { findMany: jest.fn(), count: jest.fn() },
    store: { findFirst: jest.fn(), findMany: jest.fn() },
    tenant: { count: jest.fn(), findUnique: jest.fn(), update: jest.fn() },
    blockedAttempt: {
      count: jest.fn(), findMany: jest.fn(), findFirst: jest.fn(),
      aggregate: jest.fn(), groupBy: jest.fn(),
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
jest.mock('../../src/lib/apiKeyAuth', () => ({ resolveTenantByApiKey: jest.fn() }));
jest.mock('../../src/lib/apiKeyHash', () => ({ hashApiKey: jest.fn() }));
jest.mock('../../src/lib/email', () => ({ sendRotatedKeyEmail: jest.fn() }));
jest.mock('../../src/lib/logger', () => ({
  debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn(),
}));
jest.mock('../../src/lib/protectionStatus', () => ({
  getProtectionStatus: jest.fn(),
  getProtectionLayers: jest.fn(),
}));

const { PrismaClient } = require('@prisma/client');
const mockPrisma = new PrismaClient();
const { resolveTenantByApiKey } = require('../../src/lib/apiKeyAuth');
const dashboardRouter = require('../../src/routes/dashboard');

function getRouteHandlers(method, path) {
  const layer = dashboardRouter.stack.find(
    (l) => l.route && l.route.path === path && l.route.methods[method.toLowerCase()]
  );
  if (!layer) throw new Error('Route not found: ' + method.toUpperCase() + ' ' + path);
  return layer.route.stack.map((s) => s.handle);
}

// Same dispatch pattern as dashboard-data.test.js: waits for the whole chain
// even when a middleware calls next() fire-and-forget.
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

let ipCounter = 0;
function makeReq(overrides = {}) {
  ipCounter += 1;
  return {
    headers: { 'x-api-key': 'test-api-key' },
    body: {},
    params: {},
    query: {},
    ip: 'test-ip-' + ipCounter,
    ...overrides,
  };
}

function makeRes() {
  const res = {};
  res.statusCode = 200;
  res.status = jest.fn((code) => { res.statusCode = code; return res; });
  res.json = jest.fn((body) => { res.body = body; return res; });
  res.send = jest.fn((body) => { res.body = body; return res; });
  res.set = jest.fn(() => res);
  res.setHeader = jest.fn(() => res);
  return res;
}

// The export limiter is keyed by tenant id (max 5), so every test gets its own tenant.
let tenantSeq = 0;
function makeTenant(overrides = {}) {
  tenantSeq += 1;
  return {
    id: 'export_tenant_' + tenantSeq,
    email: 'merchant@example.com',
    plan: 'pro',
    isActive: true,
    emailVerified: true,
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    keyRotatedAt: null,
    ...overrides,
  };
}

const row = (o = {}) => ({
  orderId: '1001',
  email: 'buyer@example.com',
  amount: 10.5,
  currency: 'USD',
  riskScore: 12,
  riskLevel: 'low',
  decision: 'approve',
  createdAt: new Date('2026-10-01T10:00:00.000Z'),
  ...o,
});

const handlers = () => getRouteHandlers('GET', '/orders/export.csv');
const dataLines = (res) => res.body.split('\n').slice(1);
const cells = (line) => line.split(',');
const statusOf = (res) => res.status.mock.calls.map((c) => c[0]).pop();

async function exportCsv({ plan = 'pro', query = {}, orders = [], findManyError = null } = {}) {
  const tenant = makeTenant({ plan });
  resolveTenantByApiKey.mockResolvedValue({ tenant, usedPreviousKey: false });
  if (findManyError) mockPrisma.order.findMany.mockRejectedValue(findManyError);
  else mockPrisma.order.findMany.mockResolvedValue(orders);
  const req = makeReq({ query });
  const res = makeRes();
  await dispatch(handlers(), req, res);
  return { tenant, req, res };
}

beforeEach(() => {
  jest.resetAllMocks();
});

describe('GET /orders/export.csv', () => {
  describe('formula-injection guard', () => {
    test.each(['=1+1', '+1+1', '-2+3', '@SUM(1)', '\tcmd'])(
      'prefixes a single quote on text starting with a formula character %j',
      async (evil) => {
        const { res } = await exportCsv({ orders: [row({ email: evil })] });
        expect(cells(dataLines(res)[0])[1]).toBe("'" + evil);
      }
    );

    test('prefixes string order ids that start with a formula character', async () => {
      // orderId is a string column, so a leading "-" is treated as text (intended).
      const { res } = await exportCsv({ orders: [row({ orderId: '-123' })] });
      expect(cells(dataLines(res)[0])[0]).toBe("'-123");
    });

    test('leaves real numbers untouched, including negatives and zero', async () => {
      const { res } = await exportCsv({ orders: [row({ amount: -5.5, riskScore: 0 })] });
      const c = cells(dataLines(res)[0]);
      expect(c[2]).toBe('-5.5');
      expect(c[4]).toBe('0');
    });

    test('leaves benign text untouched and renders null fields as empty cells', async () => {
      const { res } = await exportCsv({
        orders: [
          row(),
          row({ orderId: '1002', email: null, riskScore: null, riskLevel: null, decision: null }),
        ],
      });
      const [a, b] = dataLines(res).map(cells);
      expect(a.slice(0, 2)).toEqual(['1001', 'buyer@example.com']);
      expect(b).toEqual(['1002', '', '10.5', 'USD', '', '', '', '2026-10-01T10:00:00.000Z']);
    });
  });

  describe('CSV quoting', () => {
    test('quotes cells containing commas and doubles embedded quotes', async () => {
      const { res } = await exportCsv({
        orders: [row({ email: 'a,b@x.com' }), row({ email: 'say "hi"@x.com' })],
      });
      const [l1, l2] = dataLines(res);
      expect(l1).toContain('"a,b@x.com"');
      expect(l2).toContain('"say ""hi""@x.com"');
    });

    test('applies the formula prefix before quoting', async () => {
      const { res } = await exportCsv({ orders: [row({ email: '=a,b' })] });
      expect(dataLines(res)[0]).toContain('"\'=a,b"');
    });
  });

  describe('response shape', () => {
    test('sends header row, CSV headers and status 200', async () => {
      const { res } = await exportCsv({ orders: [row()] });
      expect(statusOf(res)).toBe(200);
      expect(res.body.split('\n')[0]).toBe(
        'Order ID,Email,Amount,Currency,Risk Score,Risk Level,Decision,Created At (UTC)'
      );
      expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'text/csv; charset=utf-8');
      expect(res.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
      const disp = res.setHeader.mock.calls.find((c) => c[0] === 'Content-Disposition')[1];
      expect(disp).toMatch(/^attachment; filename="chargeguard-orders-\d{4}-\d{2}-\d{2}\.csv"$/);
    });
  });

  describe('access control and scoping', () => {
    test('rejects non-Pro tenants with 403 PRO_REQUIRED and never queries orders', async () => {
      const { res } = await exportCsv({ plan: 'starter' });
      expect(statusOf(res)).toBe(403);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'PRO_REQUIRED' }));
      expect(mockPrisma.order.findMany).not.toHaveBeenCalled();
    });

    test('scopes the query to the tenant and applies filters', async () => {
      const { tenant } = await exportCsv({
        query: { email: ' Foo ', orderId: ' 12 ', decision: 'block' },
      });
      const arg = mockPrisma.order.findMany.mock.calls[0][0];
      expect(arg.where.merchantId).toBe(tenant.id);
      expect(arg.where.email).toEqual({ contains: 'Foo', mode: 'insensitive' });
      expect(arg.where.orderId).toEqual({ contains: '12' });
      expect(arg.where.decision).toBe('block');
      expect(arg.where.storeId).toBeUndefined();
      expect(arg.take).toBe(5000);
      expect(arg.orderBy).toEqual({ createdAt: 'desc' });
      const ageMs = Date.now() - arg.where.createdAt.gte.getTime();
      expect(Math.abs(ageMs - 90 * 24 * 60 * 60 * 1000)).toBeLessThan(10000);
      expect(Object.keys(arg.select).sort()).toEqual([
        'amount', 'createdAt', 'currency', 'decision', 'email', 'orderId', 'riskLevel', 'riskScore',
      ]);
    });

    test('ignores an unknown decision filter', async () => {
      await exportCsv({ query: { decision: 'bogus' } });
      expect(mockPrisma.order.findMany.mock.calls[0][0].where.decision).toBeUndefined();
    });

    test('rejects a storeId that does not belong to the tenant', async () => {
      mockPrisma.store.findFirst.mockResolvedValue(null);
      const { res } = await exportCsv({ query: { storeId: 'nope' } });
      expect(statusOf(res)).toBe(400);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'INVALID_STORE' }));
      expect(mockPrisma.order.findMany).not.toHaveBeenCalled();
    });

    test('scopes to a valid storeId', async () => {
      mockPrisma.store.findFirst.mockResolvedValue({ id: 'store_1' });
      const { tenant } = await exportCsv({ query: { storeId: 'store_1' } });
      expect(mockPrisma.store.findFirst.mock.calls[0][0].where).toEqual({
        id: 'store_1', tenantId: tenant.id, isActive: true,
      });
      expect(mockPrisma.order.findMany.mock.calls[0][0].where.storeId).toBe('store_1');
    });
  });

  describe('failure handling', () => {
    test('returns 500 INTERNAL_ERROR when the query fails', async () => {
      const { res } = await exportCsv({ findManyError: new Error('boom') });
      expect(statusOf(res)).toBe(500);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'INTERNAL_ERROR' }));
    });

    test('rate-limits to 5 exports per tenant', async () => {
      const tenant = makeTenant({ plan: 'pro' });
      resolveTenantByApiKey.mockResolvedValue({ tenant, usedPreviousKey: false });
      mockPrisma.order.findMany.mockResolvedValue([]);
      const statuses = [];
      for (let i = 0; i < 6; i += 1) {
        const res = makeRes();
        await dispatch(handlers(), makeReq(), res);
        statuses.push(statusOf(res));
      }
      expect(statuses).toEqual([200, 200, 200, 200, 200, 429]);
    });
  });
});