'use strict';

// PRIV-LOCAL-NORMALIZE + PRIV-CHALLENGE-CASE (Batch P1a)
// DELETE /api/privacy/erase in src/routes/privacy.js.
// Pins: input validation, the shared email normaliser (the one risk.js uses
// when it writes Order.normalizedEmail), tenant scoping, case-insensitive
// matching, PII fields cleared, response shape, failure paths, rate limit.
// Mocking pattern follows tests/dashboard/export-csv.test.js.

jest.mock('../../src/lib/db', () => ({
  order: { updateMany: jest.fn() },
  challengeVerification: { deleteMany: jest.fn() },
}));
jest.mock('../../src/lib/logger', () => ({
  debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn(),
}));
jest.mock('../../src/lib/cloudflareRanges', () => ({
  getCloudflareRanges: jest.fn(() => []),
}));
jest.mock('../../src/middleware/authenticate', () => ({
  requireAuth: () => (req, res, next) => {
    req.tenant = { id: req.headers['x-test-tenant'] || 'tenant_a' };
    return next();
  },
}));
jest.mock('../../src/lib/utils', () => {
  const actual = jest.requireActual('../../src/lib/utils');
  return { ...actual, normalizeEmail: jest.fn(actual.normalizeEmail) };
});

const db = require('../../src/lib/db');
const { normalizeEmail } = require('../../src/lib/utils');
const realUtils = jest.requireActual('../../src/lib/utils');
const privacyRouter = require('../../src/routes/privacy');

const stored = (email) => realUtils.normalizeEmail(email);

function getRouteHandlers(method, path) {
  const layer = privacyRouter.stack.find(
    (l) => l.route && l.route.path === path && l.route.methods[method.toLowerCase()]
  );
  if (!layer) throw new Error('Route not found: ' + method.toUpperCase() + ' ' + path);
  return layer.route.stack.map((s) => s.handle);
}

// Same dispatch pattern as export-csv.test.js: waits for the whole chain even
// when a middleware calls next() fire-and-forget.
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

function makeRes() {
  const res = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn((body) => { res.body = body; return res; });
  return res;
}

const statusOf = (res) => res.status.mock.calls.map((c) => c[0]).pop();

// The limiter is keyed by the raw x-api-key header (5 per hour), so every
// test gets its own key unless it is testing the limiter itself.
let keySeq = 0;
const nextKey = () => 'privacy-test-key-' + (++keySeq);

async function erase(opts = {}) {
  const body = Object.prototype.hasOwnProperty.call(opts, 'body')
    ? opts.body
    : { email: 'buyer@example.com' };
  const req = {
    headers: {
      'x-api-key': opts.apiKey || nextKey(),
      'x-test-tenant': opts.tenant || 'tenant_a',
    },
    body,
    ip: '203.0.113.9',
  };
  const res = makeRes();
  await dispatch(getRouteHandlers('DELETE', '/erase'), req, res);
  return { req, res };
}

beforeEach(() => {
  jest.resetAllMocks();
  normalizeEmail.mockImplementation(realUtils.normalizeEmail);
  db.order.updateMany.mockResolvedValue({ count: 2 });
  db.challengeVerification.deleteMany.mockResolvedValue({ count: 1 });
});

describe('DELETE /erase', () => {
  describe('input validation', () => {
    test.each([[undefined], [null], [''], ['   '], ['no-at-sign'], [123], [{}]])(
      'rejects email %j with 400 and touches nothing',
      async (value) => {
        const { res } = await erase({ body: { email: value } });
        expect(statusOf(res)).toBe(400);
        expect(res.body).toEqual({ error: 'email is required' });
        expect(db.order.updateMany).not.toHaveBeenCalled();
        expect(db.challengeVerification.deleteMany).not.toHaveBeenCalled();
      }
    );

    test('rejects a request with no body at all', async () => {
      const { res } = await erase({ body: undefined });
      expect(statusOf(res)).toBe(400);
      expect(db.order.updateMany).not.toHaveBeenCalled();
    });

    test('rejects (not 500s) when the normaliser throws', async () => {
      normalizeEmail.mockImplementation(() => { throw new Error('bad input'); });
      const { res } = await erase({ body: { email: 'x@y.com' } });
      expect(statusOf(res)).toBe(400);
      expect(res.body).toEqual({ error: 'a valid email is required' });
      expect(db.order.updateMany).not.toHaveBeenCalled();
      expect(db.challengeVerification.deleteMany).not.toHaveBeenCalled();
    });

    test('rejects when the normaliser returns an empty string', async () => {
      normalizeEmail.mockReturnValueOnce('');
      const { res } = await erase({ body: { email: 'x@y.com' } });
      expect(statusOf(res)).toBe(400);
      expect(res.body).toEqual({ error: 'a valid email is required' });
      expect(db.order.updateMany).not.toHaveBeenCalled();
    });
  });

  describe('order erasure', () => {
    test('scopes to the authenticated tenant and matches normalised OR raw email', async () => {
      await erase({ tenant: 'tenant_x', body: { email: 'Buyer@Example.com' } });
      const arg = db.order.updateMany.mock.calls[0][0];
      expect(arg.where.merchantId).toBe('tenant_x');
      expect(arg.where.OR).toEqual([
        { normalizedEmail: stored('Buyer@Example.com') },
        { email: { equals: 'Buyer@Example.com', mode: 'insensitive' } },
      ]);
    });

    test('clears every personal identifier it is responsible for', async () => {
      await erase();
      expect(db.order.updateMany.mock.calls[0][0].data).toEqual({
        email: null,
        normalizedEmail: null,
        ipAddress: null,
        customerLoginId: null,
        deviceFingerprint: null,
        fingerprintVersion: null,
        fingerprintStatus: null,
      });
    });

    test('trims the raw email before matching', async () => {
      await erase({ body: { email: '  John@Example.com  ' } });
      const arg = db.order.updateMany.mock.calls[0][0];
      expect(arg.where.OR[1]).toEqual({ email: { equals: 'John@Example.com', mode: 'insensitive' } });
    });

    test('finds an order stored under the dot-less gmail form', async () => {
      await erase({ body: { email: 'john.doe@gmail.com' } });
      const arg = db.order.updateMany.mock.calls[0][0];
      expect(arg.where.OR[0]).toEqual({ normalizedEmail: 'johndoe@gmail.com' });
    });
  });

  describe('challenge erasure', () => {
    test('deletes challenges case-insensitively, scoped to the tenant', async () => {
      await erase({ tenant: 'tenant_c', body: { email: 'John@X.com' } });
      expect(db.challengeVerification.deleteMany).toHaveBeenCalledWith({
        where: { merchantId: 'tenant_c', email: { equals: 'John@X.com', mode: 'insensitive' } },
      });
    });
  });

  describe('responses and failures', () => {
    test('returns 200 with both counts', async () => {
      const { res } = await erase();
      expect(statusOf(res)).toBe(200);
      expect(res.body).toEqual({ success: true, ordersUpdated: 2, challengesDeleted: 1 });
    });

    test('still returns 200 success when nothing matched (pins PRIV-ZERO-SILENT)', async () => {
      db.order.updateMany.mockResolvedValue({ count: 0 });
      db.challengeVerification.deleteMany.mockResolvedValue({ count: 0 });
      const { res } = await erase();
      expect(statusOf(res)).toBe(200);
      expect(res.body).toEqual({ success: true, ordersUpdated: 0, challengesDeleted: 0 });
    });

    test('returns 500 and skips the challenge delete when the order update fails', async () => {
      db.order.updateMany.mockRejectedValue(new Error('boom'));
      const { res } = await erase();
      expect(statusOf(res)).toBe(500);
      expect(res.body).toEqual({ error: 'Internal server error' });
      expect(db.challengeVerification.deleteMany).not.toHaveBeenCalled();
    });

    test('returns 500 when the challenge delete fails', async () => {
      db.challengeVerification.deleteMany.mockRejectedValue(new Error('boom'));
      const { res } = await erase();
      expect(statusOf(res)).toBe(500);
      expect(res.body).toEqual({ error: 'Internal server error' });
    });

    test('rate-limits to 5 requests per API key per hour', async () => {
      const apiKey = nextKey();
      const statuses = [];
      for (let i = 0; i < 6; i += 1) {
        const { res } = await erase({ apiKey });
        statuses.push(statusOf(res));
      }
      expect(statuses).toEqual([200, 200, 200, 200, 200, 429]);
    });
  });
});