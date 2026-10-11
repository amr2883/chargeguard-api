// src/__tests__/middleware/autoRegisterStore.test.js
//
// Contract pinned here (autoRegisterStoreMiddleware, Solution D "verify" half):
//   - no pendingStoreDomain            -> next(), nothing touched
//   - kill switch off                  -> 403 DOMAIN_MISMATCH
//   - signature not domain-bound       -> 403 DOMAIN_MISMATCH (v1, unknown, missing)
//   - domain-bound signature (v2, v3)  -> proceeds to the Agency / Store logic
//   - non-Agency tenant                -> 403
//   - every rejection must NOT create a Store and must NOT call next()
//
// The middleware swallows its own errors (outer catch -> 503), so happy-path
// tests also assert that the 503 branch was not taken.

jest.mock('../../lib/db', () => ({
  store: { findUnique: jest.fn(), count: jest.fn(), create: jest.fn() },
}));
jest.mock('../../lib/logger', () => ({
  info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(),
}));
jest.mock('../../lib/planAccess', () => ({ isAgency: jest.fn() }));

const db = require('../../lib/db');
const { isAgency } = require('../../lib/planAccess');
const autoRegisterStoreMiddleware = require('../../middleware/autoRegisterStore');

const DOMAIN = 'new-store.example.com';

function makeReq(overrides = {}) {
  return {
    pendingStoreDomain: DOMAIN,
    hmacSignatureVersion: 'v2',
    tenant: { id: 'tenant_1', plan: 'agency' },
    path: '/risk/evaluate',
    headers: { 'x-store-domain': DOMAIN },
    ...overrides,
  };
}
function makeRes() {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
}
async function run(req) {
  const res = makeRes();
  const next = jest.fn();
  await autoRegisterStoreMiddleware(req, res, next);
  return { res, next };
}
function expectRejected(res, next, status, code) {
  expect(res.status).toHaveBeenCalledWith(status);
  expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code }));
  expect(next).not.toHaveBeenCalled();
  expect(db.store.create).not.toHaveBeenCalled();
}

describe('autoRegisterStoreMiddleware', () => {
  const originalFlag = process.env.AGENCY_AUTO_REGISTER_ENABLED;

  beforeEach(() => {
    jest.resetAllMocks();
    process.env.AGENCY_AUTO_REGISTER_ENABLED = 'true';
    isAgency.mockReturnValue(true);
    db.store.findUnique.mockResolvedValue(null);
    db.store.count.mockResolvedValue(0);
    db.store.create.mockResolvedValue({ id: 'store_new' });
  });

  afterAll(() => {
    if (originalFlag === undefined) delete process.env.AGENCY_AUTO_REGISTER_ENABLED;
    else process.env.AGENCY_AUTO_REGISTER_ENABLED = originalFlag;
  });

  test('no pendingStoreDomain: passes through and touches nothing', async () => {
    const { res, next } = await run(makeReq({ pendingStoreDomain: undefined }));
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
    expect(db.store.findUnique).not.toHaveBeenCalled();
    expect(db.store.create).not.toHaveBeenCalled();
  });

  test('kill switch off: rejects with DOMAIN_MISMATCH even for a v2 signature', async () => {
    process.env.AGENCY_AUTO_REGISTER_ENABLED = 'false';
    const { res, next } = await run(makeReq({ hmacSignatureVersion: 'v2' }));
    expectRejected(res, next, 403, 'DOMAIN_MISMATCH');
  });

  test.each(['v1', 'v4', '', undefined])(
    'signature version %p is not domain-bound: rejected, no Store created',
    async (version) => {
      const { res, next } = await run(makeReq({ hmacSignatureVersion: version }));
      expectRejected(res, next, 403, 'DOMAIN_MISMATCH');
      expect(db.store.findUnique).not.toHaveBeenCalled();
    }
  );

  test.each(['v2', 'v3'])(
    'domain-bound signature %s: registers the Store and continues',
    async (version) => {
      const req = makeReq({ hmacSignatureVersion: version });
      const { res, next } = await run(req);
      expect(res.status).not.toHaveBeenCalled();
      expect(db.store.create).toHaveBeenCalledTimes(1);
      expect(db.store.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant_1',
          storeUrl: DOMAIN,
          normalizedDomain: DOMAIN,
          label: null,
        },
      });
      expect(req.storeId).toBe('store_new');
      expect(req.storeDomain).toBe(DOMAIN);
      expect(next).toHaveBeenCalledTimes(1);
    }
  );

  test('non-Agency tenant: rejected even with a v3 signature', async () => {
    isAgency.mockReturnValue(false);
    const { res, next } = await run(makeReq({ hmacSignatureVersion: 'v3' }));
    expectRejected(res, next, 403, 'DOMAIN_MISMATCH');
  });
  describe('Store resolution after a domain-bound signature (#58)', () => {
    const lookup = { where: { tenantId_normalizedDomain: { tenantId: 'tenant_1', normalizedDomain: DOMAIN } } };

    test('existing soft-deleted Store: rejected with STORE_DEACTIVATED, never reactivated, no cap check', async () => {
      db.store.findUnique.mockResolvedValue({ id: 'store_old', isActive: false });
      const { res, next } = await run(makeReq());
      expectRejected(res, next, 403, 'STORE_DEACTIVATED');
      expect(db.store.count).not.toHaveBeenCalled();
    });

    test('existing active Store: attributed idempotently, nothing created', async () => {
      db.store.findUnique.mockResolvedValue({ id: 'store_old', isActive: true });
      const req = makeReq();
      const { res, next } = await run(req);
      expect(res.status).not.toHaveBeenCalled();
      expect(next).toHaveBeenCalledTimes(1);
      expect(db.store.findUnique).toHaveBeenCalledWith(lookup);
      expect(db.store.count).not.toHaveBeenCalled();
      expect(db.store.create).not.toHaveBeenCalled();
      expect(req.storeId).toBe('store_old');
      expect(req.storeDomain).toBe(DOMAIN);
    });

    test('cap reached (5 active Stores): rejected with STORE_LIMIT_REACHED', async () => {
      db.store.count.mockResolvedValue(5);
      const { res, next } = await run(makeReq());
      expectRejected(res, next, 403, 'STORE_LIMIT_REACHED');
      expect(db.store.count).toHaveBeenCalledWith({ where: { tenantId: 'tenant_1', isActive: true } });
    });

    test('one below the cap (4 active Stores): still registers', async () => {
      db.store.count.mockResolvedValue(4);
      const { res, next } = await run(makeReq());
      expect(res.status).not.toHaveBeenCalled();
      expect(db.store.create).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledTimes(1);
    });

    test('concurrent create race (P2002), winner is active: attributes to it, creates once', async () => {
      db.store.findUnique.mockResolvedValueOnce(null).mockResolvedValueOnce({ id: 'store_race', isActive: true });
      db.store.create.mockRejectedValue({ code: 'P2002' });
      const req = makeReq();
      const { res, next } = await run(req);
      expect(res.status).not.toHaveBeenCalled();
      expect(db.store.create).toHaveBeenCalledTimes(1);
      expect(db.store.findUnique).toHaveBeenCalledTimes(2);
      expect(next).toHaveBeenCalledTimes(1);
      expect(req.storeId).toBe('store_race');
    });

    test('concurrent create race (P2002), winner is inactive: rejected with DOMAIN_MISMATCH', async () => {
      db.store.findUnique.mockResolvedValueOnce(null).mockResolvedValueOnce({ id: 'store_race', isActive: false });
      db.store.create.mockRejectedValue({ code: 'P2002' });
      const { res, next } = await run(makeReq());
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'DOMAIN_MISMATCH' }));
      expect(next).not.toHaveBeenCalled();
    });

    test('unexpected DB error on lookup: fails closed with 503', async () => {
      db.store.findUnique.mockRejectedValue(new Error('db down'));
      const { res, next } = await run(makeReq());
      expectRejected(res, next, 503, 'DOMAIN_CHECK_UNAVAILABLE');
    });

    test('non-P2002 error on create: fails closed with 503', async () => {
      db.store.create.mockRejectedValue(new Error('boom'));
      const { res, next } = await run(makeReq());
      expect(res.status).toHaveBeenCalledWith(503);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'DOMAIN_CHECK_UNAVAILABLE' }));
      expect(next).not.toHaveBeenCalled();
    });
  });

});
// END-OF-FILE-58
