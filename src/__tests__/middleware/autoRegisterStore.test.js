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
});
// END-OF-FILE-58
