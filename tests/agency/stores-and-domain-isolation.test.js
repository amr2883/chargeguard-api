'use strict';

// ══════════════════════════════════════════════════════════════════════════════
// SCOPE: Test 9 — Agency Multi-Store Management & Tenant Isolation
//   - src/routes/stores.js
//       GET    /api/stores
//       POST   /api/stores
//       DELETE /api/stores/:id
//   - src/lib/domainAuth.js
//       domainAuthMiddleware (tested standalone — NOT mounted in stores.js;
//       stores.js only imports normalizeDomain from this module)
//       normalizeDomain, isDevDomain (pure helpers, smoke-tested directly)
//
// MOCKING STRATEGY:
//   - db.js mocked (manual factory) — stores.js uses the shared db.js
//     singleton (same pattern as payments.js/settings.js), NOT a
//     self-instantiated PrismaClient (unlike dashboard.js). domainAuth.js
//     requires the SAME './db' path, so this single mock backs both units
//     under test — no separate Prisma mock needed for domainAuth.js.
//   - logger.js mocked to silence output; asserted on for error-path coverage.
//   - lib/apiKeyAuth.js: only resolveTenantByApiKey mocked.
//     middleware/authenticate.js (requireAuth) is NOT mocked — real
//     middleware runs, same convention as T2/T6/T7/T8.
//   - lib/planAccess.js is NOT mocked. It is pure logic with zero
//     dependencies (no db, no logger) — same treatment as webhook.js's pure
//     functions in T8. Using the real isAgency() gives genuine plan-hierarchy
//     coverage instead of a hand-rolled stub.
//   - lib/domainAuth.js is NOT mocked. stores.js needs the real
//     normalizeDomain() for its own parsing logic, and domainAuthMiddleware
//     itself is a direct unit under test in this same file. Since domainAuth.js
//     requires the same mocked './db' and './logger', its internal db calls
//     are fully controllable via db.store.* / db.tenant.* mocks below.
//
// SHARED MOCK TARGET WARNING:
//   db.store.findFirst is used for TWO different purposes across the two
//   units under test: stores.js's DELETE ownership check, and
//   domainAuthMiddleware's store-match lookup. jest.resetAllMocks() in
//   beforeEach plus per-test mockResolvedValueOnce/mockImplementation calls
//   mean there is no cross-contamination, but this is flagged here since it
//   is not obvious from either source file in isolation.
//
// QUIRKS / BEHAVIORAL NOTES DOCUMENTED INLINE AT POINT OF RELEVANCE:
//   1. CAP-CHECK ORDER QUIRK: in POST /, the "existing domain" lookup runs
//      BEFORE the active-store cap check, and the cap check applies
//      UNCONDITIONALLY — including when reactivating a previously
//      soft-deleted store. A tenant at 5/5 active stores who tries to
//      re-add a domain they'd previously removed is blocked by
//      STORE_LIMIT_REACHED just like a brand-new domain would be; the code
//      does not exempt reactivation from the cap.
//   2. TWO SEPARATE TENANT-ISOLATION MECHANISMS exist and are tested
//      independently:
//        (a) stores.js DELETE /:id — ownership check via
//            db.store.findFirst({ where: { id, tenantId } }). A store ID
//            that exists but belongs to a different tenant returns 404,
//            not 403 — it does not reveal the store's existence at all.
//        (b) domainAuthMiddleware — the Store lookup in the "store-aware
//            resolution" block is queried as
//            where: { tenantId: req.tenant.id, normalizedDomain, isActive }.
//            This is scoped to the REQUESTING tenant's own ID, so Tenant A's
//            request can never match Tenant B's Store row even when the
//            domain string is byte-for-byte identical.
//   3. COMPOUND-KEY INDEPENDENCE: the Prisma schema's
//      @@unique([tenantId, normalizedDomain]) on Store means two different
//      tenants can register the exact same domain independently, with no
//      collision — verified below by asserting the findUnique/findFirst
//      calls are always scoped by the caller's own tenantId.
//   4. A store found by domainAuthMiddleware's Store query with
//      isActive: false is indistinguishable, from the middleware's
//      perspective, from "no store at all for this domain" — the query
//      itself filters on isActive: true, so it simply won't match and the
//      request falls through to the tenantHasStores / DOMAIN_MISMATCH path.
// ══════════════════════════════════════════════════════════════════════════════

jest.mock('../../src/lib/db', () => ({
  store: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    count: jest.fn(),
    update: jest.fn(),
    create: jest.fn(),
    findFirst: jest.fn(),
  },
  tenant: {
    findUnique: jest.fn(),
  },
}));

jest.mock('../../src/lib/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

jest.mock('../../src/lib/apiKeyAuth', () => ({
  resolveTenantByApiKey: jest.fn(),
}));

const db = require('../../src/lib/db');
const logger = require('../../src/lib/logger');
const { resolveTenantByApiKey } = require('../../src/lib/apiKeyAuth');
const storesRouter = require('../../src/routes/stores');
const { domainAuthMiddleware, normalizeDomain, isDevDomain } = require('../../src/lib/domainAuth');

// ── Route-stack extraction + dispatch (T6/T7/T8 convention) ────────────────
function getRouteHandlers(method, path) {
  const layer = storesRouter.stack.find(
    (l) => l.route && l.route.path === path && l.route.methods[method.toLowerCase()]
  );
  if (!layer) throw new Error(`Route not found: ${method.toUpperCase()} ${path}`);
  return layer.route.stack.map((s) => s.handle);
}

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
  return `test-api-key-${apiKeyCounter}`;
}

function makeReq({ headers = {}, body = {}, params = {}, tenant, ip = '127.0.0.1', path = '/api/stores' } = {}) {
  const req = {
    headers: { 'x-api-key': uniqueApiKey(), ...headers },
    body,
    params,
    ip,
    path,
  };
  if (tenant) req.tenant = tenant;
  return req;
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
    plan: 'agency',
    ...overrides,
  };
}

function makeStore(overrides = {}) {
  return {
    id: 'store_1',
    tenantId: 'tenant_1',
    storeUrl: 'https://mystore.com',
    normalizedDomain: 'mystore.com',
    label: null,
    isActive: true,
    deactivatedAt: null,
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-01T00:00:00.000Z'),
    lastActivityAt: null,
    ...overrides,
  };
}

function mockAuthenticatedTenant(tenant) {
  resolveTenantByApiKey.mockResolvedValue({ tenant, usedPreviousKey: false });
}

let ORIGINAL_NODE_ENV;

beforeAll(() => {
  process.env.EMAIL_VERIFICATION_DISABLED = 'false';
});

beforeEach(() => {
  jest.resetAllMocks();
  ORIGINAL_NODE_ENV = process.env.NODE_ENV;
  delete process.env.INTERNAL_TOKEN;
});

afterEach(() => {
  process.env.NODE_ENV = ORIGINAL_NODE_ENV;
  jest.useRealTimers();
});

// ══════════════════════════════════════════════════════════════════════════════
describe('GET /api/stores', () => {
  const handlers = () => getRouteHandlers('get', '/');

  test('returns tenant-scoped stores, ordered by createdAt asc, with count and limit', async () => {
    const tenant = makeTenant();
    mockAuthenticatedTenant(tenant);
    const stores = [makeStore({ id: 's1' }), makeStore({ id: 's2', normalizedDomain: 'other.com' })];
    db.store.findMany.mockResolvedValue(stores);
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(db.store.findMany).toHaveBeenCalledWith({
      where: { tenantId: 'tenant_1', isActive: true },
      orderBy: { createdAt: 'asc' },
    });
    expect(res.json).toHaveBeenCalledWith({ success: true, stores, count: 2, limit: 5 });
  });

  test('empty store list → count 0', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.store.findMany.mockResolvedValue([]);
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.json).toHaveBeenCalledWith({ success: true, stores: [], count: 0, limit: 5 });
  });

  test('db.store.findMany throws → 500', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.store.findMany.mockRejectedValue(new Error('db down'));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
    expect(logger.error).toHaveBeenCalled();
  });

  // ── Shared auth-stack spot-check (representative for POST/DELETE too) ──
  test('missing API key → 401 (real requireAuth), route logic never reached', async () => {
    const req = makeReq({ headers: { 'x-api-key': undefined } });
    delete req.headers['x-api-key'];
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'API key is required' });
    expect(db.store.findMany).not.toHaveBeenCalled();
  });

  test('invalid/inactive API key → 401, delayed (real requireAuth)', async () => {
    jest.useFakeTimers();
    resolveTenantByApiKey.mockResolvedValue({ tenant: null, usedPreviousKey: false });
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);
    jest.advanceTimersByTime(200);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid or inactive API key' });
  });

  test('unverified tenant → 403 EMAIL_NOT_VERIFIED (real requireAuth)', async () => {
    mockAuthenticatedTenant(makeTenant({ emailVerified: false }));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'EMAIL_NOT_VERIFIED' }));
    expect(db.store.findMany).not.toHaveBeenCalled();
  });

  test('non-Agency plan → 403 AGENCY_REQUIRED (real isAgency), route logic never reached', async () => {
    mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
    const req = makeReq();
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Multi-store management is an Agency feature.',
      code: 'AGENCY_REQUIRED',
    });
    expect(db.store.findMany).not.toHaveBeenCalled();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('POST /api/stores', () => {
  const handlers = () => getRouteHandlers('post', '/');

  test('missing storeUrl → 400', async () => {
    mockAuthenticatedTenant(makeTenant());
    const req = makeReq({ body: {} });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'storeUrl is required' });
    expect(db.store.findUnique).not.toHaveBeenCalled();
  });

  test('unparseable storeUrl → 400 (bare "https://" has no host, new URL() throws)', async () => {
    mockAuthenticatedTenant(makeTenant());
    const req = makeReq({ body: { storeUrl: 'https://' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'storeUrl could not be parsed into a valid domain' });
    expect(db.store.findUnique).not.toHaveBeenCalled();
  });

  test('domain already registered as an active store → 409 STORE_EXISTS', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.store.findUnique.mockResolvedValue(makeStore({ isActive: true }));
    const req = makeReq({ body: { storeUrl: 'https://mystore.com' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(409);
    expect(res.json).toHaveBeenCalledWith({
      error: 'This domain is already registered as an active store',
      code: 'STORE_EXISTS',
    });
    expect(db.store.count).not.toHaveBeenCalled();
  });

  test('at cap (5 active stores) → 403 STORE_LIMIT_REACHED, create never called', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.store.findUnique.mockResolvedValue(null);
    db.store.count.mockResolvedValue(5);
    const req = makeReq({ body: { storeUrl: 'https://newstore.com' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Store limit reached. Agency plan supports up to 5 active stores.',
      code: 'STORE_LIMIT_REACHED',
    });
    expect(db.store.create).not.toHaveBeenCalled();
  });

  test('cap check counts only active stores — asserts where clause', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.store.findUnique.mockResolvedValue(null);
    db.store.count.mockResolvedValue(0);
    db.store.create.mockResolvedValue(makeStore());
    const req = makeReq({ body: { storeUrl: 'https://mystore.com' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(db.store.count).toHaveBeenCalledWith({ where: { tenantId: 'tenant_1', isActive: true } });
  });

  test('boundary: 4 active stores → 5th add succeeds (201)', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.store.findUnique.mockResolvedValue(null);
    db.store.count.mockResolvedValue(4);
    const newStore = makeStore({ id: 'store_5' });
    db.store.create.mockResolvedValue(newStore);
    const req = makeReq({ body: { storeUrl: 'https://mystore.com' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith({ success: true, store: newStore });
  });

  test('new domain, under cap, no label → creates with label: null', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.store.findUnique.mockResolvedValue(null);
    db.store.count.mockResolvedValue(0);
    const newStore = makeStore();
    db.store.create.mockResolvedValue(newStore);
    const req = makeReq({ body: { storeUrl: 'https://www.MyStore.com:8080/' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(db.store.create).toHaveBeenCalledWith({
      data: {
        tenantId: 'tenant_1',
        storeUrl: 'https://www.MyStore.com:8080/',
        normalizedDomain: 'mystore.com',
        label: null,
      },
    });
    expect(res.status).toHaveBeenCalledWith(201);
  });

  test('new domain with label → creates with provided label', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.store.findUnique.mockResolvedValue(null);
    db.store.count.mockResolvedValue(0);
    db.store.create.mockResolvedValue(makeStore({ label: 'Client A' }));
    const req = makeReq({ body: { storeUrl: 'https://clienta.com', label: 'Client A' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(db.store.create).toHaveBeenCalledWith({
      data: {
        tenantId: 'tenant_1',
        storeUrl: 'https://clienta.com',
        normalizedDomain: 'clienta.com',
        label: 'Client A',
      },
    });
  });

  test('reactivates a soft-deleted store, under cap, no label → falls back to existing.label', async () => {
    mockAuthenticatedTenant(makeTenant());
    const existing = makeStore({ id: 'store_old', isActive: false, label: 'Old Label' });
    db.store.findUnique.mockResolvedValue(existing);
    db.store.count.mockResolvedValue(0);
    const reactivated = makeStore({ id: 'store_old', isActive: true, label: 'Old Label' });
    db.store.update.mockResolvedValue(reactivated);
    const req = makeReq({ body: { storeUrl: 'https://mystore.com' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(db.store.update).toHaveBeenCalledWith({
      where: { id: 'store_old' },
      data: { isActive: true, deactivatedAt: null, storeUrl: 'https://mystore.com', label: 'Old Label' },
    });
    expect(db.store.create).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(201);
  });

  test('reactivates a soft-deleted store with a new label → overrides existing.label', async () => {
    mockAuthenticatedTenant(makeTenant());
    const existing = makeStore({ id: 'store_old', isActive: false, label: 'Old Label' });
    db.store.findUnique.mockResolvedValue(existing);
    db.store.count.mockResolvedValue(0);
    db.store.update.mockResolvedValue(makeStore({ id: 'store_old', label: 'New Label' }));
    const req = makeReq({ body: { storeUrl: 'https://mystore.com', label: 'New Label' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(db.store.update).toHaveBeenCalledWith({
      where: { id: 'store_old' },
      data: { isActive: true, deactivatedAt: null, storeUrl: 'https://mystore.com', label: 'New Label' },
    });
  });

  // Quirk #1: cap check runs unconditionally, even for reactivation of a
  // domain the tenant already owned. It is NOT exempt just because the
  // domain is "already known" to this tenant.
  test('QUIRK: reactivating a soft-deleted store is still blocked by the 5-store cap', async () => {
    mockAuthenticatedTenant(makeTenant());
    const existing = makeStore({ id: 'store_old', isActive: false });
    db.store.findUnique.mockResolvedValue(existing);
    db.store.count.mockResolvedValue(5);
    const req = makeReq({ body: { storeUrl: 'https://mystore.com' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'STORE_LIMIT_REACHED' }));
    expect(db.store.update).not.toHaveBeenCalled();
    expect(db.store.create).not.toHaveBeenCalled();
  });

  test('db.store.findUnique throws → 500', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.store.findUnique.mockRejectedValue(new Error('db down'));
    const req = makeReq({ body: { storeUrl: 'https://mystore.com' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(logger.error).toHaveBeenCalled();
  });

  // Quirk #3 / isolation: the compound unique key is [tenantId, normalizedDomain],
  // so two different tenants registering the identical domain string never
  // collide — each tenant's findUnique lookup is scoped to their own tenantId.
  test('isolation: two different tenants can independently register the identical domain', async () => {
    db.store.findUnique.mockResolvedValue(null);
    db.store.count.mockResolvedValue(0);

    mockAuthenticatedTenant(makeTenant({ id: 'tenant_A' }));
    db.store.create.mockResolvedValueOnce(makeStore({ tenantId: 'tenant_A' }));
    const reqA = makeReq({ body: { storeUrl: 'https://shared-domain.com' } });
    const resA = makeRes();
    await dispatch(handlers(), reqA, resA);

    expect(db.store.findUnique).toHaveBeenCalledWith({
      where: { tenantId_normalizedDomain: { tenantId: 'tenant_A', normalizedDomain: 'shared-domain.com' } },
    });
    expect(resA.status).toHaveBeenCalledWith(201);

    mockAuthenticatedTenant(makeTenant({ id: 'tenant_B' }));
    db.store.create.mockResolvedValueOnce(makeStore({ tenantId: 'tenant_B' }));
    const reqB = makeReq({ body: { storeUrl: 'https://shared-domain.com' } });
    const resB = makeRes();
    await dispatch(handlers(), reqB, resB);

    expect(db.store.findUnique).toHaveBeenCalledWith({
      where: { tenantId_normalizedDomain: { tenantId: 'tenant_B', normalizedDomain: 'shared-domain.com' } },
    });
    expect(resB.status).toHaveBeenCalledWith(201);
  });

  test('non-Agency plan → 403 AGENCY_REQUIRED, no db calls', async () => {
    mockAuthenticatedTenant(makeTenant({ plan: 'starter' }));
    const req = makeReq({ body: { storeUrl: 'https://mystore.com' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'AGENCY_REQUIRED' }));
    expect(db.store.findUnique).not.toHaveBeenCalled();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('DELETE /api/stores/:id', () => {
  const handlers = () => getRouteHandlers('delete', '/:id');

  test('store not found → 404', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.store.findFirst.mockResolvedValue(null);
    const req = makeReq({ params: { id: 'store_nonexistent' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(db.store.findFirst).toHaveBeenCalledWith({ where: { id: 'store_nonexistent', tenantId: 'tenant_1' } });
    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json).toHaveBeenCalledWith({ error: 'Store not found or not owned by this tenant' });
    expect(db.store.update).not.toHaveBeenCalled();
  });

  // Isolation mechanism (a): the findFirst query is scoped to id + the
  // requesting tenant's own id. A store that exists but is owned by a
  // different tenant returns 404 — identical to "doesn't exist" — never
  // 403, so a guessed ID can't even confirm the store's existence.
  test('isolation: store exists but is owned by a different tenant → 404, not 403', async () => {
    mockAuthenticatedTenant(makeTenant({ id: 'tenant_B' }));
    // Simulates the real DB: a tenantId-scoped query can never return
    // Tenant A's row when queried as Tenant B.
    db.store.findFirst.mockResolvedValue(null);
    const req = makeReq({ tenant: undefined, params: { id: 'store_owned_by_tenant_A' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(db.store.findFirst).toHaveBeenCalledWith({
      where: { id: 'store_owned_by_tenant_A', tenantId: 'tenant_B' },
    });
    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.status).not.toHaveBeenCalledWith(403);
  });

  test('success → soft-deletes (isActive: false, deactivatedAt set), does not hard-delete', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.store.findFirst.mockResolvedValue(makeStore({ id: 'store_1' }));
    db.store.update.mockResolvedValue(makeStore({ id: 'store_1', isActive: false }));
    const req = makeReq({ params: { id: 'store_1' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(db.store.update).toHaveBeenCalledWith({
      where: { id: 'store_1' },
      data: { isActive: false, deactivatedAt: expect.any(Date) },
    });
    expect(res.json).toHaveBeenCalledWith({ success: true, message: 'Store removed' });
  });

  test('db.store.findFirst throws → 500', async () => {
    mockAuthenticatedTenant(makeTenant());
    db.store.findFirst.mockRejectedValue(new Error('db down'));
    const req = makeReq({ params: { id: 'store_1' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(logger.error).toHaveBeenCalled();
  });

  test('non-Agency plan → 403 AGENCY_REQUIRED, ownership check never runs', async () => {
    mockAuthenticatedTenant(makeTenant({ plan: 'pro' }));
    const req = makeReq({ params: { id: 'store_1' } });
    const res = makeRes();

    await dispatch(handlers(), req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(db.store.findFirst).not.toHaveBeenCalled();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('domainAuthMiddleware', () => {
  describe('internal token bypass', () => {
    test('valid internal token → next(), no domain/db checks at all', async () => {
      process.env.INTERNAL_TOKEN = 'secret-internal-token';
      const req = makeReq({ headers: { 'x-internal-token': 'secret-internal-token' } });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(db.store.findFirst).not.toHaveBeenCalled();
    });

    test('internal token present but wrong → 403 INVALID_INTERNAL_TOKEN', async () => {
      process.env.INTERNAL_TOKEN = 'secret-internal-token';
      const req = makeReq({ headers: { 'x-internal-token': 'wrong-token' } });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ error: 'Invalid internal token', code: 'INVALID_INTERNAL_TOKEN' });
    });
  });

  describe('domain header validation', () => {
    test('missing X-Store-Domain header → 400 MISSING_DOMAIN', async () => {
      const req = makeReq({ tenant: makeTenant() });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'MISSING_DOMAIN' }));
    });

    test('unparseable X-Store-Domain header → 400 MISSING_DOMAIN', async () => {
      const req = makeReq({ tenant: makeTenant(), headers: { 'x-store-domain': 'https://' } });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'MISSING_DOMAIN' }));
    });
  });

  describe('dev domain bypass (production-gated)', () => {
    test('non-production + dev domain → bypass, next(), db never called', async () => {
      process.env.NODE_ENV = 'test';
      const req = makeReq({ headers: { 'x-store-domain': 'localhost' } }); // no req.tenant at all
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(req.storeDomain).toBe('localhost');
      expect(db.store.findFirst).not.toHaveBeenCalled();
    });

    test('production + dev-looking domain → bypass NOT applied, falls through to tenant check', async () => {
      process.env.NODE_ENV = 'production';
      const req = makeReq({ headers: { 'x-store-domain': 'localhost' } }); // req.tenant missing on purpose
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'MISSING_TENANT_CONTEXT' }));
    });
  });

  describe('tenant context requirement', () => {
    test('req.tenant missing (non-dev domain) → 500 MISSING_TENANT_CONTEXT', async () => {
      const req = makeReq({ headers: { 'x-store-domain': 'mystore.com' } });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'MISSING_TENANT_CONTEXT' }));
    });
  });

  describe('store-aware resolution (Agency multi-store)', () => {
    test('matching active Store found → next(), req.storeId + req.storeDomain set', async () => {
      db.store.findFirst.mockResolvedValue({ id: 'store_1' });
      const req = makeReq({ tenant: { id: 'tenant_1' }, headers: { 'x-store-domain': 'mystore.com' } });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(db.store.findFirst).toHaveBeenCalledWith({
        where: { tenantId: 'tenant_1', normalizedDomain: 'mystore.com', isActive: true },
        select: { id: true },
      });
      expect(req.storeId).toBe('store_1');
      expect(req.storeDomain).toBe('mystore.com');
      expect(next).toHaveBeenCalledTimes(1);
    });

    // Note #4: a store row with isActive:false never satisfies the
    // isActive:true filter in the query itself, so it is indistinguishable
    // here from "no store matches this domain at all" — both fall through
    // to the same DOMAIN_MISMATCH path below.
    test('store-managed tenant, domain matches none of their active stores → 403 DOMAIN_MISMATCH, legacy path skipped', async () => {
      db.store.findFirst.mockResolvedValue(null);
      db.store.count.mockResolvedValue(2); // tenant has OTHER active stores
      const req = makeReq({ tenant: { id: 'tenant_1' }, headers: { 'x-store-domain': 'unregistered-domain.com' } });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'DOMAIN_MISMATCH' }));
      expect(db.tenant.findUnique).not.toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    // Isolation mechanism (b): the Store lookup is scoped to the requesting
    // tenant's OWN id. Tenant B's request against a domain that is actually
    // registered to Tenant A can never match Tenant A's row.
    test('isolation: domain lookup always scoped to the requesting tenant — Tenant B can never match Tenant A\'s Store row', async () => {
      const tenantAStore = { id: 'store_A', tenantId: 'tenant_A' };
      db.store.findFirst.mockImplementation(({ where }) =>
        Promise.resolve(where.tenantId === 'tenant_A' ? tenantAStore : null)
      );
      db.store.count.mockResolvedValue(0);
      db.tenant.findUnique.mockResolvedValue({ allowedDomains: [] });

      const req = makeReq({
        tenant: { id: 'tenant_B' },
        headers: { 'x-store-domain': 'shared-looking-domain.com' },
      });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(db.store.findFirst).toHaveBeenCalledWith({
        where: { tenantId: 'tenant_B', normalizedDomain: 'shared-looking-domain.com', isActive: true },
        select: { id: true },
      });
      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });
  });

  describe('legacy allowedDomains path (Starter/Pro — zero Store rows)', () => {
    test('zero stores + empty allowedDomains → 403 NO_ALLOWED_DOMAINS (default-deny)', async () => {
      db.store.findFirst.mockResolvedValue(null);
      db.store.count.mockResolvedValue(0);
      db.tenant.findUnique.mockResolvedValue({ allowedDomains: [] });
      const req = makeReq({ tenant: { id: 'tenant_1' }, headers: { 'x-store-domain': 'mystore.com' } });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'NO_ALLOWED_DOMAINS' }));
      expect(next).not.toHaveBeenCalled();
    });

    test('zero stores + domain in allowedDomains → next()', async () => {
      db.store.findFirst.mockResolvedValue(null);
      db.store.count.mockResolvedValue(0);
      db.tenant.findUnique.mockResolvedValue({ allowedDomains: ['mystore.com', 'other.com'] });
      const req = makeReq({ tenant: { id: 'tenant_1' }, headers: { 'x-store-domain': 'mystore.com' } });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(req.storeDomain).toBe('mystore.com');
    });

    test('zero stores + domain not in allowedDomains → 403 DOMAIN_MISMATCH', async () => {
      db.store.findFirst.mockResolvedValue(null);
      db.store.count.mockResolvedValue(0);
      db.tenant.findUnique.mockResolvedValue({ allowedDomains: ['other.com'] });
      const req = makeReq({ tenant: { id: 'tenant_1' }, headers: { 'x-store-domain': 'mystore.com' } });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'DOMAIN_MISMATCH' }));
    });

    test('tenantRecord null → allowedDomains defaults to [] → 403 NO_ALLOWED_DOMAINS', async () => {
      db.store.findFirst.mockResolvedValue(null);
      db.store.count.mockResolvedValue(0);
      db.tenant.findUnique.mockResolvedValue(null);
      const req = makeReq({ tenant: { id: 'tenant_1' }, headers: { 'x-store-domain': 'mystore.com' } });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'NO_ALLOWED_DOMAINS' }));
    });
  });

  describe('fail-closed on unexpected errors', () => {
    test('db.store.findFirst throws → 503 DOMAIN_CHECK_UNAVAILABLE', async () => {
      db.store.findFirst.mockRejectedValue(new Error('connection reset'));
      const req = makeReq({ tenant: { id: 'tenant_1' }, headers: { 'x-store-domain': 'mystore.com' } });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(503);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'DOMAIN_CHECK_UNAVAILABLE' }));
      expect(next).not.toHaveBeenCalled();
      expect(logger.error).toHaveBeenCalled();
    });

    test('db.tenant.findUnique throws (legacy path) → 503 DOMAIN_CHECK_UNAVAILABLE', async () => {
      db.store.findFirst.mockResolvedValue(null);
      db.store.count.mockResolvedValue(0);
      db.tenant.findUnique.mockRejectedValue(new Error('connection reset'));
      const req = makeReq({ tenant: { id: 'tenant_1' }, headers: { 'x-store-domain': 'mystore.com' } });
      const res = makeRes();
      const next = jest.fn();

      await domainAuthMiddleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(503);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'DOMAIN_CHECK_UNAVAILABLE' }));
    });
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('normalizeDomain (pure helper, load-bearing for isolation)', () => {
  test('strips protocol, www, port, and lowercases', () => {
    expect(normalizeDomain('https://www.MyStore.com:8080/')).toBe('mystore.com');
  });

  test('adds https:// automatically when protocol is missing', () => {
    expect(normalizeDomain('MyStore.com')).toBe('mystore.com');
  });

  test('missing/empty input → null', () => {
    expect(normalizeDomain(undefined)).toBeNull();
    expect(normalizeDomain('')).toBeNull();
    expect(normalizeDomain('   ')).toBeNull();
  });

  test('non-string input → null', () => {
    expect(normalizeDomain(12345)).toBeNull();
  });

  test('unparseable input → null', () => {
    expect(normalizeDomain('https://')).toBeNull();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('isDevDomain (pure helper, gates the domainAuth bypass)', () => {
  test.each([
    ['localhost', 'localhost'],
    ['127.0.0.1', '127.0.0.1'],
    ['::1', '::1'],
    ['0.0.0.0', '0.0.0.0'],
    ['.local suffix', 'myapp.local'],
    ['.test suffix', 'myapp.test'],
    ['.dev suffix', 'myapp.dev'],
    ['.localhost suffix', 'foo.localhost'],
    ['10.x private', '10.0.0.5'],
    ['172.16.x private (lower bound)', '172.16.0.1'],
    ['172.31.x private (upper bound)', '172.31.255.254'],
    ['192.168.x private', '192.168.1.1'],
  ])('%s → true', (_label, domain) => {
    expect(isDevDomain(domain)).toBe(true);
  });

  test('public domain → false', () => {
    expect(isDevDomain('mystore.com')).toBe(false);
  });

  test('172.15.x (just below private range) → false — regex boundary is exact', () => {
    expect(isDevDomain('172.15.255.255')).toBe(false);
  });

  test('172.32.x (just above private range) → false — regex boundary is exact', () => {
    expect(isDevDomain('172.32.0.1')).toBe(false);
  });

  test('empty/falsy input → false', () => {
    expect(isDevDomain('')).toBe(false);
    expect(isDevDomain(null)).toBe(false);
  });
});