const request = require('supertest');
const crypto = require('crypto');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');

// Black-box calculateRiskScore entirely — T3a tests risk.js's own
// orchestration (quota, idempotency, whitelist/blacklist, BlockedAttempt
// transaction), not the scoring math itself (that's T3d).
jest.mock('../../src/lib/riskScoring');
const { calculateRiskScore } = require('../../src/lib/riskScoring');

// buildGraphFromOrder is fire-and-forget (wrapped in try/catch, result
// unused) but touches identityGraph internals we don't have visibility
// into — mocked to keep this suite hermetic and fast rather than
// accidentally depending on unreviewed code.
jest.mock('../../src/lib/identityGraph');

const prisma = new PrismaClient();
const db = require('../../src/lib/db'); // same singleton risk.js uses — needed to spy on $transaction

function defaultScoreResult(overrides = {}) {
  return {
    score: 85,
    decision: 'Low Risk — Approve',
    decisionColor: '#007A5C',
    decisionBg: '#F1F8F5',
    flags: [],
    positives: [],
    isLearning: false,
    scoringVersion: 'mock-v1',
    economicData: null,
    computedSignals: {},
    graphRisk: 0,
    ipIntel: null,
    emailIntel: null,
    binIntel: null,
    ...overrides,
  };
}

function uniqueIp(label) {
  return `10.99.${Math.floor(Math.random() * 255)}.${label}-${Date.now()}`;
}

function uniqueOrderId(label) {
  return `order-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

async function seedTenant(overrides = {}) {
  const label = overrides.label || 'x';
  const testEmail = `eval-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
  const plaintextKey = crypto.randomBytes(32).toString('base64');
  const domain = `example-eval-${label}-${Date.now()}.com`;

  const tenant = await prisma.tenant.create({
    data: {
      email: testEmail,
      storeUrl: `https://${domain}`,
      allowedDomains: [domain],
      webhookSecret: crypto.randomBytes(32).toString('hex'),
      apiKeyHash: hashApiKey(plaintextKey),
      apiKey: null,
      isActive: true,
      emailVerified: true,
      plan: overrides.plan ?? 'starter',
      monthlyBlockedCount: overrides.monthlyBlockedCount ?? 0,
      quotaResetDate: overrides.quotaResetDate ?? null,
      countryOverrides: overrides.countryOverrides ?? {},
    },
  });

  if (!tenant?.id) {
    throw new Error(`seedTenant('${label}') failed to create a tenant row — cannot proceed.`);
  }

  return { tenant, domain, plaintextKey };
}

function signBody(secret, bodyString) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signedStr = `${timestamp}.${bodyString}`;
  const signature = 'v1=' + crypto.createHmac('sha256', secret).update(signedStr).digest('hex');
  return { timestamp, signature };
}

function evaluateRequest(tenant, domain, bodyObj, headerOverrides = {}) {
  const bodyString = JSON.stringify(bodyObj);
  const { timestamp, signature } = signBody(tenant.webhookSecret, bodyString);

  const req = request(app)
    .post('/api/risk/evaluate')
    .set('Content-Type', 'application/json');

  if (headerOverrides.apiKey !== null) req.set('X-Api-Key', headerOverrides.apiKey ?? tenant._plaintextKeyForAuth);
  if (headerOverrides.domain !== null) req.set('X-Store-Domain', headerOverrides.domain ?? domain);
  if (headerOverrides.signature !== null) req.set('X-ChargeGuard-Signature', headerOverrides.signature ?? signature);
  if (headerOverrides.timestamp !== null) req.set('X-ChargeGuard-Timestamp', headerOverrides.timestamp ?? timestamp);

  return req.send(headerOverrides.bodyString ?? bodyString);
}

describe('/evaluate — access control & orchestration (T3a)', () => {
  const createdTenantIds = [];

  afterAll(async () => {
    if (createdTenantIds.length) {
      await prisma.cardTestAttempt.deleteMany({ where: { merchantId: { in: createdTenantIds } } });
      await prisma.order.deleteMany({ where: { merchantId: { in: createdTenantIds } } });
      await prisma.blockedAttempt.deleteMany({ where: { tenantId: { in: createdTenantIds } } });
      await prisma.tenant.deleteMany({ where: { id: { in: createdTenantIds } } });
    }
    await prisma.$disconnect();
  });

  beforeEach(() => {
    jest.clearAllMocks();
    calculateRiskScore.mockResolvedValue(defaultScoreResult());
  });

  // ── 1. Access control ordering ─────────────────────────────────────────
  describe('auth/domain/HMAC gate ordering', () => {
    let tenant, domain, plaintextKey;

    beforeAll(async () => {
      const seeded = await seedTenant({ label: 'authorder' });
      tenant = seeded.tenant;
      tenant._plaintextKeyForAuth = seeded.plaintextKey;
      domain = seeded.domain;
      createdTenantIds.push(tenant.id);
    });

    test('missing API key is rejected (401) before any other check', async () => {
      const res = await evaluateRequest(tenant, domain, { orderId: uniqueOrderId('noauth') }, { apiKey: '' });
      // requireAuth rejects before domain/HMAC middleware ever runs.
      expect(res.status).toBe(401);
    });

    test('wrong domain is rejected (403 DOMAIN_MISMATCH) even when HMAC would otherwise be valid', async () => {
      const bodyObj = { orderId: uniqueOrderId('wrongdomain') };
      const bodyString = JSON.stringify(bodyObj);
      const { timestamp, signature } = signBody(tenant.webhookSecret, bodyString);

      const res = await request(app)
        .post('/api/risk/evaluate')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', tenant._plaintextKeyForAuth)
        .set('X-Store-Domain', 'not-this-tenants-domain.com')
        .set('X-ChargeGuard-Signature', signature)
        .set('X-ChargeGuard-Timestamp', timestamp)
        .send(bodyString);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOMAIN_MISMATCH');
    });

    test('domain check runs before HMAC check: wrong domain + missing HMAC headers still yields 403, not 401', async () => {
      const res = await request(app)
        .post('/api/risk/evaluate')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', tenant._plaintextKeyForAuth)
        .set('X-Store-Domain', 'still-not-this-tenants-domain.com')
        .send(JSON.stringify({ orderId: uniqueOrderId('ordering') }));

      // If this ever flips to 401, the middleware order in risk.js's route
      // definition has changed — worth knowing immediately, since T2's
      // domain-before-HMAC assumption for /blacklist would no longer
      // generalize to every route.
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOMAIN_MISMATCH');
    });

    test('correct domain but missing HMAC headers is rejected (401)', async () => {
      const res = await request(app)
        .post('/api/risk/evaluate')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', tenant._plaintextKeyForAuth)
        .set('X-Store-Domain', domain)
        .send(JSON.stringify({ orderId: uniqueOrderId('nohmac') }));

      expect(res.status).toBe(401);
      expect(calculateRiskScore).not.toHaveBeenCalled();
    });
  });

  // ── 2. Idempotency caching ──────────────────────────────────────────────
  describe('idempotency caching', () => {
    let tenant, domain;

    beforeAll(async () => {
      const seeded = await seedTenant({ label: 'idempotent' });
      tenant = seeded.tenant;
      tenant._plaintextKeyForAuth = seeded.plaintextKey;
      domain = seeded.domain;
      createdTenantIds.push(tenant.id);
    });

    test('a duplicate orderId within the 5-minute window returns the cached decision without re-scoring', async () => {
      const orderId = uniqueOrderId('cached');
      await prisma.order.create({
        data: {
          orderId,
          merchantId: tenant.id,
          amount: 42,
          currency: 'USD',
          decision: 'review',
          riskScore: 55,
          signalsSnapshot: JSON.stringify({ flags: [{ severity: 'medium', text: 'cached flag' }] }),
          createdAt: new Date(), // fresh — inside the 5-minute window
        },
      });

      const res = await evaluateRequest(tenant, domain, {
        orderId,
        ipAddress: uniqueIp('cached'),
        amount: 999, // deliberately different from the cached row — must be ignored
      });

      expect(res.status).toBe(200);
      expect(res.body.cached).toBe(true);
      expect(res.body.score).toBe(55);
      expect(res.body.decision).toBe('review');
      expect(res.body.flags).toEqual([{ severity: 'medium', text: 'cached flag' }]);
      expect(calculateRiskScore).not.toHaveBeenCalled();
    });

    test('an orderId outside the 5-minute window is re-scored, not served from cache', async () => {
      const orderId = uniqueOrderId('stale-cache');
      await prisma.order.create({
        data: {
          orderId,
          merchantId: tenant.id,
          amount: 42,
          currency: 'USD',
          decision: 'approve',
          riskScore: 90,
          signalsSnapshot: JSON.stringify({ flags: [] }),
          createdAt: new Date(Date.now() - 6 * 60 * 1000), // 6 minutes ago — outside the window
        },
      });

      const res = await evaluateRequest(tenant, domain, {
        orderId,
        ipAddress: uniqueIp('stale-cache'),
      });

      expect(res.status).toBe(200);
      expect(res.body.cached).toBeUndefined();
      expect(calculateRiskScore).toHaveBeenCalledTimes(1);
    });
  });

  // ── 3. Whitelist bypass ──────────────────────────────────────────────────
  describe('whitelist bypass', () => {
    let tenant, domain;

    beforeAll(async () => {
      const seeded = await seedTenant({ label: 'whitelist' });
      tenant = seeded.tenant;
      tenant._plaintextKeyForAuth = seeded.plaintextKey;
      domain = seeded.domain;
      createdTenantIds.push(tenant.id);
    });

    test('a whitelisted email short-circuits before scoring, velocity, or BIN checks', async () => {
      const testEmail = `whitelisted-${Date.now()}@example.com`;
      await prisma.whitelistEntry.create({
        data: { merchantId: tenant.id, type: 'EMAIL', value: testEmail },
      });

      const res = await evaluateRequest(tenant, domain, {
        orderId: uniqueOrderId('whitelisted'),
        email: testEmail,
        ipAddress: uniqueIp('whitelisted'),
      });

      expect(res.status).toBe(200);
      expect(res.body.whitelisted).toBe(true);
      expect(res.body.decision).toBe('approve');
      expect(res.body.score).toBe(0);
      expect(calculateRiskScore).not.toHaveBeenCalled();
    });
  });

  // ── 4. Blacklist rejection ───────────────────────────────────────────────
  describe('blacklist rejection', () => {
    let tenant, domain;

    beforeAll(async () => {
      const seeded = await seedTenant({ label: 'blacklist' });
      tenant = seeded.tenant;
      tenant._plaintextKeyForAuth = seeded.plaintextKey;
      domain = seeded.domain;
      createdTenantIds.push(tenant.id);
    });

    test('a blacklisted IP is rejected with 403 before scoring is ever attempted', async () => {
      const blockedIp = uniqueIp('blacklisted');
      await prisma.blacklistEntry.create({
        data: { merchantId: tenant.id, type: 'IP', value: blockedIp },
      });

      const res = await evaluateRequest(tenant, domain, {
        orderId: uniqueOrderId('blacklisted'),
        ipAddress: blockedIp,
      });

      expect(res.status).toBe(403);
      expect(res.body.decision).toBe('block');
      expect(calculateRiskScore).not.toHaveBeenCalled();

      const orderRow = await prisma.order.findFirst({ where: { merchantId: tenant.id, ipAddress: blockedIp } });
      expect(orderRow).toBeNull(); // rejected before any Order write
    });
  });

  // ── 5. Quota gate (race-safe reset) ──────────────────────────────────────
  describe('quota gate', () => {
    test('starter plan under quota (499/500) succeeds', async () => {
      const seeded = await seedTenant({
        label: 'quota-under',
        plan: 'starter',
        monthlyBlockedCount: 499,
        quotaResetDate: new Date(Date.now() + 24 * 60 * 60 * 1000), // already reset this cycle
      });
      createdTenantIds.push(seeded.tenant.id);

      const res = await evaluateRequest(
        { ...seeded.tenant, _plaintextKeyForAuth: seeded.plaintextKey },
        seeded.domain,
        {
        orderId: uniqueOrderId('quota-under'),
        ipAddress: uniqueIp('quota-under'),
      });

      expect(res.status).toBe(200);
    });

    test('starter plan at quota (500/500) is blocked with quota_exceeded', async () => {
      const seeded = await seedTenant({
        label: 'quota-at',
        plan: 'starter',
        monthlyBlockedCount: 500,
        quotaResetDate: new Date(Date.now() + 24 * 60 * 60 * 1000),
      });
      createdTenantIds.push(seeded.tenant.id);

      const res = await evaluateRequest(
        { ...seeded.tenant, _plaintextKeyForAuth: seeded.plaintextKey },
        seeded.domain,
        { orderId: uniqueOrderId('quota-at'), ipAddress: uniqueIp('quota-at') }
      );

      expect(res.status).toBe(403);
      expect(res.body.blocked_reason).toBe('quota_exceeded');
      expect(calculateRiskScore).not.toHaveBeenCalled();
    });

    test('pro plan at its 5000 quota returns pro_quota_exceeded (distinct message from starter)', async () => {
      const seeded = await seedTenant({
        label: 'quota-pro',
        plan: 'pro',
        monthlyBlockedCount: 5000,
        quotaResetDate: new Date(Date.now() + 24 * 60 * 60 * 1000),
      });
      createdTenantIds.push(seeded.tenant.id);

      const res = await evaluateRequest(
        { ...seeded.tenant, _plaintextKeyForAuth: seeded.plaintextKey },
        seeded.domain,
        { orderId: uniqueOrderId('quota-pro'), ipAddress: uniqueIp('quota-pro') }
      );

      expect(res.status).toBe(403);
      expect(res.body.blocked_reason).toBe('pro_quota_exceeded');
    });

    test('agency plan is exempt from quota enforcement regardless of monthlyBlockedCount', async () => {
      const seeded = await seedTenant({
        label: 'quota-agency',
        plan: 'agency',
        monthlyBlockedCount: 999999,
        quotaResetDate: new Date(Date.now() + 24 * 60 * 60 * 1000),
      });
      createdTenantIds.push(seeded.tenant.id);

      const res = await evaluateRequest(
        { ...seeded.tenant, _plaintextKeyForAuth: seeded.plaintextKey },
        seeded.domain,
        { orderId: uniqueOrderId('quota-agency'), ipAddress: uniqueIp('quota-agency') }
      );

      expect(res.status).toBe(200);
    });

    test('a null quotaResetDate triggers an automatic reset to 0 and allows the request through', async () => {
      const seeded = await seedTenant({
        label: 'quota-null-reset',
        plan: 'starter',
        monthlyBlockedCount: 500, // would exceed the limit if NOT reset
        quotaResetDate: null,
      });
      createdTenantIds.push(seeded.tenant.id);

      const res = await evaluateRequest(
        { ...seeded.tenant, _plaintextKeyForAuth: seeded.plaintextKey },
        seeded.domain,
        { orderId: uniqueOrderId('quota-null-reset'), ipAddress: uniqueIp('quota-null-reset') }
      );

      expect(res.status).toBe(200);

      const updated = await prisma.tenant.findUnique({ where: { id: seeded.tenant.id } });
      expect(updated.monthlyBlockedCount).toBe(0);
      expect(updated.quotaResetDate).not.toBeNull();
    });

    test('a stale (past) quotaResetDate triggers reset to 0 and sets quotaResetDate to the start of next UTC month', async () => {
      const seeded = await seedTenant({
        label: 'quota-stale-reset',
        plan: 'starter',
        monthlyBlockedCount: 500,
        quotaResetDate: new Date(Date.now() - 24 * 60 * 60 * 1000), // yesterday — stale
      });
      createdTenantIds.push(seeded.tenant.id);

      const res = await evaluateRequest(
        { ...seeded.tenant, _plaintextKeyForAuth: seeded.plaintextKey },
        seeded.domain,
        { orderId: uniqueOrderId('quota-stale-reset'), ipAddress: uniqueIp('quota-stale-reset') }
      );

      expect(res.status).toBe(200);

      const now = new Date();
      const expectedReset = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1, 0, 0, 0, 0));
      const updated = await prisma.tenant.findUnique({ where: { id: seeded.tenant.id } });
      expect(updated.monthlyBlockedCount).toBe(0);
      expect(new Date(updated.quotaResetDate).getTime()).toBe(expectedReset.getTime());
    });

    test('two concurrent requests racing a stale quotaResetDate reset to a single, consistent state (T1-verification-race-shaped test — confirming the existing fix holds, not hunting a new bug)', async () => {
      const seeded = await seedTenant({
        label: 'quota-race',
        plan: 'starter',
        monthlyBlockedCount: 10,
        quotaResetDate: new Date(Date.now() - 24 * 60 * 60 * 1000), // stale — both requests will attempt a reset
      });
      createdTenantIds.push(seeded.tenant.id);
      const tenantWithKey = { ...seeded.tenant, _plaintextKeyForAuth: seeded.plaintextKey };

      const [resA, resB] = await Promise.all([
        evaluateRequest(tenantWithKey, seeded.domain, {
          orderId: uniqueOrderId('quota-race-a'),
          ipAddress: uniqueIp('quota-race-a'),
        }),
        evaluateRequest(tenantWithKey, seeded.domain, {
          orderId: uniqueOrderId('quota-race-b'),
          ipAddress: uniqueIp('quota-race-b'),
        }),
      ]);

      expect(resA.status).toBe(200);
      expect(resB.status).toBe(200);

      const now = new Date();
      const expectedReset = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1, 0, 0, 0, 0));
      const final = await prisma.tenant.findUnique({ where: { id: seeded.tenant.id } });

      // Exactly one canonical reset should have occurred — not a double
      // reset, not two conflicting quotaResetDate writes.
      expect(final.monthlyBlockedCount).toBe(0);
      expect(new Date(final.quotaResetDate).getTime()).toBe(expectedReset.getTime());
    });
  });

  // ── 6. BlockedAttempt transactional write ────────────────────────────────
  describe('BlockedAttempt + monthlyBlockedCount transactional write', () => {
    test('a block decision creates a BlockedAttempt row and increments monthlyBlockedCount atomically', async () => {
      const seeded = await seedTenant({
        label: 'blocked-txn-ok',
        plan: 'starter',
        monthlyBlockedCount: 0,
        quotaResetDate: new Date(Date.now() + 24 * 60 * 60 * 1000),
      });
      createdTenantIds.push(seeded.tenant.id);
      calculateRiskScore.mockResolvedValue(defaultScoreResult({
        score: 10,
        decision: 'High Risk — Block',
        flags: [{ severity: 'critical', text: 'mock block reason' }],
      }));

      const ip = uniqueIp('blocked-txn-ok');
      const res = await evaluateRequest(
        { ...seeded.tenant, _plaintextKeyForAuth: seeded.plaintextKey },
        seeded.domain,
        { orderId: uniqueOrderId('blocked-txn-ok'), ipAddress: ip, amount: 77 }
      );

      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('block');

      const attempt = await prisma.blockedAttempt.findFirst({ where: { tenantId: seeded.tenant.id } });
      expect(attempt).not.toBeNull();
      expect(attempt.reason).toBe('pattern');
      expect(attempt.riskScore).toBe(10);

      const updated = await prisma.tenant.findUnique({ where: { id: seeded.tenant.id } });
      expect(updated.monthlyBlockedCount).toBe(1);
    });

    test('if the BlockedAttempt/counter transaction itself fails, the block decision still returns successfully (documented resilience behavior, not silently swallowed)', async () => {
      const seeded = await seedTenant({
        label: 'blocked-txn-fail',
        plan: 'starter',
        monthlyBlockedCount: 0,
        quotaResetDate: new Date(Date.now() + 24 * 60 * 60 * 1000),
      });
      createdTenantIds.push(seeded.tenant.id);
      calculateRiskScore.mockResolvedValue(defaultScoreResult({
        score: 5,
        decision: 'High Risk — Block',
        flags: [{ severity: 'critical', text: 'mock block reason' }],
      }));

      const txnSpy = jest.spyOn(db, '$transaction').mockRejectedValueOnce(new Error('simulated transaction failure'));

      try {
        const res = await evaluateRequest(
          { ...seeded.tenant, _plaintextKeyForAuth: seeded.plaintextKey },
          seeded.domain,
          { orderId: uniqueOrderId('blocked-txn-fail'), ipAddress: uniqueIp('blocked-txn-fail'), amount: 33 }
        );

        // The merchant still gets a correct, immediate block decision — the
        // counter-write failure is logged, not surfaced as a 500. This is a
        // deliberate design tradeoff (documented in risk.js's own comments)
        // and this test locks it in as intentional behavior.
        expect(res.status).toBe(200);
        expect(res.body.decision).toBe('block');

        const attempt = await prisma.blockedAttempt.findFirst({ where: { tenantId: seeded.tenant.id } });
        expect(attempt).toBeNull(); // the failed transaction means nothing was persisted

        const updated = await prisma.tenant.findUnique({ where: { id: seeded.tenant.id } });
        expect(updated.monthlyBlockedCount).toBe(0); // count never incremented
      } finally {
        txnSpy.mockRestore();
      }
    });
  });
});