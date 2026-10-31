// tests/jobs/replay-enrichment.test.js
//
// Guards REPLAY-JOB-NOT-WIRED (R1): verifies replayOnce() correctly processes
// pending rows, expires stale ones, skips paypal_ placeholders, and releases
// unlinked rows for the next sweep -- all against a REAL local database.
// The mock-based enrichment-processor.test.js cannot cover claim/expire/skip.
// Mutation: removing the explicit deleteMany (replayPendingEnrichments.js:126)
// causes T1 to fail because processEnrichment's internal deleteMany filters on
// status:'pending' but the row is already 'processing' at that point.

jest.mock('../../src/lib/riskScoring', () => ({
  calculateRiskScore: jest.fn(),
}));
jest.mock('../../src/lib/binSequenceDetector', () => ({
  checkBINSequence: jest.fn(),
  checkCardFingerprintVelocity: jest.fn(),
  recordBINAttempt: jest.fn(),
  recordEntityPrefixAttempt: jest.fn(),
  recordCardFingerprintAttempt: jest.fn(),
  getBINStats: jest.fn(),
  THRESHOLDS: {},
}));
jest.mock('../../src/lib/email', () => ({
  sendPaypalAlertEmail:     jest.fn().mockResolvedValue(undefined),
  sendRenewalReminderEmail: jest.fn().mockResolvedValue(undefined),
  sendGracePeriodEmail:     jest.fn().mockResolvedValue(undefined),
}));

const crypto = require('crypto');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { calculateRiskScore } = require('../../src/lib/riskScoring');
const { checkBINSequence, checkCardFingerprintVelocity } = require('../../src/lib/binSequenceDetector');
const { replayOnce } = require('../../src/jobs/replayPendingEnrichments');

const prisma = new PrismaClient();
const run   = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const HOUR  = 60 * 60 * 1000;

function scoreResult() {
  return {
    score: 20, riskLevel: 'low', decision: 'Low Risk - Approve',
    flags: [], positives: [], scoringVersion: 'mock-v1',
    economicData: null, computedSignals: {}, ipIntel: null,
    emailIntel: null, binIntel: null, limitedScoring: false,
  };
}

const cleanup = { pendingIds: [], orderIds: [], tenantId: null };

async function seedTenant() {
  const domain = `replay-${run}.test.example.com`;
  const t = await prisma.tenant.create({
    data: {
      email:          `replay-${run}@test.example.com`,
      storeUrl:       `https://${domain}`,
      allowedDomains: [domain],
      webhookSecret:  crypto.randomBytes(32).toString('hex'),
      apiKeyHash:     hashApiKey(crypto.randomBytes(32).toString('base64')),
      apiKey:         null,
      isActive:       true,
      emailVerified:  true,
      plan:           'starter',
    },
  });
  cleanup.tenantId = t.id;
  return t;
}

async function seedOrder(merchantId, orderId) {
  const o = await prisma.order.create({
    data: { orderId, merchantId, storeId: null, amount: 99, decision: 'review', riskScore: 50 },
  });
  cleanup.orderIds.push(o.id);
  return o;
}

async function seedPending({ orderId, merchantId, createdAgoMs = 90000 }) {
  const p = await prisma.pendingEnrichment.create({
    data: {
      merchantId,
      orderId,
      enrichData: JSON.stringify({ bin: '411111', source: 'stripe' }),
      status:     'pending',
      createdAt:  new Date(Date.now() - createdAgoMs),
    },
  });
  cleanup.pendingIds.push(p.id);
  return p;
}

const pendingExists = (id) =>
  prisma.pendingEnrichment.count({ where: { id } }).then((n) => n === 1);

describe('replayOnce -- real DB (REPLAY-JOB-NOT-WIRED)', () => {
  let tenant;

  beforeAll(async () => {
    await prisma.$connect();
    tenant = await seedTenant();
    calculateRiskScore.mockResolvedValue(scoreResult());
    checkBINSequence.mockResolvedValue({ blocked: false });
    checkCardFingerprintVelocity.mockResolvedValue({ blocked: false });
  }, 60000);

  afterAll(async () => {
    if (cleanup.pendingIds.length)
      await prisma.pendingEnrichment.deleteMany({ where: { id: { in: cleanup.pendingIds } } });
    if (cleanup.orderIds.length)
      await prisma.order.deleteMany({ where: { id: { in: cleanup.orderIds } } });
    if (cleanup.tenantId)
      await prisma.tenant.deleteMany({ where: { id: cleanup.tenantId } });
    await prisma.$disconnect();
  });

  test('T1 pending row with a linked Order is processed and the row is deleted', async () => {
    const orderId = `replay-t1-${run}`;
    await seedOrder(tenant.id, orderId);
    const p = await seedPending({ orderId, merchantId: tenant.id });

    await replayOnce();

    // row must be gone — deleted by the explicit deleteMany in replayPendingEnrichments.js:126
    // (mutation: removing that line lets the row survive because processEnrichment's
    //  internal deleteMany filters on status:'pending', but the row is 'processing')
    expect(await pendingExists(p.id)).toBe(false);
    const order = await prisma.order.findFirst({
      where: { merchantId: tenant.id, orderId, storeId: null },
    });
    expect(order).not.toBeNull();
    expect(order.decision).toBe('approve');
  }, 30000);

  test('T2 pending row with no matching Order is released back to pending', async () => {
    const orderId = `replay-t2-${run}-nomatch`;
    const p = await seedPending({ orderId, merchantId: tenant.id });

    await replayOnce();

    expect(await pendingExists(p.id)).toBe(true);
    const row = await prisma.pendingEnrichment.findUnique({ where: { id: p.id } });
    expect(row.status).toBe('pending');
  }, 30000);

  test('T3 pending row older than 24h is marked expired without processing', async () => {
    const orderId = `replay-t3-${run}-stale`;
    const p = await seedPending({ orderId, merchantId: tenant.id, createdAgoMs: 25 * HOUR });

    await replayOnce();

    expect(await pendingExists(p.id)).toBe(true);
    const row = await prisma.pendingEnrichment.findUnique({ where: { id: p.id } });
    expect(row.status).toBe('expired');
  }, 30000);

  test('T4 paypal_ placeholder row is not fetched or touched by replay', async () => {
    const orderId = `paypal_replay-t4-${run}`;
    const p = await seedPending({ orderId, merchantId: tenant.id });

    await replayOnce();

    expect(await pendingExists(p.id)).toBe(true);
    const row = await prisma.pendingEnrichment.findUnique({ where: { id: p.id } });
    expect(row.status).toBe('pending'); // WHERE NOT startsWith('paypal_') skips it entirely
  }, 30000);
});