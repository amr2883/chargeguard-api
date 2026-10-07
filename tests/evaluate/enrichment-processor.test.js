// tests/evaluate/enrichment-processor.test.js
//
// Guards #74: enrichmentProcessor.js called findOrderByBusinessKey without
// importing it (ReferenceError on every /risk/enrich for an existing order).
// Calls processEnrichment() directly -- auth/quota/HMAC are not under test.

const crypto = require('crypto');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');

// Explicit factories: the real modules are never loaded (no Redis, no
// external IP/email/BIN intelligence).
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

const { calculateRiskScore } = require('../../src/lib/riskScoring');
const { checkBINSequence, checkCardFingerprintVelocity } = require('../../src/lib/binSequenceDetector');
const { processEnrichment } = require('../../src/lib/enrichmentProcessor');

const prisma = new PrismaClient();

function uniqueOrderId(label) {
  return `enrich-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function scoreResult() {
  return {
    score: 85,
    riskLevel: 'low',
    decision: 'Low Risk - Approve',
    flags: [],
    positives: [],
    scoringVersion: 'mock-v1',
    economicData: null,
    computedSignals: {},
    ipIntel: null,
    emailIntel: null,
    binIntel: null,
    limitedScoring: false,
  };
}

async function seedTenant(label, overrides = {}) {
  const domain = `example-enrich-${label}-${Date.now()}.com`;
  return prisma.tenant.create({
    data: {
      email: `enrich-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`,
      storeUrl: `https://${domain}`,
      allowedDomains: [domain],
      webhookSecret: crypto.randomBytes(32).toString('hex'),
      apiKeyHash: hashApiKey(crypto.randomBytes(32).toString('base64')),
      apiKey: null,
      isActive: true,
      emailVerified: true,
      plan: 'starter',
      ...overrides,
    },
  });
}

describe('processEnrichment -- order lookup by business key (#74 / C4)', () => {
  const createdTenantIds = [];
  let tenant;
  let perStoreTenant;

  beforeAll(async () => {
    tenant = await seedTenant('pooled');
    perStoreTenant = await seedTenant('perstore', { fraudIsolationMode: 'per_store' });
    createdTenantIds.push(tenant.id, perStoreTenant.id);
  });

  beforeEach(() => {
    calculateRiskScore.mockReset();
    calculateRiskScore.mockResolvedValue(scoreResult());
    checkBINSequence.mockReset();
    checkBINSequence.mockResolvedValue({ blocked: false });
    checkCardFingerprintVelocity.mockReset();
    checkCardFingerprintVelocity.mockResolvedValue({ blocked: false });
  });

  afterAll(async () => {
    if (createdTenantIds.length) {
      await prisma.order.deleteMany({ where: { merchantId: { in: createdTenantIds } } });
      await prisma.tenant.deleteMany({ where: { id: { in: createdTenantIds } } });
    }
    await prisma.$disconnect();
  });

  test('T1: pooled order (storeId null) is found and enriched', async () => {
    const orderId = uniqueOrderId('t1');
    await prisma.order.create({
      data: { orderId, merchantId: tenant.id, storeId: null, amount: 42, decision: 'review', riskScore: 50 },
    });

    const result = await processEnrichment({
      merchantId: tenant.id, orderId, body: { bin: '411111', source: 'stripe' }, storeId: null, tenant,
    });

    expect(result.status).toBe(200);
    expect(result.body.enriched).toBe(true);
    const row = await prisma.order.findFirst({ where: { merchantId: tenant.id, orderId, storeId: null } });
    expect(row.decision).toBe('approve');
    expect(row.enrichmentSource).toBe('stripe');
    expect(row.cardBinPrefix).toBe('411111');
  });

  test('T2: store-scoped order is found when the same storeId is passed', async () => {
    const orderId = uniqueOrderId('t2');
    await prisma.order.create({
      data: { orderId, merchantId: perStoreTenant.id, storeId: 'store-a', amount: 42, decision: 'review', riskScore: 50 },
    });

    const result = await processEnrichment({
      merchantId: perStoreTenant.id, orderId, body: { bin: '411111', source: 'stripe' }, storeId: 'store-a', tenant: perStoreTenant,
    });

    expect(result.status).toBe(200);
    expect(result.body.enriched).toBe(true);
    const row = await prisma.order.findFirst({ where: { merchantId: perStoreTenant.id, orderId, storeId: 'store-a' } });
    expect(row.decision).toBe('approve');
  });

  test('T3: store-scoped order is NOT found when storeId null is passed', async () => {
    const orderId = uniqueOrderId('t3');
    await prisma.order.create({
      data: { orderId, merchantId: perStoreTenant.id, storeId: 'store-a', amount: 42, decision: 'review', riskScore: 50 },
    });

    const result = await processEnrichment({
      merchantId: perStoreTenant.id, orderId, body: { bin: '411111' }, storeId: null, tenant: perStoreTenant,
    });

    expect(result.status).toBe(404);
    const row = await prisma.order.findFirst({ where: { merchantId: perStoreTenant.id, orderId } });
    expect(row.decision).toBe('review');
  });

  test('T4: unknown orderId returns 404', async () => {
    const result = await processEnrichment({
      merchantId: tenant.id, orderId: uniqueOrderId('t4'), body: { bin: '411111' }, storeId: null, tenant,
    });
    expect(result.status).toBe(404);
    expect(result.body).toEqual({ error: 'Order not found' });
  });

  test('T5: pooled order is NOT found when a storeId is passed', async () => {
    const orderId = uniqueOrderId('t5');
    await prisma.order.create({
      data: { orderId, merchantId: perStoreTenant.id, storeId: null, amount: 42, decision: 'review', riskScore: 50 },
    });

    const result = await processEnrichment({
      merchantId: perStoreTenant.id, orderId, body: { bin: '411111' }, storeId: 'store-a', tenant: perStoreTenant,
    });

    expect(result.status).toBe(404);
    const row = await prisma.order.findFirst({ where: { merchantId: perStoreTenant.id, orderId } });
    expect(row.decision).toBe('review');
  });

  test('T6: same orderId under two stores -- each call updates only its own row', async () => {
    const orderId = uniqueOrderId('t6');
    await prisma.order.create({
      data: { orderId, merchantId: perStoreTenant.id, storeId: 'store-a', amount: 10, decision: 'review', riskScore: 50 },
    });
    await prisma.order.create({
      data: { orderId, merchantId: perStoreTenant.id, storeId: 'store-b', amount: 20, decision: 'review', riskScore: 50 },
    });

    const result = await processEnrichment({
      merchantId: perStoreTenant.id, orderId, body: { bin: '411111', source: 'stripe' }, storeId: 'store-b', tenant: perStoreTenant,
    });

    expect(result.status).toBe(200);
    const a = await prisma.order.findFirst({ where: { merchantId: perStoreTenant.id, orderId, storeId: 'store-a' } });
    const b = await prisma.order.findFirst({ where: { merchantId: perStoreTenant.id, orderId, storeId: 'store-b' } });
    expect(b.decision).toBe('approve');
    expect(b.enrichmentSource).toBe('stripe');
    expect(a.decision).toBe('review');
    expect(a.enrichmentSource).toBeNull();
  });
});