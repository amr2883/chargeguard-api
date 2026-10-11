// tests/feedback/feedback-dispute-scope.test.js
// Guards N18b: two stores of the same tenant may share an orderId. Feedback for
// each must produce its own DisputeOutcome row (unique is (merchantId, disputeId)).

const crypto = require('crypto');

jest.mock('../../src/lib/identityGraph', () => ({ markOrderAsFraud: jest.fn() }));
jest.mock('../../src/lib/patternSharing', () => ({
  markPatternAsFraud: jest.fn(),
  markPatternAsLegit: jest.fn(),
}));
jest.mock('../../src/lib/logger', () => ({
  info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(),
}));

const db = require('../../src/lib/db');
const logger = require('../../src/lib/logger');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { markOrderAsFraud } = require('../../src/lib/identityGraph');
const { markPatternAsFraud } = require('../../src/lib/patternSharing');
const { processFeedbackSimplified } = require('../../src/lib/feedbackLoop');

function uid(label) {
  return `fbd-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

describe('processFeedbackSimplified -- DisputeOutcome per store (N18b)', () => {
  let tenant;

  beforeAll(async () => {
    const domain = `example-fbdisp-${Date.now()}.com`;
    tenant = await db.tenant.create({
      data: {
        email: `fbdisp-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`,
        storeUrl: `https://${domain}`,
        allowedDomains: [domain],
        webhookSecret: crypto.randomBytes(32).toString('hex'),
        apiKeyHash: hashApiKey(crypto.randomBytes(32).toString('base64')),
        apiKey: null,
        isActive: true,
        emailVerified: true,
        plan: 'starter',
        fraudIsolationMode: 'per_store',
      },
    });
  });

  beforeEach(() => {
    jest.clearAllMocks();
    markOrderAsFraud.mockResolvedValue(undefined);
    markPatternAsFraud.mockResolvedValue(undefined);
  });

  afterAll(async () => {
    if (tenant) {
      await db.disputeOutcome.deleteMany({ where: { merchantId: tenant.id } });
      await db.order.deleteMany({ where: { merchantId: tenant.id } });
      await db.merchantProfile.deleteMany({ where: { merchantId: tenant.id } });
      await db.tenant.deleteMany({ where: { id: tenant.id } });
    }
    await db.$disconnect();
  });

  test('T-D1: same orderId in two stores gives two DisputeOutcome rows', async () => {
    const orderId = uid('same');
    const storeA = uid('store-a');
    const storeB = uid('store-b');
    const base = { orderId, merchantId: tenant.id, amount: 42, decision: 'review', riskScore: 50 };
    const a = await db.order.create({ data: { ...base, storeId: storeA } });
    const b = await db.order.create({ data: { ...base, storeId: storeB } });

    await processFeedbackSimplified(orderId, true, tenant.id, storeA);
    await processFeedbackSimplified(orderId, true, tenant.id, storeB);

    expect(logger.error).not.toHaveBeenCalled();
    const rows = await db.disputeOutcome.findMany({ where: { merchantId: tenant.id, orderId: { in: [a.id, b.id] } } });
    expect(rows).toHaveLength(2);
    expect(new Set(rows.map((r) => r.orderId))).toEqual(new Set([a.id, b.id]));
    expect(markOrderAsFraud).toHaveBeenCalledTimes(2);
  });

  test('T-D2: pooled order keeps disputeId equal to the plain orderId', async () => {
    const orderId = uid('pooled');
    await db.order.create({ data: { orderId, merchantId: tenant.id, storeId: null, amount: 42, decision: 'review', riskScore: 50 } });

    await processFeedbackSimplified(orderId, true, tenant.id);

    expect(logger.error).not.toHaveBeenCalled();
    const rows = await db.disputeOutcome.findMany({ where: { merchantId: tenant.id, disputeId: orderId } });
    expect(rows).toHaveLength(1);
  });
});
