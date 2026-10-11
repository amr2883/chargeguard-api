// tests/feedback/feedback-store-scope.test.js
//
// Guards N15(b) and N18a on a REAL test DB.
//   N15(b): processFeedbackSimplified() must find a store-scoped order when the
//           caller passes its storeId (POST /risk/feedback has req.storeId).
//   N18a:   the idempotency claim must touch only the row that was looked up,
//           never another row with the same (merchantId, orderId).
// identityGraph, patternSharing and logger are mocked, same as feedbackLoop.test.js.
// Intended signature: processFeedbackSimplified(orderId, result, merchantId, storeId = null)

const crypto = require('crypto');

jest.mock('../../src/lib/identityGraph', () => ({
  markOrderAsFraud: jest.fn(),
}));
jest.mock('../../src/lib/patternSharing', () => ({
  markPatternAsFraud: jest.fn(),
  markPatternAsLegit: jest.fn(),
}));
jest.mock('../../src/lib/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const db = require('../../src/lib/db');
const logger = require('../../src/lib/logger');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { markOrderAsFraud } = require('../../src/lib/identityGraph');
const { markPatternAsFraud } = require('../../src/lib/patternSharing');
const { processFeedbackSimplified } = require('../../src/lib/feedbackLoop');

const NOT_FOUND_MSG = 'Order not found for this merchant, cannot process feedback';

function uid(label) {
  return `fb-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

describe('processFeedbackSimplified -- store scope (N15b / N18a)', () => {
  let tenant;

  const mkOrder = (orderId, storeId) =>
    db.order.create({
      data: { orderId, merchantId: tenant.id, storeId, amount: 42, decision: 'review', riskScore: 50 },
    });
  const reload = (id) => db.order.findUnique({ where: { id } });
  const totalDisputes = async () => {
    const p = await db.merchantProfile.findUnique({ where: { merchantId: tenant.id } });
    return p ? p.totalDisputes : 0;
  };

  beforeAll(async () => {
    const domain = `example-fbscope-${Date.now()}.com`;
    tenant = await db.tenant.create({
      data: {
        email: `fbscope-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`,
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

  test('T1 (N18a): feedback on the pooled row must not mark a store-scoped row with the same orderId', async () => {
    const orderId = uid('n18a');
    const pooled = await mkOrder(orderId, null);
    const scoped = await mkOrder(orderId, uid('store-a'));

    await processFeedbackSimplified(orderId, true, tenant.id);

    expect(logger.error).not.toHaveBeenCalled();
    const outcomes = await db.disputeOutcome.findMany({ where: { merchantId: tenant.id, disputeId: orderId } });
    expect(outcomes).toHaveLength(1);
    expect(outcomes[0].orderId).toBe(pooled.id);
    expect((await reload(pooled.id)).feedbackProcessedAt).not.toBeNull();
    expect((await reload(scoped.id)).feedbackProcessedAt).toBeNull();
  });

  test('T2 (N15b): a store-scoped order is found when the caller passes its storeId', async () => {
    const orderId = uid('n15b');
    const storeId = uid('store-a');
    const scoped = await mkOrder(orderId, storeId);

    await processFeedbackSimplified(orderId, true, tenant.id, storeId);

    expect(logger.error).not.toHaveBeenCalled();
    expect(logger.warn).not.toHaveBeenCalledWith(expect.anything(), NOT_FOUND_MSG);
    expect((await reload(scoped.id)).feedbackProcessedAt).not.toBeNull();
    expect(markOrderAsFraud).toHaveBeenCalledTimes(1);
  });

  test('T3 (fallback guard): a legacy pooled order is still found when the caller passes a storeId', async () => {
    const orderId = uid('fallback');
    const pooled = await mkOrder(orderId, null);

    await processFeedbackSimplified(orderId, true, tenant.id, uid('store-late'));

    expect(logger.error).not.toHaveBeenCalled();
    expect(logger.warn).not.toHaveBeenCalledWith(expect.anything(), NOT_FOUND_MSG);
    expect((await reload(pooled.id)).feedbackProcessedAt).not.toBeNull();
  });

  test('T5 (idempotency guard): a second feedback call for the same order changes nothing', async () => {
    const orderId = uid('idem');
    await mkOrder(orderId, null);
    const before = await totalDisputes();

    await processFeedbackSimplified(orderId, true, tenant.id);
    await processFeedbackSimplified(orderId, true, tenant.id);

    expect(logger.error).not.toHaveBeenCalled();
    expect(await totalDisputes()).toBe(before + 1);
    expect(markOrderAsFraud).toHaveBeenCalledTimes(1);
  });
});
