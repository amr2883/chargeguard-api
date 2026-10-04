'use strict';

/**
 * tests/enrich/enrich-quota.test.js
 *
 * #299: quota / limitedScoring behaviour on POST /api/risk/enrich.
 * The scorer is mocked so the LAST argument passed to calculateRiskScore
 * (the limitedScoring flag) is observable. The limitedScoring field in the
 * response comes from the scorer result, so with a mock it is not a valid
 * detector and is deliberately NOT asserted here.
 * Body is { orderId, last4 } only: no bin (BIN blacklist / BIN sequence -> Redis),
 * no cardFingerprint, no full card tuple (CardHash) - those paths are out of scope.
 */

const crypto = require('crypto');
const request = require('supertest');

jest.mock('../../src/lib/riskScoring');
jest.mock('../../src/lib/email');

const app = require('../../src/app');
const db = require('../../src/lib/db');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { calculateRiskScore } = require('../../src/lib/riskScoring');
const email = require('../../src/lib/email');

jest.setTimeout(60000);

const API_PATH = '/api/risk/enrich';
const DEBUG = process.env.ENRICH_TEST_DEBUG === '1';
const FILE_PREFIX = `enr-${crypto.randomBytes(4).toString('hex')}`;
const hex = (n = 6) => crypto.randomBytes(n).toString('hex');
const createdTenantIds = [];
const tomorrow = () => new Date(Date.now() + 24 * 60 * 60 * 1000);

function defaultScoreResult(overrides = {}) {
  return {
    score: 85,
    riskLevel: 'low',
    decision: 'Low Risk - Approve',
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

async function createTenant(overrides = {}) {
  const label = `${FILE_PREFIX}-${hex(4)}`;
  const apiKey = crypto.randomBytes(32).toString('base64');
  const domain = `example-${label}-store.com`;
  const tenant = await db.tenant.create({
    data: {
      email: `${label}@example.com`,
      storeUrl: `https://${domain}`,
      allowedDomains: [domain],
      webhookSecret: crypto.randomBytes(32).toString('hex'),
      apiKeyHash: hashApiKey(apiKey),
      apiKey: null,
      isActive: true,
      emailVerified: true,
      plan: 'early_access',
      ...overrides,
    },
  });
  createdTenantIds.push(tenant.id);
  return { id: tenant.id, apiKey, webhookSecret: tenant.webhookSecret, domain };
}

async function seedOrder(merchantId) {
  const orderId = `ENR-${hex(6)}`;
  await db.order.create({ data: { orderId, merchantId, amount: 49.9 } });
  return orderId;
}

function signV3(secret, domain, requestId, bodyString) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signedStr = `${timestamp}.${domain}.${requestId}.${bodyString}`;
  const signature = 'v3=' + crypto.createHmac('sha256', secret).update(signedStr).digest('hex');
  return { timestamp, signature };
}

async function postEnrich(tenant, payload) {
  const body = JSON.stringify(payload);
  const requestId = hex(16);
  const { timestamp, signature } = signV3(tenant.webhookSecret, tenant.domain, requestId, body);
  const res = await request(app)
    .post(API_PATH)
    .set('Content-Type', 'application/json')
    .set('X-API-Key', tenant.apiKey)
    .set('X-Store-Domain', tenant.domain)
    .set('X-ChargeGuard-Signature', signature)
    .set('X-ChargeGuard-Timestamp', timestamp)
    .set('X-ChargeGuard-Request-Id', requestId)
    .send(body);
  if (DEBUG) console.log(`[enrich] status=${res.status} body=${JSON.stringify(res.body)}`);
  return res;
}

beforeEach(() => {
  jest.clearAllMocks();
  calculateRiskScore.mockResolvedValue(defaultScoreResult());
  email.sendQuotaExceededEmail.mockResolvedValue();
});

afterAll(async () => {
  try {
    if (createdTenantIds.length) {
      try {
        await db.riskEvaluation.deleteMany({ where: { order: { merchantId: { in: createdTenantIds } } } });
        await db.order.deleteMany({ where: { merchantId: { in: createdTenantIds } } });
        await db.pendingEnrichment.deleteMany({ where: { merchantId: { in: createdTenantIds } } });
      } catch (e) {
        if (DEBUG) console.log('[enrich] order cleanup failed: ' + e.message);
      }
      await db.tenant.deleteMany({ where: { id: { in: createdTenantIds } } });
    }
  } finally {
    await db.$disconnect();
  }
});

describe('POST /api/risk/enrich quota / limitedScoring (#299)', () => {
  test('under quota (499/500): scorer receives limitedScoring=false', async () => {
    const t = await createTenant({ plan: 'early_access', monthlyBlockedCount: 499, quotaResetDate: tomorrow() });
    const orderId = await seedOrder(t.id);
    const res = await postEnrich(t, { orderId, last4: '4242' });

    expect(res.status).toBe(200);
    expect(res.body.enriched).toBe(true);
    expect(calculateRiskScore).toHaveBeenCalledTimes(1);
    expect(calculateRiskScore.mock.calls[0].at(-1)).toBe(false);
    expect(email.sendQuotaExceededEmail).not.toHaveBeenCalled();
  });

  test('at quota (500/500): keeps enriching, scorer receives limitedScoring=true', async () => {
    const t = await createTenant({ plan: 'early_access', monthlyBlockedCount: 500, quotaResetDate: tomorrow() });
    const orderId = await seedOrder(t.id);
    const res = await postEnrich(t, { orderId, last4: '4242' });

    expect(res.status).toBe(200);
    expect(res.body.enriched).toBe(true);
    expect(calculateRiskScore).toHaveBeenCalledTimes(1);
    expect(calculateRiskScore.mock.calls[0].at(-1)).toBe(true);
  });

  test('agency plan is exempt from quota even with a huge counter', async () => {
    const t = await createTenant({ plan: 'agency', monthlyBlockedCount: 999999, quotaResetDate: tomorrow() });
    const orderId = await seedOrder(t.id);
    const res = await postEnrich(t, { orderId, last4: '4242' });

    expect(res.status).toBe(200);
    expect(res.body.enriched).toBe(true);
    expect(calculateRiskScore).toHaveBeenCalledTimes(1);
    expect(calculateRiskScore.mock.calls[0].at(-1)).toBe(false);
  });
});
