'use strict';

/**
 * tests/enrich/enrich-cardhash.test.js
 *
 * #302: ONE POST /api/risk/enrich request must count as ONE attempt on
 * CardHash.attemptCount. The route and enrichmentProcessor both upsert the
 * same CardHash row (increment), so a live request counts twice.
 * The scorer is mocked; calculateRiskScore argument index 7 is cardHashRecord.
 * Body has no bin / cardFingerprint, so no Redis path is touched.
 */

const crypto = require('crypto');
const request = require('supertest');

jest.mock('../../src/lib/riskScoring');
jest.mock('../../src/lib/email');

const app = require('../../src/app');
const db = require('../../src/lib/db');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { signV3 } = require('../helpers/signV3');
const { calculateRiskScore } = require('../../src/lib/riskScoring');
const email = require('../../src/lib/email');

jest.setTimeout(60000);

const API_PATH = '/api/risk/enrich';
const DEBUG = process.env.ENRICH_TEST_DEBUG === '1';
const FILE_PREFIX = `ech-${crypto.randomBytes(4).toString('hex')}`;
const hex = (n = 6) => crypto.randomBytes(n).toString('hex');
const createdTenantIds = [];
const tomorrow = () => new Date(Date.now() + 24 * 60 * 60 * 1000);
const CARD = { last4: '4242', expMonth: 12, expYear: 2030, brand: 'visa' };

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

async function createTenant() {
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
      monthlyBlockedCount: 0,
      quotaResetDate: tomorrow(),
    },
  });
  createdTenantIds.push(tenant.id);
  return { id: tenant.id, apiKey, webhookSecret: tenant.webhookSecret, domain };
}

async function seedOrder(merchantId) {
  const orderId = `ECH-${hex(6)}`;
  await db.order.create({ data: { orderId, merchantId, amount: 49.9 } });
  return orderId;
}

async function postEnrich(tenant, payload) {
  const body = JSON.stringify(payload);
  const requestId = hex(16);
  const headers = signV3({ secret: tenant.webhookSecret, domain: tenant.domain, requestId, method: 'POST', target: API_PATH, body });
  const res = await request(app)
    .post(API_PATH)
    .set('Content-Type', 'application/json')
    .set('X-API-Key', tenant.apiKey)
    .set(headers)
    .send(body);
  if (DEBUG) console.log(`[enrich] status=${res.status} body=${JSON.stringify(res.body)}`);
  return res;
}

const cardRows = (merchantId) => db.cardHash.findMany({ where: { merchantId } });

beforeEach(() => {
  jest.clearAllMocks();
  calculateRiskScore.mockResolvedValue(defaultScoreResult());
  email.sendQuotaExceededEmail.mockResolvedValue();
});

afterAll(async () => {
  const safe = async (fn) => {
    try { await fn(); } catch (e) { if (DEBUG) console.log('[enrich] cleanup step failed: ' + e.message); }
  };
  try {
    if (createdTenantIds.length) {
      const where = { merchantId: { in: createdTenantIds } };
      await safe(() => db.riskEvaluation.deleteMany({ where: { order: where } }));
      await safe(() => db.order.deleteMany({ where }));
      await safe(() => db.pendingEnrichment.deleteMany({ where }));
      await safe(() => db.cardHash.deleteMany({ where }));
      await safe(() => db.tenant.deleteMany({ where: { id: { in: createdTenantIds } } }));
    }
  } finally {
    await db.$disconnect();
  }
});

describe('POST /api/risk/enrich CardHash attemptCount (#302)', () => {
  test('control: scorer receives the CardHash record of this card, one row in DB', async () => {
    const t = await createTenant();
    const orderId = await seedOrder(t.id);
    const res = await postEnrich(t, { orderId, ...CARD });

    expect(res.status).toBe(200);
    expect(res.body.enriched).toBe(true);
    expect(calculateRiskScore).toHaveBeenCalledTimes(1);
    const rec = calculateRiskScore.mock.calls[0][7];
    expect(rec).toBeTruthy();
    expect(rec.merchantId).toBe(t.id);
    expect(rec.last4).toBe('4242');
    expect(rec.brand).toBe('visa');
    expect(await cardRows(t.id)).toHaveLength(1);
  });

  test('new card: one request counts as one attempt in the DB', async () => {
    const t = await createTenant();
    const orderId = await seedOrder(t.id);
    const res = await postEnrich(t, { orderId, ...CARD });

    expect(res.status).toBe(200);
    const rows = await cardRows(t.id);
    expect(rows).toHaveLength(1);
    expect(rows[0].attemptCount).toBe(1);
  });

  test('new card: scorer receives attemptCount 1', async () => {
    const t = await createTenant();
    const orderId = await seedOrder(t.id);
    const res = await postEnrich(t, { orderId, ...CARD });

    expect(res.status).toBe(200);
    expect(calculateRiskScore).toHaveBeenCalledTimes(1);
    expect(calculateRiskScore.mock.calls[0][7].attemptCount).toBe(1);
  });

  test('same card on two orders: two requests count as two attempts', async () => {
    const t = await createTenant();
    const o1 = await seedOrder(t.id);
    const o2 = await seedOrder(t.id);
    const r1 = await postEnrich(t, { orderId: o1, ...CARD });
    const r2 = await postEnrich(t, { orderId: o2, ...CARD });

    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    const rows = await cardRows(t.id);
    expect(rows).toHaveLength(1);
    expect(rows[0].attemptCount).toBe(2);
  });
});
