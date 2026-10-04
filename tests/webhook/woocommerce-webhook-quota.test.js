'use strict';

/**
 * tests/webhook/woocommerce-webhook-quota.test.js
 *
 * #299: quota / limitedScoring behaviour on POST /api/risk/woocommerce-webhook.
 * The scorer is mocked so the LAST argument passed to calculateRiskScore
 * (the limitedScoring flag) is observable. Everything before the scorer
 * (auth, WC signature, hard-block layers, identity graph) runs for real.
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

const API_PATH = '/api/risk/woocommerce-webhook';
const FILE_PREFIX = `whq-${crypto.randomBytes(4).toString('hex')}`;
const hex = (n = 6) => crypto.randomBytes(n).toString('hex');
const createdTenantIds = [];
const ORDER_BASE = 100000000 + Math.floor(Math.random() * 800000000);
let orderCounter = 0;
let ipCounter = 0;
const nextOrderId = () => ORDER_BASE + ++orderCounter;
const uniqueIp = () => `9.9.${20 + (++ipCounter % 200)}.${1 + (ipCounter % 250)}`;
const uniqueEmail = () => `buyer-${hex()}@gmail.com`;
const tomorrow = () => new Date(Date.now() + 24 * 60 * 60 * 1000);

function defaultScoreResult(overrides = {}) {
  return {
    score: 85,
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
  const domain = `${label}-store.test`;
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

function buildPayload() {
  return {
    id: nextOrderId(),
    status: 'processing',
    currency: 'USD',
    total: '49.90',
    customer_ip_address: uniqueIp(),
    customer_id: 0,
    date_created: '2026-09-28T10:00:00',
    billing: { first_name: 'Test', last_name: 'Buyer', email: uniqueEmail(), country: 'EG' },
    shipping: { country: 'EG' },
  };
}

function postSigned(tenant, payload) {
  const body = JSON.stringify(payload);
  const sig = crypto.createHmac('sha256', tenant.webhookSecret).update(body).digest('base64');
  return request(app)
    .post(API_PATH)
    .set('Content-Type', 'application/json')
    .set('X-API-Key', tenant.apiKey)
    .set('X-WC-Webhook-Signature', sig)
    .send(body);
}

beforeEach(() => {
  jest.clearAllMocks();
  calculateRiskScore.mockResolvedValue(defaultScoreResult());
  email.sendQuotaExceededEmail.mockResolvedValue();
});

afterAll(async () => {
  try {
    if (createdTenantIds.length) {
      await db.tenant.deleteMany({ where: { id: { in: createdTenantIds } } });
    }
  } finally {
    await db.$disconnect();
  }
});

describe('POST /api/risk/woocommerce-webhook quota / limitedScoring (#299)', () => {
  test('under quota (499/500): limitedScoring=false in response and scorer', async () => {
    const t = await createTenant({ plan: 'early_access', monthlyBlockedCount: 499, quotaResetDate: tomorrow() });
    const res = await postSigned(t, buildPayload());

    expect(res.status).toBe(200);
    expect(res.body.scored).toBe(true);
    expect(res.body.decision).toBe('approve');
    expect(res.body.limitedScoring).toBe(false);
    expect(calculateRiskScore).toHaveBeenCalledTimes(1);
    expect(calculateRiskScore.mock.calls[0].at(-1)).toBe(false);
    expect(email.sendQuotaExceededEmail).not.toHaveBeenCalled();
  });

  test('at quota (500/500): keeps scoring with limitedScoring=true, no 403', async () => {
    const t = await createTenant({ plan: 'early_access', monthlyBlockedCount: 500, quotaResetDate: tomorrow() });
    const res = await postSigned(t, buildPayload());

    expect(res.status).toBe(200);
    expect(res.body.scored).toBe(true);
    expect(res.body.decision).toBe('approve');
    expect(res.body.limitedScoring).toBe(true);
    expect(calculateRiskScore).toHaveBeenCalledTimes(1);
    expect(calculateRiskScore.mock.calls[0].at(-1)).toBe(true);
  });

  test('agency plan is exempt from quota even with a huge counter', async () => {
    const t = await createTenant({ plan: 'agency', monthlyBlockedCount: 999999, quotaResetDate: tomorrow() });
    const res = await postSigned(t, buildPayload());

    expect(res.status).toBe(200);
    expect(res.body.scored).toBe(true);
    expect(res.body.limitedScoring).toBe(false);
    expect(calculateRiskScore).toHaveBeenCalledTimes(1);
    expect(calculateRiskScore.mock.calls[0].at(-1)).toBe(false);
  });
});
