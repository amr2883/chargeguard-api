'use strict';

/**
 * tests/webhook/whitelist-scope.test.js
 *
 * #288: how does the WooCommerce webhook treat WhitelistEntry rows under
 * Agency per-store isolation? /evaluate and enrich filter the whitelist with
 * getStoreScope(); the webhook whitelist check does not. This file MEASURES
 * the real behaviour. Tests 3-5 log [MEASURE] lines and do not assert a
 * direction yet; tests 1-2 are real assertions (plumbing controls).
 * Detector: res.body.whitelisted === true. No scorer mock.
 */

const crypto = require('crypto');
const request = require('supertest');

jest.mock('../../src/lib/email');

const app = require('../../src/app');
const db = require('../../src/lib/db');
const { hashApiKey } = require('../../src/lib/apiKeyHash');

jest.setTimeout(60000);

const API_PATH = '/api/risk/woocommerce-webhook';
const FILE_PREFIX = `wls-${crypto.randomBytes(4).toString('hex')}`;
const hex = (n = 6) => crypto.randomBytes(n).toString('hex');
const createdTenantIds = [];
const tomorrow = () => new Date(Date.now() + 24 * 60 * 60 * 1000);
const ORDER_BASE = 100000000 + Math.floor(Math.random() * 800000000);
let orderCounter = 0;
let ipCounter = 0;
const nextOrderId = () => ORDER_BASE + ++orderCounter;
const uniqueIp = () => `7.7.${20 + (++ipCounter % 200)}.${1 + (ipCounter % 250)}`;

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
      monthlyBlockedCount: 0,
      quotaResetDate: tomorrow(),
      ...overrides,
    },
  });
  createdTenantIds.push(tenant.id);
  return { id: tenant.id, apiKey, webhookSecret: tenant.webhookSecret, domain };
}

async function createStore(tenantId, label) {
  const domain = `example-${label}-${hex(3)}-shop.com`;
  const store = await db.store.create({
    data: { tenantId, storeUrl: `https://${domain}`, normalizedDomain: domain },
  });
  return { id: store.id, domain };
}

function post(tenant, sourceDomain, ip) {
  const payload = {
    id: nextOrderId(),
    status: 'processing',
    currency: 'USD',
    total: '49.90',
    customer_ip_address: ip,
    customer_id: 0,
    date_created: '2026-09-28T10:00:00',
    billing: { first_name: 'Test', last_name: 'Buyer', email: `buyer-${hex()}@gmail.com`, country: 'EG' },
    shipping: { country: 'EG' },
  };
  const body = JSON.stringify(payload);
  const sig = crypto.createHmac('sha256', tenant.webhookSecret).update(body).digest('base64');
  return request(app)
    .post(API_PATH)
    .set('Content-Type', 'application/json')
    .set('X-API-Key', tenant.apiKey)
    .set('X-WC-Webhook-Signature', sig)
    .set('X-WC-Webhook-Source', `https://${sourceDomain}/`)
    .send(body);
}

const addWhitelistIp = (merchantId, ip, storeId) =>
  db.whitelistEntry.create({
    data: { merchantId, storeId: storeId ?? null, type: 'IP', value: ip, normalizedValue: ip },
  });

const measure = (label, res) =>
  console.log(`[MEASURE] ${label}: status=${res.status} whitelisted=${res.body && res.body.whitelisted === true} decision=${res.body && res.body.decision}`);

beforeEach(() => {
  jest.clearAllMocks();
});

afterAll(async () => {
  const safe = async (fn) => { try { await fn(); } catch (e) { /* best effort */ } };
  try {
    if (createdTenantIds.length) {
      const where = { merchantId: { in: createdTenantIds } };
      await safe(() => db.whitelistEntry.deleteMany({ where }));
      await safe(() => db.riskEvaluation.deleteMany({ where: { order: where } }));
      await safe(() => db.order.deleteMany({ where }));
      await safe(() => db.blockedAttempt.deleteMany({ where: { tenantId: { in: createdTenantIds } } }));
      await safe(() => db.identitySighting.deleteMany({ where }));
      await safe(() => db.tenant.deleteMany({ where: { id: { in: createdTenantIds } } }));
    }
  } finally {
    await db.$disconnect();
  }
});

describe('webhook whitelist vs per-store isolation (#288)', () => {
  test('control (pooled): whitelist IP with storeId NULL bypasses', async () => {
    const t = await createTenant({ fraudIsolationMode: 'pooled' });
    const s = await createStore(t.id, 'a');
    const ip = uniqueIp();
    await addWhitelistIp(t.id, ip, null);
    const res = await post(t, s.domain, ip);
    measure('pooled/NULL', res);

    expect(res.status).toBe(200);
    expect(res.body.whitelisted).toBe(true);
  });

  test('control (per_store, no whitelist): request is scored, not whitelisted', async () => {
    const t = await createTenant({ fraudIsolationMode: 'per_store' });
    const s = await createStore(t.id, 'a');
    const res = await post(t, s.domain, uniqueIp());
    measure('per_store/no-entry', res);

    expect(res.status).toBe(200);
    expect(res.body.whitelisted).not.toBe(true);
  });

  test('per_store: entry with storeId NULL does not bypass (strict, same as /evaluate)', async () => {
    const t = await createTenant({ fraudIsolationMode: 'per_store' });
    const s = await createStore(t.id, 'a');
    const ip = uniqueIp();
    await addWhitelistIp(t.id, ip, null);
    const res = await post(t, s.domain, ip);
    measure('per_store/NULL-entry', res);

    expect(res.status).toBe(200);
    expect(res.body.whitelisted).not.toBe(true);
  });

  test('per_store: entry of ANOTHER store does not bypass', async () => {
    const t = await createTenant({ fraudIsolationMode: 'per_store' });
    const a = await createStore(t.id, 'a');
    const b = await createStore(t.id, 'b');
    const ip = uniqueIp();
    await addWhitelistIp(t.id, ip, b.id);
    const res = await post(t, a.domain, ip);
    measure('per_store/other-store-entry', res);

    expect(res.status).toBe(200);
    expect(res.body.whitelisted).not.toBe(true);
  });

  test('per_store: entry of the SAME store bypasses', async () => {
    const t = await createTenant({ fraudIsolationMode: 'per_store' });
    const a = await createStore(t.id, 'a');
    const ip = uniqueIp();
    await addWhitelistIp(t.id, ip, a.id);
    const res = await post(t, a.domain, ip);
    measure('per_store/same-store-entry', res);

    expect(res.status).toBe(200);
    expect(res.body.whitelisted).toBe(true);
  });
});
