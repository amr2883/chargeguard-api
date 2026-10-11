'use strict';

// Integration test (real DB, real auth + domain + HMAC chain) for the duplicate
// handling of POST /api/risk/blacklist and POST /api/risk/whitelist.
// The routes insert with storeId NULL, so the partial unique indexes
// (*_null_store_unique) reject a repeat, and the handlers must turn the
// resulting P2002 into 409 instead of 500.
//
// Every request is signed with an explicit timestamp. Two requests with identical
// signed bytes (same body, same second) were observed to return 200 without
// reaching the duplicate handling, so the repeat uses a different timestamp.

const request = require('supertest');
const crypto = require('crypto');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');

jest.mock('../../src/lib/email');

const prisma = new PrismaClient();

function signRequest(secret, bodyString, ageSec = 0) {
  const timestamp = String(Math.floor(Date.now() / 1000) - ageSec);
  const signedStr = `${timestamp}.${bodyString}`;
  const signature = 'v1=' + crypto.createHmac('sha256', secret).update(signedStr).digest('hex');
  return { timestamp, signature };
}

describe('POST /api/risk/blacklist and /whitelist - duplicate entry returns 409', () => {
  let tenant;
  let apiKey;
  let domain;

  const post = (path, body, ageSec = 0) => {
    const bodyString = JSON.stringify(body);
    const { timestamp, signature } = signRequest(tenant.webhookSecret, bodyString, ageSec);
    return request(app)
      .post(path)
      .set('Content-Type', 'application/json')
      .set('X-Api-Key', apiKey)
      .set('X-Store-Domain', domain)
      .set('X-ChargeGuard-Signature', signature)
      .set('X-ChargeGuard-Timestamp', timestamp)
      .send(bodyString);
  };

  beforeAll(async () => {
    const rand = Math.random().toString(36).slice(2);
    apiKey = crypto.randomBytes(32).toString('base64');
    domain = `example-dup-${rand}-store.com`;
    tenant = await prisma.tenant.create({
      data: {
        email: `dup-${Date.now()}-${rand}@example.com`,
        storeUrl: `https://${domain}`,
        allowedDomains: [domain],
        webhookSecret: crypto.randomBytes(32).toString('hex'),
        apiKeyHash: hashApiKey(apiKey),
        apiKey: null,
        isActive: true,
        emailVerified: true,
        plan: 'early_access',
      },
    });
    // Warm-up: the first request in a fresh process pays one-time costs.
    await post('/api/risk/blacklist', { type: 'EMAIL', value: `warmup-${rand}@example.com` });
  }, 60000);

  afterAll(async () => {
    if (tenant) {
      await prisma.blacklistEntry.deleteMany({ where: { merchantId: tenant.id } });
      await prisma.whitelistEntry.deleteMany({ where: { merchantId: tenant.id } });
      await prisma.tenant.deleteMany({ where: { id: tenant.id } });
    }
    await prisma.$disconnect();
  });

  test.each([
    ['blacklist', 'blacklistEntry'],
    ['whitelist', 'whitelistEntry'],
  ])('%s: same entry twice gives 200 then 409, exactly one row, a different entry still gives 200', async (list, model) => {
    const path = `/api/risk/${list}`;
    const value = `dup-${list}-${Date.now()}@example.com`;

    const first = await post(path, { type: 'EMAIL', value }, 20);
    expect(first.status).toBe(200);

    const second = await post(path, { type: 'EMAIL', value }, 10);
    expect(second.status).toBe(409);
    expect(second.body.error).toBe(`This entry already exists in the ${list}`);

    const rows = await prisma[model].count({ where: { merchantId: tenant.id, type: 'EMAIL', value } });
    expect(rows).toBe(1);

    const other = await post(path, { type: 'EMAIL', value: `other-${list}-${Date.now()}@example.com` });
    expect(other.status).toBe(200);
  });
});
// ACCESS-LIST-DUP-TEST-END