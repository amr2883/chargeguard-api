const request = require('supertest');
const crypto = require('crypto');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');

const prisma = new PrismaClient();

// Same signing scheme as connect-flow.test.js / verifyHmac.js: v1 = HMAC(secret, `${ts}.${rawBody}`)
function signRequest(secret, bodyString) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signature = 'v1=' + crypto.createHmac('sha256', secret).update(`${timestamp}.${bodyString}`).digest('hex');
  return { timestamp, signature };
}

// Every row written through POST /risk/blacklist|whitelist has storeId NULL, and Postgres treats
// NULLs as distinct in the composite unique, so duplicates were silently accepted before the
// partial unique indexes (migration 20260920000100). These tests lock that behaviour in.
describe('blacklist/whitelist: duplicate adds', () => {
  let tenant, apiKey, domain;
  const models = { blacklist: 'blacklistEntry', whitelist: 'whitelistEntry' };

  beforeAll(async () => {
    const uniq = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    apiKey = crypto.randomBytes(32).toString('base64');
    domain = `dup-${uniq}-store.com`;
    tenant = await prisma.tenant.create({
      data: {
        email: `dup-${uniq}@example.com`,
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
  });

  afterAll(async () => {
    if (tenant) {
      await prisma.blacklistEntry.deleteMany({ where: { merchantId: tenant.id } });
      await prisma.whitelistEntry.deleteMany({ where: { merchantId: tenant.id } });
      await prisma.tenant.deleteMany({ where: { id: tenant.id } });
    }
    await prisma.$disconnect();
  });

  function add(list, body) {
    const bodyString = JSON.stringify(body);
    const { timestamp, signature } = signRequest(tenant.webhookSecret, bodyString);
    return request(app)
      .post(`/api/risk/${list}`)
      .set('Content-Type', 'application/json')
      .set('X-Api-Key', apiKey)
      .set('X-Store-Domain', domain)
      .set('X-ChargeGuard-Signature', signature)
      .set('X-ChargeGuard-Timestamp', timestamp)
      .send(bodyString);
  }

  const count = (list, value) =>
    prisma[models[list]].count({ where: { merchantId: tenant.id, type: 'EMAIL', value } });

  test.each(['blacklist', 'whitelist'])('%s: same value twice -> 200 then 409, one row', async (list) => {
    const value = `seq-${list}-${Date.now()}@example.com`;
    const first = await add(list, { type: 'EMAIL', value });
    const second = await add(list, { type: 'EMAIL', value });
    expect({ first: first.status, second: second.status }).toEqual({ first: 200, second: 409 });
    expect(second.body.error).toMatch(/already exists/i);
    expect(await count(list, value)).toBe(1);
  });

  test.each(['blacklist', 'whitelist'])('%s: 10 parallel identical adds -> exactly one 200, nine 409, no 5xx, one row', async (list) => {
    const value = `par-${list}-${Date.now()}@example.com`;
    const results = await Promise.all(Array.from({ length: 10 }, () => add(list, { type: 'EMAIL', value })));
    const statuses = results.map((r) => r.status);
    const summary = {
      ok: statuses.filter((s) => s === 200).length,
      conflict: statuses.filter((s) => s === 409).length,
      other: statuses.filter((s) => s !== 200 && s !== 409),
    };
    expect(summary).toEqual({ ok: 1, conflict: 9, other: [] });
    expect(await count(list, value)).toBe(1);
  });

  test.each(['blacklist', 'whitelist'])('%s: two different values are both accepted', async (list) => {
    const a = await add(list, { type: 'EMAIL', value: `diff-a-${list}-${Date.now()}@example.com` });
    const b = await add(list, { type: 'EMAIL', value: `diff-b-${list}-${Date.now()}@example.com` });
    expect({ a: a.status, b: b.status }).toEqual({ a: 200, b: 200 });
  });
});