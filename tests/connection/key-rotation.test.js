'use strict';

// Integration test (real DB, real auth chain, no prisma mocks) for the API-key
// rotation flow: POST /api/auth/connect-with-key -> POST /api/dashboard/rotate-key.
//
// Tests marked CURRENT BEHAVIOR pin down behavior that is expected to change
// once the previous (grace-period) key is no longer accepted on these routes.
// Do not use fake timers here: failed auth responses are delayed with setTimeout.

const request = require('supertest');
const crypto = require('crypto');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');

jest.mock('../../src/lib/email');
const email = require('../../src/lib/email');

const prisma = new PrismaClient();

const MIN = 60 * 1000;
const ago = (ms) => new Date(Date.now() - ms);

async function seedTenant(label) {
  const rand = Math.random().toString(36).slice(2);
  const originalKey = crypto.randomBytes(32).toString('base64');
  const domain = `example-rot-${label}-${rand}-store.com`;
  const tenant = await prisma.tenant.create({
    data: {
      email: `rot-${label}-${Date.now()}-${rand}@example.com`,
      storeUrl: `https://${domain}`,
      allowedDomains: [domain],
      webhookSecret: crypto.randomBytes(32).toString('hex'),
      apiKeyHash: hashApiKey(originalKey),
      apiKey: null,
      isActive: true,
      emailVerified: true,
      plan: 'early_access',
    },
  });
  return { tenant, originalKey };
}

const connect = (key) =>
  request(app).post('/api/auth/connect-with-key').set('X-Api-Key', key).send({});
const rotate = (key) =>
  request(app).post('/api/dashboard/rotate-key').set('X-Api-Key', key);
const loadRow = (id) => prisma.tenant.findUnique({ where: { id } });

describe('API key rotation - integration (connect-with-key -> rotate-key)', () => {
  const createdTenantIds = [];
  const seed = async (label) => {
    const s = await seedTenant(label);
    createdTenantIds.push(s.tenant.id);
    return s;
  };

  afterAll(async () => {
    if (createdTenantIds.length) {
      await prisma.tenant.deleteMany({ where: { id: { in: createdTenantIds } } });
    }
    await prisma.$disconnect();
  });

  // Same warm-up rationale as connect-flow.test.js (first request pays one-time costs).
  beforeAll(async () => {
    const { originalKey } = await seed('warmup');
    await connect(originalKey);
  }, 60000);

  beforeEach(() => {
    jest.clearAllMocks();
    delete process.env.KEY_ROTATION_GRACE_HOURS;
    email.sendRotatedKeyEmail.mockResolvedValue(undefined);
  });

  test('T1 current key: connect then rotate; hashes, grace window and email are persisted', async () => {
    const { tenant, originalKey } = await seed('t1');

    expect((await connect(originalKey)).status).toBe(200);
    const r = await rotate(originalKey);
    expect(r.status).toBe(200);
    expect(typeof r.body.newApiKey).toBe('string');
    expect(r.body.newApiKey).not.toBe(originalKey);

    const row = await loadRow(tenant.id);
    expect(row.apiKeyHash).toBe(hashApiKey(r.body.newApiKey));
    expect(row.previousApiKeyHash).toBe(hashApiKey(originalKey));
    expect(row.keyRotatedAt).not.toBeNull();

    const graceMs = new Date(row.previousApiKeyExpiresAt).getTime() - Date.now();
    expect(graceMs).toBeGreaterThan(24 * 60 * MIN - MIN);
    expect(graceMs).toBeLessThanOrEqual(24 * 60 * MIN + 5000);

    expect(email.sendRotatedKeyEmail).toHaveBeenCalledWith(tenant.email, r.body.newApiKey);
  });

  test('T2 the new key works on connect-with-key and is not flagged as deprecated', async () => {
    const { originalKey } = await seed('t2');

    expect((await connect(originalKey)).status).toBe(200);
    const r = await rotate(originalKey);
    expect(r.status).toBe(200);

    const res = await connect(r.body.newApiKey);
    expect(res.status).toBe(200);
    expect(res.headers['x-chargeguard-key-deprecated']).toBeUndefined();
  });

  test('T3 CURRENT BEHAVIOR: previous key is still accepted during grace, with deprecation header', async () => {
    const { originalKey } = await seed('t3');

    expect((await connect(originalKey)).status).toBe(200);
    expect((await rotate(originalKey)).status).toBe(200);

    const res = await connect(originalKey);
    expect(res.status).toBe(200);
    expect(res.headers['x-chargeguard-key-deprecated']).toBe('true');
  });

  test('T4 CURRENT BEHAVIOR (N51): previous key can connect and rotate again; displaced key becomes the previous one', async () => {
    const { tenant, originalKey: k0 } = await seed('t4');

    expect((await connect(k0)).status).toBe(200);
    const r1 = await rotate(k0);
    expect(r1.status).toBe(200);
    const k1 = r1.body.newApiKey;

    // Skip the 5-minute cooldown between rotations.
    await prisma.tenant.update({ where: { id: tenant.id }, data: { keyRotatedAt: ago(10 * MIN) } });

    const c2 = await connect(k0);
    expect(c2.status).toBe(200);
    expect(c2.headers['x-chargeguard-key-deprecated']).toBe('true');
    const r2 = await rotate(k0);
    expect(r2.status).toBe(200);
    const k2 = r2.body.newApiKey;

    const row = await loadRow(tenant.id);
    expect(row.apiKeyHash).toBe(hashApiKey(k2));
    expect(row.previousApiKeyHash).toBe(hashApiKey(k1));

    // k0 was dropped entirely by the second rotation.
    expect((await connect(k0)).status).toBe(401);
  });

  test('T5 rotate without a recent connect is rejected (never connected, then connected 20 minutes ago)', async () => {
    const { tenant, originalKey } = await seed('t5');
    const before = (await loadRow(tenant.id)).apiKeyHash;

    const r1 = await rotate(originalKey);
    expect(r1.status).toBe(403);
    expect(r1.body.code).toBe('RECENT_VERIFICATION_REQUIRED');

    await prisma.tenant.update({ where: { id: tenant.id }, data: { lastConnectVerifiedAt: ago(20 * MIN) } });
    const r2 = await rotate(originalKey);
    expect(r2.status).toBe(403);
    expect(r2.body.code).toBe('RECENT_VERIFICATION_REQUIRED');

    expect((await loadRow(tenant.id)).apiKeyHash).toBe(before);
    expect(email.sendRotatedKeyEmail).not.toHaveBeenCalled();
  });

  test('T6 previous key is rejected once the grace period has expired; current key keeps working', async () => {
    const { tenant, originalKey: k0 } = await seed('t6');

    expect((await connect(k0)).status).toBe(200);
    const r = await rotate(k0);
    expect(r.status).toBe(200);
    const k1 = r.body.newApiKey;

    await prisma.tenant.update({ where: { id: tenant.id }, data: { previousApiKeyExpiresAt: ago(MIN) } });

    expect((await connect(k0)).status).toBe(401);
    const ok = await connect(k1);
    expect(ok.status).toBe(200);
    expect(ok.headers['x-chargeguard-key-deprecated']).toBeUndefined();
  });
});
// KEY-ROTATION-TEST-END