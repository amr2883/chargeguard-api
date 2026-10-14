const request = require('supertest');
const crypto = require('crypto');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { signV3 } = require('../helpers/signV3');

jest.mock('../../src/lib/email');
const email = require('../../src/lib/email');

const prisma = new PrismaClient();
const createdTenantIds = [];
const originalFlag = process.env.AGENCY_AUTO_REGISTER_ENABLED;

async function seedTenant(label, plan) {
  const apiKey = crypto.randomBytes(32).toString('base64');
  const tenant = await prisma.tenant.create({
    data: {
      email: `ar-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`,
      storeUrl: `https://example-${label}-owner.com`,
      allowedDomains: [],
      webhookSecret: crypto.randomBytes(32).toString('hex'),
      apiKeyHash: hashApiKey(apiKey),
      apiKey: null,
      isActive: true,
      emailVerified: true,
      plan,
    },
  });
  createdTenantIds.push(tenant.id);
  return { tenant, apiKey };
}

function callChallenge({ tenant, apiKey, domain, signer }) {
  const rnd = Math.random().toString(36).slice(2);
  const bodyString = JSON.stringify({ deviceFingerprint: `fp-${rnd}`, email: `buyer-${rnd}@example.com` });
  const headers = signer
    ? signer(tenant.webhookSecret, domain, bodyString)
    : signV3({ secret: tenant.webhookSecret, domain, method: 'POST', target: '/api/risk/challenge/request', body: bodyString });
  return request(app)
    .post('/api/risk/challenge/request')
    .set('Content-Type', 'application/json')
    .set('X-Api-Key', apiKey)
    .set(headers)
    .send(bodyString);
}

function signV1(secret, domain, bodyString) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signature = 'v1=' + crypto.createHmac('sha256', secret).update(`${timestamp}.${bodyString}`).digest('hex');
  return { 'x-store-domain': domain, 'x-chargeguard-signature': signature, 'x-chargeguard-timestamp': timestamp };
}

describe('Agency auto-register, end to end through challenge/request (#58)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    email.sendChallengeOtpEmail.mockResolvedValue(undefined);
    process.env.AGENCY_AUTO_REGISTER_ENABLED = 'true';
  });

  afterAll(async () => {
    if (originalFlag === undefined) delete process.env.AGENCY_AUTO_REGISTER_ENABLED;
    else process.env.AGENCY_AUTO_REGISTER_ENABLED = originalFlag;
    if (createdTenantIds.length) {
      await prisma.tenant.deleteMany({ where: { id: { in: createdTenantIds } } });
    }
    await prisma.$disconnect();
  }, 60000);

  test('A1: Agency + flag on + new domain + v3 signature: accepted and an active Store is created', async () => {
    const t = await seedTenant('a1', 'agency');
    const domain = 'example-a1-client.com';
    const res = await callChallenge({ ...t, domain });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    const stores = await prisma.store.findMany({ where: { tenantId: t.tenant.id } });
    expect(stores).toHaveLength(1);
    expect(stores[0].normalizedDomain).toBe(domain);
    expect(stores[0].isActive).toBe(true);
  });

  test('A2: flag off: rejected 403 DOMAIN_MISMATCH, no Store', async () => {
    process.env.AGENCY_AUTO_REGISTER_ENABLED = 'false';
    const t = await seedTenant('a2', 'agency');
    const res = await callChallenge({ ...t, domain: 'example-a2-client.com' });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('DOMAIN_MISMATCH');
    expect(await prisma.store.count({ where: { tenantId: t.tenant.id } })).toBe(0);
  });

  test('A3: v1 signature (not domain-bound): rejected, no Store', async () => {
    const t = await seedTenant('a3', 'agency');
    const res = await callChallenge({ ...t, domain: 'example-a3-client.com', signer: signV1 });
    expect(res.status).toBe(403);
    expect(await prisma.store.count({ where: { tenantId: t.tenant.id } })).toBe(0);
  });

  test('A4: non-Agency tenant with an unregistered domain: rejected 403, no Store', async () => {
    const t = await seedTenant('a4', 'early_access');
    const res = await callChallenge({ ...t, domain: 'example-a4-client.com' });
    expect(res.status).toBe(403);
    expect(await prisma.store.count({ where: { tenantId: t.tenant.id } })).toBe(0);
  });
});