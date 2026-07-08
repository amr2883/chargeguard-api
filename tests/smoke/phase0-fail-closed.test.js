const request = require('supertest');

describe('Phase 0 smoke test — fail closed without API_KEY_HASH_SECRET', () => {
  const originalSecret = process.env.API_KEY_HASH_SECRET;

  afterEach(() => {
    process.env.API_KEY_HASH_SECRET = originalSecret;
    jest.resetModules();
  });

  test('registration returns 500 and creates no Tenant row when API_KEY_HASH_SECRET is missing', async () => {
    process.env.API_KEY_HASH_SECRET = ''; // empty, not deleted — see diagnosis notes
    jest.resetModules();

    const app = require('../../src/app');
    const { PrismaClient } = require('@prisma/client');
    const prisma = new PrismaClient();

    const testEmail = `phase0-smoke-${Date.now()}@example.com`;

    const res = await request(app)
      .post('/api/risk/tenants/register')
      .send({
        email: testEmail,
        storeUrl: 'https://example-test-store.com',
        turnstileToken: 'dummy-token-for-always-pass-testing-secret',
      });

    expect(res.status).toBe(500);

    const tenant = await prisma.tenant.findUnique({ where: { email: testEmail } });
    expect(tenant).toBeNull();

    await prisma.$disconnect();
  });
});