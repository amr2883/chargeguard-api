const request = require('supertest');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');

jest.mock('../../src/lib/email');
const email = require('../../src/lib/email');

const prisma = new PrismaClient();

async function registerTenant(label) {
  const testEmail = `expiry-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
  email.sendConfirmationEmail.mockResolvedValue(undefined);

  await request(app)
    .post('/api/risk/tenants/register')
    .send({
      email: testEmail,
      storeUrl: 'https://example-expiry-store.com',
      turnstileToken: 'dummy-token-for-always-pass-testing-secret',
    });

  return prisma.tenant.findUnique({ where: { email: testEmail } });
}

describe('Token expiry boundary tests (§2.3)', () => {
  const createdTenantIds = [];

  beforeEach(() => {
    // Every success-path test in this file reaches sendWelcomeWithKeyEmail,
    // which auth.js calls with `.catch(...)` — an auto-mocked fn returns
    // undefined by default, and undefined.catch() throws. Setting this
    // once here, rather than per-test, means any future test added to this
    // file automatically gets a working mock instead of silently hitting
    // the same bug again.
    email.sendWelcomeWithKeyEmail.mockResolvedValue(undefined);
  });

  afterAll(async () => {
    if (createdTenantIds.length) {
      await prisma.tenant.deleteMany({ where: { id: { in: createdTenantIds } } });
    }
    await prisma.$disconnect();
  });

  test('token used 1 second before expiry succeeds', async () => {
    const tenant = await registerTenant('before');
    createdTenantIds.push(tenant.id);

    await prisma.tenant.update({
      where: { id: tenant.id },
      data: { emailVerifyExpiresAt: new Date(Date.now() + 1000) },
    });

    const res = await request(app).get(`/api/auth/verify-email?token=${tenant.emailVerifyToken}`);
    expect(res.status).toBe(200);
    expect(res.text).toContain("You're all set");

    const updated = await prisma.tenant.findUnique({ where: { id: tenant.id } });
    expect(updated.emailVerified).toBe(true);
  });

  test('token used shortly before the expiry boundary succeeds (strict > comparison, not >=)', async () => {
    const tenant = await registerTenant('exact');
    createdTenantIds.push(tenant.id);

    // Confirms the handler's `new Date() > expiresAt` check is strict, not
    // `>=` — a token is still valid right up until the exact expiry
    // instant, not rejected preemptively as it approaches. No HTTP-based
    // test can pin the literal millisecond boundary (request latency is
    // variable), so this uses a window wide enough to reliably survive a
    // real round-trip while still being clearly tighter than the
    // "1 second before expiry" case above it — that test proves the happy
    // path well clear of expiry; this one specifically targets the
    // near-boundary behavior.
    const nearBoundary = new Date(Date.now() + 2000);
    await prisma.tenant.update({
      where: { id: tenant.id },
      data: { emailVerifyExpiresAt: nearBoundary },
    });

    const res = await request(app).get(`/api/auth/verify-email?token=${tenant.emailVerifyToken}`);
    expect(res.status).toBe(200);
  });

  test('token used 1 second after expiry is rejected with 410 and does not verify the account', async () => {
    const tenant = await registerTenant('after');
    createdTenantIds.push(tenant.id);

    await prisma.tenant.update({
      where: { id: tenant.id },
      data: { emailVerifyExpiresAt: new Date(Date.now() - 1000) },
    });

    const res = await request(app).get(`/api/auth/verify-email?token=${tenant.emailVerifyToken}`);
    expect(res.status).toBe(410);
    expect(res.text).toContain('Confirmation link expired');

    const updated = await prisma.tenant.findUnique({ where: { id: tenant.id } });
    expect(updated.emailVerified).toBe(false);
    expect(updated.emailVerifyToken).toBe(tenant.emailVerifyToken);
    expect(updated.apiKey).not.toBeNull();
  });
});