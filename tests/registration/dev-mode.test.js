const request = require('supertest');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');

jest.mock('../../src/lib/email');
const email = require('../../src/lib/email');

const prisma = new PrismaClient();

describe('Dev mode — EMAIL_VERIFICATION_DISABLED=true (§2.4)', () => {
  const createdTenantIds = [];
  let originalFlag;

  beforeAll(() => {
    originalFlag = process.env.EMAIL_VERIFICATION_DISABLED;
    // Read live inside the route handler on every request (not cached at
    // module load, same pattern as API_KEY_HASH_SECRET), so a plain
    // process.env override here is sufficient — no need to run this as a
    // fully separate process invocation, contrary to what the original
    // plan assumed for this section.
    process.env.EMAIL_VERIFICATION_DISABLED = 'true';
  });

  afterAll(async () => {
    process.env.EMAIL_VERIFICATION_DISABLED = originalFlag;
    if (createdTenantIds.length) {
      await prisma.tenant.deleteMany({ where: { id: { in: createdTenantIds } } });
    }
    await prisma.$disconnect();
  });

  beforeEach(() => {
    jest.clearAllMocks();
    email.sendApiKeyEmail.mockResolvedValue(undefined);
    email.sendConfirmationEmail.mockResolvedValue(undefined);
  });

  test('registration immediately verifies the tenant and sends the key via email — not in the HTTP response', async () => {
    const testEmail = `devmode-${Date.now()}@example.com`;

    const res = await request(app)
      .post('/api/risk/tenants/register')
      .send({
        email: testEmail,
        storeUrl: 'https://example-devmode-store.com',
        turnstileToken: 'dummy-token-for-always-pass-testing-secret',
      });

    expect(res.status).toBe(201);
    expect(res.body.verified).toBe(true);
    expect(res.body).not.toHaveProperty('apiKey');

    const tenant = await prisma.tenant.findUnique({ where: { email: testEmail } });
    expect(tenant).not.toBeNull();
    createdTenantIds.push(tenant.id);

    expect(tenant.emailVerified).toBe(true);
    expect(tenant.emailVerifyToken).toBeNull();
    expect(tenant.emailVerifyExpiresAt).toBeNull();
    // Plaintext never persists, even on the dev-mode path.
    expect(tenant.apiKey).toBeNull();
    expect(tenant.apiKeyHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('confirmation email is never sent in dev mode — only the direct API-key email', async () => {
    const testEmail = `devmode-noconfirm-${Date.now()}@example.com`;

    await request(app)
      .post('/api/risk/tenants/register')
      .send({
        email: testEmail,
        storeUrl: 'https://example-devmode-store.com',
        turnstileToken: 'dummy-token-for-always-pass-testing-secret',
      });

    const tenant = await prisma.tenant.findUnique({ where: { email: testEmail } });
    createdTenantIds.push(tenant.id);

    expect(email.sendConfirmationEmail).not.toHaveBeenCalled();
    expect(email.sendApiKeyEmail).toHaveBeenCalledTimes(1);
  });

  test('the key emailed via sendApiKeyEmail matches the stored apiKeyHash', async () => {
    const testEmail = `devmode-keymatch-${Date.now()}@example.com`;

    await request(app)
      .post('/api/risk/tenants/register')
      .send({
        email: testEmail,
        storeUrl: 'https://example-devmode-store.com',
        turnstileToken: 'dummy-token-for-always-pass-testing-secret',
      });

    const tenant = await prisma.tenant.findUnique({ where: { email: testEmail } });
    createdTenantIds.push(tenant.id);

    const [sentTo, plaintextKey] = email.sendApiKeyEmail.mock.calls[0];
    expect(sentTo).toBe(testEmail);
    expect(hashApiKey(plaintextKey)).toBe(tenant.apiKeyHash);
  });

  test('/verify-email is a no-op dead end in dev mode — no token exists to hit it with', async () => {
    // Since emailVerifyToken is null for dev-mode tenants, there is no
    // valid link to click. This confirms attempting the endpoint with a
    // garbage token behaves the same as any other malformed-token case —
    // it does not accidentally "verify" anything a second time.
    const res = await request(app).get('/api/auth/verify-email?token=0'.padEnd(65, '0'));
    expect(res.status).toBe(404);
  });
});