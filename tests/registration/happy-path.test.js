const request = require('supertest');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');

jest.mock('../../src/lib/email');
const email = require('../../src/lib/email');

const prisma = new PrismaClient();

describe('Happy path — registration through email verification (production mode)', () => {
  const testEmail = `happy-path-${Date.now()}@example.com`;
  const testStoreUrl = 'https://example-happy-path-store.com';
  let tenantId;
  let confirmUrl;
  let emailVerifyToken;

  afterAll(async () => {
    if (tenantId) {
      await prisma.tenant.deleteMany({ where: { id: tenantId } });
    }
    await prisma.$disconnect();
  });

  test('Step 1 — registration creates a Tenant with correct pending-verification state', async () => {
    email.sendConfirmationEmail.mockResolvedValue(undefined);

    const res = await request(app)
      .post('/api/risk/tenants/register')
      .send({
        email: testEmail,
        storeUrl: testStoreUrl,
        turnstileToken: 'dummy-token-for-always-pass-testing-secret',
      });

    expect(res.status).toBe(201);
    expect(res.body.verified).toBe(false);
    expect(res.body.requiresVerification).toBe(true);
    // Plaintext key must never appear in the registration response body itself
    expect(JSON.stringify(res.body)).not.toMatch(/[A-Za-z0-9+/]{40,}={0,2}/);

    const tenant = await prisma.tenant.findUnique({ where: { email: testEmail } });
    expect(tenant).not.toBeNull();
    tenantId = tenant.id;

    expect(tenant.plan).toBe('early_access');
    expect(tenant.emailVerified).toBe(false);
    expect(tenant.apiKeyHash).toMatch(/^[0-9a-f]{64}$/);
    expect(tenant.apiKey).not.toBeNull(); // transiently held pre-verification — expected here
    expect(tenant.emailVerifyToken).toMatch(/^[0-9a-f]{64}$/);
    expect(tenant.webhookSecret).toMatch(/^[0-9a-f]{64}$/);
    expect(tenant.allowedDomains).toContain('example-happy-path-store.com');

    const expiresAt = new Date(tenant.emailVerifyExpiresAt).getTime();
    const expectedExpiry = Date.now() + 24 * 60 * 60 * 1000;
    expect(Math.abs(expiresAt - expectedExpiry)).toBeLessThan(60 * 1000); // within 60s tolerance

    emailVerifyToken = tenant.emailVerifyToken;
  });

  test('Step 2 — confirmation email was sent with a matching verification link', () => {
    expect(email.sendConfirmationEmail).toHaveBeenCalledTimes(1);
    const [sentTo, sentConfirmUrl] = email.sendConfirmationEmail.mock.calls[0];

    expect(sentTo).toBe(testEmail);
    expect(sentConfirmUrl).toContain('/api/auth/verify-email?token=');
    expect(sentConfirmUrl).toContain(emailVerifyToken);

    confirmUrl = sentConfirmUrl;
  });

  test('Step 3 — clicking the verification link activates the account and purges the plaintext key', async () => {
    email.sendWelcomeWithKeyEmail.mockResolvedValue(undefined);

    const verifyPath = confirmUrl.replace(/^https?:\/\/[^/]+/, ''); // strip origin, keep path+query
    const res = await request(app).get(verifyPath);

    expect(res.status).toBe(200);
    expect(res.text).toContain("You're all set");

    const tenant = await prisma.tenant.findUnique({ where: { id: tenantId } });
    expect(tenant.emailVerified).toBe(true);
    expect(tenant.emailVerifyToken).toBeNull();
    expect(tenant.emailVerifyExpiresAt).toBeNull();

    // The single most security-critical assertion in the whole suite (§4.1
    // of the original test plan) — plaintext key must be gone immediately
    // after this request completes, synchronously, not dependent on the
    // fire-and-forget welcome email having sent yet.
    expect(tenant.apiKey).toBeNull();
  });

  test('Step 4 — welcome email contains the correct plaintext key, matching apiKeyHash', () => {
    expect(email.sendWelcomeWithKeyEmail).toHaveBeenCalledTimes(1);
    const [sentTo, plaintextKey] = email.sendWelcomeWithKeyEmail.mock.calls[0];

    expect(sentTo).toBe(testEmail);
    expect(typeof plaintextKey).toBe('string');
    expect(plaintextKey.length).toBeGreaterThan(0);
  });

  test('Step 5 — final consolidated state check', async () => {
    const tenant = await prisma.tenant.findUnique({ where: { id: tenantId } });
    const [, plaintextKey] = email.sendWelcomeWithKeyEmail.mock.calls[0];

    // Confirms the key emailed to the merchant actually authenticates them —
    // done via hash comparison, never by storing plaintext for comparison.
    expect(hashApiKey(plaintextKey)).toBe(tenant.apiKeyHash);

    expect(tenant.emailVerified).toBe(true);
    expect(tenant.apiKey).toBeNull();
    expect(tenant.plan).toBe('early_access');
  });
});