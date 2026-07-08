const request = require('supertest');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');

jest.mock('../../src/lib/email');
const email = require('../../src/lib/email');

const prisma = new PrismaClient();

async function registerTenant(label, overrides = {}) {
  const testEmail = overrides.email ?? `neg-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
  email.sendConfirmationEmail.mockResolvedValue(undefined);
  email.sendWelcomeWithKeyEmail.mockResolvedValue(undefined);

  const res = await request(app)
    .post('/api/risk/tenants/register')
    .send({
      email: testEmail,
      storeUrl: overrides.storeUrl ?? 'https://example-negative-store.com',
      turnstileToken: overrides.turnstileToken ?? 'dummy-token-for-always-pass-testing-secret',
    });

  return { res, testEmail };
}

describe('Negative & edge-case tests (§3.2)', () => {
  const createdTenantIds = [];

  beforeEach(() => {
    // Clear call history so each test's assertions on call counts
    // are isolated from previous tests in this file.
    email.sendWelcomeWithKeyEmail.mockClear();
    email.sendConfirmationEmail.mockClear();
  });

  afterAll(async () => {
    if (createdTenantIds.length) {
      await prisma.tenant.deleteMany({ where: { id: { in: createdTenantIds } } });
    }
    await prisma.$disconnect();
  });

  // ── §3.2 #4 — duplicate email ──────────────────────────────────────────
  test('registering an already-registered email returns 400 and creates no second row', async () => {
    const { testEmail } = await registerTenant('dup');
    const first = await prisma.tenant.findUnique({ where: { email: testEmail } });
    createdTenantIds.push(first.id);

    const { res: secondRes } = await registerTenant('dup', { email: testEmail });
    expect(secondRes.status).toBe(400);
    expect(secondRes.body.error).toMatch(/already registered/i);

    const count = await prisma.tenant.count({ where: { email: testEmail } });
    expect(count).toBe(1);
  });

  // ── §3.2 #2 — malformed/garbage token ──────────────────────────────────
  test.each([
    ['too-short-hex', 'abc123'],
    ['non-hex-characters', 'zz'.repeat(32)],
    ['sql-injection-shaped', "' OR '1'='1"],
    ['empty-string', ''],
  ])('malformed token (%s) is rejected without a server error', async (_label, badToken) => {
    const res = await request(app).get(`/api/auth/verify-email?token=${encodeURIComponent(badToken)}`);
    expect([400, 404]).toContain(res.status);
    expect(res.status).not.toBe(500);
  });

  // ── §3.2 #3 / #10 — sequential reuse of an already-consumed token ─────
  test('reusing a token after successful verification returns 404, not "already verified" — token is nulled, not merely flagged', async () => {
    const { testEmail } = await registerTenant('reuse');
    const tenant = await prisma.tenant.findUnique({ where: { email: testEmail } });
    createdTenantIds.push(tenant.id);

    const firstVerify = await request(app).get(`/api/auth/verify-email?token=${tenant.emailVerifyToken}`);
    expect(firstVerify.status).toBe(200);

    const secondVerify = await request(app).get(`/api/auth/verify-email?token=${tenant.emailVerifyToken}`);
    // Documenting actual behavior: since the token is nulled (not just
    // flagged) on first success, a second click with the same token value
    // no longer matches any row — it hits the generic "not found" branch,
    // not the dedicated "Already Verified" page.
    expect(secondVerify.status).toBe(404);
    expect(secondVerify.text).toContain('already used or invalid');

    // Only one welcome email should ever have been sent, regardless.
    expect(email.sendWelcomeWithKeyEmail).toHaveBeenCalledTimes(1);
  });

  // ── Race condition — two near-simultaneous verify requests ────────────
  test('two concurrent verification requests for the same token result in exactly one successful verification', async () => {
    const { testEmail } = await registerTenant('race');
    const tenant = await prisma.tenant.findUnique({ where: { email: testEmail } });
    createdTenantIds.push(tenant.id);

    const [resA, resB] = await Promise.all([
      request(app).get(`/api/auth/verify-email?token=${tenant.emailVerifyToken}`),
      request(app).get(`/api/auth/verify-email?token=${tenant.emailVerifyToken}`),
    ]);

    // Both responses return 200 by design — the winner sees the "You're
    // all set" first-verification page, the loser sees the "Already
    // Verified" page (added by the atomic updateMany fix). Status codes
    // alone can no longer distinguish winner from loser, so we assert on
    // page content and side effects instead.
    expect(resA.status).toBe(200);
    expect(resB.status).toBe(200);

    const bodies = [resA.text, resB.text];
    const winnerCount = bodies.filter(t => t.includes("You're all set")).length;
    const loserCount = bodies.filter(t => t.includes('Account already active')).length;

    expect(winnerCount).toBe(1);
    expect(loserCount).toBe(1);

    // The real invariant this test protects: exactly one welcome email
    // sent, exactly one plaintext-key delivery, regardless of the race.
    expect(email.sendWelcomeWithKeyEmail).toHaveBeenCalledTimes(1);

    const finalTenant = await prisma.tenant.findUnique({ where: { id: tenant.id } });
    expect(finalTenant.emailVerified).toBe(true);
    expect(finalTenant.apiKey).toBeNull();
  });

  // ── §3.2 #5 — missing Turnstile token ──────────────────────────────────
  test('registration without a Turnstile token is rejected before any DB write', async () => {
    const testEmail = `neg-noturnstile-${Date.now()}@example.com`;
    const res = await request(app)
      .post('/api/risk/tenants/register')
      .send({ email: testEmail, storeUrl: 'https://example.com' }); // no turnstileToken field at all

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/security check token missing/i);

    const tenant = await prisma.tenant.findUnique({ where: { email: testEmail } });
    expect(tenant).toBeNull();
  });

  // ── §3.2 #6 — invalid Turnstile token ──────────────────────────────────
  test('registration with an invalid Turnstile token is rejected (403)', async () => {
    const originalSecret = process.env.TURNSTILE_SECRET_KEY;
    // Cloudflare's documented "always fails" testing secret key.
    process.env.TURNSTILE_SECRET_KEY = '2x0000000000000000000000000000000AA';

    try {
      const testEmail = `neg-badturnstile-${Date.now()}@example.com`;
      const res = await request(app)
        .post('/api/risk/tenants/register')
        .send({
          email: testEmail,
          storeUrl: 'https://example.com',
          turnstileToken: 'any-non-empty-value',
        });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/security check failed/i);

      const tenant = await prisma.tenant.findUnique({ where: { email: testEmail } });
      expect(tenant).toBeNull();
    } finally {
      process.env.TURNSTILE_SECRET_KEY = originalSecret;
    }
  });

  // ── §3.2 #7 — invalid email format ─────────────────────────────────────
  describe('email format validation (documents actual — weak — current behavior)', () => {
    test('missing email is rejected', async () => {
      const res = await request(app)
        .post('/api/risk/tenants/register')
        .send({ turnstileToken: 'dummy-token-for-always-pass-testing-secret' });
      expect(res.status).toBe(400);
    });

    test('email with no "@" is rejected', async () => {
      const res = await request(app)
        .post('/api/risk/tenants/register')
        .send({ email: 'not-an-email', turnstileToken: 'dummy-token-for-always-pass-testing-secret' });
      expect(res.status).toBe(400);
    });

    // NOTE: these three currently SUCCEED under the real validation
    // (`!email.includes('@')` is the entire check — no domain/TLD
    // requirement). This is a known gap, documented here rather than
    // silently patched. Flag for a product decision on whether to harden
    // this check before these tests are treated as final.
    test.each([
      ['bare-at-sign', '@'],
      ['nothing-after-at', 'user@'],
      ['nothing-before-at', '@example.com'],
    ])('email "%s" (%s) currently passes validation — documented gap, not a hardened assertion', async (_label, looseEmail) => {
      const { res, testEmail } = await registerTenant('loose-email', {
        email: `${looseEmail}-${Date.now()}`, // suffixed to avoid unique-constraint collisions across reruns
      });
      expect(res.status).toBe(201);

      const tenant = await prisma.tenant.findUnique({ where: { email: testEmail } });
      if (tenant) createdTenantIds.push(tenant.id);
    });
  });

  // ── §3.2 #8 — rate limiting ─────────────────────────────────────────────
  test('6th registration attempt within the window is rate-limited; first 5 process normally', async () => {
    const results = [];
    for (let i = 0; i < 6; i++) {
      const { res, testEmail } = await registerTenant(`ratelimit-${i}`);
      results.push(res.status);
      if (res.status === 201) {
        const tenant = await prisma.tenant.findUnique({ where: { email: testEmail } });
        if (tenant) createdTenantIds.push(tenant.id);
      }
    }

    expect(results.slice(0, 5)).toEqual([201, 201, 201, 201, 201]);
    expect(results[5]).toBe(429);
  });

  // ── §3.2 #9 — honeypot ──────────────────────────────────────────────────
  test('honeypot-filled submission is silently rejected — no Tenant row created', async () => {
    const testEmail = `honeypot-${Date.now()}@example.com`;

    const res = await request(app)
      .post('/api/risk/tenants/register')
      .send({
        email: testEmail,
        storeUrl: 'https://example.com',
        turnstileToken: 'dummy-token-for-always-pass-testing-secret',
        website: 'http://spam-bot-filled-this-field.com', // honeypot field
      });

    expect(res.status).toBe(200);
    expect(res.body.verified).toBe(false);

    const tenant = await prisma.tenant.findUnique({ where: { email: testEmail } });
    expect(tenant).toBeNull();

    // Confirm no email was sent either — a bot hitting the honeypot
    // shouldn't trigger any outbound Gmail API call.
    expect(email.sendConfirmationEmail).not.toHaveBeenCalled();
  });
});