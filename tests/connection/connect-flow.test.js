const request = require('supertest');
const crypto = require('crypto');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');

jest.mock('../../src/lib/email');
const email = require('../../src/lib/email');

const prisma = new PrismaClient();

const TURNSTILE_ALWAYS_PASS = 'dummy-token-for-always-pass-testing-secret';
const TURNSTILE_ALWAYS_FAIL_SECRET = '2x0000000000000000000000000000000AA';

// Builds the same signed-string HMAC the PHP plugin's ChargeGuard_API_Client
// and Node's verifyHmac.js both construct: `${timestamp}.${rawBody}`,
// signed as 'v1=' + HMAC-SHA256(secret, signedStr) hex.
function signRequest(secret, bodyString) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signedStr = `${timestamp}.${bodyString}`;
  const signature = 'v1=' + crypto.createHmac('sha256', secret).update(signedStr).digest('hex');
  return { timestamp, signature };
}

// Directly seeds a verified, already-onboarded tenant — bypassing the T1
// registration flow entirely, since T2 is testing key recovery for a
// tenant that already has a key, not first-time registration.
async function seedConnectableTenant(label) {
  const testEmail = `connect-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
  const originalKey = crypto.randomBytes(32).toString('base64');
  const domain = `example-${label}-store.com`;

  const tenant = await prisma.tenant.create({
    data: {
      email: testEmail,
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

  return { tenant, domain, originalKey };
}

describe('Plugin Connection — /connect + /connect/confirm (T2)', () => {
  const createdTenantIds = [];

  afterAll(async () => {
    if (createdTenantIds.length) {
      await prisma.tenant.deleteMany({ where: { id: { in: createdTenantIds } } });
    }
    await prisma.$disconnect();
  });

  beforeEach(() => {
    jest.clearAllMocks();
    email.sendConfirmationEmail.mockResolvedValue(undefined);
  });

  // ── Positive path ─────────────────────────────────────────────────────
  describe('positive path', () => {
    test('POST /connect for a registered, verified tenant issues a connect token and sends the email', async () => {
      const { tenant, domain } = await seedConnectableTenant('happy');
      createdTenantIds.push(tenant.id);

      const res = await request(app)
        .post('/api/auth/connect')
        .send({ email: tenant.email, siteUrl: `https://${domain}`, turnstileToken: TURNSTILE_ALWAYS_PASS });

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/connect link has been sent/i);

      const updated = await prisma.tenant.findUnique({ where: { id: tenant.id } });
      expect(updated.connectToken).toMatch(/^[0-9a-f]{64}$/);
      const expiresAt = new Date(updated.connectTokenExpiresAt).getTime();
      expect(Math.abs(expiresAt - (Date.now() + 15 * 60 * 1000))).toBeLessThan(60 * 1000);

      expect(email.sendConfirmationEmail).toHaveBeenCalledTimes(1);
      const [sentTo, confirmUrl] = email.sendConfirmationEmail.mock.calls[0];
      expect(sentTo).toBe(tenant.email);
      expect(confirmUrl).toContain('/api/auth/connect/confirm?token=');
      expect(confirmUrl).toContain(updated.connectToken);
    });

    test('GET /connect/confirm issues a brand-new apiKey + webhookSecret, returned in the JSON body (by design — this endpoint differs from /verify-email)', async () => {
      const { tenant } = await seedConnectableTenant('confirm');
      createdTenantIds.push(tenant.id);
      const oldApiKeyHash = tenant.apiKeyHash;
      const oldWebhookSecret = tenant.webhookSecret;

      await request(app)
        .post('/api/auth/connect')
        .send({ email: tenant.email, turnstileToken: TURNSTILE_ALWAYS_PASS });

      const withToken = await prisma.tenant.findUnique({ where: { id: tenant.id } });

      const res = await request(app).get(`/api/auth/connect/confirm?token=${withToken.connectToken}`);

      expect(res.status).toBe(200);
      expect(res.body.merchantId).toBe(tenant.id);
      expect(res.body.email).toBe(tenant.email);
      // Unlike /verify-email, this response DOES carry the plaintext key —
      // intentional, since /connect already proved inbox ownership and no
      // separate delivery email is sent for this recovery flow.
      expect(typeof res.body.apiKey).toBe('string');
      expect(res.body.apiKey.length).toBeGreaterThan(0);
      expect(res.body.webhookSecret).toBe(oldWebhookSecret); // preserved, not rotated

      const final = await prisma.tenant.findUnique({ where: { id: tenant.id } });
      expect(final.connectToken).toBeNull();
      expect(final.connectTokenExpiresAt).toBeNull();
      expect(final.apiKey).toBeNull(); // plaintext never persisted, same invariant as T1
      expect(final.apiKeyHash).not.toBe(oldApiKeyHash); // rotated
      expect(hashApiKey(res.body.apiKey)).toBe(final.apiKeyHash);
      expect(final.keyRotatedAt).not.toBeNull();
    });
  });

  // ── Negative paths ────────────────────────────────────────────────────
  describe('negative paths', () => {
    test('POST /connect for an unregistered email returns the same generic response (no enumeration signal)', async () => {
      const res = await request(app)
        .post('/api/auth/connect')
        .send({ email: `nonexistent-${Date.now()}@example.com`, turnstileToken: TURNSTILE_ALWAYS_PASS });

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/if this email is registered/i);
      expect(email.sendConfirmationEmail).not.toHaveBeenCalled();
    });

    test('GET /connect/confirm with an invalid token returns 401', async () => {
      const res = await request(app).get('/api/auth/connect/confirm?token=' + 'f'.repeat(64));
      expect(res.status).toBe(401);
    });

    test('GET /connect/confirm with an expired token returns 410 and does not rotate the key', async () => {
      const { tenant } = await seedConnectableTenant('expired');
      createdTenantIds.push(tenant.id);
      const oldApiKeyHash = tenant.apiKeyHash;

      await request(app)
        .post('/api/auth/connect')
        .send({ email: tenant.email, turnstileToken: TURNSTILE_ALWAYS_PASS });

      const withToken = await prisma.tenant.findUnique({ where: { id: tenant.id } });
      await prisma.tenant.update({
        where: { id: tenant.id },
        data: { connectTokenExpiresAt: new Date(Date.now() - 1000) },
      });

      const res = await request(app).get(`/api/auth/connect/confirm?token=${withToken.connectToken}`);
      expect(res.status).toBe(410);

      const final = await prisma.tenant.findUnique({ where: { id: tenant.id } });
      expect(final.apiKeyHash).toBe(oldApiKeyHash); // untouched
    });

    test('POST /connect without a Turnstile token is rejected before any token is issued', async () => {
      const { tenant } = await seedConnectableTenant('noturnstile');
      createdTenantIds.push(tenant.id);

      const res = await request(app).post('/api/auth/connect').send({ email: tenant.email });
      expect(res.status).toBe(400);

      const unchanged = await prisma.tenant.findUnique({ where: { id: tenant.id } });
      expect(unchanged.connectToken).toBeNull();
    });

    test('POST /connect with an invalid Turnstile token is rejected (403)', async () => {
      const originalSecret = process.env.TURNSTILE_SECRET_KEY;
      process.env.TURNSTILE_SECRET_KEY = TURNSTILE_ALWAYS_FAIL_SECRET;
      try {
        const { tenant } = await seedConnectableTenant('badturnstile');
        createdTenantIds.push(tenant.id);

        const res = await request(app)
          .post('/api/auth/connect')
          .send({ email: tenant.email, turnstileToken: 'any-non-empty-value' });
        expect(res.status).toBe(403);
      } finally {
        process.env.TURNSTILE_SECRET_KEY = originalSecret;
      }
    });

    test('4th /connect attempt within 15 minutes is rate-limited; first 3 succeed', async () => {
      const { tenant } = await seedConnectableTenant('ratelimit');
      createdTenantIds.push(tenant.id);

      const results = [];
      for (let i = 0; i < 4; i++) {
        const res = await request(app)
          .post('/api/auth/connect')
          .send({ email: tenant.email, turnstileToken: TURNSTILE_ALWAYS_PASS });
        results.push(res.status);
      }
      expect(results.slice(0, 3)).toEqual([200, 200, 200]);
      expect(results[3]).toBe(429);
    });
  });

  // ── Security: domain enforcement ──────────────────────────────────────
  describe('domain enforcement (domainAuthMiddleware)', () => {
    let liveTenant, liveApiKey, liveDomain;

    beforeAll(async () => {
      // Clear rate-limit table explicitly — beforeAll runs before
      // beforeEach, so the global reset hasn't fired yet.
      await prisma.connectAttempt.deleteMany({});

      const { tenant, domain } = await seedConnectableTenant('domaincheck');
      createdTenantIds.push(tenant.id);

      await request(app).post('/api/auth/connect').send({ email: tenant.email, turnstileToken: TURNSTILE_ALWAYS_PASS });
      const withToken = await prisma.tenant.findUnique({ where: { id: tenant.id } });
      const confirmRes = await request(app).get(`/api/auth/connect/confirm?token=${withToken.connectToken}`);

      liveTenant = tenant;
      liveApiKey = confirmRes.body.apiKey;
      liveDomain = domain;

      if (!liveApiKey) {
        throw new Error('Fixture setup failed: /connect or /connect/confirm did not return an apiKey — check for rate-limiting or token issues before this describe block runs.');
      }
    });

    test('request with the correct X-Store-Domain and a valid HMAC signature is accepted', async () => {
      const bodyObj = { type: 'EMAIL', value: `whitelist-test-${Date.now()}@example.com` };
      const bodyString = JSON.stringify(bodyObj);
      const { timestamp, signature } = signRequest(liveTenant.webhookSecret, bodyString);

      const res = await request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', liveApiKey)
        .set('X-Store-Domain', liveDomain)
        .set('X-ChargeGuard-Signature', signature)
        .set('X-ChargeGuard-Timestamp', timestamp)
        .send(bodyString);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    test('request with a mismatched X-Store-Domain is rejected by domainAuthMiddleware (403), before HMAC is even checked', async () => {
      const bodyObj = { type: 'EMAIL', value: `domain-mismatch-${Date.now()}@example.com` };
      const bodyString = JSON.stringify(bodyObj);
      const { timestamp, signature } = signRequest(liveTenant.webhookSecret, bodyString);

      const res = await request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', liveApiKey)
        .set('X-Store-Domain', 'totally-different-domain.com')
        .set('X-ChargeGuard-Signature', signature)
        .set('X-ChargeGuard-Timestamp', timestamp)
        .send(bodyString);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOMAIN_MISMATCH');
    });
  });

  // ── Security: HMAC enforcement ─────────────────────────────────────────
  describe('HMAC signature enforcement (verifyHmacSignature)', () => {
    let liveTenant, liveApiKey, liveDomain;

    beforeAll(async () => {
      // beforeAll runs before this block's first beforeEach, so the global
      // rate-limit reset in tests/setup/resetRateLimits.js hasn't fired yet.
      await prisma.connectAttempt.deleteMany({});

      const { tenant, domain } = await seedConnectableTenant('hmaccheck');
      createdTenantIds.push(tenant.id);

      await request(app).post('/api/auth/connect').send({ email: tenant.email, turnstileToken: TURNSTILE_ALWAYS_PASS });
      const withToken = await prisma.tenant.findUnique({ where: { id: tenant.id } });
      const confirmRes = await request(app).get(`/api/auth/connect/confirm?token=${withToken.connectToken}`);

      liveTenant = tenant;
      liveApiKey = confirmRes.body.apiKey;
      liveDomain = domain;

      if (!liveApiKey) {
        throw new Error('Fixture setup failed: /connect or /connect/confirm did not return an apiKey — check for rate-limiting or token issues before this describe block runs.');
      }
    });

    test('missing signature headers are rejected (401)', async () => {
      const bodyString = JSON.stringify({ type: 'EMAIL', value: `nohmac-${Date.now()}@example.com` });

      const res = await request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', liveApiKey)
        .set('X-Store-Domain', liveDomain)
        .send(bodyString);

      expect(res.status).toBe(401);
    });

    test('a tampered signature is rejected (401)', async () => {
      const bodyObj = { type: 'EMAIL', value: `tampered-${Date.now()}@example.com` };
      const bodyString = JSON.stringify(bodyObj);
      const { timestamp, signature } = signRequest(liveTenant.webhookSecret, bodyString);
      const tamperedSignature = signature.slice(0, -4) + 'dead'; // flip the last 4 hex chars

      const res = await request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', liveApiKey)
        .set('X-Store-Domain', liveDomain)
        .set('X-ChargeGuard-Signature', tamperedSignature)
        .set('X-ChargeGuard-Timestamp', timestamp)
        .send(bodyString);

      expect(res.status).toBe(401);
    });

    test('a stale timestamp (older than the 300s tolerance) is rejected (401)', async () => {
      const bodyObj = { type: 'EMAIL', value: `stale-${Date.now()}@example.com` };
      const bodyString = JSON.stringify(bodyObj);
      const staleTimestamp = String(Math.floor(Date.now() / 1000) - 400); // 400s old, beyond the 300s window
      const signedStr = `${staleTimestamp}.${bodyString}`;
      const signature = 'v1=' + crypto.createHmac('sha256', liveTenant.webhookSecret).update(signedStr).digest('hex');

      const res = await request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', liveApiKey)
        .set('X-Store-Domain', liveDomain)
        .set('X-ChargeGuard-Signature', signature)
        .set('X-ChargeGuard-Timestamp', staleTimestamp)
        .send(bodyString);

      expect(res.status).toBe(401);
    });
  });
});