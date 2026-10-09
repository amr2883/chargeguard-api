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

  // Warm-up: the first /connect in a fresh process pays one-time costs (two
  // Prisma connections, cold query paths). Measured ~13s on this machine for
  // the first test, against the 15s per-test limit. This runs the same
  // operations once, under an explicit hook timeout, so the per-test limit
  // only catches steady-state slowness. Its rate-limit row is cleared by the
  // global beforeEach reset before the first test.
  beforeAll(async () => {
    email.sendConfirmationEmail.mockResolvedValue(undefined);
    const { tenant, domain } = await seedConnectableTenant('warmup');
    createdTenantIds.push(tenant.id);
    await request(app)
      .post('/api/auth/connect')
      .send({ email: tenant.email, siteUrl: `https://${domain}`, turnstileToken: TURNSTILE_ALWAYS_PASS });
  }, 60000);
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

    test('GET /connect/confirm issues a new apiKey (browser gets HTML only); the plugin collects it once via GET /connect/status', async () => {
      const { tenant } = await seedConnectableTenant('confirm');
      createdTenantIds.push(tenant.id);
      const oldApiKeyHash = tenant.apiKeyHash;
      const oldWebhookSecret = tenant.webhookSecret;

      const connectRes = await request(app)
        .post('/api/auth/connect')
        .send({ email: tenant.email, turnstileToken: TURNSTILE_ALWAYS_PASS });
      const requestId = connectRes.body.connectRequestId;
      expect(typeof requestId).toBe('string');
      expect(requestId.length).toBeGreaterThan(0);

      const withToken = await prisma.tenant.findUnique({ where: { id: tenant.id } });

      // Step 1: browser click on the emailed link. HTML only, no credentials.
      const confirmRes = await request(app).get(`/api/auth/connect/confirm?token=${withToken.connectToken}`);
      expect(confirmRes.status).toBe(200);
      expect(confirmRes.headers['content-type']).toMatch(/text\/html/);

      const afterConfirm = await prisma.tenant.findUnique({ where: { id: tenant.id } });
      expect(afterConfirm.connectToken).toBeNull();
      expect(afterConfirm.connectTokenExpiresAt).toBeNull();
      expect(afterConfirm.apiKeyHash).not.toBe(oldApiKeyHash); // rotated
      expect(afterConfirm.keyRotatedAt).not.toBeNull();
      // Plaintext is staged (not permanent) until the plugin collects it.
      expect(typeof afterConfirm.apiKey).toBe('string');
      expect(afterConfirm.apiKey.length).toBeGreaterThan(0);
      expect(hashApiKey(afterConfirm.apiKey)).toBe(afterConfirm.apiKeyHash);
      // The browser-facing page must never contain the key.
      expect(confirmRes.text).not.toContain(afterConfirm.apiKey);

      // Step 2: plugin polls /status and receives the credentials once.
      const statusUrl = `/api/auth/connect/status?requestId=${encodeURIComponent(requestId)}`;
      const statusRes = await request(app).get(statusUrl);
      expect(statusRes.status).toBe(200);
      expect(statusRes.body.status).toBe('active');
      expect(statusRes.body.merchantId).toBe(tenant.id);
      expect(statusRes.body.email).toBe(tenant.email);
      expect(statusRes.body.webhookSecret).toBe(oldWebhookSecret); // preserved, not rotated
      expect(statusRes.body.apiKey).toBe(afterConfirm.apiKey);
      expect(hashApiKey(statusRes.body.apiKey)).toBe(afterConfirm.apiKeyHash);

      // After delivery: plaintext and requestId are purged, hash unchanged.
      const afterStatus = await prisma.tenant.findUnique({ where: { id: tenant.id } });
      expect(afterStatus.apiKey).toBeNull();
      expect(afterStatus.connectRequestId).toBeNull();
      expect(afterStatus.apiKeyHash).toBe(afterConfirm.apiKeyHash);

      // Step 3: delivery is one-time. Same requestId now yields pending, no key.
      const again = await request(app).get(statusUrl);
      expect(again.status).toBe(200);
      expect(again.body.status).toBe('pending');
      expect(again.body.apiKey).toBeUndefined();
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
      liveApiKey = (await request(app).get(`/api/auth/connect/status?requestId=${withToken.connectRequestId}`)).body.apiKey;
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
      liveApiKey = (await request(app).get(`/api/auth/connect/status?requestId=${withToken.connectRequestId}`)).body.apiKey;
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

    test('a missing signature with a valid timestamp is rejected (401)', async () => {
      const bodyString = JSON.stringify({ type: 'EMAIL', value: `nosig-${Date.now()}@example.com` });
      const { timestamp } = signRequest(liveTenant.webhookSecret, bodyString);

      const res = await request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', liveApiKey)
        .set('X-Store-Domain', liveDomain)
        .set('X-ChargeGuard-Timestamp', timestamp)
        .send(bodyString);

      expect(res.status).toBe(401);
    });

    test('a missing timestamp with a signature present is rejected (401)', async () => {
      const bodyString = JSON.stringify({ type: 'EMAIL', value: `nots-${Date.now()}@example.com` });
      const { signature } = signRequest(liveTenant.webhookSecret, bodyString);

      const res = await request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', liveApiKey)
        .set('X-Store-Domain', liveDomain)
        .set('X-ChargeGuard-Signature', signature)
        .send(bodyString);

      expect(res.status).toBe(401);
    });
  });
  
  // ── /connect/status edge cases ────────────────────────────────────────
  describe('GET /connect/status edge cases', () => {
    const randomRequestId = () => crypto.randomBytes(32).toString('hex');
    const INVALID_BODY = { status: 'invalid', error: 'requestId is required' };

    test('a missing requestId is rejected with 400', async () => {
      const res = await request(app).get('/api/auth/connect/status');

      expect(res.status).toBe(400);
      expect(res.body).toEqual(INVALID_BODY);
    });

    test('a non-string requestId (repeated query parameter) is rejected with 400', async () => {
      const res = await request(app).get('/api/auth/connect/status?requestId=a&requestId=b');

      expect(res.status).toBe(400);
      expect(res.body).toEqual(INVALID_BODY);
    });

    test('an unknown requestId returns exactly {status: "pending"}', async () => {
      const res = await request(app).get(`/api/auth/connect/status?requestId=${randomRequestId()}`);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: 'pending' });
    });

    test('a known requestId before confirmation is indistinguishable from an unknown one', async () => {
      const { tenant } = await seedConnectableTenant('statuspending');
      createdTenantIds.push(tenant.id);

      const connectRes = await request(app)
        .post('/api/auth/connect')
        .send({ email: tenant.email, turnstileToken: TURNSTILE_ALWAYS_PASS });
      const requestId = connectRes.body.connectRequestId;
      expect(typeof requestId).toBe('string');

      // Guard: the id really is a known one (stored on the tenant).
      const stored = await prisma.tenant.findUnique({ where: { id: tenant.id } });
      expect(stored.connectRequestId).toBe(requestId);

      const known = await request(app).get(`/api/auth/connect/status?requestId=${requestId}`);
      const unknown = await request(app).get(`/api/auth/connect/status?requestId=${randomRequestId()}`);

      expect(known.status).toBe(unknown.status);
      expect(known.body).toEqual(unknown.body);
      expect(known.body).toEqual({ status: 'pending' });
    });

    test('a known requestId whose connect token has expired returns {status: "expired"}', async () => {
      const { tenant } = await seedConnectableTenant('statusexpired');
      createdTenantIds.push(tenant.id);

      const connectRes = await request(app)
        .post('/api/auth/connect')
        .send({ email: tenant.email, turnstileToken: TURNSTILE_ALWAYS_PASS });
      const requestId = connectRes.body.connectRequestId;
      expect(typeof requestId).toBe('string');

      await prisma.tenant.update({
        where: { id: tenant.id },
        data: { connectTokenExpiresAt: new Date(Date.now() - 1000) },
      });

      const res = await request(app).get(`/api/auth/connect/status?requestId=${requestId}`);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: 'expired' });
    });
  });
});
