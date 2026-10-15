const request = require('supertest');
const crypto = require('crypto');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { signV3 } = require('../helpers/signV3');

jest.mock('../../src/lib/email');
const email = require('../../src/lib/email');

const prisma = new PrismaClient();

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

describe('Plugin Connection - connect-with-key, domain and HMAC enforcement (T2)', () => {
  const createdTenantIds = [];

  afterAll(async () => {
    if (createdTenantIds.length) {
      await prisma.tenant.deleteMany({ where: { id: { in: createdTenantIds } } });
    }
    await prisma.$disconnect();
  });

  // Warm-up: the first authenticated request in a fresh process pays one-time
  // costs (Prisma connections, cold query paths). Earlier runs measured ~13s for
  // the first test (when it went through /connect), against the 15s per-test
  // limit. This performs the same kind of request once, under an explicit hook
  // timeout. Its rate-limit row is cleared by the global beforeEach reset
  // before the first test.
  beforeAll(async () => {
    const { tenant, originalKey } = await seedConnectableTenant('warmup');
    createdTenantIds.push(tenant.id);
    await request(app)
      .post('/api/auth/connect-with-key')
      .set('X-Api-Key', originalKey)
      .send({});
  }, 60000);
  beforeEach(() => {
    jest.clearAllMocks();
    email.sendConfirmationEmail.mockResolvedValue(undefined);
  });

  // -- Rate limiting shared by the connect family (connectRateLimit) --
  describe('connect-with-key rate limiting', () => {
    test('4th /connect-with-key attempt within 15 minutes is rate-limited; first 3 succeed', async () => {
      const { tenant, originalKey } = await seedConnectableTenant('ratelimit');
      // Self-contained: clear prior attempts so this test never depends on the
      // global beforeEach reset having run (a leftover warm-up row makes the 3rd call 429).
      await prisma.connectAttempt.deleteMany({});
      createdTenantIds.push(tenant.id);

      const results = [];
      for (let i = 0; i < 4; i++) {
        const res = await request(app)
          .post('/api/auth/connect-with-key')
          .set('X-Api-Key', originalKey)
          .send({});
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
      // The seeded tenant already has a live hashed API key and a webhookSecret,
      // so no connect flow is needed to obtain credentials.
      const { tenant, domain, originalKey } = await seedConnectableTenant('domaincheck');
      createdTenantIds.push(tenant.id);
      liveTenant = tenant;
      liveApiKey = originalKey;
      liveDomain = domain;
    });

    test('request with the correct X-Store-Domain and a valid HMAC signature is accepted', async () => {
      const bodyObj = { type: 'EMAIL', value: `whitelist-test-${Date.now()}@example.com` };
      const bodyString = JSON.stringify(bodyObj);
      const headers = signV3({ secret: liveTenant.webhookSecret, domain: liveDomain, method: 'POST', target: '/api/risk/blacklist', body: bodyString });

      const res = await request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', liveApiKey)
        .set(headers)
        .send(bodyString);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    test('request with a mismatched X-Store-Domain is rejected by domainAuthMiddleware (403), before HMAC is even checked', async () => {
      const bodyObj = { type: 'EMAIL', value: `domain-mismatch-${Date.now()}@example.com` };
      const bodyString = JSON.stringify(bodyObj);
      const wrongDomain = 'totally-different-domain.com';
      const headers = signV3({ secret: liveTenant.webhookSecret, domain: wrongDomain, method: 'POST', target: '/api/risk/blacklist', body: bodyString });

      const res = await request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', liveApiKey)
        .set(headers)
        .send(bodyString);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOMAIN_MISMATCH');
    });
  });

  // ── Security: Store-aware domain resolution (Agency multi-store) ─────
  describe('store-aware domain resolution (domainAuthMiddleware)', () => {
    // Tenant with NO legacy allowedDomains, so only the Store table can authorize a domain.
    async function seedStoreManagedTenant(label) {
      const key = crypto.randomBytes(32).toString('base64');
      const tenant = await prisma.tenant.create({
        data: {
          email: `store-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`,
          storeUrl: `https://example-${label}-owner.com`,
          allowedDomains: [],
          webhookSecret: crypto.randomBytes(32).toString('hex'),
          apiKeyHash: hashApiKey(key),
          apiKey: null,
          isActive: true,
          emailVerified: true,
          plan: 'early_access',
        },
      });
      return { tenant, apiKey: key };
    }

    async function addStore(tenantId, domain, isActive = true) {
      return prisma.store.create({
        data: { tenantId, storeUrl: `https://${domain}`, normalizedDomain: domain, isActive },
      });
    }

    async function callBlacklist({ tenant, apiKey, domain }) {
      const bodyString = JSON.stringify({ type: 'EMAIL', value: `store-test-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com` });
      const headers = signV3({ secret: tenant.webhookSecret, domain, method: 'POST', target: '/api/risk/blacklist', body: bodyString });
      return request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', apiKey)
        .set(headers)
        .send(bodyString);
    }

    test('S1: active Store with the requested domain is accepted', async () => {
      const t = await seedStoreManagedTenant('s1');
      createdTenantIds.push(t.tenant.id);
      await addStore(t.tenant.id, 'example-s1-store.com');
      const res = await callBlacklist({ ...t, domain: 'example-s1-store.com' });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    test('S2: active Store for a different domain rejects the requested domain (403 DOMAIN_MISMATCH)', async () => {
      const t = await seedStoreManagedTenant('s2');
      createdTenantIds.push(t.tenant.id);
      await addStore(t.tenant.id, 'example-s2-other.com');
      const res = await callBlacklist({ ...t, domain: 'example-s2-store.com' });
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOMAIN_MISMATCH');
    });

    test('S3: inactive Store with the requested domain does not authorize it (403 NO_ALLOWED_DOMAINS)', async () => {
      const t = await seedStoreManagedTenant('s3');
      createdTenantIds.push(t.tenant.id);
      await addStore(t.tenant.id, 'example-s3-store.com', false);
      const res = await callBlacklist({ ...t, domain: 'example-s3-store.com' });
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('NO_ALLOWED_DOMAINS');
    });

    test("S4: another tenant's active Store with the same domain does not authorize it (403 NO_ALLOWED_DOMAINS)", async () => {
      const t = await seedStoreManagedTenant('s4');
      const other = await seedStoreManagedTenant('s4other');
      createdTenantIds.push(t.tenant.id, other.tenant.id);
      await addStore(other.tenant.id, 'example-s4-store.com');
      const res = await callBlacklist({ ...t, domain: 'example-s4-store.com' });
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('NO_ALLOWED_DOMAINS');
    });
  });

  // ── Security: HMAC enforcement ─────────────────────────────────────────
  describe('HMAC signature enforcement (verifyHmacSignature)', () => {
    let liveTenant, liveApiKey, liveDomain;

    beforeAll(async () => {
      // The seeded tenant already has a live hashed API key and a webhookSecret,
      // so no connect flow is needed to obtain credentials.
      const { tenant, domain, originalKey } = await seedConnectableTenant('hmaccheck');
      createdTenantIds.push(tenant.id);
      liveTenant = tenant;
      liveApiKey = originalKey;
      liveDomain = domain;
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
      const headers = signV3({ secret: liveTenant.webhookSecret, domain: liveDomain, method: 'POST', target: '/api/risk/blacklist', body: bodyString });
      const tamperedSignature = headers['x-chargeguard-signature'].slice(0, -4) + 'dead'; // flip the last 4 hex chars

      const res = await request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', liveApiKey)
        .set({ ...headers, 'x-chargeguard-signature': tamperedSignature })
        .send(bodyString);

      expect(res.status).toBe(401);
    });

    test('a stale timestamp (older than the 300s tolerance) is rejected (401)', async () => {
      const bodyObj = { type: 'EMAIL', value: `stale-${Date.now()}@example.com` };
      const bodyString = JSON.stringify(bodyObj);
      // 400s old, beyond the 300s window
      const headers = signV3({ secret: liveTenant.webhookSecret, domain: liveDomain, method: 'POST', target: '/api/risk/blacklist', body: bodyString, ageSec: 400 });

      const res = await request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', liveApiKey)
        .set(headers)
        .send(bodyString);

      expect(res.status).toBe(401);
    });

    test('a missing signature with a valid timestamp is rejected (401)', async () => {
      const bodyString = JSON.stringify({ type: 'EMAIL', value: `nosig-${Date.now()}@example.com` });
      const { 'x-chargeguard-signature': _omitted, ...withoutSignature } = signV3({ secret: liveTenant.webhookSecret, domain: liveDomain, method: 'POST', target: '/api/risk/blacklist', body: bodyString });

      const res = await request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', liveApiKey)
        .set(withoutSignature)
        .send(bodyString);

      expect(res.status).toBe(401);
    });

    test('a missing timestamp with a signature present is rejected (401)', async () => {
      const bodyString = JSON.stringify({ type: 'EMAIL', value: `nots-${Date.now()}@example.com` });
      const { 'x-chargeguard-timestamp': _omitted, ...withoutTimestamp } = signV3({ secret: liveTenant.webhookSecret, domain: liveDomain, method: 'POST', target: '/api/risk/blacklist', body: bodyString });

      const res = await request(app)
        .post('/api/risk/blacklist')
        .set('Content-Type', 'application/json')
        .set('X-Api-Key', liveApiKey)
        .set(withoutTimestamp)
        .send(bodyString);

      expect(res.status).toBe(401);
    });
  });
  
  // -- Legacy email-based connect flow was removed (#52) --
  describe('legacy email-based connect flow is removed (#52)', () => {
    test('POST /api/auth/connect is not routed (404)', async () => {
      const res = await request(app)
        .post('/api/auth/connect')
        .send({ email: `legacy-${Date.now()}@example.com`, siteUrl: 'https://legacy.example.com', turnstileToken: 'any-non-empty-value' });
      expect(res.status).toBe(404);
    });

    test('GET /api/auth/connect/confirm is not routed (404)', async () => {
      const res = await request(app).get('/api/auth/connect/confirm?token=' + 'f'.repeat(64));
      expect(res.status).toBe(404);
    });

    test('GET /api/auth/connect/status is not routed (404)', async () => {
      const res = await request(app).get('/api/auth/connect/status?requestId=' + 'f'.repeat(64));
      expect(res.status).toBe(404);
    });
  });
});
