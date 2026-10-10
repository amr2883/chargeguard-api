'use strict';

/**
 * tests/webhook/woocommerce-webhook.test.js
 *
 * HTTP-level integration suite for POST /api/risk/woocommerce-webhook.
 * Purpose: produce EXECUTABLE EVIDENCE that the request path works end to end:
 *   HTTP -> express.raw -> requireAuth -> WC signature -> identity extraction
 *        -> hard-block layers -> scoring -> DB write -> response.
 *
 * Tiers:
 *   [A] grounded in code we have read (literal error strings, extraction, cleanup).
 *   [B] calibration-dependent: the exact block-response shape has NOT been seen yet.
 *       looksBlocked() is deliberately tolerant; when it fails it throws with the
 *       real status/body so the first run doubles as calibration.
 *
 * Assumptions to confirm on the first run:
 *   A1  API key header is X-API-Key and failures are 401/403 (requireAuth).
 *   A2  WC signature = base64(HMAC-SHA256(webhookSecret, rawBody)) in X-WC-Webhook-Signature.
 *   A3  TEST-NET IPs (203.0.113.x) are not discarded by the handler.
 *   A4  A block is either HTTP 403 or a body whose decision/action contains "block".
 *   A5  SECRET_SALT exists in .env.test (recordFailedAttempt hashes IPs with it).
 *   A6  Velocity threshold is 5 attempts / 10 min (from velocity-detector.test.js).
 *
 * Not covered (remain UNKNOWN): Agency per-store isolation, BIN-sequence path,
 * Redis/DB failure behaviour (fail-open vs fail-closed) on this route.
 *
 * Debug: set WEBHOOK_TEST_DEBUG=1 to print every response (no secrets are printed).
 */

const crypto = require('crypto');
const request = require('supertest');

jest.mock('../../src/lib/email');

const app = require('../../src/app');
const db = require('../../src/lib/db');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { normalizeEmail } = require('../../src/lib/utils');
const { recordFailedAttempt } = require('../../src/lib/velocityDetector');

jest.setTimeout(60000);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const API_PATH = '/api/risk/woocommerce-webhook';
const DEBUG = process.env.WEBHOOK_TEST_DEBUG === '1';
const FILE_PREFIX = `wh-${crypto.randomBytes(4).toString('hex')}`;

const hex = (n = 6) => crypto.randomBytes(n).toString('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const dbg = (label, res) => {
  if (DEBUG) console.log(`[${label}] status=${res.status} body=${JSON.stringify(res.body)}`);
};

const createdTenantIds = [];
const ORDER_BASE = 100000000 + Math.floor(Math.random() * 800000000);
let orderCounter = 0;
let ipCounter = 0;
const nextOrderId = () => ORDER_BASE + ++orderCounter;
const uniqueIp = () => `8.8.${20 + (++ipCounter % 200)}.${1 + (ipCounter % 250)}`;
const uniqueEmail = (domain = 'gmail.com') => `buyer-${hex()}@${domain}`;

async function createTenant(overrides = {}) {
  const label = `${FILE_PREFIX}-${hex(4)}`;
  const apiKey = crypto.randomBytes(32).toString('base64');
  const domain = `${label}-store.test`;
  const tenant = await db.tenant.create({
    data: {
      email: `${label}@example.com`,
      storeUrl: `https://${domain}`,
      allowedDomains: [domain],
      webhookSecret: crypto.randomBytes(32).toString('hex'),
      apiKeyHash: hashApiKey(apiKey),
      apiKey: null,
      isActive: true,
      emailVerified: true,
      plan: 'early_access',
      ...overrides,
    },
  });
  createdTenantIds.push(tenant.id);
  return { id: tenant.id, apiKey, webhookSecret: tenant.webhookSecret, domain };
}

function signBody(secret, body) {
  return crypto.createHmac('sha256', secret).update(body).digest('base64');
}

/**
 * opts.apiKey    : null => omit header; string => override
 * opts.signature : null => omit header; string => override
 * opts.secret    : override the secret used to sign
 * opts.signBody  : sign a different body than the one sent
 */
function postWebhook(tenant, payload, opts = {}) {
  const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const secret = opts.secret !== undefined ? opts.secret : tenant.webhookSecret;
  const req = request(app).post(API_PATH).set('Content-Type', 'application/json');
  if (opts.apiKey !== null) req.set('X-API-Key', opts.apiKey !== undefined ? opts.apiKey : tenant.apiKey);
  if (opts.signature !== null) {
    const sig =
      opts.signature !== undefined
        ? opts.signature
        : secret
        ? signBody(secret, opts.signBody !== undefined ? opts.signBody : body)
        : undefined;
    if (sig) req.set('X-WC-Webhook-Signature', sig);
  }
  return req.send(body);
}

function buildPayload(o = {}) {
  const payload = {
    id: o.orderId !== undefined ? o.orderId : nextOrderId(),
    status: 'processing',
    currency: 'USD',
    total: o.total || '49.90',
    customer_ip_address: o.ip || uniqueIp(),
    customer_id: 0,
    date_created: '2026-09-28T10:00:00',
    billing: {
      first_name: 'Test',
      last_name: 'Buyer',
      email: o.email || uniqueEmail(),
      country: o.billingCountry || 'EG',
    },
    shipping: { country: o.shippingCountry || 'EG' },
  };
  if (o.deviceFingerprint) payload.device_fingerprint = o.deviceFingerprint;
  return payload;
}

function decisionOf(res) {
  const b = res.body || {};
  const d = String(b.decision !== undefined ? b.decision : b.action !== undefined ? b.action : '').toLowerCase();
  if (d.includes('approve')) return 'approve';
  if (d.includes('review')) return 'review';
  if (d.includes('block')) return 'block';
  if (res.status === 403) return 'block';
  return null;
}

const looksBlocked = (res) => decisionOf(res) === 'block' || (res.body && res.body.blocked === true);

function expectBlocked(res, label) {
  dbg(label, res);
  if (!looksBlocked(res)) {
    throw new Error(`[${label}] expected a block response but got status=${res.status} body=${JSON.stringify(res.body)}`);
  }
}

const ordersFor = (merchantId, orderId) =>
  db.order.findMany({ where: { merchantId, orderId: String(orderId) } });

async function waitFor(fn, { timeoutMs = 4000, intervalMs = 200 } = {}) {
  const start = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - start > timeoutMs) return v;
    await sleep(intervalMs);
  }
}

async function safe(label, fn, quiet = false) {
  try {
    await fn();
  } catch (e) {
    if (!quiet) console.warn(`[cleanup:${label}] ${e.message}`);
  }
}

beforeAll(async () => {
  let host = '';
  let name = '';
  try {
    const u = new URL(process.env.DATABASE_URL || '');
    host = u.hostname;
    name = u.pathname.replace(/^\//, '');
  } catch (e) {
    throw new Error('DATABASE_URL missing or unparsable; refusing to run the webhook suite.');
  }
  const localHosts = ['localhost', '127.0.0.1', '[::1]'];
  if (!localHosts.includes(host) || !/test/i.test(name)) {
    throw new Error(`Refusing to run: DB host="${host}" name="${name}" must be local and contain "test".`);
  }
  try {
    await db.$queryRaw`SELECT 1`;
  } catch (e) {
    throw new Error('Test database unreachable: ' + e.message);
  }
}, 20000);

afterAll(async () => {
  const ids = createdTenantIds;
  if (ids.length) {
    await safe('riskEvaluation', () => db.riskEvaluation.deleteMany({ where: { order: { merchantId: { in: ids } } } }));
    await safe('order', () => db.order.deleteMany({ where: { merchantId: { in: ids } } }));
    await safe('blockedAttempt', () => db.blockedAttempt.deleteMany({ where: { tenantId: { in: ids } } }));
    await safe('cardTestAttempt', () => db.cardTestAttempt.deleteMany({ where: { merchantId: { in: ids } } }));
    await safe('blacklistEntry', () => db.blacklistEntry.deleteMany({ where: { merchantId: { in: ids } } }));
    await safe('whitelistEntry', () => db.whitelistEntry.deleteMany({ where: { merchantId: { in: ids } } }), true);
    await safe('identitySighting', () => db.identitySighting.deleteMany({ where: { merchantId: { in: ids } } }), true);
    await safe('pendingEnrichment', () => db.pendingEnrichment.deleteMany({ where: { merchantId: { in: ids } } }), true);
    await safe('tenant', () => db.tenant.deleteMany({ where: { id: { in: ids } } }));
  }
  await db.$disconnect();
});

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------
describe('POST /api/risk/woocommerce-webhook', () => {
  describe('0. Baseline', () => {
    test('[B] accepts an ordinary signed order and persists the identity fields extracted from the payload', async () => {
      const t = await createTenant();
      const fp = `fp-${hex()}`;
      const payload = buildPayload({ deviceFingerprint: fp });
      const res = await postWebhook(t, payload);
      dbg('baseline', res);

      expect(res.status).toBe(200);
      expect(looksBlocked(res)).toBe(false);

      const rows = await ordersFor(t.id, payload.id);
      expect(rows).toHaveLength(1);
      const o = rows[0];
      expect(o.merchantId).toBe(t.id);
      expect(o.storeId).toBeNull();
      expect(o.email).toBe(payload.billing.email);
      expect(o.ipAddress).toBe(payload.customer_ip_address);
      expect(o.deviceFingerprint).toBe(fp);
      expect(Number(o.amount)).toBeCloseTo(49.9, 2);
    });
  });

  describe('1-2. Authentication', () => {
    test('[A] rejects a request with no API key and creates no order', async () => {
      const t = await createTenant();
      const payload = buildPayload();
      const res = await postWebhook(t, payload, { apiKey: null });
      dbg('auth-no-key', res);
      expect([401, 403]).toContain(res.status);
      expect(await ordersFor(t.id, payload.id)).toHaveLength(0);
    });

    test('[A] rejects an unknown API key and creates no order', async () => {
      const t = await createTenant();
      const payload = buildPayload();
      const res = await postWebhook(t, payload, { apiKey: crypto.randomBytes(32).toString('base64') });
      dbg('auth-bad-key', res);
      expect([401, 403]).toContain(res.status);
      expect(await ordersFor(t.id, payload.id)).toHaveLength(0);
    });

    test.each([
      ['inactive tenant', { isActive: false }],
      ['unverified tenant', { emailVerified: false }],
    ])('[A] rejects a valid key belonging to an %s', async (_name, overrides) => {
      const t = await createTenant(overrides);
      const payload = buildPayload();
      const res = await postWebhook(t, payload);
      dbg(`auth-${_name}`, res);
      expect([401, 403]).toContain(res.status);
      expect(await ordersFor(t.id, payload.id)).toHaveLength(0);
    });
  });

  describe('3-4. WooCommerce signature (HMAC over the raw bytes)', () => {
    test('[A] accepts a correctly signed request', async () => {
      const t = await createTenant();
      const res = await postWebhook(t, buildPayload());
      dbg('hmac-valid', res);
      expect(res.status).not.toBe(401);
      expect(res.status).not.toBe(400);
      expect(res.status).toBeLessThan(500);
    });

    test('[A] rejects a missing signature when the tenant has a secret ("Missing signature")', async () => {
      const t = await createTenant();
      const payload = buildPayload();
      const res = await postWebhook(t, payload, { signature: null });
      dbg('hmac-missing', res);
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Missing signature');
      expect(await ordersFor(t.id, payload.id)).toHaveLength(0);
    });

    test('[A] rejects a wrong signature of the correct length ("Invalid signature")', async () => {
      const t = await createTenant();
      const payload = buildPayload();
      const res = await postWebhook(t, payload, { signBody: JSON.stringify({ tampered: true }) });
      dbg('hmac-wrong', res);
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid signature');
      expect(await ordersFor(t.id, payload.id)).toHaveLength(0);
    });

    test('[A] rejects a garbled signature of the wrong length with 401, not 500', async () => {
      const t = await createTenant();
      const payload = buildPayload();
      const res = await postWebhook(t, payload, { signature: 'abc' });
      dbg('hmac-short', res);
      expect(res.status).toBe(401);
      expect(await ordersFor(t.id, payload.id)).toHaveLength(0);
    });

    test('[A] rejects a body that was altered after signing', async () => {
      const t = await createTenant();
      const original = buildPayload({ total: '10.00' });
      const altered = { ...original, total: '1.00' };
      const res = await postWebhook(t, altered, { signBody: JSON.stringify(original) });
      dbg('hmac-altered', res);
      expect(res.status).toBe(401);
      expect(await ordersFor(t.id, altered.id)).toHaveLength(0);
    });

    test('[A] rejects invalid JSON from an authenticated caller with 400', async () => {
      const t = await createTenant();
      const res = await postWebhook(t, 'not-json');
      dbg('bad-json', res);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Invalid JSON payload');
    });
  });

  describe('5. Blacklist hard block', () => {
    test.each([['EMAIL'], ['IP'], ['DEVICE_FINGERPRINT']])(
      '[B] blocks a blacklisted %s and does not block a clean identity in the same tenant',
      async (type) => {
        const t = await createTenant();
        const email = uniqueEmail();
        const ip = uniqueIp();
        const fp = `fp-${hex()}`;
        const value = type === 'EMAIL' ? email : type === 'IP' ? ip : fp;
        const normalizedValue = type === 'EMAIL' ? normalizeEmail(email) : value.trim();

        await db.blacklistEntry.create({
          data: { merchantId: t.id, storeId: null, type, value, normalizedValue, reason: 'webhook-suite', createdBy: 'test' },
        });

        const hit = await postWebhook(t, buildPayload({ email, ip, deviceFingerprint: fp }));
        expectBlocked(hit, `blacklist-${type}`);

        const control = await postWebhook(t, buildPayload({ deviceFingerprint: `fp-${hex()}` }));
        dbg(`blacklist-${type}-control`, control);
        expect(looksBlocked(control)).toBe(false);
      }
    );
  });

  describe('6. Disposable email hard block', () => {
    test('[B] blocks a known disposable domain (also with an upper-case domain) and passes a mainstream domain', async () => {
      const t = await createTenant();

      const bad1 = await postWebhook(t, buildPayload({ email: `x-${hex()}@tempmail.com` }));
      expectBlocked(bad1, 'disposable-lower');

      const bad2 = await postWebhook(t, buildPayload({ email: `x-${hex()}@TempMail.COM` }));
      expectBlocked(bad2, 'disposable-upper');

      const ok = await postWebhook(t, buildPayload({ email: `ok-${hex()}@gmail.com` }));
      dbg('disposable-control', ok);
      expect(looksBlocked(ok)).toBe(false);
    });
  });

  describe('7. Velocity hard block (5 seeds written by the real writer, then HTTP)', () => {
    test('[B] blocks the request once the IP already has 5 recent failed attempts', async () => {
      const t = await createTenant();
      const ip = uniqueIp();
      for (let i = 0; i < 5; i++) await recordFailedAttempt({ ip, merchantId: t.id, amount: 10 });

      const res = await postWebhook(t, buildPayload({ ip }));
      expectBlocked(res, 'velocity-5');

      const control = await postWebhook(t, buildPayload({ ip: uniqueIp() }));
      dbg('velocity-control', control);
      expect(looksBlocked(control)).toBe(false);
    });

    test('[B] boundary: 4 prior failed attempts must NOT trigger the velocity hard block', async () => {
      const t = await createTenant();
      const ip = uniqueIp();
      for (let i = 0; i < 4; i++) await recordFailedAttempt({ ip, merchantId: t.id, amount: 10 });

      const res = await postWebhook(t, buildPayload({ ip }));
      dbg('velocity-4', res);
      expect(looksBlocked(res)).toBe(false);
    });
  });

  describe('8. Device-fingerprint rotation from one IP', () => {
    test('[B] blocks once 6 distinct fingerprints appear from the same IP, and not because of the velocity threshold', async () => {
      const t = await createTenant();
      const ip = uniqueIp();
      const tag = hex(4);
      const trace = [];

      for (let i = 0; i < 8; i++) {
        const attemptsBefore = await db.cardTestAttempt.count({ where: { merchantId: t.id } });
        const res = await postWebhook(t, buildPayload({ ip, deviceFingerprint: `rot-${i}-${tag}` }));
        dbg(`rotation-${i}`, res);
        trace.push({ i, status: res.status, blocked: looksBlocked(res), attemptsBefore });
        if (looksBlocked(res)) break;
      }

      const first = trace.find((r) => r.blocked);
      if (!first) {
        throw new Error(`rotation: nothing blocked after ${trace.length} distinct fingerprints from one IP. trace=${JSON.stringify(trace)}`);
      }
      // Block must not be attributable to the 5-attempt velocity threshold.
      if (first.attemptsBefore >= 5) {
        throw new Error(`rotation: block is ambiguous (velocity may be responsible). trace=${JSON.stringify(trace)}`);
      }
      // Threshold is 6 distinct fingerprints: the 6th (index 5) or the 7th (index 6) request.
      expect([5, 6]).toContain(first.i);

      const recorded = await waitFor(async () => (await db.blockedAttempt.count({ where: { tenantId: t.id } })) >= 1);
      expect(recorded).toBe(true);
    });
  });

  describe('9. CardTestAttempt persistence', () => {
    test.each([
      ['ordinary order', {}],
      ['high-risk-shaped order', { total: '25000.00', billingCountry: 'NG', shippingCountry: 'US' }],
    ])('[B] %s: a failed attempt is recorded if and only if the final decision is not approve', async (_name, extra) => {
      const t = await createTenant();
      const res = await postWebhook(t, buildPayload({ ip: uniqueIp(), ...extra }));
      dbg(`persistence-${_name}`, res);

      const decision = decisionOf(res);
      if (!decision) {
        throw new Error(`persistence: cannot derive decision. status=${res.status} body=${JSON.stringify(res.body)}`);
      }
      const count = () => db.cardTestAttempt.count({ where: { merchantId: t.id } });

      if (decision === 'approve') {
        await sleep(1000);
        expect(await count()).toBe(0);
      } else {
        const seen = await waitFor(async () => (await count()) >= 1);
        expect(seen).toBe(true);
        expect(await count()).toBe(1);
      }
    });
  });

  describe('10. Replay / idempotency / concurrency', () => {
    test('[B] replaying an identical signed delivery yields one Order row and the same score', async () => {
      const t = await createTenant();
      const payload = buildPayload({ deviceFingerprint: `fp-${hex()}` });
      const body = JSON.stringify(payload);

      const r1 = await postWebhook(t, body);
      dbg('replay-1', r1);
      if (r1.status !== 200) throw new Error(`replay: first delivery not 200. status=${r1.status} body=${JSON.stringify(r1.body)}`);

      const r2 = await postWebhook(t, body);
      dbg('replay-2', r2);
      expect(r2.status).toBe(200);
      expect(String(r2.body.orderId)).toBe(String(payload.id));
      expect(typeof r1.body.score).toBe('number');
      expect(r2.body.score).toBe(r1.body.score);
      expect(await ordersFor(t.id, payload.id)).toHaveLength(1);
    });

    test('[B] concurrent identical deliveries produce one Order row and one consistent score (advisory-lock fix)', async () => {
      const t = await createTenant();
      const payload = buildPayload({ deviceFingerprint: `fp-${hex()}` });
      const body = JSON.stringify(payload);

      const responses = await Promise.all(Array.from({ length: 8 }, () => postWebhook(t, body)));
      responses.forEach((r, i) => dbg(`concurrent-${i}`, r));

      expect(responses.filter((r) => r.status >= 500)).toHaveLength(0);

      const rows = await ordersFor(t.id, payload.id);
      expect(rows).toHaveLength(1);

      const scores = responses.map((r) => r.body && r.body.score).filter((s) => typeof s === 'number');
      if (scores.length === 0) {
        throw new Error(`concurrency: no numeric score in any response. sample=${JSON.stringify(responses[0].body)}`);
      }
      expect(new Set(scores).size).toBe(1);
      expect(Math.round(scores[0])).toBe(Math.round(rows[0].riskScore));
    });
  });

  describe('11. Tenant isolation', () => {
    test('[B] a blacklist entry and its block belong to one tenant only', async () => {
      const A = await createTenant();
      const B = await createTenant();
      const email = uniqueEmail();
      await db.blacklistEntry.create({
        data: { merchantId: A.id, storeId: null, type: 'EMAIL', value: email, normalizedValue: normalizeEmail(email), reason: 'isolation', createdBy: 'test' },
      });

      expectBlocked(await postWebhook(A, buildPayload({ email })), 'isolation-A');

      const payloadB = buildPayload({ email });
      const resB = await postWebhook(B, payloadB);
      dbg('isolation-B', resB);
      expect(looksBlocked(resB)).toBe(false);
      expect(await ordersFor(B.id, payloadB.id)).toHaveLength(1);
    });

    test('[B] velocity history seeded for tenant A does not affect tenant B on the same IP', async () => {
      const A = await createTenant();
      const B = await createTenant();
      const ip = uniqueIp();
      for (let i = 0; i < 5; i++) await recordFailedAttempt({ ip, merchantId: A.id, amount: 10 });

      expectBlocked(await postWebhook(A, buildPayload({ ip })), 'velocity-isolation-A');

      const resB = await postWebhook(B, buildPayload({ ip }));
      dbg('velocity-isolation-B', resB);
      expect(looksBlocked(resB)).toBe(false);
    });

    test('[B] the same orderId under two tenants yields two independent Order rows', async () => {
      const A = await createTenant();
      const B = await createTenant();
      const orderId = nextOrderId();
      const pa = buildPayload({ orderId });
      const pb = buildPayload({ orderId });

      const ra = await postWebhook(A, pa);
      const rb = await postWebhook(B, pb);
      dbg('same-order-A', ra);
      dbg('same-order-B', rb);
      expect(ra.status).toBe(200);
      expect(rb.status).toBe(200);

      const rowsA = await ordersFor(A.id, orderId);
      const rowsB = await ordersFor(B.id, orderId);
      expect(rowsA).toHaveLength(1);
      expect(rowsB).toHaveLength(1);
      expect(rowsA[0].email).toBe(pa.billing.email);
      expect(rowsB[0].email).toBe(pb.billing.email);
    });

    test('[A] a request signed with a different tenant secret is rejected', async () => {
      const A = await createTenant();
      const B = await createTenant();
      const payload = buildPayload();
      const res = await postWebhook(B, payload, { secret: A.webhookSecret });
      dbg('cross-secret', res);
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid signature');
      expect(await ordersFor(B.id, payload.id)).toHaveLength(0);
    });
  });
});