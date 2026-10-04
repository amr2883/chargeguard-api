const request = require('supertest');
const crypto = require('crypto');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');

// Black-box calculateRiskScore entirely — T3a tests risk.js's own
// orchestration (quota, idempotency, whitelist/blacklist, BlockedAttempt
// transaction), not the scoring math itself (that's T3d).
jest.mock('../../src/lib/riskScoring');
const { calculateRiskScore } = require('../../src/lib/riskScoring');

// buildGraphFromOrder is fire-and-forget (wrapped in try/catch, result
// unused) but touches identityGraph internals we don't have visibility
// into — mocked to keep this suite hermetic and fast rather than
// accidentally depending on unreviewed code.
jest.mock('../../src/lib/identityGraph');

const prisma = new PrismaClient();
const db = require('../../src/lib/db'); // same singleton risk.js uses — needed to spy on $transaction

function defaultScoreResult(overrides = {}) {
  return {
    score: 85,
    decision: 'Low Risk — Approve',
    decisionColor: '#007A5C',
    decisionBg: '#F1F8F5',
    flags: [],
    positives: [],
    isLearning: false,
    scoringVersion: 'mock-v1',
    economicData: null,
    computedSignals: {},
    graphRisk: 0,
    ipIntel: null,
    emailIntel: null,
    binIntel: null,
    ...overrides,
  };
}

function uniqueIp(label) {
  return `10.99.${Math.floor(Math.random() * 255)}.${label}-${Date.now()}`;
}

function uniqueOrderId(label) {
  return `order-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

async function seedTenant(overrides = {}) {
  const label = overrides.label || 'x';
  const testEmail = `eval-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
  const plaintextKey = crypto.randomBytes(32).toString('base64');
  const domain = `example-eval-${label}-${Date.now()}.com`;

  const tenant = await prisma.tenant.create({
    data: {
      email: testEmail,
      storeUrl: `https://${domain}`,
      allowedDomains: [domain],
      webhookSecret: crypto.randomBytes(32).toString('hex'),
      apiKeyHash: hashApiKey(plaintextKey),
      apiKey: null,
      isActive: true,
      emailVerified: true,
      plan: overrides.plan ?? 'starter',
      monthlyBlockedCount: overrides.monthlyBlockedCount ?? 0,
      quotaResetDate: overrides.quotaResetDate ?? null,
      countryOverrides: overrides.countryOverrides ?? {},
    },
  });

  if (!tenant?.id) {
    throw new Error(`seedTenant('${label}') failed to create a tenant row — cannot proceed.`);
  }

  return { tenant, domain, plaintextKey };
}

function signBody(secret, bodyString) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signedStr = `${timestamp}.${bodyString}`;
  const signature = 'v1=' + crypto.createHmac('sha256', secret).update(signedStr).digest('hex');
  return { timestamp, signature };
}

function evaluateRequest(tenant, domain, bodyObj, headerOverrides = {}) {
  const bodyString = JSON.stringify(bodyObj);
  const { timestamp, signature } = signBody(tenant.webhookSecret, bodyString);

  const req = request(app)
    .post('/api/risk/evaluate')
    .set('Content-Type', 'application/json');

  if (headerOverrides.apiKey !== null) req.set('X-Api-Key', headerOverrides.apiKey ?? tenant._plaintextKeyForAuth);
  if (headerOverrides.domain !== null) req.set('X-Store-Domain', headerOverrides.domain ?? domain);
  if (headerOverrides.signature !== null) req.set('X-ChargeGuard-Signature', headerOverrides.signature ?? signature);
  if (headerOverrides.timestamp !== null) req.set('X-ChargeGuard-Timestamp', headerOverrides.timestamp ?? timestamp);

  return req.send(headerOverrides.bodyString ?? bodyString);
}

const { normalizeEmail } = require('../../src/lib/utils');

describe('admin blacklist/whitelist writes normalizedValue (#246)', () => {
  const ids = [];
  const ADMIN_KEY = crypto.randomBytes(16).toString('hex');
  let prevAdmin;

  beforeAll(() => { prevAdmin = process.env.ADMIN_SECRET; process.env.ADMIN_SECRET = ADMIN_KEY; });
  afterAll(async () => {
    if (prevAdmin === undefined) delete process.env.ADMIN_SECRET; else process.env.ADMIN_SECRET = prevAdmin;
    if (ids.length) {
      await prisma.blacklistEntry.deleteMany({ where: { merchantId: { in: ids } } });
      await prisma.whitelistEntry.deleteMany({ where: { merchantId: { in: ids } } });
      await prisma.cardTestAttempt.deleteMany({ where: { merchantId: { in: ids } } });
      await prisma.order.deleteMany({ where: { merchantId: { in: ids } } });
      await prisma.blockedAttempt.deleteMany({ where: { tenantId: { in: ids } } });
      await prisma.adminAction.deleteMany({ where: { tenantId: { in: ids } } });
      await prisma.tenant.deleteMany({ where: { id: { in: ids } } });
    }
    await prisma.$disconnect();
  });
  beforeEach(() => { jest.clearAllMocks(); calculateRiskScore.mockResolvedValue(defaultScoreResult()); });

  async function addViaAdmin(list, tenantId, type, value) {
    return request(app).post(`/admin/tenants/${tenantId}/${list}`).set('x-admin-key', ADMIN_KEY).send({ type, value });
  }

  test('A: admin-added blacklist EMAIL blocks a differently-cased request via /evaluate', async () => {
    const seeded = await seedTenant({ label: 'adminbl' });
    seeded.tenant._plaintextKeyForAuth = seeded.plaintextKey; ids.push(seeded.tenant.id);
    const stamp = Date.now() + '-' + Math.random().toString(36).slice(2);
    const added = await addViaAdmin('blacklist', seeded.tenant.id, 'EMAIL', `Mixed.Case-${stamp}@Example.com`);
    expect(added.status).toBe(201);
    const res = await evaluateRequest(seeded.tenant, seeded.domain, { orderId: uniqueOrderId('adminbl'), email: `mixed.case-${stamp}@example.com` });
    expect(res.status).toBe(403);
    expect(res.body.decision).toBe('block');
    expect(calculateRiskScore).not.toHaveBeenCalled();
  });

  test('B: stored row has normalizedValue = normalizeEmail(value)', async () => {
    const seeded = await seedTenant({ label: 'adminnv' });
    ids.push(seeded.tenant.id);
    const stamp = Date.now() + '-' + Math.random().toString(36).slice(2);
    const raw = `Stored.Case-${stamp}@Example.com`;
    const added = await addViaAdmin('blacklist', seeded.tenant.id, 'EMAIL', raw);
    expect(added.status).toBe(201);
    const row = await prisma.blacklistEntry.findFirst({ where: { merchantId: seeded.tenant.id, type: 'EMAIL' } });
    expect(row.normalizedValue).toBe(normalizeEmail(raw));
  });

  test('C: admin-added whitelist EMAIL bypasses scoring via /evaluate', async () => {
    const seeded = await seedTenant({ label: 'adminwl' });
    seeded.tenant._plaintextKeyForAuth = seeded.plaintextKey; ids.push(seeded.tenant.id);
    const stamp = Date.now() + '-' + Math.random().toString(36).slice(2);
    const added = await addViaAdmin('whitelist', seeded.tenant.id, 'EMAIL', `Trusted.Case-${stamp}@Example.com`);
    expect(added.status).toBe(201);
    const res = await evaluateRequest(seeded.tenant, seeded.domain, { orderId: uniqueOrderId('adminwl'), email: `trusted.case-${stamp}@example.com` });
    expect(res.status).toBe(200);
    expect(res.body.whitelisted).toBe(true);
    expect(calculateRiskScore).not.toHaveBeenCalled();
  });
});