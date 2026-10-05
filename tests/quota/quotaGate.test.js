'use strict';

/**
 * tests/quota/quotaGate.test.js
 *
 * #293: direct tests for checkQuotaGate() against the real test DB.
 * Covers: verdict at the limit, first-crossing claim (flag + ProtectionEvent
 * + one email), concurrency, monthly reset, agency exemption, pro limit.
 * Only lib/email is mocked (the email is fire-and-forget inside the gate).
 */

const crypto = require('crypto');

jest.mock('../../src/lib/email');

const db = require('../../src/lib/db');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { checkQuotaGate, computeStartOfNextMonth } = require('../../src/lib/quotaGate');
const email = require('../../src/lib/email');

jest.setTimeout(60000);

const FILE_PREFIX = `qg-${crypto.randomBytes(4).toString('hex')}`;
const hex = (n = 4) => crypto.randomBytes(n).toString('hex');
const createdTenantIds = [];
const tomorrow = () => new Date(Date.now() + 24 * 60 * 60 * 1000);
const yesterday = () => new Date(Date.now() - 24 * 60 * 60 * 1000);
const flush = () => new Promise((r) => setImmediate(r));

async function createTenant(overrides = {}) {
  const label = `${FILE_PREFIX}-${hex()}`;
  const tenant = await db.tenant.create({
    data: {
      email: `${label}@example.com`,
      storeUrl: `https://example-${label}-store.com`,
      allowedDomains: [`example-${label}-store.com`],
      webhookSecret: crypto.randomBytes(32).toString('hex'),
      apiKeyHash: hashApiKey(crypto.randomBytes(32).toString('base64')),
      apiKey: null,
      isActive: true,
      emailVerified: true,
      plan: 'early_access',
      monthlyBlockedCount: 0,
      quotaResetDate: tomorrow(),
      ...overrides,
    },
  });
  createdTenantIds.push(tenant.id);
  return tenant;
}

const events = (tenantId) => db.protectionEvent.findMany({ where: { tenantId } });
const fresh = (tenantId) => db.tenant.findUnique({ where: { id: tenantId } });

beforeEach(() => {
  jest.clearAllMocks();
  email.sendQuotaExceededEmail.mockResolvedValue();
});

afterAll(async () => {
  try {
    if (createdTenantIds.length) {
      await db.tenant.deleteMany({ where: { id: { in: createdTenantIds } } });
    }
  } finally {
    await db.$disconnect();
  }
});

describe('checkQuotaGate (#293)', () => {
  test('under the limit (499/500): not exceeded, no notice, no event, no email', async () => {
    const t = await createTenant({ monthlyBlockedCount: 499 });
    const v = await checkQuotaGate({ tenant: t }, 'test');
    await flush();

    expect(v.exceeded).toBe(false);
    expect(v.limit).toBe(500);
    expect((await fresh(t.id)).lastQuotaExceededNoticeSentAt).toBeNull();
    expect(await events(t.id)).toHaveLength(0);
    expect(email.sendQuotaExceededEmail).not.toHaveBeenCalled();
  });

  test('at the limit (500/500): exceeded, flag claimed, one event with metadata, one email', async () => {
    const t = await createTenant({ monthlyBlockedCount: 500 });
    const v = await checkQuotaGate({ tenant: t }, 'test');
    await flush();

    expect(v.exceeded).toBe(true);
    expect(v.limit).toBe(500);
    expect(v.monthlyCount).toBe(500);
    expect((await fresh(t.id)).lastQuotaExceededNoticeSentAt).not.toBeNull();
    const ev = await events(t.id);
    expect(ev).toHaveLength(1);
    expect(ev[0].type).toBe('quota_exceeded');
    expect(ev[0].endedAt).toBeNull();
    expect(ev[0].metadata).toEqual({ limit: 500, monthlyCountAtTrigger: 500 });
    expect(email.sendQuotaExceededEmail).toHaveBeenCalledTimes(1);
    expect(email.sendQuotaExceededEmail.mock.calls[0][0].email).toBe(t.email);
  });

  test('second call at the limit: still exceeded, but no second event or email', async () => {
    const t = await createTenant({ monthlyBlockedCount: 500 });
    await checkQuotaGate({ tenant: t }, 'test');
    const v2 = await checkQuotaGate({ tenant: t }, 'test');
    await flush();

    expect(v2.exceeded).toBe(true);
    expect(await events(t.id)).toHaveLength(1);
    expect(email.sendQuotaExceededEmail).toHaveBeenCalledTimes(1);
  });

  test('5 concurrent calls at the limit: all exceeded, exactly one event and one email', async () => {
    const t = await createTenant({ monthlyBlockedCount: 500 });
    const vs = await Promise.all([1, 2, 3, 4, 5].map(() => checkQuotaGate({ tenant: t }, 'test')));
    await flush();

    expect(vs.every((v) => v.exceeded === true)).toBe(true);
    expect(await events(t.id)).toHaveLength(1);
    expect(email.sendQuotaExceededEmail).toHaveBeenCalledTimes(1);
  });

  test('stale reset date: counter reset to 0, next month start, notice cleared, open event closed', async () => {
    const t = await createTenant({
      monthlyBlockedCount: 500,
      quotaResetDate: yesterday(),
      lastQuotaExceededNoticeSentAt: new Date(),
    });
    await db.protectionEvent.create({ data: { tenantId: t.id, type: 'quota_exceeded' } });
    const v = await checkQuotaGate({ tenant: t }, 'test');
    await flush();

    expect(v.exceeded).toBe(false);
    expect(v.monthlyCount).toBe(0);
    const after = await fresh(t.id);
    expect(after.monthlyBlockedCount).toBe(0);
    expect(after.quotaResetDate.toISOString()).toBe(computeStartOfNextMonth(new Date()).toISOString());
    expect(after.lastQuotaExceededNoticeSentAt).toBeNull();
    const ev = await events(t.id);
    expect(ev).toHaveLength(1);
    expect(ev[0].endedAt).not.toBeNull();
    expect(email.sendQuotaExceededEmail).not.toHaveBeenCalled();
  });

  test('agency plan: never exceeded, nothing written', async () => {
    const t = await createTenant({ plan: 'agency', monthlyBlockedCount: 999999 });
    const v = await checkQuotaGate({ tenant: t }, 'test');
    await flush();

    expect(v.exceeded).toBe(false);
    expect((await fresh(t.id)).lastQuotaExceededNoticeSentAt).toBeNull();
    expect(await events(t.id)).toHaveLength(0);
    expect(email.sendQuotaExceededEmail).not.toHaveBeenCalled();
  });

  test('pro plan limit is 5000: 4999 under, 5000 exceeded', async () => {
    const under = await createTenant({ plan: 'pro', monthlyBlockedCount: 4999 });
    const at = await createTenant({ plan: 'pro', monthlyBlockedCount: 5000 });
    const vu = await checkQuotaGate({ tenant: under }, 'test');
    const va = await checkQuotaGate({ tenant: at }, 'test');

    expect(vu.exceeded).toBe(false);
    expect(vu.limit).toBe(5000);
    expect(va.exceeded).toBe(true);
    expect(va.limit).toBe(5000);
  });
});
