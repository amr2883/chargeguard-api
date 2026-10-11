// tests/orders/order-upsert-race.test.js
// Guards N15(a)/N11: concurrent upsertOrderByBusinessKey calls for the same
// business key must end with exactly one row and no thrown error. The partial
// unique indexes are the real guard. NOTE: this test calls the helper with the
// shared client (no transaction) and without a barrier, and it was shown to pass
// on both the old (P2002 catch) and the fixed helper, so it does NOT guard the
// transaction case. That protection lives in order-upsert-tx-race.test.js.

const crypto = require('crypto');
const db = require('../../src/lib/db');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { upsertOrderByBusinessKey } = require('../../src/lib/orderIdentity');

const ROUNDS = 5;
const PARALLEL = 10;

function uid(label) {
  return `race-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

describe('upsertOrderByBusinessKey -- concurrent writers (N15a)', () => {
  let tenant;

  beforeAll(async () => {
    const domain = `example-race-${Date.now()}.com`;
    tenant = await db.tenant.create({
      data: {
        email: `race-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`,
        storeUrl: `https://${domain}`,
        allowedDomains: [domain],
        webhookSecret: crypto.randomBytes(32).toString('hex'),
        apiKeyHash: hashApiKey(crypto.randomBytes(32).toString('base64')),
        apiKey: null,
        isActive: true,
        emailVerified: true,
        plan: 'starter',
      },
    });
  });

  afterAll(async () => {
    if (tenant) {
      await db.order.deleteMany({ where: { merchantId: tenant.id } });
      await db.tenant.deleteMany({ where: { id: tenant.id } });
    }
    await db.$disconnect();
  });

  async function hammer(storeId) {
    const orderId = uid(storeId ? 'scoped' : 'pooled');
    const key = { merchantId: tenant.id, storeId, orderId };
    const create = { amount: 42, decision: 'review', riskScore: 50 };
    const results = await Promise.allSettled(
      Array.from({ length: PARALLEL }, (_, i) =>
        upsertOrderByBusinessKey(db, key, { create, update: { riskScore: 50 + i } })
      )
    );
    const rows = await db.order.findMany({ where: { merchantId: tenant.id, orderId } });
    return { results, rows };
  }

  test('pooled (storeId null): one row, no rejected call', async () => {
    for (let r = 0; r < ROUNDS; r++) {
      const { results, rows } = await hammer(null);
      expect(results.filter((x) => x.status === 'rejected')).toHaveLength(0);
      expect(rows).toHaveLength(1);
    }
  });

  test('store-scoped: one row, no rejected call', async () => {
    for (let r = 0; r < ROUNDS; r++) {
      const { results, rows } = await hammer(uid('store'));
      expect(results.filter((x) => x.status === 'rejected')).toHaveLength(0);
      expect(rows).toHaveLength(1);
    }
  });
});
