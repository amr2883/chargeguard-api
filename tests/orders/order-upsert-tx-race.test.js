// tests/orders/order-upsert-tx-race.test.js
// Guards R-TX: upsertOrderByBusinessKey called with an interactive-transaction
// client (the webhook path in risk.js) must survive losing the insert race.
// A P2002 raised inside a transaction aborts it (Postgres 25P02), so the helper
// must not depend on catching P2002. A barrier forces both callers to read
// "no row" before either inserts, so the race is deterministic.

const crypto = require('crypto');
const db = require('../../src/lib/db');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { upsertOrderByBusinessKey } = require('../../src/lib/orderIdentity');

const ROUNDS = 3;

function uid(label) {
  return `txrace-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function makeBarrier(parties) {
  let arrived = 0;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  return async () => {
    arrived += 1;
    if (arrived >= parties) release();
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('barrier timeout')), 5000);
    });
    try {
      await Promise.race([gate, timeout]);
    } finally {
      clearTimeout(timer);
    }
  };
}

// Only the first findFirst of each caller waits: both callers have then read "no row".
function withBarrier(client, barrier) {
  let first = true;
  return {
    order: {
      findFirst: async (args) => {
        const found = await client.order.findFirst(args);
        if (first) {
          first = false;
          await barrier();
        }
        return found;
      },
      create: (args) => client.order.create(args),
      createMany: (args) => client.order.createMany(args),
      update: (args) => client.order.update(args),
    },
  };
}

describe('upsertOrderByBusinessKey -- two concurrent transactions (R-TX)', () => {
  let tenant;

  beforeAll(async () => {
    const domain = `example-txrace-${Date.now()}.com`;
    tenant = await db.tenant.create({
      data: {
        email: `txrace-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`,
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

  async function raceInTransactions(storeId) {
    const orderId = uid(storeId ? 'scoped' : 'pooled');
    const key = { merchantId: tenant.id, storeId, orderId };
    const barrier = makeBarrier(2);
    const attempt = () => db.$transaction(
      (tx) => upsertOrderByBusinessKey(withBarrier(tx, barrier), key, {
        create: { amount: 1, decision: 'review', riskScore: 10 },
        update: { amount: 2, riskScore: 20 },
      }),
      { maxWait: 5000, timeout: 15000 }
    );
    const results = await Promise.allSettled([attempt(), attempt()]);
    const rows = await db.order.findMany({ where: { merchantId: tenant.id, orderId } });
    return { results, rows };
  }

  function expectCleanRace({ results, rows }) {
    const rejected = results
      .filter((r) => r.status === 'rejected')
      .map((r) => String((r.reason && r.reason.message) || r.reason).replace(/\s+/g, ' ').slice(-220));
    expect(rejected).toEqual([]);
    expect(rows).toHaveLength(1);
    // The loser found the winner's row and applied its update (INSERT ... ON CONFLICT DO NOTHING path).
    expect(rows[0].amount).toBe(2);
    expect(results[0].value.id).toBe(rows[0].id);
    expect(results[1].value.id).toBe(rows[0].id);
  }

  test('pooled (storeId null): both transactions succeed, one row, loser updates it', async () => {
    for (let r = 0; r < ROUNDS; r++) {
      expectCleanRace(await raceInTransactions(null));
    }
  });

  test('store-scoped: both transactions succeed, one row, loser updates it', async () => {
    for (let r = 0; r < ROUNDS; r++) {
      expectCleanRace(await raceInTransactions(uid('store')));
    }
  });
});