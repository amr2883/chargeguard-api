'use strict';

// ══════════════════════════════════════════════════════════════════════════════
// SCOPE: src/jobs/subscriptionScheduler.js
//   - Phase 1: processRenewalReminders
//   - Phase 2: processExpiredToGrace
//   - Phase 3: processGraceToExpired
//   - Phase 4: cleanupExpiredSessions
//   - Orchestrator: runSubscriptionCycle / startSubscriptionScheduler
//
// MOCKING STRATEGY:
//   - Only `{ startSubscriptionScheduler }` is exported — the four phase
//     functions and runSubscriptionCycle are NOT exported. Every test below
//     drives them indirectly through startSubscriptionScheduler(mockDb) with
//     jest fake timers (jest.advanceTimersByTimeAsync).
//   - `db` is passed as a plain argument to startSubscriptionScheduler (it is
//     NOT required internally by this module), so we build a fresh mock db
//     object per test rather than jest.mock('.../lib/db').
//   - lib/email.js IS required directly inside subscriptionScheduler.js, so
//     sendRenewalReminderEmail / sendGracePeriodEmail are jest.mock'd.
//   - Each cycle calls db.tenant.findMany exactly 3 times, in this order:
//       1) processRenewalReminders
//       2) processExpiredToGrace
//       3) processGraceToExpired
//     followed by db.checkoutSession.deleteMany once (cleanup). To isolate a
//     single phase, we chain mockResolvedValueOnce so the OTHER two
//     findMany calls resolve to [] for that cycle.
//   - console.log/console.error are spied and silenced to keep test output
//     clean; restored in afterEach.
//
// QUIRKS DISCOVERED (documented inline where relevant):
//   - buildRenewUrl() computes `base` from process.env.RENDER_EXTERNAL_URL
//     but never actually uses it in the returned URL — the returned link is
//     always `https://chargeguard.io/upgrade.html?plan=<planId>` regardless
//     of RENDER_EXTERNAL_URL. Renewal/grace-period email assertions below
//     rely on this fixed URL shape.
//   - Phase 2 updates the tenant's status to `grace_period` BEFORE sending
//     the grace-period email — intentional (status change must never be
//     blocked by an email failure). Verified via mock call order.
//   - Phase 2 extends `subscriptionEndDate` to the grace-period end date in
//     the SAME update call that flips status — Phase 3 relies on this to
//     find "grace period ended" tenants without a separate field.
// ══════════════════════════════════════════════════════════════════════════════

jest.mock('../../src/lib/email', () => ({
  sendRenewalReminderEmail: jest.fn().mockResolvedValue(undefined),
  sendGracePeriodEmail: jest.fn().mockResolvedValue(undefined),
}));

const { sendRenewalReminderEmail, sendGracePeriodEmail } = require('../../src/lib/email');
const { startSubscriptionScheduler } = require('../../src/jobs/subscriptionScheduler');

const INITIAL_DELAY_MS = 2 * 60 * 1000; // matches subscriptionScheduler.js
const INTERVAL_MS = 60 * 60 * 1000; // matches subscriptionScheduler.js

// ── Factories ────────────────────────────────────────────────────────────────
function makeMockDb() {
  return {
    tenant: {
      findMany: jest.fn(),
      update: jest.fn().mockResolvedValue({}),
    },
    checkoutSession: {
      deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
    },
  };
}

function makeTenant(overrides = {}) {
  return {
    id: 'tenant_1',
    email: 'merchant@example.com',
    storeUrl: 'https://merchant-store.com',
    plan: 'pro',
    billingCycle: 'monthly',
    subscriptionEndDate: new Date(),
    lastRenewalReminderSentAt: null,
    lastGracePeriodNoticeSentAt: null,
    ...overrides,
  };
}

// Runs exactly one subscription cycle: advances fake timers past the initial
// 2-minute startup delay (which fires runSubscriptionCycle once) and stops
// there, so a single cycle's findMany/deleteMany calls can be asserted.
async function runOneCycle(db) {
  startSubscriptionScheduler(db);
  await jest.advanceTimersByTimeAsync(INITIAL_DELAY_MS);
}

let consoleLogSpy;
let consoleErrorSpy;

beforeEach(() => {
  jest.clearAllMocks();
  jest.useFakeTimers();
  consoleLogSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.clearAllTimers();
  jest.useRealTimers();
  consoleLogSpy.mockRestore();
  consoleErrorSpy.mockRestore();
});

// ══════════════════════════════════════════════════════════════════════════════
describe('Scheduler — Phase 1 (renewal reminders)', () => {
  test('empty tenant list → no-op', async () => {
    const db = makeMockDb();
    db.tenant.findMany
      .mockResolvedValueOnce([]) // phase 1
      .mockResolvedValueOnce([]) // phase 2
      .mockResolvedValueOnce([]); // phase 3

    await runOneCycle(db);

    expect(sendRenewalReminderEmail).not.toHaveBeenCalled();
    expect(db.tenant.update).not.toHaveBeenCalled();
  });

  test('tenant in 7-day window → reminder sent + lastRenewalReminderSentAt updated', async () => {
    const now = Date.now();
    const tenant = makeTenant({
      subscriptionEndDate: new Date(now + 150 * 60 * 60 * 1000), // 150h ≈ within the 7-day window (143–168h)
      lastRenewalReminderSentAt: null,
    });

    const db = makeMockDb();
    db.tenant.findMany
      .mockResolvedValueOnce([tenant]) // phase 1
      .mockResolvedValueOnce([]) // phase 2
      .mockResolvedValueOnce([]); // phase 3

    await runOneCycle(db);

    expect(sendRenewalReminderEmail).toHaveBeenCalledWith(
      { email: tenant.email, storeUrl: tenant.storeUrl },
      expect.objectContaining({
        daysRemaining: 7,
        planLabel: 'Pro',
        renewUrl: 'https://chargeguard.io/upgrade.html?plan=pro_monthly',
      })
    );
    expect(db.tenant.update).toHaveBeenCalledWith({
      where: { id: tenant.id },
      data: { lastRenewalReminderSentAt: expect.any(Date) },
    });
  });

  test('tenant outside all windows → skipped', async () => {
    const now = Date.now();
    const tenant = makeTenant({
      // ~4.16 days out — falls between the 3-day and 7-day windows.
      subscriptionEndDate: new Date(now + 100 * 60 * 60 * 1000),
    });

    const db = makeMockDb();
    db.tenant.findMany
      .mockResolvedValueOnce([tenant])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([]);

    await runOneCycle(db);

    expect(sendRenewalReminderEmail).not.toHaveBeenCalled();
    expect(db.tenant.update).not.toHaveBeenCalled();
  });

  test('cooldown active (<20h since last) → skipped, no email', async () => {
    const now = Date.now();
    const tenant = makeTenant({
      subscriptionEndDate: new Date(now + 20 * 60 * 60 * 1000), // within 1-day window
      lastRenewalReminderSentAt: new Date(now - 5 * 60 * 60 * 1000), // 5h ago — cooldown is 20h
    });

    const db = makeMockDb();
    db.tenant.findMany
      .mockResolvedValueOnce([tenant])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([]);

    await runOneCycle(db);

    expect(sendRenewalReminderEmail).not.toHaveBeenCalled();
    expect(db.tenant.update).not.toHaveBeenCalled();
  });

  test('email throws for one tenant → other tenants still processed', async () => {
    const now = Date.now();
    const tenantA = makeTenant({ id: 'tenant_a', email: 'a@example.com', subscriptionEndDate: new Date(now + 150 * 60 * 60 * 1000) });
    const tenantB = makeTenant({ id: 'tenant_b', email: 'b@example.com', subscriptionEndDate: new Date(now + 150 * 60 * 60 * 1000) });

    sendRenewalReminderEmail
      .mockRejectedValueOnce(new Error('smtp down'))
      .mockResolvedValueOnce(undefined);

    const db = makeMockDb();
    db.tenant.findMany
      .mockResolvedValueOnce([tenantA, tenantB])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([]);

    await runOneCycle(db);

    expect(sendRenewalReminderEmail).toHaveBeenCalledTimes(2);
    // Only tenantB's update should have succeeded (tenantA's email threw
    // before its update call was reached, isolated by the per-tenant try/catch).
    expect(db.tenant.update).toHaveBeenCalledWith({
      where: { id: 'tenant_b' },
      data: { lastRenewalReminderSentAt: expect.any(Date) },
    });
    expect(db.tenant.update).toHaveBeenCalledTimes(1);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('Scheduler — Phase 2 (active→grace)', () => {
  test('empty list → no-op', async () => {
    const db = makeMockDb();
    db.tenant.findMany
      .mockResolvedValueOnce([]) // phase 1
      .mockResolvedValueOnce([]) // phase 2
      .mockResolvedValueOnce([]); // phase 3

    await runOneCycle(db);

    expect(db.tenant.update).not.toHaveBeenCalled();
    expect(sendGracePeriodEmail).not.toHaveBeenCalled();
  });

  test('expired tenant found → status updated to grace_period FIRST (before email)', async () => {
    const tenant = makeTenant({ subscriptionEndDate: new Date(Date.now() - 60000) });

    const db = makeMockDb();
    db.tenant.findMany
      .mockResolvedValueOnce([]) // phase 1
      .mockResolvedValueOnce([tenant]) // phase 2
      .mockResolvedValueOnce([]); // phase 3

    await runOneCycle(db);

    expect(db.tenant.update).toHaveBeenCalledWith({
      where: { id: tenant.id },
      data: {
        subscriptionStatus: 'grace_period',
        subscriptionEndDate: expect.any(Date),
      },
    });
    expect(sendGracePeriodEmail).toHaveBeenCalled();

    // Ordering: status update must be dispatched before the email call.
    const updateOrder = db.tenant.update.mock.invocationCallOrder[0];
    const emailOrder = sendGracePeriodEmail.mock.invocationCallOrder[0];
    expect(updateOrder).toBeLessThan(emailOrder);
  });

  test('cooldown active for notice → status still updated, email skipped', async () => {
    const tenant = makeTenant({
      subscriptionEndDate: new Date(Date.now() - 60000),
      lastGracePeriodNoticeSentAt: new Date(Date.now() - 5 * 60 * 60 * 1000), // 5h ago, cooldown 20h
    });

    const db = makeMockDb();
    db.tenant.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([tenant])
      .mockResolvedValueOnce([]);

    await runOneCycle(db);

    // Only ONE update call (the status change) — no second update for
    // lastGracePeriodNoticeSentAt since the email itself was skipped.
    expect(db.tenant.update).toHaveBeenCalledTimes(1);
    expect(sendGracePeriodEmail).not.toHaveBeenCalled();
  });

  test('cooldown clear → email sent + lastGracePeriodNoticeSentAt updated', async () => {
    const tenant = makeTenant({
      subscriptionEndDate: new Date(Date.now() - 60000),
      lastGracePeriodNoticeSentAt: null,
    });

    const db = makeMockDb();
    db.tenant.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([tenant])
      .mockResolvedValueOnce([]);

    await runOneCycle(db);

    expect(sendGracePeriodEmail).toHaveBeenCalledWith(
      { email: tenant.email, storeUrl: tenant.storeUrl },
      expect.objectContaining({ planLabel: 'Pro', renewUrl: 'https://chargeguard.io/upgrade.html?plan=pro_monthly' })
    );
    // Two update calls: the status flip, then the notice-sent timestamp.
    expect(db.tenant.update).toHaveBeenCalledTimes(2);
    expect(db.tenant.update).toHaveBeenNthCalledWith(2, {
      where: { id: tenant.id },
      data: { lastGracePeriodNoticeSentAt: expect.any(Date) },
    });
  });

  test('update/email throws → isolated per tenant', async () => {
    const tenantA = makeTenant({ id: 'tenant_a', subscriptionEndDate: new Date(Date.now() - 60000) });
    const tenantB = makeTenant({ id: 'tenant_b', subscriptionEndDate: new Date(Date.now() - 60000) });

    const db = makeMockDb();
    db.tenant.update
      .mockRejectedValueOnce(new Error('db write failed')) // tenantA's status update fails
      .mockResolvedValue({}); // tenantB (and any subsequent calls) succeed

    db.tenant.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([tenantA, tenantB])
      .mockResolvedValueOnce([]);

    await runOneCycle(db);

    // tenantB should still have been processed despite tenantA's failure.
    expect(db.tenant.update).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: 'tenant_b' } })
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('Scheduler — Phase 3 (grace→expired)', () => {
  test('empty list → no-op', async () => {
    const db = makeMockDb();
    db.tenant.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([]);

    await runOneCycle(db);

    expect(db.tenant.update).not.toHaveBeenCalled();
  });

  test('grace-expired tenant → downgraded to starter/expired, dates nulled', async () => {
    const tenant = makeTenant({ id: 'tenant_grace', plan: 'agency' });

    const db = makeMockDb();
    db.tenant.findMany
      .mockResolvedValueOnce([]) // phase 1
      .mockResolvedValueOnce([]) // phase 2
      .mockResolvedValueOnce([tenant]); // phase 3

    await runOneCycle(db);

    expect(db.tenant.update).toHaveBeenCalledWith({
      where: { id: 'tenant_grace' },
      data: {
        plan: 'starter',
        subscriptionStatus: 'expired',
        subscriptionEndDate: null,
        billingCycle: null,
      },
    });
  });

  test('update throws → isolated', async () => {
    const tenantA = makeTenant({ id: 'tenant_a' });
    const tenantB = makeTenant({ id: 'tenant_b' });

    const db = makeMockDb();
    db.tenant.update
      .mockRejectedValueOnce(new Error('db write failed'))
      .mockResolvedValue({});

    db.tenant.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([tenantA, tenantB]);

    await runOneCycle(db);

    expect(db.tenant.update).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: 'tenant_b' } })
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('Scheduler — Phase 4 (cleanup)', () => {
  test('deletes match OR condition', async () => {
    const db = makeMockDb();
    db.tenant.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([]);

    await runOneCycle(db);

    expect(db.checkoutSession.deleteMany).toHaveBeenCalledWith({
      where: {
        OR: [
          { status: 'pending', expiresAt: { lte: expect.any(Date) } },
          { status: { in: ['completed', 'failed', 'expired'] }, createdAt: { lte: expect.any(Date) } },
        ],
      },
    });
  });

  test('throws → caught, non-fatal', async () => {
    const db = makeMockDb();
    db.checkoutSession.deleteMany.mockRejectedValue(new Error('delete failed'));
    db.tenant.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([]);

    await expect(runOneCycle(db)).resolves.not.toThrow();
    expect(consoleErrorSpy).toHaveBeenCalled();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
describe('Orchestrator / bootstrap', () => {
  test('runSubscriptionCycle phase order preserved (verified via sequenced findMany)', async () => {
    const db = makeMockDb();
    db.tenant.findMany
      .mockResolvedValueOnce([]) // phase 1: renewal reminders
      .mockResolvedValueOnce([]) // phase 2: active → grace
      .mockResolvedValueOnce([]); // phase 3: grace → expired

    await runOneCycle(db);

    expect(db.tenant.findMany).toHaveBeenCalledTimes(3);

    const [call1, call2, call3] = db.tenant.findMany.mock.calls;
    // Phase 1 looks for still-active tenants with an upcoming end date.
    expect(call1[0].where).toEqual(
      expect.objectContaining({ subscriptionStatus: 'active', subscriptionEndDate: expect.objectContaining({ gt: expect.any(Date), lte: expect.any(Date) }) })
    );
    // Phase 2 looks for active tenants whose end date has already passed.
    expect(call2[0].where).toEqual(
      expect.objectContaining({ subscriptionStatus: 'active', subscriptionEndDate: { lte: expect.any(Date) } })
    );
    // Phase 3 looks for grace_period tenants whose (extended) end date has passed.
    expect(call3[0].where).toEqual(
      expect.objectContaining({ subscriptionStatus: 'grace_period', subscriptionEndDate: { lte: expect.any(Date) } })
    );

    // deleteMany (Phase 4) runs after all three findMany calls.
    const lastFindManyOrder = db.tenant.findMany.mock.invocationCallOrder[2];
    const deleteManyOrder = db.checkoutSession.deleteMany.mock.invocationCallOrder[0];
    expect(lastFindManyOrder).toBeLessThan(deleteManyOrder);
  });

  test('unhandled top-level error doesn’t crash', async () => {
    const db = makeMockDb();
    db.tenant.findMany.mockRejectedValue(new Error('catastrophic db outage'));

    await expect(runOneCycle(db)).resolves.not.toThrow();
    expect(consoleErrorSpy).toHaveBeenCalled();
  });

  test('startSubscriptionScheduler fires after 2min delay, then hourly', async () => {
    const db = makeMockDb();
    // Provide enough resolved values for multiple cycles (3 findMany calls per cycle).
    db.tenant.findMany.mockResolvedValue([]);

    startSubscriptionScheduler(db);

    // Nothing should have run before the initial delay elapses.
    expect(db.tenant.findMany).not.toHaveBeenCalled();

    await jest.advanceTimersByTimeAsync(INITIAL_DELAY_MS);
    expect(db.tenant.findMany).toHaveBeenCalledTimes(3); // first cycle (immediate run on startup)

    await jest.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(db.tenant.findMany).toHaveBeenCalledTimes(6); // second cycle, one hour later

    await jest.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(db.tenant.findMany).toHaveBeenCalledTimes(9); // third cycle
  });
});