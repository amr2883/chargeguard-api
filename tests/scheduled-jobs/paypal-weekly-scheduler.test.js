'use strict';

/**
 * ══════════════════════════════════════════════════════════════════════════
 * SCOPE
 * ══════════════════════════════════════════════════════════════════════════
 * Covers src/jobs/paypalWeeklyReportScheduler.js (13 test cases, mapping
 * table §5.3):
 *   1. Gate: Sunday but minute < 30 → no-op
 *   2. Gate: Sunday, hour 9, minute >= 30 → proceeds
 *   3. alreadySent this week → skip
 *   4. malformed signalsSnapshot JSON → filtered out silently (try/catch)
 *   5. enrichmentSource !== 'paypal' → excluded from paypalOrders
 *   6. paypalTxnCount === 0 → tenant skipped entirely (no AlertLog, no email)
 *   7. some blocked + some flagged → counts correct, thisWeekSuspicious = sum
 *   8. topCardCountry only counted from block/review orders (approve excluded)
 *   9. weekOverWeekPct null when prevWeek suspicious === 0
 *   10. AlertLog.create happens before email dispatch
 *   11. tenant error isolation (one tenant throws, others still processed)
 *   12. 4s inter-tenant delay
 *   13. timer wiring — 90min startup delay, hourly interval
 *
 * ══════════════════════════════════════════════════════════════════════════
 * MOCKING STRATEGY
 * ══════════════════════════════════════════════════════════════════════════
 * - The scheduler dead-imports '../lib/db' at module load (it never actually
 *   uses the `db` binding — prisma is injected as a function parameter
 *   instead). We mock '../../src/lib/db' to a plain {} purely to prevent a
 *   real PrismaClient from being constructed on require.
 * - The real `prisma` used by the scheduler is a plain object built per-test
 *   via makePrisma() and passed into startPaypalWeeklyReportScheduler(prisma).
 * - '../../src/lib/email' is mocked so we can assert on
 *   sendPaypalWeeklyReportEmail's call args without building real HTML.
 * - '../../src/lib/constants' is mocked to pin SAVINGS_PER_ATTACK to a known
 *   value (25) so savedAmount assertions are deterministic.
 * - No logger.js mock — the module logs via console.* directly; we don't
 *   assert on console output except where explicitly relevant.
 * - jest.useFakeTimers() + jest.setSystemTime() control both the gate check
 *   (`new Date()` inside runPaypalWeeklyReportCheck) and the setTimeout/
 *   setInterval wiring. System time is always seeded 90 minutes *before*
 *   the desired "now" at first-run time, since STARTUP_DELAY_MS elapses
 *   before the first check executes.
 *
 * QUIRK NOTES (documented inline near relevant tests):
 * - order.findMany is called TWICE per tenant (this-week, then prev-week)
 *   with the same prisma mock — differentiated here by inspecting the
 *   `where.createdAt` shape (`lt` present => prev-week query).
 * - Email dispatch is fire-and-forget (`.then/.catch`, not awaited) inside
 *   processPaypalTenant, so tests flush microtasks after advancing timers
 *   to let the dispatch's promise chain settle before asserting.
 */

jest.mock('../../src/lib/db', () => ({}));

jest.mock('../../src/lib/email', () => ({
  sendPaypalWeeklyReportEmail: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../../src/lib/constants', () => ({
  SAVINGS_PER_ATTACK: 25,
}));

const { startPaypalWeeklyReportScheduler } = require('../../src/jobs/paypalWeeklyReportScheduler');
const { sendPaypalWeeklyReportEmail }      = require('../../src/lib/email');

// ── Tuneable constants mirrored from the source module ─────────────────────
const STARTUP_DELAY_MS = 90 * 60 * 1000; // 90 min
const INTERVAL_MS      = 60 * 60 * 1000; // 1 hr
const TENANT_DELAY_MS  = 4000;           // 4s

// System-time anchors. STARTUP_DELAY_MS elapses before the first check runs,
// so we seed "now" 90 minutes earlier than the target check time.
const SUNDAY_0930_TARGET     = new Date('2024-01-07T09:30:00.000Z'); // Sun, minute===30 → proceeds
const SUNDAY_0915_TARGET     = new Date('2024-01-07T09:15:00.000Z'); // Sun, minute<30  → no-op
const SEED_FOR_0930 = new Date(SUNDAY_0930_TARGET.getTime() - STARTUP_DELAY_MS);
const SEED_FOR_0915 = new Date(SUNDAY_0915_TARGET.getTime() - STARTUP_DELAY_MS);

// ── Helper factories ─────────────────────────────────────────────────────

function makeTenant(overrides = {}) {
  return {
    id: 'tenant-1',
    email: 'merchant@example.com',
    storeUrl: 'https://shop.example.com',
    ...overrides,
  };
}

function makeOrder({ decision = 'approve', enrichmentSource = 'paypal', cardIssuerCountry = null, snapshotOverride } = {}) {
  const snapshot = snapshotOverride !== undefined
    ? snapshotOverride
    : JSON.stringify({ enrichmentSource, cardIssuerCountry });
  return { decision, signalsSnapshot: snapshot };
}

function makePrisma() {
  return {
    tenant: { findMany: jest.fn() },
    order:  { findMany: jest.fn() },
    alertLog: {
      findFirst: jest.fn(),
      create:    jest.fn(),
      aggregate: jest.fn(),
    },
  };
}

function applyPersistentDefaults(prisma) {
  prisma.tenant.findMany.mockResolvedValue([]);
  prisma.order.findMany.mockResolvedValue([]);
  prisma.alertLog.findFirst.mockResolvedValue(null);
  prisma.alertLog.create.mockResolvedValue({});
  prisma.alertLog.aggregate.mockResolvedValue({ _sum: { attackCount: 0 } });
}

// Configures order.findMany to return per-tenant, per-window data, keyed by
// merchantId. `current` = this-week orders, `prev` = last-week orders.
// throwOnCurrent/throwOnPrev let tests simulate a rejected fetch.
function configureOrders(prisma, configByMerchantId) {
  prisma.order.findMany.mockImplementation(async ({ where }) => {
    const cfg = configByMerchantId[where.merchantId];
    if (!cfg) return [];
    const isPrevWeek = !!(where.createdAt && 'lt' in where.createdAt);
    if (isPrevWeek && cfg.throwOnPrev) throw cfg.throwOnPrev;
    if (!isPrevWeek && cfg.throwOnCurrent) throw cfg.throwOnCurrent;
    return isPrevWeek ? (cfg.prev || []) : (cfg.current || []);
  });
}

function configureAlreadySent(prisma, sentTenantIds) {
  prisma.alertLog.findFirst.mockImplementation(async ({ where }) => (
    sentTenantIds.includes(where.tenantId) ? { id: 'alert-1' } : null
  ));
}

async function flushMicrotasks() {
  for (let i = 0; i < 5; i++) {
    await Promise.resolve();
  }
}

// Starts the scheduler and advances past STARTUP_DELAY_MS so the first
// check executes at the seeded "now".
async function triggerInitialRun(prisma) {
  startPaypalWeeklyReportScheduler(prisma);
  await jest.advanceTimersByTimeAsync(STARTUP_DELAY_MS);
  await flushMicrotasks();
}

// ── Test suite ───────────────────────────────────────────────────────────

describe('paypalWeeklyReportScheduler', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.resetAllMocks();
    sendPaypalWeeklyReportEmail.mockResolvedValue(undefined);
  });

  afterEach(() => {
    jest.clearAllTimers();
    jest.useRealTimers();
  });

  // ── Gate logic ───────────────────────────────────────────────────────────
  describe('gate: Sunday 09:30-09:59 UTC window', () => {
    test('1. Sunday but minute < 30 → no-op (tenant fetch never runs)', async () => {
      jest.setSystemTime(SEED_FOR_0915);
      const prisma = makePrisma();
      applyPersistentDefaults(prisma);

      await triggerInitialRun(prisma);

      expect(prisma.tenant.findMany).not.toHaveBeenCalled();
    });

    test('2. Sunday, hour 9, minute >= 30 → proceeds (tenant fetch runs)', async () => {
      jest.setSystemTime(SEED_FOR_0930);
      const prisma = makePrisma();
      applyPersistentDefaults(prisma);
      prisma.tenant.findMany.mockResolvedValue([makeTenant()]);

      await triggerInitialRun(prisma);

      expect(prisma.tenant.findMany).toHaveBeenCalledWith({
        where:  { isActive: true },
        select: { id: true, email: true, storeUrl: true },
      });
    });
  });

  // ── Anti-duplication ─────────────────────────────────────────────────────
  describe('anti-duplication', () => {
    test('3. alreadySent this week → tenant skipped', async () => {
      jest.setSystemTime(SEED_FOR_0930);
      const tenant = makeTenant();
      const prisma = makePrisma();
      applyPersistentDefaults(prisma);
      prisma.tenant.findMany.mockResolvedValue([tenant]);
      configureAlreadySent(prisma, [tenant.id]);

      await triggerInitialRun(prisma);

      expect(prisma.alertLog.findFirst).toHaveBeenCalledWith({
        where: expect.objectContaining({
          tenantId:  tenant.id,
          alertType: 'paypal_weekly_shield',
        }),
        select: { id: true },
      });
      expect(prisma.order.findMany).not.toHaveBeenCalled();
      expect(prisma.alertLog.create).not.toHaveBeenCalled();
      expect(sendPaypalWeeklyReportEmail).not.toHaveBeenCalled();
    });
  });

  // ── signalsSnapshot filtering ────────────────────────────────────────────
  describe('signalsSnapshot filtering', () => {
    test('4. malformed signalsSnapshot JSON filtered out silently', async () => {
      jest.setSystemTime(SEED_FOR_0930);
      const tenant = makeTenant();
      const prisma = makePrisma();
      applyPersistentDefaults(prisma);
      prisma.tenant.findMany.mockResolvedValue([tenant]);

      configureOrders(prisma, {
        [tenant.id]: {
          current: [
            makeOrder({ snapshotOverride: '{not valid json' }), // malformed → excluded
            makeOrder({ decision: 'approve', enrichmentSource: 'paypal' }), // valid → counted
          ],
        },
      });

      await triggerInitialRun(prisma);

      expect(sendPaypalWeeklyReportEmail).toHaveBeenCalledWith(
        expect.objectContaining({ paypalTxnCount: 1 })
      );
    });

    test('5. enrichmentSource !== "paypal" excluded from paypalOrders', async () => {
      jest.setSystemTime(SEED_FOR_0930);
      const tenant = makeTenant();
      const prisma = makePrisma();
      applyPersistentDefaults(prisma);
      prisma.tenant.findMany.mockResolvedValue([tenant]);

      configureOrders(prisma, {
        [tenant.id]: {
          current: [
            makeOrder({ decision: 'approve', enrichmentSource: 'stripe' }), // excluded
            makeOrder({ decision: 'approve', enrichmentSource: 'paypal' }), // counted
          ],
        },
      });

      await triggerInitialRun(prisma);

      expect(sendPaypalWeeklyReportEmail).toHaveBeenCalledWith(
        expect.objectContaining({ paypalTxnCount: 1 })
      );
    });
  });

  // ── Zero-PayPal-usage skip ───────────────────────────────────────────────
  describe('zero PayPal transactions', () => {
    test('6. paypalTxnCount === 0 → tenant skipped entirely (no AlertLog, no email)', async () => {
      jest.setSystemTime(SEED_FOR_0930);
      const tenant = makeTenant();
      const prisma = makePrisma();
      applyPersistentDefaults(prisma);
      prisma.tenant.findMany.mockResolvedValue([tenant]);
      configureOrders(prisma, { [tenant.id]: { current: [] } });

      await triggerInitialRun(prisma);

      // Duplication check still happens (it precedes the txn-count gate)...
      expect(prisma.alertLog.findFirst).toHaveBeenCalled();
      // ...but nothing further is written or sent.
      expect(prisma.alertLog.create).not.toHaveBeenCalled();
      expect(sendPaypalWeeklyReportEmail).not.toHaveBeenCalled();
    });
  });

  // ── Blocked/flagged counting ─────────────────────────────────────────────
  describe('blocked + flagged counting', () => {
    test('7. paypalBlockedCount/paypalFlaggedCount counted correctly; thisWeekSuspicious = sum', async () => {
      jest.setSystemTime(SEED_FOR_0930);
      const tenant = makeTenant();
      const prisma = makePrisma();
      applyPersistentDefaults(prisma);
      prisma.tenant.findMany.mockResolvedValue([tenant]);

      configureOrders(prisma, {
        [tenant.id]: {
          current: [
            makeOrder({ decision: 'block' }),
            makeOrder({ decision: 'block' }),
            makeOrder({ decision: 'review' }),
            makeOrder({ decision: 'approve' }),
          ],
        },
      });

      await triggerInitialRun(prisma);

      expect(sendPaypalWeeklyReportEmail).toHaveBeenCalledWith(
        expect.objectContaining({
          paypalTxnCount:     4,
          paypalBlockedCount: 2,
          paypalFlaggedCount: 1,
        })
      );
      // thisWeekSuspicious isn't a direct email field by that name, but it
      // flows into AlertLog.attackCount — verify the sum there too.
      expect(prisma.alertLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({ attackCount: 3 }),
      });
    });
  });

  // ── topCardCountry tally ─────────────────────────────────────────────────
  describe('topCardCountry tally', () => {
    test('8. approve-decision orders excluded from country tally', async () => {
      jest.setSystemTime(SEED_FOR_0930);
      const tenant = makeTenant();
      const prisma = makePrisma();
      applyPersistentDefaults(prisma);
      prisma.tenant.findMany.mockResolvedValue([tenant]);

      configureOrders(prisma, {
        [tenant.id]: {
          current: [
            // 3x approve/US — would dominate the tally if wrongly included
            makeOrder({ decision: 'approve', cardIssuerCountry: 'US' }),
            makeOrder({ decision: 'approve', cardIssuerCountry: 'US' }),
            makeOrder({ decision: 'approve', cardIssuerCountry: 'US' }),
            // FR: 1 block + 1 review = 2 (counted)
            makeOrder({ decision: 'block',  cardIssuerCountry: 'FR' }),
            makeOrder({ decision: 'review', cardIssuerCountry: 'FR' }),
            // DE: 1 block = 1 (counted, but fewer than FR)
            makeOrder({ decision: 'block',  cardIssuerCountry: 'DE' }),
          ],
        },
      });

      await triggerInitialRun(prisma);

      expect(sendPaypalWeeklyReportEmail).toHaveBeenCalledWith(
        expect.objectContaining({ topCardCountry: 'FR' })
      );
    });
  });

  // ── weekOverWeekPct ──────────────────────────────────────────────────────
  describe('weekOverWeekPct', () => {
    test('9. null when prevWeek suspicious count is 0', async () => {
      jest.setSystemTime(SEED_FOR_0930);
      const tenant = makeTenant();
      const prisma = makePrisma();
      applyPersistentDefaults(prisma);
      prisma.tenant.findMany.mockResolvedValue([tenant]);

      configureOrders(prisma, {
        [tenant.id]: {
          current: [makeOrder({ decision: 'block' })],
          prev:    [], // no suspicious orders last week
        },
      });

      await triggerInitialRun(prisma);

      expect(sendPaypalWeeklyReportEmail).toHaveBeenCalledWith(
        expect.objectContaining({ weekOverWeekPct: null })
      );
    });
  });

  // ── Write-before-send ordering ───────────────────────────────────────────
  describe('AlertLog.create ordering', () => {
    test('10. AlertLog.create happens before email dispatch', async () => {
      jest.setSystemTime(SEED_FOR_0930);
      const tenant = makeTenant();
      const prisma = makePrisma();
      applyPersistentDefaults(prisma);
      prisma.tenant.findMany.mockResolvedValue([tenant]);
      configureOrders(prisma, {
        [tenant.id]: { current: [makeOrder({ decision: 'block' })] },
      });

      const callOrder = [];
      prisma.alertLog.create.mockImplementation(async () => {
        callOrder.push('create');
        return {};
      });
      sendPaypalWeeklyReportEmail.mockImplementation(async () => {
        callOrder.push('email');
      });

      await triggerInitialRun(prisma);

      expect(callOrder).toEqual(['create', 'email']);
    });
  });

  // ── Tenant error isolation ───────────────────────────────────────────────
  describe('tenant error isolation', () => {
    test('11. one tenant throwing does not stop processing of remaining tenants', async () => {
      jest.setSystemTime(SEED_FOR_0930);
      const failingTenant  = makeTenant({ id: 'tenant-fail', email: 'fail@example.com' });
      const healthyTenant  = makeTenant({ id: 'tenant-ok',   email: 'ok@example.com' });
      const prisma = makePrisma();
      applyPersistentDefaults(prisma);
      prisma.tenant.findMany.mockResolvedValue([failingTenant, healthyTenant]);

      configureOrders(prisma, {
        [failingTenant.id]: { throwOnCurrent: new Error('DB blew up') },
        [healthyTenant.id]: { current: [makeOrder({ decision: 'block' })] },
      });

      await triggerInitialRun(prisma);
      // Flush the 4s inter-tenant delay so the healthy tenant is processed.
      await jest.advanceTimersByTimeAsync(TENANT_DELAY_MS);
      await flushMicrotasks();

      // Healthy tenant still got its alert + email despite the other's failure.
      expect(prisma.alertLog.create).toHaveBeenCalledTimes(1);
      expect(sendPaypalWeeklyReportEmail).toHaveBeenCalledTimes(1);
      expect(sendPaypalWeeklyReportEmail).toHaveBeenCalledWith(
        expect.objectContaining({ tenant: healthyTenant })
      );
    });
  });

  // ── Inter-tenant delay ───────────────────────────────────────────────────
  describe('inter-tenant delay', () => {
    test('12. 4s delay between tenants', async () => {
      jest.setSystemTime(SEED_FOR_0930);
      const tenant1 = makeTenant({ id: 'tenant-1', email: 't1@example.com' });
      const tenant2 = makeTenant({ id: 'tenant-2', email: 't2@example.com' });
      const prisma = makePrisma();
      applyPersistentDefaults(prisma);
      prisma.tenant.findMany.mockResolvedValue([tenant1, tenant2]);

      configureOrders(prisma, {
        [tenant1.id]: { current: [makeOrder({ decision: 'block' })] },
        [tenant2.id]: { current: [makeOrder({ decision: 'block' })] },
      });

      await triggerInitialRun(prisma);

      // Tenant 1 fully processed synchronously; tenant 2 not yet (delay pending).
      expect(prisma.alertLog.create).toHaveBeenCalledTimes(1);
      expect(sendPaypalWeeklyReportEmail).toHaveBeenCalledTimes(1);

      // Just under 4s — still nothing new.
      await jest.advanceTimersByTimeAsync(TENANT_DELAY_MS - 1);
      await flushMicrotasks();
      expect(prisma.alertLog.create).toHaveBeenCalledTimes(1);

      // The final millisecond releases tenant 2.
      await jest.advanceTimersByTimeAsync(1);
      await flushMicrotasks();
      expect(prisma.alertLog.create).toHaveBeenCalledTimes(2);
      expect(sendPaypalWeeklyReportEmail).toHaveBeenCalledTimes(2);
    });
  });

  // ── Timer wiring ─────────────────────────────────────────────────────────
  describe('timer wiring', () => {
    test('13. 90min startup delay, hourly recurring interval', async () => {
      jest.setSystemTime(SEED_FOR_0930);
      const prisma = makePrisma();
      applyPersistentDefaults(prisma);

      const setTimeoutSpy  = jest.spyOn(global, 'setTimeout');
      const setIntervalSpy = jest.spyOn(global, 'setInterval');

      startPaypalWeeklyReportScheduler(prisma);

      expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), STARTUP_DELAY_MS);
      // Interval is only registered once the startup timeout fires.
      expect(setIntervalSpy).not.toHaveBeenCalled();

      await jest.advanceTimersByTimeAsync(STARTUP_DELAY_MS);
      await flushMicrotasks();

      expect(setIntervalSpy).toHaveBeenCalledWith(expect.any(Function), INTERVAL_MS);

      setTimeoutSpy.mockRestore();
      setIntervalSpy.mockRestore();
    });
  });
});