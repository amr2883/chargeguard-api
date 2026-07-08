'use strict';

/**
 * SCOPE: src/lib/attackAlertScheduler.js
 * ---------------------------------------------------------------------------
 * Covers all 10 approved test cases from the T10 mapping table §5.1.
 *
 * MOCKING STRATEGY:
 *   - `../../src/lib/db` is mocked ONLY to prevent a real PrismaClient from
 *     being constructed on require (the module does `const db = require('./db')`
 *     at the top but NEVER actually uses it anywhere in the file — every query
 *     goes through the `prisma` argument injected into `startAttackAlertScheduler(prisma)`).
 *     This is a documented quirk, not a bug we're testing for; it just means
 *     mocking db.js has zero behavioral effect here, and the "real" mock is
 *     the plain object we build ourselves and pass in as `prisma`.
 *   - `../../src/lib/notify` is mocked for `notifyTenant` assertions.
 *   - `../../src/lib/planAccess` is NOT mocked — it's simple, pure, and
 *     already unit-tested elsewhere. We use real 'pro' / 'agency' / 'starter'
 *     values so the defense-in-depth re-check (test 3) exercises real logic.
 *   - No `logger.js` mock: this module logs via raw console.log/warn/error,
 *     not the shared logger. We spy on console methods to silence + assert.
 *   - `runAttackAlertCheck` is NOT exported — only `startAttackAlertScheduler`
 *     is. Every test therefore calls `startAttackAlertScheduler(prisma)` and
 *     advances fake timers to reach the core logic; there is no way to call
 *     the check function directly.
 */

jest.mock('../../src/lib/db', () => ({
  tenant: {},
  blockedAttempt: {},
  alertLog: {},
}));

jest.mock('../../src/lib/notify', () => ({
  notifyTenant: jest.fn(),
}));

const { startAttackAlertScheduler } = require('../../src/lib/attackAlertScheduler');
const { notifyTenant } = require('../../src/lib/notify');
const { SAVINGS_PER_ATTACK } = require('../../src/lib/constants');

// Mirrors non-exported constants from src/lib/attackAlertScheduler.js.
// Kept in sync manually since the module doesn't export them.
const STARTUP_DELAY_MS      = 2  * 60 * 1000;
const SCHEDULER_INTERVAL_MS = 2  * 60 * 1000;
const ATTACK_THRESHOLD      = 10;

// ── Factories ────────────────────────────────────────────────────────────

let tenantIdCounter = 0;
function makeTenant(overrides = {}) {
  tenantIdCounter += 1;
  return {
    id: `tenant-${tenantIdCounter}`,
    email: `tenant${tenantIdCounter}@example.com`,
    storeUrl: `https://store${tenantIdCounter}.example.com`,
    webhookUrl: null,
    webhookType: null,
    plan: 'pro',
    ...overrides,
  };
}

function makePrisma() {
  return {
    tenant: {
      findMany: jest.fn(),
    },
    blockedAttempt: {
      count: jest.fn(),
    },
    alertLog: {
      findFirst: jest.fn(),
      create: jest.fn(),
    },
  };
}

function applyPersistentDefaults(prisma) {
  prisma.tenant.findMany.mockResolvedValue([]);
  prisma.blockedAttempt.count.mockResolvedValue(0);
  prisma.alertLog.findFirst.mockResolvedValue(null);
  prisma.alertLog.create.mockResolvedValue({});
  notifyTenant.mockResolvedValue(undefined);
}

// Starts the scheduler and advances past the startup delay so the first
// tick's async work (including its internal awaits) has fully settled.
async function triggerFirstTick(prisma) {
  startAttackAlertScheduler(prisma);
  await jest.advanceTimersByTimeAsync(STARTUP_DELAY_MS);
}

describe('attackAlertScheduler', () => {
  let prisma;
  let logSpy;
  let warnSpy;
  let errorSpy;

  beforeEach(() => {
    jest.useFakeTimers();
    jest.resetAllMocks();
    prisma = makePrisma();
    applyPersistentDefaults(prisma);
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.clearAllTimers();
    jest.useRealTimers();
    logSpy.mockRestore();
    warnSpy.mockRestore();
    errorSpy.mockRestore();
  });

  // ── 1. tenant.findMany throws ───────────────────────────────────────────
  test('logs error and returns without further processing when tenant.findMany throws', async () => {
    prisma.tenant.findMany.mockRejectedValue(new Error('DB connection lost'));

    await triggerFirstTick(prisma);

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Failed to fetch tenants:'),
      'DB connection lost'
    );
    expect(prisma.blockedAttempt.count).not.toHaveBeenCalled();
    expect(prisma.alertLog.create).not.toHaveBeenCalled();
    expect(notifyTenant).not.toHaveBeenCalled();
  });

  // ── 2. empty tenant list ─────────────────────────────────────────────────
  test('no-ops with no notify calls when tenant list is empty', async () => {
    prisma.tenant.findMany.mockResolvedValue([]);

    await triggerFirstTick(prisma);

    expect(prisma.blockedAttempt.count).not.toHaveBeenCalled();
    expect(notifyTenant).not.toHaveBeenCalled();
  });

  // ── 3. defense-in-depth plan re-check ────────────────────────────────────
  test('skips tenant via defense-in-depth re-check when plan is not Pro+ despite query filter', async () => {
    // Simulates a query-filter regression: findMany "should" only return
    // pro/agency tenants, but here we return one with a non-qualifying plan
    // to prove the in-loop isProOrAbove() re-check catches it independently.
    const badTenant = makeTenant({ plan: 'starter' });
    prisma.tenant.findMany.mockResolvedValue([badTenant]);

    await triggerFirstTick(prisma);

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining(`Non-qualifying plan 'starter' reached alert loop`)
    );
    expect(prisma.blockedAttempt.count).not.toHaveBeenCalled();
    expect(notifyTenant).not.toHaveBeenCalled();
  });

  // ── 4. attackCount below threshold ──────────────────────────────────────
  test('does not alert when attackCount is below ATTACK_THRESHOLD', async () => {
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    prisma.blockedAttempt.count.mockResolvedValue(ATTACK_THRESHOLD - 1); // 9

    await triggerFirstTick(prisma);

    expect(prisma.alertLog.create).not.toHaveBeenCalled();
    expect(notifyTenant).not.toHaveBeenCalled();
  });

  // ── 5. threshold met, no recent alert → create THEN notify ─────────────
  test('creates AlertLog with correct fields then calls notifyTenant when threshold met and no recent alert', async () => {
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    prisma.blockedAttempt.count.mockResolvedValue(12);
    prisma.alertLog.findFirst.mockResolvedValue(null);

    await triggerFirstTick(prisma);

    const expectedSavedAmount = 12 * SAVINGS_PER_ATTACK;

    expect(prisma.alertLog.create).toHaveBeenCalledWith({
      data: {
        tenantId: tenant.id,
        alertType: 'attack_detected',
        attackCount: 12,
        savedAmount: expectedSavedAmount,
      },
    });
    expect(notifyTenant).toHaveBeenCalledWith(tenant, 12, expectedSavedAmount);

    // Ordering: create must be called before notifyTenant.
    const createOrder = prisma.alertLog.create.mock.invocationCallOrder[0];
    const notifyOrder = notifyTenant.mock.invocationCallOrder[0];
    expect(createOrder).toBeLessThan(notifyOrder);
  });

  // ── 6. recent alert within cooldown ─────────────────────────────────────
  test('skips tenant with no create/notify when a recent AlertLog exists within cooldown', async () => {
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    prisma.blockedAttempt.count.mockResolvedValue(15);
    prisma.alertLog.findFirst.mockResolvedValue({ id: 'existing-alert-id' });

    await triggerFirstTick(prisma);

    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining(`Skipping ${tenant.email} — alert sent within cooldown window`)
    );
    expect(prisma.alertLog.create).not.toHaveBeenCalled();
    expect(notifyTenant).not.toHaveBeenCalled();
  });

  // ── 7. notifyTenant rejects ──────────────────────────────────────────────
  test('catches notifyTenant rejection without throwing to the outer loop', async () => {
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    prisma.blockedAttempt.count.mockResolvedValue(10);
    prisma.alertLog.findFirst.mockResolvedValue(null);
    notifyTenant.mockRejectedValue(new Error('SMTP down'));

    // Should not throw / reject even though notifyTenant rejects internally.
    await expect(triggerFirstTick(prisma)).resolves.not.toThrow();

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining(`Notification failed for ${tenant.email}:`),
      'SMTP down'
    );
  });

  // ── 8. per-tenant isolation on blockedAttempt.count throw ───────────────
  test('isolates a tenant whose blockedAttempt.count throws, other tenants still processed', async () => {
    const failingTenant = makeTenant({ id: 'tenant-fail' });
    const okTenant = makeTenant({ id: 'tenant-ok' });
    prisma.tenant.findMany.mockResolvedValue([failingTenant, okTenant]);

    prisma.blockedAttempt.count.mockImplementation(({ where }) => {
      if (where.tenantId === 'tenant-fail') {
        return Promise.reject(new Error('count query exploded'));
      }
      return Promise.resolve(11);
    });
    prisma.alertLog.findFirst.mockResolvedValue(null);

    await triggerFirstTick(prisma);

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Error processing tenant tenant-fail:'),
      'count query exploded'
    );
    // The healthy tenant still reaches AlertLog.create + notifyTenant.
    expect(prisma.alertLog.create).toHaveBeenCalledWith({
      data: {
        tenantId: 'tenant-ok',
        alertType: 'attack_detected',
        attackCount: 11,
        savedAmount: 11 * SAVINGS_PER_ATTACK,
      },
    });
    expect(notifyTenant).toHaveBeenCalledWith(okTenant, 11, 11 * SAVINGS_PER_ATTACK);
  });

  // ── 9. timer wiring ──────────────────────────────────────────────────────
  test('fires first run after 2min startup delay, then every 2min via setInterval', async () => {
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    prisma.blockedAttempt.count.mockResolvedValue(0);

    startAttackAlertScheduler(prisma);

    // Before the startup delay elapses, nothing should have run yet.
    expect(prisma.tenant.findMany).not.toHaveBeenCalled();

    await jest.advanceTimersByTimeAsync(STARTUP_DELAY_MS);
    expect(prisma.tenant.findMany).toHaveBeenCalledTimes(1);

    // Advance one full interval — second run should fire.
    await jest.advanceTimersByTimeAsync(SCHEDULER_INTERVAL_MS);
    expect(prisma.tenant.findMany).toHaveBeenCalledTimes(2);

    // Advance another interval — third run should fire.
    await jest.advanceTimersByTimeAsync(SCHEDULER_INTERVAL_MS);
    expect(prisma.tenant.findMany).toHaveBeenCalledTimes(3);
  });

  // ── 10. savedAmount calculation ──────────────────────────────────────────
  test('calculates savedAmount as attackCount * SAVINGS_PER_ATTACK exactly', async () => {
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    prisma.blockedAttempt.count.mockResolvedValue(37);
    prisma.alertLog.findFirst.mockResolvedValue(null);

    await triggerFirstTick(prisma);

    const expected = 37 * SAVINGS_PER_ATTACK; // 11.1

    expect(prisma.alertLog.create.mock.calls[0][0].data.savedAmount).toBeCloseTo(expected, 5);
    expect(notifyTenant.mock.calls[0][2]).toBeCloseTo(expected, 5);
  });
});