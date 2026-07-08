'use strict';

/**
 * SCOPE: src/jobs/weeklySummaryScheduler.js
 * ---------------------------------------------------------------------------
 * Covers all 14 approved test cases from the T10 mapping table §5.2.
 *
 * MOCKING STRATEGY:
 *   - `../../src/lib/db` is mocked ONLY to prevent a real PrismaClient from
 *     being constructed on require. As with attackAlertScheduler.js, the
 *     module `require`s db.js but NEVER uses it — every query goes through
 *     the `prisma` argument injected into `startWeeklySummaryScheduler(prisma)`.
 *   - `../../src/lib/email` is mocked for `sendWeeklySummaryEmail` assertions.
 *   - No `planAccess` mock: unlike attackAlertScheduler.js, this scheduler's
 *     `tenant.findMany` query has NO plan filter (`where: { isActive: true }`
 *     only) and there is no in-loop plan re-check. Weekly summaries go to
 *     ALL active tenants regardless of plan — confirmed from source, not
 *     assumed from the attack-alert pattern.
 *   - No `logger.js` mock: this module logs via raw console.log/warn/error.
 *     We spy on console methods to silence + assert.
 *   - `runWeeklySummaryCheck` / `processTenant` are NOT exported — only
 *     `startWeeklySummaryScheduler` is. Every test calls
 *     `startWeeklySummaryScheduler(prisma)` and advances fake timers.
 *   - The gate (`now.getUTCDay() !== SEND_DAY_UTC || now.getUTCHours() !== SEND_HOUR_UTC`)
 *     depends on wall-clock time read via `new Date()` inside the module, so
 *     we use `jest.setSystemTime()` BEFORE starting the scheduler, offset
 *     backwards by STARTUP_DELAY_MS, so that after advancing fake timers by
 *     STARTUP_DELAY_MS the simulated "now" lands exactly on our target date.
 */

jest.mock('../../src/lib/db', () => ({
  tenant: {},
  alertLog: {},
  blockedAttempt: {},
}));

jest.mock('../../src/lib/email', () => ({
  sendWeeklySummaryEmail: jest.fn(),
}));

const { startWeeklySummaryScheduler } = require('../../src/jobs/weeklySummaryScheduler');
const { sendWeeklySummaryEmail } = require('../../src/lib/email');
const { SAVINGS_PER_ATTACK, QUIET_STREAK_THRESHOLD } = require('../../src/lib/constants');

// Mirrors non-exported constants from src/jobs/weeklySummaryScheduler.js.
const STARTUP_DELAY_MS       = 60 * 60 * 1000; // 1 hour
const SCHEDULER_INTERVAL_MS  = 60 * 60 * 1000; // 1 hour
const TENANT_DELAY_MS        = 3000;           // 3s courtesy delay

// Jan 1, 2023 00:00:00 UTC is a Sunday — fixed anchor, no calendar lookups needed.
const SUNDAY_0930  = new Date(Date.UTC(2023, 0, 1, 9, 30, 0));  // Sunday, in-window
const SUNDAY_1000  = new Date(Date.UTC(2023, 0, 1, 10, 0, 0));  // Sunday, wrong hour
const MONDAY_0930  = new Date(Date.UTC(2023, 0, 2, 9, 30, 0));  // Monday, right hour

// ── Factories ────────────────────────────────────────────────────────────

let tenantIdCounter = 0;
function makeTenant(overrides = {}) {
  tenantIdCounter += 1;
  return {
    id: `tenant-${tenantIdCounter}`,
    email: `tenant${tenantIdCounter}@example.com`,
    storeUrl: `https://store${tenantIdCounter}.example.com`,
    ...overrides,
  };
}

function makeBlockedAttempt(reason) {
  return { reason };
}

function makeAlertLog(overrides = {}) {
  return { attackCount: 0, ...overrides };
}

function makePrisma() {
  return {
    tenant: {
      findMany: jest.fn(),
    },
    alertLog: {
      findFirst: jest.fn(),
      findMany: jest.fn(),
      create: jest.fn(),
      aggregate: jest.fn(),
    },
    blockedAttempt: {
      findMany: jest.fn(),
      count: jest.fn(),
    },
  };
}

function applyPersistentDefaults(prisma) {
  prisma.tenant.findMany.mockResolvedValue([]);
  prisma.alertLog.findFirst.mockResolvedValue(null);
  prisma.alertLog.findMany.mockResolvedValue([]);
  prisma.alertLog.create.mockResolvedValue({});
  prisma.alertLog.aggregate.mockResolvedValue({ _sum: { attackCount: 0, savedAmount: 0 } });
  prisma.blockedAttempt.findMany.mockResolvedValue([]);
  prisma.blockedAttempt.count.mockResolvedValue(0);
  sendWeeklySummaryEmail.mockResolvedValue(undefined);
}

// Sets system time so that after advancing STARTUP_DELAY_MS, "now" equals target.
function setNowForTick(target) {
  jest.setSystemTime(new Date(target.getTime() - STARTUP_DELAY_MS));
}

async function triggerFirstTick(prisma) {
  startWeeklySummaryScheduler(prisma);
  await jest.advanceTimersByTimeAsync(STARTUP_DELAY_MS);
}

describe('weeklySummaryScheduler', () => {
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

  // ── 1. gate: not Sunday ──────────────────────────────────────────────────
  test('no-ops when today is not Sunday', async () => {
    setNowForTick(MONDAY_0930);

    await triggerFirstTick(prisma);

    expect(prisma.tenant.findMany).not.toHaveBeenCalled();
  });

  // ── 2. gate: Sunday but wrong hour ───────────────────────────────────────
  test('no-ops when it is Sunday but outside the 09:xx UTC window', async () => {
    setNowForTick(SUNDAY_1000);

    await triggerFirstTick(prisma);

    expect(prisma.tenant.findMany).not.toHaveBeenCalled();
  });

  // ── 3. gate: Sunday 09:xx UTC ─────────────────────────────────────────────
  test('proceeds when it is Sunday within the 09:xx UTC window', async () => {
    setNowForTick(SUNDAY_0930);
    prisma.tenant.findMany.mockResolvedValue([]);

    await triggerFirstTick(prisma);

    expect(prisma.tenant.findMany).toHaveBeenCalledWith({
      where: { isActive: true },
      select: { id: true, email: true, storeUrl: true },
    });
  });

  // ── 4. alreadySent this week ──────────────────────────────────────────────
  test('skips tenant entirely when weekly_summary already sent this week', async () => {
    setNowForTick(SUNDAY_0930);
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    prisma.alertLog.findFirst.mockResolvedValue({ id: 'existing-log' });

    await triggerFirstTick(prisma);

    expect(prisma.blockedAttempt.findMany).not.toHaveBeenCalled();
    expect(prisma.alertLog.create).not.toHaveBeenCalled();
    expect(sendWeeklySummaryEmail).not.toHaveBeenCalled();
  });

  // ── 5. active week: reasonBreakdown/topReason, create BEFORE email ──────
  test('computes reasonBreakdown/topReason, writes AlertLog BEFORE sending full email', async () => {
    setNowForTick(SUNDAY_0930);
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    prisma.alertLog.findFirst.mockResolvedValue(null);
    prisma.blockedAttempt.findMany.mockResolvedValue([
      makeBlockedAttempt('card_testing'),
      makeBlockedAttempt('card_testing'),
      makeBlockedAttempt('velocity'),
    ]);
    prisma.blockedAttempt.count.mockResolvedValue(0); // prevWeekCount

    await triggerFirstTick(prisma);

    const expectedSavedAmount = 3 * SAVINGS_PER_ATTACK;

    expect(prisma.alertLog.create).toHaveBeenCalledWith({
      data: {
        tenantId: tenant.id,
        alertType: 'weekly_summary',
        attackCount: 3,
        savedAmount: expectedSavedAmount,
      },
    });

    expect(sendWeeklySummaryEmail).toHaveBeenCalledWith(
      expect.objectContaining({
        tenant,
        thisWeekCount: 3,
        savedAmount: expectedSavedAmount,
        topReason: 'card_testing',
        reasonBreakdown: [
          { reason: 'card_testing', count: 2, pct: 67 },
          { reason: 'velocity', count: 1, pct: 33 },
        ],
        historicalTotal: null,
      })
    );

    const createOrder = prisma.alertLog.create.mock.invocationCallOrder[0];
    const emailOrder = sendWeeklySummaryEmail.mock.invocationCallOrder[0];
    expect(createOrder).toBeLessThan(emailOrder);
  });

  // ── 6. quiet week, streak below threshold ────────────────────────────────
  test('writes AlertLog with attackCount:0 and sends quiet email when streak is below threshold', async () => {
    setNowForTick(SUNDAY_0930);
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    prisma.alertLog.findFirst.mockResolvedValue(null);
    prisma.blockedAttempt.findMany.mockResolvedValue([]); // thisWeekCount = 0
    prisma.blockedAttempt.count.mockResolvedValue(0);
    // Only 1 prior quiet week on record — streak (1) < QUIET_STREAK_THRESHOLD (3)
    prisma.alertLog.findMany.mockResolvedValue([makeAlertLog({ attackCount: 0 })]);

    await triggerFirstTick(prisma);

    expect(prisma.alertLog.create).toHaveBeenCalledWith({
      data: {
        tenantId: tenant.id,
        alertType: 'weekly_summary',
        attackCount: 0,
        savedAmount: 0,
      },
    });
    expect(sendWeeklySummaryEmail).toHaveBeenCalledWith(
      expect.objectContaining({ thisWeekCount: 0 })
    );
  });

  // ── 7. quiet week, streak >= threshold ───────────────────────────────────
  test('still writes AlertLog but SKIPS email when quiet streak reaches threshold', async () => {
    setNowForTick(SUNDAY_0930);
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    prisma.alertLog.findFirst.mockResolvedValue(null);
    prisma.blockedAttempt.findMany.mockResolvedValue([]);
    prisma.blockedAttempt.count.mockResolvedValue(0);
    // 3 consecutive quiet weeks already on record — streak (3) >= QUIET_STREAK_THRESHOLD (3)
    prisma.alertLog.findMany.mockResolvedValue([
      makeAlertLog({ attackCount: 0 }),
      makeAlertLog({ attackCount: 0 }),
      makeAlertLog({ attackCount: 0 }),
    ]);

    await triggerFirstTick(prisma);

    expect(prisma.alertLog.create).toHaveBeenCalledWith({
      data: {
        tenantId: tenant.id,
        alertType: 'weekly_summary',
        attackCount: 0,
        savedAmount: 0,
      },
    });
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining(`${QUIET_STREAK_THRESHOLD} consecutive quiet weeks, skipping email`)
    );
    expect(sendWeeklySummaryEmail).not.toHaveBeenCalled();
  });

  // ── 8. weekOverWeekPct null on prevWeekCount === 0 ──────────────────────
  test('weekOverWeekPct is null when prevWeekCount is 0 (avoids divide-by-zero)', async () => {
    setNowForTick(SUNDAY_0930);
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    prisma.alertLog.findFirst.mockResolvedValue(null);
    prisma.blockedAttempt.findMany.mockResolvedValue([makeBlockedAttempt('velocity')]);
    prisma.blockedAttempt.count.mockResolvedValue(0);

    await triggerFirstTick(prisma);

    expect(sendWeeklySummaryEmail).toHaveBeenCalledWith(
      expect.objectContaining({ weekOverWeekPct: null })
    );
  });

  // ── 9. weekOverWeekPct normal calculation ────────────────────────────────
  test('weekOverWeekPct computes correct rounded percentage change', async () => {
    setNowForTick(SUNDAY_0930);
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    prisma.alertLog.findFirst.mockResolvedValue(null);
    // thisWeekCount = 5, prevWeekCount = 4 → (5-4)/4 * 100 = 25%
    prisma.blockedAttempt.findMany.mockResolvedValue([
      makeBlockedAttempt('velocity'),
      makeBlockedAttempt('velocity'),
      makeBlockedAttempt('velocity'),
      makeBlockedAttempt('velocity'),
      makeBlockedAttempt('velocity'),
    ]);
    prisma.blockedAttempt.count.mockResolvedValue(4);

    await triggerFirstTick(prisma);

    expect(sendWeeklySummaryEmail).toHaveBeenCalledWith(
      expect.objectContaining({ weekOverWeekPct: 25 })
    );
  });

  // ── 10. historicalTotal only computed when thisWeekCount===0 && shouldSendEmail ──
  test('historicalTotal is not computed on active weeks, but is computed on a quiet week that sends email', async () => {
    setNowForTick(SUNDAY_0930);

    // Active week: aggregate must NOT be called.
    const activeTenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([activeTenant]);
    prisma.alertLog.findFirst.mockResolvedValue(null);
    prisma.blockedAttempt.findMany.mockResolvedValue([makeBlockedAttempt('velocity')]);
    prisma.blockedAttempt.count.mockResolvedValue(0);

    await triggerFirstTick(prisma);

    expect(prisma.alertLog.aggregate).not.toHaveBeenCalled();

    // Quiet week with email sent (streak below threshold): aggregate MUST be called.
    jest.clearAllTimers();
    jest.resetAllMocks();
    prisma = makePrisma();
    applyPersistentDefaults(prisma);
    setNowForTick(SUNDAY_0930);
    const quietTenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([quietTenant]);
    prisma.alertLog.findFirst.mockResolvedValue(null);
    prisma.blockedAttempt.findMany.mockResolvedValue([]);
    prisma.blockedAttempt.count.mockResolvedValue(0);
    prisma.alertLog.findMany.mockResolvedValue([makeAlertLog({ attackCount: 0 })]); // streak 1 < 3
    prisma.alertLog.aggregate.mockResolvedValue({
      _sum: { attackCount: 40, savedAmount: 12 },
    });

    await triggerFirstTick(prisma);

    expect(prisma.alertLog.aggregate).toHaveBeenCalledWith({
      where: { tenantId: quietTenant.id, alertType: 'weekly_summary' },
      _sum: { attackCount: true, savedAmount: true },
    });
    expect(sendWeeklySummaryEmail).toHaveBeenCalledWith(
      expect.objectContaining({ historicalTotal: { attacks: 40, saved: 12 } })
    );
  });

  // ── 11. tenant processing throws — isolated ──────────────────────────────
  test('isolates a tenant whose processing throws; other tenants still processed', async () => {
    setNowForTick(SUNDAY_0930);
    const failingTenant = makeTenant({ id: 'tenant-fail' });
    const okTenant = makeTenant({ id: 'tenant-ok' });
    prisma.tenant.findMany.mockResolvedValue([failingTenant, okTenant]);
    prisma.alertLog.findFirst.mockResolvedValue(null);

    prisma.blockedAttempt.findMany.mockImplementation(({ where }) => {
      if (where.tenantId === 'tenant-fail') {
        return Promise.reject(new Error('query exploded'));
      }
      return Promise.resolve([makeBlockedAttempt('velocity')]);
    });
    prisma.blockedAttempt.count.mockResolvedValue(0);

    startWeeklySummaryScheduler(prisma);
    await jest.advanceTimersByTimeAsync(STARTUP_DELAY_MS);
    // Advance past the inter-tenant courtesy delay so the second tenant runs.
    await jest.advanceTimersByTimeAsync(TENANT_DELAY_MS);

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Unhandled error for tenant tenant-fail:'),
      'query exploded'
    );
    expect(prisma.alertLog.create).toHaveBeenCalledWith({
      data: {
        tenantId: 'tenant-ok',
        alertType: 'weekly_summary',
        attackCount: 1,
        savedAmount: 1 * SAVINGS_PER_ATTACK,
      },
    });
  });

  // ── 12. email rejects — caught, not propagated ───────────────────────────
  test('catches a rejected sendWeeklySummaryEmail without propagating', async () => {
    setNowForTick(SUNDAY_0930);
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    prisma.alertLog.findFirst.mockResolvedValue(null);
    prisma.blockedAttempt.findMany.mockResolvedValue([makeBlockedAttempt('velocity')]);
    prisma.blockedAttempt.count.mockResolvedValue(0);
    sendWeeklySummaryEmail.mockRejectedValue(new Error('SMTP down'));

    await expect(triggerFirstTick(prisma)).resolves.not.toThrow();

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining(`Email failed for ${tenant.email}:`),
      'SMTP down'
    );
  });

  // ── 13. inter-tenant delay (3s) ───────────────────────────────────────────
  test('waits TENANT_DELAY_MS (3s) between processing tenants', async () => {
    setNowForTick(SUNDAY_0930);
    const tenant1 = makeTenant({ id: 'tenant-1' });
    const tenant2 = makeTenant({ id: 'tenant-2' });
    prisma.tenant.findMany.mockResolvedValue([tenant1, tenant2]);
    prisma.alertLog.findFirst.mockResolvedValue(null);
    prisma.blockedAttempt.findMany.mockResolvedValue([]);
    prisma.blockedAttempt.count.mockResolvedValue(0);

    startWeeklySummaryScheduler(prisma);
    await jest.advanceTimersByTimeAsync(STARTUP_DELAY_MS);

    // Only the first tenant should have reached the anti-duplication check so far.
    expect(prisma.alertLog.findFirst).toHaveBeenCalledTimes(1);
    expect(prisma.alertLog.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({ where: expect.objectContaining({ tenantId: 'tenant-1' }) })
    );

    await jest.advanceTimersByTimeAsync(TENANT_DELAY_MS);

    expect(prisma.alertLog.findFirst).toHaveBeenCalledTimes(2);
    expect(prisma.alertLog.findFirst).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ where: expect.objectContaining({ tenantId: 'tenant-2' }) })
    );
  });

  // ── 14. timer wiring ──────────────────────────────────────────────────────
  test('wires 1h startup delay then hourly interval', async () => {
    const setTimeoutSpy = jest.spyOn(global, 'setTimeout');
    const setIntervalSpy = jest.spyOn(global, 'setInterval');

    setNowForTick(SUNDAY_0930);
    const tenant = makeTenant();
    prisma.tenant.findMany.mockResolvedValue([tenant]);
    // Short-circuit via alreadySent so this tick completes without extra timers.
    prisma.alertLog.findFirst.mockResolvedValue({ id: 'already-sent' });

    startWeeklySummaryScheduler(prisma);

    expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), STARTUP_DELAY_MS);
    expect(prisma.tenant.findMany).not.toHaveBeenCalled();

    await jest.advanceTimersByTimeAsync(STARTUP_DELAY_MS);

    expect(prisma.tenant.findMany).toHaveBeenCalledTimes(1);
    expect(setIntervalSpy).toHaveBeenCalledWith(expect.any(Function), SCHEDULER_INTERVAL_MS);
  });
});