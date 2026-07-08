'use strict';

/**
 * SCOPE
 * -----
 * tests/scheduled-jobs/monthly-report-scheduler.test.js
 * Covers src/jobs/monthlyReportScheduler.js — the hourly-tick / 1st-of-month
 * gate, getReportPeriod's month-rollover math (incl. the January edge case),
 * the anti-duplication + upsert-as-lock pattern, the 'ready'/'failed' status
 * transitions, the fire-and-forget email send, buildDownloadUrl's env-var
 * fallback, the 5s inter-tenant delay, and the 1h-startup/hourly timer wiring.
 *
 * MOCKING STRATEGY
 * -----------------
 * - `../../src/lib/reportDataService` is mocked: buildMonthlyReportData is a
 *   jest.fn() we control per-test (resolve/reject).
 * - `../../src/lib/email` is mocked: sendMonthlyReportEmail is a jest.fn().
 * - `../../src/lib/db` is NOT mocked/required here — this scheduler receives
 *   `prisma` as an injected parameter from app.js and never constructs its
 *   own PrismaClient, so there is nothing to intercept.
 * - `prisma` itself is a hand-rolled mock object (makePrisma()) covering only
 *   the two models this scheduler touches: `tenant` and `monthlyReport`.
 * - Only `startMonthlyReportScheduler` is exported. `runMonthlyReportCheck`,
 *   `processTenant`, `getReportPeriod`, and `buildDownloadUrl` are internal —
 *   every test below drives behavior through the public entrypoint using
 *   fake timers (jest.setSystemTime + jest.advanceTimersByTimeAsync), which
 *   is also how getReportPeriod's month math is verified: indirectly, via
 *   the (month, year) arguments buildMonthlyReportData is called with.
 */

jest.mock('../../src/lib/reportDataService', () => ({
  buildMonthlyReportData: jest.fn(),
}));
jest.mock('../../src/lib/email', () => ({
  sendMonthlyReportEmail: jest.fn(),
}));

const { startMonthlyReportScheduler } = require('../../src/jobs/monthlyReportScheduler');
const { buildMonthlyReportData } = require('../../src/lib/reportDataService');
const { sendMonthlyReportEmail } = require('../../src/lib/email');

// ─── Constants mirrored from source (not exported) ──────────────────────────
const STARTUP_DELAY_MS = 60 * 60 * 1000; // 1h
const TENANT_DELAY_MS  = 5_000;          // 5s

// ─── Factories ────────────────────────────────────────────────────────────
function makeTenant(overrides = {}) {
  return {
    id: 'tenant-1',
    email: 'merchant@example.com',
    storeUrl: 'https://shop.example.com',
    plan: 'starter',
    ...overrides,
  };
}

function makeReportData(overrides = {}) {
  return {
    monthName: 'February',
    totalAttacks: 42,
    totalProtected: 1234.56,
    totalFeesSaved: 210.1,
    securityScore: 87,
    topCountry: 'US',
    topReason: 'card_testing',
    prevMonthAttacks: 30,
    ...overrides,
  };
}

function makePrisma() {
  return {
    tenant: {
      findMany: jest.fn(),
    },
    monthlyReport: {
      findFirst: jest.fn(),
      upsert: jest.fn(),
      update: jest.fn(),
    },
  };
}

function applyPersistentDefaults(prisma, tenants = [makeTenant()]) {
  prisma.tenant.findMany.mockResolvedValue(tenants);
  prisma.monthlyReport.findFirst.mockResolvedValue(null); // no 'ready' record
  prisma.monthlyReport.upsert.mockResolvedValue({ id: 'report-1' });
  prisma.monthlyReport.update.mockResolvedValue({});
  buildMonthlyReportData.mockResolvedValue(makeReportData());
  sendMonthlyReportEmail.mockResolvedValue(undefined);
}

// Time just before the 1h startup delay elapses, such that STARTUP_DELAY_MS
// later lands exactly on `targetISO`.
function timeBeforeStartup(targetISO) {
  return new Date(new Date(targetISO).getTime() - STARTUP_DELAY_MS);
}

async function bootToFirstTick(prisma) {
  startMonthlyReportScheduler(prisma);
  await jest.advanceTimersByTimeAsync(STARTUP_DELAY_MS);
}

function errorLoggedContaining(substr) {
  return console.error.mock.calls.some(call =>
    call.some(arg => typeof arg === 'string' && arg.includes(substr))
  );
}

// ─── Setup ────────────────────────────────────────────────────────────────
let prisma;

beforeEach(() => {
  jest.useFakeTimers();
  jest.resetAllMocks();
  prisma = makePrisma();
  applyPersistentDefaults(prisma);
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
  delete process.env.RENDER_EXTERNAL_URL;
});

afterEach(() => {
  jest.clearAllTimers();
  jest.useRealTimers();
});

// ─── Tests ────────────────────────────────────────────────────────────────

describe('monthly-report-scheduler', () => {

  // 1. gate: not 1st of month → no-op
  test('gate: not 1st of month → no-op', async () => {
    // After +1h startup delay lands on the 15th (day mismatch), 10:00 UTC.
    jest.setSystemTime(timeBeforeStartup('2025-03-15T10:00:00.000Z'));
    await bootToFirstTick(prisma);

    expect(prisma.tenant.findMany).not.toHaveBeenCalled();
    expect(buildMonthlyReportData).not.toHaveBeenCalled();
  });

  // 2. gate: 1st but wrong hour → no-op
  test('gate: 1st but wrong hour → no-op', async () => {
    // After +1h startup delay lands on 2025-03-01T09:00:00Z (hour mismatch).
    jest.setSystemTime(timeBeforeStartup('2025-03-01T09:00:00.000Z'));
    await bootToFirstTick(prisma);

    expect(prisma.tenant.findMany).not.toHaveBeenCalled();
    expect(buildMonthlyReportData).not.toHaveBeenCalled();
  });

  // 3. getReportPeriod normal month → correct month/year
  test('getReportPeriod: normal month resolves to previous month/year', async () => {
    // March 1st 10:00 UTC → report covers February 2025 (month=2, year=2025).
    jest.setSystemTime(timeBeforeStartup('2025-03-01T10:00:00.000Z'));
    await bootToFirstTick(prisma);
    await jest.advanceTimersByTimeAsync(0);

    expect(buildMonthlyReportData).toHaveBeenCalledWith(prisma, 'tenant-1', 2, 2025);
  });

  // 4. getReportPeriod January edge case → Dec of prior year
  test('getReportPeriod: January edge case rolls back to December of prior year', async () => {
    // January 1st 10:00 UTC → report covers December 2024 (month=12, year=2024).
    jest.setSystemTime(timeBeforeStartup('2025-01-01T10:00:00.000Z'));
    await bootToFirstTick(prisma);
    await jest.advanceTimersByTimeAsync(0);

    expect(buildMonthlyReportData).toHaveBeenCalledWith(prisma, 'tenant-1', 12, 2024);
  });

  // 5. existingReady found (status:'ready') → tenant skipped
  test('existingReady found (status ready) → tenant is skipped entirely', async () => {
    prisma.monthlyReport.findFirst.mockResolvedValue({ id: 'existing-ready' });
    jest.setSystemTime(timeBeforeStartup('2025-03-01T10:00:00.000Z'));
    await bootToFirstTick(prisma);
    await jest.advanceTimersByTimeAsync(0);

    expect(prisma.monthlyReport.upsert).not.toHaveBeenCalled();
    expect(buildMonthlyReportData).not.toHaveBeenCalled();
    expect(sendMonthlyReportEmail).not.toHaveBeenCalled();
  });

  // 6. no existing record → upsert creates with status:'generating'
  test('no existing ready record → upsert locks with status generating (create branch)', async () => {
    jest.setSystemTime(timeBeforeStartup('2025-03-01T10:00:00.000Z'));
    await bootToFirstTick(prisma);
    await jest.advanceTimersByTimeAsync(0);

    expect(prisma.monthlyReport.upsert).toHaveBeenCalledWith({
      where: {
        tenantId_reportMonth_reportYear: {
          tenantId: 'tenant-1',
          reportMonth: 2,
          reportYear: 2025,
        },
      },
      create: {
        tenantId: 'tenant-1',
        reportMonth: 2,
        reportYear: 2025,
        status: 'generating',
      },
      update: { status: 'generating' },
      select: { id: true },
    });
  });

  // 7. stale 'failed'/'generating' record exists → upsert resets to 'generating' (retry)
  test('stale failed/generating record → upsert update branch resets status to generating', async () => {
    // findFirst only ever filters on status:'ready', so a stale 'failed' or
    // 'generating' record is invisible to it (returns null either way) —
    // the retry happens transparently inside Prisma's upsert(), which takes
    // the SAME where/create/update shape regardless of what's already there.
    // This test documents that quirk: the call args are identical to the
    // "no existing record" case; only the DB-side branch differs.
    prisma.monthlyReport.findFirst.mockResolvedValue(null);
    // Simulate upsert hitting its update branch by having it resolve as if
    // it reset a pre-existing record.
    prisma.monthlyReport.upsert.mockResolvedValue({ id: 'report-retried' });

    jest.setSystemTime(timeBeforeStartup('2025-03-01T10:00:00.000Z'));
    await bootToFirstTick(prisma);
    await jest.advanceTimersByTimeAsync(0);

    expect(prisma.monthlyReport.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: { status: 'generating' },
      })
    );
    // The retried record's id must be used downstream, not a stale one.
    expect(prisma.monthlyReport.update).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: 'report-retried' } })
    );
  });

  // 8. upsert (lock) itself throws → tenant aborted, no crash
  test('upsert throws → tenant aborted cleanly, no crash, no downstream calls', async () => {
    prisma.monthlyReport.upsert.mockRejectedValue(new Error('lock write failed'));
    jest.setSystemTime(timeBeforeStartup('2025-03-01T10:00:00.000Z'));

    await bootToFirstTick(prisma);
    await jest.advanceTimersByTimeAsync(0);

    expect(buildMonthlyReportData).not.toHaveBeenCalled();
    expect(prisma.monthlyReport.update).not.toHaveBeenCalled();
    expect(sendMonthlyReportEmail).not.toHaveBeenCalled();
    expect(errorLoggedContaining('failed to create generating record')).toBe(true);
  });

  // 9. buildMonthlyReportData succeeds → record updated to 'ready' with all fields; email fired
  test('buildMonthlyReportData succeeds → record set to ready with all fields, email sent', async () => {
    const reportData = makeReportData();
    buildMonthlyReportData.mockResolvedValue(reportData);
    jest.setSystemTime(timeBeforeStartup('2025-03-01T10:00:00.000Z'));

    await bootToFirstTick(prisma);
    await jest.advanceTimersByTimeAsync(0);

    expect(prisma.monthlyReport.update).toHaveBeenCalledWith({
      where: { id: 'report-1' },
      data: {
        status: 'ready',
        totalAttacks: reportData.totalAttacks,
        totalProtected: reportData.totalProtected,
        totalFeesSaved: reportData.totalFeesSaved,
        securityScore: reportData.securityScore,
        topCountry: reportData.topCountry,
        topReason: reportData.topReason,
        prevMonthAttacks: reportData.prevMonthAttacks,
      },
    });

    expect(sendMonthlyReportEmail).toHaveBeenCalledWith(
      expect.objectContaining({
        tenant: expect.objectContaining({ id: 'tenant-1' }),
        reportData,
        downloadUrl: expect.stringContaining('tenantId=tenant-1'),
      })
    );
  });

  // 10. buildMonthlyReportData throws → record 'failed'; error re-thrown; outer catch logs; loop continues
  test('buildMonthlyReportData throws → record marked failed, outer catch logs, loop continues to next tenant', async () => {
    const tenants = [makeTenant({ id: 'tenant-1', email: 'a@example.com' }), makeTenant({ id: 'tenant-2', email: 'b@example.com' })];
    prisma.tenant.findMany.mockResolvedValue(tenants);
    prisma.monthlyReport.upsert
      .mockResolvedValueOnce({ id: 'report-1' })
      .mockResolvedValueOnce({ id: 'report-2' });
    buildMonthlyReportData
      .mockRejectedValueOnce(new Error('data engine exploded'))
      .mockResolvedValueOnce(makeReportData());

    jest.setSystemTime(timeBeforeStartup('2025-03-01T10:00:00.000Z'));
    await bootToFirstTick(prisma);
    await jest.advanceTimersByTimeAsync(0);

    // Tenant 1: marked failed.
    expect(prisma.monthlyReport.update).toHaveBeenCalledWith({
      where: { id: 'report-1' },
      data: { status: 'failed' },
    });
    expect(errorLoggedContaining('report generation failed')).toBe(true);
    expect(errorLoggedContaining('Unhandled error for tenant')).toBe(true);

    // Loop must continue: tenant 2 processed after the inter-tenant delay.
    await jest.advanceTimersByTimeAsync(TENANT_DELAY_MS);
    expect(prisma.monthlyReport.upsert).toHaveBeenCalledTimes(2);
    expect(sendMonthlyReportEmail).toHaveBeenCalledWith(
      expect.objectContaining({ tenant: expect.objectContaining({ id: 'tenant-2' }) })
    );
  });

  // 11. update-to-'failed' itself throws (double failure) → logged, doesn't crash
  test('double failure: update-to-failed also throws → logged, no crash', async () => {
    buildMonthlyReportData.mockRejectedValue(new Error('data engine exploded'));
    prisma.monthlyReport.update.mockRejectedValueOnce(new Error('db connection lost'));

    jest.setSystemTime(timeBeforeStartup('2025-03-01T10:00:00.000Z'));

    await expect(bootToFirstTick(prisma)).resolves.not.toThrow();
    await jest.advanceTimersByTimeAsync(0);

    expect(errorLoggedContaining("could not update record to 'failed'")).toBe(true);
    // The unhandled-error catch in the outer loop still logs too.
    expect(errorLoggedContaining('Unhandled error for tenant')).toBe(true);
  });

  // 12. email send fails after 'ready' → status stays 'ready'
  test('email send fails after ready → status is not reverted, stays ready', async () => {
    sendMonthlyReportEmail.mockRejectedValue(new Error('smtp timeout'));
    jest.setSystemTime(timeBeforeStartup('2025-03-01T10:00:00.000Z'));

    await bootToFirstTick(prisma);
    await jest.advanceTimersByTimeAsync(0);
    // Flush the fire-and-forget email promise's rejection handler.
    await jest.advanceTimersByTimeAsync(0);

    expect(prisma.monthlyReport.update).toHaveBeenCalledTimes(1);
    expect(prisma.monthlyReport.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: 'ready' }) })
    );
    expect(errorLoggedContaining('Email failed for')).toBe(true);
  });

  // 13. buildDownloadUrl uses RENDER_EXTERNAL_URL or fallback → both cases
  test('buildDownloadUrl: uses RENDER_EXTERNAL_URL when set', async () => {
    process.env.RENDER_EXTERNAL_URL = 'https://custom-host.example.com';
    jest.setSystemTime(timeBeforeStartup('2025-03-01T10:00:00.000Z'));

    await bootToFirstTick(prisma);
    await jest.advanceTimersByTimeAsync(0);

    expect(sendMonthlyReportEmail).toHaveBeenCalledWith(
      expect.objectContaining({
        downloadUrl: 'https://custom-host.example.com/api/dashboard/monthly-report-preview?tenantId=tenant-1&month=2&year=2025',
      })
    );
  });

  test('buildDownloadUrl: falls back to onrender.com URL when env var unset', async () => {
    delete process.env.RENDER_EXTERNAL_URL;
    jest.setSystemTime(timeBeforeStartup('2025-03-01T10:00:00.000Z'));

    await bootToFirstTick(prisma);
    await jest.advanceTimersByTimeAsync(0);

    expect(sendMonthlyReportEmail).toHaveBeenCalledWith(
      expect.objectContaining({
        downloadUrl: 'https://chargeguard-api.onrender.com/api/dashboard/monthly-report-preview?tenantId=tenant-1&month=2&year=2025',
      })
    );
  });

  // 14. 5s inter-tenant delay → verified
  test('inter-tenant delay: second tenant is not touched until 5s after the first completes', async () => {
    const tenants = [makeTenant({ id: 'tenant-1' }), makeTenant({ id: 'tenant-2' })];
    prisma.tenant.findMany.mockResolvedValue(tenants);

    jest.setSystemTime(timeBeforeStartup('2025-03-01T10:00:00.000Z'));
    startMonthlyReportScheduler(prisma);
    await jest.advanceTimersByTimeAsync(STARTUP_DELAY_MS);

    // Tenant 1 fully processed synchronously (relative to fake timers);
    // tenant 2 must still be untouched, blocked behind the 5s delay.
    expect(prisma.monthlyReport.findFirst).toHaveBeenCalledTimes(1);

    // Advance right up to (but not past) the delay boundary.
    await jest.advanceTimersByTimeAsync(TENANT_DELAY_MS - 1);
    expect(prisma.monthlyReport.findFirst).toHaveBeenCalledTimes(1);

    // Cross the boundary — tenant 2 now proceeds.
    await jest.advanceTimersByTimeAsync(1);
    expect(prisma.monthlyReport.findFirst).toHaveBeenCalledTimes(2);
  });

  // 15. timer wiring → 1h startup delay, hourly
  test('timer wiring: 1h startup delay, then hourly interval', () => {
    const setTimeoutSpy = jest.spyOn(global, 'setTimeout');
    const setIntervalSpy = jest.spyOn(global, 'setInterval');

    jest.setSystemTime(new Date('2025-03-01T00:00:00.000Z'));
    startMonthlyReportScheduler(prisma);

    expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), STARTUP_DELAY_MS);

    // Manually invoke the startup callback (sync portion only) to confirm it
    // wires the hourly interval with the correct period.
    const startupCallback = setTimeoutSpy.mock.calls[0][0];
    startupCallback();

    expect(setIntervalSpy).toHaveBeenCalledWith(expect.any(Function), STARTUP_DELAY_MS);
    // SCHEDULER_INTERVAL_MS === STARTUP_DELAY_MS (both 1h) in this scheduler.

    setTimeoutSpy.mockRestore();
    setIntervalSpy.mockRestore();
  });

});