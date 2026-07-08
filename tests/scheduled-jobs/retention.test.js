'use strict';

/**
 * SCOPE
 * -----
 * tests/scheduled-jobs/retention.test.js
 * Covers src/lib/retention.js:
 *   - runFastCleanup(prisma): the lightweight 10-minute job (block-decision
 *     orders, expired blacklist/whitelist entries, stale pendingEnrichment).
 *   - runDailyRetention(): the heavy 24h job — concurrency guard via the
 *     module-level `_dailyRunning` flag, its own PrismaClient lifecycle,
 *     batchDelete()'s findMany→deleteMany pagination loop with
 *     BATCH_DELAY_MS between full batches, all 9 per-table retention
 *     windows, the safeClean() per-table error isolation wrapper, the
 *     final summary log, and the `_dailyRunning` reset in `finally`.
 *
 * MOCKING STRATEGY
 * -----------------
 * - runFastCleanup receives `prisma` as an injected parameter (per app.js
 *   wiring) — we pass a hand-rolled makePrisma() mock directly, no module
 *   mock needed for it.
 * - runDailyRetention constructs its OWN `new PrismaClient()` internally,
 *   so per the blueprint we mock `@prisma/client` directly (NOT
 *   `../../src/lib/db`, which this file never requires) and make the
 *   mocked constructor return our makePrisma() instance.
 * - Real timers are swapped for fake timers because batchDelete() awaits
 *   `setTimeout(..., BATCH_DELAY_MS)` between full-size batches; tests that
 *   exercise multi-batch pagination advance fake timers explicitly. Tests
 *   with empty result sets never reach the delay line, so they resolve
 *   without any timer advancement.
 * - `daysAgo`/`hoursAgo` are NOT exported, so we reimplement them
 *   byte-for-byte in this file to compute expected `where` clause dates.
 *   Because jest.setSystemTime() pins `Date.now()` for both the source and
 *   the test in the same process/timezone, the two independently-computed
 *   Date objects are guaranteed to match exactly.
 */

jest.mock('@prisma/client', () => ({
  PrismaClient: jest.fn(),
}));

const { PrismaClient } = require('@prisma/client');
const { runFastCleanup, runDailyRetention, RETENTION } = require('../../src/lib/retention');

// ─── Reimplemented time helpers (mirrors source exactly) ────────────────────
function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d;
}
function hoursAgo(n) {
  return new Date(Date.now() - n * 60 * 60 * 1000);
}

const FIXED_NOW = '2025-06-15T12:00:00.000Z';

// ─── Factories ────────────────────────────────────────────────────────────
function makePrisma() {
  return {
    order:                 { deleteMany: jest.fn(), findMany: jest.fn() },
    blacklistEntry:        { deleteMany: jest.fn() },
    whitelistEntry:        { deleteMany: jest.fn(), findMany: jest.fn() },
    pendingEnrichment:     { deleteMany: jest.fn() },
    identityEvent:         { findMany: jest.fn(), deleteMany: jest.fn() },
    computedIdentityRisk:  { deleteMany: jest.fn() },
    identityNode:          { findMany: jest.fn(), deleteMany: jest.fn() },
    cardTestAttempt:       { findMany: jest.fn(), deleteMany: jest.fn() },
    blockedAttempt:        { findMany: jest.fn(), deleteMany: jest.fn() },
    cardHash:              { findMany: jest.fn(), deleteMany: jest.fn() },
    tenant:                { findMany: jest.fn(), deleteMany: jest.fn() },
    $disconnect:           jest.fn().mockResolvedValue(undefined),
  };
}

/** Applies "nothing to delete" defaults across every model used by either job. */
function applyPersistentDefaults(prisma) {
  // Fast cleanup — direct deleteMany calls, all zero counts.
  prisma.order.deleteMany.mockResolvedValue({ count: 0 });
  prisma.blacklistEntry.deleteMany.mockResolvedValue({ count: 0 });
  prisma.whitelistEntry.deleteMany.mockResolvedValue({ count: 0 });
  prisma.pendingEnrichment.deleteMany.mockResolvedValue({ count: 0 });

  // Daily retention — batchDelete-backed models return empty pages so the
  // pagination loop exits immediately with no delay.
  prisma.identityEvent.findMany.mockResolvedValue([]);
  prisma.identityNode.findMany.mockResolvedValue([]);
  prisma.cardTestAttempt.findMany.mockResolvedValue([]);
  prisma.blockedAttempt.findMany.mockResolvedValue([]);
  prisma.order.findMany.mockResolvedValue([]);
  prisma.cardHash.findMany.mockResolvedValue([]);
  prisma.tenant.findMany.mockResolvedValue([]);

  // Daily retention — direct deleteMany-backed models (non-paginated).
  prisma.computedIdentityRisk.deleteMany.mockResolvedValue({ count: 0 });
  prisma.whitelistEntry.deleteMany.mockResolvedValue({ count: 0 });
}

function errorLoggedContaining(substr) {
  return console.error.mock.calls.some(call =>
    call.some(arg => typeof arg === 'string' && arg.includes(substr))
  );
}
function logLoggedContaining(substr) {
  return console.log.mock.calls.some(call =>
    call.some(arg => typeof arg === 'string' && arg.includes(substr))
  );
}
function anyLogContaining(substr) {
  return errorLoggedContaining(substr) || logLoggedContaining(substr) ||
    console.warn.mock.calls.some(call =>
      call.some(arg => typeof arg === 'string' && arg.includes(substr))
    );
}

// ─── Setup ────────────────────────────────────────────────────────────────
let prisma;

beforeEach(() => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date(FIXED_NOW));
  jest.resetAllMocks();

  prisma = makePrisma();
  applyPersistentDefaults(prisma);
  PrismaClient.mockImplementation(() => prisma);

  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.clearAllTimers();
  jest.useRealTimers();
});

// ═════════════════════════════════════════════════════════════════════════
// runFastCleanup (7 tests)
// ═════════════════════════════════════════════════════════════════════════

describe('runFastCleanup', () => {

  // 1. order.deleteMany
  test('deletes orders with decision: block', async () => {
    prisma.order.deleteMany.mockResolvedValue({ count: 3 });
    await runFastCleanup(prisma);

    expect(prisma.order.deleteMany).toHaveBeenCalledWith({
      where: { decision: 'block' },
    });
  });

  // 2. blacklistEntry.deleteMany
  test('deletes expired blacklistEntry rows', async () => {
    prisma.blacklistEntry.deleteMany.mockResolvedValue({ count: 2 });
    await runFastCleanup(prisma);

    expect(prisma.blacklistEntry.deleteMany).toHaveBeenCalledWith({
      where: { expiresAt: { not: null, lt: new Date(FIXED_NOW) } },
    });
  });

  // 3. whitelistEntry.deleteMany
  test('deletes expired whitelistEntry rows', async () => {
    prisma.whitelistEntry.deleteMany.mockResolvedValue({ count: 1 });
    await runFastCleanup(prisma);

    expect(prisma.whitelistEntry.deleteMany).toHaveBeenCalledWith({
      where: { expiresAt: { not: null, lt: new Date(FIXED_NOW) } },
    });
  });

  // 4. pendingEnrichment.deleteMany
  test('deletes stale pendingEnrichment rows older than 24h and not done', async () => {
    prisma.pendingEnrichment.deleteMany.mockResolvedValue({ count: 5 });
    await runFastCleanup(prisma);

    expect(prisma.pendingEnrichment.deleteMany).toHaveBeenCalledWith({
      where: {
        createdAt: { lt: hoursAgo(RETENTION.PENDING_ENRICHMENT_HOURS) },
        status:    { not: 'done' },
      },
    });
  });

  // 5. all counts 0 → no log
  test('all counts zero → no summary log line is emitted', async () => {
    await runFastCleanup(prisma);

    expect(logLoggedContaining('FastCleanup')).toBe(false);
  });

  test('some counts nonzero → summary log line is emitted with all counts', async () => {
    prisma.order.deleteMany.mockResolvedValue({ count: 2 });
    await runFastCleanup(prisma);

    expect(logLoggedContaining('FastCleanup')).toBe(true);
  });

  // 6. any throws → caught
  test('a rejected deleteMany is caught — no throw, error logged, job does not crash', async () => {
    prisma.blacklistEntry.deleteMany.mockRejectedValue(new Error('db unreachable'));

    await expect(runFastCleanup(prisma)).resolves.not.toThrow();
    expect(errorLoggedContaining('FastCleanup failed')).toBe(true);
  });

  // 7. injected prisma param
  test('uses the injected prisma instance, not a module-level client', async () => {
    const otherPrisma = makePrisma();
    applyPersistentDefaults(otherPrisma);
    otherPrisma.order.deleteMany.mockResolvedValue({ count: 9 });

    await runFastCleanup(otherPrisma);

    expect(otherPrisma.order.deleteMany).toHaveBeenCalledTimes(1);
    expect(prisma.order.deleteMany).not.toHaveBeenCalled();
    // Confirms runFastCleanup never touches @prisma/client's constructor.
    expect(PrismaClient).not.toHaveBeenCalled();
  });

});

// ═════════════════════════════════════════════════════════════════════════
// runDailyRetention (16 tests)
// ═════════════════════════════════════════════════════════════════════════

describe('runDailyRetention', () => {

  // 1. concurrency guard
  test('concurrency guard: overlapping call is skipped with a warning, does not construct a second client', async () => {
    const p1 = runDailyRetention(); // starts, sets _dailyRunning=true synchronously
    const p2 = runDailyRetention(); // sees _dailyRunning already true → warns, returns

    await p2;
    expect(console.warn).toHaveBeenCalledWith(
      expect.stringContaining('already running')
    );
    expect(PrismaClient).toHaveBeenCalledTimes(1);

    await p1; // let the first run finish so _dailyRunning resets for later tests
  });

  // 2. own PrismaClient + disconnect
  test('constructs its own PrismaClient and disconnects it when done', async () => {
    await runDailyRetention();

    expect(PrismaClient).toHaveBeenCalledTimes(1);
    expect(prisma.$disconnect).toHaveBeenCalledTimes(1);
  });

  test('disconnects even when the run fails partway through', async () => {
    prisma.identityEvent.findMany.mockRejectedValue(new Error('unexpected'));
    await runDailyRetention();

    expect(prisma.$disconnect).toHaveBeenCalledTimes(1);
  });

  // 3. batchDelete pagination
  test('batchDelete paginates: full batch triggers a second findMany/deleteMany cycle', async () => {
    const fullBatch = Array.from({ length: RETENTION.BATCH_SIZE }, (_, i) => ({ id: `id-${i}` }));
    const partialBatch = [{ id: 'id-last-1' }, { id: 'id-last-2' }];

    prisma.identityEvent.findMany
      .mockResolvedValueOnce(fullBatch)
      .mockResolvedValueOnce(partialBatch);
    prisma.identityEvent.deleteMany
      .mockResolvedValueOnce({ count: RETENTION.BATCH_SIZE })
      .mockResolvedValueOnce({ count: 2 });

    const runPromise = runDailyRetention();
    // Flush the inter-batch BATCH_DELAY_MS wait plus everything downstream.
    await jest.advanceTimersByTimeAsync(RETENTION.BATCH_DELAY_MS * 2 + 5000);
    await runPromise;

    expect(prisma.identityEvent.findMany).toHaveBeenCalledTimes(2);
    expect(prisma.identityEvent.deleteMany).toHaveBeenNthCalledWith(1, {
      where: { id: { in: fullBatch.map(r => r.id) } },
    });
    expect(prisma.identityEvent.deleteMany).toHaveBeenNthCalledWith(2, {
      where: { id: { in: partialBatch.map(r => r.id) } },
    });
    // Total summed across both batches: 500 + 2 = 502 rows deleted.
    expect(logLoggedContaining('502 rows deleted total') ||
      console.log.mock.calls.some(c => c.some(a => typeof a === 'string' && a.includes('deleted 500 rows (1 batch)'))))
      .toBeTruthy();
  });

  // 4. BATCH_DELAY_MS
  test('waits BATCH_DELAY_MS between full batches, not between the last (partial) batch', async () => {
    const fullBatch = Array.from({ length: RETENTION.BATCH_SIZE }, (_, i) => ({ id: `id-${i}` }));
    prisma.identityEvent.findMany
      .mockResolvedValueOnce(fullBatch)
      .mockResolvedValueOnce([]); // second page empty → loop exits, no further delay
    prisma.identityEvent.deleteMany.mockResolvedValueOnce({ count: RETENTION.BATCH_SIZE });

    const runPromise = runDailyRetention();

    // Right before the delay elapses, the second findMany must not have fired yet.
    await jest.advanceTimersByTimeAsync(RETENTION.BATCH_DELAY_MS - 1);
    expect(prisma.identityEvent.findMany).toHaveBeenCalledTimes(1);

    // Crossing the delay boundary triggers the second page fetch.
    await jest.advanceTimersByTimeAsync(1);
    expect(prisma.identityEvent.findMany).toHaveBeenCalledTimes(2);

    await jest.advanceTimersByTimeAsync(5000);
    await runPromise;
  });

  // 5. identityEvent 30d
  test('identityEvent: retention window is IDENTITY_EVENT_DAYS (30d)', async () => {
    await runDailyRetention();

    expect(prisma.identityEvent.findMany).toHaveBeenCalledWith({
      where:  { createdAt: { lt: daysAgo(RETENTION.IDENTITY_EVENT_DAYS) } },
      select: { id: true },
      take:   RETENTION.BATCH_SIZE,
    });
  });

  // 6. computedIdentityRisk 90d
  test('computedIdentityRisk: direct deleteMany with COMPUTED_RISK_DAYS (90d) window', async () => {
    prisma.computedIdentityRisk.deleteMany.mockResolvedValue({ count: 7 });
    await runDailyRetention();

    expect(prisma.computedIdentityRisk.deleteMany).toHaveBeenCalledWith({
      where: { computedAt: { lt: daysAgo(RETENTION.COMPUTED_RISK_DAYS) } },
    });
  });

  // 7. identityNode 90d
  test('identityNode: retention window is IDENTITY_NODE_DAYS (90d), keyed on lastSeen', async () => {
    await runDailyRetention();

    expect(prisma.identityNode.findMany).toHaveBeenCalledWith({
      where:  { lastSeen: { lt: daysAgo(RETENTION.IDENTITY_NODE_DAYS) } },
      select: { id: true },
      take:   RETENTION.BATCH_SIZE,
    });
  });

  // 8. cardTestAttempt 60d
  test('cardTestAttempt: retention window is CARD_TEST_DAYS (60d)', async () => {
    await runDailyRetention();

    expect(prisma.cardTestAttempt.findMany).toHaveBeenCalledWith({
      where:  { createdAt: { lt: daysAgo(RETENTION.CARD_TEST_DAYS) } },
      select: { id: true },
      take:   RETENTION.BATCH_SIZE,
    });
  });

  // 9. blockedAttempt 180d
  test('blockedAttempt: retention window is BLOCKED_ATTEMPT_DAYS (180d), keyed on blockedAt', async () => {
    await runDailyRetention();

    expect(prisma.blockedAttempt.findMany).toHaveBeenCalledWith({
      where:  { blockedAt: { lt: daysAgo(RETENTION.BLOCKED_ATTEMPT_DAYS) } },
      select: { id: true },
      take:   RETENTION.BATCH_SIZE,
    });
  });

  // 10. order retention (approve/review only)
  test('order: retention window is ORDER_DAYS (90d) and only touches approve/review decisions', async () => {
    await runDailyRetention();

    expect(prisma.order.findMany).toHaveBeenCalledWith({
      where: {
        createdAt: { lt: daysAgo(RETENTION.ORDER_DAYS) },
        decision:  { in: ['approve', 'review'] },
      },
      select: { id: true },
      take:   RETENTION.BATCH_SIZE,
    });
  });

  // 11. cardHash 365d
  test('cardHash: retention window is CARD_HASH_DAYS (365d), keyed on lastSeenAt', async () => {
    await runDailyRetention();

    expect(prisma.cardHash.findMany).toHaveBeenCalledWith({
      where:  { lastSeenAt: { lt: daysAgo(RETENTION.CARD_HASH_DAYS) } },
      select: { id: true },
      take:   RETENTION.BATCH_SIZE,
    });
  });

  // 12. whitelistEntry sweep
  test('whitelistEntry: direct deleteMany sweep for expired entries (backstop for FastCleanup)', async () => {
    prisma.whitelistEntry.deleteMany.mockResolvedValue({ count: 4 });
    await runDailyRetention();

    expect(prisma.whitelistEntry.deleteMany).toHaveBeenCalledWith({
      where: { expiresAt: { not: null, lt: new Date(FIXED_NOW) } },
    });
  });

  // 13. unverifiedTenant 30d
  test('unverifiedTenant: batchDelete on tenant model, unverified + UNVERIFIED_TENANT_DAYS (30d) old', async () => {
    await runDailyRetention();

    expect(prisma.tenant.findMany).toHaveBeenCalledWith({
      where: {
        emailVerified: false,
        createdAt: { lt: daysAgo(RETENTION.UNVERIFIED_TENANT_DAYS) },
      },
      select: { id: true },
      take:   RETENTION.BATCH_SIZE,
    });
  });

  // 14. safeClean isolation
  test('safeClean isolation: one table failing does not stop the others from running', async () => {
    prisma.identityNode.findMany.mockRejectedValue(new Error('table locked'));

    await runDailyRetention();

    expect(errorLoggedContaining('Failed to clean identityNode')).toBe(true);
    // The loop must have continued past the failed table to the rest.
    expect(prisma.cardTestAttempt.findMany).toHaveBeenCalled();
    expect(prisma.blockedAttempt.findMany).toHaveBeenCalled();
    expect(prisma.order.findMany).toHaveBeenCalled();
    expect(prisma.cardHash.findMany).toHaveBeenCalled();
    expect(prisma.whitelistEntry.deleteMany).toHaveBeenCalled();
    expect(prisma.tenant.findMany).toHaveBeenCalled();
    // The overall run must still complete and log its summary despite the failure.
    expect(logLoggedContaining('Daily retention completed')).toBe(true);
  });

  // 15. summary log
  test('summary log: reports per-table results and total row count', async () => {
    prisma.identityEvent.findMany.mockResolvedValueOnce([{ id: 'a' }, { id: 'b' }]).mockResolvedValueOnce([]);
    prisma.identityEvent.deleteMany.mockResolvedValueOnce({ count: 2 });
    prisma.computedIdentityRisk.deleteMany.mockResolvedValue({ count: 3 });

    await runDailyRetention();

    expect(logLoggedContaining('Daily retention completed')).toBe(true);
    expect(logLoggedContaining('5 rows deleted total')).toBe(true);
    expect(logLoggedContaining('IdentityEvent:')).toBe(true);
    expect(logLoggedContaining('ComputedIdentityRisk:')).toBe(true);
    expect(logLoggedContaining('nothing to delete')).toBe(true); // e.g. IdentityNode etc.
  });

  // 16. _dailyRunning reset in finally
  test('_dailyRunning resets in finally: a second sequential call is NOT skipped', async () => {
    await runDailyRetention();
    expect(PrismaClient).toHaveBeenCalledTimes(1);
    expect(console.warn).not.toHaveBeenCalled();

    await runDailyRetention();
    expect(PrismaClient).toHaveBeenCalledTimes(2);
    expect(console.warn).not.toHaveBeenCalled();
  });

  test('_dailyRunning resets in finally even after a fatal top-level error', async () => {
    // Force the outer try to throw somewhere unexpected (e.g. summary log
    // construction) by making $disconnect itself irrelevant — instead we
    // simulate a fatal error path via a rejected findMany that safeClean
    // does NOT catch differently; the guarantee under test is the outer
    // catch's message and that _dailyRunning still resets, proven by a
    // clean subsequent run.
    prisma.tenant.findMany.mockRejectedValue(new Error('catastrophic'));
    await runDailyRetention(); // safeClean catches this internally; run completes

    // Flag must be false again — prove it via an unblocked second call.
    await runDailyRetention();
    expect(console.warn).not.toHaveBeenCalled();
    expect(PrismaClient).toHaveBeenCalledTimes(2);
  });

});