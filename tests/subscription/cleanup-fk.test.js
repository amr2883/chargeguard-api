// PHASE4-FK: subscriptionScheduler Phase 4 (cleanupExpiredSessions) against a REAL database.
// Payment.checkoutSessionId -> CheckoutSession.id is ON DELETE RESTRICT, so a delete that
// targets a completed session that has a Payment fails as a whole statement. The mock-based
// scheduler-lifecycle.test.js cannot see that. Real local DB, mocked lock and mail.

jest.mock('../../src/lib/distributedLock', () => ({
  acquireLock: jest.fn().mockResolvedValue(true),
  INSTANCE_ID: 'test-instance',
}));
jest.mock('../../src/lib/email', () => ({
  sendRenewalReminderEmail: jest.fn().mockResolvedValue(undefined),
  sendGracePeriodEmail: jest.fn().mockResolvedValue(undefined),
}));

const { PrismaClient } = require('@prisma/client');
const logger = require('../../src/lib/logger');
const { startSubscriptionScheduler } = require('../../src/jobs/subscriptionScheduler');

const prisma = new PrismaClient();
const HOUR = 60 * 60 * 1000;
const INITIAL_DELAY_MS = 2 * 60 * 1000;
const run = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

let tenantId;
let errSpy;
let infoSpy;
const sessionIds = [];

async function seedSession(tag, { status, createdAgoH = 0, expiresInH = 1, withPayment = false }) {
  const now = Date.now();
  const s = await prisma.checkoutSession.create({
    data: {
      tenantId,
      planId: 'pro_monthly',
      amount: 29,
      billingCycle: 'monthly',
      status,
      expiresAt: new Date(now + expiresInH * HOUR),
      createdAt: new Date(now - createdAgoH * HOUR),
    },
  });
  sessionIds.push(s.id);
  if (withPayment) {
    await prisma.payment.create({
      data: {
        tenantId,
        checkoutSessionId: s.id,
        captureId: `cap-${run}-${tag}`,
        amount: 29,
        expectedAmount: 29,
        planId: 'pro_monthly',
        billingCycle: 'monthly',
        status: 'completed',
      },
    });
  }
  return s.id;
}

const exists = async (id) => (await prisma.checkoutSession.count({ where: { id } })) === 1;
const cleanupFailureLogged = () =>
  errSpy.mock.calls.some((c) => c.some((a) => typeof a === 'string' && a.includes('Session cleanup failed')));

const cycleFinished = () =>
  infoSpy.mock.calls.some((c) => c[1] === 'Subscription cycle completed') ||
  errSpy.mock.calls.some((c) => c[1] === 'Subscription cycle failed');

// runSubscriptionCycle is fire-and-forget inside the scheduler's setTimeout, so
// advancing fake timers does NOT wait for the real DB work. Wait for the cycle's own log line.
async function runOneCycle() {
  jest.useFakeTimers();
  try {
    startSubscriptionScheduler(prisma);
    await jest.advanceTimersByTimeAsync(INITIAL_DELAY_MS);
  } finally {
    jest.clearAllTimers();
    jest.useRealTimers();
  }
  const deadline = Date.now() + 20000;
  while (!cycleFinished() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  if (!cycleFinished()) throw new Error('CYCLE-DID-NOT-FINISH');
}

describe('Phase 4 cleanup vs real FK (PHASE4-FK)', () => {
  beforeAll(async () => {
    await prisma.$connect(); // BEFORE fake timers (see probe 67y)
    const t = await prisma.tenant.create({
      data: { email: `cleanup-fk-${run}@example.com`, emailVerified: true },
    });
    tenantId = t.id;
  }, 60000);

  beforeEach(() => {
    errSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    infoSpy = jest.spyOn(logger, 'info').mockImplementation(() => {});
  });

  afterEach(() => {
    errSpy.mockRestore();
    infoSpy.mockRestore();
  });

  afterAll(async () => {
    if (sessionIds.length) {
      await prisma.payment.deleteMany({ where: { checkoutSessionId: { in: sessionIds } } });
      await prisma.checkoutSession.deleteMany({ where: { id: { in: sessionIds } } });
    }
    if (tenantId) await prisma.tenant.deleteMany({ where: { id: tenantId } });
    await prisma.$disconnect();
  });

  test('T1 completed session older than 24h WITH a Payment is kept and the cleanup does not fail', async () => {
    const id = await seedSession('t1', { status: 'completed', createdAgoH: 30, withPayment: true });
    await runOneCycle();
    expect(await exists(id)).toBe(true);
    expect(await prisma.payment.count({ where: { checkoutSessionId: id } })).toBe(1);
    expect(cleanupFailureLogged()).toBe(false);
  }, 30000);

  test('T2 completed session older than 24h WITHOUT a Payment is deleted', async () => {
    const id = await seedSession('t2', { status: 'completed', createdAgoH: 30 });
    await runOneCycle();
    expect(await exists(id)).toBe(false);
  }, 30000);

  test('T3 pending session that expired less than 24h ago is kept (late payment window)', async () => {
    const id = await seedSession('t3', { status: 'pending', createdAgoH: 2, expiresInH: -1 });
    await runOneCycle();
    expect(await exists(id)).toBe(true);
  }, 30000);

  test('T4 pending session that expired more than 24h ago is deleted', async () => {
    const id = await seedSession('t4', { status: 'pending', createdAgoH: 40, expiresInH: -30 });
    await runOneCycle();
    expect(await exists(id)).toBe(false);
  }, 30000);

  test('T5 one protected session does not stop the others: kept stays, deletable goes, no failure logged', async () => {
    const kept = await seedSession('t5a', { status: 'completed', createdAgoH: 30, withPayment: true });
    const gone = await seedSession('t5b', { status: 'failed', createdAgoH: 30 });
    await runOneCycle();
    expect(await exists(kept)).toBe(true);
    expect(await exists(gone)).toBe(false);
    expect(cleanupFailureLogged()).toBe(false);
  }, 30000);
});