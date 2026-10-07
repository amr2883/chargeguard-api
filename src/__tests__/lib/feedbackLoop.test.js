// src/__tests__/lib/feedbackLoop.test.js
//
// Tests for processFeedbackSimplified().
//
// Contract pinned here:
//   - the caller MUST pass its own merchantId (throws otherwise)
//   - the order is looked up scoped to that merchant
//   - an idempotency claim (feedbackProcessedAt) is taken before counters move
//   - MerchantProfile + SignalStat counters move together inside one $transaction
//   - fraud-only side effects (identity graph, pattern network, cardHash) run after
//
// IMPORTANT: processFeedbackSimplified() swallows its own errors (outer catch ->
// logger.error). A test that only asserts "X was NOT called" would pass vacuously
// if the function crashed early, so every happy-path test also asserts that
// logger.error was never called.

jest.mock('../../lib/identityGraph', () => ({
  markOrderAsFraud: jest.fn(),
}));
jest.mock('../../lib/patternSharing', () => ({
  markPatternAsFraud: jest.fn(),
  markPatternAsLegit: jest.fn(),
}));
jest.mock('../../lib/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));
jest.mock('../../lib/db', () => ({
  order: { findFirst: jest.fn(), updateMany: jest.fn() },
  merchantProfile: { upsert: jest.fn() },
  disputeOutcome: { create: jest.fn() },
  cardHash: { update: jest.fn() },
  $transaction: jest.fn(),
  $executeRaw: jest.fn(),
}));

const { processFeedback, processFeedbackSimplified } = require('../../lib/feedbackLoop');
const { markOrderAsFraud } = require('../../lib/identityGraph');
const { markPatternAsFraud, markPatternAsLegit } = require('../../lib/patternSharing');
const db = require('../../lib/db');
const logger = require('../../lib/logger');

const GLOBAL_SCOPE = '__global__';

// Signals extractSignalsFromSnapshot() must produce from mockOrder's snapshot.
// Values are stored upper-cased by updateSignalStat().
const EXPECTED_SIGNALS = [
  ['BIN_PREPAID', 'TRUE'],
  ['EMAIL_DISPOSABLE', 'TRUE'],
  ['IP_DATACENTER', 'TRUE'],
  ['NEW_CUSTOMER', 'TRUE'],
  ['DEVICE_VELOCITY', 'CRITICAL'],
  ['IP_VELOCITY', 'HIGH'],
];

describe('feedbackLoop.js', () => {
  describe('processFeedbackSimplified', () => {
    const orderId = 'test_order_123';
    const merchantId = 'merchant_001';
    const rowId = 'order_row_001';

    const mockOrder = {
      id: rowId,
      orderId,
      merchantId,
      email: 'test@example.com',
      ipAddress: '1.2.3.4',
      deviceFingerprint: 'fp123',
      amount: 100,
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
      signalsSnapshot: JSON.stringify({
        emailIntel: { isDisposable: true },
        ipIntel: { isDatacenter: true },
        binIntel: { isPrepaid: true },
        deviceVelocityCount: 3,
        ipVelocityCount: 2,
        emailVelocityCount: 1,
        isNewCustomer: true,
      }),
    };

    beforeEach(() => {
      jest.resetAllMocks();
      db.$transaction.mockImplementation(async (cb) => cb(db));
      db.$executeRaw.mockResolvedValue(1);
      db.order.updateMany.mockResolvedValue({ count: 1 });
      db.merchantProfile.upsert.mockResolvedValue({});
      db.disputeOutcome.create.mockResolvedValue({});
      db.cardHash.update.mockResolvedValue({});
      markOrderAsFraud.mockResolvedValue(undefined);
      markPatternAsFraud.mockResolvedValue(undefined);
      markPatternAsLegit.mockResolvedValue(undefined);
    });

    // $executeRaw is used as a tagged template: calls are (strings, ...values).
    // Match on values regardless of their position.
    const rawValues = () => db.$executeRaw.mock.calls.map(([, ...values]) => values);
    const signalCalls = (scope, type, value) =>
      rawValues().filter((v) => v.includes(scope) && v.includes(type) && v.includes(value));
    const expectEverySignalUpdatedTwice = () => {
      expect(db.$executeRaw).toHaveBeenCalledTimes(EXPECTED_SIGNALS.length * 2);
      for (const [type, value] of EXPECTED_SIGNALS) {
        expect(signalCalls(GLOBAL_SCOPE, type, value)).toHaveLength(1);
        expect(signalCalls(merchantId, type, value)).toHaveLength(1);
      }
    };

    test('throws when callerMerchantId is missing and touches nothing', async () => {
      await expect(processFeedbackSimplified(orderId, true)).rejects.toThrow(
        'callerMerchantId is required'
      );
      expect(db.order.findFirst).not.toHaveBeenCalled();
      expect(db.order.updateMany).not.toHaveBeenCalled();
      expect(db.$transaction).not.toHaveBeenCalled();
    });

    test('returns early when the order is not found for this merchant', async () => {
      db.order.findFirst.mockResolvedValue(null);

      await processFeedbackSimplified(orderId, true, merchantId);

      expect(db.order.findFirst).toHaveBeenCalledWith({
        where: { merchantId, orderId, storeId: null },
      });
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ orderId, callerMerchantId: merchantId }),
        'Order not found for this merchant, cannot process feedback'
      );
      expect(db.order.updateMany).not.toHaveBeenCalled();
      expect(db.$transaction).not.toHaveBeenCalled();
      expect(db.merchantProfile.upsert).not.toHaveBeenCalled();
      expect(db.disputeOutcome.create).not.toHaveBeenCalled();
      expect(markOrderAsFraud).not.toHaveBeenCalled();
      expect(logger.error).not.toHaveBeenCalled();
    });

    test('refuses a row that belongs to a different merchant (C4 guard)', async () => {
      db.order.findFirst.mockResolvedValue({ ...mockOrder, merchantId: 'other_merchant' });

      await processFeedbackSimplified(orderId, true, merchantId);

      expect(logger.error).toHaveBeenCalledWith(
        expect.objectContaining({
          orderId,
          callerMerchantId: merchantId,
          actualMerchantId: 'other_merchant',
        }),
        expect.stringContaining('C4 guard tripped')
      );
      expect(db.order.updateMany).not.toHaveBeenCalled();
      expect(db.$transaction).not.toHaveBeenCalled();
      expect(db.merchantProfile.upsert).not.toHaveBeenCalled();
      expect(markOrderAsFraud).not.toHaveBeenCalled();
    });

    test('skips everything on a duplicate feedback call (idempotency claim lost)', async () => {
      db.order.findFirst.mockResolvedValue(mockOrder);
      db.order.updateMany.mockResolvedValue({ count: 0 });

      await processFeedbackSimplified(orderId, true, merchantId);

      expect(db.order.updateMany).toHaveBeenCalledWith({
        where: { merchantId, orderId, feedbackProcessedAt: null },
        data: { feedbackProcessedAt: expect.any(Date) },
      });
      expect(logger.info).toHaveBeenCalledWith(
        expect.objectContaining({ orderId, merchantId }),
        expect.stringContaining('Duplicate feedback call detected')
      );
      expect(db.$transaction).not.toHaveBeenCalled();
      expect(db.merchantProfile.upsert).not.toHaveBeenCalled();
      expect(db.$executeRaw).not.toHaveBeenCalled();
      expect(db.disputeOutcome.create).not.toHaveBeenCalled();
      expect(markOrderAsFraud).not.toHaveBeenCalled();
      expect(markPatternAsFraud).not.toHaveBeenCalled();
      expect(logger.error).not.toHaveBeenCalled();
    });

    test('fraud (isFraud=true): counts a loss, updates every signal, marks fraud', async () => {
      db.order.findFirst.mockResolvedValue(mockOrder);

      await processFeedbackSimplified(orderId, true, merchantId);

      expect(db.order.updateMany).toHaveBeenCalledTimes(1);
      expect(db.$transaction).toHaveBeenCalledTimes(1);
      expect(db.merchantProfile.upsert).toHaveBeenCalledTimes(1);
      expect(db.merchantProfile.upsert).toHaveBeenCalledWith({
        where: { merchantId },
        create: {
          merchantId,
          wonDisputes: 0,
          lostDisputes: 1,
          totalDisputes: 1,
          trustScore: 0.3,
          reportCount: 1,
        },
        update: {
          wonDisputes: undefined,
          lostDisputes: { increment: 1 },
          totalDisputes: { increment: 1 },
          reportCount: { increment: 1 },
        },
      });

      expectEverySignalUpdatedTwice();

      expect(markOrderAsFraud).toHaveBeenCalledTimes(1);
      expect(markOrderAsFraud).toHaveBeenCalledWith(
        expect.objectContaining({
          deviceFingerprint: 'fp123',
          email: 'test@example.com',
          ipAddress: '1.2.3.4',
          fingerprintVersion: 'v3',
        }),
        merchantId
      );
      expect(markPatternAsFraud).toHaveBeenCalledTimes(1);
      expect(markPatternAsFraud).toHaveBeenCalledWith(
        expect.objectContaining({ amount: 100, isNewCustomer: true }),
        { isDisposable: true },
        { isDatacenter: true },
        merchantId,
        { isHighVelocity: true }
      );
      expect(markPatternAsLegit).not.toHaveBeenCalled();
      expect(db.cardHash.update).not.toHaveBeenCalled();

      expect(db.disputeOutcome.create).toHaveBeenCalledTimes(1);
      const { data } = db.disputeOutcome.create.mock.calls[0][0];
      expect(data).toEqual({
        disputeId: orderId,
        merchantId,
        orderId: rowId,
        result: 'lost',
        signalsPresent: expect.any(String),
      });
      expect(JSON.parse(data.signalsPresent).map((s) => s.type).sort()).toEqual(
        EXPECTED_SIGNALS.map(([type]) => type).sort()
      );

      expect(logger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          orderId,
          isFraud: true,
          isWin: false,
          merchantId,
          signalsCount: EXPECTED_SIGNALS.length,
        }),
        'Feedback processed with SignalStat updates'
      );
      expect(logger.error).not.toHaveBeenCalled();
    });

    test('legit (isFraud=false): counts a win, updates every signal, no fraud marking', async () => {
      db.order.findFirst.mockResolvedValue(mockOrder);

      await processFeedbackSimplified(orderId, false, merchantId);

      expect(db.merchantProfile.upsert).toHaveBeenCalledTimes(1);
      expect(db.merchantProfile.upsert).toHaveBeenCalledWith({
        where: { merchantId },
        create: {
          merchantId,
          wonDisputes: 1,
          lostDisputes: 0,
          totalDisputes: 1,
          trustScore: 0.3,
          reportCount: 1,
        },
        update: {
          wonDisputes: { increment: 1 },
          lostDisputes: undefined,
          totalDisputes: { increment: 1 },
          reportCount: { increment: 1 },
        },
      });

      expectEverySignalUpdatedTwice();

      expect(markOrderAsFraud).not.toHaveBeenCalled();
      expect(markPatternAsFraud).not.toHaveBeenCalled();
      expect(markPatternAsLegit).toHaveBeenCalledTimes(1);
      expect(markPatternAsLegit).toHaveBeenCalledWith(
        expect.objectContaining({ amount: 100, isNewCustomer: true }),
        { isDisposable: true },
        { isDatacenter: true },
        merchantId,
        { isHighVelocity: true }
      );
      expect(db.cardHash.update).not.toHaveBeenCalled();
      expect(db.disputeOutcome.create).toHaveBeenCalledWith({
        data: expect.objectContaining({ disputeId: orderId, merchantId, result: 'won' }),
      });
      expect(logger.error).not.toHaveBeenCalled();
    });

    test('missing signalsSnapshot: still counts the outcome, updates no signals', async () => {
      db.order.findFirst.mockResolvedValue({ ...mockOrder, signalsSnapshot: null });

      await processFeedbackSimplified(orderId, true, merchantId);

      expect(db.merchantProfile.upsert).toHaveBeenCalledTimes(1);
      expect(db.$executeRaw).not.toHaveBeenCalled();
      expect(db.disputeOutcome.create).toHaveBeenCalledWith({
        data: expect.objectContaining({ result: 'lost', signalsPresent: '[]' }),
      });
      expect(markPatternAsFraud).toHaveBeenCalledWith(
        expect.objectContaining({ isNewCustomer: false }),
        null,
        null,
        merchantId,
        { isHighVelocity: false }
      );
      expect(logger.error).not.toHaveBeenCalled();
    });

    test('malformed signalsSnapshot: logs it, still counts the outcome', async () => {
      db.order.findFirst.mockResolvedValue({ ...mockOrder, signalsSnapshot: '{not valid json' });

      await processFeedbackSimplified(orderId, false, merchantId);

      expect(logger.error).toHaveBeenCalledWith(
        expect.objectContaining({ module: 'feedbackLoop' }),
        'Failed to parse signalsSnapshot'
      );
      expect(logger.error).toHaveBeenCalledTimes(1);
      expect(db.merchantProfile.upsert).toHaveBeenCalledTimes(1);
      expect(db.$executeRaw).not.toHaveBeenCalled();
      expect(db.disputeOutcome.create).toHaveBeenCalledWith({
        data: expect.objectContaining({ result: 'won', signalsPresent: '[]' }),
      });
    });

    test('fraud on an order with a cardHash increments blockCount for that card', async () => {
      db.order.findFirst.mockResolvedValue({ ...mockOrder, cardHash: 'ch_abc123' });

      await processFeedbackSimplified(orderId, true, merchantId);

      expect(db.cardHash.update).toHaveBeenCalledTimes(1);
      expect(db.cardHash.update).toHaveBeenCalledWith({
        where: { cardHash: 'ch_abc123' },
        data: { blockCount: { increment: 1 } },
      });
      expect(logger.error).not.toHaveBeenCalled();
    });

    test('processFeedback: throws when callerMerchantId is missing and touches nothing', async () => {
      await expect(processFeedback(orderId, 'lost')).rejects.toThrow(
        'processFeedback: callerMerchantId is required'
      );
      expect(db.order.findFirst).not.toHaveBeenCalled();
      expect(db.order.updateMany).not.toHaveBeenCalled();
      expect(db.$transaction).not.toHaveBeenCalled();
    });

    test('processFeedback: delegates to the simplified path, mapping "lost" to fraud', async () => {
      db.order.findFirst.mockResolvedValue(mockOrder);

      await processFeedback(orderId, 'lost', merchantId);

      expect(db.order.findFirst).toHaveBeenCalledWith({
        where: { merchantId, orderId, storeId: null },
      });
      expect(db.merchantProfile.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          create: expect.objectContaining({ wonDisputes: 0, lostDisputes: 1 }),
        })
      );
      expect(markOrderAsFraud).toHaveBeenCalledTimes(1);
      expect(logger.error).not.toHaveBeenCalled();
    });
    test('legit outcome never touches cardHash.blockCount', async () => {
      db.order.findFirst.mockResolvedValue({ ...mockOrder, cardHash: 'ch_abc123' });

      await processFeedbackSimplified(orderId, false, merchantId);

      expect(db.cardHash.update).not.toHaveBeenCalled();
      expect(db.merchantProfile.upsert).toHaveBeenCalledTimes(1);
      expect(logger.error).not.toHaveBeenCalled();
    });
  });
});
// END-OF-FILE-192
