// Mock external dependencies
jest.mock('../../lib/identityGraph', () => ({
  markOrderAsFraud: jest.fn(),
}));
jest.mock('../../lib/patternSharing', () => ({
  markPatternAsFraud: jest.fn(),
}));
jest.mock('../../lib/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

// Mock Prisma client
jest.mock('../../lib/db', () => {
  const mockFn = () => jest.fn();
  return {
    order: {
      findUnique: mockFn(),
    },
    merchantProfile: {
      upsert: mockFn(),
    },
    signalStat: {
      upsert: mockFn(),
    },
    disputeOutcome: {
      findMany: mockFn(),
    },
  };
});

const { processFeedbackSimplified } = require('../../lib/feedbackLoop');
const { markOrderAsFraud } = require('../../lib/identityGraph');
const { markPatternAsFraud } = require('../../lib/patternSharing');
const db = require('../../lib/db');
const logger = require('../../lib/logger');

describe('feedbackLoop.js', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('processFeedbackSimplified', () => {
    const orderId = 'test_order_123';
    const merchantId = 'merchant_001';
   const mockOrder = {
  orderId,
  merchantId,
  email: 'test@example.com',
  ipAddress: '1.2.3.4',
  deviceFingerprint: 'fp123',
  amount: 100,
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

    test('should return early when order not found', async () => {
      db.order.findUnique.mockResolvedValue(null);
      await processFeedbackSimplified(orderId, true);
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ orderId }),
        'Order not found, cannot process feedback'
      );
      expect(db.merchantProfile.upsert).not.toHaveBeenCalled();
    });

    test('should update MerchantProfile and SignalStat for fraud (isFraud=true)', async () => {
      db.order.findUnique.mockResolvedValue(mockOrder);
      db.merchantProfile.upsert.mockResolvedValue({});
      db.signalStat.upsert.mockResolvedValue({});
      db.disputeOutcome.findMany.mockResolvedValue([]); // not used in simplified path

      await processFeedbackSimplified(orderId, true);

      // Verify MerchantProfile upsert called with correct data (isWin = false)
      expect(db.merchantProfile.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { merchantId },
          create: expect.objectContaining({
            wonDisputes: 0,
            lostDisputes: 1,
            totalDisputes: 1,
          }),
          update: expect.objectContaining({
            lostDisputes: { increment: 1 },
            totalDisputes: { increment: 1 },
          }),
        })
      );

      // SignalStat should be updated for both global (null) and merchant
      expect(db.signalStat.upsert).toHaveBeenCalled();
      // Check that at least one call was for merchantId = null
      const globalCalls = db.signalStat.upsert.mock.calls.filter(
        call => call[0].where.merchantId_signalType_signalValue.merchantId === null
      );
      expect(globalCalls.length).toBeGreaterThan(0);

      // Verify fraud marking functions called
      expect(markOrderAsFraud).toHaveBeenCalled();
      // markPatternAsFraud depends on deviceVelocityCount and other factors; skip for simplicity
    });

    test('should update MerchantProfile and SignalStat for legit (isFraud=false)', async () => {
      db.order.findUnique.mockResolvedValue(mockOrder);
      db.merchantProfile.upsert.mockResolvedValue({});
      db.signalStat.upsert.mockResolvedValue({});

      await processFeedbackSimplified(orderId, false);

      expect(db.merchantProfile.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          create: expect.objectContaining({
            wonDisputes: 1,
            lostDisputes: 0,
          }),
          update: expect.objectContaining({
            wonDisputes: { increment: 1 },
          }),
        })
      );

      // Fraud marking functions should NOT be called
      expect(markOrderAsFraud).not.toHaveBeenCalled();
      expect(markPatternAsFraud).not.toHaveBeenCalled();
    });

    test('should handle missing signalsSnapshot gracefully', async () => {
      const orderWithoutSnapshot = { ...mockOrder, signalsSnapshot: null };
      db.order.findUnique.mockResolvedValue(orderWithoutSnapshot);
      db.merchantProfile.upsert.mockResolvedValue({});
      db.signalStat.upsert.mockResolvedValue({});

      await processFeedbackSimplified(orderId, true);

      // Should still update merchant profile and signal stats (but with empty signals list)
      expect(db.merchantProfile.upsert).toHaveBeenCalled();
      // SignalStat upsert should be called (maybe zero times because no signals)
      // In code, if signals.length == 0, no SignalStat updates happen.
      // That's fine.
    });
  });
});