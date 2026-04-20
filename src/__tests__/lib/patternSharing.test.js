process.env.PATTERN_SHARING_SECRET = 'test-secret';

// Mock Prisma client
jest.mock('../../lib/db', () => {
  const mockFn = () => jest.fn();
  return {
    fraudPattern: {
      findUnique: mockFn(),
      updateMany: mockFn(),
      upsert: mockFn(),
      findMany: mockFn(),
    },
    fraudCluster: {
      findUnique: mockFn(),
      update: mockFn(),
      upsert: mockFn(),
      findMany: mockFn(),
    },
    patternMerchant: {
      create: mockFn(),
    },
    $transaction: jest.fn((callback) => callback({
      fraudPattern: { upsert: mockFn(), update: mockFn() },
      fraudCluster: { update: mockFn() }, // added update for cluster
    })),
  };
});

const {
  buildPattern,
  recordPattern,
  checkPatternRisk,
} = require('../../lib/patternSharing');
const db = require('../../lib/db');

describe('patternSharing.js', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('buildPattern', () => {
    test('extracts active signals from order', () => {
      const order = { amount: 250, isNewCustomer: true };
      const emailIntel = { isDisposable: true };
      const ipIntel = { isDatacenter: true };
      const context = { isHighVelocity: true };
      const result = buildPattern(order, emailIntel, ipIntel, context);
      expect(result.activeSignals).toContain('highAmount');
      expect(result.activeSignals).toContain('isNewCustomer');
      expect(result.activeSignals).toContain('isDisposableEmail');
      expect(result.activeSignals).toContain('isDatacenterIP');
      expect(result.activeSignals).toContain('isHighVelocity');
    });
  });

  describe('recordPattern', () => {
    test('creates new pattern when none exists', async () => {
      const order = { amount: 200, isNewCustomer: true, createdAt: new Date() };
      const emailIntel = { isDisposable: true };
      const ipIntel = { isDatacenter: true };
      const isFraud = true;
      const merchantId = 'merchant1';
      const patternContext = {};

      db.fraudPattern.findUnique.mockResolvedValue(null);
      db.fraudCluster.findMany.mockResolvedValue([]);
      db.fraudCluster.upsert.mockResolvedValue({ id: 'clusterId' });
      db.$transaction.mockImplementation(async (cb) => cb({
        fraudPattern: { upsert: jest.fn().mockResolvedValue({}) },
        fraudCluster: { update: jest.fn().mockResolvedValue({}) },
      }));

      await recordPattern(order, emailIntel, ipIntel, isFraud, merchantId, patternContext);
      expect(db.fraudPattern.findUnique).toHaveBeenCalled();
      expect(db.$transaction).toHaveBeenCalled();
    });

    test('updates existing pattern', async () => {
      const existingPattern = { patternHash: 'hash', version: 0, totalCount: 5, fraudCount: 2, legitCount: 3 };
      db.fraudPattern.findUnique.mockResolvedValue(existingPattern);
      db.fraudPattern.updateMany.mockResolvedValue({ count: 1 });

      await recordPattern({ amount: 200 }, { isDisposable: true }, { isDatacenter: true }, true, 'merchant1');
      expect(db.fraudPattern.updateMany).toHaveBeenCalled();
    });
  });

  describe('checkPatternRisk', () => {
    test('returns zero when no pattern matches', async () => {
      db.fraudPattern.findUnique.mockResolvedValue(null);
      const result = await checkPatternRisk({ amount: 100 }, {}, {});
      expect(result.penalty).toBe(0);
    });

    test('returns penalty when pattern has high fraud rate', async () => {
      const existingPattern = {
        patternHash: 'hash',
        fraudCount: 8,
        legitCount: 2,
        totalCount: 10,
        lastSeen: new Date(),
        merchantsSeen: 2,
      };
      db.fraudPattern.findUnique.mockResolvedValue(existingPattern);
      db.fraudCluster.findUnique.mockResolvedValue(null);
      const result = await checkPatternRisk({ amount: 200, isNewCustomer: true }, { isDisposable: true }, { isDatacenter: true });
      expect(result.penalty).toBeGreaterThan(0);
    });
  });
});