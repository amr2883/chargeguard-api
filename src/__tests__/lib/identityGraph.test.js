process.env.IDENTITY_GRAPH_SECRET = 'test-secret-key';

// Observe logging: the errors identityGraph swallows are asserted through logger.error.
jest.mock('../../lib/logger', () => ({
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

// Mock the db module correctly (since db.js exports prisma directly, not as default)
jest.mock('../../lib/db', () => {
  const mockFn = () => jest.fn();
  return {
    identityNode: {
      upsert: mockFn(),
      findFirst: mockFn(),
      findMany: mockFn(),
      update: mockFn(),
      updateMany: mockFn(),
    },
    identityEdge: {
      upsert: mockFn(),
      findUnique: mockFn(),
      findMany: mockFn(),
      count: mockFn(),
    },
    identityEvent: {
      create: mockFn(),
      findMany: mockFn(),
    },
    identityNodeMerchant: {
      create: mockFn(),
      update: mockFn(),
    },
    computedIdentityRisk: {
      upsert: mockFn(),
      findUnique: mockFn(),
    },
    merchantProfile: {
      findUnique: mockFn(),
      update: mockFn(),
    },
    $transaction: jest.fn((callback) => callback({
      identityNode: {
        update: mockFn(),
        updateMany: mockFn(),
      },
      merchantProfile: {
        update: mockFn(),
      },
    })),
  };
});

const {
  buildGraphFromOrder,
  getConnectedRisk,
  markOrderAsFraud,
  markOrderAsClean,
} = require('../../lib/identityGraph');
const prisma = require('../../lib/db');
const logger = require('../../lib/logger');

describe('identityGraph.js (public functions)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('buildGraphFromOrder', () => {
    test('builds graph from order data', async () => {
      const order = {
        deviceFingerprint: 'device123',
        email: 'test@example.com',
        ipAddress: '1.2.3.4',
        shippingAddress: JSON.stringify({ city: 'Cairo', zip: '12345', country: 'EG' }),
      };
      const merchantId = 'merchant1';

      prisma.identityNode.findFirst.mockResolvedValue(null);
      prisma.identityEdge.count.mockResolvedValue(0);

      // upsertNode runs for DEVICE, EMAIL, IP and ADDRESS = 4 calls (the FINGERPRINT connection equals the device id and is filtered out)
      prisma.identityNode.upsert
        .mockResolvedValueOnce({ id: 'deviceNodeId', fraudEvents: 0 })
        .mockResolvedValue({ id: 'connNodeId' });
      prisma.identityEdge.upsert.mockResolvedValue({});

      await buildGraphFromOrder(order, merchantId);
      // Total upsert calls: 4 from upsertNode + 3 from upsertGlobalNode = 7
      expect(prisma.identityNode.upsert).toHaveBeenCalledTimes(7);
      // Edges: EMAIL, IP and ADDRESS = 3 (FINGERPRINT is filtered out like above)
expect(prisma.identityEdge.upsert).toHaveBeenCalledTimes(3);
    });
  });

  describe('buildGraphFromOrder - cross-merchant junction (upsertGlobalNode)', () => {
    // Global nodes are built for DEVICE, IP and FINGERPRINT, so each test
    // expects three junction operations.
    const order = {
      deviceFingerprint: 'device123',
      email: 'test@example.com',
      ipAddress: '1.2.3.4',
    };
    const merchantId = 'merchant1';

    const incrementCalls = () =>
      prisma.identityNode.update.mock.calls.filter(([arg]) => arg && arg.data && arg.data.merchantsSeen);
    const globalNodeErrors = () =>
      logger.error.mock.calls.filter(([, msg]) => msg === 'upsertGlobalNode error');

    beforeEach(() => {
      prisma.identityNode.findFirst.mockReset();
      prisma.identityNode.upsert.mockReset();
      prisma.identityNode.update.mockReset();
      prisma.identityEdge.count.mockReset();
      prisma.identityEdge.upsert.mockReset();
      prisma.identityNodeMerchant.create.mockReset();
      prisma.identityNodeMerchant.update.mockReset();

      prisma.identityNode.findFirst.mockResolvedValue(null);
      prisma.identityEdge.count.mockResolvedValue(0);
      prisma.identityNode.upsert
        .mockResolvedValueOnce({ id: 'deviceNodeId', fraudEvents: 0 })
        .mockResolvedValue({ id: 'connNodeId' });
      prisma.identityNode.update.mockResolvedValue({});
      prisma.identityEdge.upsert.mockResolvedValue({});
      prisma.identityNodeMerchant.create.mockResolvedValue({});
      prisma.identityNodeMerchant.update.mockResolvedValue({});
    });

    // Put the three mocks only this block configures back to their original state.
    afterAll(() => {
      prisma.identityNode.update.mockReset();
      prisma.identityNodeMerchant.create.mockReset();
      prisma.identityNodeMerchant.update.mockReset();
    });

    test('links each global node to the merchant and increments both counters once', async () => {
      await buildGraphFromOrder(order, merchantId);

      expect(prisma.identityNodeMerchant.create).toHaveBeenCalledTimes(3);
      expect(prisma.identityNodeMerchant.create).toHaveBeenCalledWith({
        data: { nodeId: 'connNodeId', merchantId },
      });
      expect(incrementCalls()).toHaveLength(3);
      for (const [arg] of incrementCalls()) {
        expect(arg).toEqual({
          where: { id: 'connNodeId' },
          data: {
            merchantsSeen: { increment: 1 },
            recentMerchants: { increment: 1 },
          },
        });
      }
      expect(prisma.identityNodeMerchant.update).not.toHaveBeenCalled();
      expect(globalNodeErrors()).toHaveLength(0);
    });

    test('on P2002 refreshes lastSeenAt on the existing link and does not increment', async () => {
      prisma.identityNodeMerchant.create.mockRejectedValue(
        Object.assign(new Error('Unique constraint failed'), { code: 'P2002' })
      );

      await buildGraphFromOrder(order, merchantId);

      expect(prisma.identityNodeMerchant.update).toHaveBeenCalledTimes(3);
      expect(prisma.identityNodeMerchant.update).toHaveBeenCalledWith({
        where: { nodeId_merchantId: { nodeId: 'connNodeId', merchantId } },
        data: { lastSeenAt: expect.any(Date) },
      });
      expect(incrementCalls()).toHaveLength(0);
      expect(globalNodeErrors()).toHaveLength(0);
    });

    test('on any other create error logs upsertGlobalNode error and does not increment', async () => {
      prisma.identityNodeMerchant.create.mockRejectedValue(new Error('boom'));

      await buildGraphFromOrder(order, merchantId);

      expect(globalNodeErrors()).toHaveLength(3);
      expect(prisma.identityNodeMerchant.update).not.toHaveBeenCalled();
      expect(incrementCalls()).toHaveLength(0);
    });

    test('without a merchantId no junction row is created and nothing is incremented', async () => {
      await buildGraphFromOrder(order, undefined);

      expect(prisma.identityNodeMerchant.create).not.toHaveBeenCalled();
      expect(prisma.identityNodeMerchant.update).not.toHaveBeenCalled();
      expect(incrementCalls()).toHaveLength(0);
      expect(globalNodeErrors()).toHaveLength(0);
    });
  });

  describe('getConnectedRisk', () => {
    test('returns zero when no device', async () => {
      const order = { deviceFingerprint: null };
      const result = await getConnectedRisk(order, 'merchant1');
      expect(result).toEqual({ connectedRisk: 0, hasConnections: false, graphPath: [] });
    });

    test('handles config match (since hashedValue differs)', async () => {
      const order = {
        deviceFingerprint: 'device123',
        fingerprintVersion: 'v3',
        fingerprintConfig: 'config',
        fingerprintHardware: 'hardware',
      };
      const merchantId = 'merchant1';
      const deviceNode = {
        id: 'deviceId',
        hashedValue: 'different_hash',
        fingerprintConfig: 'config',
        fingerprintHardware: 'hardware',
      };
      prisma.identityNode.findMany.mockResolvedValue([deviceNode]);
      prisma.identityEdge.findMany.mockResolvedValue([]);
      prisma.identityNode.findFirst.mockResolvedValue(null);
      prisma.computedIdentityRisk.findUnique.mockResolvedValue(null);
      prisma.identityEdge.count.mockResolvedValue(0);

      const result = await getConnectedRisk(order, merchantId);
      expect(result.connectedRisk).toBeDefined();
      // Since hashedValue doesn't match, it falls back to config match
      expect(result.matchTier).toBe('config');
    });
  });

  describe('markOrderAsFraud', () => {
    test('marks device as fraud', async () => {
      const order = { deviceFingerprint: 'device123', ipAddress: '1.2.3.4', email: 'test@example.com' };
      const merchantId = 'merchant1';
      const deviceNode = { id: 'deviceId', fraudEvents: 0, chargebacks: 0 };

      prisma.identityNode.findFirst
        .mockResolvedValueOnce(deviceNode)
        .mockResolvedValueOnce({ id: 'globalId' });

      prisma.identityEdge.findMany.mockResolvedValue([{ to: { id: 'connId' } }]);
      prisma.merchantProfile.findUnique.mockResolvedValue({ trustScore: 0.5, reportCount: 10 });
      prisma.identityEvent.findMany.mockResolvedValue([]);
      prisma.identityEvent.create.mockResolvedValue({});
      prisma.computedIdentityRisk.upsert.mockResolvedValue({});

      await markOrderAsFraud(order, merchantId);
      // Verify that the transaction was called
      expect(prisma.$transaction).toHaveBeenCalled();
      // Optionally, verify that the update inside transaction was called (through the mock)
      // We can also check that the transaction callback was invoked.
    });
  });
});