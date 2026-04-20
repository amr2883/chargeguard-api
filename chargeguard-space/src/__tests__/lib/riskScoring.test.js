// Mock external dependencies
jest.mock('../../lib/ipIntelligence', () => ({
  getIPIntelligence: jest.fn(),
  calculateIPPenalty: jest.fn(() => ({ penalty: 0, flags: [] })),
}));
jest.mock('../../lib/emailIntelligence', () => ({
  getEmailIntelligence: jest.fn(),
  calculateEmailPenalty: jest.fn(() => ({ penalty: 0, flags: [] })),
}));
jest.mock('../../lib/binIntelligence', () => ({
  getBINIntelligence: jest.fn(),
  calculateBINPenalty: jest.fn(() => ({ penalty: 0, flags: [] })),
}));
jest.mock('../../lib/identityGraph', () => ({
  getConnectedRisk: jest.fn(),
}));
jest.mock('../../lib/patternSharing', () => ({
  checkPatternRisk: jest.fn(),
  recordPattern: jest.fn().mockResolvedValue(),
}));
jest.mock('../../lib/signalWeights', () => ({
  getWeightsForMerchant: jest.fn(),
  getStaticWeight: jest.fn(),
}));
jest.mock('../../lib/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const { calculateRiskScore } = require('../../lib/riskScoring');
const { getIPIntelligence } = require('../../lib/ipIntelligence');
const { getEmailIntelligence } = require('../../lib/emailIntelligence');
const { getBINIntelligence } = require('../../lib/binIntelligence');
const { getConnectedRisk } = require('../../lib/identityGraph');
const { checkPatternRisk } = require('../../lib/patternSharing');

describe('riskScoring.js', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  const createOrder = (overrides = {}) => ({
    id: 'order1',
    email: 'test@example.com',
    ipAddress: '1.2.3.4',
    deviceFingerprint: 'fp123',
    amount: 100,
    billingAddress: JSON.stringify({ country: 'US' }),
    shippingAddress: JSON.stringify({ country: 'US' }),
    ...overrides,
  });

  const allOrders = [];
  const disputes = [];
  const blacklist = [];

  test('should return default score when no signals', async () => {
    getIPIntelligence.mockResolvedValue({ riskScore: 0, confidence: 0.9, country: 'US', isDatacenter: false, source: 'api' });
    getEmailIntelligence.mockResolvedValue({ riskScore: 0, confidence: 0.9, domainExists: true, isDisposable: false, isFreeProvider: false, source: 'api' });
    getBINIntelligence.mockResolvedValue(null);
    getConnectedRisk.mockResolvedValue({ connectedRisk: 0, graphPath: [] });
    checkPatternRisk.mockResolvedValue({ penalty: 0, flags: [] });

    const result = await calculateRiskScore(createOrder(), allOrders, disputes, blacklist, null, false);
    expect(result.score).toBeDefined();
    expect(result.decision).toMatch(/Approve|Review|Block/);
  });

  test('should apply blacklist penalty', async () => {
    const blacklistEntry = { email: 'test@example.com' };
    const result = await calculateRiskScore(createOrder(), allOrders, disputes, [blacklistEntry], null, false);
    expect(result.score).toBeLessThan(100);
    expect(result.flags.some(f => f.text.includes('fraud blacklist'))).toBe(true);
  });

  test('should apply device velocity penalty', async () => {
    const order = createOrder({ deviceFingerprint: 'fp123' });
    const ordersWithSameDevice = [
      { ...order, id: 'order2', deviceFingerprint: 'fp123', createdAt: new Date(Date.now() - 30 * 60 * 1000) },
      { ...order, id: 'order3', deviceFingerprint: 'fp123', createdAt: new Date(Date.now() - 10 * 60 * 1000) },
    ];
    getIPIntelligence.mockResolvedValue({ riskScore: 0, confidence: 0.9, country: 'US', isDatacenter: false, source: 'api' });
    getEmailIntelligence.mockResolvedValue({ riskScore: 0, confidence: 0.9, domainExists: true, isDisposable: false, isFreeProvider: false, source: 'api' });
    getBINIntelligence.mockResolvedValue(null);
    getConnectedRisk.mockResolvedValue({ connectedRisk: 0, graphPath: [] });
    checkPatternRisk.mockResolvedValue({ penalty: 0, flags: [] });

    const result = await calculateRiskScore(order, ordersWithSameDevice, disputes, blacklist, null, false);
    expect(result.score).toBeLessThan(85);
    expect(result.flags.some(f => f.text.includes('Device fingerprint linked to'))).toBe(true);
  });
});