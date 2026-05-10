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

  test('should survive when IP and BIN intelligence fail (timeout/null)', async () => {
    getIPIntelligence.mockResolvedValue({ riskScore: 0, confidence: 0, country: null, isDatacenter: false, source: 'timeout' });
    getBINIntelligence.mockResolvedValue(null);
    getEmailIntelligence.mockResolvedValue({ riskScore: 0, confidence: 0.9, domainExists: true, isDisposable: false, isFreeProvider: false, source: 'api' });
    getConnectedRisk.mockResolvedValue({ connectedRisk: 0, graphPath: [] });
    checkPatternRisk.mockResolvedValue({ penalty: 0, flags: [] });

    const result = await calculateRiskScore(createOrder(), allOrders, disputes, blacklist, null, false);
    expect(result.score).toBeDefined();
    expect(result.decision).toMatch(/Approve|Review|Block/);
    // لا يجب أن يكون هناك flags تشير إلى أخطاء داخلية
    expect(result.flags.every(f => !f.text.includes('Error'))).toBe(true);
  });

  test('classic velocity attack: 4 orders from same device/IP/email', async () => {
    const now = Date.now();
    const device = 'velocity-device-123';
    const ip = '10.0.0.1';
    const email = 'attacker@test.com';

    // بناء 4 طلبات متتالية
    const orders = [];
    for (let i = 1; i <= 4; i++) {
      orders.push({
        id: `vel-order-${i}`,
        email,
        ipAddress: ip,
        deviceFingerprint: device,
        deviceId: device,
        amount: 5.00,
        billingAddress: JSON.stringify({ country: 'US' }),
        shippingAddress: JSON.stringify({ country: 'US' }),
           createdAt: new Date(now - (4 - i) * 60000).toISOString(),
      riskLevel: i === 1 ? null : (i <= 2 ? 'low' : 'medium'),
      decision: i === 1 ? null : (i <= 2 ? 'approve' : 'review'),
      payment_details: { card_bin: '411111' }, // BIN موحد لاختبار BIN Velocity
      });
    }

    const allOrders = orders.slice(0, 3);
    const currentOrder = orders[3];

    getIPIntelligence.mockResolvedValue({ riskScore: 0, confidence: 0.9, country: 'US', isDatacenter: false, source: 'api' });
    getEmailIntelligence.mockResolvedValue({ riskScore: 0, confidence: 0.9, domainExists: true, isDisposable: false, isFreeProvider: false, source: 'api' });
    getBINIntelligence.mockResolvedValue(null);
    getConnectedRisk.mockResolvedValue({ connectedRisk: 0, graphPath: [] });
    checkPatternRisk.mockResolvedValue({ penalty: 0, flags: [] });

    const result = await calculateRiskScore(
      { ...currentOrder, payment_details: { card_bin: '411111' } },
      allOrders,
      [],
      [],
      null,
      false,
      null
    );

    expect(result.score).toBeLessThanOrEqual(30);
    expect(result.decision).toMatch(/Block/);
    expect(result.flags.some(f => f.text.includes('Device fingerprint linked to 4 orders'))).toBe(true);
    expect(result.flags.some(f => f.text.includes('4 orders from same IP'))).toBe(true);
    expect(result.flags.some(f => f.text.includes('BIN attack pattern detected'))).toBe(true);
  });
});