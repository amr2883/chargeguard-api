// #236 / #237: learned-weight path of calculateRiskScore (merchantId set, getWeightsForMerchant mocked).
// learnedMultiplier = learned / staticBase, with IP_VELOCITY:HIGH and EMAIL_VELOCITY:HIGH static base = 20.
// Penalty = min(round(coef * multiplier * log2(count + 1)), cap): IP coef 15 cap 35 (count 2), email coef 12 cap 30 (count 3).
jest.mock('prom-client', () => ({
  Counter: jest.fn().mockImplementation(() => ({ inc: jest.fn(), labels: jest.fn().mockReturnThis() })),
  Histogram: jest.fn().mockImplementation(() => ({ observe: jest.fn(), labels: jest.fn().mockReturnThis(), startTimer: jest.fn().mockReturnValue(jest.fn()) })),
  collectDefaultMetrics: jest.fn(),
  register: { metrics: jest.fn().mockResolvedValue(''), contentType: 'text/plain', registerMetric: jest.fn(), clear: jest.fn() },
}));
jest.mock('../../src/lib/db', () => ({ merchantProfile: { findUnique: jest.fn().mockResolvedValue(null) } }));
jest.mock('../../src/lib/signalWeights', () => {
  const actual = jest.requireActual('../../src/lib/signalWeights');
  return { ...actual, getWeightsForMerchant: jest.fn() };
});
jest.mock('../../src/lib/ipIntelligence', () => ({ getIPIntelligence: jest.fn(), calculateIPPenalty: jest.fn(), invalidateIPCache: jest.fn(), normalizeIP: jest.fn((ip) => ip) }));
jest.mock('../../src/lib/patternSharing', () => ({ checkPatternRisk: jest.fn().mockResolvedValue({ penalty: 0, flags: [] }), recordPattern: jest.fn().mockResolvedValue(null), buildPattern: jest.fn(), markPatternAsFraud: jest.fn().mockResolvedValue(null) }));
jest.mock('../../src/lib/emailIntelligence', () => ({ getEmailIntelligence: jest.fn(), calculateEmailPenalty: jest.fn(), invalidateEmailCache: jest.fn() }));
jest.mock('../../src/lib/binIntelligence', () => ({ getBINIntelligence: jest.fn(), calculateBINPenalty: jest.fn(), normalizeBin: jest.fn(() => null), extractBIN: jest.fn() }));
jest.mock('../../src/lib/identityGraph', () => ({ getConnectedRisk: jest.fn().mockResolvedValue({ connectedRisk: 0, hasConnections: false, graphPath: [] }), buildGraphFromOrder: jest.fn(), markOrderAsFraud: jest.fn(), markOrderAsClean: jest.fn() }));

const { calculateRiskScore } = require('../../src/lib/riskScoring');
const { getWeightsForMerchant } = require('../../src/lib/signalWeights');
const { getIPIntelligence, calculateIPPenalty } = require('../../src/lib/ipIntelligence');
const { getEmailIntelligence, calculateEmailPenalty } = require('../../src/lib/emailIntelligence');
const { getBINIntelligence, calculateBINPenalty } = require('../../src/lib/binIntelligence');

const minutesAgo = (m) => new Date(Date.now() - m * 60 * 1000);
const NOON = new Date(2025, 5, 15, 12, 0, 0);

async function runLearned(order, allOrders, disputes, weights) {
  getIPIntelligence.mockResolvedValue({});
  calculateIPPenalty.mockReturnValue({ penalty: 0, flags: [] });
  getEmailIntelligence.mockResolvedValue({});
  calculateEmailPenalty.mockReturnValue({ penalty: 0, flags: [] });
  getBINIntelligence.mockResolvedValue({});
  calculateBINPenalty.mockReturnValue({ penalty: 0, flags: [] });
  getWeightsForMerchant.mockResolvedValue({ weights, merchantWeightRatio: 0, isLearning: true, totalDisputes: 0 });
  return calculateRiskScore(order, allOrders, disputes, [], 'merchant-learned', false, null, null, null);
}

const ipOrder = { id: 'o1', amount: 50, ipAddress: '198.51.100.50', email: 'orderemail@example.com', createdAt: NOON };
const ipHist = [
  { id: 'h1', amount: 50, ipAddress: '198.51.100.50', email: 'a1@example.com', createdAt: minutesAgo(30) },
  { id: 'h2', amount: 50, ipAddress: '198.51.100.50', email: 'a2@example.com', createdAt: minutesAgo(45) },
];
const emOrder = { id: 'o2', amount: 50, email: 'buyer@example.com', ipAddress: 'unique-ip-x', createdAt: NOON };
const emHist = [1, 2, 3].map((n) => ({ id: 'e' + n, amount: 50, email: 'buyer@example.com', ipAddress: 'ip-' + n, createdAt: minutesAgo(30 + 15 * n) }));
// disputes only exclude the history orders from prevGoodOrders (same trick as static-scoring.test.js)
const emDisp = [1, 2, 3].map((n) => ({ id: 's' + n, orderId: 'e' + n }));

beforeEach(() => { jest.clearAllMocks(); });

describe('learned weights scale the IP and email velocity penalty (merchantId set)', () => {
  test.each([
    [10, 0.5, -12],
    [20, 1.0, -24],
    [40, 2.0, -35],
  ])('IP_VELOCITY:HIGH weight %i (multiplier %f) gives contribution %i', async (w, _m, expected) => {
    const r = await runLearned(ipOrder, ipHist, [], { 'IP_VELOCITY:HIGH': w });
    const sig = r.topSignals.filter((s) => s.type === 'IP_VELOCITY');
    expect(sig.length).toBe(1);
    expect(sig[0].value).toBe(2);
    expect(sig[0].contribution).toBe(expected);
  });

  test('IP penalty at the 35 cap (multiplier 2.0) lands below the risk floor: score 65', async () => {
    const r = await runLearned(ipOrder, ipHist, [], { 'IP_VELOCITY:HIGH': 40 });
    expect(r.score).toBe(65);
  });

  test.each([
    [10, 0.5, -12],
    [20, 1.0, -24],
    [40, 2.0, -30],
  ])('EMAIL_VELOCITY:HIGH weight %i (multiplier %f) gives contribution %i', async (w, _m, expected) => {
    const r = await runLearned(emOrder, emHist, emDisp, { 'EMAIL_VELOCITY:HIGH': w });
    const sig = r.topSignals.filter((s) => s.type === 'EMAIL_VELOCITY');
    expect(sig.length).toBe(1);
    expect(sig[0].value).toBe(3);
    expect(sig[0].contribution).toBe(expected);
  });
});