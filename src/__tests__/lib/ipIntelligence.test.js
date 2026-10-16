const { getIPIntelligence, calculateIPPenalty, normalizeIP } = require('../../lib/ipIntelligence');

// Mock logger لتجنب رسائل console في الاختبارات
jest.mock('../../lib/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

// جعل المتغير البيئي IP_INTEL_ENABLED = true (الافتراضي)
process.env.ENABLE_IP_INTEL = 'true';

describe('getIPIntelligence - API failure handling', () => {
  let originalFetch;

  afterEach(() => {
    global.fetch = originalFetch;
  });

  beforeEach(() => {
    jest.resetModules();
    originalFetch = global.fetch;
    global.fetch = jest.fn().mockRejectedValue(new Error('unexpected network call in test'));
    // إزالة أي تأثير للمتغيرات العامة
    delete process.env.IPLOCATE_API_KEY;
    delete process.env.MOCK_IP_INTEL;
    process.env.ENABLE_IP_INTEL = 'true';
  });

  test('returns timeout source when API key is missing (degraded mode)', async () => {
    const fixedIP = '1.1.1.1';
    const result = await getIPIntelligence(fixedIP, 'merchant1');
    expect(result.source).toBe('timeout');
    expect(result.riskScore).toBe(0);
  }, 10000);

  test('returns timeout source for a public IP when API key is missing', async () => {
    const result = await getIPIntelligence('8.8.8.8', 'merchant1');
    expect(result.source).toBe('timeout');
    expect(result.riskScore).toBe(0);
  }, 10000);

  test('does not call fetch when API key is missing', async () => {
    const result = await getIPIntelligence('9.9.9.9', 'merchant1');
    expect(global.fetch).not.toHaveBeenCalled();
    expect(result.source).toBe('timeout');
    expect(result.riskScore).toBe(0);
  }, 10000);

  test.each(['127.127.127.127', '10.1.2.3', '172.20.1.1', '192.168.5.5'])(
    'returns skipped without a network call for reserved IP %s',
    async (ip) => {
      const result = await getIPIntelligence(ip, 'merchant1');
      expect(result.source).toBe('skipped');
      expect(result.riskScore).toBe(0);
      expect(global.fetch).not.toHaveBeenCalled();
    },
    10000
  );

  test('skipped IP never penalizes', () => {
    const skippedIP = { source: 'skipped', riskScore: 0 };
    const penalty = calculateIPPenalty(skippedIP, 100, 'US');
    expect(penalty.penalty).toBe(0);
    expect(penalty.flags).toEqual([]);
  });

  test('timeout IP never penalizes', () => {
    const timeoutIP = { source: 'timeout', riskScore: 0 };
    const penalty = calculateIPPenalty(timeoutIP, 100, 'US');
    expect(penalty.penalty).toBe(0);
    expect(penalty.flags).toEqual([]);
  });
});

describe('normalizeIP', () => {
  test('handles IPv4 with port', () => {
    expect(normalizeIP('192.168.1.1:443')).toBe('192.168.1.1');
  });
  test('handles IPv6 brackets', () => {
    expect(normalizeIP('[::1]:8080')).toBe('::1');
  });
  test('handles null', () => {
    expect(normalizeIP(null)).toBe(null);
  });
});
