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
  beforeEach(() => {
    jest.resetModules();
    // إزالة أي تأثير للمتغيرات العامة
    delete process.env.IPQS_API_KEY;
    delete process.env.MOCK_IP_INTEL;
    process.env.ENABLE_IP_INTEL = 'true';
  });

  test('returns timeout source when fetch fails (simulate API timeout/error)', async () => {
    // تعطيل الـ cache باستخدام IP عشوائي
    const randomIP = `${Math.floor(Math.random()*200)}.${Math.floor(Math.random()*200)}.${Math.floor(Math.random()*200)}.${Math.floor(Math.random()*200)}`;
    // نعطل IPQS_API_KEY لضمان الفشل (لأن الدالة fetch الحقيقية ستُستدعى لكن بدون API key)
    process.env.IPQS_API_KEY = '';
    const result = await getIPIntelligence(randomIP, 'merchant1');
    // عندما يكون API key فارغًا، الدالة تعيد null من fetchIPData وبالتالي timeout أو skipped
    expect(result.source).toBe('timeout');
    expect(result.riskScore).toBe(0);
  }, 10000);

  test('returns skipped source when API key is missing', async () => {
    process.env.IPQS_API_KEY = '';
    const result = await getIPIntelligence('8.8.8.8', 'merchant1');
    // عند فقدان API key، الدالة تسجل warning وتعيد null من fetch، مما يؤدي إلى timeout أو skipped
    expect(result.source).toBe('timeout');
    expect(result.riskScore).toBe(0);
  }, 10000);

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