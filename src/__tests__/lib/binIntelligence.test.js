const { normalizeBin } = require('../../lib/binIntelligence');

describe('normalizeBin', () => {
  test('returns first 6-8 digits from valid BIN', () => {
    expect(normalizeBin('4242424242424242')).toBe('42424242');
    expect(normalizeBin('123456')).toBe('123456');
    expect(normalizeBin('12345678')).toBe('12345678');
  });

  test('returns null for strings with less than 6 digits after cleaning', () => {
    expect(normalizeBin('abcd1234')).toBe(null); // '1234' is only 4 digits
    expect(normalizeBin('12-34-56')).toBe('123456'); // 6 digits
  });

  test('returns null for invalid BIN (less than 6 digits)', () => {
    expect(normalizeBin('12345')).toBe(null);
    expect(normalizeBin('')).toBe(null);
    expect(normalizeBin(null)).toBe(null);
  });
});
const { getBINIntelligence, extractBIN } = require('../../lib/binIntelligence');

// Mock logger
jest.mock('../../lib/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

describe('extractBIN', () => {
  test('extracts BIN from WooCommerce card_bin field', () => {
    const order = { payment_details: { card_bin: '424242' } };
    expect(extractBIN(order)).toBe('424242');
  });

  test('falls back to credit_card_bin', () => {
    const order = { payment_details: { credit_card_bin: '550000' } };
    expect(extractBIN(order)).toBe('550000');
  });

  test('returns null if no payment_details', () => {
    const order = {};
    expect(extractBIN(order)).toBeNull();
  });
});

describe('getBINIntelligence - API failure scenarios', () => {
  beforeEach(() => {
    jest.resetModules();
    delete process.env.NEUTRINO_API_KEY;
    process.env.ENABLE_BIN_INTEL = 'true';
    process.env.BIN_FALLBACK_API = 'free';
  });

  test('returns skipped when BIN is empty or invalid', async () => {
    const result = await getBINIntelligence('', 'merchant1');
    expect(result.source).toBe('skipped');
  });

  test('returns skipped when binlist.net fails (simulate network error)', async () => {
    const result = await getBINIntelligence('000000', 'merchant1');
    expect(result.source).toBe('skipped');
  }, 10000);

  test('returns skipped when global rate limit is reached', async () => {
    jest.mock('../../lib/metrics', () => ({
      recordBIN: jest.fn(),
      checkBINLimit: jest.fn().mockReturnValue(true),
      binlistGlobalBucket: { consume: jest.fn().mockReturnValue(false), get available() { return 0; } },
    }));
    // إعادة استيراد الوحدة لتطبيق الـ mock الجديد
    const { getBINIntelligence } = require('../../lib/binIntelligence');
    const result = await getBINIntelligence('424242', 'merchant1');
    expect(result.source).toBe('skipped');
  });
});