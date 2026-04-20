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