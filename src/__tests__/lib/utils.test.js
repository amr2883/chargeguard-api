const { normalizeEmail } = require('../../lib/utils');

describe('normalizeEmail', () => {
  test('normalizes Gmail addresses (dots and plus)', () => {
    expect(normalizeEmail('john.doe+spam@gmail.com')).toBe('johndoe@gmail.com');
    expect(normalizeEmail('john.doe@googlemail.com')).toBe('johndoe@gmail.com');
    expect(normalizeEmail('john.doe@GMAIL.COM')).toBe('johndoe@gmail.com');
  });

  test('handles non-Gmail addresses without modification', () => {
    expect(normalizeEmail('user@example.com')).toBe('user@example.com');
    expect(normalizeEmail('user+filter@example.com')).toBe('user@example.com');
  });

  test('returns empty string for invalid input', () => {
    expect(normalizeEmail(null)).toBe('');
    expect(normalizeEmail('')).toBe('');
    expect(normalizeEmail('notanemail')).toBe('notanemail');
  });
});
