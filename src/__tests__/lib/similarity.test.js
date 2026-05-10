const {
  normalizeEmail,
  areEmailsSimilar,
  addressSimilarity,
  areAddressesSimilar,
  areSameSubnet
} = require('../../lib/similarity');

describe('similarity.js', () => {
  describe('normalizeEmail', () => {
    test('handles Gmail dots and plus', () => {
      expect(normalizeEmail('john.doe+spam@gmail.com')).toBe('johndoe@gmail.com');
      expect(normalizeEmail('john.doe@googlemail.com')).toBe('johndoe@gmail.com');
      expect(normalizeEmail('JOHN.DOE@GMAIL.COM')).toBe('johndoe@gmail.com');
    });
    test('handles non-Gmail addresses', () => {
      expect(normalizeEmail('user@example.com')).toBe('user@example.com');
      expect(normalizeEmail('user+filter@example.com')).toBe('user@example.com');
    });
    test('returns empty string for invalid input', () => {
      expect(normalizeEmail(null)).toBe('');
      expect(normalizeEmail('')).toBe('');
    });
  });

  describe('areEmailsSimilar', () => {
    test('detects similar emails', () => {
      expect(areEmailsSimilar('ahmed@gmail.com', 'ahm3d@gmail.com')).toBe(true);
      expect(areEmailsSimilar('john.doe@gmail.com', 'john.doe1@gmail.com')).toBe(true);
      expect(areEmailsSimilar('test@example.com', 'test1@example.com')).toBe(true);
    });
    test('returns false for different domains', () => {
      expect(areEmailsSimilar('test@example.com', 'test@test.com')).toBe(false);
    });
  });

  describe('addressSimilarity', () => {
    test('calculates Jaccard similarity', () => {
      const sim = addressSimilarity('123 Main St Cairo', '123 Main Street Cairo');
      expect(sim).toBeGreaterThan(0.7);
    });
    test('returns 0 for empty addresses', () => {
      expect(addressSimilarity('', 'something')).toBe(0);
    });
  });

  describe('areAddressesSimilar', () => {
    test('returns true for similar addresses', () => {
      expect(areAddressesSimilar('123 Main St', '123 Main Street')).toBe(true);
    });
  });

  describe('areSameSubnet', () => {
    test('detects same /24 subnet', () => {
 expect(areSameSubnet('8.8.8.8', '8.8.8.9')).toBe(true);
expect(areSameSubnet('1.2.3.4', '1.2.3.5')).toBe(true);
    });
    test('returns false for different subnets', () => {
      expect(areSameSubnet('192.168.1.1', '192.168.2.1')).toBe(false);
    });
    test('ignores private IPs', () => {
      expect(areSameSubnet('10.0.0.1', '10.0.0.2')).toBe(false); // private, should be ignored
    });
  });
});
