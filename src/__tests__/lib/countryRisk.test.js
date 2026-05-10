const {
  getCountryRiskTier,
  calculateCountryRiskPenalty
} = require('../../lib/countryRisk');

describe('countryRisk.js', () => {
  describe('getCountryRiskTier', () => {
    test('returns correct tier for critical countries', () => {
      expect(getCountryRiskTier('NG')).toMatchObject({ tier: 'critical', basePenalty: 15 });
      expect(getCountryRiskTier('CM')).toMatchObject({ tier: 'critical', basePenalty: 15 });
    });
    test('returns correct tier for high risk countries', () => {
      expect(getCountryRiskTier('PK')).toMatchObject({ tier: 'high', basePenalty: 10 });
    });
    test('returns null for safe countries', () => {
      expect(getCountryRiskTier('US')).toBeNull();
      expect(getCountryRiskTier('DE')).toBeNull();
    });
  });

  describe('calculateCountryRiskPenalty', () => {
    test('applies penalty for critical country', () => {
      const result = calculateCountryRiskPenalty('NG', 150);
      expect(result.penalty).toBe(15);
      expect(result.flag.severity).toBe('high');
    });
    test('scales penalty based on amount', () => {
      expect(calculateCountryRiskPenalty('NG', 50).penalty).toBe(7); // half of 15
    });
    test('merchant override allow suppresses penalty', () => {
      const merchantConfig = { countryOverrides: { NG: 'allow' } };
      expect(calculateCountryRiskPenalty('NG', 150, merchantConfig)).toBeNull();
    });
    test('merchant override escalate doubles penalty', () => {
      const merchantConfig = { countryOverrides: { NG: 'escalate' } };
      const result = calculateCountryRiskPenalty('NG', 150, merchantConfig);
      expect(result.penalty).toBe(20); // 15 * 2, capped at 20? Actually min(30,20) = 20. Let's check code.
      // Note: In countryRisk.js, escalate caps at 20. So we expect 20.
      expect(result.penalty).toBe(20);
    });
  });
});
