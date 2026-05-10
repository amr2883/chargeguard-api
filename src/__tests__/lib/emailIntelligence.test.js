const { calculateEmailPenalty } = require('../../lib/emailIntelligence');

describe('calculateEmailPenalty', () => {
  test('domain does not exist gives critical penalty', () => {
    const emailIntel = { source: 'api', domainExists: false, uncertain: false };
    const { penalty, flags } = calculateEmailPenalty(emailIntel, 100, false);
    expect(penalty).toBe(40);
    expect(flags[0].severity).toBe('critical');
    expect(flags[0].text).toContain('Email domain does not exist');
  });

  test('disposable email gives penalty if no domain penalty', () => {
    const emailIntel = { source: 'api', domainExists: true, hasMX: true, uncertain: false, isDisposable: true, domain: 'mailinator.com' };
    const { penalty, flags } = calculateEmailPenalty(emailIntel, 100, false);
    expect(penalty).toBe(35);
    expect(flags[0].severity).toBe('critical');
    expect(flags[0].text).toContain('Disposable email domain');
  });

  test('free provider + new customer + high value gives penalty', () => {
    const emailIntel = { source: 'api', domainExists: true, hasMX: true, uncertain: false, isFreeProvider: true, isDisposable: false };
    const { penalty, flags } = calculateEmailPenalty(emailIntel, 300, true);
    expect(penalty).toBe(10);
    expect(flags[0].severity).toBe('medium');
    expect(flags[0].text).toContain('Free email provider with high-value first order');
  });

  test('skipped source returns zero', () => {
    const emailIntel = { source: 'skipped' };
    const { penalty, flags } = calculateEmailPenalty(emailIntel, 100, false);
    expect(penalty).toBe(0);
    expect(flags).toEqual([]);
  });
    test('DNS timeout (uncertain) gives only small penalty', () => {
    // محاكاة نتيجة getEmailIntelligence عند فشل DNS
    const emailIntel = {
      source: 'api',
      domainExists: false,
      hasMX: false,
      uncertain: true,       // فشل الشبكة، وليس تأكيدًا على عدم وجود النطاق
      riskScore: 0.1,
      confidence: 0.2,
      isDisposable: false,
      isFreeProvider: false,
    };
    const { penalty, flags } = calculateEmailPenalty(emailIntel, 100, false);
    // يجب أن يكون العقوبة صغيرة لأنها حالة uncertain (network issue)
    expect(penalty).toBeLessThanOrEqual(5);
    // يجب أن يكون هناك flag يوضح أن المجال غير مؤكد
    expect(flags.some(f => f.text.includes('could not be verified'))).toBe(true);
  });
});
