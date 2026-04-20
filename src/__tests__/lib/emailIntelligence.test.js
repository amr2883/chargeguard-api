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
});
