const { calculateBINPenalty } = require('../../lib/binIntelligence');

describe('calculateBINPenalty', () => {
  // Helper to create order object
  const createOrder = (amount, billingCountry) => ({
    amount,
    billingAddress: billingCountry ? JSON.stringify({ country: billingCountry }) : null
  });

  test('prepaid card + new customer + high amount gives high penalty', () => {
    const binIntel = {
      source: 'api',
      isPrepaid: true,
      brand: 'VISA',
      issuerCountry: 'US'
    };
    const order = createOrder(200, 'US');
    const isNewCustomer = true;
    const result = calculateBINPenalty(binIntel, order, isNewCustomer, null, null);
    
    expect(result.penalty).toBeGreaterThan(25); // العقوبة الفعلية 28
    expect(result.flags).toHaveLength(2);
    expect(result.flags[0].severity).toBe('medium');
    expect(result.flags[1].severity).toBe('critical');
  });

  test('prepaid card + returning customer + moderate amount gives medium penalty', () => {
    const binIntel = { source: 'api', isPrepaid: true, brand: 'VISA', issuerCountry: 'US' };
    const order = createOrder(100, 'US');
    const isNewCustomer = false;
    const result = calculateBINPenalty(binIntel, order, isNewCustomer, null, null);
    
    expect(result.penalty).toBeGreaterThan(0);
    expect(result.penalty).toBeLessThanOrEqual(20);
    expect(result.flags[0].severity).toBe('medium');
  });

  test('country mismatch penalty', () => {
    const binIntel = { source: 'api', isPrepaid: false, issuerCountry: 'NG' };
    const order = createOrder(150, 'US');
    const result = calculateBINPenalty(binIntel, order, false, null, null);
    
    expect(result.penalty).toBeGreaterThan(0);
    expect(result.flags.some(f => f.text.includes('Card issued in NG, billing in US'))).toBe(true);
  });

  test('triple mismatch (card + IP + billing) gives extra penalty', () => {
    const binIntel = { source: 'api', isPrepaid: false, issuerCountry: 'NG' };
    const order = createOrder(100, 'US');
    const ipIntel = { country: 'FR' };
    const result = calculateBINPenalty(binIntel, order, false, ipIntel, null);
    
    expect(result.penalty).toBeGreaterThan(0);
    expect(result.flags.some(f => f.text.includes('Geographic triple mismatch'))).toBe(true);
  });

  test('skipped source returns zero penalty', () => {
    const binIntel = { source: 'skipped' };
    const result = calculateBINPenalty(binIntel, createOrder(100, 'US'), false, null, null);
    expect(result.penalty).toBe(0);
    expect(result.flags).toEqual([]);
  });
});
