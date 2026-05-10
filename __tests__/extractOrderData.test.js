const { extractOrderData } = require('../src/lib/woocommerce');
const payload = require('./fixtures/woocommerce-order-created.json');

describe('extractOrderData', () => {
  test('extracts all required fields correctly', () => {
    const extracted = extractOrderData(payload);

    expect(extracted).toEqual({
      orderId: '12345',
      email: 'ahmed@example.com',
      ipAddress: '192.168.1.100',
      bin: '424242',
      amount: 149.99,
      billingCountry: 'EG',
      shippingCountry: 'EG',
      customerLoginId: 6789,
      createdAt: '2025-04-22T10:30:00',
    });
  });

  test('handles missing payment_details gracefully', () => {
    const payloadWithoutPayment = { ...payload, payment_details: null };
    const extracted = extractOrderData(payloadWithoutPayment);
    expect(extracted.bin).toBeNull();
  });
});
