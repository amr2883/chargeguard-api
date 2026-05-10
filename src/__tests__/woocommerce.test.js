const {
  extractOrderData,
  verifyWebhookSignature,
  buildRiskEvaluationRequest,
} = require('../lib/woocommerce');
const payload = require('./fixtures/woocommerce-order-created.json');

describe('woocommerce webhook helpers', () => {
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
      const payloadWithout = { ...payload, payment_details: null };
      const extracted = extractOrderData(payloadWithout);
      expect(extracted.bin).toBeNull();
    });

    test('handles missing optional fields', () => {
      const minimalPayload = { id: 1, total: '10', billing: { email: 'a@b.com' } };
      const extracted = extractOrderData(minimalPayload);
      expect(extracted.orderId).toBe('1');
      expect(extracted.email).toBe('a@b.com');
      expect(extracted.ipAddress).toBeNull();
    });
  });

  describe('verifyWebhookSignature', () => {
    const secret = 'my_webhook_secret';
    const rawBody = '{"id":123}';
    // Generate a valid signature using same algorithm
    const crypto = require('crypto');
    const validSignature = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');

    test('returns true for valid signature', () => {
      expect(verifyWebhookSignature(rawBody, validSignature, secret)).toBe(true);
    });

    test('returns false for invalid signature', () => {
      expect(verifyWebhookSignature(rawBody, 'invalid', secret)).toBe(false);
    });

    test('returns false when missing parameters', () => {
      expect(verifyWebhookSignature(null, validSignature, secret)).toBe(false);
      expect(verifyWebhookSignature(rawBody, null, secret)).toBe(false);
      expect(verifyWebhookSignature(rawBody, validSignature, null)).toBe(false);
    });
  });

  describe('buildRiskEvaluationRequest', () => {
    const extracted = {
      orderId: '123',
      email: 'test@example.com',
      ipAddress: '1.2.3.4',
      bin: '424242',
      amount: 99.99,
      billingCountry: 'US',
      shippingCountry: 'US',
      customerLoginId: 456,
      createdAt: '2025-01-01T00:00:00Z',
    };
    const result = buildRiskEvaluationRequest(extracted);

    test('maps fields correctly', () => {
      expect(result.orderId).toBe('123');
      expect(result.email).toBe('test@example.com');
      expect(result.ipAddress).toBe('1.2.3.4');
      expect(result.bin).toBe('424242');
      expect(result.amount).toBe(99.99);
      expect(result.billingCountry).toBe('US');
      expect(result.shippingCountry).toBe('US');
      expect(result.customerLoginId).toBe(456);
      expect(result.createdAt).toBe('2025-01-01T00:00:00Z');
    });

    test('sets deviceFingerprint to null', () => {
      expect(result.deviceFingerprint).toBeNull();
    });

    test('merchantId is null (to be filled by route)', () => {
      expect(result.merchantId).toBeNull();
    });
  });
});
