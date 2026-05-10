// src/lib/woocommerce.js
const crypto = require('crypto');

/**
 * Extracts required fields from WooCommerce webhook payload.
 * @param {Object} payload - Parsed JSON payload.
 * @returns {Object} Normalized order data.
 */
function extractOrderData(payload) {
  if (!payload) throw new Error('Payload is required');

  return {
    orderId: String(payload.id),
    email: payload.billing?.email || null,
    ipAddress: payload.customer_ip_address || null,
    bin: payload.payment_details?.card_bin || null,
    amount: parseFloat(payload.total || 0),
    billingCountry: payload.billing?.country || null,
    shippingCountry: payload.shipping?.country || null,
    customerLoginId: payload.customer_id || null,
    createdAt: payload.date_created || null,
  };
}

/**
 * Verifies WooCommerce webhook signature using HMAC-SHA256.
 * @param {Buffer|string} rawBody - The raw request body (as received).
 * @param {string} signatureHeader - Value of X-WC-Webhook-Signature header.
 * @param {string} secret - The webhook secret configured in WooCommerce.
 * @returns {boolean} True if signature is valid.
 */
function verifyWebhookSignature(rawBody, signatureHeader, secret) {
  if (!rawBody || !signatureHeader || !secret) return false;
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
  console.log("Expected signature:", expected);
  console.log("Received signature:", signatureHeader);
  // Constant-time comparison only if lengths match
  if (expected.length !== signatureHeader.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signatureHeader));
}

/**
 * Builds the request object expected by calculateRiskScore.
 * @param {Object} extracted - Output from extractOrderData.
 * @returns {Object} Request compatible with /evaluate endpoint.
 */
function buildRiskEvaluationRequest(extracted) {
  return {
    orderId: extracted.orderId,
    email: extracted.email,
    ipAddress: extracted.ipAddress,
    bin: extracted.bin,
    amount: extracted.amount,
    billingCountry: extracted.billingCountry,
    shippingCountry: extracted.shippingCountry,
    customerLoginId: extracted.customerLoginId,
    createdAt: extracted.createdAt,
    deviceFingerprint: null, // WooCommerce does not provide this; will be ignored
    merchantId: null, // To be set by the route handler
  };
}

module.exports = {
  extractOrderData,
  verifyWebhookSignature,
  buildRiskEvaluationRequest,
};
