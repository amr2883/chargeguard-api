'use strict';

const crypto = require('crypto');

/**
 * HMAC-SHA256(apiKey, API_KEY_HASH_SECRET).
 * Reuses the same pattern as the existing CARD_HASH_SECRET mechanism in risk.js.
 * Pepper lives only in env vars — never in the database — so a DB-only
 * compromise is insufficient to compute valid lookup hashes (OWASP ASVS V6.2.1
 * defense-in-depth; NIST SP 800-63B §5.1.3 look-up secret storage).
 */
function hashApiKey(rawKey) {
  const secret = process.env.API_KEY_HASH_SECRET;
  if (!secret) {
    // Fail closed — never silently hash without a pepper.
    throw new Error('API_KEY_HASH_SECRET is not configured');
  }
  return crypto.createHmac('sha256', secret).update(String(rawKey)).digest('hex');
}

module.exports = { hashApiKey };