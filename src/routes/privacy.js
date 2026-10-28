'use strict';
// ─────────────────────────────────────────────────────────────────────────────
// GDPR Article 17 — Right to Erasure
// Route:   DELETE /api/privacy/erase
// Caller:  class-privacy.php :: send_backend_erasure_request()
// Auth:    X-Api-Key header (same key as all other plugin calls)
// Body:    { "email": "customer@example.com" }
// Returns: 200 { success, ordersUpdated, challengesDeleted }
//          400 { error: "email is required" }
//          401 / 403 / 429 / 500
// ─────────────────────────────────────────────────────────────────────────────

const express = require('express');
const router  = express.Router();
const db      = require('../lib/db');
const logger  = require('../lib/logger');
const { requireAuth } = require('../middleware/authenticate');
const { normalizeEmail } = require('../lib/utils');

// ── Rate limiter: 5 req / hour per API key ────────────────────────────────
// GDPR erasure requests are rare; a low cap prevents automated bulk abuse
// while covering every legitimate workflow.
const PRIV_RATE = new Map();
const MAX_REQ   = 5;
const WINDOW_MS = 60 * 60 * 1000; // 1 hour

const rateLimit = (req, res, next) => {
  const key = req.headers['x-api-key'] || req.ip || 'unknown';
  const now  = Date.now();
  const rec  = PRIV_RATE.get(key);
  if (rec) {
    if (now - rec.firstAt > WINDOW_MS) {
      PRIV_RATE.delete(key);
    } else if (rec.count >= MAX_REQ) {
      return res.status(429).json({ error: 'Too Many Requests' });
    } else {
      rec.count++;
    }
  } else {
    PRIV_RATE.set(key, { count: 1, firstAt: now });
  }
  next();
};

// ── Auth — grace-period key rejected; erasure must use current key only ───
const apiKeyAuth = requireAuth(
  { id: true, isActive: true, emailVerified: true },
  { allowPreviousKey: false }
);

// ── Email normalisation (kept in sync with risk.js / auth.js) ─────────────
// Imported from lib/utils: the SAME function risk.js uses when it writes
// Order.normalizedEmail, so the lookup key always matches the stored key
// (NFKC, homoglyphs, domain aliases, +tag, gmail dots).

// ── DELETE /api/privacy/erase ─────────────────────────────────────────────
router.delete('/erase', rateLimit, apiKeyAuth, async (req, res) => {
  const tenantId = req.tenant.id;
  const rawEmail = typeof req.body?.email === 'string'
    ? req.body.email.trim()
    : '';

  if (!rawEmail || !rawEmail.includes('@')) {
    return res.status(400).json({ error: 'email is required' });
  }

  // The shared normaliser is stricter than the old local one. Never let a
  // throw or an empty result reach the query: an empty key could match
  // unrelated rows, so reject instead.
  let normEmail = '';
  try {
    normEmail = normalizeEmail(rawEmail);
  } catch (_) {
    normEmail = '';
  }
  if (typeof normEmail !== 'string' || normEmail === '') {
    return res.status(400).json({ error: 'a valid email is required' });
  }

  try {
    // 1. Null PII on every Order row for this tenant + customer.
    //    The Order row itself is retained — order history is a legitimate
    //    business record under GDPR Article 17(3)(b). Only the personal
    //    identifiers are cleared.
    const orderUpdate = await db.order.updateMany({
      where: {
        merchantId: tenantId,
        OR: [
          { normalizedEmail: normEmail },
          { email: { equals: rawEmail, mode: 'insensitive' } },
        ],
      },
      data: {
        email:              null,
        normalizedEmail:    null,
        ipAddress:          null,
        customerLoginId:    null,
        deviceFingerprint:  null,
        fingerprintVersion: null,
        fingerprintStatus:  null,
      },
    });

    // 2. Delete ChallengeVerification rows.
    //    Stored exactly as the shopper typed it at checkout (no trim or
    //    lowercase), so match case-insensitively. Scoped to this tenant only.
    const challengeDelete = await db.challengeVerification.deleteMany({
      where: {
        merchantId: tenantId,
        email: { equals: rawEmail, mode: 'insensitive' },
      },
    });

    logger.info(
      {
        module:            'privacy',
        tenantId,
        ordersUpdated:     orderUpdate.count,
        challengesDeleted: challengeDelete.count,
      },
      'GDPR erasure completed'
    );

    return res.status(200).json({
      success:           true,
      ordersUpdated:     orderUpdate.count,
      challengesDeleted: challengeDelete.count,
    });

  } catch (err) {
    logger.error(
      { module: 'privacy', tenantId, error: err.message },
      'GDPR erasure failed'
    );
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;