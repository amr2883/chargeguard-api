// ─── Quota-Increment Dedup ──────────────────────────────────────────────
// Prevents a single repeatedly-blocked entity (same device fingerprint,
// IP, or email hitting the same cheap hard gate over and over) from
// burning a tenant's entire monthlyBlockedCount quota in minutes, which
// degrades their protection (limitedScoring: true) for the rest of the
// month even against unrelated, novel attackers.
//
// This does NOT suppress BlockedAttempt row creation or the 403 decision
// itself — every blocked request is still logged for the dashboard and
// still rejected. It only gates whether THIS block ALSO increments
// monthlyBlockedCount, the counter that gates access to expensive
// external IP/email/BIN intelligence (see quotaGate.js).
//
// In-memory, same pattern already used in this codebase for
// globalRotationDetector.js and velocityDetector.js's DB-error fallback
// store — no schema migration, no extra DB round trip on the block path.
// Approximate by design: under a race (two concurrent requests for the
// same entity both pass the check simultaneously) both may increment —
// that fails toward the PRE-FIX behavior (occasional over-count), never
// toward under-counting a genuinely novel attacker's blocks, which is the
// property that actually matters here.

const crypto = require('crypto');

const DEDUP_WINDOW_MS = 60 * 60 * 1000; // 1 hour — after this, a still-active
// repeat offender counts toward quota once more, so sustained attacks
// remain visible in aggregate usage rather than being suppressed forever.

const seen = new Map(); // `${merchantId}:${reason}:${entityHash}` -> expiryTimestamp

const SWEEP_INTERVAL_MS = 15 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [key, expiry] of seen.entries()) {
    if (expiry <= now) seen.delete(key);
  }
}, SWEEP_INTERVAL_MS).unref();

/**
 * @param {string} merchantId
 * @param {string} reason - same `reason` string passed to recordBlockedAttempt
 * @param {string|null|undefined} entityValue - the raw device fingerprint,
 *   IP address, email, or BIN this specific gate actually matched on. Pass
 *   null/undefined if this gate has no stable entity to key on — in that
 *   case this always returns true (fails toward counting, i.e. today's
 *   behavior), rather than silently never counting these blocks.
 * @returns {boolean} true if this block should increment monthlyBlockedCount
 */
function shouldIncrementQuota(merchantId, reason, entityValue) {
  if (!merchantId || !entityValue) {
    return true;
  }

  const entityHash = crypto.createHash('sha256').update(String(entityValue)).digest('hex');
  const key = `${merchantId}:${reason}:${entityHash}`;
  const now = Date.now();
  const expiry = seen.get(key);

  if (expiry && expiry > now) {
    return false; // already counted this (merchant, reason, entity) within the window
  }

  seen.set(key, now + DEDUP_WINDOW_MS);
  return true;
}

module.exports = { shouldIncrementQuota, DEDUP_WINDOW_MS };