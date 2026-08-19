// src/lib/velocityDetector.js
// ╪╖╪ذ┘é╪ر ┘â╪┤┘ ╪│╪▒╪╣╪ر ┘à╪ص╪د┘ê┘╪د╪ز ╪د┘╪»┘╪╣ ظ¤ persistent via CardTestAttempt (Prisma)

const crypto = require('crypto');
const db     = require('./db');
const logger = require('./logger');

const FAILURE_WINDOW_MS = 10 * 60 * 1000; // 10 ╪»┘é╪د╪خ┘é
const BLOCK_DURATION_MS = 60 * 60 * 1000; // 1 ╪│╪د╪╣╪ر

const THRESHOLDS = {
  IP:     5,
  DEVICE: 5,
};

// Softer threshold for requests flagged for manual review (decision ===
// 'review') rather than hard-blocked (decision === 'block'). A single
// review-worthy request is weak evidence on its own (e.g. a borderline
// risk-floor cap on a clean customer) and must not count 1-for-1
// alongside a confirmed block. Requires more repetitions from the same
// IP/device before escalating to a hard velocity block. Starting value
// (12) is a reasoned default, not a measured constant — revisit once
// real merchant traffic data is available.
const REVIEW_THRESHOLDS = {
  IP:     12,
  DEVICE: 12,
};

// ظ¤ظ¤ظ¤ DB-Error Fallback Store ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤ظ¤
// Used ONLY when the authoritative CardTestAttempt count query below
// throws (transient DB blip, Prisma timeout, schema mismatch, etc.).
// Mirrors two existing patterns in this codebase rather than inventing a
// third: binSequenceDetector.js's Redis-with-in-memory-fallback design,
// and the WooCommerce plugin's "hard per-IP rate limit that only
// activates while the authoritative API is unreachable" fallback
// (class-dynamic-firewall.php resolve_api_unavailable_decision()).
//
// Without this, a DB error on this one table silently asserted "this
// request is clean" (blocked: false) ظ¤ a positive claim, not a neutral
// one ظ¤ which is a stronger and more dangerous failure mode than simply
// having no opinion. This fallback ensures a DB error degrades detection
// rather than disabling it.
//
// KNOWN LIMITATION (accepted, same tradeoff as binSequenceDetector.js's
// in-memory fallback): this store is per-process, not shared across
// instances. Under horizontal scaling, an attacker could in principle
// split traffic across instances to stay under each instance's local
// threshold ظ¤ but only during an actual DB outage affecting this table,
// which is itself a narrow and transient window, not the steady-state
// detection posture. A future improvement, if this ever needs
// hardening further, is to reuse binSequenceDetector.js's existing Redis
// client (when REDIS_URL is configured) for this fallback store too,
// rather than introducing a second, unrelated in-memory Map.
const DB_ERROR_FALLBACK_WINDOW_MS = FAILURE_WINDOW_MS; // same 10-minute window as the authoritative check
const DB_ERROR_FALLBACK_THRESHOLDS = {
  IP:     THRESHOLDS.IP,
  DEVICE: THRESHOLDS.DEVICE,
};
const dbErrorFallbackStore = new Map(); // key ('ip:<hash>' | 'device:<hash>') -> timestamp[]

function dbErrorFallbackRecordAndCheck(key, threshold, now) {
  const fresh = (dbErrorFallbackStore.get(key) || []).filter(t => t > now - DB_ERROR_FALLBACK_WINDOW_MS);
  fresh.push(now);
  dbErrorFallbackStore.set(key, fresh);
  return fresh.length >= threshold;
}

// Periodic sweep so this Map never grows unbounded ظ¤ same cleanup
// pattern used by binSequenceDetector.js's memoryStore.
setInterval(() => {
  const now = Date.now();
  for (const [key, timestamps] of dbErrorFallbackStore.entries()) {
    const fresh = timestamps.filter(t => t > now - DB_ERROR_FALLBACK_WINDOW_MS);
    if (fresh.length === 0) dbErrorFallbackStore.delete(key);
    else dbErrorFallbackStore.set(key, fresh);
  }
}, 5 * 60 * 1000).unref();

// GDPR-safe hashing ظ¤ ┘┘╪│ ┘┘à╪╖ risk.js
const SECRET_SALT = process.env.SECRET_SALT;
if (!SECRET_SALT) {
  throw new Error('[velocityDetector] SECRET_SALT environment variable is required');
}

const hashValue = (val) => {
  return crypto.createHmac('sha256', SECRET_SALT).update(String(val)).digest('hex');
};

/**
 * ╪ز╪│╪ش┘è┘ ┘à╪ص╪د┘ê┘╪ر ┘╪د╪┤┘╪ر ┘┘è CardTestAttempt
 * @param {object} params - { ip, deviceFingerprint, merchantId, amount }
 */
async function recordFailedAttempt({ ip, deviceFingerprint, merchantId = 'unknown', storeId = null, amount = 0, wasBlocked = true }) {
  try {
    await db.cardTestAttempt.create({
      data: {
        merchantId,
        storeId,
        ipHash:     ip               ? hashValue(ip)               : null,
        deviceHash: deviceFingerprint ? hashValue(deviceFingerprint) : null,
        amount,
        wasBlocked,
      },
    });
  } catch (err) {
    logger.error({ module: 'velocityDetector', err }, 'recordFailedAttempt failed');
  }
}

/**
 * ╪د┘╪ز╪ص┘é┘é ┘à┘à╪د ╪ح╪░╪د ┘â╪د┘ IP ╪ث┘ê ╪ش┘ç╪د╪▓ ┘à╪╣┘è┘ ┘è╪ز╪ش╪د┘ê╪▓ ╪╣╪ز╪ذ╪ر ╪د┘╪│╪▒╪╣╪ر
 * @param {object} params - { ip, deviceFingerprint, merchantId }
 * @returns {Promise<{blocked: boolean, reason: string|null, dbError?: boolean}>}
 *   dbError is present and true only when the authoritative DB query
 *   failed and this result came from the in-memory fallback path
 *   instead ظ¤ see DB-Error Fallback Store above. Absent (undefined) on
 *   every normal, successfully-scored path, so existing callers that
 *   only read `.blocked` are unaffected.
 */
async function checkVelocity({ ip, deviceFingerprint, merchantId = 'unknown', storeId = null }) {
  const since = new Date(Date.now() - FAILURE_WINDOW_MS);
  const storeScope = storeId ? { storeId } : {};

  try {
    if (ip) {
      const ipHash = hashValue(ip);
      const ipGroups = await db.cardTestAttempt.groupBy({
        by: ['wasBlocked'],
        where: { merchantId: merchantId || 'unknown', ...storeScope, ipHash, createdAt: { gte: since } },
        _count: { _all: true },
      });
      const ipBlockedCount = ipGroups.find(g => g.wasBlocked === true)?._count._all || 0;
      const ipReviewCount  = ipGroups.find(g => g.wasBlocked === false)?._count._all || 0;

      if (ipBlockedCount >= THRESHOLDS.IP) {
        logger.info({ module: 'velocityDetector', ipBlockedCount }, 'velocity_ip_blocked');
        return {
          blocked: true,
          reason:  'velocity_ip_blocked',
        };
      }
      if (ipReviewCount >= REVIEW_THRESHOLDS.IP) {
        logger.info({ module: 'velocityDetector', ipReviewCount }, 'velocity_ip_review_accumulated');
        return {
          blocked: true,
          reason:  'velocity_ip_review_accumulated',
        };
      }
    }

    if (deviceFingerprint) {
      const deviceHash = hashValue(deviceFingerprint);
      const deviceGroups = await db.cardTestAttempt.groupBy({
        by: ['wasBlocked'],
        where: { merchantId: merchantId || 'unknown', ...storeScope, deviceHash, createdAt: { gte: since } },
        _count: { _all: true },
      });
      const deviceBlockedCount = deviceGroups.find(g => g.wasBlocked === true)?._count._all || 0;
      const deviceReviewCount  = deviceGroups.find(g => g.wasBlocked === false)?._count._all || 0;

      if (deviceBlockedCount >= THRESHOLDS.DEVICE) {
        logger.info({ module: 'velocityDetector', deviceBlockedCount }, 'velocity_device_blocked');
        return {
          blocked: true,
          reason:  'velocity_device_blocked',
        };
      }
      if (deviceReviewCount >= REVIEW_THRESHOLDS.DEVICE) {
        logger.info({ module: 'velocityDetector', deviceReviewCount }, 'velocity_device_review_accumulated');
        return {
          blocked: true,
          reason:  'velocity_device_review_accumulated',
        };
      }
    }
  } catch (err) {
    // Was previously: log and return { blocked: false, reason: null } ظ¤
    // structurally identical to a genuine pass, which meant a DB error
    // silently asserted "clean" rather than "unknown". This is the last
    // of the three independent fail-open paths (circuit breaker, quota
    // gate, and this one) in the pre-charge detection pipeline.
    //
    // Fixed by falling back to a cheap, always-available local check
    // instead of either extreme: not a blind approve (the old bug), and
    // not a full block-everything (which would take checkout down
    // store-wide on e.g. a narrow schema-mismatch bug affecting only
    // this table, per the DB errors this function can actually throw).
    logger.error(
      { module: 'velocityDetector', err, ip: ip ? 'present' : 'absent', deviceFingerprint: deviceFingerprint ? 'present' : 'absent' },
      'checkVelocity DB error ظ¤ using in-memory fallback rate limit instead of failing open'
    );

    try {
      if (typeof require('./prometheus').recordVelocityDbError === 'function') {
        require('./prometheus').recordVelocityDbError();
      }
    } catch (metricErr) {
      // Metrics must never affect the security decision below.
    }

    const now = Date.now();

    if (ip) {
      const key = 'ip:' + hashValue(ip);
      if (dbErrorFallbackRecordAndCheck(key, DB_ERROR_FALLBACK_THRESHOLDS.IP, now)) {
        return {
          blocked: true,
          reason:  'velocity_ip_blocked',
          dbError: true,
        };
      }
    }

    if (deviceFingerprint) {
      const key = 'device:' + hashValue(deviceFingerprint);
      if (dbErrorFallbackRecordAndCheck(key, DB_ERROR_FALLBACK_THRESHOLDS.DEVICE, now)) {
        return {
          blocked: true,
          reason:  'velocity_device_blocked',
          dbError: true,
        };
      }
    }

    return { blocked: false, reason: null, dbError: true };
  }

  return { blocked: false, reason: null };
}

module.exports = { recordFailedAttempt, checkVelocity };
