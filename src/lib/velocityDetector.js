// src/lib/velocityDetector.js
// طبقة كشف سرعة محاولات الدفع — persistent via CardTestAttempt (Prisma)

const crypto = require('crypto');
const db     = require('./db');
const logger = require('./logger');

const FAILURE_WINDOW_MS = 10 * 60 * 1000; // 10 دقائق
const BLOCK_DURATION_MS = 60 * 60 * 1000; // 1 ساعة

const THRESHOLDS = {
  IP:     5,
  DEVICE: 5,
};

// GDPR-safe hashing — نفس نمط risk.js
const hashValue = (val) => {
  const salt = process.env.SECRET_SALT || 'default_salt_change_me';
  return crypto.createHmac('sha256', salt).update(String(val)).digest('hex');
};

/**
 * تسجيل محاولة فاشلة في CardTestAttempt
 * @param {object} params - { ip, deviceFingerprint, merchantId, amount }
 */
async function recordFailedAttempt({ ip, deviceFingerprint, merchantId = 'unknown', amount = 0 }) {
  try {
    await db.cardTestAttempt.create({
      data: {
        merchantId,
        ipHash:     ip               ? hashValue(ip)               : null,
        deviceHash: deviceFingerprint ? hashValue(deviceFingerprint) : null,
        amount,
        wasBlocked: true,
      },
    });
  } catch (err) {
    logger.error({ module: 'velocityDetector', err }, 'recordFailedAttempt failed');
  }
}

/**
 * التحقق مما إذا كان IP أو جهاز معين يتجاوز عتبة السرعة
 * @param {object} params - { ip, deviceFingerprint, merchantId }
 * @returns {Promise<{blocked: boolean, reason: string|null}>}
 */
async function checkVelocity({ ip, deviceFingerprint, merchantId = 'unknown' }) {
  const since = new Date(Date.now() - FAILURE_WINDOW_MS);

  try {
    if (ip) {
      const ipHash  = hashValue(ip);
      const ipCount = await db.cardTestAttempt.count({
        where: { ipHash, createdAt: { gte: since } },
      });
      if (ipCount >= THRESHOLDS.IP) {
        return {
          blocked: true,
          reason:  `IP temporarily blocked due to high failure rate (${ipCount} attempts in 10 min)`,
        };
      }
    }

    if (deviceFingerprint) {
      const deviceHash  = hashValue(deviceFingerprint);
      const deviceCount = await db.cardTestAttempt.count({
        where: { deviceHash, createdAt: { gte: since } },
      });
      if (deviceCount >= THRESHOLDS.DEVICE) {
        return {
          blocked: true,
          reason:  `Device temporarily blocked due to high failure rate (${deviceCount} attempts in 10 min)`,
        };
      }
    }
  } catch (err) {
    logger.error({ module: 'velocityDetector', err }, 'checkVelocity DB error — failing open');
    // Fail open: لو الـ DB فشل، نكمل ولا نوقف الطلب
    return { blocked: false, reason: null };
  }

  return { blocked: false, reason: null };
}

module.exports = { recordFailedAttempt, checkVelocity };