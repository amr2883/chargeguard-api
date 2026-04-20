// src/lib/velocityDetector.js
// طبقة كشف سرعة محاولات الدفع لمنع هجمات اختبار البطاقات (Card Testing)

const velocityStore = new Map(); // key: `ip:${ip}` أو `device:${deviceFingerprint}`
const FAILURE_WINDOW_MS = 10 * 60 * 1000; // 10 دقائق
const BLOCK_DURATION_MS = 60 * 60 * 1000; // 1 ساعة

// عتبات الحظر
const THRESHOLDS = {
  IP: 5,     // 5 محاولات فاشلة من نفس IP في 10 دقائق
  DEVICE: 5  // 5 محاولات فاشلة من نفس الجهاز في 10 دقائق
};

// تنظيف دوري للمخزن (كل 5 دقائق)
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of velocityStore.entries()) {
    if (entry.blockedUntil && entry.blockedUntil < now) {
      velocityStore.delete(key);
    } else if (entry.timestamp < now - FAILURE_WINDOW_MS) {
      velocityStore.delete(key);
    }
  }
}, 5 * 60 * 1000).unref();

/**
 * تسجيل محاولة فاشلة (يتم استدعاؤها عندما يكون القرار Block)
 * @param {object} params - { ip, deviceFingerprint }
 */
function recordFailedAttempt({ ip, deviceFingerprint }) {
  const now = Date.now();
  
  if (ip) {
    const key = `ip:${ip}`;
    const entry = velocityStore.get(key) || { count: 0, timestamp: now };
    entry.count++;
    entry.timestamp = now;
    if (entry.count >= THRESHOLDS.IP) {
      entry.blockedUntil = now + BLOCK_DURATION_MS;
    }
    velocityStore.set(key, entry);
  }

  if (deviceFingerprint) {
    const key = `device:${deviceFingerprint}`;
    const entry = velocityStore.get(key) || { count: 0, timestamp: now };
    entry.count++;
    entry.timestamp = now;
    if (entry.count >= THRESHOLDS.DEVICE) {
      entry.blockedUntil = now + BLOCK_DURATION_MS;
    }
    velocityStore.set(key, entry);
  }
}

/**
 * التحقق مما إذا كان IP أو جهاز معين محظورًا حاليًا بسبب السرعة العالية
 * @param {object} params - { ip, deviceFingerprint }
 * @returns {object} - { blocked: boolean, reason: string | null }
 */
function checkVelocity({ ip, deviceFingerprint }) {
  const now = Date.now();
  
  if (ip) {
    const ipEntry = velocityStore.get(`ip:${ip}`);
    if (ipEntry && ipEntry.blockedUntil && ipEntry.blockedUntil > now) {
      return { 
        blocked: true, 
        reason: `IP temporarily blocked due to high failure rate (${ipEntry.count} attempts)` 
      };
    }
  }

  if (deviceFingerprint) {
    const deviceEntry = velocityStore.get(`device:${deviceFingerprint}`);
    if (deviceEntry && deviceEntry.blockedUntil && deviceEntry.blockedUntil > now) {
      return { 
        blocked: true, 
        reason: `Device temporarily blocked due to high failure rate (${deviceEntry.count} attempts)` 
      };
    }
  }

  return { blocked: false, reason: null };
}

module.exports = { recordFailedAttempt, checkVelocity };