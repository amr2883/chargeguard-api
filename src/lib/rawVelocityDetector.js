// ─── Raw (Unconditional) Device Velocity Detector ─────────────────────────
// يقفل الفجوة اللي سايبها checkVelocity() (velocityDetector.js): الفحص
// هناك بيشوف بس المحاولات اللي اترفضت (عبر recordFailedAttempt، بتتنادى
// بس لو response.decision !== 'approve'). بوت بيثبّت الـ device fingerprint
// ويلف على BIN prefixes مختلفة (يتفادى binSequenceDetector's per-prefix
// counter)، وبياخد سكور واطي كفاية إنه approve في أغلب المحاولات — العداد
// القديم مايتحركش أبدًا مهما كان عدد المحاولات.
//
// device fingerprint بس (مش IP) عمدًا — لأنه المتغير الوحيد اللي بيعدّي
// من كل الطبقات الحالية مع بعض:
//   - IP ثابت + device بيتلف  → مغطى بالفعل بـ per-IP rotation check
//     (قسم 1c في risk.js).
//   - device ثابت + IP بيتلف  → مش مغطى بحاجة تانية خالص.
//   - device ثابت + IP ثابت   → مش مغطى بحاجة تانية خالص.
// "device ثابت" هي الحالة الوحيدة المتبقية، بغض النظر عن سلوك الـ IP.
//
// نفس نمط "سجّل الأول، افحص بعدين" المستخدم في binSequenceDetector.js's
// recordBINAttempt() وglobalRotationDetector.js's
// recordAndCheckGlobalRotation() — in-memory بالكامل، صفر DB I/O على
// /evaluate (أعلى endpoint ترافيك في الملف كله).
//
// KNOWN LIMITATION (نفس تريد أوف globalRotationDetector.js): per-process.
// تحت horizontal scaling، مهاجم يقدر نظريًا يوزّع الطلبات على instances
// مختلفة عشان يفضل تحت العتبة على كل instance لوحده. قابل للترقية لـ
// Redis لاحقًا بنفس الـ client المستخدم في binSequenceDetector.js — نفس
// توقيع الدالة، نفس شكل الإرجاع.
//
// KNOWN GAP لسه موجودة بعد الفيكس ده: بوت مبيبعتش device fingerprint
// خالص + IP بيتلف بمعدل أبطأ من عتبة الـ IP fallback. هامشي عمليًا (أي
// checkout حقيقي عبر JS pixel بيبعت fingerprint)، لكن موثّق هنا كـ
// residual risk مش مغطى بالكامل.

const RAW_VELOCITY_WINDOW_MS =
  (parseInt(process.env.RAW_VELOCITY_WINDOW_MINUTES, 10) || 10) * 60 * 1000;

const RAW_DEVICE_BLOCK_THRESHOLD =
  parseInt(process.env.RAW_DEVICE_VELOCITY_THRESHOLD, 10) || 5; // 5+ محاولات من نفس الـ device، أي قرار، لكل تاجر، خلال النافذة — كان 10: بيسمح بـ 9 عمليات approve حقيقية قبل الحظر (راجع اختبار bin-diverse الحقيقي). حظر أبكر بكتير مع احتفاظ بهامش كافي لعميل حقيقي بيجرب أكتر من بطاقة مرة أو اتنين.

const RAW_IP_FALLBACK_BLOCK_THRESHOLD =
  parseInt(process.env.RAW_IP_VELOCITY_FALLBACK_THRESHOLD, 10) || 25; // عتبة أعلى بكتير — fallback بس لما مفيش fingerprint خالص

// merchantId -> Map<deviceFingerprint, timestamp[]>
const deviceAttempts = new Map();
// merchantId -> Map<ipHash, timestamp[]>  (fallback path بس)
const ipFallbackAttempts = new Map();

const SWEEP_INTERVAL_MS = 5 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const store of [deviceAttempts, ipFallbackAttempts]) {
    for (const [merchantId, innerMap] of store.entries()) {
      for (const [key, timestamps] of innerMap.entries()) {
        const fresh = timestamps.filter(t => t > now - RAW_VELOCITY_WINDOW_MS);
        if (fresh.length === 0) innerMap.delete(key);
        else innerMap.set(key, fresh);
      }
      if (innerMap.size === 0) store.delete(merchantId);
    }
  }
}, SWEEP_INTERVAL_MS).unref();

function recordAndCheck(store, merchantId, key, threshold) {
  if (!merchantId || !key) return { count: 0, blocked: false };
  const now = Date.now();
  let innerMap = store.get(merchantId);
  if (!innerMap) {
    innerMap = new Map();
    store.set(merchantId, innerMap);
  }
  const fresh = (innerMap.get(key) || []).filter(t => t > now - RAW_VELOCITY_WINDOW_MS);
  fresh.push(now);
  innerMap.set(key, fresh);
  return { count: fresh.length, blocked: fresh.length >= threshold };
}

/**
 * فحص سرعة غير مشروط بالقرار، مفتاحه device fingerprint. يتنادى على كل
 * /evaluate (وwebhook) request معاه deviceFingerprint حقيقي (مش synthetic
 * fallback زي wc_${orderId})، بغض النظر عن القرار النهائي لهذا الـ
 * request نفسه.
 */
function checkRawDeviceVelocity(merchantId, deviceFingerprint) {
  const { count, blocked } = recordAndCheck(
    deviceAttempts, merchantId, deviceFingerprint, RAW_DEVICE_BLOCK_THRESHOLD
  );
  return { count, blocked, threshold: RAW_DEVICE_BLOCK_THRESHOLD };
}

/**
 * Fallback بس — يتنادى فقط لما deviceFingerprint غايب تمامًا (يعني
 * checkRawDeviceVelocity مايقدرش يشتغل أصلاً). عتبة أعلى بكتير، عشان
 * نتحمّل شبكات NAT/مكاتب مشتركة.
 */
function checkRawIpVelocityFallback(merchantId, ipHash) {
  const { count, blocked } = recordAndCheck(
    ipFallbackAttempts, merchantId, ipHash, RAW_IP_FALLBACK_BLOCK_THRESHOLD
  );
  return { count, blocked, threshold: RAW_IP_FALLBACK_BLOCK_THRESHOLD };
}

module.exports = {
  checkRawDeviceVelocity,
  checkRawIpVelocityFallback,
  RAW_VELOCITY_WINDOW_MS,
  RAW_DEVICE_BLOCK_THRESHOLD,
  RAW_IP_FALLBACK_BLOCK_THRESHOLD,
};