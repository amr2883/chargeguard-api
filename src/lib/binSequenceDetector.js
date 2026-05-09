// --- ChargeGuard BIN Sequence Detector ---
// يكشف هجمات Card Testing حتى لو البوت غير IP + Device + Email في كل طلب
//
// الفكرة الأساسية:
// البوت بيجيب بطاقات من نفس الـ dump → نفس الـ BIN prefix (أول 6 أرقام)
// حتى لو غير كل حاجة تانية، الـ BIN range بيفضح نمط الهجوم
//
// 3 طبقات كشف:
// Layer 1: BIN Prefix Velocity  — كتير BINs من نفس الـ prefix في وقت قصير
// Layer 2: Sequential BIN Scan  — BINs بترتيب تصاعدي/تنازلي (علامة brute-force)
// Layer 3: Cross-Entity Linking — نفس الـ BIN prefix مع entities مختلفة تماماً

'use strict';

// --- Constants ---
const WINDOW_MS         = 10 * 60 * 1000;  // نافذة 10 دقائق
const BLOCK_DURATION_MS = 60 * 60 * 1000;  // حظر ساعة
const PREFIX_LENGTH     = 4;               // أول 4 أرقام من الـ BIN (bank identifier)

const THRESHOLDS = {
  // Layer 1: كمية BINs مختلفة من نفس الـ prefix في 10 دقائق
  UNIQUE_BINS_PER_PREFIX: 8,

  // Layer 2: كمية BINs بتفرق 1 أو 2 رقم بين بعض (sequential scan)
  SEQUENTIAL_BINS: 5,

  // Layer 3: نفس الـ BIN prefix مع كمية entities مختلفة (IPs أو devices)
  UNIQUE_ENTITIES_PER_PREFIX: 6,
};

// --- In-Memory Store ---
// key: binPrefix (أول 4 أرقام)
// value: { bins: Map<bin, timestamp[]>, entities: Map<entity, timestamp>, blockedUntil? }
const prefixStore = new Map();

// تنظيف دوري كل 5 دقائق
setInterval(() => {
  const now = Date.now();
  for (const [prefix, data] of prefixStore.entries()) {
    // لو محظور وخلص وقت الحظر → امسحه
    if (data.blockedUntil && data.blockedUntil < now) {
      prefixStore.delete(prefix);
      continue;
    }
    // نظف الـ BINs القديمة من كل prefix
    for (const [bin, timestamps] of data.bins.entries()) {
      const fresh = timestamps.filter(t => t > now - WINDOW_MS);
      if (fresh.length === 0) data.bins.delete(bin);
      else data.bins.set(bin, fresh);
    }
    // لو الـ prefix فاضي تماماً → امسحه
    if (data.bins.size === 0 && !data.blockedUntil) {
      prefixStore.delete(prefix);
    }
  }
}, 5 * 60 * 1000).unref();

// --- Helper: استخراج الـ prefix ---
function extractPrefix(bin) {
  if (!bin || typeof bin !== 'string') return null;
  const digits = bin.replace(/\D/g, '');
  if (digits.length < PREFIX_LENGTH) return null;
  return digits.slice(0, PREFIX_LENGTH);
}

// --- Helper: كشف BINs بترتيب تصاعدي/تنازلي ---
// لو 5 BINs بتفرق بينهم 1-2 رقم → brute-force scan
function detectSequentialScan(bins) {
  if (bins.length < THRESHOLDS.SEQUENTIAL_BINS) return false;

  // خد آخر 6 أرقام من كل BIN (الجزء المتغير)
  const suffixes = bins
    .map(b => parseInt(b.slice(PREFIX_LENGTH), 10))
    .filter(n => !isNaN(n))
    .sort((a, b) => a - b);

  if (suffixes.length < THRESHOLDS.SEQUENTIAL_BINS) return false;

  // دور على تسلسل بفرق ≤ 2
  let streak = 1;
  for (let i = 1; i < suffixes.length; i++) {
    const diff = suffixes[i] - suffixes[i - 1];
    if (diff >= 1 && diff <= 2) {
      streak++;
      if (streak >= THRESHOLDS.SEQUENTIAL_BINS) return true;
    } else {
      streak = 1;
    }
  }
  return false;
}

// --- تسجيل طلب جديد ---
// entity = IP أو device fingerprint (أي identifier)
function recordBINAttempt({ bin, entity }) {
  const prefix = extractPrefix(bin);
  if (!prefix) return;

  const now = Date.now();

  if (!prefixStore.has(prefix)) {
    prefixStore.set(prefix, {
      bins: new Map(),
      entities: new Map(),
      blockedUntil: null,
    });
  }

  const data = prefixStore.get(prefix);

  // سجل الـ BIN
  const existingTimestamps = data.bins.get(bin) || [];
  existingTimestamps.push(now);
  data.bins.set(bin, existingTimestamps);

  // سجل الـ entity
  data.entities.set(entity, now);

  // تحقق من الـ thresholds وحدد حظر لو لزم
  const { triggered } = checkPrefix(prefix, data, now);
  if (triggered) {
    data.blockedUntil = now + BLOCK_DURATION_MS;
  }
}

// --- فحص prefix معين ---
function checkPrefix(prefix, data, now = Date.now()) {
  const windowStart = now - WINDOW_MS;

  // BINs نشطة في الـ window
  const activeBins = [];
  for (const [bin, timestamps] of data.bins.entries()) {
    if (timestamps.some(t => t > windowStart)) {
      activeBins.push(bin);
    }
  }

  // Entities نشطة في الـ window
  const activeEntities = [...data.entities.entries()]
    .filter(([, t]) => t > windowStart)
    .map(([e]) => e);

  // Layer 1: BIN velocity
  if (activeBins.length >= THRESHOLDS.UNIQUE_BINS_PER_PREFIX) {
    return {
      triggered: true,
      layer: 1,
      reason: `BIN prefix ${prefix}xx: ${activeBins.length} unique BINs tested in 10 minutes`,
      riskAddition: 35,
    };
  }

  // Layer 2: Sequential scan
  if (detectSequentialScan(activeBins)) {
    return {
      triggered: true,
      layer: 2,
      reason: `BIN prefix ${prefix}xx: sequential card scan detected`,
      riskAddition: 40,
    };
  }

  // Layer 3: Cross-entity (نفس الـ BIN prefix من entities مختلفة جداً)
  if (activeBins.length >= 4 && activeEntities.length >= THRESHOLDS.UNIQUE_ENTITIES_PER_PREFIX) {
    return {
      triggered: true,
      layer: 3,
      reason: `BIN prefix ${prefix}xx: ${activeBins.length} BINs from ${activeEntities.length} different sources`,
      riskAddition: 30,
    };
  }

  return { triggered: false, layer: null, reason: null, riskAddition: 0 };
}

// --- الدالة الرئيسية: يستخدمها الـ risk scoring ---
// بترجع { blocked, riskAddition, reason, layer }
function checkBINSequence({ bin, ipAddress, deviceFingerprint }) {
  const prefix = extractPrefix(bin);
  if (!prefix) return { blocked: false, riskAddition: 0, reason: null };

  const now = Date.now();
  const data = prefixStore.get(prefix);

  // لو محظور من قبل
  if (data?.blockedUntil && data.blockedUntil > now) {
    return {
      blocked: true,
      riskAddition: 50,
      reason: `BIN prefix ${prefix}xx temporarily blocked (active attack wave)`,
      layer: 0,
    };
  }

  // entity = IP أو device (أيهما متاح)
  const entity = ipAddress || deviceFingerprint || 'unknown';
  recordBINAttempt({ bin, entity });

  // إعادة الفحص بعد التسجيل
  const freshData = prefixStore.get(prefix);
  if (!freshData) return { blocked: false, riskAddition: 0, reason: null };

  const result = checkPrefix(prefix, freshData, now);

  return {
    blocked: result.triggered,
    riskAddition: result.riskAddition || 0,
    reason: result.reason,
    layer: result.layer,
  };
}

// --- إحصائيات للـ dashboard ---
function getBINStats() {
  const now = Date.now();
  let activePrefixes = 0;
  let blockedPrefixes = 0;
  let totalActiveBINs = 0;

  for (const [, data] of prefixStore.entries()) {
    const windowStart = now - WINDOW_MS;
    const activeBins = [...data.bins.values()].filter(ts =>
      ts.some(t => t > windowStart)
    ).length;

    if (activeBins > 0) {
      activePrefixes++;
      totalActiveBINs += activeBins;
    }
    if (data.blockedUntil && data.blockedUntil > now) {
      blockedPrefixes++;
    }
  }

  return { activePrefixes, blockedPrefixes, totalActiveBINs };
}

module.exports = { checkBINSequence, recordBINAttempt, getBINStats };
