// ─── ChargeGuard Signal Weights ───────────────────────────────────────────
// Reads learned signal weights from DB and applies:
// 1. Lazy Exponential Decay
// 2. Bayesian Smoothing
// 3. Log-odds transformation
// 4. Confidence-based blending (global ↔ merchant)

const db = require('./db');

// ─── Constants ────────────────────────────────────────────────────────────
const DECAY_LAMBDA = 0.003;   // ~58% weight after 180 days
const BAYESIAN_ALPHA = 5;     // prior wins  (neutral = 50%)
const BAYESIAN_BETA  = 5;     // prior losses

// ─── Survivorship Bias Note ───────────────────────────────────────────────
// الـ learning system بيتعلم بس من الـ orders اللي وصلوا لـ dispute outcome
// (won أو lost). الـ fraud اللي عدى بدون dispute مش بيأثر على الـ weights.
// النتيجة: الـ weights ممكن تكون optimized للـ disputed orders بس —
// مش للـ fraud universe الكامل.
//
// Mitigation:
// 1. MIN_EVENTS_FOR_CONFIDENCE: نحتاج minimum events قبل ما نثق في الـ weight
// 2. الـ Bayesian prior (alpha=5, beta=5) بيحمي من overfit على عينة صغيرة
// 3. الـ confidence field في SignalStat بيعكس حجم العينة — مش بس الـ win rate
//
// Long-term fix: integrate proxy labels (high-risk orders that weren't disputed)
// as weak negative signals to reduce survivorship bias gradually.
const MIN_EVENTS_FOR_CONFIDENCE = 10; // أقل من كده → نثق في الـ prior أكثر

// Log-odds scaling
// BASE = 1.0 means "neutral signal" (no learning yet)
// SCALE controls how much learning moves the weight
const logger = require('./logger');

const LOG_ODDS_BASE = 1.0;
const LOG_ODDS_SCALE = 0.4;
const MAX_EFFECTIVE_WEIGHT = 5.0; // يمنع أي signal يكسر الـ scoring balance
// Merchant weight ratio constants (same as in feedbackLoop.js)
const MIN_DISPUTES_FOR_MERCHANT = 10;
const MAX_MERCHANT_RATIO = 0.30;
function calculateMerchantRatio(profile) {
  if (!profile || profile.totalDisputes < MIN_DISPUTES_FOR_MERCHANT) return 0;
  const { wonDisputes, lostDisputes, totalDisputes } = profile;
  const resolvedDisputes = wonDisputes + (lostDisputes ?? 0);
  const effectiveTotal = resolvedDisputes > 0 ? resolvedDisputes : totalDisputes;
  const extra = totalDisputes - MIN_DISPUTES_FOR_MERCHANT;
  const baseRatio = Math.min(MAX_MERCHANT_RATIO, extra * 0.01);
  const winRate = effectiveTotal > 0 ? wonDisputes / effectiveTotal : 0.5;
  const winRateModifier = winRate >= 0.5 ? 1.0 : Math.max(0.3, winRate * 2);
  return parseFloat((baseRatio * winRateModifier).toFixed(4));
}

// ─── Static Baseline Weights ──────────────────────────────────────────────
// Used when no learned data exists yet (cold start)
// These mirror the original scoring points
const STATIC_WEIGHTS = {
  "ECI:5":                   { base: 4.0, description: "Full 3DS authentication" },
  "ECI:6":                   { base: 3.5, description: "Attempted 3DS authentication" },
  "ECI:7":                   { base: 0.0, description: "No 3DS" },
  "AVS:Y":                   { base: 2.0, description: "Full address match" },
  "AVS:A":                   { base: 0.8, description: "Address only match" },
  "AVS:Z":                   { base: 0.8, description: "ZIP only match" },
  "AVS:N":                   { base: 0.0, description: "No address match" },
  "CVV2:M":                  { base: 1.0, description: "CVV matched" },
  "CVV2:N":                  { base: 0.0, description: "CVV not matched" },
  "TRACKING:confirmed":      { base: 2.0, description: "Tracking confirmed" },
  "DELIVERY_PROOF:present":  { base: 3.0, description: "Proof of delivery" },
  "LOGIN:present":           { base: 2.0, description: "Customer login recorded" },
  "CTA:accepted":            { base: 2.0, description: "Click-to-accept recorded" },
  "PRE_CHARGE:sent":         { base: 2.0, description: "7-day pre-charge notice" },
  "USAGE_LOGS:present":      { base: 2.0, description: "Usage logs after cancellation" },
  "NO_CANCEL_REQUEST:confirmed": { base: 2.0, description: "No cancellation request" },
  "CE30:eligible":           { base: 3.0, description: "CE 3.0 eligible" },
  "REFUND:processed":        { base: 3.0, description: "Refund already processed" },

  // ===== إشارات WooCommerce (Card Testing) =====
  "BIN_PREPAID:true":          { base: 15, description: "Prepaid card detected" },
  "BIN_COUNTRY:NG":            { base: 15, description: "Card issued in Nigeria" },
  "BIN_COUNTRY:CM":            { base: 15, description: "Card issued in Cameroon" },
  "BIN_COUNTRY:GH":            { base: 15, description: "Card issued in Ghana" },
  "BIN_COUNTRY:PK":            { base: 10, description: "Card issued in Pakistan" },
  "BIN_COUNTRY:BD":            { base: 10, description: "Card issued in Bangladesh" },
  "BIN_COUNTRY:VN":            { base: 6,  description: "Card issued in Vietnam" },
  "BIN_COUNTRY:ID":            { base: 6,  description: "Card issued in Indonesia" },
  "BIN_COUNTRY:PH":            { base: 6,  description: "Card issued in Philippines" },
  "EMAIL_DISPOSABLE:true":     { base: 20, description: "Disposable email address" },
  "EMAIL_FREE_PROVIDER:true":  { base: 5,  description: "Free email provider" },
  "EMAIL_DOMAIN_INVALID:true": { base: 30, description: "Email domain does not exist" },
  "IP_DATACENTER:true":        { base: 15, description: "IP from datacenter/VPN" },
  "IP_PROXY:true":             { base: 20, description: "IP is a proxy" },
  "IP_TOR:true":               { base: 30, description: "IP is a Tor exit node" },
  "NEW_CUSTOMER:true":         { base: 10, description: "New customer" },
  "HIGH_VALUE:true":           { base: 10, description: "High value order" },
  "GRAPH_RISK_HIGH:true":      { base: 20, description: "High identity graph risk" },

  // ===== إشارات السرعة والسلوك =====
  "DEVICE_VELOCITY:high":      { base: 25, description: "High device velocity (3+ orders/hour)" },
  "DEVICE_VELOCITY:medium":    { base: 15, description: "Medium device velocity (2 orders/hour)" },
  "IP_VELOCITY:high":          { base: 20, description: "High IP velocity" },
  "IP_VELOCITY:medium":        { base: 10, description: "Medium IP velocity" },
  "EMAIL_VELOCITY:high":       { base: 20, description: "High email velocity" },
  "SHIPPING_BILLING_MISMATCH:true": { base: 10, description: "Shipping country differs from billing" },
  "BIN_ISSUER_MISMATCH:true":  { base: 10, description: "Card issuer country differs from billing" },
  "AMOUNT_ANOMALY:true":       { base: 15, description: "Order amount significantly above average" },
};
// ─── Apply Lazy Exponential Decay ─────────────────────────────────────────
function applyDecay(rawWins, rawLosses, lastDecayAt) {
  if (!lastDecayAt) return { wins: rawWins, losses: rawLosses };
  const daysSince = (Date.now() - new Date(lastDecayAt).getTime()) / (1000 * 60 * 60 * 24);
  const MIN_DECAY_VALUE = 0.05;

  // Asymmetric decay — losses بتتـ decay أبطأ من wins
  // DECAY_LAMBDA = 0.003 للـ wins (~58% بعد 180 يوم)
  // DECAY_LAMBDA * 0.5 للـ losses (~76% بعد 180 يوم)
  // المنطق: fraud signal قديم لسه مهم — clean signal القديم أقل أهمية
  const winFactor  = Math.exp(-DECAY_LAMBDA * daysSince);
  const lossFactor = Math.exp(-DECAY_LAMBDA * 0.5 * daysSince);

  return {
    wins:   Math.max(MIN_DECAY_VALUE, rawWins  * winFactor),
    losses: Math.max(MIN_DECAY_VALUE, rawLosses * lossFactor),
  };
}
// ─── Bayesian Win Rate ─────────────────────────────────────────────────────
// Prevents overconfidence with small samples
// With 0 data: returns 0.5 (neutral)
// With 100 wins, 0 losses: returns ~0.91 (not 1.0)
function bayesianWinRate(wins, losses) {
  return (wins + BAYESIAN_ALPHA) / (wins + losses + BAYESIAN_ALPHA + BAYESIAN_BETA);
}

// ─── Log-odds Transformation ───────────────────────────────────────────────
// Converts win rate to a weight multiplier
// winRate = 0.5 → logOdds = 0  → weight = BASE (neutral)
// winRate = 0.9 → logOdds = 2.2 → weight = BASE + SCALE*2.2 (boosted)
// winRate = 0.1 → logOdds = -2.2 → weight = BASE - SCALE*2.2 (penalized)
function logOddsWeight(winRate) {
  // Clamp to avoid log(0) or log(inf)
  const clamped = Math.max(0.01, Math.min(0.99, winRate));
  const logOdds = Math.log(clamped / (1 - clamped));
  return Math.max(0, LOG_ODDS_BASE + LOG_ODDS_SCALE * logOdds);
}

// ─── Confidence-based Blending ─────────────────────────────────────────────
// Low confidence → trust global more
// High confidence → trust learned weight more
function blendWeights(globalWeight, learnedWeight, confidence) {
  return (1 - confidence) * globalWeight + confidence * learnedWeight;
}



// ─── Get All Weights for Merchant ─────────────────────────────────────────
// Batch loads all weights for a merchant in one call
// Returns a map: "ECI:5" → effective weight
async function getWeightsForMerchant(merchantId) {
  try {
    // 1. جلب ملف التاجر
    const profile = await db.merchantProfile.findUnique({ where: { merchantId } });
    const ratio = calculateMerchantRatio(profile);

    // 2. جلب جميع إحصائيات الإشارات (للتاجر وللعام)
    const allStats = await db.signalStat.findMany({
      where: {
        OR: [
          { merchantId: null },
          { merchantId },
        ],
      },
    });

    const globalStats = new Map();
    const merchantStats = new Map();
    for (const stat of allStats) {
      const key = `${stat.signalType}:${stat.signalValue}`;
      if (stat.merchantId === null) globalStats.set(key, stat);
      else merchantStats.set(key, stat);
    }

    const weightMap = {};

    for (const signalKey of Object.keys(STATIC_WEIGHTS)) {
      const staticWeight = STATIC_WEIGHTS[signalKey].base;
      if (staticWeight === 0) {
        weightMap[signalKey] = 0;
        continue;
      }

      // الوزن العام
      let globalWeight = staticWeight;
      const globalStat = globalStats.get(signalKey);
      if (globalStat && globalStat.totalEvents >= 3) {
        const { wins, losses } = applyDecay(globalStat.rawWins, globalStat.rawLosses, globalStat.lastDecayAt);
        const winRate = bayesianWinRate(wins, losses);
        const learnedWeight = logOddsWeight(winRate) * staticWeight;
        const confidence = Math.min(1, globalStat.totalEvents / MIN_EVENTS_FOR_CONFIDENCE);
        globalWeight = blendWeights(staticWeight, learnedWeight, confidence);
      }

      // وزن التاجر
      let merchantWeight = globalWeight;
      if (ratio > 0) {
        const merchantStat = merchantStats.get(signalKey);
        if (merchantStat && merchantStat.totalEvents >= 3) {
          const { wins: mWins, losses: mLosses } = applyDecay(merchantStat.rawWins, merchantStat.rawLosses, merchantStat.lastDecayAt);
          const mWinRate = bayesianWinRate(mWins, mLosses);
          const mLearned = logOddsWeight(mWinRate) * staticWeight;
          const mConfidence = Math.min(1, merchantStat.totalEvents / MIN_EVENTS_FOR_CONFIDENCE);
          merchantWeight = blendWeights(staticWeight, mLearned, mConfidence);
        }
      }

      const finalWeight = (1 - ratio) * globalWeight + ratio * merchantWeight;
      weightMap[signalKey] = Math.min(MAX_EFFECTIVE_WEIGHT, Math.max(0, finalWeight));
    }

    return {
      weights: weightMap,
      merchantWeightRatio: ratio,
      isLearning: (profile?.totalDisputes ?? 0) >= MIN_DISPUTES_FOR_MERCHANT,
      totalDisputes: profile?.totalDisputes ?? 0,
    };
  } catch (err) {
    logger.error({ module: 'signalWeights', err }, 'Failed to load learned weights, using static fallback');
    const staticFallback = {};
    for (const key of Object.keys(STATIC_WEIGHTS)) {
      staticFallback[key] = STATIC_WEIGHTS[key].base;
    }
    return {
      weights: staticFallback,
      merchantWeightRatio: 0,
      isLearning: false,
      totalDisputes: 0,
    };
  }
}
// ─── Get Weight for Specific Signal ───────────────────────────────────────
/**
 * @deprecated استخدم getWeightsForMerchant() بدلاً منها في أي request بيحتاج أكتر من signal
 * ⚠️  SLOW PATH — 3 DB queries per call (profile + global stat + merchant stat)
 * لو اتنادت في loop على N signals = N*3 queries
 *
 * متى تستخدمها:
 * ✅ signal واحدة فقط في isolated context (مثلاً debugging أو admin tool)
 * ❌ أبداً في loop أو في calculateRiskScore
 */
async function getWeightForSignal(signalType, signalValue, merchantId) {
  const weights = await getWeightsForMerchant(merchantId);
  return weights.weights[`${signalType}:${signalValue}`] ?? 0;
}

// ─── Get Static Weight (no DB call) ───────────────────────────────────────
// Fast path — used when learning is disabled or for comparison
function getStaticWeight(signalType, signalValue) {
  return STATIC_WEIGHTS[`${signalType}:${signalValue}`]?.base ?? 0;
}

// ─── Get Weight Description ────────────────────────────────────────────────
function getSignalDescription(signalType, signalValue) {
  return STATIC_WEIGHTS[`${signalType}:${signalValue}`]?.description ?? "Unknown signal";
}

// ─── Explain Weights (for debugging + merchant UI) ────────────────────────
// Returns a detailed breakdown of why each signal has its weight
async function explainWeights(merchantId) {
  const { weights, merchantWeightRatio, isLearning, totalDisputes } = await getWeightsForMerchant(merchantId);
  const ratio = merchantWeightRatio;
  const explanation = [];

  for (const signalKey of Object.keys(STATIC_WEIGHTS)) {
    const staticW = STATIC_WEIGHTS[signalKey].base;
    const effectiveW = weights[signalKey] ?? 0;

    explanation.push({
      signal: signalKey,
      description: STATIC_WEIGHTS[signalKey].description,
      staticWeight: staticW,
      effectiveWeight: parseFloat(effectiveW.toFixed(3)),
      delta: parseFloat((effectiveW - staticW).toFixed(3)),
      direction: effectiveW > staticW ? "boosted" : effectiveW < staticW ? "penalized" : "neutral",
    });
  }

  return {
    merchantId,
    isLearning,
    merchantWeightRatio: ratio,
    totalDisputes,
    signals: explanation.sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta)),
  };
}
module.exports = {
  getWeightsForMerchant,
  getWeightForSignal,
  getStaticWeight,
  getSignalDescription,
  explainWeights,
};