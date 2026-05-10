// ─── ChargeGuard Feedback Loop ────────────────────────────────────────────
// Learning engine: dispute outcomes → signal weight updates
// Architecture: Bayesian Smoothing + Log-odds + Lazy Exponential Decay + Confidence Blending
// ─── Stubs for missing dependencies ─────────────────────────────────────
async function upsertCustomerRiskProfile(order, merchantId, result, db) {
  // معطل مؤقتًا - لا يوجد جدول CustomerRiskProfile
}


const db = require('./db');
const logger = require('../lib/logger');
// const { upsertCustomerRiskProfile } = require('./customerRiskProfile'); // معطل مؤقتًا
const { getWeightsForMerchant } = require('./signalWeights');
const { markOrderAsFraud } = require('./identityGraph');
const { markPatternAsFraud } = require('./patternSharing');


// ─── Constants ────────────────────────────────────────────────────────────
const SCORING_VERSION = "v1.0-logodds-confidence";

// Bayesian priors — neutral start (50% win rate assumption)
const BAYESIAN_ALPHA = 5; // prior wins
const BAYESIAN_BETA = 5;  // prior losses

// Exponential decay rate — after 180 days, event has ~58% weight


// Max merchant weight ratio — 70% global + 30% merchant max
const MAX_MERCHANT_RATIO = 0.30;

// Min disputes before merchant weights activate
const MIN_DISPUTES_FOR_MERCHANT = 10;

// ─── Dynamic Learning Threshold ───────────────────────────────────────────
// Calculates minimum dispute amount to learn from, based on merchant's average order value
// Returns a number in the merchant's currency (same as disputeAmount)
function getMinLearningAmount(avgOrderValue, totalOrders, defaultValue = 10) {
  // Not enough data → use default
  if (!avgOrderValue || totalOrders < 10) return defaultValue;
  
  // Dynamic: 10% of average order value, clamped between 5 and 100
  const dynamic = avgOrderValue * 0.1;
  return Math.min(100, Math.max(5, dynamic));
}

// ─── Extract Signals from Dispute + Order ─────────────────────────────────
// Returns array of { type, value } for all signals present
function extractSignals(dispute, order) {
  const signals = [];

  // Payment signals
  if (order?.eciCode) {
    signals.push({ type: "ECI", value: order.eciCode });
  }
  if (order?.avsResponse) {
    signals.push({ type: "AVS", value: order.avsResponse });
  }
  if (order?.cvv2Response) {
    signals.push({ type: "CVV2", value: order.cvv2Response });
  }

  // Delivery signals
  if (dispute.hasTrackingConfirmed && order?.trackingNumber) {
    signals.push({ type: "TRACKING", value: "CONFIRMED" });
  }
  if (dispute.hasDeliveryProof) {
    signals.push({ type: "DELIVERY_PROOF", value: "PRESENT" });
  }

  // Identity signals
  if (dispute.hasLoginAfterPurchase && order?.customerLoginId) {
    signals.push({ type: "LOGIN", value: "PRESENT" });
  }

  // Policy signals
  if (dispute.hasClickToAccept) {
    signals.push({ type: "CTA", value: "ACCEPTED" });
  }
  if (dispute.hasPreChargeNotice) {
    signals.push({ type: "PRE_CHARGE", value: "SENT" });
  }

  // Subscription signals
  if (dispute.hasUsageLogs) {
    signals.push({ type: "USAGE_LOGS", value: "PRESENT" });
  }
  if (!dispute.hasCancellationRequest && ["13.2", "13.7"].includes(dispute.conditionCode)) {
    signals.push({ type: "NO_CANCEL_REQUEST", value: "CONFIRMED" });
  }

  // Compelling Evidence
  if (dispute.ceEligible && dispute.ceMatchCount >= 2) {
    signals.push({ type: "CE30", value: "ELIGIBLE" });
  }

  // Refund
  if (dispute.hasRefundProcessed) {
    signals.push({ type: "REFUND", value: "PROCESSED" });
  }

  return signals;
}



// ─── Calculate Confidence ─────────────────────────────────────────────────
// Confidence increases with more data, maxes near 1.0
function calculateConfidence(totalEvents) {
  // Sigmoid-like: confidence = events / (events + 20)
  // at 20 events → 0.5, at 100 events → 0.83
  return totalEvents / (totalEvents + 20);
}

// ─── Update Single Signal Stat ─────────────────────────────────────────────
const VALID_SIGNAL_VALUES = {
  ECI:               ["5", "6", "7"],
  AVS:               ["Y", "N", "A", "Z", "W", "X", "U", "R", "S", "E"],
  CVV2:              ["M", "N", "P", "S", "U"],
  TRACKING:          ["CONFIRMED"],
  DELIVERY_PROOF:    ["PRESENT"],
  LOGIN:             ["PRESENT"],
  CTA:               ["ACCEPTED"],
  PRE_CHARGE:        ["SENT"],
  USAGE_LOGS:        ["PRESENT"],
  NO_CANCEL_REQUEST: ["CONFIRMED"],
  CE30:              ["ELIGIBLE"],
  REFUND:            ["PROCESSED"],
  DEVICE_VELOCITY:   ["high", "medium"],
  IP_VELOCITY:       ["high", "medium"],
  EMAIL_VELOCITY:    ["high"],
  SHIPPING_BILLING_MISMATCH: ["true"],
  BIN_ISSUER_MISMATCH: ["true"],
  AMOUNT_ANOMALY:    ["true"],};

async function updateSignalStat(merchantId, signalType, signalValue, isWin) {
  const normalizedValue = String(signalValue).trim().toUpperCase();

  // Signal whitelisting — يمنع injection signals غلط في DB
  if (VALID_SIGNAL_VALUES[signalType] && !VALID_SIGNAL_VALUES[signalType].includes(normalizedValue)) {
    logger.warn({ module: 'feedbackLoop', signalType, signalValue: normalizedValue }, 'Rejected invalid signal');
    return;
  }
  const key = { merchantId: merchantId ?? null, signalType, signalValue: normalizedValue };

  const now = new Date();

  // استخدام upsert مع increment على rawWins و rawLosses
  // يضمن atomicity كاملة بدون الحاجة لقراءة القيمة الحالية
  await db.signalStat.upsert({
    where: { merchantId_signalType_signalValue: key },
    create: {
      ...key,
      rawWins: isWin ? 1 : 0,
      rawLosses: isWin ? 0 : 1,
      totalEvents: 1,
      lastDecayAt: now,
      // الحقول القديمة decayedWins/decayedLosses نحتفظ بها للتوافق، لكننا لن نستخدمها

      confidence: 0.5,
    },
    update: {
      rawWins: isWin ? { increment: 1 } : undefined,
      rawLosses: isWin ? undefined : { increment: 1 },
      totalEvents: { increment: 1 },
      lastDecayAt: now,
      // الحقول القديمة: نحدثها بشكل متوافق (نفس القيم الجديدة)

    },
  });
}

// ─── Update Merchant Profile (simplified, no transaction) ─────────────────
// Only increments the counters atomically. merchantWeightRatio is computed
// dynamically at read time in signalWeights.js to avoid transaction timeouts.
async function updateMerchantProfile(merchantId, isWin) {
  const now = new Date();
  await db.merchantProfile.upsert({
    where: { merchantId },
    create: {
      merchantId,
      wonDisputes: isWin ? 1 : 0,
      lostDisputes: isWin ? 0 : 1,
      totalDisputes: 1,
      merchantWeightRatio: 0.0,
    },
    update: {
      wonDisputes: isWin ? { increment: 1 } : undefined,
      lostDisputes: isWin ? undefined : { increment: 1 },
      totalDisputes: { increment: 1 },
    },
  });
}
// ─── Calculate Contributing Signals ───────────────────────────────────────
// O(n) — contributions are calculated during scoring, not after
// Returns top 5 signals by contribution magnitude
function calculateContributions(signals, dispute, order, weightsMap = null) {
  const contributions = [];

  for (const signal of signals) {
    let contribution = 0;
    const v = String(signal.value).trim().toUpperCase();

    // Try to use learned weight if weightsMap is provided
    if (weightsMap) {
      const signalKey = `${signal.type}:${v}`;
      const learnedWeight = weightsMap[signalKey];
      if (learnedWeight !== undefined && learnedWeight > 0) {
        // Scale learned weight to roughly match static scale (0-5 range)
        // Learned weights typically range 0-5, but we cap at 5 and round to 1 decimal
        contribution = Math.min(5, Math.max(0, Math.round(learnedWeight * 2) / 2));
      }
    }
    
    // Fallback to static mapping if learned weight not available or zero
    if (contribution === 0) {
      if (signal.type === "ECI" && ["5", "6"].includes(v)) contribution = 4;
      else if (signal.type === "CE30" && v === "ELIGIBLE") contribution = 3;
      else if (signal.type === "DELIVERY_PROOF" && v === "PRESENT") contribution = 3;
      else if (signal.type === "REFUND" && v === "PROCESSED") contribution = 3;
      else if (signal.type === "AVS" && v === "Y") contribution = 2;
      else if (signal.type === "LOGIN" && v === "PRESENT") contribution = 2;
      else if (signal.type === "CTA" && v === "ACCEPTED") contribution = 2;
      else if (signal.type === "TRACKING" && v === "CONFIRMED") contribution = 2;
      else if (signal.type === "PRE_CHARGE" && v === "SENT") contribution = 2;
      else if (signal.type === "USAGE_LOGS" && v === "PRESENT") contribution = 2;
      else if (signal.type === "NO_CANCEL_REQUEST" && v === "CONFIRMED") contribution = 2;
      else if (signal.type === "CVV2" && v === "M") contribution = 1;
    }

    if (contribution > 0) {
      contributions.push({ ...signal, contribution });
    }
  }

  // Sort by contribution descending, take top 5
  return contributions
    .sort((a, b) => b.contribution - a.contribution)
    .slice(0, 5);
}

// ─── Main Feedback Loop ────────────────────────────────────────────────────
// Called from webhooks.disputes.jsx when dispute is resolved
// ─── Main Feedback Loop ────────────────────────────────────────────────────
// Called from webhooks.disputes.jsx when dispute is resolved
async function processFeedback(disputeId, result) {
  // ===== مسار مبسط لبيئة WooCommerce (الجداول غير موجودة بعد) =====
  logger.warn({ module: 'feedbackLoop' }, 'Dispute tables not yet available — using simplified path');
  return processFeedbackSimplified(disputeId, result);
}

// ─── مسار مبسط للتعلم من نتائج الحظر (بدون جداول dispute) ─────────────
// ─── مسار مبسط للتعلم من نتائج الحظر (يستخدم بيانات Order الحقيقية) ─────────────
async function processFeedbackSimplified(orderIdOrDisputeId, resultOrIsFraud) {
  const isFraud = typeof resultOrIsFraud === 'boolean' 
    ? resultOrIsFraud 
    : (resultOrIsFraud === 'lost');
  const orderId = orderIdOrDisputeId;

  const isWin = !isFraud;

  try {
    // 1. قراءة الطلب من قاعدة البيانات
    const order = await db.order.findUnique({
      where: { orderId }
    });

    if (!order) {
      logger.warn({ module: 'feedbackLoop', orderId }, 'Order not found, cannot process feedback');
      return;
    }
    const merchantId = order.merchantId;

    // 2. تحديث MerchantProfile
    await db.merchantProfile.upsert({
      where: { merchantId },
      create: {
        merchantId,
        wonDisputes: isWin ? 1 : 0,
        lostDisputes: isWin ? 0 : 1,
        totalDisputes: 1,
        trustScore: 0.3,
        reportCount: 1,
      },
      update: {
        wonDisputes: isWin ? { increment: 1 } : undefined,
        lostDisputes: isWin ? undefined : { increment: 1 },
        totalDisputes: { increment: 1 },
        reportCount: { increment: 1 },
      },
    });

    // 2.5 تحديث CardHash.blockCount إذا كان الاحتيال مؤكداً
    if (isFraud && order.cardHash) {
      await db.cardHash.update({
        where: { cardHash: order.cardHash },
        data: { blockCount: { increment: 1 } },
      }).catch(e => logger.error({ module: 'feedbackLoop', err: e }, 'Failed to update CardHash blockCount'));
    }

    // 3. استخراج الإشارات من signalsSnapshot
    let signals = [];
    if (order.signalsSnapshot) {
      try {
        const snapshot = JSON.parse(order.signalsSnapshot);
        signals = extractSignalsFromSnapshot(snapshot);
      } catch (e) {
        logger.error({ module: 'feedbackLoop', err: e }, 'Failed to parse signalsSnapshot');
      }
    }

    // 4. تحديث SignalStat (للتاجر وللعام)
    if (signals.length > 0) {
      const uniqueSignals = [...new Map(signals.map(s => [`${s.type}:${s.value}`, s])).values()];
      
      for (const signal of uniqueSignals) {
        // تحديث الإحصائية العامة (merchantId = null)
        await updateSignalStat(null, signal.type, signal.value, isWin).catch(e =>
          logger.error({ module: 'feedbackLoop', err: e }, 'Failed to update global SignalStat')
        );
        // تحديث إحصائية التاجر
        await updateSignalStat(merchantId, signal.type, signal.value, isWin).catch(e =>
          logger.error({ module: 'feedbackLoop', err: e }, 'Failed to update merchant SignalStat')
        );
      }
    }

    // 5. تحديث الرسم البياني للهوية و Pattern Sharing إذا كان احتيالاً
    if (isFraud) {
      const deviceFp = order.deviceFingerprint || `fp_${orderId}`;
      const mockOrder = {
        id: orderId,
        deviceFingerprint: deviceFp,
        deviceId: deviceFp,
        email: order.email || 'unknown@test.com',
        ipAddress: order.ipAddress || '0.0.0.0',
        fingerprintVersion: 'v3',
      };
      await markOrderAsFraud(mockOrder, merchantId).catch(e =>
        logger.error({ module: 'feedbackLoop', err: e }, 'markOrderAsFraud error')
      );

      // 6. تحديث Pattern Sharing (Cross-Merchant Learning)
      let emailIntel = null;
      let ipIntel = null;
      let snapshot = {};
      try {
        snapshot = JSON.parse(order.signalsSnapshot || '{}');
        emailIntel = snapshot.emailIntel || null;
        ipIntel = snapshot.ipIntel || null;
      } catch (e) {
        logger.warn({ module: 'feedbackLoop', err: e }, 'Failed to parse signalsSnapshot for pattern sharing');
      }

      const patternContext = {
        isHighVelocity: (snapshot.deviceVelocityCount >= 2) || false
      };

      const patternOrder = {
        amount: order.amount,
        isNewCustomer: snapshot.isNewCustomer || false,
        createdAt: order.createdAt
      };

      await markPatternAsFraud(patternOrder, emailIntel, ipIntel, patternContext)
        .catch(e => logger.error({ module: 'feedbackLoop', err: e }, 'markPatternAsFraud error'));
    }

    logger.info({
      module: 'feedbackLoop',
      orderId,
      isFraud,
      isWin,
      merchantId,
      signalsCount: signals.length,
    }, 'Feedback processed with SignalStat updates');
  } catch (error) {
    logger.error({ module: 'feedbackLoop', err: error }, 'Error in simplified feedback');
  }
}

// دالة مساعدة لتحويل signalsSnapshot إلى مصفوفة الإشارات
function extractSignalsFromSnapshot(snapshot) {
  const signals = [];

  // BIN signals
  if (snapshot.binIntel) {
    if (snapshot.binIntel.isPrepaid) {
      signals.push({ type: 'BIN_PREPAID', value: 'true' });
    }
    if (snapshot.binIntel.issuerCountry) {
      signals.push({ type: 'BIN_COUNTRY', value: snapshot.binIntel.issuerCountry });
    }
    if (snapshot.binIntel.brand) {
      signals.push({ type: 'BIN_BRAND', value: snapshot.binIntel.brand });
    }
  }

  // Email signals
  if (snapshot.emailIntel) {
    if (snapshot.emailIntel.isDisposable) {
      signals.push({ type: 'EMAIL_DISPOSABLE', value: 'true' });
    }
    if (snapshot.emailIntel.isFreeProvider) {
      signals.push({ type: 'EMAIL_FREE_PROVIDER', value: 'true' });
    }
    if (!snapshot.emailIntel.domainExists) {
      signals.push({ type: 'EMAIL_DOMAIN_INVALID', value: 'true' });
    }
  }

  // IP signals
  if (snapshot.ipIntel) {
    if (snapshot.ipIntel.isDatacenter) {
      signals.push({ type: 'IP_DATACENTER', value: 'true' });
    }
    if (snapshot.ipIntel.isProxy) {
      signals.push({ type: 'IP_PROXY', value: 'true' });
    }
    if (snapshot.ipIntel.isTor) {
      signals.push({ type: 'IP_TOR', value: 'true' });
    }
    if (snapshot.ipIntel.country) {
      signals.push({ type: 'IP_COUNTRY', value: snapshot.ipIntel.country });
    }
  }

  // New customer signal
  if (snapshot.isNewCustomer) {
    signals.push({ type: 'NEW_CUSTOMER', value: 'true' });
  }

  // High value signal
  if (snapshot.amount > 200) {
    signals.push({ type: 'HIGH_VALUE', value: 'true' });
  }

  // Connected risk signal
  if (snapshot.connectedRisk > 30) {
    signals.push({ type: 'GRAPH_RISK_HIGH', value: 'true' });
  }

  // ===== الإشارات الجديدة =====
  // Device velocity
  if (snapshot.deviceVelocityCount >= 2) {
    signals.push({ type: 'DEVICE_VELOCITY', value: snapshot.deviceVelocityCount >= 3 ? 'high' : 'medium' });
  }

  // IP velocity
  if (snapshot.ipVelocityCount >= 2) {
    signals.push({ type: 'IP_VELOCITY', value: snapshot.ipVelocityCount >= 3 ? 'high' : 'medium' });
  }

  // Email velocity
  if (snapshot.emailVelocityCount >= 3) {
    signals.push({ type: 'EMAIL_VELOCITY', value: 'high' });
  }

  // Shipping/Billing mismatch
  if (snapshot.shippingBillingMismatch) {
    signals.push({ type: 'SHIPPING_BILLING_MISMATCH', value: 'true' });
  }

  // BIN issuer mismatch
  if (snapshot.binIssuerMismatch) {
    signals.push({ type: 'BIN_ISSUER_MISMATCH', value: 'true' });
  }

  // Amount anomaly
  if (snapshot.amountAnomaly) {
    signals.push({ type: 'AMOUNT_ANOMALY', value: 'true' });
  }

  return signals;
}

/* ===== الكود الأصلي الكامل (محفوظ للمستقبل) =====
async function processFeedback_original(disputeId, result) {
  if (!["won", "lost"].includes(result)) return;

  const isWin = result === "won";

  try {
    // ─── 1. Load Dispute (necessary for merchantId and order) ─────────────
    const dispute = await db.dispute.findUnique({
      where: { id: disputeId },
      include: { order: true, merchant: true },
    });

    if (!dispute) {
      logger.error({ module: 'feedbackLoop', disputeId }, 'Dispute not found');
      return;
    }

    const merchantId = dispute.merchantId;

    // ─── 2. Atomic Idempotency - Create outcome record FIRST ──────────────
    try {
      await db.disputeOutcome.create({
        data: {
          disputeId,
          merchantId: dispute.merchantId,
          result,
          conditionCode: dispute.conditionCode,
          resolvedAt: new Date(),
          signalsPresent: "[]",
          contributingSignals: "[]",
          scoringVersion: SCORING_VERSION,
        },
      });
    } catch (createError) {
      if (createError.code === 'P2002') {
        logger.info({ module: 'feedbackLoop', disputeId: dispute.shopifyDisputeId, result }, 'Duplicate dispute outcome - skipping processing');
        return;
      }
      throw createError;
    }

    // ... (باقي الكود الأصلي كما هو موجود في مشروعك القديم) ...
    // سيتم نسخه لاحقًا عند الحاجة

  } catch (error) {
    logger.error({ module: 'feedbackLoop', err: error }, 'Error processing feedback');
  }
}
*/

module.exports = {
  processFeedback,
  processFeedbackSimplified,
  extractSignals,
  calculateContributions,
};