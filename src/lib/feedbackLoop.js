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

async function updateSignalStat(merchantId, signalType, signalValue, isWin, dbClient = db) {
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
  // dbClient defaults to the module-level `db`, but callers inside the
  // M7 transaction boundary (processFeedbackSimplified) pass `tx` so
  // these writes participate in the surrounding transaction.
  await dbClient.signalStat.upsert({
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
async function processFeedback(disputeId, result, callerMerchantId) {
  // CRITICAL FIX (C4): callerMerchantId is now a required parameter,
  // threaded straight through to processFeedbackSimplified(), which uses
  // it to scope the order lookup to the calling tenant. Deliberately made
  // required (not optional with a silent default) — a default that meant
  // "skip the ownership check" would recreate exactly the vulnerability
  // this fix closes the moment any future caller forgot to pass it.
  if (!callerMerchantId) {
    throw new Error('processFeedback: callerMerchantId is required');
  }
  // ===== مسار مبسط لبيئة WooCommerce (الجداول غير موجودة بعد) =====
  logger.warn({ module: 'feedbackLoop' }, 'Dispute tables not yet available — using simplified path');
  return processFeedbackSimplified(disputeId, result, callerMerchantId);
}

// ─── مسار مبسط للتعلم من نتائج الحظر (بدون جداول dispute) ─────────────
// ─── مسار مبسط للتعلم من نتائج الحظر (يستخدم بيانات Order الحقيقية) ─────────────
async function processFeedbackSimplified(orderIdOrDisputeId, resultOrIsFraud, callerMerchantId) {
  const isFraud = typeof resultOrIsFraud === 'boolean' 
    ? resultOrIsFraud 
    : (resultOrIsFraud === 'lost');
  const orderId = orderIdOrDisputeId;

  const isWin = !isFraud;

  // CRITICAL FIX (C4): required, not optional — see processFeedback() above.
  if (!callerMerchantId) {
    throw new Error('processFeedbackSimplified: callerMerchantId is required');
  }

  try {
    // 1. قراءة الطلب من قاعدة البيانات
    // Scoped to (callerMerchantId, orderId) via the C3 compound unique key
    // — this query can structurally only ever return a row belonging to
    // the calling tenant, or no row at all. It can never return another
    // tenant's order under a matching orderId.
    // PREREQUISITE: this assumes the C3 schema migration
    // (@@unique([merchantId, orderId]) on Order) has already been applied
    // and the Prisma client regenerated. If that migration has not yet
    // been run, this compound-key lookup will fail at runtime — do not
    // deploy this change ahead of the C3 migration.
    const order = await db.order.findUnique({
      where: { merchantId_orderId: { merchantId: callerMerchantId, orderId } }
    });

    if (!order) {
      // Deliberately generic: this branch is reached both when the order
      // truly doesn't exist AND when it belongs to a different tenant — the
      // caller-facing behavior must not distinguish these two cases, or an
      // attacker could use response differences to enumerate which order
      // IDs exist for other merchants (an information-disclosure oracle).
      logger.warn({ module: 'feedbackLoop', orderId, callerMerchantId }, 'Order not found for this merchant, cannot process feedback');
      return;
    }

    // Defense-in-depth (C4): should be unreachable given the compound key
    // above, but asserted explicitly so a future regression (e.g. someone
    // "simplifying" the query back to a bare orderId lookup) fails loudly
    // in logs rather than silently reopening this vulnerability.
    if (order.merchantId !== callerMerchantId) {
      logger.error(
        { module: 'feedbackLoop', orderId, callerMerchantId, actualMerchantId: order.merchantId },
        'C4 guard tripped — compound key returned a different merchant\'s row; should be unreachable'
      );
      return;
    }

    const merchantId = order.merchantId;

    // ── Idempotency Gate (atomic) ───────────────────────────────────────────
    // Guards against duplicate processing when this function is invoked twice
    // for the same order — a realistic scenario given at-least-once webhook
    // delivery from both Stripe and PayPal, or a retried/duplicated call to
    // POST /risk/feedback. This is a single atomic UPDATE ... WHERE
    // feedbackProcessedAt IS NULL — not a separate findFirst-then-write —
    // so it is race-safe even if two calls for the same order arrive
    // concurrently: the database itself resolves which call "wins" via row
    // locking, and the loser observes count === 0 and returns without
    // touching any counter below.
    const idempotencyClaim = await db.order.updateMany({
      where: { merchantId, orderId, feedbackProcessedAt: null },
      data:  { feedbackProcessedAt: new Date() },
    });

    if (idempotencyClaim.count === 0) {
      logger.info(
        { module: 'feedbackLoop', orderId, merchantId },
        'Duplicate feedback call detected — already processed, skipping all counter updates'
      );
      return;
    }

    // 3. استخراج الإشارات من signalsSnapshot
    // Moved ahead of the transaction: this is pure in-memory parsing of
    // data already fetched (order.signalsSnapshot), not a DB write, so it
    // does not need to run inside the transaction and doing so would only
    // extend the time the DB connection/lock is held.
    let signals = [];
    if (order.signalsSnapshot) {
      try {
        const snapshot = JSON.parse(order.signalsSnapshot);
        signals = extractSignalsFromSnapshot(snapshot);
      } catch (e) {
        logger.error({ module: 'feedbackLoop', err: e }, 'Failed to parse signalsSnapshot');
      }
    }

    // ── M7 TRANSACTION BOUNDARY ─────────────────────────────────────────
    // merchantProfile, cardHash, and signalStat must be atomic with each
    // other: if any write in this block fails, all of them roll back,
    // so we never end up with (e.g.) reportCount incremented but the
    // signal-level training data for that report missing.
    //
    // markOrderAsFraud() and markPatternAsFraud() deliberately stay OUTSIDE
    // this block, below, and run only after it commits. They use separate
    // Prisma client instances (identityGraph.js, patternSharing.js) that
    // cannot participate in this transaction, and they are best-effort:
    // if they fail, the core accounting above is already committed and
    // consistent, and the failure is logged for retry rather than rolling
    // back correct data.
    //
    // Note: the cardHash update and signalStat upserts below no longer
    // swallow their own errors with .catch() — inside a transaction, an
    // unhandled rejection is exactly what triggers the rollback we want.
    // The outer try/catch in this function still logs the overall failure.
    await db.$transaction(async (tx) => {
      // 2. تحديث MerchantProfile
      await tx.merchantProfile.upsert({
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
        await tx.cardHash.update({
          where: { cardHash: order.cardHash },
          data: { blockCount: { increment: 1 } },
        });
      }

      // 4. تحديث SignalStat (للتاجر وللعام)
      if (signals.length > 0) {
        const uniqueSignals = [...new Map(signals.map(s => [`${s.type}:${s.value}`, s])).values()];

        for (const signal of uniqueSignals) {
          // تحديث الإحصائية العامة (merchantId = null)
          await updateSignalStat(null, signal.type, signal.value, isWin, tx);
          // تحديث إحصائية التاجر
          await updateSignalStat(merchantId, signal.type, signal.value, isWin, tx);
        }
      }
    });

    // ── DisputeOutcome persistence (H1 fix) ─────────────────────────────
    // Writes the row that Tier-1 dispute-driven scoring signals
    // (deviceDisputes, ipDisputes, emailDisputes, findSimilarDisputes in
    // riskScoring.js) depend on, via `disputes = await db.disputeOutcome
    // .findMany(...)` in routes/risk.js. Without this write, those four
    // signals were permanently inert — disputes was always [].
    //
    // disputeId: the simplified path has no separate Dispute entity, so we
    // reuse the merchant-facing orderId as the dispute identifier — this
    // matches how POST /risk/feedback already passes orderId as disputeId
    // into processFeedback().
    //
    // orderId (FK): DisputeOutcome.orderId relates to Order.id (the
    // internal cuid), NOT Order.orderId (the WooCommerce-facing id) — uses
    // order.id here, not the orderId variable, on purpose.
    //
    // Runs outside the M7 transaction above (that boundary is intentionally
    // scoped to merchantProfile/cardHash/signalStat only), but still before
    // the best-effort markOrderAsFraud/markPatternAsFraud calls below. A
    // P2002 here means a duplicate disputeId — this order's outcome was
    // already recorded by an earlier call — which the feedbackProcessedAt
    // gate above should already prevent in the normal case; this catch is
    // defense-in-depth for that constraint, treated as a second idempotency
    // guard: log informationally and continue, never throw.
    try {
      await db.disputeOutcome.create({
        data: {
          disputeId: orderId,
          merchantId,
          orderId: order.id,
          result: isWin ? 'won' : 'lost',
          signalsPresent: JSON.stringify(signals),
        },
      });
    } catch (disputeOutcomeErr) {
      if (disputeOutcomeErr.code === 'P2002') {
        logger.info(
          { module: 'feedbackLoop', orderId, merchantId },
          'DisputeOutcome already exists for this disputeId — skipping (idempotent)'
        );
      } else {
        logger.error(
          { module: 'feedbackLoop', orderId, merchantId, err: disputeOutcomeErr },
          'Failed to create DisputeOutcome'
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

      await markPatternAsFraud(patternOrder, emailIntel, ipIntel, merchantId, patternContext)
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