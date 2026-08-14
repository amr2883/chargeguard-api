// ─── ChargeGuard Feedback Loop ────────────────────────────────────────────
// Learning engine: dispute outcomes → signal weight updates
// Architecture: Bayesian Smoothing + Log-odds + Lazy Exponential Decay + Confidence Blending
// ─── Stubs for missing dependencies ─────────────────────────────────────
async function upsertCustomerRiskProfile(order, merchantId, result, db) {
  // معطل مؤقتًا - لا يوجد جدول CustomerRiskProfile
}


const crypto = require('crypto');
const db = require('./db');
const logger = require('../lib/logger');
// const { upsertCustomerRiskProfile } = require('./customerRiskProfile'); // معطل مؤقتًا
const { getWeightsForMerchant, DECAY_LAMBDA } = require('./signalWeights');
const { markOrderAsFraud } = require('./identityGraph');
const { markPatternAsFraud } = require('./patternSharing');


// ─── Constants ────────────────────────────────────────────────────────────
const SCORING_VERSION = "v1.0-logodds-confidence";

// [Global-tier NULL bug fix] Sentinel value لتمثيل "الإحصائية العامة
// (غير مرتبطة بتاجر معيّن)" بدل SQL NULL. مستخدمة في updateSignalStat()
// هنا، ولازم تطابق نفس القيمة بالحرف في signalWeights.js's
// getWeightsForMerchant() (القراءة). مستحيل تتصادم مع أي merchantId
// حقيقي — الـ Tenant.id بيتولّد بـ cuid() وصيغته مختلفة تمامًا
// (زي "clx4k2j8a0000...").
const GLOBAL_MERCHANT_ID = '__global__';

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
  // [Case-normalization fix — اكتشاف الجلسة] updateSignalStat() تحت
  // بتعمل .toUpperCase() على أي signalValue بلا شرط، لكل الإشارات، قبل
  // ما تقارنها بالقايمة دي وقبل ما تخزّنها في DB. القيم هنا كانت
  // lowercase ("high"/"medium"/"true") فكانت بترفض بصمت (log.warn
  // 'Rejected invalid signal') من غير ما تتسجل في SignalStat خالص، من
  // أول يوم اتضافت فيه — .includes() على array lowercase مقابل قيمة
  // uppercase ترجع false دايمًا. صُححت لتطابق فعليًا القيمة بعد التطبيع.
  // "critical" أُضيفت لـ DEVICE_VELOCITY (تدريج count=3+ كان مفقود
  // بالكامل — راجع فيكس extractSignalsFromSnapshot تحت). IP_BURST مفتاح
  // جديد بالكامل — نفس السبب.
  DEVICE_VELOCITY:   ["HIGH", "MEDIUM", "CRITICAL"],
  IP_VELOCITY:       ["HIGH", "MEDIUM"],
  IP_BURST:          ["TRUE"],
  EMAIL_VELOCITY:    ["HIGH"],
  SHIPPING_BILLING_MISMATCH: ["TRUE"],
  // [Case-normalization fix] راجع نفس الشرح فوق — كانت مرفوضة بصمت.
  BIN_ISSUER_MISMATCH: ["TRUE"],
  AMOUNT_ANOMALY:    ["TRUE"],
  // [BIN Velocity learning-loop wiring — أهم إشارة كارد تيستنج في
  // المشروع كله] الثلاث تدريجات دي if/else-if في riskScoring.js — أوردر
  // واحد بيطلق واحدة بس منهم كحد أقصى، فمعاملتهم كإشارات boolean مستقلة
  // (نفس نمط IP_BURST) صحيحة، مش تدريج متعدد المستويات زي DEVICE_VELOCITY.
  BIN_VELOCITY_10MIN: ["TRUE"],
  BIN_VELOCITY_1H:    ["TRUE"],
  BIN_VELOCITY_24H:   ["TRUE"],
  // [SignalStat cardinality fix] كانت غايبة تمامًا من هذا الـ whitelist —
  // extractSignalsFromSnapshot() بتستخرج IP_COUNTRY (أي كود دولة موجود
  // في العالم)، BIN_COUNTRY، وBIN_BRAND، وبتتكتب في SignalStat بلا أي
  // قيد (الشرط `VALID_SIGNAL_VALUES[signalType] && !...includes()` كان
  // بيرجع false تلقائيًا لغياب المفتاح، يعني مفيش رفض خالص). ده تضخم
  // cardinality بلا حدود شغال في الإنتاج دلوقتي، مستقل تمامًا عن أي قرار
  // getW(). القوائم هنا مطابقة لنفس الدول/البراندات المُعرّفة فعليًا في
  // STATIC_WEIGHTS (signalWeights.js) وCOUNTRY_RISK_TIERS (countryRisk.js)
  // — أي دولة/براند غير موجود هنا بيتم رفضه بصمت (log.warn) بدل ما يتكتب.
  // [BIN_COUNTRY completeness fix] أضيفت RO/UA — راجع التعليق المقابل في
  // signalWeights.js.
  BIN_COUNTRY:       ["NG", "CM", "GH", "PK", "BD", "VN", "ID", "PH", "RO", "UA"],
  BIN_BRAND:         ["VISA", "MASTERCARD", "AMEX", "DISCOVER"],
  IP_COUNTRY:        ["NG", "CM", "GH", "PK", "BD", "VN", "ID", "PH", "RO", "UA"],
  // [Case-normalization fix — Card Testing scope] نفس علة DEVICE_VELOCITY/
  // IP_VELOCITY المُصلَّحة قبل كده بالحرف: updateSignalStat() تحت بتعمل
  // .toUpperCase() بلا شرط على أي signalValue قبل ما تقارنها بالقايمة دي.
  // القيم كانت lowercase ("true") بينما extractSignalsFromSnapshot() بتبعت
  // 'true' برضو (lowercase) — بعد التطبيع بيبقى "TRUE"، و.includes("TRUE")
  // على array فيها "true" ترجع false دايمًا. النتيجة: IP_BOT/EMAIL_DISPOSABLE/
  // EMAIL_FREE_PROVIDER/EMAIL_DOMAIN_* كانت بترفض بصمت (log.warn 'Rejected
  // invalid signal') من أول يوم اتضافت فيه — صفر صف وصل SignalStat خالص.
  // مطابقة الآن لما فعليًا هيتسجل بعد الـ .toUpperCase().
  IP_BOT:            ["TRUE"],
  EMAIL_DISPOSABLE:       ["TRUE"],
  EMAIL_FREE_PROVIDER:    ["TRUE"],
  EMAIL_DOMAIN_NOT_FOUND:  ["TRUE"],
  EMAIL_DOMAIN_UNVERIFIED: ["TRUE"],
  EMAIL_DOMAIN_NO_MX:      ["TRUE"],
};

async function updateSignalStat(merchantId, signalType, signalValue, isWin, dbClient = db) {
  const normalizedValue = String(signalValue).trim().toUpperCase();

  // Signal whitelisting — يمنع injection signals غلط في DB
  if (VALID_SIGNAL_VALUES[signalType] && !VALID_SIGNAL_VALUES[signalType].includes(normalizedValue)) {
    logger.warn({ module: 'feedbackLoop', signalType, signalValue: normalizedValue }, 'Rejected invalid signal');
    return;
  }

  const scopedMerchantId = merchantId ?? null;
  const winIncrement  = isWin ? 1 : 0;
  const lossIncrement = isWin ? 0 : 1;
  const newId = crypto.randomUUID();

  // [lastDecayAt fix] الكود القديم كان بيحدّث lastDecayAt = now() في كل
  // استدعاء (create وupdate الاتنين) — ده كان بيكسر معنى الـ decay
  // بالكامل: applyDecay() في signalWeights.js بتحسب daysSince = now -
  // lastDecayAt وبتطبّقه على *كل* الـ rawWins/rawLosses التراكمية من أول
  // يوم. لو lastDecayAt بيتحدّث مع كل حدث جديد، أي إشارة نشطة (زي IP_TOR
  // وقت هجوم حقيقي) هتفضل daysSince ≈ 0 دايمًا وقت القراءة — يعني الـ
  // decay بيتوقف فعليًا عن أي تأثير عليها، بينما الإشارات الهادئة بس هي
  // اللي بتتأثر. ده معكوس الغرض الأساسي (تقليل تأثير بيانات قديمة، مش
  // حديثة) — وأخطر ما يكون بالظبط في الإشارات الأهم لمشروع الكارد
  // تيستنج (IP_TOR, IP_DATACENTER, BIN_PREPAID).
  //
  // الفيكس: "decay-then-accumulate" ذرّي في statement واحد (INSERT ...
  // ON CONFLICT DO UPDATE). Postgres بيقيّم كل تعبيرات SET ضد قيمة الصف
  // *قبل* التحديث (مش ضد بعضها البعض) — يعني "SignalStat"."rawWins" في
  // المعادلة تحت هي القيمة القديمة بالظبط، فمفيش أي read-then-write race
  // حتى مع كتّاب متزامنين على نفس الصف (Postgres بيقفل الصف وقت الـ
  // UPDATE زي أي UPDATE عادي — مفيش داعي لـ row locking يدوي). كل حدث
  // جديد: decay القيمة القديمة على قد الوقت اللي فات من آخر لمسة فعلية
  // للصف، يضيف +1 للفوز أو الخسارة، يحدّث lastDecayAt = now(). ده
  // بالتحديد تعريف "lazy exponential decay accumulator" الصحيح — نفس
  // المعنى اللي applyDecay() في signalWeights.js مبنية عليه من الأول.
  // الطبقتين (هنا وقت الكتابة، وapplyDecay وقت القراءة) بيتكاملوا مع
  // بعض صح رياضيًا: exp(-λd1) × exp(-λd2) = exp(-λ(d1+d2))، فمفيش أي
  // double-decay — كل طبقة بتغطي فترة زمنية مختلفة (من آخر event لآخر
  // event، ومن آخر event لحظة القراءة).
  //
  // DECAY_LAMBDA مستوردة من signalWeights.js (مصدر واحد للحقيقة) بدل ما
  // تتكرر كرقم منفصل هنا — أي تغيير هناك بينعكس هنا تلقائيًا من غير drift.
  //
  // id بيتولّد يدويًا (crypto.randomUUID()) لأن @default(cuid()) في الـ
  // schema بيتطبّق client-side جوه Prisma's fluent API بس — $executeRaw
  // بيتخطاه، فلازم نجهزه إحنا قبل الـ INSERT.
  await dbClient.$executeRaw`
    INSERT INTO "SignalStat" (
      "id", "merchantId", "signalType", "signalValue",
      "rawWins", "rawLosses", "totalEvents", "confidence",
      "lastDecayAt", "createdAt", "updatedAt"
    )
    VALUES (
      ${newId}, ${scopedMerchantId}, ${signalType}, ${normalizedValue},
      ${winIncrement}, ${lossIncrement}, 1, 0.5,
      now(), now(), now()
    )
    ON CONFLICT ("merchantId", "signalType", "signalValue")
    DO UPDATE SET
      "rawWins" = "SignalStat"."rawWins"
        * exp(-${DECAY_LAMBDA}::float8 * (EXTRACT(EPOCH FROM (now() - COALESCE("SignalStat"."lastDecayAt", "SignalStat"."createdAt"))) / 86400.0))
        + ${winIncrement},
      "rawLosses" = "SignalStat"."rawLosses"
        * exp(-${DECAY_LAMBDA * 0.5}::float8 * (EXTRACT(EPOCH FROM (now() - COALESCE("SignalStat"."lastDecayAt", "SignalStat"."createdAt"))) / 86400.0))
        + ${lossIncrement},
      "totalEvents" = "SignalStat"."totalEvents" + 1,
      "lastDecayAt" = now(),
      "updatedAt" = now()
  `;
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
          // [Global-tier NULL bug fix] كانت merchantId=null — الـ unique
          // constraint (@@unique([merchantId, signalType, signalValue]))
          // في Postgres بيتجاهل NULL كمعيار مطابقة (NULL ≠ NULL في فحص
          // الـ unique index)، يعني كل استدعاء بـ merchantId=null كان
          // هيعمل INSERT صف جديد بدل UPDATE على الصف الموجود، فتتراكم
          // آلاف الصفوف المكررة بمرور الوقت بدل صف واحد مجمّع لكل إشارة.
          // اتأكدنا إن الجدول فاضي تمامًا حاليًا (صفر صفوف، صفر
          // DisputeOutcome) — يعني الفيكس ده بيتطبّق قبل أي بيانات
          // تتجمع، فمفيش أي migration/دمج مطلوب. GLOBAL_MERCHANT_ID قيمة
          // ثابتة (مش NULL) فالـ unique constraint هتشتغل صح تلقائيًا.
          await updateSignalStat(GLOBAL_MERCHANT_ID, signal.type, signal.value, isWin, tx);
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
    // [Granularity fix] بديل EMAIL_DOMAIN_INVALID الخام — بيطابق فروع
    // calculateEmailPenalty() في emailIntelligence.js حرفيًا (نفس شروط
    // domainExists/uncertain/hasMX)، بدل شرط واحد كان بيخلط حالتين
    // ويترك حالة تالتة عمياء تمامًا. snapshot.emailIntel هنا هو نفس شكل
    // نتيجة getEmailIntelligence() (مخزّن كامل في signalsSnapshot.emailIntel
    // عبر risk.js)، فكل الحقول دي متاحة.
    if (snapshot.emailIntel.domainExists === false && snapshot.emailIntel.uncertain !== true) {
      signals.push({ type: 'EMAIL_DOMAIN_NOT_FOUND', value: 'true' });
    } else if (snapshot.emailIntel.domainExists === false && snapshot.emailIntel.uncertain === true) {
      signals.push({ type: 'EMAIL_DOMAIN_UNVERIFIED', value: 'true' });
    } else if (snapshot.emailIntel.hasMX === false && snapshot.emailIntel.uncertain !== true) {
      signals.push({ type: 'EMAIL_DOMAIN_NO_MX', value: 'true' });
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
    // [IP_BOT wiring] كانت غايبة تمامًا — isBot عندها عقوبة فعلية شغالة في
    // calculateIPPenalty() من زمان (راجع ipIntelligence.js) لكن التعلّم
    // منها ما بدأش خالص لغياب هذا السطر.
    if (snapshot.ipIntel.isBot) {
      signals.push({ type: 'IP_BOT', value: 'true' });
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

  // Connected risk signal — [threshold fix] riskScoring.js's الفعلي
  // بيبدأ العقوبة من `graphRisk > 10` — العتبة القديمة هنا (>30) كانت
  // بتفوّت كل النطاق من 11 لـ30 رغم إنه بياخد عقوبة فعلية (لحد -30).
  if (snapshot.connectedRisk > 10) {
    signals.push({ type: 'GRAPH_RISK_HIGH', value: 'true' });
  }

  // ===== الإشارات الجديدة =====
  // [Card-testing signal fidelity fix] كانت الكتلتين تحت بتخترعوا تدريج
  // medium/high مش له أساس في riskScoring.js الحقيقي — مطابقة دلوقتي
  // بالحرف. القيم لسه lowercase هنا (زي ما كانت) — مفيش داعي uppercase
  // في الاستخراج نفسه، updateSignalStat() بتطبّعها بعد كده تلقائيًا.

  // Device velocity — [fix] كانت بتبدأ من count>=2، وبتخلط count=2
  // وcount=3+ تحت "high" واحدة، وبتتجاهل count=1 تمامًا رغم إنه بياخد
  // عقوبة فعلية (-15). دلوقتي مطابقة لتدريج riskScoring.js's
  // deviceVelocityCount بالحرف: medium=1(-15), high=2(-25), critical=3+(-40)
  // — نفس القيم المستخدمة في topSignals هناك بالظبط.
  if (snapshot.deviceVelocityCount >= 3) {
    signals.push({ type: 'DEVICE_VELOCITY', value: 'critical' });
  } else if (snapshot.deviceVelocityCount === 2) {
    signals.push({ type: 'DEVICE_VELOCITY', value: 'high' });
  } else if (snapshot.deviceVelocityCount === 1) {
    signals.push({ type: 'DEVICE_VELOCITY', value: 'medium' });
  }

  // IP velocity — [fix] riskScoring.js's ipVelocityCount>=2 gate صيغة
  // log2 مستمرة بسيفريتي واحدة "high" بس دايمًا — مفيش تدريج medium
  // حقيقي خالص. التدريج القديم هنا (count>=3→'high' وإلا 'medium') كان
  // اختراع بلا أساس في الكود الحقيقي.
  if (snapshot.ipVelocityCount >= 2) {
    signals.push({ type: 'IP_VELOCITY', value: 'high' });
  }

  // IP burst — [إشارة جديدة] كانت غايبة بالكامل. riskScoring.js's
  // "sustained_ip_burst" override (ipVelocityCount>=10 → -50, critical،
  // topSignals type "IP_BURST") بيتفعّل بـ if مستقل (مش else-if) جنب
  // بلوك IP_VELOCITY فوق — الاتنين بيطبّقوا مع بعض على نفس الحدث،
  // فتسجيلهم مع بعض هنا صحيح ومطابق للواقع، مش تكرار.
  if (snapshot.ipVelocityCount >= 10) {
    signals.push({ type: 'IP_BURST', value: 'true' });
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

  // [BIN Velocity learning-loop wiring] if/else-if مطابق بالحرف لنفس
  // الأولوية المستخدمة في riskScoring.js (10min > 1h > 24h) — أوردر
  // واحد بيولّد إشارة واحدة بس، تعكس بالظبط التدريج اللي فعليًا طبّق
  // العقوبة على هذا الأوردر، مش كل التدريجات اللي تحقق شرطها.
  if (snapshot.binVelocityCount10min >= 2) {
    signals.push({ type: 'BIN_VELOCITY_10MIN', value: 'true' });
  } else if (snapshot.binVelocityCount1h >= 3) {
    signals.push({ type: 'BIN_VELOCITY_1H', value: 'true' });
  } else if (snapshot.binVelocityCount24h >= 5) {
    signals.push({ type: 'BIN_VELOCITY_24H', value: 'true' });
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