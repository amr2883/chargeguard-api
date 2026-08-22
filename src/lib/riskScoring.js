// ─── ChargeGuard Risk Scoring Engine ──────────────────────────────────────
// Tier 1: Definitive | Tier 2: Strong | Tier 3: Contextual
// v2: Integrated with Learning System (SignalWeights + RiskEvaluation)

const db = require('../lib/db');
const { getWeightsForMerchant, getStaticWeight, getLearnedMultiplier } = require('./signalWeights');
const { getConnectedRisk } = require('./identityGraph');
const { normalizeEmail } = require('../lib/utils');
const { computeNormalizedValue } = require('./blacklistGate');
const { getIPIntelligence, calculateIPPenalty } = require('./ipIntelligence');
const { getEmailIntelligence, calculateEmailPenalty, invalidateEmailCache } = require('./emailIntelligence');
const { findSimilarDisputes } = require('./similarity');
const { checkPatternRisk, recordPattern } = require('./patternSharing');
const logger = require('../lib/logger');

const { getBINIntelligence, calculateBINPenalty } = require('./binIntelligence');

const SCORING_VERSION = "v1.0-logodds-confidence";

// ─── Shared Threshold Calculator ─────────────────────────────────────────
// Single source of truth للـ thresholds — يستخدمها calculateRiskScore و rescoreOrder
// يمنع inconsistency لو الـ logic اتغير في مكان واحد بس
function calculateThresholds(orderAmount, merchantProfile, allOrders = []) {
  const logScale = orderAmount > 0
    ? Math.min(Math.log(orderAmount) * 2.0, 20)
    : 0;

  const { adjustment: merchantAdjustment } = getMerchantAdjustment(merchantProfile);

  let approveThreshold = Math.round(62 + logScale + merchantAdjustment);
  approveThreshold = Math.min(90, Math.max(60, approveThreshold));

  const reviewThresholdBase = Math.round(32 + (merchantAdjustment * 0.7));

  let fatigueAdjustment = 0;
  if (allOrders.length >= 20) {
    const recent100 = [...allOrders]
      .filter(o => o.riskLevel !== "high")
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 100);
    const mediumCount = recent100.filter(o => o.riskLevel === "medium").length;
    const reviewRate = recent100.length > 0 ? mediumCount / recent100.length : 0;

    if (reviewRate > 0.20) fatigueAdjustment = 8;
    else if (reviewRate > 0.15) fatigueAdjustment = 4;
    fatigueAdjustment = Math.min(fatigueAdjustment, 8);
  }

  const reviewThreshold = Math.min(80, Math.max(40, reviewThresholdBase + fatigueAdjustment));

  return { approveThreshold, reviewThreshold };
}

// ─── Email Normalization ───────────────────────────────────────────────────
// normalizeEmail moved to utils.js — re-exported here for
// backward compatibility with all existing consumers
// normalizeEmail is already imported from utils

// ─── Static Score (old system — for comparison) ───────────────────────────
// Exact copy of original logic — used as baseline in RiskEvaluation
function calculateStaticPositives(order) {
  let bonus = 0;
  if (order.eciCode && ["5", "6"].includes(order.eciCode)) bonus += 20;
  if (order.avsResponse === "Y") bonus += 10;
  if (order.cvv2Response === "M") bonus += 8;
  return bonus;
}

// ─── Merchant Risk Context ────────────────────────────────────────────────
// بيحسب تعديل الـ thresholds بناءً على أداء التاجر التاريخي
// تاجر fraud rate عالي → thresholds أعلى (أكثر صرامة)
// تاجر fraud rate منخفض → thresholds أقل (أقل false positives)

function getMerchantAdjustment(profile) {
  if (!profile || profile.totalOrders < 20) {
    return { adjustment: 0, reason: null };
  }

  // Fraud rate مع smoothing — يمنع overreaction للتجار الصغيرين
  // لو أقل من 50 order → نضيف smoothing factor
  // Bayesian smoothing continuous — بدون cliff عند 50
  // prior = 1 dispute في 20 orders (industry average ~5%)
  // كل ما زاد totalOrders، تأثير الـ prior بيقل تدريجياً
  const fraudRate = (profile.totalDisputes + 1) / (profile.totalOrders + 20);

  // Semi-continuous adjustment — أدق من buckets
  // 1% → 0, 3% → +4, 5% → +8, < 0.5% → -4
  let adjustment = Math.min(8, Math.max(-4, (fraudRate - 0.01) * 200));

  // Win rate modifier — Bayesian smoothing يمنع overreaction على عينة صغيرة
  // Prior: 2 wins, 3 losses → prior winRate = 0.4 (industry average ~40%)
  // تاجر بـ dispute واحدة وخسرها → smoothed winRate = 2/6 = 0.33 مش 0
  // تاجر بـ 10 disputes وخسر كلهم → smoothed winRate = 2/15 = 0.13
  const PRIOR_WINS   = 2;
  const PRIOR_LOSSES = 3;
  const smoothedWinRate = (profile.wonDisputes + PRIOR_WINS) /
    (profile.totalDisputes + PRIOR_WINS + PRIOR_LOSSES);
  if (smoothedWinRate < 0.3) adjustment += 2;

  // Volume confidence — تاجر عنده 10 orders ≠ تاجر عنده 1000
  const confidence = Math.min(1, profile.totalOrders / 500);
  adjustment = adjustment * confidence;

  // Round to 1 decimal
  adjustment = Math.round(adjustment * 10) / 10;

  // Explainability reason
  let reason = null;
  if (fraudRate > 0.03) {
    reason = `High merchant fraud rate (${(fraudRate * 100).toFixed(1)}%) — thresholds tightened`;
  } else if (fraudRate < 0.005 && profile.totalOrders >= 50) {
    reason = `Excellent merchant fraud rate (${(fraudRate * 100).toFixed(1)}%) — thresholds relaxed`;
  }

  return { adjustment, reason };
}

// ─── Economic Fraud Engine ────────────────────────────────────────────────
// بيحول القرار من "هل ده fraud؟" لـ "هل يستاهل المخاطرة مالياً؟"
// Sigmoid probability بدل linear — أقرب للواقع
// Dynamic threshold بناءً على AOV و order value
// Asymmetric overrides — strict في الرفع، lenient في النزول

const SIGMOID_SCALE = 10;  // configurable — يتغير مع calibration

function scoreToProbability(score, merchantFraudRate = 0) {
  // Sigmoid calibration — non-linear risk
  const x = (score - 50) / SIGMOID_SCALE;
  const rawProb = 1 / (1 + Math.exp(x));

  // Dynamic floor بناءً على merchant fraud rate
  // تاجر high-risk → floor أعلى (أكثر حذراً)
  const baseMin    = 0.005;
  const maxMin     = 0.02;
  const riskFactor = Math.min(1, merchantFraudRate / 0.05);
  const dynamicMin = baseMin + (maxMin - baseMin) * riskFactor;

  return Math.max(rawProb, dynamicMin);
}

function calculateEconomicRisk(score, orderAmount, merchantProfile) {
  const merchantFraudRate = merchantProfile?.totalOrders >= 20
    ? (merchantProfile.totalDisputes || 0) / merchantProfile.totalOrders
    : 0;

  const fraudProb    = scoreToProbability(score, merchantFraudRate);
  const expectedLoss = fraudProb * orderAmount;

  // Dynamic threshold — يشمل AOV والـ order الحالي
  // يمنع AOV صغير يعمل threshold ضعيف لـ orders كبيرة
  const avgOrderValue   = merchantProfile?.avgOrderValue || 50;
  const baseThreshold   = Math.max(20, Math.max(avgOrderValue, orderAmount * 0.3) * 0.8);

  // Clamp — يمنع extreme decisions
  const safeLoss = Math.min(expectedLoss, baseThreshold * 3);

  return { fraudProb, expectedLoss, safeLoss, baseThreshold, merchantFraudRate };
}

// ─── Main Scoring Function ────────────────────────────────────────────────
// merchantId: optional — if provided, uses learned weights
// saveEvaluation: if true, saves to RiskEvaluation table (flight recorder)
async function calculateRiskScore(
  order,
  allOrders,
  disputes,
  blacklist = [],
  merchantId = null,
  saveEvaluation = true,
  externalVelocity = null,   // { deviceVelocityCount, ipVelocityCount, emailVelocityCount }
  cardHashRecord = null,     // ← إضافة معامل cardHashRecord
  merchantConfig = null,     // ← merchant country overrides
  limitedScoring = false,    // ← true when caller's monthly quota is exhausted:
                             //   skip expensive external intel (IP/email/BIN),
                             //   everything else still runs at full strength.
) {
    let score = 100;
  let sameIPOrders = [];
  let sameEmailOrders = [];
  const flags = [];
  const positives = [];
  const topSignals = []; // top contributing signals for flight recorder

  // Normalized email — يمنع +alias و dot bypass
  const email = normalizeEmail(order.email);
  const ip = order.ipAddress || "";
  const deviceId = order.deviceFingerprint || order.deviceId || "";

  // [Discovery 2 fix] BIN لازم تتحسب هنا فوق، مش عند binRaw تحت (قسم IP
  // Intelligence) — inBlacklist في Tier 1 تحت محتاجها قبل نقطة تعريف
  // binRaw بمراحل طويلة. نفس نمط earlyHasCorroboration/earlyDeviceTrustFactor
  // تحت (إعادة حساب مبكرة من نفس المصدر بدل إعادة ترتيب الفنكشن كله).
  // Digit-strip + slice(0,6) نفس منطق enrichmentProcessor.js's
  // cardBinPrefix — مش نفس binPrefix المُعرّف لاحقًا في قسم BIN Velocity
  // (ده من غير strip، ومُعرّف بعد نقطة استخدام inBlacklist بمراحل).
  const earlyOrderBin = order.payment_details?.card_bin ?? order.payment_details?.credit_card_bin ?? null;
  const earlyBinPrefix = earlyOrderBin ? String(earlyOrderBin).replace(/\D/g, '').slice(0, 6) : null;

  // TDZ FIX (hotfix): isNewEmail لازم تتحسب هنا، فور توفر `email`، لأن
  // بلوك deviceDisputes في Tier 1 تحت بيقراها عن طريق earlyHasCorroboration
  // قبل نقطة تعريفها الأصلية (اللي كانت قبل كده قريبة من isNewDevice، بعد
  // مئات السطور). قراءة const قبل تعريفها بترمي ReferenceError (temporal
  // dead zone) — يعني أي أوردر من جهاز عليه dispute خاسرة سابقة كان بيكرش
  // الفنكشن بالكامل، وده بيتسبب كمان في فتح الـ circuit breaker في الـ
  // WordPress plugin بعد 3 فشلات متتالية (راجع request_with_breaker في
  // class-api-client.php) — يعني الحماية كلها بتتقفل مؤقتًا للمتجر كله،
  // مش بس للجهاز ده. التعريف الأصلي (دوّر على isNewDevice) اتشال، وده
  // بقى المصدر الوحيد للمتغيّر ده.
  const isNewEmail = !allOrders.some(o =>
    normalizeEmail(o.email) === email && o.id !== order.id
  );
  const shippingAddr = (() => {
    try { return JSON.parse(order.shippingAddress || "{}"); } catch { return {}; }
  })();
  const billingAddr = (() => {
    try { return JSON.parse(order.billingAddress || "{}"); } catch { return {}; }
  })();
  const last1h = new Date(Date.now() - 60 * 60 * 1000);
  const last6h = new Date(Date.now() - 6 * 60 * 60 * 1000);
  const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

  // [P0 fix] الـ duplicate declaration اللي كانت هنا اتشالت — isNewEmail
  // بالفعل معرّفة فوق (راجع تعليق "TDZ FIX (hotfix)" قبل شويّة، قبل
  // shippingAddr). كان فيه نسختين `const isNewEmail` في نفس الـ function
  // scope، وده SyntaxError وقت التحميل (Identifier 'isNewEmail' has
  // already been declared) — مش runtime error شرطي زي الـ bug الأصلي، ده
  // كان بيمنع الملف كله من إنه يتحمّل بـ require()، يعني الـ backend كان
  // مش هيقدر يقوم خالص. التعليق القديم هنا كان بيوصف نية صحيحة (نقل
  // التعريف لأول الفنكشن) لكن التنفيذ نسي يمسح النسخة القديمة.

  // ─── Intel Results Cache ───────────────────────────────────────────────
  // محفوظين هنا عشان الـ pattern sharing يستخدمهم بدون API calls جديدة
  let ipIntelResult    = null;
  let emailIntelResult = null;
  let binIntelResult   = null;

  // ─── Bot Score from Pixel ─────────────────────────────────────────────
  // الـ botScore بيجي من الـ Web Pixel — مش متاح في الـ webhook
  // بنجيبه من PixelEvent لو موجود
  // DB معطل مؤقتًا
  let pixelBotScore  = 0;
  let pixelSuspicious = false;

  // ─── Load Learned Weights ──────────────────────────────────────────────
  // If merchantId provided → use learned weights
  // Otherwise → use static weights (cold start)
  let weights = null;
  let isLearning = false;

  if (merchantId) {
    try {
      const weightData = await getWeightsForMerchant(merchantId);
      weights = weightData.weights;
      isLearning = weightData.isLearning;
    } catch (e) {
      logger.error({ module: 'riskScoring', err: e }, 'Failed to load weights, using static');
    }
  }

  // Helper — gets effective weight for a signal
  // Falls back to static if no learned weight available
  const getW = (signalType, signalValue) => {
    if (weights) return weights[`${signalType}:${signalValue}`] ?? getStaticWeight(signalType, signalValue);
    return getStaticWeight(signalType, signalValue);
  };

  // ─── Tier 1 — Definitive ───────────────────────────────────────────────

  // ─── Bot Detection Penalty ───────────────────────────────────────────
  // بيجي من الـ Web Pixel — أقوى signal لأنه client-side behavior
  // pixelBotScore scale: 0–100 (combinedBotScore from Phase B)
  // suspicious = webdriver detected أو behavioral score >= 20
  if (pixelSuspicious) {
    score -= 40;
    flags.push({
      severity: "critical",
      text: "bot_detected",
    });
    topSignals.push({ type: "BOT", value: "suspicious", contribution: -40 });
  } else if (pixelBotScore >= 80) {
    score -= 40;
    flags.push({
      severity: "critical",
      text: "bot_detected",
    });
    topSignals.push({ type: "BOT", value: "suspicious", contribution: -40 });
  } else if (pixelBotScore >= 20) {
    score -= 15;
    flags.push({
      severity: "medium",
      text: "bot_suspicious",
    });
    topSignals.push({ type: "BOT", value: "elevated", contribution: -15 });
  }

  // [Discovery 1 fix] كانت بتقارن b.email/b.ip/b.deviceId — حقول مش
  // موجودة أصلاً على BlacklistEntry (الـ schema الحقيقي: type/value/
  // normalizedValue، راجع blacklistGate.js). كانت dead code دايمًا —
  // .some() ترجع false مهما كان محتوى blacklist. المطابقة دلوقتي صحيحة
  // ضد الـ shape الفعلي. عمليًا هذا الفحص الآن defense-in-depth بس، مش
  // الدفاع الأساسي: /evaluate و/woocommerce-webhook الاتنين بيوقفوا
  // الطلب بـ 403 قبل ما يوصلوا هنا لو فيه تطابق (راجع risk.js's early
  // gates)، فـ blacklist هنا بيوصل فاضي دايمًا من المسارين المعروفين —
  // لكن أي caller مستقبلي لـ calculateRiskScore() من غير early gate
  // خاص بيه (مثال: rescoreOrder() لو اتفعّلت) هيستفيد من الحماية دي
  // فعليًا بدل ما تكون فخ صامت.
  const inBlacklist = blacklist.some(b => {
    if (!b || !b.type) return false;
    const bNormalized = b.normalizedValue ?? computeNormalizedValue(b.type, b.value);
    if (b.type === 'EMAIL')              return !!email && bNormalized === email;
    if (b.type === 'IP')                 return !!ip && bNormalized === String(ip).trim();
    if (b.type === 'DEVICE_FINGERPRINT') return !!deviceId && bNormalized === String(deviceId).trim();
    // [Discovery 2 fix] كانت BIN غايبة من هذا الفحص خالص — نفس فئة باگ
    // Discovery 1 الأصلي (حقل مدعوم في الـ schema بس مش متفحّص فعليًا).
    // defense-in-depth بس حاليًا: الـ 3 callers المعروفين (evaluate،
    // webhook، enrich) بيمرروا blacklist=[] دايمًا — enrichmentProcessor.js
    // دلوقتي عنده early BIN gate خاص بيه قبل ما يوصل هنا خالص — لكن أي
    // caller مستقبلي من غير early gate هيستفيد من الحماية دي فعليًا بدل
    // ما تكون فخ صامت تاني.
    if (b.type === 'BIN')                return !!earlyBinPrefix && bNormalized === earlyBinPrefix;
    return false;
  });
  if (inBlacklist) {
    score -= 80;
    flags.push({ severity: "critical", text: "Customer is on the fraud blacklist" });
  }

  const deviceDisputes = disputes.filter(d =>
    d.order?.deviceFingerprint === deviceId && deviceId && d.result === "lost"
  );
  if (deviceDisputes.length > 0) {
    // deviceTrustFactor is computed further below (deviceVelocityCount
    // section) — but disputes are evaluated here, earlier in the function.
    // Recomputed inline from the same inputs rather than reordering the
    // whole function, since only this one early penalty needs it before
    // the main deviceTrustFactor block runs.
    const earlyHasCorroboration = !isNewEmail; // ipVelocityCount/emailVelocityCount not yet computed at this point in the function
    const earlyDeviceTrustFactor = merchantConfig?.deviceSignal
      ? (merchantConfig.deviceSignal.trust === 'signed' ? 1.0
        : merchantConfig.deviceSignal.trust === 'signed_ip_mismatch' ? 0.85
        : earlyHasCorroboration ? 0.75 : 0.4)
      : 1.0;
    const disputePenalty = Math.round(60 * earlyDeviceTrustFactor);
    score -= disputePenalty;
    flags.push({ severity: earlyDeviceTrustFactor >= 0.75 ? "critical" : "high", text: "device_dispute_history" });
    topSignals.push({ type: "DEVICE_DISPUTE", value: "lost", contribution: -disputePenalty });
  }

  const ipDisputes = disputes.filter(d =>
    d.order?.ipAddress === ip && ip && d.result === "lost"
  );
  if (ipDisputes.length >= 3) {
    score -= 50;
    flags.push({ severity: "critical", text: "ip_dispute_network" });
    topSignals.push({ type: "IP_DISPUTE_NETWORK", value: ipDisputes.length, contribution: -50 });
  }

  // ─── Tier 2 — Strong ──────────────────────────────────────────────────

  // ─── IP Intelligence ──────────────────────────────────────────────────
  // بيستبدل الـ static Egyptian IPs list بـ real-time IP analysis
  // ─── Parallel Intel Calls ─────────────────────────────────────────────
  // IP + Email + BIN مستقلين تماماً — نشغلهم في نفس الوقت
  // Promise.allSettled يضمن إن فشل واحد مش بيوقف الباقيين
  const binRaw = order.payment_details?.card_bin ?? order.payment_details?.credit_card_bin ?? null;
  
  // limitedScoring: quota exhausted for this tenant — skip the three
  // external network calls entirely (cost + rate-limit protection), but
  // let every other detector below run at full strength. Skipped intel
  // resolves to `null`, which every downstream consumer already treats
  // as "no intel available" (see the ?? fallbacks a few lines down) —
  // no other code path needs to change.
  const [ipIntelSettled, emailIntelSettled, binIntelSettled] = await Promise.allSettled([
    (!limitedScoring && ip)      ? getIPIntelligence(ip, merchantId)         : Promise.resolve(null),
    limitedScoring                ? Promise.resolve(null)                    : getEmailIntelligence(email, merchantId),
    (!limitedScoring && binRaw)  ? getBINIntelligence(binRaw, merchantId)    : Promise.resolve(null),
  ]);

  // ─── IP Intel Result ──────────────────────────────────────────────────
  if (ipIntelSettled.status === 'fulfilled' && ipIntelSettled.value) {
    try {
      ipIntelResult = ipIntelSettled.value;
      const billingCountry = billingAddr.country?.toUpperCase() ?? null;
      // [Learning-loop wiring] getW مُمرّرة دلوقتي — getW معرّفة فوق (Helper
      // — gets effective weight for a signal) وبتستخدم weights المحمّلة
      // من getWeightsForMerchant() لو merchantId متاح، أو fallback لـ
      // getStaticWeight() (نفس القيم الثابتة القديمة) لو مش متاح — بالظبط
      // نفس النمط المستخدم بالفعل لـ ECI/AVS/CVV2 فوق.
      const { penalty: ipPenalty, flags: ipFlags } = calculateIPPenalty(
        ipIntelResult,
        order.amount || 0,
        billingCountry,
        getW,
      );
      if (ipPenalty > 0) {
        score -= ipPenalty;
        flags.push(...ipFlags);
        topSignals.push({ type: "IP", value: ipIntelResult.isDatacenter ? "datacenter" : "mismatch", contribution: -ipPenalty });
      }
    } catch (ipErr) {
      logger.error({ module: 'riskScoring', err: ipErr }, 'IP intelligence error');
    }
  } else if (ipIntelSettled.status === 'rejected') {
    logger.error({ module: 'riskScoring', err: ipIntelSettled.reason }, 'IP intelligence error');
  }

  if (shippingAddr.country && billingAddr.country && shippingAddr.country !== billingAddr.country) {
    score -= 15;
    // [Bug #4 fix] كانت جملة بشرية ("Shipping country differs from billing
    // country") بعكس كل الأعلام التانية في الملف (كلها snake_case).
    // risk.js's /evaluate كان بيدوّر على 'shipping_billing_mismatch'
    // بالظبط فمكنش بيلاقيها أبدًا — shippingBillingMismatch في
    // signalsSnapshot كانت دايمًا false. نفس السبب الجذري لـ Bug #10
    // (SHIPPING_BILLING_MISMATCH learning signal ميت) — التوحيد بيحل
    // الاتنين مرة واحدة.
    flags.push({ severity: "high", text: "shipping_billing_mismatch" });
  }


  // H2 fix: the early inline IP-velocity block (computed from the limited,
  // recency-capped `allOrders` sample) was removed from here. It duplicated
  // the externalVelocity-driven IP-velocity block further below — same
  // threshold, formula, cap, and flag text — causing every real evaluation
  // to apply this penalty twice (max -70 instead of the intended -35).
  // The externalVelocity-driven block, which uses an accurate DB-backed
  // count rather than this capped sample, is the one that remains.

  const otherOrders = allOrders.filter(o => o.id !== order.id);
  const avgOrderValue = otherOrders.length > 0
    ? otherOrders.reduce((s, o) => s + o.amount, 0) / otherOrders.length
    : 0;
  const orderMultiple = avgOrderValue > 0 ? order.amount / avgOrderValue : 0;
  const isHighValue = orderMultiple >= 3;
  // isNewEmail is now computed earlier in this function (right after
  // last1h/last6h/last24h) — see the TDZ crash fix comment there.

  // isNewDevice — device مش شفناه قبل كده
  const isNewDevice = !deviceId || !allOrders.some(o =>
    (o.deviceFingerprint === deviceId || o.deviceId === deviceId) && o.id !== order.id
  );

  // isNewCustomer — الاتنين جدد مع بعض
  // بيمنع attacker من bypass الـ penalty بتغيير الـ email بس مع device قديم
  const isNewCustomer = isNewEmail && isNewDevice;

  // highValuePenaltyApplied — بيمنع double penalty لو نفس الـ signal اتحسب تاني
  let highValuePenaltyApplied = false;

  if (avgOrderValue > 0) {
    if (orderMultiple >= 5) {
      const penalty = isNewCustomer ? 30 : 25;
      score -= penalty;
      highValuePenaltyApplied = true;
      flags.push({
        severity: "high",
        text: "order_value_extreme_anomaly",
      });
      topSignals.push({ type: "HIGH_VALUE", value: "extreme", contribution: -penalty });
    } else if (orderMultiple >= 3) {
      const penalty = isNewCustomer ? 20 : 10;
      const severity = isNewCustomer ? "high" : "medium";
      score -= penalty;
      highValuePenaltyApplied = true;
      flags.push({
        severity,
        text: isNewCustomer ? "new_customer_high_value_order" : "high_value_order",
      });
      topSignals.push({ type: "HIGH_VALUE", value: isNewCustomer ? "new_customer" : "returning", contribution: -penalty });
    }
  }

  // Bug fix: unlike deviceDisputes/ipDisputes just above (both filtered by
  // d.result === "lost"), this filter was missing the outcome check
  // entirely — meaning a customer who WON a prior dispute (proven
  // legitimate, evidence accepted) was penalized identically to one who
  // lost it. Winning a dispute is evidence of legitimacy, not fraud risk.
  const emailDisputes = disputes.filter(d =>
    normalizeEmail(d.order?.email) === email && email && d.result === "lost"
  );
  if (emailDisputes.length > 0) {
    score -= 30;
    flags.push({ severity: "high", text: "email_dispute_history" });
    topSignals.push({ type: "EMAIL_DISPUTE", value: "lost", contribution: -30 });
  }
// ─── Authenticated Account Signal ────────────────────────────────────────
  // customerLoginId = Shopify customer account ID (null for guest checkout)
  // بيعبر إن الـ customer عنده account حقيقي — مش guest
  // Trust signal في الـ initial scoring فقط — Post-purchase events للـ re-scoring
  const customerLoginId = order.customerLoginId ?? null;
  if (customerLoginId) {
    score += 5;
    positives.push({ text: "Authenticated Shopify account — not a guest checkout" });
  }


  // ─── Similarity Engine — Fuzzy Identity Detection ──────────────────────
  // بيكشف المحتال اللي بيغير بياناته بشكل طفيف
  // Penalty أقل من exact match — لأنه similarity مش certainty
  try {
    const emailDisputeIds = new Set(emailDisputes.map(d => d.id));
    const similar = findSimilarDisputes(
      email,
      ip,
      order.shippingAddress,
      disputes.filter(d => !emailDisputeIds.has(d.id)),
    );
        

    if (similar.similarEmail.length > 0) {
      score -= 15;
      flags.push({
        severity: "high",
        text: "email_similarity_match",
      });
    }

    if (similar.similarIP.length > 0 && similar.similarIP.length >= 2) {
      score -= 10;
      flags.push({
        severity: "medium",
        text: "ip_subnet_similarity",
      });
    }

    if (similar.similarAddr.length > 0) {
      score -= 10;
      flags.push({
        severity: "medium",
        text: "address_similarity_match",
      });
    }
  } catch (simErr) {
    // Non-critical — continue without similarity check
    logger.error({ module: 'riskScoring', err: simErr }, 'Similarity check error');
  }
  // ─── CardHash Penalty ─────────────────────────────────────────────────
  if (cardHashRecord) {
    const attemptBonus = Math.min(cardHashRecord.attemptCount * 5, 25);
    const blockBonus = cardHashRecord.blockCount > 0 ? 20 : 0;
    let cardPenalty = attemptBonus + blockBonus;
    if (cardPenalty > 0) {
      score -= cardPenalty;
      flags.push({
        severity: cardPenalty > 30 ? 'critical' : 'high',
        text: 'card_reuse_detected',
      });
      topSignals.push({ type: 'CARD_HASH', value: 'repeated', contribution: -cardPenalty });
    }
  }

  // ─── BIN Intel Result ─────────────────────────────────────────────────

if (binIntelSettled.status === 'fulfilled' && binIntelSettled.value) {
    try {
      binIntelResult = binIntelSettled.value;
      const binIntel = binIntelResult;
      const { penalty: binPenalty, flags: binFlags } = calculateBINPenalty(
        binIntel,
        { amount: order.amount, billingAddress: billingAddr },
        isNewCustomer,
        ipIntelResult,
        merchantConfig,
        getW,
      );
      if (binPenalty > 0) {
        score -= binPenalty;
        flags.push(...binFlags);
        topSignals.push({ type: "BIN", value: binIntel.isPrepaid ? "prepaid" : "mismatch", contribution: -binPenalty });
      }
    } catch (binErr) {
      logger.error({ module: 'riskScoring', err: binErr }, 'BIN intelligence error');
    }
  } else if (binIntelSettled.status === 'rejected') {
    logger.error({ module: 'riskScoring', err: binIntelSettled.reason }, 'BIN intelligence error');
  }

  // ─── Email Intelligence ────────────────────────────────────────────────
  // بيستبدل الـ static email rules بـ multi-layer email analysis:
  // Layer 1: HaveIBeenPwned (k-anonymity — privacy safe)
  // Layer 2: DNS domain validation
  // Layer 3: Enhanced rules (entropy, TLD risk, disposable)




  // ─── Email Intel Result ───────────────────────────────────────────────
  if (emailIntelSettled.status === 'fulfilled' && emailIntelSettled.value) {
    try {
      emailIntelResult = emailIntelSettled.value;
      const { penalty: emailPenalty, flags: emailFlags } = calculateEmailPenalty(
        emailIntelResult,
        order.amount || 0,
        isNewEmail,
        getW,
      );
      if (emailPenalty > 0) {
        score -= emailPenalty;
        flags.push(...emailFlags);
        topSignals.push({ type: "EMAIL", value: emailIntelResult.isDisposable ? "disposable" : "suspicious", contribution: -emailPenalty });
      }
    } catch (emailErr) {
      logger.error({ module: 'riskScoring', err: emailErr }, 'Email intelligence error');
      // Fallback: basic rules لو الـ processing فشل
      const emailDomain = email.split("@")[1]?.toLowerCase() || "";
      const disposableDomains = ["tempmail.com", "guerrillamail.com", "mailinator.com", "throwam.com", "trashmail.com", "fakeinbox.com"];
      if (disposableDomains.includes(emailDomain)) {
        score -= 35;
        flags.push({ severity: "critical", text: "disposable_email_domain" });
      }
    }
  } else if (emailIntelSettled.status === 'rejected') {
    logger.error({ module: 'riskScoring', err: emailIntelSettled.reason }, 'Email intelligence error');
  }

  // H2 fix: the early inline email-velocity block (computed from the
  // limited, recency-capped `allOrders` sample) was removed from here. It
  // duplicated the externalVelocity-driven email-velocity block further
  // below — same threshold, formula, cap, and flag text — causing every
  // real evaluation to apply this penalty twice (max -60 instead of the
  // intended -30). The externalVelocity-driven block, which uses an
  // accurate DB-backed count rather than this capped sample, is the one
  // that remains.

  // استخدام قيم السرعة من externalVelocity إذا وُجدت (أكثر دقة وأداء)
  let deviceVelocityCount = 0;
  let ipVelocityCount = 0;
  let emailVelocityCount = 0;
  if (externalVelocity) {
    deviceVelocityCount = externalVelocity.deviceVelocityCount || 0;
    ipVelocityCount = externalVelocity.ipVelocityCount || 0;
    emailVelocityCount = externalVelocity.emailVelocityCount || 0;
  } else {
    // احتياط: احسب من allOrders (أقل دقة)

    if (deviceId) {
      deviceVelocityCount = allOrders.filter(o =>
        (o.deviceFingerprint === deviceId || o.deviceId === deviceId) &&
        new Date(o.createdAt) > last1h &&
        o.id !== order.id
      ).length;
    }
    if (ip) {
      ipVelocityCount = allOrders.filter(o =>
        o.ipAddress === ip &&
        new Date(o.createdAt) > last24h &&
        o.id !== order.id
      ).length;
    }
    if (email) {
      emailVelocityCount = allOrders.filter(o =>
        normalizeEmail(o.email) === email &&
        new Date(o.createdAt) > last6h &&
        o.id !== order.id
      ).length;
    }
  }

  // ─── Device Trust Factor ───────────────────────────────────────────────
  // Scales how much weight device-anchored signals (dispute history,
  // "known trusted device" / "first-time device" heuristics, and the
  // identity-graph contribution below) carry, based on how forgeable this
  // request's device fingerprint is. Deliberately NOT applied to the
  // same-request DEVICE_VELOCITY block immediately below — repeating the
  // SAME fingerprint across a burst within one hour is a strong signal
  // regardless of forgeability (the attacker either reused a value or
  // failed to rotate), so that stays at full weight.
  //
  // merchantConfig.deviceSignal is set by risk.js's /evaluate handler.
  // Absent entirely on /enrich and /woocommerce-webhook (which don't
  // receive a deviceToken today) — deviceTrustFactor defaults to 1.0 in
  // that case, i.e. identical to pre-hardening behavior. This is what
  // makes the change backward compatible for un-upgraded plugin installs
  // and for call sites that don't pass merchantConfig at all.
  const deviceSignal = merchantConfig?.deviceSignal || null;
  const hasCorroboration = ipVelocityCount > 0 || emailVelocityCount > 0 || !isNewEmail;
  let deviceTrustFactor = 1.0;
  if (deviceSignal) {
    if (deviceSignal.trust === 'signed') {
      deviceTrustFactor = 1.0;
    } else if (deviceSignal.trust === 'signed_ip_mismatch') {
      deviceTrustFactor = 0.85;
    } else {
      // 'unsigned' (no token sent — un-upgraded plugin or pre-hardening
      // request) or 'invalid_token' (forged/expired/tampered token).
      deviceTrustFactor = hasCorroboration ? 0.75 : 0.4;
    }
  }

  // [Learning-loop wiring — Card Testing priority] كانت قيم ثابتة تمامًا
  // (40/25/15) بمعزل كامل عن نظام التعلّم — رغم إن DEVICE_VELOCITY أهم
  // إشارة كارد تيستنج كلاسيكية (تكرار نفس الجهاز بسرعة). الأرقام دي
  // مطابقة بالحرف لـ base القيم في STATIC_WEIGHTS
  // (DEVICE_VELOCITY:CRITICAL/HIGH/MEDIUM = 40/25/15)، فاستبدال مباشر
  // بـ getW() آمن 100%: عند cold start (صفر بيانات تعلّم) بترجع نفس
  // القيم الثابتة بالضبط — صفر أثر سلوكي وقت النشر. مع تراكم dispute
  // outcomes حقيقية، القيمة تتحرك جوه [0, base×3] (راجع
  // MAX_WEIGHT_MULTIPLIER في signalWeights.js).
  if (deviceVelocityCount >= 3) {
    const penalty = Math.round(getW("DEVICE_VELOCITY", "CRITICAL"));
    score -= penalty;
    flags.push({ severity: "critical", text: "device_velocity_blocked" });
    topSignals.push({ type: "DEVICE_VELOCITY", value: "critical", contribution: -penalty });
  } else if (deviceVelocityCount === 2) {
    const penalty = Math.round(getW("DEVICE_VELOCITY", "HIGH"));
    score -= penalty;
    flags.push({ severity: "high", text: "device_velocity_blocked" });
    topSignals.push({ type: "DEVICE_VELOCITY", value: "high", contribution: -penalty });
  } else if (deviceVelocityCount === 1) {
    const penalty = Math.round(getW("DEVICE_VELOCITY", "MEDIUM"));
    score -= penalty;
    flags.push({ severity: "medium", text: "device_velocity_blocked" });
    topSignals.push({ type: "DEVICE_VELOCITY", value: "medium", contribution: -penalty });
  }

  // [Learning-loop wiring — Card Testing priority] الـ 15 هنا معامل جوه
  // صيغة log2 مستمرة (مش عقوبة نهائية مباشرة) — استبدال كامل بـ getW()
  // كان هيمسح صيغة الـ log2 بالكامل ويحوّلها لقيمة ثابتة. بدل كده،
  // getLearnedMultiplier() بترجع *نسبة* (learned/staticBase) بتحرّك
  // المعامل الأصلي جوه نفس الصيغة — نفس نمط BIN_PREPAID في
  // binIntelligence.js بالحرف. عند cold start (getW بترجع نفس
  // static base) النسبة = 1.0 بالضبط، فالصيغة الأصلية (15 × log2)
  // تشتغل بلا أي تغيير سلوكي.
  //
  // الـ cap (35) يفضل *ثابت* عمدًا وغير متأثر بالـ multiplier — سقف أمان
  // معماري بيمنع انفجار عقوبة إشارة واحدة على حساب باقي الإشارات، مش
  // قيمة قابلة للتعلّم في حد ذاتها.
  if (ipVelocityCount >= 2) {
    const ipVelocityMultiplier = getLearnedMultiplier(getW, 'IP_VELOCITY', 'HIGH');
    const ipVelocityPenalty = Math.min(Math.round(15 * ipVelocityMultiplier * Math.log2(ipVelocityCount + 1)), 35);
    score -= ipVelocityPenalty;
    flags.push({ severity: "high", text: "ip_velocity_high" });
    topSignals.push({ type: "IP_VELOCITY", value: ipVelocityCount, contribution: -ipVelocityPenalty });
  }

  // ─── Sustained IP Burst — Critical Override ───────────────────────────
  // ip_velocity_high above is capped at "high" severity no matter how
  // large ipVelocityCount gets, and the Risk Floor further below caps the
  // score at 55/70 whenever ANY "high" flag is present — meaning a
  // sustained burst from one IP can never, on its own, cross into "Block"
  // as long as the attacker rotates deviceFingerprint/email per attempt
  // (exactly what device_velocity_blocked's own critical threshold of
  // devVelocityCount >= 3 otherwise incentivizes an attacker to do).
  // IP address is the hardest of the three identifiers (device, email, IP)
  // for an attacker to rotate on every single attempt — it requires a new
  // proxy/exit node, not just a new cookie or random string — so once the
  // count is high enough, it is treated as a definitive signal on its own,
  // independent of whether device/email signals were successfully evaded.
  // [Learning-loop wiring — Card Testing priority] كانت 50 ثابتة — مطابقة
  // بالحرف لـ IP_BURST:TRUE's base الجديد في STATIC_WEIGHTS (صفر أثر
  // سلوكي وقت النشر). IP هي أصعب إشارة على المهاجم يتفاداها (محتاج
  // exit node جديد فعليًا، مش مجرد fingerprint عشوائي) — أولوية عالية
  // لتفعيل التعلّم عليها.
  if (ipVelocityCount >= 10) {
    const burstPenalty = Math.round(getW("IP_BURST", "TRUE"));
    score -= burstPenalty;
    flags.push({ severity: "critical", text: "sustained_ip_burst" });
    topSignals.push({ type: "IP_BURST", value: ipVelocityCount, contribution: -burstPenalty });
  }

  // [Learning-loop wiring — Card Testing priority] نفس نمط IP_VELOCITY
  // فوق بالحرف — 12 معامل جوه صيغة log2، مش عقوبة نهائية. cap (30)
  // ثابت غير متأثر بالتعلّم لنفس السبب المعماري.
  if (emailVelocityCount >= 3) {
    const emailVelocityMultiplier = getLearnedMultiplier(getW, 'EMAIL_VELOCITY', 'HIGH');
    const emailVelocityPenalty = Math.min(Math.round(12 * emailVelocityMultiplier * Math.log2(emailVelocityCount + 1)), 30);
    score -= emailVelocityPenalty;
    flags.push({ severity: "high", text: "email_velocity_high" });
    topSignals.push({ type: "EMAIL_VELOCITY", value: emailVelocityCount, contribution: -emailVelocityPenalty });
  }

  // ─── BIN Velocity (Multi-window + Prepaid Intelligence) ──────────────
  // [BIN Velocity fix] كانت هذه الطبقة معطوبة بالكامل — binCount10min/1h/24h
  // كانوا يرجعوا صفر دايمًا لأن allOrders (formattedOrders) ما كانتش تحمل
  // payment_details خالص في أي من الأماكن الثلاثة اللي بتبنيها (risk.js's
  // /evaluate و/woocommerce-webhook، وenrichmentProcessor.js). المصدر
  // اتغيّر لـ عمود Order.cardBinPrefix (indexed، مضاف عبر migration) —
  // إما مباشرة من externalVelocity (عد دقيق من DB، /evaluate و
  // /woocommerce-webhook)، أو fallback من allOrders.cardBinPrefix
  // (العينة المحدودة، enrichmentProcessor.js اللي بيمرر externalVelocity=null
  // عمدًا). القيم والـ thresholds والـ prepaid multiplier لم تتغير — هذا
  // إصلاح لمصدر البيانات فقط، مش لمنطق المعايرة.
  // [BIN Velocity consistency fix] كانت بدون digit-strip — بعكس كل مصدر
  // تاني لنفس القيمة في المشروع (Order.cardBinPrefix في الـ DB،
  // cardBinPrefixForVelocity في risk.js، cardBinPrefix في
  // enrichmentProcessor.js — التلاتة بيعملوا replace(/\D/g,'') قبل
  // الـ slice). في مسار الـ fallback (allOrders.filter بتاع /enrich)،
  // المقارنة كانت هتقارن binPrefix الخام مقابل o.cardBinPrefix المُنضّف
  // — أي حرف غير رقمي في الـ bin الوارد كان هيكسر المطابقة بصمت ويرجّع
  // صفر عد رغم تكرار حقيقي.
  const rawBinForPrefix = order.payment_details?.card_bin ?? null;
  const binPrefix = rawBinForPrefix ? String(rawBinForPrefix).replace(/\D/g, '').slice(0, 6) : null;
  const isPrepaidCard = binIntelResult?.isPrepaid === true;

  // [BIN Velocity learning-loop wiring — /enrich fix] كانت معرّفة جوه
  // بلوك if(binPrefix) بس — مبتوصلش لـ computedSignals في الـ return
  // تحت، يعني calculateRiskScore() كانت بتحسب العقوبة صح لكن ترمي القيم
  // اللي حسبتها بيها. enrichmentProcessor.js (المسار الأساسي فعليًا
  // لوصول BIN حقيقي — راجع ADR-0) محتاج القيم دي عشان يضيفها لـ
  // signalsSnapshot، وده مستحيل من غير ما يرجعوا من هنا. hoisted هنا
  // برّه الـ if عشان يفضلوا في الـ function scope لحد نقطة الـ return.
  let binCount10min = 0;
  let binCount1h = 0;
  let binCount24h = 0;

  if (binPrefix) {
    const hasDbBackedBinVelocity = externalVelocity && (
      externalVelocity.binVelocityCount10min !== undefined ||
      externalVelocity.binVelocityCount1h !== undefined ||
      externalVelocity.binVelocityCount24h !== undefined
    );

    if (hasDbBackedBinVelocity) {
      // مسار دقيق — /evaluate و /woocommerce-webhook، عدّ مباشر من DB
      binCount10min = externalVelocity.binVelocityCount10min || 0;
      binCount1h    = externalVelocity.binVelocityCount1h    || 0;
      binCount24h   = externalVelocity.binVelocityCount24h   || 0;
    } else {
      // مسار fallback — enrichmentProcessor.js (وأي كولر مستقبلي ماعندوش
      // externalVelocity). كان معطوبًا بسبب payment_details المفقودة؛
      // دلوقتي بيستخدم o.cardBinPrefix الفعلي المُضاف لـ formattedOrders.
      const last10min = new Date(Date.now() - 10 * 60 * 1000);
      binCount10min = allOrders.filter(o =>
        o.cardBinPrefix === binPrefix &&
        new Date(o.createdAt) > last10min &&
        o.id !== order.id
      ).length;
      binCount1h = allOrders.filter(o =>
        o.cardBinPrefix === binPrefix &&
        new Date(o.createdAt) > last1h &&
        o.id !== order.id
      ).length;
      binCount24h = allOrders.filter(o =>
        o.cardBinPrefix === binPrefix &&
        new Date(o.createdAt) > last24h &&
        o.id !== order.id
      ).length;
    }

    // Prepaid multiplier: double the counts for prepaid cards
    const prepaidMultiplier = isPrepaidCard ? 2.5 : 1.0;

    // [Learning-loop wiring — Card Testing top priority] الـ 10/15/25
    // كانت أرقام ثابتة تمامًا — دلوقتي بتتضرب في getLearnedMultiplier()
    // (نسبة learned/staticBase) جنب prepaidMultiplier الموجود، نفس نمط
    // BIN_PREPAID في binIntelligence.js بالحرف. عند cold start النسبة
    // = 1.0 بالضبط فالمعادلة الأصلية تشتغل بلا أي تغيير سلوكي — مع
    // تراكم dispute outcomes حقيقية، الوزن بيتحرك جوه [0, base×3].
    const bin10minMultiplier = getLearnedMultiplier(getW, 'BIN_VELOCITY_10MIN', 'TRUE');
    const bin1hMultiplier    = getLearnedMultiplier(getW, 'BIN_VELOCITY_1H', 'TRUE');
    const bin24hMultiplier   = getLearnedMultiplier(getW, 'BIN_VELOCITY_24H', 'TRUE');

    // Tiered penalties
    if (binCount10min >= 2) {
      const penalty = Math.round(10 * prepaidMultiplier * bin10minMultiplier);
      score -= penalty;
      flags.push({ severity: "high", text: isPrepaidCard ? "bin_velocity_high_prepaid" : "bin_velocity_high" });
      topSignals.push({ type: "BIN_VELOCITY_10MIN", value: binCount10min, contribution: -penalty });
    } else if (binCount1h >= 3) {
      const penalty = Math.round(15 * prepaidMultiplier * bin1hMultiplier);
      score -= penalty;
      flags.push({ severity: "high", text: isPrepaidCard ? "bin_velocity_high_prepaid" : "bin_velocity_high" });
      topSignals.push({ type: "BIN_VELOCITY_1H", value: binCount1h, contribution: -penalty });
    } else if (binCount24h >= 5) {
      const penalty = Math.round(25 * prepaidMultiplier * bin24hMultiplier);
      score -= penalty;
      flags.push({ severity: "high", text: isPrepaidCard ? "bin_velocity_high_prepaid" : "bin_velocity_high" });
      topSignals.push({ type: "BIN_VELOCITY_24H", value: binCount24h, contribution: -penalty });
    }
  }


  // ─── First Seen Penalty (Cold Start Protection) ────────────────────────
  // device أو email جديد خالص = مش عندنا history عليه
  // بيحمي من attackers بيبدأوا بـ clean identity

  if (deviceId) {
    // أقدم أوردر من نفس الـ device
    const oldestDeviceOrder = allOrders
      .filter(o => (o.deviceFingerprint === deviceId || o.deviceId === deviceId) && o.id !== order.id)
      .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))[0];

    const deviceAgeHours = oldestDeviceOrder
      ? (Date.now() - new Date(oldestDeviceOrder.createdAt).getTime()) / (1000 * 60 * 60)
      : 0;

   const isFirstTimeDevice = !oldestDeviceOrder;
    if (isFirstTimeDevice && order.amount >= 100) {
      // Device جديد خالص + أوردر فوق $100
      // Dampened by deviceTrustFactor: an unsigned/uncorroborated
      // "first-time device" is expected noise from every rotating
      // attacker AND every legitimate first-time visitor alike — full
      // weight here mainly penalizes real new customers without adding
      // much signal against a forger who rotates on every request anyway.
      const firstTimePenalty = Math.round(15 * deviceTrustFactor);
      score -= firstTimePenalty;
      flags.push({ severity: "medium", text: "first_time_device_high_value" });
    } else if (deviceAgeHours < 24 && order.amount >= 200) {
      // Device شفناه من أقل من 24 ساعة + أوردر كبير
      const newDevicePenalty = Math.round(10 * deviceTrustFactor);
      score -= newDevicePenalty;
      flags.push({ severity: "medium", text: "new_device_high_value" });
    }
  }

  if (isNewCustomer && order.amount >= 150) {
    // Email جديد خالص + أوردر فوق $150
    // ملاحظة: مش بنعاقب كل عميل جديد — بس مع high value
    if (!highValuePenaltyApplied) {
      score -= 10;
      flags.push({ severity: "medium", text: "new_customer_high_value" });
    }
  }

  // ─── Tier 3 — Positive Signals (Learning-aware) ───────────────────────
  // Anti-Balancing Attack Protection:
  // كل الـ positives بتتجمع في totalPositiveBonus
  // بعدين بنضيف الـ min(total, MAX_POSITIVE_BOOST) للـ score
  // يمنع محتال يجمع ECI+AVS+CVV2+device+returning ويعوض critical flags

  const MAX_POSITIVE_BOOST = 25; // max +25 مهما كانت الـ positive signals
  let totalPositiveBonus = 0;

  // ECI — uses learned weight
  if (order.eciCode && ["5", "6"].includes(order.eciCode)) {
    const w = getW("ECI", order.eciCode);
    // Scale to 0-25 range (static was +20)
    const bonus = Math.round(w * 5);
    totalPositiveBonus += bonus;
    positives.push({ text: `3D Secure authenticated (ECI ${order.eciCode}) — liability shifted to issuer` });
    topSignals.push({ type: "ECI", value: order.eciCode, contribution: bonus });
  }

  // AVS — uses learned weight
  if (order.avsResponse === "Y") {
    const w = getW("AVS", "Y");
    const bonus = Math.round(w * 5);
    totalPositiveBonus += bonus;
    positives.push({ text: "Address verification confirmed (AVS Y)" });
    topSignals.push({ type: "AVS", value: "Y", contribution: bonus });
  } else if (order.avsResponse === "A" || order.avsResponse === "Z") {
    // [AVS partial-match wiring] كانت AVS:A/AVS:Z معرّفة في STATIC_WEIGHTS
    // (base=0.8 لكل واحدة) من غير أي منطق مستهلك ليها خالص — الكود
    // الأصلي كان بيتأكد من avsResponse === "Y" بس، فأي رد جزئي (عنوان
    // طابق بس ZIP لأ، أو العكس) كان بيتجاهل تمامًا — بيتعامل معاه النظام
    // بالظبط زي عميل من غير أي AVS response أصلاً. هذا فرق حقيقي في صناعة
    // مكافحة الاحتيال (AVS partial match = ثقة أضعف من full match، لكن
    // أقوى من عدم وجود أي تحقق) كان بيضيع.
    //
    // بونص أصغر بكتير من AVS:Y عمدًا — الـ multiplier (×5) نفسه زي Y،
    // لكن الـ base صغير (0.8 مقابل 2.0)، فالفرق الافتراضي عند cold start
    // هو 4 نقاط (Y) مقابل ~1.6 نقطة (A/Z) — نسبة تقريبًا 40%، تعكس إن
    // partial match إشارة أضعف مش نفس قوة full match.
    //
    // AVS:N (لا تطابق خالص) عمدًا بره هذا المنطق — base=0.0 في
    // STATIC_WEIGHTS بنفس نمط ECI:7/CVV2:N (إشارات مُعطّلة عمدًا، مش
    // مؤجّلة سهوًا)، لأن غياب أي عقوبة عند AVS:N قرار تصميمي أوسع
    // (النظام هنا مبني على "بونص عند إثبات إيجابي" مش "عقوبة عند الفشل")
    // خارج نطاق هذا الفيكس تحديدًا.
    const w = getW("AVS", order.avsResponse);
    const bonus = Math.round(w * 5);
    if (bonus > 0) {
      totalPositiveBonus += bonus;
      positives.push({
        text: order.avsResponse === "A"
          ? "Partial address verification (AVS A — street address matched)"
          : "Partial address verification (AVS Z — ZIP code matched)",
      });
      topSignals.push({ type: "AVS", value: order.avsResponse, contribution: bonus });
    }
  }

  // CVV2 — uses learned weight
  if (order.cvv2Response === "M") {
    const w = getW("CVV2", "M");
    const bonus = Math.round(w * 5);
    totalPositiveBonus += bonus;
    positives.push({ text: "CVV2 matched at authorization" });
    topSignals.push({ type: "CVV2", value: "M", contribution: bonus });
  }

  // Returning customer — rule-based (no signal weight needed)
  const prevGoodOrders = allOrders.filter(o =>
    normalizeEmail(o.email) === email && o.id !== order.id &&
    !disputes.some(d => d.orderId === o.id)
  );
  if (prevGoodOrders.length >= 3) {
    // Trust Velocity — بنشيك إن الأوردرات على فترة طبيعية مش في يومين
    // أقدم أوردر وأحدث أوردر — الفرق بينهم لازم يكون أكتر من 14 يوم
    const sortedGood = prevGoodOrders.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    const oldestGood = new Date(sortedGood[0].createdAt);
    const newestGood = new Date(sortedGood[sortedGood.length - 1].createdAt);
    const spanDays = (newestGood - oldestGood) / (1000 * 60 * 60 * 24);

    if (spanDays >= 14) {
      // أوردرات على فترة طبيعية → trusted فعلاً
      totalPositiveBonus += 20;
      positives.push({ text: `Trusted customer — ${prevGoodOrders.length} orders over ${Math.round(spanDays)} days with no disputes` });
    } else {
      // أوردرات متقاربة جداً → ممكن trust farming
      totalPositiveBonus += 8; // bonus أقل بكتير
      positives.push({ text: `Returning customer — ${prevGoodOrders.length} recent orders with no disputes` });
      if (spanDays < 3 && prevGoodOrders.length >= 3) {
        // 3+ orders في أقل من 3 أيام = suspicious pattern
        score -= 10;
        flags.push({ severity: "medium", text: "trust_farming_pattern" });
      }
    }
  } else if (prevGoodOrders.length >= 1) {
    totalPositiveBonus += 10;
    positives.push({ text: `Returning customer — ${prevGoodOrders.length} previous order${prevGoodOrders.length > 1 ? "s" : ""} with no disputes` });
  }

  // Same device — rule-based
  if (deviceId) {
    const sameDeviceGood = allOrders.filter(o =>
      (o.deviceFingerprint === deviceId || o.deviceId === deviceId) &&
      o.id !== order.id &&
      !disputes.some(d => d.orderId === o.id)
    );
    if (sameDeviceGood.length >= 2) {
      // Dampened by deviceTrustFactor — an unsigned, uncorroborated device
      // match "looking trusted" is exactly the case a rotating attacker
      // could otherwise farm by replaying one forged fingerprint across a
      // handful of low-value clean orders before an attack burst.
      const trustBonus = Math.round(15 * deviceTrustFactor);
      totalPositiveBonus += trustBonus;
      positives.push({ text: `Known trusted device — ${sameDeviceGood.length} previous successful orders` });
    }
  }

  // ─── Behavioral Deviation ─────────────────────────────────────────────
  // unified مع الـ high value check فوق — avgOrderValue و orderMultiple
  // محسوبين هناك ومستخدمين في نفس الـ tiered logic (3x و 5x)
  const orderHour = new Date(order.createdAt || Date.now()).getHours();
  if (orderHour >= 2 && orderHour <= 5) {
    score -= 10;
    flags.push({ severity: "medium", text: "unusual_order_hour" });
  }

  // High value check — بس لو مش اتحسب قبل كده في الـ orderMultiple block
  // يمنع double penalty على نفس الـ signal
  if (!highValuePenaltyApplied && avgOrderValue > 0 && orderMultiple >= 3) {
    const penalty = isNewCustomer ? 20 : 10;
    score -= penalty;
    flags.push({
      severity: isNewCustomer ? "high" : "medium",
      text: isNewCustomer ? "new_customer_high_value_order" : "high_value_order",
    });
  }

  if (order.lineItems) {
    try {
      const items = JSON.parse(order.lineItems);
      if (items.length > 10) {
        score -= 10;
        flags.push({ severity: "medium", text: "large_order_item_count" });
      }
    } catch { /* skip */ }
  }

  // ─── Identity Graph — Connected Risk ──────────────────────────────────
  // يضيف risk من الـ graph network على الـ score
  let graphRisk = 0;
  let graphPath = [];
  if (deviceId) {
    try {
       const graphResult = await getConnectedRisk({
        ...order,
        fingerprintConfig:   order.fingerprintConfig   ?? null,
        fingerprintHardware: order.fingerprintHardware ?? null,
        // fingerprintVersion مش موجود في Order schema — بنحسبه من fingerprintStatus
        // identityGraph.js بيشيك على fingerprintVersion === "v3" للـ self-healing
        fingerprintVersion:  order.fingerprintVersion || "v2",
      }, merchantId || null, { deviceTrustFactor });
      graphRisk = graphResult.connectedRisk;
      graphPath = graphResult.graphPath;
      const graphMatchTier     = graphResult.matchTier     ?? "full";
      const graphMatchConfidence = graphResult.matchConfidence ?? 1.0;

      if (graphRisk > 10) {
        const graphPenalty = Math.round(Math.min(graphRisk * 0.30, 30));
        score -= graphPenalty;

        // ─── Explainability — بيوضح للتاجر نوع الـ match ─────────────────
        const tierLabel = graphMatchTier === "hardware"
          ? ` (hardware-level match — ${Math.round(graphMatchConfidence * 100)}% confidence)`
          : graphMatchTier === "config"
          ? ` (config-level match — ${Math.round(graphMatchConfidence * 100)}% confidence)`
          : "";

        flags.push({
          severity: graphRisk > 60 ? "critical" : "high",
          text: "identity_graph_risk",
        });
        topSignals.push({ type: "GRAPH", value: graphMatchTier, contribution: -graphPenalty });
      } else if (graphRisk > 0 && graphPath.length > 0) {
        // Low graph risk — positive signal (known clean network)
        const graphBonus = Math.round(Math.min(graphRisk * 0.1, 5));
        totalPositiveBonus += graphBonus;
        positives.push({ text: `Known identity network — device has clean transaction history` });
      }

      if (graphRisk > 0) {
        const earlyWarningNode = graphPath.find(
          node => node.type === "EARLY_WARNING" && (node.merchantsSeen ?? 0) >= 3
        );
        if (earlyWarningNode) {
          score -= 20;
          flags.push({
            severity: "critical",
            text: "cross_merchant_fraud_network",
          });
          topSignals.push({ type: "CROSS_MERCHANT", value: earlyWarningNode.merchantsSeen, contribution: -20 });
        }
      }
    } catch (graphErr) {
      // Non-critical — continue scoring without graph
      logger.error({ module: 'riskScoring', err: graphErr }, 'Graph risk error');
    }
  }

  // ─── Pattern Sharing — Cross-Merchant Behavioral Intelligence ─────────
  // بيشيك لو الـ order بيطابق pattern fraud مشهور عبر الشبكة
  // Non-critical — failures never block scoring
  let emailIntelForPattern = null;
  let ipIntelForPattern = null;
  try {
    // نستخدم الـ intel اللي اتحسب بالفعل في الـ parallel block
    // مش محتاجين calls جديدة — الـ results محفوظة في ipIntelResult و emailIntelResult
    emailIntelForPattern = emailIntelResult ?? { isDisposable: false };
    ipIntelForPattern    = ipIntelResult    ?? { isDatacenter: false };
  } catch { /* use defaults */ }

  // أضف isNewCustomer للـ order object مؤقتاً للـ pattern builder
  const isHighVelocitySignal = deviceId
    ? allOrders.filter(o =>
        (o.deviceFingerprint === deviceId || o.deviceId === deviceId) &&
        new Date(o.createdAt) > last1h &&
        o.id !== order.id
      ).length >= 2
    : false;

  // patternContext — computed signals بتتبنى مرة واحدة هنا
  // وبتتمرر لـ checkPatternRisk و recordPattern عشان الـ hash يكون consistent
  const patternContext = { isHighVelocity: isHighVelocitySignal };
  const orderForPattern = { ...order, isNewCustomer };

  try {
    const { penalty: patternPenalty, flags: patternFlags } = await checkPatternRisk(
      orderForPattern,
      emailIntelForPattern,
      ipIntelForPattern,
      patternContext,
    );
    if (patternPenalty > 0) {
      score -= patternPenalty;
      flags.push(...patternFlags);
      topSignals.push({ type: "PATTERN", value: "behavioral", contribution: -patternPenalty });
    }
  } catch (patternErr) {
    logger.error({ module: 'riskScoring', err: patternErr }, 'Pattern check error');
  }

  // Record pattern للـ data flywheel (async — مش بنستنى النتيجة)
  // Data Poisoning Protection — بنسجل بس الـ orders المشبوهة
  // الـ legit orders مش بتضيف للـ pattern database
  // Pattern Recording — بعد تعريف finalRiskLevel
  // سجل high risk فقط — medium ممكن يكون legit ويسمم الـ pattern database

  // ─── Apply Positive Cap (Anti-Balancing Attack Protection) ───────────
  // بنضيف الـ positives بعد كل الـ penalties
  // MAX_POSITIVE_BOOST يمنع محتال يجمع signals كتير يعوض critical flags
  const cappedBonus = Math.min(totalPositiveBonus, MAX_POSITIVE_BOOST);
  score += cappedBonus;

  // Log لو في capping حصل
  if (totalPositiveBonus > MAX_POSITIVE_BOOST) {
    logger.info({ module: 'riskScoring', totalPositiveBonus, maxPositiveBoost: MAX_POSITIVE_BOOST, suppressed: totalPositiveBonus - MAX_POSITIVE_BOOST }, 'Positive cap applied');
  }

  // ─── Final Score & Decision ────────────────────────────────────────────
  score = Math.max(0, Math.min(100, score));

  // ─── Risk Floor — Anti-Balancing Attack ───────────────────────────────
  // يمنع attacker من تجميع positives صغيرة عشان يعوض critical flags
  const hasCriticalSignal = flags.some(f => f.severity === "critical");
  const hasHighSignal = flags.some(f => f.severity === "high");
  const criticalCount = flags.filter(f => f.severity === "critical").length;
  const highCount = flags.filter(f => f.severity === "high").length;

  // Critical signal → force Block بغض النظر عن الـ thresholds
  // يمنع edge case لو الـ reviewThreshold منخفض جداً يخلي score=40 يبقى Review
  if (hasCriticalSignal) {
    score = Math.min(score, 40);
    // [TEMP DEBUG] بيطبع أسماء الـ critical flags الفعلية اللي سبّبت
    // الحظر، مش بس العدد — عشان نحدد مصدر الحظر بدقة بدل التخمين.
    // احذف السطر ده بعد ما نخلص التشخيص.
    const criticalFlagTexts = flags.filter(f => f.severity === "critical").map(f => f.text);
    logger.warn({ module: 'riskScoring', cappedAt: 40, criticalCount, criticalFlagTexts }, 'Risk floor applied (critical flags)');
  } else if (hasHighSignal && highCount >= 2 && score > 55) {
    // لو عنده 2+ high flags — أشد من واحدة بس
    score = 55;
    logger.warn({ module: 'riskScoring', cappedAt: 55, highCount }, 'Risk floor applied (multiple high flags)');
  } else if (hasHighSignal && score > 70) {
    score = 70;
    logger.warn({ module: 'riskScoring', cappedAt: 70, highCount }, 'Risk floor applied (high flag)');
  }



  // ─── Economic Layer (Smooth Scaling) ──────────────────────────────────
  // بدل hard cliffs ($499 vs $500) — بنستخدم log scaling
  // النتيجة: thresholds بتتحرك بشكل سلس مع قيمة الأوردر
  //
  // $10   → approve: 62, review: 32
  // $50   → approve: 67, review: 37
  // $100  → approve: 70, review: 40
  // $200  → approve: 73, review: 43
  // $500  → approve: 77, review: 47
  // $1000 → approve: 80, review: 50
  // $2000 → approve: 83, review: 53

  const orderAmount = order.amount || 0;


  // log scaling — بيزيد الـ threshold بشكل سلس مع قيمة الأوردر
  // Math.log(1) = 0, Math.log(10) ≈ 2.3, Math.log(100) ≈ 4.6
  const logScale = orderAmount > 0
    ? Math.min(Math.log(orderAmount) * 2.0, 20)  // max +20 points على الـ threshold
    : 0;

  // ─── Merchant Risk Context ────────────────────────────────────────────
  // بيعدل الـ thresholds بناءً على أداء التاجر التاريخي
  let merchantAdjustment = 0;
  let merchantAdjustmentReason = null;
  let cachedMerchantProfile = null;
  if (merchantId) {
    try {
      cachedMerchantProfile = await db.merchantProfile.findUnique({
        where: { merchantId },
      });
      if (cachedMerchantProfile) {
        const { adjustment, reason } = getMerchantAdjustment(cachedMerchantProfile);
        merchantAdjustment = adjustment;
        merchantAdjustmentReason = reason;
      }
    } catch (profileErr) {
      logger.error({ module: 'riskScoring', err: profileErr }, 'Failed to load merchant profile, using defaults');
    }
  }

  // [Drift-risk fix] كان الكود هنا بيكرر نفس معادلة calculateThresholds()
  // المُعرّفة أول الملف بالحرف — رغم إن تعليقها بيدّعي إنها "single source
  // of truth يستخدمها calculateRiskScore" — عمليًا مكانتش مستخدمة هنا
  // خالص (rescoreOrder() اللي المفروض تستخدمها التانية stub فاضي). أي
  // تعديل مستقبلي على calculateThresholds() كان هيبقى بلا أي أثر فعلي
  // على القرار الحقيقي، لأن النسخة الحقيقية معزولة هنا. الاستدعاء المباشر
  // دلوقتي بيقفل الفجوة دي — نفس القيم بالحرف، نفس السلوك 100%، لكن من
  // مصدر واحد فعلي.
  const { approveThreshold, reviewThreshold } = calculateThresholds(orderAmount, cachedMerchantProfile, allOrders);



  let decision, decisionColor, decisionBg;

  // Critical signal → Block مباشرة بغض النظر عن الـ score والـ thresholds
  if (hasCriticalSignal) {
    decision      = "High Risk — Block";
    decisionColor = "#C0392B";
    decisionBg    = "#FFF4F4";
  } else if (score >= approveThreshold) {
    decision      = "Low Risk — Approve";
    decisionColor = "#007A5C";
    decisionBg    = "#F1F8F5";
  } else if (score >= reviewThreshold) {
    decision      = "Medium Risk — Review";
    decisionColor = "#B44504";
    decisionBg    = "#FFF4E5";
  } else {
    decision      = "High Risk — Block";
    decisionColor = "#C0392B";
    decisionBg    = "#FFF4F4";
  }


  // ─── Economic Fraud Engine — Decision Override ────────────────────────
  // بيشتغل بعد الـ scoring decision — مش بيغير الـ score
  // بيضيف layer اقتصادية: "هل يستاهل المخاطرة مالياً؟"
  let decisionBefore = decision;
  let economicData   = null;

  try {
    const merchantProfileForEcon = cachedMerchantProfile;

    const { fraudProb, expectedLoss, safeLoss, baseThreshold } =
      calculateEconomicRisk(score, orderAmount, merchantProfileForEcon);

    economicData = {
      version:        1,
      fraudProb:      parseFloat(fraudProb.toFixed(4)),
      expectedLoss:   parseFloat(expectedLoss.toFixed(2)),
      safeLoss:       parseFloat(safeLoss.toFixed(2)),
      baseThreshold:  parseFloat(baseThreshold.toFixed(2)),
      decisionBefore,
      decisionAfter:  null, // سيُحدّث بعد الـ overrides
    };

    // ── Override 1: Block (أشد) ───────────────────────────────────────
    // safeLoss عالي جداً + probability مش صغيرة
    if (!hasCriticalSignal && expectedLoss > baseThreshold * 3 && fraudProb > 0.25) {
      decision      = "High Risk — Block";
      decisionColor = "#C0392B";
      decisionBg    = "#FFF4F4";
      flags.push({
        severity: "high",
        text: "economic_risk_block",
      });
      topSignals.push({ type: "ECONOMIC", value: "high_loss_block", contribution: -15 });
    }

    // ── Override 2: Approve → Review (صارم) ──────────────────────────
    else if (decision === "Low Risk — Approve" && safeLoss > baseThreshold * 1.5) {
      decision      = "Medium Risk — Review";
      decisionColor = "#B44504";
      decisionBg    = "#FFF4E5";
      flags.push({
        severity: "medium",
        text: "economic_risk_review",
      });
      topSignals.push({ type: "ECONOMIC", value: "high_loss_review", contribution: -10 });
    }

    // ── Override 3: Review → Approve (متساهل) ────────────────────────
    // بس لو الـ expected loss صغير جداً
    else if (decision === "Medium Risk — Review" && safeLoss < baseThreshold * 0.2 && fraudProb < 0.05 && !hasCriticalSignal) {
      decision      = "Low Risk — Approve";
      decisionColor = "#007A5C";
      decisionBg    = "#F1F8F5";
      positives.push({
        text: `Low economic exposure: $${safeLoss.toFixed(0)} potential loss on $${orderAmount} order — within acceptable range`,
      });
    }

    // ── Economic Confidence Signal (للـ topSignals) ───────────────────
    if (safeLoss > baseThreshold * 2) {
      topSignals.push({ type: "ECONOMIC_RISK", value: "high_loss", contribution: -10 });
    }

    // Update economicData بعد الـ overrides
    economicData.decisionAfter = decision;

    if (decisionBefore !== decision) {
      logger.info({ module: 'riskScoring', decisionBefore, decisionAfter: decision, expectedLoss, baseThreshold }, 'Economic override');
    }

  } catch (econErr) {
    logger.error({ module: 'riskScoring', err: econErr }, 'Economic engine error');
  }


  // ─── Flight Recorder — Save RiskEvaluation ────────────────────────────
  // DB معطل مؤقتًا — لا نحفظ التقييم

  // Update riskLevel بعد الـ economic overrides
  const finalRiskLevel = decision.includes("Approve") ? "low"
    : decision.includes("Review") ? "medium"
    : "high";

  // Pattern Recording — بعد تعريف finalRiskLevel
  // سجل high risk فقط — medium ممكن يكون legit ويسمم الـ pattern database
  if (finalRiskLevel === "high") {
    recordPattern(orderForPattern, emailIntelForPattern, ipIntelForPattern, false, merchantId, patternContext)
      .catch(e => logger.error({ module: 'riskScoring', err: e }, 'Pattern record error'));
  }

  // حساب قيم السرعة والمؤشرات للإرجاع (استخدام المتغيرات الموجودة)
  const computedSignals = {
    deviceVelocityCount: deviceVelocityCount,
    ipVelocityCount: ipVelocityCount,
    emailVelocityCount: emailVelocityCount,
    // [BIN Velocity learning-loop wiring — /enrich fix] راجع التعليق عند
    // تعريف binCount10min/1h/24h فوق. سواء اتحسبت من externalVelocity
    // (DB-backed، /evaluate و/woocommerce-webhook) أو من fallback
    // (allOrders.filter، /enrich عبر enrichmentProcessor.js)، القيمة
    // الفعلية اللي طبّقت العقوبة على هذا الأوردر بترجع هنا دلوقتي —
    // موحّدة لكل الـ callers الثلاثة، بدل ما تبقى محبوسة جوه الفنكشن.
    binVelocityCount10min: binCount10min,
    binVelocityCount1h: binCount1h,
    binVelocityCount24h: binCount24h,
    isNewCustomer,
    isNewEmail,
    isNewDevice,
    avgOrderValue,
    orderMultiple,
    deviceTrust: deviceSignal?.trust ?? 'unsigned',
    deviceTrustFactor,
  };

  return {
    score,
    riskLevel:      finalRiskLevel,
    decision,
    decisionColor,
    decisionBg,
    flags,
    positives,
    isLearning,
    scoringVersion: SCORING_VERSION,
    economicData,
    computedSignals,
    graphRisk: graphRisk,
    // [Bug #3 fix] كانت محسوبة (راجع "graphPath = graphResult.graphPath"
    // فوق) لكن مش راجعة خالص — signalsSnapshot.graphPath في risk.js كانت
    // دايمًا [] حتى مع identity-graph matches حقيقية.
    graphPath: graphPath,
    ipIntel: ipIntelResult,
    emailIntel: emailIntelResult,
    binIntel: binIntelResult,
    limitedScoring, // surfaced so callers can put it on the response/dashboard
  };
}

// ─── Rescore Order ────────────────────────────────────────────────────────
// بيتنادى من الـ webhooks لما يحصل post-purchase event
// phase: 'rescore' — بيستخدم الـ post-purchase events فعلاً
async function rescoreOrder(orderId, merchantId, triggerEvent) {
  // DB معطل مؤقتًا
  return null;
}
module.exports = {
  calculateRiskScore,
  calculateThresholds,
  scoreToProbability,
  calculateEconomicRisk,
  rescoreOrder,
  normalizeEmail,
  getMerchantAdjustment,
};