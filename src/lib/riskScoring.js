// ─── ChargeGuard Risk Scoring Engine ──────────────────────────────────────
// Tier 1: Definitive | Tier 2: Strong | Tier 3: Contextual
// v2: Integrated with Learning System (SignalWeights + RiskEvaluation)

const db = require('../lib/db');
const { getWeightsForMerchant, getStaticWeight } = require('./signalWeights');
const { getConnectedRisk } = require('./identityGraph');
const { normalizeEmail } = require('../lib/utils');
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
  const shippingAddr = (() => {
    try { return JSON.parse(order.shippingAddress || "{}"); } catch { return {}; }
  })();
  const billingAddr = (() => {
    try { return JSON.parse(order.billingAddress || "{}"); } catch { return {}; }
  })();
  const last1h = new Date(Date.now() - 60 * 60 * 1000);
  const last6h = new Date(Date.now() - 6 * 60 * 60 * 1000);
  const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);



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
      text: `Automated browser detected — bot score: ${pixelBotScore} (threshold: 80)`,
    });
    topSignals.push({ type: "BOT", value: "suspicious", contribution: -40 });
  } else if (pixelBotScore >= 80) {
    score -= 40;
    flags.push({
      severity: "critical",
      text: `Strong bot signals detected — bot score: ${pixelBotScore}/100 (threshold: 80)`,
    });
    topSignals.push({ type: "BOT", value: "suspicious", contribution: -40 });
  } else if (pixelBotScore >= 20) {
    score -= 15;
    flags.push({
      severity: "medium",
      text: `Suspicious browser behavior detected — bot score: ${pixelBotScore}/100 (threshold: 20)`,
    });
    topSignals.push({ type: "BOT", value: "elevated", contribution: -15 });
  }

  const inBlacklist = blacklist.some(b =>
    (b.email && b.email === email) ||
    (b.ip && b.ip === ip) ||
    (b.deviceId && b.deviceId === deviceId)
  );
  if (inBlacklist) {
    score -= 80;
    flags.push({ severity: "critical", text: "Customer is on the fraud blacklist" });
  }

  const deviceDisputes = disputes.filter(d =>
    d.order?.deviceFingerprint === deviceId && deviceId && d.result === "lost"
  );
  if (deviceDisputes.length > 0) {
    score -= 60;
    flags.push({ severity: "critical", text: `Device fingerprint linked to ${deviceDisputes.length} lost dispute${deviceDisputes.length > 1 ? "s" : ""}` });
  }

  const ipDisputes = disputes.filter(d =>
    d.order?.ipAddress === ip && ip && d.result === "lost"
  );
  if (ipDisputes.length >= 3) {
    score -= 50;
    flags.push({ severity: "critical", text: `IP address linked to ${ipDisputes.length} disputes across network` });
  }

  // ─── Tier 2 — Strong ──────────────────────────────────────────────────

  // ─── IP Intelligence ──────────────────────────────────────────────────
  // بيستبدل الـ static Egyptian IPs list بـ real-time IP analysis
  // ─── Parallel Intel Calls ─────────────────────────────────────────────
  // IP + Email + BIN مستقلين تماماً — نشغلهم في نفس الوقت
  // Promise.allSettled يضمن إن فشل واحد مش بيوقف الباقيين
  const binRaw = order.payment_details?.card_bin ?? order.payment_details?.credit_card_bin ?? null;
  
  const [ipIntelSettled, emailIntelSettled, binIntelSettled] = await Promise.allSettled([
    ip ? getIPIntelligence(ip, merchantId) : Promise.resolve(null),
    getEmailIntelligence(email, merchantId),
    binRaw ? getBINIntelligence(binRaw, merchantId) : Promise.resolve(null),
  ]);

  // ─── IP Intel Result ──────────────────────────────────────────────────
  if (ipIntelSettled.status === 'fulfilled' && ipIntelSettled.value) {
    try {
      ipIntelResult = ipIntelSettled.value;
      const billingCountry = billingAddr.country?.toUpperCase() ?? null;
      const { penalty: ipPenalty, flags: ipFlags } = calculateIPPenalty(
        ipIntelResult,
        order.amount || 0,
        billingCountry,
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
    flags.push({ severity: "high", text: "Shipping country differs from billing country" });
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
  // isNewEmail — email مش شفناه قبل كده
  const isNewEmail = !allOrders.some(o =>
    normalizeEmail(o.email) === email && o.id !== order.id
  );

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
        text: `Order value (${order.amount.toFixed(0)}) is ${Math.round(orderMultiple)}x above store average — extreme anomaly${isNewCustomer ? " from new customer" : ""}`,
      });
      topSignals.push({ type: "HIGH_VALUE", value: "extreme", contribution: -penalty });
    } else if (orderMultiple >= 3) {
      const penalty = isNewCustomer ? 20 : 10;
      const severity = isNewCustomer ? "high" : "medium";
      score -= penalty;
      highValuePenaltyApplied = true;
      flags.push({
        severity,
        text: isNewCustomer
          ? `New customer with order ${Math.round(orderMultiple)}x above store average`
          : `Order value ${Math.round(orderMultiple)}x above store average`,
      });
      topSignals.push({ type: "HIGH_VALUE", value: isNewCustomer ? "new_customer" : "returning", contribution: -penalty });
    }
  }

  const emailDisputes = disputes.filter(d =>
    normalizeEmail(d.order?.email) === email && email
  );
  if (emailDisputes.length > 0) {
    score -= 30;
    flags.push({ severity: "high", text: `Email linked to ${emailDisputes.length} previous dispute${emailDisputes.length > 1 ? "s" : ""}` });
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
        text: `Email closely resembles ${similar.similarEmail.length} dispute${similar.similarEmail.length > 1 ? "s" : ""} — possible identity mutation`,
      });
    }

    if (similar.similarIP.length > 0 && similar.similarIP.length >= 2) {
      score -= 10;
      flags.push({
        severity: "medium",
        text: `IP address in same subnet as ${similar.similarIP.length} previous dispute${similar.similarIP.length > 1 ? "s" : ""} — network proximity flag`,
      });
    }

    if (similar.similarAddr.length > 0) {
      score -= 10;
      flags.push({
        severity: "medium",
        text: `Shipping address similar to ${similar.similarAddr.length} previous dispute${similar.similarAddr.length > 1 ? "s" : ""} — possible address mutation`,
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
        text: `Same card used ${cardHashRecord.attemptCount} times (blocked ${cardHashRecord.blockCount} times)`,
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
        merchantConfig
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
        flags.push({ severity: "critical", text: `Disposable email address detected (${emailDomain}) — high fraud risk` });
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

  // تطبيق العقوبات بناءً على deviceVelocityCount
  if (deviceVelocityCount >= 3) {
    score -= 40;
    flags.push({ severity: "critical", text: `Device fingerprint linked to ${deviceVelocityCount + 1} orders in last hour — card testing pattern detected` });
    topSignals.push({ type: "DEVICE_VELOCITY", value: "critical", contribution: -40 });
  } else if (deviceVelocityCount === 2) {
    score -= 25;
    flags.push({ severity: "high", text: `Device fingerprint linked to ${deviceVelocityCount + 1} orders in last hour — card testing pattern detected` });
    topSignals.push({ type: "DEVICE_VELOCITY", value: "high", contribution: -25 });
  } else if (deviceVelocityCount === 1) {
    score -= 15;
    flags.push({ severity: "medium", text: `Device fingerprint linked to ${deviceVelocityCount + 1} orders in last hour — card testing pattern detected` });
    topSignals.push({ type: "DEVICE_VELOCITY", value: "medium", contribution: -15 });
  }

  // IP velocity penalty
  if (ipVelocityCount >= 2) {
    const ipVelocityPenalty = Math.min(Math.round(15 * Math.log2(ipVelocityCount + 1)), 35);
    score -= ipVelocityPenalty;
    flags.push({ severity: "high", text: `${ipVelocityCount + 1} orders from same IP in last 24 hours` });
    topSignals.push({ type: "IP_VELOCITY", value: ipVelocityCount, contribution: -ipVelocityPenalty });
  }

  // Email velocity penalty
  if (emailVelocityCount >= 3) {
    const emailVelocityPenalty = Math.min(Math.round(12 * Math.log2(emailVelocityCount + 1)), 30);
    score -= emailVelocityPenalty;
    flags.push({ severity: "high", text: `${emailVelocityCount + 1} orders from same email in last 6 hours — velocity attack pattern` });
    topSignals.push({ type: "EMAIL_VELOCITY", value: emailVelocityCount, contribution: -emailVelocityPenalty });
  }

  // ─── BIN Velocity (Multi-window + Prepaid Intelligence) ──────────────
  const binPrefix = order.payment_details?.card_bin?.slice(0, 6) ?? null;
  const isPrepaidCard = binIntelResult?.isPrepaid === true;
  
  if (binPrefix) {
    // Three time windows
    const last10min = new Date(Date.now() - 10 * 60 * 1000);
    const last1h    = new Date(Date.now() - 60 * 60 * 1000);
    
    const binCount10min = allOrders.filter(o =>
      o.payment_details?.card_bin?.slice(0, 6) === binPrefix &&
      new Date(o.createdAt) > last10min &&
      o.id !== order.id
    ).length;
    
    const binCount1h = allOrders.filter(o =>
      o.payment_details?.card_bin?.slice(0, 6) === binPrefix &&
      new Date(o.createdAt) > last1h &&
      o.id !== order.id
    ).length;
    
    const binCount24h = allOrders.filter(o =>
      o.payment_details?.card_bin?.slice(0, 6) === binPrefix &&
      new Date(o.createdAt) > last24h &&
      o.id !== order.id
    ).length;

    // Prepaid multiplier: double the counts for prepaid cards
    const prepaidMultiplier = isPrepaidCard ? 2.5 : 1.0;

    // Tiered penalties
    if (binCount10min >= 2) {
      const penalty = Math.round(10 * prepaidMultiplier);
      score -= penalty;
      flags.push({ severity: "high", text: `${binCount10min + 1} orders from same BIN prefix in 10 minutes — BIN attack pattern detected${isPrepaidCard ? ' (prepaid card)' : ''}` });
      topSignals.push({ type: "BIN_VELOCITY_10MIN", value: binCount10min, contribution: -penalty });
    } else if (binCount1h >= 3) {
      const penalty = Math.round(15 * prepaidMultiplier);
      score -= penalty;
      flags.push({ severity: "high", text: `${binCount1h + 1} orders from same BIN prefix in 1 hour — BIN attack pattern detected${isPrepaidCard ? ' (prepaid card)' : ''}` });
      topSignals.push({ type: "BIN_VELOCITY_1H", value: binCount1h, contribution: -penalty });
    } else if (binCount24h >= 5) {
      const penalty = Math.round(25 * prepaidMultiplier);
      score -= penalty;
      flags.push({ severity: "high", text: `${binCount24h + 1} orders from same BIN prefix in 24 hours — BIN attack pattern detected${isPrepaidCard ? ' (prepaid card)' : ''}` });
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
      score -= 15;
      flags.push({ severity: "medium", text: `First-time device with order $${order.amount.toFixed(0)} — no transaction history` });
    } else if (deviceAgeHours < 24 && order.amount >= 200) {
      // Device شفناه من أقل من 24 ساعة + أوردر كبير
      score -= 10;
      flags.push({ severity: "medium", text: `New device (${Math.round(deviceAgeHours)}h old) with high-value order` });
    }
  }

  if (isNewCustomer && order.amount >= 150) {
    // Email جديد خالص + أوردر فوق $150
    // ملاحظة: مش بنعاقب كل عميل جديد — بس مع high value
    const alreadyFlagged = flags.some(f => f.text.includes("New customer"));
    if (!alreadyFlagged) {
      score -= 10;
      flags.push({ severity: "medium", text: `First order from this email with value $${order.amount.toFixed(0)} — no purchase history` });
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
        flags.push({ severity: "medium", text: `Rapid order history (${prevGoodOrders.length} orders in ${Math.round(spanDays * 24)}h) — possible trust farming pattern` });
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
      totalPositiveBonus += 15;
      positives.push({ text: `Known trusted device — ${sameDeviceGood.length} previous successful orders` });
    }
  }

  // ─── Behavioral Deviation ─────────────────────────────────────────────
  // unified مع الـ high value check فوق — avgOrderValue و orderMultiple
  // محسوبين هناك ومستخدمين في نفس الـ tiered logic (3x و 5x)
  const orderHour = new Date(order.createdAt || Date.now()).getHours();
  if (orderHour >= 2 && orderHour <= 5) {
    score -= 10;
    flags.push({ severity: "medium", text: `Order placed at ${orderHour}:00 AM — unusual hour (high fraud period)` });
  }

  // High value check — بس لو مش اتحسب قبل كده في الـ orderMultiple block
  // يمنع double penalty على نفس الـ signal
  if (!highValuePenaltyApplied && avgOrderValue > 0 && orderMultiple >= 3) {
    const penalty = isNewCustomer ? 20 : 10;
    score -= penalty;
    flags.push({
      severity: isNewCustomer ? "high" : "medium",
      text: `Order value ${Math.round(orderMultiple)}x above store average${isNewCustomer ? " — new customer" : ""}`,
    });
  }

  if (order.lineItems) {
    try {
      const items = JSON.parse(order.lineItems);
      if (items.length > 10) {
        score -= 10;
        flags.push({ severity: "medium", text: `Unusually large order — ${items.length} different items` });
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
      }, merchantId || null);
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
          text: `Identity graph: device connected to ${graphPath.length} suspicious identit${graphPath.length > 1 ? "ies" : "y"}${tierLabel} — network risk ${Math.round(graphRisk)}/100`,
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
            text: `Device active across ${earlyWarningNode.merchantsSeen} merchants in last 24h — coordinated fraud network signal`,
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
    logger.warn({ module: 'riskScoring', cappedAt: 40, criticalCount }, 'Risk floor applied (critical flags)');
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

  // approve → تعديل كامل
  // review → تعديل أخف (0.7) علشان مش كل حاجة تتحول Review
  let approveThreshold = Math.round(62 + logScale + merchantAdjustment);
  let reviewThresholdBase = Math.round(32 + (merchantAdjustment * 0.7));

  // Clamp — يمنع thresholds تكون aggressive أوي أو متساهلة أوي
  approveThreshold = Math.min(90, Math.max(60, approveThreshold));

  // ─── Review Fatigue Management ────────────────────────────────────────
  // لو النظام بيدي Medium Risk كتير → نرفع الـ reviewThreshold تلقائياً
  // بيمنع Alert Fatigue — التاجر مش بيشوف كتير من Medium Risk
  // بيأثر على reviewThreshold بس — High Risk مش بيتأثر أبداً
  let fatigueAdjustment = 0;
  if (allOrders.length >= 20) {
    // استثني الـ high risk orders من حساب الـ fatigue
    // يمنع attacker من spam orders عشان يرفع الـ review rate ويخلي النظام متساهل
    const recent100 = [...allOrders]
      .filter(o => o.riskLevel !== "high")
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 100);
    const mediumCount = recent100.filter(o => o.riskLevel === "medium").length;
    const reviewRate = recent100.length > 0 ? mediumCount / recent100.length : 0;

    if (reviewRate > 0.20) {
      // أكتر من 20% من الأوردرات Medium Risk → النظام aggressive أوي
      fatigueAdjustment = 8;
      logger.info({ module: 'riskScoring', reviewRate: reviewRate * 100, fatigueAdjustment }, 'Review fatigue adjustment');
    } else if (reviewRate > 0.15) {
      // 15-20% → تعديل بسيط
      fatigueAdjustment = 4;
    }
    // Max +8 على الـ reviewThreshold — مش هنخلي النظام أعمى
    fatigueAdjustment = Math.min(fatigueAdjustment, 8);
  }

    const reviewThreshold = Math.min(80, Math.max(40, reviewThresholdBase + fatigueAdjustment));



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
        text: `Economic risk: $${safeLoss.toFixed(0)} potential loss on $${orderAmount} order — ${(fraudProb * 100).toFixed(1)}% fraud probability, ${(safeLoss / baseThreshold).toFixed(1)}x above safe limit ($${baseThreshold.toFixed(0)})`,
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
        text: `Economic risk: $${safeLoss.toFixed(0)} potential loss on $${orderAmount} order — ${(safeLoss / baseThreshold).toFixed(1)}x above safe limit ($${baseThreshold.toFixed(0)})`,
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
    isNewCustomer,
    isNewEmail,
    isNewDevice,
    avgOrderValue,
    orderMultiple,
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
    ipIntel: ipIntelResult,
    emailIntel: emailIntelResult,
    binIntel: binIntelResult,
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