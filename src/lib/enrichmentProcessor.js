// src/lib/enrichmentProcessor.js
//
// Shared enrichment logic used by both POST /risk/enrich (routes/risk.js)
// and the pending-enrichment replay job (jobs/replayPendingEnrichments.js).
// Extracted so the two call sites can never drift out of sync — see the
// PendingEnrichment replay design writeup for why that matters.

const crypto = require('crypto');
const logger = require('./logger');
const db = require('./db');
const { checkBINSequence } = require('./binSequenceDetector');
const { calculateRiskScore } = require('./riskScoring');
const { verifyDeviceToken } = require('./deviceToken');
const { getStoreScope, isProOrAbove } = require('./planAccess');

const RISK_SECRET_SALT = process.env.SECRET_SALT;
const hashIp = (ip) => crypto.createHmac('sha256', RISK_SECRET_SALT).update(ip).digest('hex');

const VALID_CARD_TYPES = new Set(['visa', 'mastercard', 'amex', 'discover', 'unknown']);

const recordBlockedAttempt = (tx, { merchantId, reason, ipHash = null, cardBin = null, cardType = null, riskScore = null, amountAttempted = null, storeId = null }) => ([
  tx.blockedAttempt.create({
    data: { tenantId: merchantId, storeId: storeId ?? null, cardBin: cardBin ?? null, cardType: cardType ?? null, reason, ipHash: ipHash ?? null, amountAttempted: amountAttempted ?? null, riskScore: riskScore ?? null },
  }),
  tx.tenant.update({ where: { id: merchantId }, data: { monthlyBlockedCount: { increment: 1 } } }),
]);

/**
 * Runs the full /enrich pipeline (whitelist check, BIN-sequence
 * detection, risk re-scoring, order/RiskEvaluation persistence, quota
 * counter, PayPal alert) against an already-resolved order.
 *
 * @param {object} params
 * @param {string} params.merchantId
 * @param {string} params.orderId
 * @param {object} params.body  The original /enrich request payload
 *                               (bin, last4, expMonth, expYear, brand,
 *                               cardBrand, cardCountry, funding, issuer,
 *                               deviceToken, source, paypalTxnId, ...).
 * @param {string|null} params.storeId
 * @param {object} params.tenant  req.tenant-shaped object (needs .plan).
 * @param {boolean} [params.limitedScoring=false]  True when the caller's
 *   monthly quota is exhausted — skips expensive external IP/email/BIN
 *   intelligence inside calculateRiskScore(), same semantics as /evaluate
 *   and /woocommerce-webhook. Explicit default of `false` so the replay
 *   cron (jobs/replayPendingEnrichments.js), which does not re-check
 *   quota for old queued enrichments, has an unambiguous, documented
 *   value at this call site rather than silently relying on
 *   calculateRiskScore()'s own default.
 * @returns {Promise<{status:number, body:object}>}
 */
async function processEnrichment({ merchantId, orderId, body, storeId = null, tenant, limitedScoring = false }) {
  const { bin, cardBrand, cardCountry, funding, issuer, last4, expMonth, expYear, brand, deviceToken } = body;

  const storeScope = getStoreScope(tenant, storeId);

  let cardHashRecord = null;
  if (last4 && expMonth && expYear && brand && merchantId) {
    const secret = process.env.CARD_HASH_SECRET;
    if (!secret) throw new Error('CARD_HASH_SECRET missing');
    const raw = `${merchantId}:${last4}:${expMonth}:${expYear}:${brand}`;
    const cardHash = crypto.createHmac('sha256', secret).update(raw).digest('hex');
    cardHashRecord = await db.cardHash.upsert({
      where: { cardHash },
      create: { merchantId, cardHash, last4, expMonth, expYear, brand, attemptCount: 1 },
      update: { attemptCount: { increment: 1 }, lastSeenAt: new Date() },
    });
  }

  const existingOrder = await db.order.findUnique({
    where: { merchantId_orderId: { merchantId, orderId } },
    select: { id: true, merchantId: true, decision: true, riskScore: true, signalsSnapshot: true, amount: true, email: true, ipAddress: true, deviceFingerprint: true, createdAt: true, customerLoginId: true, fingerprintVersion: true, riskLevel: true },
  });

  // Caller (route or replay job) is responsible for only invoking this
  // once existingOrder is known to exist — this is a defensive guard,
  // not the primary "queue as pending" branch (that logic stays in the
  // /enrich route itself, since only a live request can return a 202).
  if (!existingOrder) {
    return { status: 404, body: { error: 'Order not found' } };
  }
  if (existingOrder.merchantId !== merchantId) {
    return { status: 403, body: { error: 'Merchant ID mismatch. Order belongs to another merchant.' } };
  }

  const enrichDeviceSignal = { trust: 'unsigned', ipMatches: null, rotationCount: 0 };
  if (deviceToken) {
    const v = verifyDeviceToken(deviceToken, existingOrder.ipAddress);
    enrichDeviceSignal.trust = v.valid ? (v.ipMatches ? 'signed' : 'signed_ip_mismatch') : 'invalid_token';
    enrichDeviceSignal.ipMatches = v.valid ? v.ipMatches : null;
  }
  const enrichMerchantConfig = { deviceSignal: enrichDeviceSignal };

  // Whitelist bypass
  const wlConditions = [];
  if (existingOrder.email) wlConditions.push({ type: 'EMAIL', value: existingOrder.email });
  if (existingOrder.ipAddress) wlConditions.push({ type: 'IP', value: existingOrder.ipAddress });
  if (bin) wlConditions.push({ type: 'BIN', value: String(bin).replace(/\D/g, '').slice(0, 6) });

  if (wlConditions.length > 0) {
    const wl = await db.whitelistEntry.findFirst({
      where: { merchantId, ...storeScope, OR: wlConditions, AND: [{ OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }] }] },
    });
    if (wl) {
      await db.order.update({ where: { id: existingOrder.id }, data: { decision: 'approve', riskLevel: 'low', cardHash: cardHashRecord?.cardHash ?? null, enrichmentSource: body.source || 'stripe' } });
      await db.pendingEnrichment.deleteMany({ where: { merchantId, orderId, status: 'pending' } });
      return { status: 200, body: { success: true, orderId, enriched: true, newRiskScore: existingOrder.riskScore, newDecision: 'approve', flags: [], whitelisted: true } };
    }
  }

  // BIN-sequence detection
  if (bin) {
    const binSeq = await checkBINSequence({ tenantId: merchantId, bin, ipAddress: existingOrder.ipAddress, deviceFingerprint: existingOrder.deviceFingerprint });
    if (binSeq.blocked) {
      let cardBinNorm = null;
      const b = String(bin).replace(/\D/g, '').slice(0, 6);
      if (b.length === 6) cardBinNorm = b;

      try {
        await db.$transaction([
          db.order.update({ where: { id: existingOrder.id }, data: { decision: 'block', riskLevel: 'high', cardHash: cardHashRecord?.cardHash ?? null, enrichmentSource: body.source || 'stripe' } }),
          ...recordBlockedAttempt(db, { merchantId, storeId: storeId ?? null, cardBin: cardBinNorm, cardType: null, reason: 'card_testing', ipHash: existingOrder.ipAddress ? hashIp(existingOrder.ipAddress) : null, amountAttempted: existingOrder.amount ?? null, riskScore: null }),
        ]);
      } catch (err) {
        logger.error({ module: 'enrichmentProcessor', tenantId: merchantId, error: err.message }, 'Failed BIN-sequence block transaction');
      }
      await db.pendingEnrichment.deleteMany({ where: { merchantId, orderId, status: 'pending' } });
      return { status: 200, body: { success: true, orderId, enriched: true, newRiskScore: existingOrder.riskScore, newDecision: 'block', flags: [{ severity: 'critical', text: binSeq.reason }] } };
    }
  }

  let snapshot = {};
  try { snapshot = JSON.parse(existingOrder.signalsSnapshot || '{}'); } catch {}
  snapshot.bin = bin;
  if (cardBrand) snapshot.cardBrand = cardBrand;
  if (cardCountry) snapshot.cardIssuerCountry = cardCountry;
  if (funding) snapshot.cardFunding = funding;
  if (issuer) snapshot.cardIssuer = issuer;
  snapshot.enrichedAt = new Date().toISOString();
  const enrichmentSourceValue = body.source || 'stripe';
  snapshot.enrichmentSource = enrichmentSourceValue;

  const enrichedOrder = {
    id: existingOrder.id, orderId, email: existingOrder.email, ipAddress: existingOrder.ipAddress,
    deviceFingerprint: existingOrder.deviceFingerprint, amount: existingOrder.amount,
    billingAddress: (() => { try { const s = JSON.parse(existingOrder.signalsSnapshot || '{}'); return s.billingCountry ? JSON.stringify({ country: s.billingCountry }) : null; } catch { return null; } })(),
    shippingAddress: (() => { try { const s = JSON.parse(existingOrder.signalsSnapshot || '{}'); return s.shippingCountry ? JSON.stringify({ country: s.shippingCountry }) : null; } catch { return null; } })(),
    customerLoginId: existingOrder.customerLoginId, createdAt: existingOrder.createdAt.toISOString(),
    payment_details: { card_bin: bin }, fingerprintVersion: existingOrder.fingerprintVersion || 'v3',
    fingerprintConfig: null, fingerprintHardware: null, eciCode: null, avsResponse: null, cvv2Response: null, isNewCustomer: false,
  };

  const last7days = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const recentOrders = await db.order.findMany({ where: { merchantId, ...storeScope, createdAt: { gte: last7days } }, orderBy: { createdAt: 'desc' }, take: 200 });
  const formattedOrders = recentOrders.map(o => ({ id: o.orderId, email: o.email, ipAddress: o.ipAddress, deviceFingerprint: o.deviceFingerprint, amount: o.amount, createdAt: o.createdAt, riskLevel: o.riskLevel }));
  const disputes = await db.disputeOutcome.findMany({ where: { merchantId, resolvedAt: { gte: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000) } }, include: { order: true }, take: 200 });

  const riskResult = await calculateRiskScore(enrichedOrder, formattedOrders, disputes, [], merchantId, false, null, cardHashRecord, enrichMerchantConfig, limitedScoring);

  const updatedSnapshot = { ...snapshot, ipIntel: riskResult.ipIntel || null, emailIntel: riskResult.emailIntel || null, binIntel: riskResult.binIntel || null, flags: riskResult.flags, positives: riskResult.positives };

  await db.order.update({
    where: { id: existingOrder.id },
    data: { riskScore: riskResult.score, riskLevel: riskResult.riskLevel, decision: riskResult.decision.includes('Approve') ? 'approve' : (riskResult.decision.includes('Review') ? 'review' : 'block'), cardHash: cardHashRecord?.cardHash ?? null, enrichmentSource: enrichmentSourceValue, signalsSnapshot: JSON.stringify(updatedSnapshot) },
  });

  await db.riskEvaluation.upsert({
    where: { orderId: existingOrder.id },
    create: { orderId: existingOrder.id, staticScore: riskResult.score, learningScore: riskResult.score, finalDecision: riskResult.decision.includes('Approve') ? 'low' : (riskResult.decision.includes('Review') ? 'medium' : 'high'), topSignals: JSON.stringify(riskResult.flags.slice(0, 5)), positiveSignals: JSON.stringify(riskResult.positives || []), scoringVersion: riskResult.scoringVersion || 'v1.0', fraudProb: riskResult.economicData?.fraudProb ?? null, expectedLoss: riskResult.economicData?.expectedLoss ?? null, thresholdUsed: riskResult.economicData?.baseThreshold ?? null, decisionBefore: riskResult.economicData?.decisionBefore ?? null, decisionAfter: riskResult.economicData?.decisionAfter ?? null },
    update: { staticScore: riskResult.score, learningScore: riskResult.score, finalDecision: riskResult.decision.includes('Approve') ? 'low' : (riskResult.decision.includes('Review') ? 'medium' : 'high'), topSignals: JSON.stringify(riskResult.flags.slice(0, 5)), positiveSignals: JSON.stringify(riskResult.positives || []), fraudProb: riskResult.economicData?.fraudProb ?? null, expectedLoss: riskResult.economicData?.expectedLoss ?? null, thresholdUsed: riskResult.economicData?.baseThreshold ?? null, decisionBefore: riskResult.economicData?.decisionBefore ?? null, decisionAfter: riskResult.economicData?.decisionAfter ?? null },
  });

  await db.pendingEnrichment.deleteMany({ where: { merchantId, orderId, status: 'pending' } });

  const enrichDecision = riskResult.decision.includes('Approve') ? 'approve' : (riskResult.decision.includes('Review') ? 'review' : 'block');

  if (enrichDecision === 'block' && existingOrder.decision !== 'block') {
    let enrichCardBin = null;
    if (bin != null) { const b = String(bin).replace(/\D/g, '').slice(0, 6); if (b.length === 6) enrichCardBin = b; }
    let enrichRiskScore = null;
    if (riskResult.score != null) { const rs = parseInt(riskResult.score, 10); if (!isNaN(rs) && rs >= 0 && rs <= 100) enrichRiskScore = rs; }
    try {
      await db.$transaction(recordBlockedAttempt(db, { merchantId, storeId: storeId ?? null, cardBin: enrichCardBin, cardType: null, reason: 'pattern', ipHash: existingOrder.ipAddress ? hashIp(existingOrder.ipAddress) : null, amountAttempted: existingOrder.amount ?? null, riskScore: enrichRiskScore }));
    } catch (err) {
      logger.error({ module: 'enrichmentProcessor', tenantId: merchantId, error: err.message }, 'Failed to record BlockedAttempt / increment quota counter');
    }
  }

  if (body.source === 'paypal' && riskResult.score >= 70 && tenant && isProOrAbove(tenant.plan)) {
    const { notifyPaypalAlert } = require('./notify');
    db.tenant.findUnique({ where: { id: merchantId }, select: { id: true, email: true, storeUrl: true, webhookUrl: true, webhookType: true, plan: true } })
      .then(tenantFull => {
        if (!tenantFull) return;
        const estimatedSavings = body.amount ? Math.round(Number(body.amount) * 0.15 * 100) / 100 : null;
        return notifyPaypalAlert(tenantFull, { paypalTxnId: body.paypalTxnId || null, brand: body.brand || body.cardBrand || null, last4: body.last4 || null, cardCountry: body.cardCountry || null, amount: body.amount || null, currency: body.currency || 'USD', riskScore: riskResult.score, decision: enrichDecision, flags: riskResult.flags || [], estimatedSavings });
      }).catch(err => logger.error({ module: 'enrichmentProcessor', err: err.message }, 'PayPal alert failed'));
  }

  return { status: 200, body: { success: true, orderId, enriched: true, newRiskScore: riskResult.score, newDecision: enrichDecision, flags: riskResult.flags, limitedScoring: riskResult.limitedScoring } };
}

module.exports = { processEnrichment };