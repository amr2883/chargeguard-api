const crypto = require('crypto');

// ?? IP Hashing (GDPR-safe) ????????????????????????????????????????????????
const RISK_SECRET_SALT = process.env.SECRET_SALT;
if (!RISK_SECRET_SALT) {
  throw new Error('[risk] SECRET_SALT environment variable is required');
}

const hashIp = (ip) => {
  return crypto.createHmac('sha256', RISK_SECRET_SALT).update(ip).digest('hex');
};
// ?????????????????????????????????????????????????????????????????????????
const logger = require('../lib/logger');
const express = require('express');
const router = express.Router();
const { calculateRiskScore } = require('../lib/riskScoring');
const { checkVelocity, recordFailedAttempt } = require('../lib/velocityDetector');
const { checkBINSequence } = require('../lib/binSequenceDetector');
const db = require('../lib/db');
const { resolveTenantByApiKey } = require('../lib/apiKeyAuth');
const { hashApiKey } = require('../lib/apiKeyHash');
const { normalizeBin } = require('../lib/binIntelligence');
const { buildGraphFromOrder } = require('../lib/identityGraph');
const prometheus = require('../lib/prometheus');

const { domainAuthMiddleware, normalizeDomain } = require('../lib/domainAuth');
const { notifyBINSequenceAlert }               = require('../lib/notify');
const { isAgency, FREE_PLANS }                  = require('../lib/planAccess');
const { checkQuotaGate }                        = require('../lib/quotaGate');

// ── Early Access Pro Grant ────────────────────────────────────────────────
// Marketing promise (index.html): "Early Access cohort members receive
// 3 months of Shield Pro at no cost." Applied at registration time only —
// see /tenants/register below. EARLY_ACCESS_END_DATE is optional; if unset,
// the promo has no cutoff and applies to every new registration.
const EARLY_ACCESS_PROMO_DAYS = 90;
const EARLY_ACCESS_END_DATE = process.env.EARLY_ACCESS_END_DATE
  ? new Date(process.env.EARLY_ACCESS_END_DATE)
  : null;

// ── BIN Sequence Alert Persistence ───────────────────────────────────────
const persistBinSequenceAlert = async (tenantId, bin, binSeq) => {
  if (!tenantId) return; // webhook بدون tenant — TODO: ربط webhook بالـ tenant
  try {
    const prefix     = String(bin).replace(/\D/g, '').slice(0, 4);
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

    const existing = await db.binSequenceAlert.findFirst({
      where: {
        tenantId,
        binPrefix: prefix,
        status:    'active',
        detectedAt: { gte: oneHourAgo },
      },
    });

    if (existing) {
      await db.binSequenceAlert.update({
        where: { id: existing.id },
        data:  { cardsCount: { increment: 1 } },
      });
    } else {
      const newAlert = await db.binSequenceAlert.create({
        data: {
          tenantId,
          binPrefix:     prefix,
          layer:         binSeq.layer    || 0,
          reason:        binSeq.reason   || 'BIN sequence detected',
          cardsCount:    1,
          entitiesCount: 1,
          riskAddition:  binSeq.riskAddition || 0,
          status:        'active',
        },
      });

      // إشعار التاجر — fire-and-forget مع cooldown
      const tenant = await db.tenant.findUnique({
        where:  { id: tenantId },
        select: { id: true, email: true, webhookUrl: true, webhookType: true, plan: true },
      });
      if (tenant) {
        notifyBINSequenceAlert(tenant, newAlert)
          .catch(err => logger.error({ module: 'risk', err: err.message }, 'BIN notification failed'));
      }
    }
  } catch (err) {
    logger.error({ module: 'risk', err: err.message }, 'persistBinSequenceAlert failed');
  }
};

const { requireAuth } = require('../middleware/authenticate');
const verifyHmacSignature = require('../middleware/verifyHmac');
const { isProOrAbove } = require('../lib/planAccess');

const apiKeyAuth = requireAuth({
  id: true, email: true, isActive: true, emailVerified: true, webhookSecret: true,
  countryOverrides: true, plan: true, subscriptionStatus: true, subscriptionEndDate: true,
  monthlyBlockedCount: true, quotaResetDate: true,
});

// Shared auth middleware for the WooCommerce webhook, reusing the same
// centralized requireAuth() the rest of the file uses, instead of a manual
// resolveTenantByApiKey/isActive/emailVerified copy (CWE-1059 drift fix).
const webhookAuth = requireAuth({ id: true, isActive: true, emailVerified: true, plan: true, monthlyBlockedCount: true, quotaResetDate: true });

// Invokes an Express-style middleware inline and resolves true/false
// depending on whether next() was called or the middleware sent its own
// response (e.g. requireAuth's 401/403). Needed because the webhook route
// can't take requireAuth as a normal router-level middleware — it must run
// after the raw-body buffer is already on req.body.
const runAuthMiddleware = (req, res, mw) => new Promise((resolve) => {
  let settled = false;
  res.once('finish', () => { if (!settled) { settled = true; resolve(false); } });
  mw(req, res, () => { if (!settled) { settled = true; resolve(true); } });
});
// ── recordBlockedAttempt Helper ──────────────────────────────────────────
// Shared by all four /evaluate block paths (blacklist, velocity, BIN
// sequence, risk-scoring) so every backend-authoritative block decision
// creates a BlockedAttempt row AND increments monthlyBlockedCount in the
// same atomic transaction. Accepts the Prisma client (db, or an
// interactive tx) and returns an array of unexecuted query promises meant
// to be passed straight into db.$transaction([...]).
const recordBlockedAttempt = (tx, {
  merchantId,
  reason,
  ipHash = null,
  cardBin = null,
  cardType = null,
  riskScore = null,
  amountAttempted = null,
  storeId = null,
}) => ([
  tx.blockedAttempt.create({
    data: {
      tenantId:        merchantId,
      storeId:         storeId ?? null,
      cardBin:         cardBin ?? null,
      cardType:        cardType ?? null,
      reason,
      ipHash:          ipHash ?? null,
      amountAttempted: amountAttempted ?? null,
      riskScore:       riskScore ?? null,
    },
  }),
  tx.tenant.update({
    where: { id: merchantId },
    data:  { monthlyBlockedCount: { increment: 1 } },
  }),
]);

/**
 * @swagger
 * /risk/evaluate:
 *   post:
 *     summary: Evaluate an order for fraud risk
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/EvaluateRequest'
 *     responses:
 *       200:
 *         description: Risk assessment result
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/EvaluateResponse'
 *       400:
 *         description: Missing required fields
 *       403:
 *         description: Blocked (blacklist or velocity)
 *       500:
 *         description: Internal server error
 */
router.post('/evaluate', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    // ── 0. Subscription & Quota Gate ─────────────────────────────────────
    // هذا الفحص هو نقطة التحكم الوحيدة الفعّالة — الـ plugin لا يفحص الاشتراك
    // لذلك نرفض هنا على مستوى الخادم قبل أي معالجة

       if (await checkQuotaGate(req, res, 'evaluate')) return;
    // ── End Subscription & Quota Gate ────────────────────────────────────

    // ������� ��������
    const { orderId, ipAddress, email, bin, deviceFingerprint, amount, billingCountry, shippingCountry, isNewCustomer } = req.body;
    // merchantId is derived from the authenticated tenant (CWE-639 / OWASP API1:2023 fix).
    // It is never read from the request body or x-merchant-id header.
    const merchantId = req.tenant.id;


        // Idempotency: ������ �� ������� ������� ���� ��� 5 �����
    const idempotencyWindow = 5 * 60 * 1000; // 5 �����
    const existingOrder = await db.order.findUnique({
      where: { merchantId_orderId: { merchantId, orderId } },
      select: { merchantId: true, decision: true, riskScore: true, connectedRisk: true, signalsSnapshot: true, createdAt: true }
    });
    // Defense-in-depth (C3): the compound key above already scopes this
    // lookup to this tenant, so existingOrder.merchantId !== merchantId
    // should be unreachable — but asserting it explicitly costs nothing
    // and mirrors /enrich's existing check, guarding against any future
    // regression (e.g. someone simplifying this back to a bare orderId).
    if (existingOrder && existingOrder.merchantId !== merchantId) {
      logger.error({ module: 'risk', endpoint: 'evaluate', merchantId, orderId }, 'C3 guard tripped — compound key returned a different merchant\'s row; should be unreachable');
      return res.status(403).json({ error: 'Merchant ID mismatch.' });
    }
    if (existingOrder && (Date.now() - new Date(existingOrder.createdAt).getTime()) < idempotencyWindow) {
      // ����� ���� ������
      const oldSnapshot = existingOrder.signalsSnapshot ? JSON.parse(existingOrder.signalsSnapshot) : {};
      prometheus.recordIdempotencyHit();
      return res.json({
        orderId,
        score: existingOrder.riskScore,
        decision: existingOrder.decision,
        flags: oldSnapshot.flags || [],
        connectedRisk: existingOrder.connectedRisk || 0,
        cached: true
      });
    }

    logger.debug({ module: 'risk', orderId, bin, deviceFingerprint, merchantId }, 'Received evaluate request');

    // 0a. Whitelist Check — bypass all checks for trusted entities
    const whitelistConditions = [];
    if (email)             whitelistConditions.push({ type: 'EMAIL', value: email });
    if (ipAddress)         whitelistConditions.push({ type: 'IP',    value: ipAddress });
    if (bin)               whitelistConditions.push({ type: 'BIN',   value: String(bin).replace(/\D/g, '').slice(0, 6) });

    if (whitelistConditions.length > 0) {
      const whitelistCheck = await db.whitelistEntry.findFirst({
        where: {
          merchantId,
          OR: whitelistConditions,
          AND: [{ OR: [
            { expiresAt: null },
            { expiresAt: { gt: new Date() } }
          ]}]
        }
      });

      if (whitelistCheck) {
        prometheus.recordWhitelistBypass(whitelistCheck.type);
        logger.info(
          { module: 'risk', merchantId, type: whitelistCheck.type, orderId },
          'Request bypassed all checks — whitelisted'
        );
        return res.json({
          orderId,
          score: 0,
          decision: 'approve',
          flags:    [],
          connectedRisk: 0,
          whitelisted: true
        });
      }
    }

    // 0b. Blacklist Check
    const blacklistCheck = await db.blacklistEntry.findFirst({
      where: {
        merchantId,
        OR: [
          { type: 'EMAIL', value: email },
          { type: 'IP', value: ipAddress },
          { type: 'DEVICE_FINGERPRINT', value: deviceFingerprint }
        ],
        AND: [
          { OR: [
            { expiresAt: null },
            { expiresAt: { gt: new Date() } }
          ] }
        ]
      }
    });
    if (blacklistCheck) {
      prometheus.recordBlacklistHit(blacklistCheck.type);

      let blacklistCardBin = null;
      if (bin != null) {
        const b = String(bin).replace(/\D/g, '').slice(0, 6);
        if (b.length === 6) blacklistCardBin = b;
      }
      let blacklistCardType = null;
      if (req.body.cardType != null) {
        const ct = String(req.body.cardType).toLowerCase().trim();
        blacklistCardType = VALID_CARD_TYPES.has(ct) ? ct : 'unknown';
      }
      const blacklistIpHash = ipAddress ? hashIp(ipAddress) : null;
      let blacklistAmount = null;
      if (amount != null) {
        const amt = parseFloat(amount);
        if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) blacklistAmount = amt;
      }

      try {
        await db.$transaction(recordBlockedAttempt(db, {
          merchantId:      merchantId,
          storeId:         req.storeId ?? null,
          cardBin:         blacklistCardBin,
          cardType:        blacklistCardType,
          reason:          'blacklist',
          ipHash:          blacklistIpHash,
          amountAttempted: blacklistAmount,
          riskScore:       null,
        }));
      } catch (counterErr) {
        logger.error(
          { module: 'risk', endpoint: 'evaluate', path: 'blacklist', tenantId: merchantId, error: counterErr.message },
          'Failed to record BlockedAttempt / increment quota counter (blacklist path)'
        );
      }

      return res.status(403).json({
        error: 'Request blocked: entity is blacklisted',
        reason: blacklistCheck.reason || 'Blacklisted',
        decision: 'block'
      });
    }


    // 1. فحص السرعة (Velocity Check)
    const velocityCheck = await checkVelocity({ ip: ipAddress, deviceFingerprint, merchantId });
    if (velocityCheck.blocked) {
      let velocityCardBin = null;
      if (bin != null) {
        const b = String(bin).replace(/\D/g, '').slice(0, 6);
        if (b.length === 6) velocityCardBin = b;
      }
      let velocityCardType = null;
      if (req.body.cardType != null) {
        const ct = String(req.body.cardType).toLowerCase().trim();
        velocityCardType = VALID_CARD_TYPES.has(ct) ? ct : 'unknown';
      }
      const velocityIpHash = ipAddress ? hashIp(ipAddress) : null;
      let velocityAmount = null;
      if (amount != null) {
        const amt = parseFloat(amount);
        if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) velocityAmount = amt;
      }

      try {
        await db.$transaction(recordBlockedAttempt(db, {
          merchantId:      merchantId,
          storeId:         req.storeId ?? null,
          cardBin:         velocityCardBin,
          cardType:        velocityCardType,
          reason:          'velocity',
          ipHash:          velocityIpHash,
          amountAttempted: velocityAmount,
          riskScore:       null,
        }));
      } catch (counterErr) {
        logger.error(
          { module: 'risk', endpoint: 'evaluate', path: 'velocity', tenantId: merchantId, error: counterErr.message },
          'Failed to record BlockedAttempt / increment quota counter (velocity path)'
        );
      }

      return res.status(403).json({
        error: 'Request blocked due to suspicious activity',
        reason: velocityCheck.reason,
        decision: 'block'
      });
    }

    // 1b. BIN Sequence Detection
    if (bin) {
      // tenantId is required here for tenant-scoped storage in
      // binSequenceDetector.js — without it, attacks against one tenant
      // could false-block a different tenant's legitimate customers (CWE-653).
      const binSeq = await checkBINSequence({ tenantId: req.tenant.id, bin, ipAddress, deviceFingerprint });
      if (binSeq.blocked || binSeq.riskAddition > 0) {
        persistBinSequenceAlert(req.tenant.id, bin, binSeq)
          .catch(err => logger.error({ module: 'risk', err: err.message }, 'BinSequenceAlert persist failed'));
      }

      if (binSeq.blocked) {
        let binSeqCardBin = null;
        if (bin != null) {
          const b = String(bin).replace(/\D/g, '').slice(0, 6);
          if (b.length === 6) binSeqCardBin = b;
        }
        let binSeqCardType = null;
        if (req.body.cardType != null) {
          const ct = String(req.body.cardType).toLowerCase().trim();
          binSeqCardType = VALID_CARD_TYPES.has(ct) ? ct : 'unknown';
        }
        const binSeqIpHash = ipAddress ? hashIp(ipAddress) : null;
        let binSeqAmount = null;
        if (amount != null) {
          const amt = parseFloat(amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) binSeqAmount = amt;
        }

        try {
          await db.$transaction(recordBlockedAttempt(db, {
            merchantId:      req.tenant.id,
            storeId:         req.storeId ?? null,
            cardBin:         binSeqCardBin,
            cardType:        binSeqCardType,
            reason:          'card_testing',
            ipHash:          binSeqIpHash,
            amountAttempted: binSeqAmount,
            riskScore:       null,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'evaluate', path: 'bin_sequence', tenantId: req.tenant.id, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (BIN sequence path)'
          );
        }

        return res.status(403).json({
          error: 'Request blocked due to suspicious card testing pattern',
          reason: binSeq.reason,
          decision: 'block',
          flags: [{ severity: 'critical', text: binSeq.reason }]
        });
      }
    }

    // 1. ���� ���� order
    const order = {
      id: orderId,
      email: email,
      ipAddress: ipAddress,
      deviceFingerprint: deviceFingerprint,
      deviceId: deviceFingerprint,
      amount: amount,
      billingAddress: billingCountry ? JSON.stringify({ country: billingCountry }) : null,
      shippingAddress: shippingCountry ? JSON.stringify({ country: shippingCountry }) : null,
      customerLoginId: req.body.customerLoginId || null,
      createdAt: new Date().toISOString(),
      eciCode: null,
      avsResponse: null,
      cvv2Response: null,
      payment_details: bin ? { card_bin: bin } : null,
      fingerprintVersion: 'v3',
      fingerprintConfig: null,
      fingerprintHardware: null,
      isNewCustomer: isNewCustomer || false,
    };

    // 2. ����� �������� ��������
    const last7days = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    // ��� ������� ������� �� ����� ��������
    // ��� ��� 200 ��� ��� ����� ��������� (���� ����)
    const recentOrders = await db.order.findMany({
      where: { merchantId, createdAt: { gte: last7days } },
      orderBy: { createdAt: 'desc' },
      take: 200
    });

    const formattedOrders = recentOrders.map(o => ({
      id: o.orderId,
      email: o.email,
      ipAddress: o.ipAddress,
      deviceFingerprint: o.deviceFingerprint,
      deviceId: o.deviceFingerprint,
      amount: o.amount,
      createdAt: o.createdAt,
      riskLevel: o.riskLevel,
    }));

    // ���� ��� velocity counts �������� ��������� ������ (����)
    const last1h = new Date(Date.now() - 60 * 60 * 1000);
    const last6h = new Date(Date.now() - 6 * 60 * 60 * 1000);
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const deviceVelocityCount = deviceFingerprint ? await db.order.count({
      where: { merchantId, deviceFingerprint, createdAt: { gte: last1h } }
    }) : 0;

    const ipVelocityCount = ipAddress ? await db.order.count({
      where: { merchantId, ipAddress, createdAt: { gte: last24h } }
    }) : 0;

    const emailVelocityCount = email ? await db.order.count({
      where: { merchantId, email, createdAt: { gte: last6h } }
    }) : 0;

    // ����� ��� ����� ��� computedSignals (���� ������� ��� riskScoring ������)
    // ����� ��������� ������ �� signalsSnapshot

    // ��� �������� ������� (��� 90 ���)
    const disputes = await db.disputeOutcome.findMany({
      where: {
        merchantId,
        resolvedAt: { gte: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000) },
        OR: [
          { order: { email: email } },
          { order: { deviceFingerprint: deviceFingerprint } },
          { order: { ipAddress: ipAddress } }
        ]
      },
      include: { order: true },
      take: 200
    });
    const blacklist = [];

    // 3. ���� ����� ������� ������ �����
    const orderForGraph = {
      deviceFingerprint: deviceFingerprint,
      deviceId: deviceFingerprint,
      email: email,
      ipAddress: ipAddress,
      shippingAddress: shippingCountry ? JSON.stringify({ country: shippingCountry }) : null,
      fingerprintVersion: 'v3',
    };

    try {
      await buildGraphFromOrder(orderForGraph, merchantId);
    } catch (err) {
      logger.error({ module: 'risk', action: 'buildGraphFromOrder', error: err.message }, 'Graph build error');
    }
        const evaluateStart = Date.now();

    // 4. ������� ���� ������� (�� ����� velocityCounts)
    const merchantConfig = {
      countryOverrides: req.tenant.countryOverrides || {}
    };

    const riskResult = await calculateRiskScore(
      order,
      formattedOrders,
      disputes,
      blacklist,
      merchantId,
      false,
      { deviceVelocityCount, ipVelocityCount, emailVelocityCount },
      null,           // cardHashRecord — متاح فقط في /enrich
      merchantConfig
    );

    // 5. ���� ���������
    const response = {
      orderId: orderId,
      score: riskResult.score,
      decision: riskResult.decision.includes('Approve') ? 'approve' :
                riskResult.decision.includes('Review') ? 'review' : 'block',
      flags: riskResult.flags,
      connectedRisk: 0,
    };

    // ������� connectedRisk ������ �� ����� Identity Graph
  response.connectedRisk = riskResult.graphRisk || 0;
   // تسجيل المحاولة الفاشلة عند block
    if (response.decision === 'block') {
      recordFailedAttempt({ ip: ipAddress, deviceFingerprint, merchantId, amount: amount || 0 });

      // ── Quota Counter: coupled to the enforcement decision ─────────────
      // BlockedAttempt logging + monthlyBlockedCount increment happen here,
      // atomically, because this is the authoritative point where the block
      // decision is made — not in the separate, best-effort /blocked-attempt
      // call from the plugin, which can under-count under load (its own
      // 60/min rate limiter) or drop silently on network failure. The
      // counter must never depend on a less-trusted client's follow-up call
      // for a control that gates paid-tier revenue.
      let evalCardBin = null;
      if (bin != null) {
        const b = String(bin).replace(/\D/g, '').slice(0, 6);
        if (b.length === 6) evalCardBin = b;
      }

      let evalCardType = null;
      if (req.body.cardType != null) {
        const ct = String(req.body.cardType).toLowerCase().trim();
        evalCardType = VALID_CARD_TYPES.has(ct) ? ct : 'unknown';
      }

      const evalIpHash = ipAddress ? hashIp(ipAddress) : null;

      let evalAmount = null;
      if (amount != null) {
        const amt = parseFloat(amount);
        if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) evalAmount = amt;
      }

      let evalRiskScore = null;
      if (riskResult.score != null) {
        const rs = parseInt(riskResult.score, 10);
        if (!isNaN(rs) && rs >= 0 && rs <= 100) evalRiskScore = rs;
      }

      try {
        await db.$transaction(recordBlockedAttempt(db, {
          merchantId:      req.tenant.id,
          storeId:         req.storeId ?? null,
          cardBin:         evalCardBin,
          cardType:        evalCardType,
          reason:          'pattern',
          ipHash:          evalIpHash,
          amountAttempted: evalAmount,
          riskScore:       evalRiskScore,
        }));
      } catch (counterErr) {
        // Logged, not fatal: a failed counter write shouldn't turn an
        // already-computed, correct block decision into a 500 for the
        // merchant. This is the one residual drift window in this design —
        // see write-up for the tradeoff.
        logger.error(
          { module: 'risk', endpoint: 'evaluate', tenantId: req.tenant.id, error: counterErr.message },
          'Failed to record BlockedAttempt / increment quota counter from /evaluate'
        );
      }
    }

    // 6. ��� ����� �� ����� ��������
    if (orderId) {
        const computed = riskResult.computedSignals || {};
      // ������� ����� �������� ������ �� externalVelocity (�������� �� ������)
      const deviceVelocityCountFinal = deviceVelocityCount;   // �� ���� ������
      const ipVelocityCountFinal = ipVelocityCount;           // �� ���� ������
      const emailVelocityCountFinal = emailVelocityCount;     // �� ���� ������
      const isNewCustomerComputed = computed.isNewCustomer || false;
      const amountAnomaly = (computed.orderMultiple || 0) >= 3;

      const shippingMismatchFlag = riskResult.flags.find(f => f.text.includes('Shipping country differs from billing'));
      const shippingBillingMismatch = !!shippingMismatchFlag;

      const signalsSnapshot = {
        email,
        ipAddress,
        bin: bin || null,
        deviceFingerprint,
        amount,
        billingCountry,
        shippingCountry,
        isNewCustomer: isNewCustomerComputed,
        deviceVelocityCount: deviceVelocityCountFinal,
        ipVelocityCount: ipVelocityCountFinal,
        emailVelocityCount: emailVelocityCountFinal,
        shippingBillingMismatch,
        binIssuerMismatch: riskResult.binIntel && riskResult.binIntel.issuerCountry !== billingCountry,
        amountAnomaly,
        ipIntel: riskResult.ipIntel || null,
        emailIntel: riskResult.emailIntel || null,
        binIntel: riskResult.binIntel || null,
        connectedRisk: response.connectedRisk,
        graphPath: riskResult.graphPath || [],
        flags: riskResult.flags,
        positives: riskResult.positives,
      };

      const savedOrder = await db.order.upsert({
        where: { merchantId_orderId: { merchantId, orderId } },
        create: {
          orderId,
          merchantId,
          amount: amount || 0,
          currency: 'USD',
          email: email || null,
          ipAddress: ipAddress || null,
          deviceFingerprint: deviceFingerprint || null,
          riskScore: riskResult.score,
          riskLevel: response.decision === 'approve' ? 'low' : (response.decision === 'review' ? 'medium' : 'high'),
          decision: response.decision,
          connectedRisk: response.connectedRisk,
          signalsSnapshot: JSON.stringify(signalsSnapshot),
        },
        update: {
          amount: amount || 0,
          email: email || null,
          ipAddress: ipAddress || null,
          deviceFingerprint: deviceFingerprint || null,
          riskScore: riskResult.score,
          riskLevel: response.decision === 'approve' ? 'low' : (response.decision === 'review' ? 'medium' : 'high'),
          decision: response.decision,
          connectedRisk: response.connectedRisk,
          fingerprintVersion: order.fingerprintVersion || null,
          fingerprintStatus: order.fingerprintStatus || null,
          signalsSnapshot: JSON.stringify(signalsSnapshot),
        },
      });

      // ��� RiskEvaluation ��� ��� ������ block �� review
      if (response.decision === 'block' || response.decision === 'review') {
        await db.riskEvaluation.upsert({
        where: { orderId: savedOrder.id },
        create: {
          orderId: savedOrder.id,
            staticScore: riskResult.score,
            learningScore: riskResult.score,
            finalDecision: response.decision === 'approve' ? 'low' : (response.decision === 'review' ? 'medium' : 'high'),
            topSignals: JSON.stringify(riskResult.flags.slice(0, 5)),
            positiveSignals: JSON.stringify(riskResult.positives || []),
            scoringVersion: riskResult.scoringVersion || 'v1.0',
            fraudProb: riskResult.economicData?.fraudProb ?? null,
            expectedLoss: riskResult.economicData?.expectedLoss ?? null,
            thresholdUsed: riskResult.economicData?.baseThreshold ?? null,
            decisionBefore: riskResult.economicData?.decisionBefore ?? null,
            decisionAfter: riskResult.economicData?.decisionAfter ?? null,
          },
          update: {
            staticScore: riskResult.score,
            learningScore: riskResult.score,
            finalDecision: response.decision === 'approve' ? 'low' : (response.decision === 'review' ? 'medium' : 'high'),
            topSignals: JSON.stringify(riskResult.flags.slice(0, 5)),
            positiveSignals: JSON.stringify(riskResult.positives || []),
            fraudProb: riskResult.economicData?.fraudProb ?? null,
            expectedLoss: riskResult.economicData?.expectedLoss ?? null,
            thresholdUsed: riskResult.economicData?.baseThreshold ?? null,
            decisionBefore: riskResult.economicData?.decisionBefore ?? null,
            decisionAfter: riskResult.economicData?.decisionAfter ?? null,
          },
        });
      }
    }

    prometheus.recordEvaluateDuration(Date.now() - evaluateStart);
    prometheus.recordEvaluateDecision(response.decision);
    res.json(response);
  } catch (error) {
    logger.error({ module: 'risk', error: error.message, stack: error.stack }, 'Evaluate error');
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});
// ���� ����� ����� ���� ����� ������ ��� ���� (������ �������� ���)
/**
 * @swagger
 * /risk/mark-fraud:
 *   post:
 *     summary: Mark a device as fraudulent (for testing)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [deviceFingerprint, merchantId]
 *             properties:
 *               deviceFingerprint: { type: string }
 *               email: { type: string }
 *               ipAddress: { type: string }
 *               merchantId: { type: string }
 *     responses:
 *       200:
 *         description: Device marked as fraud
 *       400:
 *         description: Missing deviceFingerprint or merchantId
 *       500:
 *         description: Internal error
 */
router.post('/mark-fraud', apiKeyAuth, verifyHmacSignature, async (req, res) => {
  // ��� ������ �� ���� �������
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ error: 'Endpoint not available in production' });
  }
  try {
    const { deviceFingerprint, email, ipAddress } = req.body;
    if (!deviceFingerprint) {
      return res.status(400).json({ error: 'deviceFingerprint required' });
    }

    const { markOrderAsFraud } = require('../lib/identityGraph');
    
    const mockOrder = {
      deviceFingerprint,
      deviceId: deviceFingerprint,
      email: email || 'fraud@test.com',
      ipAddress: ipAddress || '192.168.1.1',
      shippingAddress: JSON.stringify({ country: 'US' }),
      fingerprintVersion: 'v3',
    };

     const merchantId = req.tenant.id;
    await markOrderAsFraud(mockOrder, merchantId);

    
    res.json({ success: true, message: `Device ${deviceFingerprint} marked as fraud` });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'mark-fraud', error: error.message }, error.message);
    res.status(500).json({ error: error.message });
  }
});
// ���� ����� ������ �� ����� ����� (Feedback Loop)
// ������ orderId � isFraud (true = ����� ��� ������, false = ����� ��� ������)
const { processFeedback } = require('../lib/feedbackLoop');
/**
 * @swagger
 * /risk/feedback:
 *   post:
 *     summary: Provide feedback on a previous evaluation (for learning)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [orderId, isFraud]
 *             properties:
 *               orderId: { type: string }
 *               isFraud: { type: boolean }
 *     responses:
 *       200:
 *         description: Feedback recorded
 *       400:
 *         description: Missing orderId or isFraud
 *       500:
 *         description: Internal error
 */
router.post('/feedback', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { orderId, isFraud } = req.body;
    // CRITICAL FIX (C4): merchantId is derived from the authenticated tenant
    // (never trusted from the request body — CWE-639 / OWASP API1:2023),
    // and is now explicitly passed to processFeedback() so the lookup
    // inside feedbackLoop.js can be scoped to this tenant's own orders.
    // Previously this call passed no merchant context at all, meaning any
    // authenticated tenant could report fraud against any other tenant's
    // orderId and poison that tenant's MerchantProfile, SignalStat,
    // identity graph, and the shared cross-merchant pattern network.
    const merchantId = req.tenant.id;

    if (!orderId) {
      return res.status(400).json({ error: 'orderId is required' });
    }
    if (isFraud === undefined || isFraud === null) {
      return res.status(400).json({ error: 'isFraud is required (true/false)' });
    }

    // ������� ���� ������
    // ���� isFraud ������ (true = lost, false = won)
    await processFeedback(orderId, isFraud ? 'lost' : 'won', merchantId);

    res.json({ success: true, message: 'Feedback recorded successfully' });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'feedback', error: error.message }, 'Feedback API error');
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});

// ========== POST /risk/reconcile ==========
// Links a temporary pre-order risk evaluation (Classic Checkout, created
// before the real WooCommerce order existed) to the real order ID once
// woocommerce_checkout_order_created fires. Without this, the Order row
// stays permanently keyed under the throwaway pre_xxxxx ID and the entire
// feedback loop (dispute recording, identity-graph fraud marking,
// pattern-sharing, SignalStat training) silently no-ops for every Classic
// Checkout order. See class-api-client.php reconcile_order() for the caller.
//
// Field names (preOrderId / orderId) match what reconcile_order() actually
// sends — not oldOrderId/newOrderId.
/**
 * @swagger
 * /risk/reconcile:
 *   post:
 *     summary: Re-key a pre-order Order row under the real WooCommerce order ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [preOrderId, orderId]
 *             properties:
 *               preOrderId: { type: string }
 *               orderId: { type: string }
 *     responses:
 *       200:
 *         description: Reconciled successfully
 *       400:
 *         description: Missing preOrderId or orderId
 *       404:
 *         description: No matching pre-order found for this tenant
 *       409:
 *         description: orderId already exists for this tenant (duplicate reconciliation)
 *       500:
 *         description: Internal error
 */
router.post('/reconcile', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { preOrderId, orderId } = req.body;
    // merchantId derived from the authenticated tenant only — never trust
    // a client-supplied merchant identifier (CWE-639 / OWASP API1:2023),
    // consistent with every other route in this file.
    const merchantId = req.tenant.id;

    if (!preOrderId || typeof preOrderId !== 'string' || !preOrderId.trim()) {
      return res.status(400).json({ error: 'preOrderId is required' });
    }
    if (!orderId || typeof orderId !== 'string' || !orderId.trim()) {
      return res.status(400).json({ error: 'orderId is required' });
    }

    // Scoped lookup via the compound key — this can structurally only
    // return a row belonging to the calling tenant, or no row at all
    // (same pattern as feedbackLoop.js's C4-guarded lookup).
    const existing = await db.order.findUnique({
      where: { merchantId_orderId: { merchantId, orderId: preOrderId } },
      select: { id: true, merchantId: true },
    });

    // Generic 404 — deliberately does not distinguish "no such pre-order"
    // from "pre-order belongs to a different tenant", to avoid an
    // enumeration oracle (same rationale as processFeedbackSimplified's
    // order-not-found branch in feedbackLoop.js).
    if (!existing) {
      logger.warn({ module: 'risk', endpoint: 'reconcile', merchantId, preOrderId }, 'Reconcile: no matching pre-order found for this tenant');
      return res.status(404).json({ error: 'Order not found' });
    }

    try {
      await db.order.update({
        where: { id: existing.id },
        data: { orderId },
      });
    } catch (updateErr) {
      if (updateErr.code === 'P2002') {
        // newOrderId already exists for this tenant — most likely a
        // duplicate/retried reconciliation call. Not a server fault.
        logger.info({ module: 'risk', endpoint: 'reconcile', merchantId, preOrderId, orderId }, 'Reconcile: target orderId already exists for this tenant');
        return res.status(409).json({ error: 'An order with this orderId already exists for this merchant' });
      }
      throw updateErr;
    }

    logger.info({ module: 'risk', endpoint: 'reconcile', merchantId, preOrderId, orderId }, 'Pre-order reconciled to real order ID');
    res.json({ success: true });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'reconcile', error: error.message, stack: error.stack }, 'Reconcile error');
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});

// ���� ����� ����� ������� buildGraphFromOrder
/**
 * @swagger
 * /risk/test-graph:
 *   post:
 *     summary: Test identity graph building (for debugging)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [deviceFingerprint, merchantId]
 *             properties:
 *               deviceFingerprint: { type: string }
 *               email: { type: string }
 *               ipAddress: { type: string }
 *               merchantId: { type: string }
 *     responses:
 *       200:
 *         description: Graph built
 *       400:
 *         description: Missing deviceFingerprint or merchantId
 *       500:
 *         description: Internal error
 */
router.post('/test-graph', apiKeyAuth, async (req, res) => {
  // ��� ������ �� ���� �������
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ error: 'Endpoint not available in production' });
  }
  try {
    const { deviceFingerprint, email, ipAddress } = req.body;
    if (!deviceFingerprint) {
      return res.status(400).json({ error: 'deviceFingerprint required' });
    }

    const { buildGraphFromOrder } = require('../lib/identityGraph');
    
    const mockOrder = {
      deviceFingerprint,
      deviceId: deviceFingerprint,
      email: email || 'test@test.com',
      ipAddress: ipAddress || '8.8.8.8',
      shippingAddress: JSON.stringify({ country: 'US' }),
      fingerprintVersion: 'v3',
    };

   const merchantId = req.tenant.id;
    await buildGraphFromOrder(mockOrder, merchantId);    
    res.json({ success: true, message: 'Graph built' });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'test-graph', error: error.message }, error.message);
    res.status(500).json({ error: error.message });
  }
});
// ========== Blacklist Management Endpoints ==========
// ����� ���� ��� ������� �������
/**
 * @swagger
 * /risk/blacklist:
 *   post:
 *     summary: Add an entry to the blacklist
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [merchantId, type, value]
 *             properties:
 *               merchantId: { type: string }
 *               type: { type: string, enum: [EMAIL, IP, DEVICE_FINGERPRINT] }
 *               value: { type: string }
 *               reason: { type: string }
 *               expiresAt: { type: string, format: date-time }
 *               createdBy: { type: string }
 *     responses:
 *       200:
 *         description: Entry created
 *       400:
 *         description: Invalid input
 */
router.post('/blacklist', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { type, value, reason, expiresAt, createdBy } = req.body;
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)
    if (!type || !value) {
      return res.status(400).json({ error: 'type and value are required' });
    }
    // ������ �� ��� �����
    const validTypes = ['EMAIL', 'IP', 'DEVICE_FINGERPRINT'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: `type must be one of: ${validTypes.join(', ')}` });
    }

    const blacklistEntry = await db.blacklistEntry.create({
      data: {
        merchantId,
        type,
        value,
        reason: reason || null,
        expiresAt: expiresAt ? new Date(expiresAt) : null,
        createdBy: createdBy || null,
      },
    });
    prometheus.recordAccessControlAction('add', 'blacklist');
    res.json({ success: true, entry: blacklistEntry });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'blacklist-add', error: error.message }, 'Error adding blacklist entry');
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});

// ��� ���� �� ������� �������
/**
 * @swagger
 * /risk/blacklist/{id}:
 *   delete:
 *     summary: Delete a blacklist entry
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [merchantId]
 *             properties:
 *               merchantId: { type: string }
 *     responses:
 *       200:
 *         description: Entry deleted
 *       404:
 *         description: Entry not found
 */
router.delete('/blacklist/:id', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { id } = req.params;
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    // ������ �� �� ������ ����� ��� ��� ������
    const existing = await db.blacklistEntry.findFirst({
      where: { id, merchantId },
    });
    if (!existing) {
      return res.status(404).json({ error: 'Blacklist entry not found or not owned by this merchant' });
    }

    await db.blacklistEntry.delete({ where: { id } });    prometheus.recordAccessControlAction('delete', 'blacklist');
    res.json({ success: true, message: 'Blacklist entry deleted' });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'blacklist-delete', error: error.message }, 'Error deleting blacklist entry');
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});
// ========== GET Blacklist (Query) ==========
// ������� ������� ������� ������ ������
/**
 * @swagger
 * /risk/blacklist:
 *   get:
 *     summary: Get blacklist entries for a merchant
 *     parameters:
 *       - in: query
 *         name: merchantId
 *         required: true
 *         schema: { type: string }
 *       - in: query
 *         name: type
 *         schema: { type: string, enum: [EMAIL, IP, DEVICE_FINGERPRINT] }
 *       - in: query
 *         name: includeExpired
 *         schema: { type: boolean }
 *     responses:
 *       200:
 *         description: List of blacklist entries
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 entries: { type: array, items: { $ref: '#/components/schemas/BlacklistEntry' } }
 */
router.get('/blacklist', apiKeyAuth, domainAuthMiddleware, async (req, res) => {
  try {
   const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    const { type, includeExpired } = req.query;
    const where = { merchantId };

    // ����� ��� ����� (�������)
    if (type) {
      const validTypes = ['EMAIL', 'IP', 'DEVICE_FINGERPRINT'];
      if (!validTypes.includes(type)) {
        return res.status(400).json({ error: `type must be one of: ${validTypes.join(', ')}` });
      }
      where.type = type;
    }

    // ����� ��������: ���� ������� ���� ��� ������� ������� (��� ������ �� expiresAt null)
    if (includeExpired !== 'true') {
      where.OR = [
        { expiresAt: null },
        { expiresAt: { gt: new Date() } }
      ];
    }

    const blacklistEntries = await db.blacklistEntry.findMany({
      where,
      orderBy: { createdAt: 'desc' }
    });

    res.json({ success: true, entries: blacklistEntries });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'blacklist-get', error: error.message }, 'Error fetching blacklist');
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});
// ========== UPDATE Blacklist Entry ==========
/**
 * @swagger
 * /risk/blacklist/{id}:
 *   put:
 *     summary: Update a blacklist entry (reason or expiresAt)
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               merchantId: { type: string }
 *               reason: { type: string }
 *               expiresAt: { type: string, format: date-time, nullable: true }
 *     responses:
 *       200:
 *         description: Entry updated
 *       400:
 *         description: Missing merchantId
 *       404:
 *         description: Entry not found or not owned by this merchant
 */
router.put('/blacklist/:id', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
     const { id } = req.params;
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    // ������ �� ����� ������
    const existing = await db.blacklistEntry.findFirst({
      where: { id, merchantId },
    });
    if (!existing) {
      return res.status(404).json({ error: 'Blacklist entry not found or not owned by this merchant' });
    }

    const { reason, expiresAt } = req.body;
    const updateData = {};
    if (reason !== undefined) updateData.reason = reason;
    if (expiresAt !== undefined) {
      updateData.expiresAt = expiresAt ? new Date(expiresAt) : null;
    }

    const updated = await db.blacklistEntry.update({
      where: { id },
      data: updateData,
    });

    res.json({ success: true, entry: updated });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'blacklist-update', error: error.message }, 'Error updating blacklist entry');
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});

// ========== Whitelist Management Endpoints ==========

router.post('/whitelist', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { type, value, reason, expiresAt, createdBy } = req.body;
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)
    if (!type || !value) {
      return res.status(400).json({ error: 'type and value are required' });
    }
    const validTypes = ['EMAIL', 'IP', 'BIN'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: `type must be one of: ${validTypes.join(', ')}` });
    }

    const normalizedValue = type === 'BIN'
      ? String(value).replace(/\D/g, '').slice(0, 6)
      : value;

    if (type === 'BIN' && normalizedValue.length !== 6) {
      return res.status(400).json({ error: 'BIN must be exactly 6 digits' });
    }

    const whitelistEntry = await db.whitelistEntry.create({
      data: {
        merchantId,
        type,
        value: normalizedValue,
        reason: reason || null,
        expiresAt: expiresAt ? new Date(expiresAt) : null,
        createdBy: createdBy || null,
      },
    });
    prometheus.recordAccessControlAction('add', 'whitelist');
    res.json({ success: true, entry: whitelistEntry });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({ error: 'This entry already exists in the whitelist' });
    }
    logger.error({ module: 'risk', endpoint: 'whitelist-add', error: error.message }, 'Error adding whitelist entry');
    res.status(500).json({ error: error.message });
  }
});

router.get('/whitelist', apiKeyAuth, domainAuthMiddleware, async (req, res) => {
  try {
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    const { type, includeExpired } = req.query;
    const where = { merchantId };

    if (type) {
      const validTypes = ['EMAIL', 'IP', 'BIN'];
      if (!validTypes.includes(type)) {
        return res.status(400).json({ error: `type must be one of: ${validTypes.join(', ')}` });
      }
      where.type = type;
    }

    if (includeExpired !== 'true') {
      where.OR = [
        { expiresAt: null },
        { expiresAt: { gt: new Date() } }
      ];
    }

    const whitelistEntries = await db.whitelistEntry.findMany({
      where,
      orderBy: { createdAt: 'desc' }
    });

    res.json({ success: true, entries: whitelistEntries });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'whitelist-get', error: error.message }, 'Error fetching whitelist');    res.status(500).json({ error: error.message });
  }
});

router.delete('/whitelist/:id', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { id } = req.params;
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    const existing = await db.whitelistEntry.findFirst({
      where: { id, merchantId },
    });
    if (!existing) {
      return res.status(404).json({ error: 'Whitelist entry not found or not owned by this merchant' });
    }

    await db.whitelistEntry.delete({ where: { id } });
    prometheus.recordAccessControlAction('delete', 'whitelist');
    res.json({ success: true, message: 'Whitelist entry deleted' });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'whitelist-delete', error: error.message }, 'Error deleting whitelist entry');
    res.status(500).json({ error: error.message });
  }
});

// WooCommerce webhook endpoint
router.post('/woocommerce-webhook', async (req, res) => {
  try {
    // 1. Get raw body for signature verification
    const rawBody = req.body; // express.raw puts Buffer in req.body
    
    if (!rawBody) {
      return res.status(400).json({ error: 'Raw body missing' });
    }

    // 2. Parse raw body to JSON (���� parsedBody �����)
    let parsedBody;
    try {
      parsedBody = JSON.parse(rawBody.toString());
    } catch (err) {
      logger.error({ module: 'risk', err: err.message }, 'Failed to parse webhook body');
      return res.status(400).json({ error: 'Invalid JSON payload' });
    }

      // merchantId is derived from the authenticated tenant via x-api-key, never from the
    // webhook payload (CWE-639 / OWASP API1:2023). The WooCommerce plugin is configured
    // with the tenant's API key and must send it on every webhook delivery.
    //
    // Tenant resolution now goes through the same centralized requireAuth()
    // middleware used by every other route in this file, instead of a manual
    // resolveTenantByApiKey/isActive/emailVerified copy (CWE-1059 drift fix —
    // see runAuthMiddleware/webhookAuth definitions above). This also gives
    // the webhook endpoint the same standardized 401/403 response shape and
    // uniform 200ms auth-failure timing delay as every other endpoint.
    const authOk = await runAuthMiddleware(req, res, webhookAuth);
    if (!authOk) return; // webhookAuth already sent the response (401/403/500)
    const merchantId = req.tenant.id;

    // ── WooCommerce Signature Verification (mirrors /evaluate's ordering:
    // auth → signature → quota → business logic) ───────────────────────────
    // Moved ahead of the quota gate (Issue #3 fix). Previously this ran
    // AFTER checkQuotaGate, so an authenticated-but-unsigned/misconfigured
    // request from a near-quota tenant surfaced as "quota exceeded" instead
    // of "invalid signature" — masking the real root cause in logs and
    // alerts. No security change: requireAuth() already gated both checks
    // before and after this reorder.
    const wcSecret = process.env.WOOCOMMERCE_WEBHOOK_SECRET;
    const signature = req.headers['x-wc-webhook-signature'];
    if (wcSecret && signature) {
      const { verifyWebhookSignature } = require('../lib/woocommerce');
      const expected = crypto.createHmac('sha256', wcSecret).update(rawBody).digest('base64');
      
      // ��� ������� �������� (���� ������� �� �������� �������)
      logger.warn({
        module: 'risk',
        receivedSignatureLength: signature.length,
        expectedSignatureLength: expected.length,
        firstRawBodyChars: rawBody.toString('utf8').slice(0, 50),
        secretConfigured: !!wcSecret,
        signaturePresent: !!signature,
      }, 'Signature debug info');
      
      const isValid = crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
      if (!isValid) {
        logger.warn({ module: 'risk', reason: 'mismatch' }, 'Signature mismatch — rejecting forged webhook request');
        return res.status(401).json({ error: 'Invalid signature' });
      }
    } else if (wcSecret && !signature) {
      // Secret configured but signature missing � reject
      return res.status(401).json({ error: 'Missing signature' });
    }
    // If no secret configured, skip signature verification (not recommended for production)

    // ── Quota Gate (mirrors /evaluate's fail-open behavior exactly) ────────
    // Both order-evaluation paths must agree on what "quota exhausted"
    // means. Without this, a Starter/Pro tenant who has hit their monthly
    // limit still gets orders scored (and potentially blocked) via this
    // webhook, even though checkout-time /evaluate is already failing
    // open for the same tenant. Returns the identical unscored-approve
    // shape /evaluate returns, before calculateRiskScore() or any
    // BlockedAttempt/monthlyBlockedCount write.
    if (await checkQuotaGate(req, res, 'woocommerce-webhook')) return;
    // ── End Quota Gate ──────────────────────────────────────────────────────

   // 5. Extract order data
   const { extractOrderData, buildRiskEvaluationRequest } = require('../lib/woocommerce');
   let extracted;
   try {
     extracted = extractOrderData(parsedBody);
   } catch (err) {
     logger.error({ module: 'risk', err: err.message }, 'Failed to extract order data');
     return res.status(400).json({ error: 'Invalid payload structure' });
   }

   // 6. Idempotency: check if order already processed
   const existingOrder = await db.order.findUnique({
      where: { merchantId_orderId: { merchantId, orderId: extracted.orderId } },
      select: { merchantId: true, decision: true, riskScore: true, signalsSnapshot: true, createdAt: true }
    });
    // Defense-in-depth (C3): mirrors the /evaluate guard above — should be
    // unreachable given the compound key, asserted anyway.
    if (existingOrder && existingOrder.merchantId !== merchantId) {
      logger.error({ module: 'risk', endpoint: 'woocommerce-webhook', merchantId, orderId: extracted.orderId }, 'C3 guard tripped — compound key returned a different merchant\'s row; should be unreachable');
      return res.status(403).json({ error: 'Merchant ID mismatch.' });
    }
    if (existingOrder) {
      // Return cached response (within reasonable time window, e.g., 24h)
      const ageHours = (Date.now() - new Date(existingOrder.createdAt).getTime()) / (1000 * 60 * 60);
      if (ageHours < 24) {
        logger.info({ module: 'risk', orderId: extracted.orderId }, 'Idempotent request � returning cached result');
        return res.json({
          orderId: extracted.orderId,
          score: existingOrder.riskScore,
          decision: existingOrder.decision,
          cached: true
        });
      }
    }

    // 7. Build request for risk scoring
    const riskRequest = buildRiskEvaluationRequest(extracted);
    riskRequest.merchantId = merchantId;

    // ������� ���� ������ �� Webhook (��� ����)
    let deviceFingerprint = parsedBody.device_fingerprint || null;
    if (!deviceFingerprint && parsedBody.meta_data) {
        const fpMeta = parsedBody.meta_data.find(m => m.key === '_chargeguard_device_fingerprint');
        if (fpMeta) deviceFingerprint = fpMeta.value;
    }
    riskRequest.deviceFingerprint = deviceFingerprint || `wc_${extracted.orderId}`; // fallback

    // 7a. Whitelist Check
    const webhookWhitelistConditions = [];
    if (extracted.email)    webhookWhitelistConditions.push({ type: 'EMAIL', value: extracted.email });
    if (extracted.ipAddress) webhookWhitelistConditions.push({ type: 'IP',   value: extracted.ipAddress });

    if (webhookWhitelistConditions.length > 0) {
      const webhookWhitelistCheck = await db.whitelistEntry.findFirst({
        where: {
          merchantId,
          OR: webhookWhitelistConditions,
          AND: [{ OR: [
            { expiresAt: null },
            { expiresAt: { gt: new Date() } }
          ]}]
        }
      });

      if (webhookWhitelistCheck) {
        prometheus.recordWhitelistBypass(webhookWhitelistCheck.type);
        logger.info(
          { module: 'risk', merchantId, type: webhookWhitelistCheck.type, orderId: extracted.orderId },
          'Webhook request bypassed all checks — whitelisted'
        );
        return res.json({
          orderId: extracted.orderId,
          score: 0,
          decision: 'approve',
          flags: [],
          connectedRisk: 0,
          whitelisted: true
        });
      }
    }

     // 7b. BIN Sequence Detection
    if (extracted.bin) {
      // tenantId is required here for tenant-scoped storage in
      // binSequenceDetector.js (CWE-653 fix) — merchantId is already
      // resolved above from the authenticated tenant (req.tenant.id).
      const binSeq = await checkBINSequence({
        tenantId: merchantId,
        bin: extracted.bin,
        ipAddress: extracted.ipAddress,
        deviceFingerprint: riskRequest.deviceFingerprint
      });
      // tenantId resolved from the authenticated tenant (merchantId, derived
      // from req.tenant.id via the webhook's requireAuth resolution above) —
      // previously hardcoded to null, which meant BinSequenceAlert rows from
      // this path had no tenant association and were invisible to the
      // dashboard and to notifyBINSequenceAlert's tenant lookup.
      if (binSeq.blocked || binSeq.riskAddition > 0) {
        persistBinSequenceAlert(merchantId, extracted.bin, binSeq)
          .catch(err => logger.error({ module: 'risk', err: err.message }, 'BinSequenceAlert persist failed'));
      }

      if (binSeq.blocked) {
        let webhookBinSeqCardBin = null;
        if (extracted.bin != null) {
          const b = String(extracted.bin).replace(/\D/g, '').slice(0, 6);
          if (b.length === 6) webhookBinSeqCardBin = b;
        }
        const webhookBinSeqIpHash = extracted.ipAddress ? hashIp(extracted.ipAddress) : null;
        let webhookBinSeqAmount = null;
        if (extracted.amount != null) {
          const amt = parseFloat(extracted.amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) webhookBinSeqAmount = amt;
        }

        // storeId is always null here — this route does not run
        // domainAuthMiddleware, so req.storeId is never populated for
        // webhook-originated blocks (known limitation; see class-api-client.php
        // notes). cardType is also always null — extractOrderData() does not
        // capture a card-type field from the WooCommerce payload.
        try {
          await db.$transaction(recordBlockedAttempt(db, {
            merchantId:      merchantId,
            storeId:         null,
            cardBin:         webhookBinSeqCardBin,
            cardType:        null,
            reason:          'card_testing',
            ipHash:          webhookBinSeqIpHash,
            amountAttempted: webhookBinSeqAmount,
            riskScore:       null,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'woocommerce-webhook', path: 'bin_sequence', tenantId: merchantId, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (webhook BIN sequence path)'
          );
        }

        return res.status(403).json({
          error: 'Request blocked due to suspicious card testing pattern',
          reason: binSeq.reason,
          decision: 'block',
          flags: [{ severity: 'critical', text: binSeq.reason }]
        });
      }
    }

    // 8. Load recent orders, disputes, blacklist for this merchant
    const last7days = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const recentOrders = await db.order.findMany({
      where: { merchantId, createdAt: { gte: last7days } },
      orderBy: { createdAt: 'desc' },
      take: 200
    });
    const formattedOrders = recentOrders.map(o => ({
      id: o.orderId,
      email: o.email,
      ipAddress: o.ipAddress,
      deviceFingerprint: o.deviceFingerprint,
      amount: o.amount,
      createdAt: o.createdAt,
      riskLevel: o.riskLevel,
    }));
    const disputes = await db.disputeOutcome.findMany({
      where: {
        merchantId,
        resolvedAt: { gte: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000) },
        OR: [
          { order: { email: extracted.email } },
          { order: { deviceFingerprint: riskRequest.deviceFingerprint } },
          { order: { ipAddress: extracted.ipAddress } }
        ]
      },
      include: { order: true },
      take: 200
    });
    const blacklistOr = [];
    if (extracted.email) blacklistOr.push({ type: 'EMAIL', value: extracted.email });
    if (extracted.ipAddress) blacklistOr.push({ type: 'IP', value: extracted.ipAddress });
    if (riskRequest.deviceFingerprint) blacklistOr.push({ type: 'DEVICE_FINGERPRINT', value: riskRequest.deviceFingerprint });

    let blacklist = [];
    if (blacklistOr.length > 0) {
      blacklist = await db.blacklistEntry.findMany({
        where: {
          merchantId,
          OR: blacklistOr,
          AND: [
            { OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }] }
          ]
        }
      });
    }

    // 9. Velocity counts
    const last1h = new Date(Date.now() - 60 * 60 * 1000);
    const last6h = new Date(Date.now() - 6 * 60 * 60 * 1000);
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const deviceVelocityCount = riskRequest.deviceFingerprint ? await db.order.count({
      where: { merchantId, deviceFingerprint: riskRequest.deviceFingerprint, createdAt: { gte: last1h } }
    }) : 0;
    const ipVelocityCount = extracted.ipAddress ? await db.order.count({
      where: { merchantId, ipAddress: extracted.ipAddress, createdAt: { gte: last24h } }
    }) : 0;
    const emailVelocityCount = extracted.email ? await db.order.count({
      where: { merchantId, email: extracted.email, createdAt: { gte: last6h } }
    }) : 0;

    // 10. Build order object for riskScoring (compatible with calculateRiskScore)
    const orderForScoring = {
      id: extracted.orderId,
      email: extracted.email,
      ipAddress: extracted.ipAddress,
      deviceFingerprint: riskRequest.deviceFingerprint,
      amount: extracted.amount,
      billingAddress: extracted.billingCountry ? JSON.stringify({ country: extracted.billingCountry }) : null,
      shippingAddress: extracted.shippingCountry ? JSON.stringify({ country: extracted.shippingCountry }) : null,
      customerLoginId: extracted.customerLoginId,
      createdAt: extracted.createdAt || new Date().toISOString(),
      eciCode: null,
      avsResponse: null,
      cvv2Response: null,
      payment_details: extracted.bin ? { card_bin: extracted.bin } : null,
      fingerprintVersion: 'v3',
      fingerprintConfig: null,
      fingerprintHardware: null,
      isNewCustomer: false, // will be computed inside riskScoring
    };

    const { calculateRiskScore } = require('../lib/riskScoring');
    const riskResult = await calculateRiskScore(
      orderForScoring,
      formattedOrders,
      disputes,
      blacklist,
      merchantId,
      true,  // saveEvaluation
      { deviceVelocityCount, ipVelocityCount, emailVelocityCount }
    );

    // 11. Build signals snapshot
    const signalsSnapshot = {
      email: extracted.email,
      ipAddress: extracted.ipAddress,
      bin: extracted.bin,
      deviceFingerprint: riskRequest.deviceFingerprint,
      amount: extracted.amount,
      billingCountry: extracted.billingCountry,
      shippingCountry: extracted.shippingCountry,
      isNewCustomer: riskResult.computedSignals?.isNewCustomer || false,
      deviceVelocityCount,
      ipVelocityCount,
      emailVelocityCount,
      shippingBillingMismatch: extracted.billingCountry !== extracted.shippingCountry,
      binIssuerMismatch: false, // would need BIN intel
      amountAnomaly: (riskResult.computedSignals?.orderMultiple || 0) >= 3,
      ipIntel: riskResult.ipIntel || null,
      emailIntel: riskResult.emailIntel || null,
      binIntel: riskResult.binIntel || null,
      connectedRisk: riskResult.graphRisk || 0,
      graphPath: riskResult.graphPath || [],
      flags: riskResult.flags,
      positives: riskResult.positives,
    };

    // 12. Save order and risk evaluation
    await db.order.upsert({
      where: { merchantId_orderId: { merchantId, orderId: extracted.orderId } },
      create: {
        orderId: extracted.orderId,
        merchantId,
        amount: extracted.amount,
        currency: 'USD',
        email: extracted.email,
        ipAddress: extracted.ipAddress,
        deviceFingerprint: riskRequest.deviceFingerprint,
        riskScore: riskResult.score,
        riskLevel: riskResult.riskLevel,
        decision: riskResult.decision.includes('Approve') ? 'approve' : (riskResult.decision.includes('Review') ? 'review' : 'block'),
        connectedRisk: riskResult.graphRisk || 0,
        signalsSnapshot: JSON.stringify(signalsSnapshot),
        fingerprintVersion: 'v3',
      },
      update: {
        amount: extracted.amount,
        email: extracted.email,
        ipAddress: extracted.ipAddress,
        deviceFingerprint: riskRequest.deviceFingerprint,
        riskScore: riskResult.score,
        riskLevel: riskResult.riskLevel,
        decision: riskResult.decision.includes('Approve') ? 'approve' : (riskResult.decision.includes('Review') ? 'review' : 'block'),
        connectedRisk: riskResult.graphRisk || 0,
        signalsSnapshot: JSON.stringify(signalsSnapshot),
      },
    });

    // Optionally save RiskEvaluation if decision is block or review
    if (riskResult.decision.includes('Block') || riskResult.decision.includes('Review')) {
      const savedOrder = await db.order.findUnique({ where: { merchantId_orderId: { merchantId, orderId: extracted.orderId } } });
      if (savedOrder) {
        await db.riskEvaluation.upsert({
          where: { orderId: savedOrder.id },
          create: {
            orderId: savedOrder.id,
            staticScore: riskResult.score,
            learningScore: riskResult.score,
            finalDecision: riskResult.decision.includes('Approve') ? 'low' : (riskResult.decision.includes('Review') ? 'medium' : 'high'),
            topSignals: JSON.stringify(riskResult.flags.slice(0, 5)),
            positiveSignals: JSON.stringify(riskResult.positives || []),
            scoringVersion: riskResult.scoringVersion || 'v1.0',
            fraudProb: riskResult.economicData?.fraudProb ?? null,
            expectedLoss: riskResult.economicData?.expectedLoss ?? null,
            thresholdUsed: riskResult.economicData?.baseThreshold ?? null,
            decisionBefore: riskResult.economicData?.decisionBefore ?? null,
            decisionAfter: riskResult.economicData?.decisionAfter ?? null,
          },
          update: {
            staticScore: riskResult.score,
            learningScore: riskResult.score,
            finalDecision: riskResult.decision.includes('Approve') ? 'low' : (riskResult.decision.includes('Review') ? 'medium' : 'high'),
            topSignals: JSON.stringify(riskResult.flags.slice(0, 5)),
            positiveSignals: JSON.stringify(riskResult.positives || []),
            fraudProb: riskResult.economicData?.fraudProb ?? null,
            expectedLoss: riskResult.economicData?.expectedLoss ?? null,
            thresholdUsed: riskResult.economicData?.baseThreshold ?? null,
            decisionBefore: riskResult.economicData?.decisionBefore ?? null,
            decisionAfter: riskResult.economicData?.decisionAfter ?? null,
          },
        });
      }
    }

    // ── Quota Counter: webhook risk-scoring block path ──────────────────
    // Second of two block-producing decision points on this route (the
    // first being the BIN-sequence early-return above). Without this,
    // blocks resolved via calculateRiskScore() through the webhook were
    // written to Order/RiskEvaluation but never counted in BlockedAttempt
    // or monthlyBlockedCount — this closes that gap.
    const webhookFinalDecision = riskResult.decision.includes('Approve') ? 'approve' : (riskResult.decision.includes('Review') ? 'review' : 'block');
    if (webhookFinalDecision === 'block') {
      let webhookFinalCardBin = null;
      if (extracted.bin != null) {
        const b = String(extracted.bin).replace(/\D/g, '').slice(0, 6);
        if (b.length === 6) webhookFinalCardBin = b;
      }
      const webhookFinalIpHash = extracted.ipAddress ? hashIp(extracted.ipAddress) : null;
      let webhookFinalAmount = null;
      if (extracted.amount != null) {
        const amt = parseFloat(extracted.amount);
        if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) webhookFinalAmount = amt;
      }
      let webhookFinalRiskScore = null;
      if (riskResult.score != null) {
        const rs = parseInt(riskResult.score, 10);
        if (!isNaN(rs) && rs >= 0 && rs <= 100) webhookFinalRiskScore = rs;
      }

      try {
        await db.$transaction(recordBlockedAttempt(db, {
          merchantId:      merchantId,
          storeId:         null, // domainAuthMiddleware does not run on this route
          cardBin:         webhookFinalCardBin,
          cardType:        null, // not captured by extractOrderData()
          reason:          'pattern',
          ipHash:          webhookFinalIpHash,
          amountAttempted: webhookFinalAmount,
          riskScore:       webhookFinalRiskScore,
        }));
      } catch (counterErr) {
        logger.error(
          { module: 'risk', endpoint: 'woocommerce-webhook', tenantId: merchantId, error: counterErr.message },
          'Failed to record BlockedAttempt / increment quota counter from woocommerce-webhook'
        );
      }
    }

    // Return response
    res.json({
      orderId: extracted.orderId,
      score: riskResult.score,
      decision: riskResult.decision.includes('Approve') ? 'approve' : (riskResult.decision.includes('Review') ? 'review' : 'block'),
      flags: riskResult.flags,
      connectedRisk: riskResult.graphRisk || 0,
    });

  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'woocommerce-webhook', error: error.message, stack: error.stack }, 'Webhook error');
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});
// ========== Check Device Endpoint ==========
// ������� ������ ���� ������� ���������� �� ������� �������
router.post('/check-device', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { fingerprint } = req.body;
    if (!fingerprint) {
      return res.status(400).json({ error: 'fingerprint is required' });
    }

  const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    // 1. ����� �� ���� ������ �� Identity Graph    const { getConnectedRisk } = require('../lib/identityGraph');
    const mockOrder = {
      deviceFingerprint: fingerprint,
      fingerprintVersion: 'v3',
    };

    let blocked = false;
    let reason = null;

    try {
      const graphResult = await getConnectedRisk(mockOrder, merchantId);
      // ��� ��� connectedRisk >= 80 ������ ������� ������ ������
      if (graphResult.connectedRisk >= 45) {
        blocked = true;
        reason = 'Device fingerprint linked to high-risk network';
      }
    } catch (err) {
      logger.error({ module: 'risk', endpoint: 'check-device', err }, 'Graph lookup error');
      // ��� ���: �� ���� �������� ��� ��� �����
    }

    // 2. (�������) ����� �� ������� ������� ��������
    if (!blocked) {
      const blacklisted = await db.blacklistEntry.findFirst({
        where: {
          merchantId,
          type: 'DEVICE_FINGERPRINT',
          value: fingerprint,
          OR: [
            { expiresAt: null },
            { expiresAt: { gt: new Date() } },
          ],
        },
      });
      if (blacklisted) {
        blocked = true;
        reason = 'Device is blacklisted';
      }
    }

    res.json({ blocked, reason });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'check-device', error: error.message }, 'Check-device error');
    // �� ���� ����á ���� blocked: false ���� ���������� �������
    res.status(500).json({ blocked: false, error: error.message });
  }
});

// ========== Enrich Endpoint ==========
// ������� ������ ����� ������� BIN �� ������ ����� �������� (��� Stripe)
router.post('/enrich', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { 
      orderId, 
      paymentIntentId, 
      bin, 
      cardBrand, 
      cardCountry, 
      funding, 
      issuer,
      last4,
      expMonth,
      expYear,
      brand,
      idempotencyKey 
    } = req.body;

    if (!orderId) {
      return res.status(400).json({ error: 'orderId is required' });
    }
    if (!bin && !last4) {
      return res.status(400).json({ error: 'bin or last4 is required' });
    }

    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    // ??? CardHash generation (if last4+expiry+brand provided) ???rovided) ???
    let cardHashRecord = null;
    if (last4 && expMonth && expYear && brand && merchantId) {

      const secret = process.env.CARD_HASH_SECRET;
      if (!secret) throw new Error('CARD_HASH_SECRET missing');
      const raw = `${merchantId}:${last4}:${expMonth}:${expYear}:${brand}`;
      const cardHash = crypto.createHmac('sha256', secret).update(raw).digest('hex');
      
      cardHashRecord = await db.cardHash.upsert({
        where: { cardHash },
        create: {
          merchantId,
          cardHash,
          last4,
          expMonth,
          expYear,
          brand,
          attemptCount: 1,
        },
        update: {
          attemptCount: { increment: 1 },
          lastSeenAt: new Date(),
        },
      });
    }

    // 1. ����� �� ����� �������
    const existingOrder = await db.order.findUnique({
      where: { merchantId_orderId: { merchantId, orderId } },
      select: { 
        id: true, 
        merchantId: true, 
        decision: true, 
        riskScore: true, 
        signalsSnapshot: true,
    
        amount: true,
        email: true,
        ipAddress: true,
        deviceFingerprint: true,
        createdAt: true,

        customerLoginId: true,
        fingerprintVersion: true,

        riskLevel: true,
      }
    });

    // 2. ��� �� ���� ����ȡ ���� pending enrichment
    if (!existingOrder) {
      await db.pendingEnrichment.create({
        data: {
          orderId,
          paymentIntentId: paymentIntentId || null,
          enrichData: JSON.stringify(req.body),
          status: 'pending'
        }
      });
      return res.status(202).json({ 
        success: true, 
        message: 'Order not found. Enrichment queued for processing.',
        orderId 
      });
    }

    // 3. ������ �� ����� ������
    if (existingOrder.merchantId !== merchantId) {
      return res.status(403).json({ error: 'Merchant ID mismatch. Order belongs to another merchant.' });
    }



    // 5. ����� ����� ������� enrichment
    let snapshot = {};
    try {
      snapshot = JSON.parse(existingOrder.signalsSnapshot || '{}');
    } catch {}

    // ���� �� ���� ������ ������� �� snapshot
    snapshot.bin = bin;
    if (cardBrand) snapshot.cardBrand = cardBrand;
    if (cardCountry) snapshot.cardIssuerCountry = cardCountry;
    if (funding) snapshot.cardFunding = funding;
    if (issuer) snapshot.cardIssuer = issuer;
    snapshot.enrichedAt = new Date().toISOString();
    // L3 perf fix: single source of truth for enrichment source, written
    // both into the JSON snapshot (existing consumers) and the indexed
    // top-level column below (db.order.update) — never derive one from
    // the other separately, or they can drift.
    const enrichmentSourceValue = req.body.source || 'stripe';
    snapshot.enrichmentSource = enrichmentSourceValue;

    // 6. ����� ����� ������ ������
    const enrichedOrder = {
      id: existingOrder.id,
      orderId: existingOrder.orderId,
      email: existingOrder.email,
      ipAddress: existingOrder.ipAddress,
      deviceFingerprint: existingOrder.deviceFingerprint,
      amount: existingOrder.amount,
      billingAddress: (() => {
        try { const s = JSON.parse(existingOrder.signalsSnapshot || '{}'); return s.billingCountry ? JSON.stringify({ country: s.billingCountry }) : null; } catch { return null; }
      })(),
      shippingAddress: (() => {
        try { const s = JSON.parse(existingOrder.signalsSnapshot || '{}'); return s.shippingCountry ? JSON.stringify({ country: s.shippingCountry }) : null; } catch { return null; }
      })(),
      customerLoginId: existingOrder.customerLoginId,
      createdAt: existingOrder.createdAt.toISOString(),
      payment_details: { card_bin: bin },
      fingerprintVersion: existingOrder.fingerprintVersion || 'v3',
      fingerprintConfig: null,
      fingerprintHardware: null,
      eciCode: null,
      avsResponse: null,
      cvv2Response: null,
      isNewCustomer: false,
    };

    // ����� �������� ��������
    const last7days = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const recentOrders = await db.order.findMany({
      where: { merchantId, createdAt: { gte: last7days } },
      orderBy: { createdAt: 'desc' },
      take: 200
    });
    const formattedOrders = recentOrders.map(o => ({
      id: o.orderId,
      email: o.email,
      ipAddress: o.ipAddress,
      deviceFingerprint: o.deviceFingerprint,
      amount: o.amount,
      createdAt: o.createdAt,
      riskLevel: o.riskLevel,
    }));
    const disputes = await db.disputeOutcome.findMany({
      where: { merchantId, resolvedAt: { gte: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000) } },
      include: { order: true },
      take: 200
    });
    const blacklist = [];

    // 7. ����� ���� �������
    const { calculateRiskScore } = require('../lib/riskScoring');
    const riskResult = await calculateRiskScore(
      enrichedOrder,
      formattedOrders,
      disputes,
      blacklist,
      merchantId,
      false, // �� ���� ������� �������� ��� �� �����
      null,
      cardHashRecord   // ? ����� ����� cardHashRecord
    );

    // 8. ��� ������� �������
    const updatedSnapshot = {
      ...snapshot,
      ipIntel: riskResult.ipIntel || null,
      emailIntel: riskResult.emailIntel || null,
      binIntel: riskResult.binIntel || null,
      flags: riskResult.flags,
      positives: riskResult.positives,
    };

     await db.order.update({
      where: { id: existingOrder.id },
      data: {
        riskScore: riskResult.score,
        riskLevel: riskResult.riskLevel,
        decision: riskResult.decision.includes('Approve') ? 'approve' : (riskResult.decision.includes('Review') ? 'review' : 'block'),
        cardHash: cardHashRecord?.cardHash ?? null,   // <-- ????? ??????
        enrichmentSource: enrichmentSourceValue,       // L3 perf fix — indexed column mirrors JSON value
        signalsSnapshot: JSON.stringify(updatedSnapshot),
      }
    });

    // 9. ��� RiskEvaluation ����� (upsert ����� ����� orderId)
    await db.riskEvaluation.upsert({
      where: { orderId: existingOrder.id },
      create: {
        orderId: existingOrder.id,
        staticScore: riskResult.score,
        learningScore: riskResult.score,
        finalDecision: riskResult.decision.includes('Approve') ? 'low' : (riskResult.decision.includes('Review') ? 'medium' : 'high'),
        topSignals: JSON.stringify(riskResult.flags.slice(0, 5)),
        positiveSignals: JSON.stringify(riskResult.positives || []),
        scoringVersion: riskResult.scoringVersion || 'v1.0',
        fraudProb: riskResult.economicData?.fraudProb ?? null,
        expectedLoss: riskResult.economicData?.expectedLoss ?? null,
        thresholdUsed: riskResult.economicData?.baseThreshold ?? null,
        decisionBefore: riskResult.economicData?.decisionBefore ?? null,
        decisionAfter: riskResult.economicData?.decisionAfter ?? null,
      },
      update: {
        staticScore: riskResult.score,
        learningScore: riskResult.score,
        finalDecision: riskResult.decision.includes('Approve') ? 'low' : (riskResult.decision.includes('Review') ? 'medium' : 'high'),
        topSignals: JSON.stringify(riskResult.flags.slice(0, 5)),
        positiveSignals: JSON.stringify(riskResult.positives || []),
        fraudProb: riskResult.economicData?.fraudProb ?? null,
        expectedLoss: riskResult.economicData?.expectedLoss ?? null,
        thresholdUsed: riskResult.economicData?.baseThreshold ?? null,
        decisionBefore: riskResult.economicData?.decisionBefore ?? null,
        decisionAfter: riskResult.economicData?.decisionAfter ?? null,
      },
    });

    // 10. ������ �� pending enrichments (��� ���� ���� �����) - ����� ����� ����
    await db.pendingEnrichment.deleteMany({
      where: { orderId, status: 'pending' }
    });

    // ── 11. PayPal Alert (fire-and-forget) ───────────────────────────
    const enrichSource   = req.body.source || null;
    const enrichDecision = riskResult.decision.includes('Approve') ? 'approve'
                         : riskResult.decision.includes('Review')  ? 'review'
                         : 'block';

    // ── Quota Counter: post-enrichment block upgrade ────────────────────
    // existingOrder.decision (selected above, before this route's own
    // db.order.update() overwrote it) is the pre-enrichment decision.
    // Comparing it against enrichDecision distinguishes a genuine
    // review/approve → block upgrade from an order that was already
    // block and stays block — the latter must NOT re-trigger this, or
    // repeated /enrich calls on the same order would double-count.
    if (enrichDecision === 'block' && existingOrder.decision !== 'block') {
      let enrichCardBin = null;
      if (bin != null) {
        const b = String(bin).replace(/\D/g, '').slice(0, 6);
        if (b.length === 6) enrichCardBin = b;
      }
      // cardType is not part of /enrich's documented request shape today
      // (the plugin sends cardBrand, not cardType) — normalized the same
      // way as /evaluate for forward-compatibility, but will resolve to
      // null under the current payload.
      let enrichCardType = null;
      if (req.body.cardType != null) {
        const ct = String(req.body.cardType).toLowerCase().trim();
        enrichCardType = VALID_CARD_TYPES.has(ct) ? ct : 'unknown';
      }
      const enrichIpHash = existingOrder.ipAddress ? hashIp(existingOrder.ipAddress) : null;
      let enrichAmount = null;
      if (existingOrder.amount != null) {
        const amt = parseFloat(existingOrder.amount);
        if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) enrichAmount = amt;
      }
      let enrichRiskScore = null;
      if (riskResult.score != null) {
        const rs = parseInt(riskResult.score, 10);
        if (!isNaN(rs) && rs >= 0 && rs <= 100) enrichRiskScore = rs;
      }

      try {
        await db.$transaction(recordBlockedAttempt(db, {
          merchantId:      merchantId,
          storeId:         req.storeId ?? null,
          cardBin:         enrichCardBin,
          cardType:        enrichCardType,
          reason:          'pattern',
          ipHash:          enrichIpHash,
          amountAttempted: enrichAmount,
          riskScore:       enrichRiskScore,
        }));
      } catch (counterErr) {
        logger.error(
          { module: 'risk', endpoint: 'enrich', tenantId: merchantId, error: counterErr.message },
          'Failed to record BlockedAttempt / increment quota counter from /enrich'
        );
      }
    }

    if (enrichSource === 'paypal' && riskResult.score >= 70 && isProOrAbove(req.tenant.plan)) {
      const { notifyPaypalAlert } = require('../lib/notify');

       db.tenant.findUnique({
        where:  { id: req.tenant.id },
        select: { id: true, email: true, storeUrl: true, webhookUrl: true, webhookType: true, plan: true },
      }).then(tenantFull => {
        if (!tenantFull) return;

        const estimatedSavings = req.body.amount
          ? Math.round(Number(req.body.amount) * 0.15 * 100) / 100
          : null;

        return notifyPaypalAlert(tenantFull, {
          paypalTxnId:     req.body.paypalTxnId   || null,
          brand:           req.body.brand         || req.body.cardBrand || null,
          last4:           req.body.last4          || null,
          cardCountry:     req.body.cardCountry    || null,
          amount:          req.body.amount         || null,
          currency:        req.body.currency       || 'USD',
          riskScore:       riskResult.score,
          decision:        enrichDecision,
          flags:           riskResult.flags        || [],
          estimatedSavings,
        });
      }).catch(err =>
        logger.error({ module: 'risk', endpoint: 'enrich', err: err.message }, 'PayPal alert failed')
      );
    }

    // ��������� ��������
    res.json({
      success: true,
      orderId,
      enriched: true,
      newRiskScore: riskResult.score,
      newDecision: enrichDecision,
      flags: riskResult.flags,
    });

  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'enrich', error: error.message, stack: error.stack }, 'Enrich error');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== Tenant Registration (Early Access) ==========

/**
 * @swagger
 * /tenants/register:
 *   post:
 *     summary: Register a new tenant and receive an API key
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email]
 *             properties:
 *               email: { type: string, format: email }
 *               storeUrl: { type: string }
 *     responses:
 *       201:
 *         description: Registration successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 apiKey: { type: string }
 *                 email: { type: string }
 *       400:
 *         description: Missing email or email already registered
 *       500:
 *         description: Internal server error
 */


router.post('/tenants/register', async (req, res) => {
      // ?? Rate Limiting (Persistent DB) ????????????????????????????????????????
  const ip = req.ip || req.connection.remoteAddress;
  const ipHash = hashIp(ip);
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
  const MAX_ATTEMPTS = 5;

  try {
    const [, recentCount] = await Promise.all([
      db.registrationAttempt.deleteMany({
        where: { createdAt: { lt: oneHourAgo } }
      }),
      db.registrationAttempt.count({
        where: { ipHash, createdAt: { gte: oneHourAgo } }
      })
    ]);

    if (recentCount >= MAX_ATTEMPTS) {
      const oldestAttempt = await db.registrationAttempt.findFirst({
        where: { ipHash, createdAt: { gte: oneHourAgo } },
        orderBy: { createdAt: 'asc' },
        select: { createdAt: true }
      });
      const resetAt = oldestAttempt
        ? new Date(oldestAttempt.createdAt).getTime() + 60 * 60 * 1000
        : Date.now() + 60 * 60 * 1000;
      const retryAfterSecs = Math.ceil((resetAt - Date.now()) / 1000);
      const retryAfterMins = Math.ceil(retryAfterSecs / 60);
      res.set('Retry-After', String(retryAfterSecs));
      return res.status(429).json({
        error: `Too many registration attempts. Please try again in ${retryAfterMins} minute(s).`,
        retryAfter: retryAfterSecs
      });
    }

    await db.registrationAttempt.create({ data: { ipHash } });

  } catch (rateLimitErr) {
    logger.error(
      { module: 'risk', endpoint: 'register', error: rateLimitErr.message },
      'Rate limiter DB error � failing open'
    );
  }
  // ?? End Rate Limiting ?????????????????????????????????????????????????????

  // ?? Turnstile verification ????????????????????????????????????????????
      const turnstileToken = req.body.turnstileToken || '';
      if (!turnstileToken) {
        return res.status(400).json({ error: 'Security check token missing.' });
      }
      try {
        const turnstileRes = await fetch(
          'https://challenges.cloudflare.com/turnstile/v0/siteverify',
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              secret:   process.env.TURNSTILE_SECRET_KEY,
              response: turnstileToken,
              remoteip: req.ip || req.connection.remoteAddress
            })
          }
        );
        const turnstileData = await turnstileRes.json();
        if (!turnstileData.success) {
          return res.status(403).json({ error: 'Security check failed. Please try again.' });
        }
      } catch (turnstileErr) {
        console.error('Turnstile verification error:', turnstileErr);
        return res.status(503).json({ error: 'Security check unavailable. Please try again.' });
      }
// ?? End Turnstile ?????????????????????????????????????????????????????

  // ?? Honeypot check ????????????????????????????????????????????????????
  // A hidden field (name="website") that only bots reliably fill in. Real
  // users never see or complete it (CSS-hidden in index.html). Any
  // non-empty value here is treated as a bot signal — respond with a
  // generic success-shaped message (not an error) to avoid teaching a bot
  // it tripped a filter, and skip tenant creation entirely.
  const honeypotValue = req.body.website || '';
  if (honeypotValue.trim() !== '') {
    logger.warn({ module: 'risk', endpoint: 'register' }, 'Honeypot field filled — likely bot submission, rejecting silently');
    return res.status(200).json({
      email: req.body.email || null,
      plan: 'early_access',
      verified: false,
      requiresVerification: true,
      message: 'Almost there! We sent a confirmation link to your email. Click it to activate your account and receive your API key.'
    });
  }
  // ?? End honeypot check ???????????????????????????????????????????????      


  try {
    const { email, storeUrl } = req.body;



    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    // Check if tenant already exists
    const existing = await db.tenant.findUnique({ where: { email } });
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Generate a unique API key (256-bit CSPRNG — NIST SP 800-63B §5.1.1.2 entropy requirement)
    const apiKey = crypto.randomBytes(32).toString('base64');
    const apiKeyHash = hashApiKey(apiKey);

    // Generate email verification token
    const emailVerifyToken = crypto.randomBytes(32).toString('hex');
    const emailVerifyExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Normalize storeUrl domain — this becomes the tenant's only authorized
    // origin for API key use (CWE-636 fix: domain binding must be populated
    // at creation time so domainAuthMiddleware has real data to enforce
    // against rather than failing open on a missing/empty array).
    const allowedDomains = [];
    if (storeUrl) {
      const normalizedDomain = normalizeDomain(storeUrl);
      if (normalizedDomain) {
        allowedDomains.push(normalizedDomain);
      }
    }

    // In development mode, skip email verification
    const skipVerification = process.env.EMAIL_VERIFICATION_DISABLED === 'true';

    // Webhook signing secret — required by verifyHmacSignature on every mutating
    // route. Must be generated here at tenant-creation time (not deferred to a
    // later recovery flow), otherwise req.tenant.webhookSecret stays null forever
    // and /evaluate, /enrich, /blacklist, /whitelist, /blocked-attempt all 401.
    // Same pattern as /connect/confirm in src/routes/auth.js.
    const webhookSecret = crypto.randomBytes(32).toString('hex');

    // Early Access Pro Grant — evaluated once, at the moment of tenant
    // creation. If EARLY_ACCESS_END_DATE is unset or still in the future,
    // this registration is eligible for "3 months of Shield Pro at no
    // cost." Ineligible registrations (after the cutoff) fall back to the
    // pre-existing free early_access behavior — unchanged from today.
    const isEarlyAccessEligible = !EARLY_ACCESS_END_DATE || new Date() <= EARLY_ACCESS_END_DATE;

    const earlyAccessGrant = isEarlyAccessEligible
      ? {
          plan:                'pro',
          subscriptionStatus:  'active',
          subscriptionEndDate: new Date(Date.now() + EARLY_ACCESS_PROMO_DAYS * 24 * 60 * 60 * 1000),
          billingCycle:        'early_access_promo',
        }
      : {
          plan:                'early_access',
          subscriptionStatus:  'free',
          subscriptionEndDate: null,
          billingCycle:        null,
        };

   const tenant = await db.tenant.create({
      data: {
        email,
        storeUrl: storeUrl || null,
        allowedDomains, // Domain-binding allowlist (CWE-636 fix) — enforced by domainAuthMiddleware
        webhookSecret, // HMAC request-signing secret — provisioned at tenant creation, not deferred
        apiKeyHash, // Source of truth for authentication (OWASP ASVS V6.2.1)
        // Production path only: apiKey plaintext is held transiently so the post-verification
        // welcome email (sent from /verify-email, only after inbox ownership is proven) can
        // include it. It is purged in the same DB write that sets emailVerified = true (see
        // routes/auth.js), bounding the exposure window to "time until the merchant clicks the
        // confirmation link" — the same transient-then-deleted pattern already used for
        // emailVerifyToken (CWE-532 minimization; NIST SP 800-63B authenticator lifecycle).
        // The skipVerification (dev mode) path below never writes apiKey at all, since the key
        // is sent directly from this request's closure before this row is committed.
        apiKey: skipVerification ? null : apiKey,
        ...earlyAccessGrant,
        isActive: true,
        emailVerified: skipVerification,
        emailVerifyToken: skipVerification ? null : emailVerifyToken,
        emailVerifyExpiresAt: skipVerification ? null : emailVerifyExpiresAt,
      }
    });

    logger.info({ module: 'risk', newTenant: tenant.email }, 'New tenant registered');

    if (skipVerification) {
      // Dev mode — send API key immediately as before
      const { sendApiKeyEmail } = require('../lib/email');
      sendApiKeyEmail(tenant.email, apiKey).catch(err => {
        logger.error({ module: 'email', error: err.message }, 'Failed to send API key email (dev mode)');
      });

      return res.status(201).json({
        email: tenant.email,
        plan: tenant.plan,
        verified: true,
        message: 'Welcome to ChargeGuard Early Access! Check your email for your API key.'
      });
    }

    // Production — send confirmation email, withhold API key
    const baseUrl = process.env.RENDER_EXTERNAL_URL || 'https://chargeguard-api.onrender.com';
    const confirmUrl = `${baseUrl}/api/auth/verify-email?token=${emailVerifyToken}`;

    const { sendConfirmationEmail } = require('../lib/email');
    sendConfirmationEmail(tenant.email, confirmUrl).catch(err => {
      logger.error({ module: 'email', error: err.message }, 'Failed to send confirmation email');
    });

    res.status(201).json({
      email: tenant.email,
      plan: tenant.plan,
      verified: false,
      requiresVerification: true,
      message: 'Almost there! We sent a confirmation link to your email. Click it to activate your account and receive your API key.'
    });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'register', error: error.message }, 'Registration error');
    res.status(500).json({ error: 'Internal server error' });
  }
});
// ========== Auto-Cleanup Blocked Orders ==========
router.post('/cleanup-blocked', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    // ����� �� ������� �������� (decision = 'block')
    const blockedOrders = await db.order.findMany({
      where: { merchantId, decision: 'block' },
      select: { id: true, orderId: true }
    });

    if (blockedOrders.length === 0) {
      return res.json({ success: true, cleanedCount: 0, message: 'No blocked orders to clean' });
    }

    // ��� ������� ��������
    const deleteResult = await db.order.deleteMany({
      where: { merchantId, decision: 'block' }
    });

    logger.info({ 
      module: 'risk', 
      merchantId, 
      cleanedCount: deleteResult.count 
    }, 'Auto-cleanup completed');

    res.json({ 
      success: true, 
      cleanedCount: deleteResult.count,
      message: `Cleaned ${deleteResult.count} blocked orders` 
    });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'cleanup-blocked', error: error.message }, 'Cleanup error');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== GET /risk/verify-key ==========
// ������� ������ �� "���� �� �������" �� ����� WooCommerce
// �� ������ domainAuthMiddleware ����� � ������ �� ����� ��� ����� ������
/**
 * @swagger
 * /risk/verify-key:
 *   get:
 *     summary: Verify if an API key is valid and active
 *     parameters:
 *       - in: header
 *         name: x-api-key
 *         required: true
 *         schema: { type: string }
 *       - in: header
 *         name: x-store-domain
 *         required: false
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: API key is valid and active
 *       400:
 *         description: Missing x-api-key header
 *       401:
 *         description: Invalid or inactive API key
 *       403:
 *         description: Domain not authorized for this key
 *       500:
 *         description: Internal server error
 */
// SANCTIONED EXCEPTION to the centralized requireAuth() pattern (CWE-1059
// drift-prevention documentation — same rationale as the /connect/confirm
// no-grace-period note in routes/auth.js). Do NOT "fix" this to use
// requireAuth() without re-reading this comment in full.
//
// This is a lightweight HEALTH-CHECK endpoint: the WooCommerce plugin calls
// it to ask "is my API key still valid?" before doing anything else,
// including before it has fetched webhookSecret. Three deliberate
// deviations from the standard pattern follow from that:
//
//   a) No requireAuth() AUTH_FAIL_DELAY_MS (200ms) on failure. That delay
//      exists to blunt key-enumeration timing attacks against mutating,
//      capability-granting endpoints (CWE-208). A pure validity probe is a
//      much lower-value timing oracle — knowing a key is "valid" grants no
//      capability an attacker couldn't get more directly by trying the key
//      against a real endpoint — and this route is polled frequently, so
//      artificial latency here has a real operational cost with no
//      proportionate security benefit (cf. Kubernetes liveness/readiness
//      probes, which are intentionally excluded from the full
//      auth/authz chain the live application enforces, for the same
//      cost/benefit reason).
//   b) No domainAuthMiddleware. The plugin calls this from the merchant's
//      own server process, not a browser subject to origin enforcement —
//      there is no "origin" to bind in the way there is for browser-facing
//      mutating calls.
//   c) No verifyHmacSignature. The plugin may not have fetched
//      webhookSecret yet — requiring an HMAC signature here would be
//      circular (the secret needed to sign isn't available until after a
//      successful authenticated call).
//
// What is NOT relaxed: this handler still manually enforces tenant.isActive
// and tenant.emailVerified (mirroring requireAuth's policy exactly), and
// returns no sensitive data — only plan/subscription metadata, never a
// secret. If those manual checks and requireAuth's checks ever diverge,
// that is the one thing to fix; the missing delay/domain/HMAC layers above
// are by design and should stay missing.
router.get('/verify-key', async (req, res) => {
  try {
    // 1. ������ �� ���� ��� header
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
      return res.status(400).json({
        valid: false,
        message: 'Missing x-api-key header'
      });
    }

    // 2. Find tenant by API key (hash-first with deprecated-plaintext fallback — zero-downtime migration)
    const { tenant } = await resolveTenantByApiKey(apiKey, {
      id: true,
      isActive: true,
      emailVerified: true,
    });

    // 2. Validate tenant
    if (!tenant || !tenant.isActive) {
      return res.status(401).json({
        valid: false,
        message: 'Invalid or inactive API key'
      });
    }

    if (!tenant.emailVerified && process.env.EMAIL_VERIFICATION_DISABLED !== 'true') {
      return res.status(403).json({
        valid: false,
        message: 'Email not verified. Please check your inbox and click the confirmation link.',
        code: 'EMAIL_NOT_VERIFIED'
      });
    }

    // 4. ������ ��������� �� �������
    //    ������� ��� ��� ��� ������ ���� allowedDomains �����
    //    (������ ��� ������� �� ������ ������� ����� ��� ����� ����� ����)
    // TODO: ����� ������ �� ������� ��� ���� ��� allowedDomains

    // 5. إرجاع حالة الاشتراك مع الـ validation
    const tenantFull = await db.tenant.findUnique({
      where:  { id: tenant.id },
      select: {
        plan:               true,
        subscriptionStatus: true,
        subscriptionEndDate: true,
        billingCycle:       true,
        lastPaymentDate:    true,
      },
    });

    return res.status(200).json({
      valid:              true,
      message:            'API key is valid',
      plan:               tenantFull?.plan               || 'starter',
      subscriptionStatus: tenantFull?.subscriptionStatus || 'free',
      subscriptionEndDate: tenantFull?.subscriptionEndDate || null,
      billingCycle:       tenantFull?.billingCycle        || null,
      lastPaymentDate:    tenantFull?.lastPaymentDate     || null,
    });

  } catch (error) {
    logger.error(
      { module: 'risk', endpoint: 'verify-key', error: error.message },
      'Verify key error'
    );
    return res.status(500).json({
      valid: false,
      message: 'Internal server error'
    });
  }
});

// ========== POST /risk/blocked-attempt ==========
// Receives blocked card-testing events from the WooCommerce Plugin.
// Stores them in BlockedAttempt table for the user dashboard.
//
// Auth:     X-Api-Key header (same apiKeyAuth middleware)
// Privacy:  Only ipHash (SHA-256) is accepted — real IP is never stored
// Reliability: Fire-and-forget from plugin side; failures are silent

const BLOCKED_ATTEMPT_RATE = new Map(); // keyed on apiKey, not IP
const BA_MAX_REQ   = 60;
const BA_WINDOW_MS = 60 * 1000;

// L3 fix: independent periodic sweep, mirroring the CONNECT_STATUS_RATE
// fix in routes/auth.js — a key polled exactly once (or never re-polled)
// was previously never pruned, since pruning only happened on a re-poll
// of the SAME key after its window expired. This closes that regardless
// of whether the map is ever populated pre-auth or not; see the
// middleware-ordering fix below for the actual root-cause fix.
setInterval(() => {
  const now = Date.now();
  for (const [key, rec] of BLOCKED_ATTEMPT_RATE.entries()) {
    if (now - rec.firstAt > BA_WINDOW_MS) {
      BLOCKED_ATTEMPT_RATE.delete(key);
    }
  }
}, BA_WINDOW_MS).unref();

const blockedAttemptRateLimit = (req, res, next) => {
  // L3 fix: this middleware now runs AFTER apiKeyAuth in the route
  // definition below (see that change), so req.tenant is guaranteed to
  // exist here — key on the authenticated tenant's id, not the raw
  // x-api-key header value. Previously this ran before authentication,
  // meaning an unauthenticated caller could populate this map with
  // arbitrary/garbage x-api-key values (or fall back to req.ip) without
  // bound, and a rejected key would still consume a map slot for no
  // legitimate reason.
  const key = req.tenant?.id || req.ip || 'unknown';
  const now = Date.now();
  const rec = BLOCKED_ATTEMPT_RATE.get(key);
  if (rec) {
    if (now - rec.firstAt > BA_WINDOW_MS) {
      BLOCKED_ATTEMPT_RATE.delete(key);
    } else if (rec.count >= BA_MAX_REQ) {
      return res.status(429).json({ error: 'Too Many Requests' });
    } else {
      rec.count++;
    }
  } else {
    BLOCKED_ATTEMPT_RATE.set(key, { count: 1, firstAt: now });
  }
  next();
};

const VALID_REASONS    = new Set(['card_testing', 'velocity', 'blacklist', 'pattern']);
const VALID_CARD_TYPES = new Set(['visa', 'mastercard', 'amex', 'discover', 'unknown']);

// L3 fix: blockedAttemptRateLimit now runs after apiKeyAuth rather than
// before it. Only a request that has already presented a real, valid
// API key reaches the rate limiter and can grow BLOCKED_ATTEMPT_RATE —
// an unauthenticated caller is rejected by apiKeyAuth first and never
// touches the map at all. This also means the rate-limit key (req.tenant.id,
// set inside the middleware above) is now trustworthy tenant identity
// rather than a client-supplied header value.
router.post('/blocked-attempt', apiKeyAuth, blockedAttemptRateLimit, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { cardBin, cardType, reason, ipHash, amountAttempted } = req.body;

    if (!reason || !VALID_REASONS.has(reason)) {
      return res.status(400).json({
        error: `Invalid or missing 'reason'. Allowed: ${[...VALID_REASONS].join(', ')}`,
      });
    }

    // cardBin: accept only 6 numeric digits
    let safeBin = null;
    if (cardBin != null) {
      const b = String(cardBin).replace(/\D/g, '').slice(0, 6);
      if (b.length === 6) safeBin = b;
    }

    // cardType: normalise to lowercase, fallback to 'unknown'
    let safeCardType = null;
    if (cardType != null) {
      const ct = String(cardType).toLowerCase().trim();
      safeCardType = VALID_CARD_TYPES.has(ct) ? ct : 'unknown';
    }

    // ipHash: must be 64-char hex (SHA-256)
    let safeIpHash = null;
    if (ipHash != null) {
      const h = String(ipHash).toLowerCase().trim();
      if (/^[0-9a-f]{64}$/.test(h)) safeIpHash = h;
    }

    // amountAttempted: positive number, sanity-capped at $999,999
    let safeAmount = null;
    if (amountAttempted != null) {
      const amt = parseFloat(amountAttempted);
      if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) safeAmount = amt;
    }

    // riskScore: integer 0-100, nullable for legacy data
    let safeRiskScore = null;
    if (req.body.riskScore != null) {
      const rs = parseInt(req.body.riskScore, 10);
      if (!isNaN(rs) && rs >= 0 && rs <= 100) safeRiskScore = rs;
    }

    // monthlyBlockedCount is NO LONGER incremented here. The quota counter
    // is now driven solely by the /evaluate block-decision path (see the
    // $transaction there), which is the authoritative enforcement point.
    // Incrementing it here too would double-count every attack that goes
    // through /evaluate → block → plugin calls /blocked-attempt. This
    // endpoint still creates BlockedAttempt rows for dashboard/reporting —
    // e.g. plugin-local firewall blocks that never reach /evaluate — just
    // without touching the counter.
    await db.blockedAttempt.create({
      data: {
        tenantId:        req.tenant.id,
        // Agency multi-store attribution — req.storeId is set by
        // domainAuthMiddleware only for store-managed tenants; null for
        // Starter/Pro (no Store rows exist for them), which is the correct
        // "no store to attribute to" value, not an error.
        storeId:         req.storeId ?? null,
        cardBin:         safeBin,
        cardType:        safeCardType,
        reason:          reason,
        ipHash:          safeIpHash,
        amountAttempted: safeAmount,
        riskScore:       safeRiskScore,
      },
    });

    return res.status(200).json({ success: true });

  } catch (err) {
    logger.error(
      { module: 'risk', endpoint: 'blocked-attempt', error: err.message },
      'Failed to record blocked attempt'
    );
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

module.exports = router;

