const crypto = require('crypto');

// ?? IP Hashing (GDPR-safe) ????????????????????????????????????????????????
const hashIp = (ip) => {
  const salt = process.env.SECRET_SALT || 'default_salt_change_me';
  return crypto.createHmac('sha256', salt).update(ip).digest('hex');
};
// ?????????????????????????????????????????????????????????????????????????
const logger = require('../lib/logger');
const express = require('express');
const router = express.Router();
const { calculateRiskScore } = require('../lib/riskScoring');
const { checkVelocity, recordFailedAttempt } = require('../lib/velocityDetector');
const { checkBINSequence } = require('../lib/binSequenceDetector');
const db = require('../lib/db');
const { normalizeBin } = require('../lib/binIntelligence');
const { buildGraphFromOrder } = require('../lib/identityGraph');
const prometheus = require('../lib/prometheus');

const { domainAuthMiddleware, normalizeDomain } = require('../lib/domainAuth');

const apiKeyAuth = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    return res.status(401).json({ error: 'API key is required' });
  }

  const tenant = await db.tenant.findUnique({
    where: { apiKey },
    select: { id: true, email: true, isActive: true, emailVerified: true, webhookSecret: true }
  });

  if (!tenant || !tenant.isActive) {
    return res.status(401).json({ error: 'Invalid or inactive API key' });
  }

  if (!tenant.emailVerified) {
    // Allow in development mode
    if (process.env.EMAIL_VERIFICATION_DISABLED !== 'true') {
      return res.status(403).json({
        error: 'Email not verified. Please check your inbox and click the confirmation link.',
        code: 'EMAIL_NOT_VERIFIED'
      });
    }
  }

  req.tenant = { id: tenant.id, email: tenant.email, webhookSecret: tenant.webhookSecret };
  next();
};
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
router.post('/evaluate', apiKeyAuth, domainAuthMiddleware, async (req, res) => {
  try {
    // ������� ��������
    const { orderId, ipAddress, email, bin, deviceFingerprint, amount, billingCountry, shippingCountry, isNewCustomer, merchantId: bodyMerchantId } = req.body;
    const merchantId = bodyMerchantId || req.headers['x-merchant-id'];
    if (!merchantId) {
      return res.status(400).json({ error: 'merchantId is required' });
    }

        // Idempotency: ������ �� ������� ������� ���� ��� 5 �����
    const idempotencyWindow = 5 * 60 * 1000; // 5 �����
    const existingOrder = await db.order.findUnique({
      where: { orderId },
      select: { decision: true, riskScore: true, connectedRisk: true, signalsSnapshot: true, createdAt: true }
    });
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
      return res.status(403).json({
        error: 'Request blocked: entity is blacklisted',
        reason: blacklistCheck.reason || 'Blacklisted',
        decision: 'block'
      });
    }


    // 1. ��� ������ (Velocity Check)
    const velocityCheck = checkVelocity({ ip: ipAddress, deviceFingerprint });
    if (velocityCheck.blocked) {
      return res.status(403).json({
        error: 'Request blocked due to suspicious activity',
        reason: velocityCheck.reason,
        decision: 'block'
      });
    }

    // 1b. BIN Sequence Detection
    if (bin) {
      const binSeq = checkBINSequence({ bin, ipAddress, deviceFingerprint });
      if (binSeq.blocked) {
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
    const riskResult = await calculateRiskScore(
      order,
      formattedOrders,
      disputes,
      blacklist,
      merchantId,
      false,
      { deviceVelocityCount, ipVelocityCount, emailVelocityCount }  // velocity counts
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
    // ����� �������� ������� �� ���� ������
    if (response.decision === 'block') {
      recordFailedAttempt({ ip: ipAddress, deviceFingerprint });
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
        where: { orderId },
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
          },
          update: {
            staticScore: riskResult.score,
            learningScore: riskResult.score,
            finalDecision: response.decision === 'approve' ? 'low' : (response.decision === 'review' ? 'medium' : 'high'),
            topSignals: JSON.stringify(riskResult.flags.slice(0, 5)),
            positiveSignals: JSON.stringify(riskResult.positives || []),
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
router.post('/mark-fraud', apiKeyAuth, async (req, res) => {
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

    const merchantId = req.body.merchantId || req.headers['x-merchant-id'];
    if (!merchantId) {
      return res.status(400).json({ error: 'merchantId is required' });
    }
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
router.post('/feedback', apiKeyAuth, async (req, res) => {
  try {
    const { orderId, isFraud } = req.body;

    if (!orderId) {
      return res.status(400).json({ error: 'orderId is required' });
    }
    if (isFraud === undefined || isFraud === null) {
      return res.status(400).json({ error: 'isFraud is required (true/false)' });
    }

    // ������� ���� ������
    // ���� isFraud ������ (true = lost, false = won)
    await processFeedback(orderId, isFraud ? 'lost' : 'won');

    res.json({ success: true, message: 'Feedback recorded successfully' });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'feedback', error: error.message }, 'Feedback API error');
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

    const merchantId = req.body.merchantId || req.headers['x-merchant-id'];
    if (!merchantId) {
      return res.status(400).json({ error: 'merchantId is required' });
    }
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
router.post('/blacklist', apiKeyAuth, async (req, res) => {
  try {
    const { merchantId, type, value, reason, expiresAt, createdBy } = req.body;
    if (!merchantId || !type || !value) {
      return res.status(400).json({ error: 'merchantId, type, and value are required' });
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
router.delete('/blacklist/:id', apiKeyAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const merchantId = req.body.merchantId || req.headers['x-merchant-id'];
    if (!merchantId) {
      return res.status(400).json({ error: 'merchantId is required' });
    }

    // ������ �� �� ������ ����� ��� ��� ������
    const existing = await db.blacklistEntry.findFirst({
      where: { id, merchantId },
    });
    if (!existing) {
      return res.status(404).json({ error: 'Blacklist entry not found or not owned by this merchant' });
    }

    await db.blacklistEntry.delete({ where: { id } });
    prometheus.recordAccessControlAction('delete', 'blacklist');
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
router.get('/blacklist', apiKeyAuth, async (req, res) => {
  try {
    const merchantId = req.query.merchantId || req.headers['x-merchant-id'];
    if (!merchantId) {
      return res.status(400).json({ error: 'merchantId is required (as query param or header)' });
    }

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
router.put('/blacklist/:id', apiKeyAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const merchantId = req.body.merchantId || req.headers['x-merchant-id'];
    if (!merchantId) {
      return res.status(400).json({ error: 'merchantId is required' });
    }

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

router.post('/whitelist', apiKeyAuth, async (req, res) => {
  try {
    const { merchantId, type, value, reason, expiresAt, createdBy } = req.body;
    if (!merchantId || !type || !value) {
      return res.status(400).json({ error: 'merchantId, type, and value are required' });
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

router.get('/whitelist', apiKeyAuth, async (req, res) => {
  try {
    const merchantId = req.query.merchantId || req.headers['x-merchant-id'];
    if (!merchantId) {
      return res.status(400).json({ error: 'merchantId is required (as query param or header)' });
    }

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
    logger.error({ module: 'risk', endpoint: 'whitelist-get', error: error.message }, 'Error fetching whitelist');
    res.status(500).json({ error: error.message });
  }
});

router.delete('/whitelist/:id', apiKeyAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const merchantId = req.body.merchantId || req.headers['x-merchant-id'];
    if (!merchantId) {
      return res.status(400).json({ error: 'merchantId is required' });
    }

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

    // 3. ������� merchantId (����� ������ parsedBody)
    let merchantId = parsedBody.merchantId || req.headers['x-merchant-id'];
    if (!merchantId) {
      merchantId = 'test_merchant_001'; // default for testing
      logger.warn({ module: 'risk', endpoint: 'woocommerce-webhook' }, 'Merchant ID missing, using default');
    }

    // 4. Verify WooCommerce signature (if secret is configured)
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
        logger.warn({ module: 'risk', reason: 'mismatch' }, 'Signature mismatch details');
        // return res.status(401).json({ error: 'Invalid signature', debug: { receivedLength: signature.length, expectedLength: expected.length } });
      }
    } else if (wcSecret && !signature) {
      // Secret configured but signature missing � reject
      return res.status(401).json({ error: 'Missing signature' });
    }
    // If no secret configured, skip signature verification (not recommended for production)

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
      where: { orderId: extracted.orderId },
      select: { decision: true, riskScore: true, signalsSnapshot: true, createdAt: true }
    });
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
      where: { orderId: extracted.orderId },
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
      const savedOrder = await db.order.findUnique({ where: { orderId: extracted.orderId } });
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
          },
          update: {
            staticScore: riskResult.score,
            learningScore: riskResult.score,
            finalDecision: riskResult.decision.includes('Approve') ? 'low' : (riskResult.decision.includes('Review') ? 'medium' : 'high'),
            topSignals: JSON.stringify(riskResult.flags.slice(0, 5)),
            positiveSignals: JSON.stringify(riskResult.positives || []),
          },
        });
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
router.post('/check-device', apiKeyAuth, domainAuthMiddleware, async (req, res) => {
  try {
    const { fingerprint } = req.body;
    if (!fingerprint) {
      return res.status(400).json({ error: 'fingerprint is required' });
    }

    const merchantId = req.headers['x-merchant-id'];
    if (!merchantId) {
      return res.status(400).json({ error: 'x-merchant-id header is required' });
    }

    // 1. ����� �� ���� ������ �� Identity Graph
    const { getConnectedRisk } = require('../lib/identityGraph');
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
router.post('/enrich', apiKeyAuth, domainAuthMiddleware, async (req, res) => {
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
    if (!bin) {
      return res.status(400).json({ error: 'bin is required' });
    }

    const merchantId = req.headers['x-merchant-id'];
    if (!merchantId) {
      return res.status(400).json({ error: 'x-merchant-id header is required' });
    }

    // ??? CardHash generation (if last4+expiry+brand provided) ???
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
      where: { orderId },
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
    snapshot.enrichmentSource = 'stripe'; // or other gateway

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
        cardHash: cardHashRecord?.cardHash ?? null,   // <-- ����� ������
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
      },
      update: {
        staticScore: riskResult.score,
        learningScore: riskResult.score,
        finalDecision: riskResult.decision.includes('Approve') ? 'low' : (riskResult.decision.includes('Review') ? 'medium' : 'high'),
        topSignals: JSON.stringify(riskResult.flags.slice(0, 5)),
        positiveSignals: JSON.stringify(riskResult.positives || []),
      },
    });

    // 10. ������ �� pending enrichments (��� ���� ���� �����) - ����� ����� ����
    await db.pendingEnrichment.deleteMany({
      where: { orderId, status: 'pending' }
    });

    // ��������� ��������
    res.json({
      success: true,
      orderId,
      enriched: true,
      newRiskScore: riskResult.score,
      newDecision: riskResult.decision.includes('Approve') ? 'approve' : (riskResult.decision.includes('Review') ? 'review' : 'block'),
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

    // Generate a unique API key
    const apiKey = crypto.randomBytes(32).toString('base64');

    // Generate email verification token
    const emailVerifyToken = crypto.randomBytes(32).toString('hex');
    const emailVerifyExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Normalize storeUrl domain
    const allowedDomains = [];
    if (storeUrl) {
      const normalizedDomain = normalizeDomain(storeUrl);
      if (normalizedDomain) {
        allowedDomains.push(normalizedDomain);
      }
    }

    // In development mode, skip email verification
    const skipVerification = process.env.EMAIL_VERIFICATION_DISABLED === 'true';

    const tenant = await db.tenant.create({
      data: {
        email,
        storeUrl: storeUrl || null,
        apiKey,
        plan: 'early_access',
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
      sendApiKeyEmail(tenant.email, tenant.apiKey).catch(err => {
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
router.post('/cleanup-blocked', apiKeyAuth, async (req, res) => {
  try {
    const merchantId = req.headers['x-merchant-id'];
    if (!merchantId) {
      return res.status(400).json({ error: 'x-merchant-id header is required' });
    }

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

    // 2. Find tenant by API key
    const tenant = await db.tenant.findUnique({
      where: { apiKey },
      select: {
        id: true,
        isActive: true,
        emailVerified: true,
      }
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

    // 5. �� ��� ����
    return res.status(200).json({
      valid: true,
      message: 'API key is valid'
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

const blockedAttemptRateLimit = (req, res, next) => {
  const key = req.headers['x-api-key'] || req.ip || 'unknown';
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

const verifyHmacSignature = require('../middleware/verifyHmac');

router.post('/blocked-attempt', blockedAttemptRateLimit, apiKeyAuth, verifyHmacSignature, async (req, res) => {
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

    await db.blockedAttempt.create({
      data: {
        tenantId:        req.tenant.id,
        cardBin:         safeBin,
        cardType:        safeCardType,
        reason:          reason,
        ipHash:          safeIpHash,
        amountAttempted: safeAmount,
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

