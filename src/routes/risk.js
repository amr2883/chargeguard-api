const crypto = require('crypto');
const logger = require('../lib/logger');
const express = require('express');
const router = express.Router();
const { calculateRiskScore } = require('../lib/riskScoring');
const { checkVelocity, recordFailedAttempt } = require('../lib/velocityDetector');
const db = require('../lib/db');
const { normalizeBin } = require('../lib/binIntelligence');
const { buildGraphFromOrder } = require('../lib/identityGraph');
const prometheus = require('../lib/prometheus');

const apiKeyAuth = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    return res.status(401).json({ error: 'API key is required' });
  }

  // البحث عن مفتاح API في جدول Tenant
  const tenant = await db.tenant.findUnique({
    where: { apiKey },
    select: { id: true, email: true, isActive: true }
  });

  if (!tenant || !tenant.isActive) {
    return res.status(401).json({ error: 'Invalid or inactive API key' });
  }

  // إرفاق معلومات المستأجر بالطلب لاستخدامها لاحقًا
  req.tenant = { id: tenant.id, email: tenant.email };
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
router.post('/evaluate', apiKeyAuth, async (req, res) => {
  try {
    // استخراج البيانات
    const { orderId, ipAddress, email, bin, deviceFingerprint, amount, billingCountry, shippingCountry, isNewCustomer, merchantId: bodyMerchantId } = req.body;
    const merchantId = bodyMerchantId || req.headers['x-merchant-id'];
    if (!merchantId) {
      return res.status(400).json({ error: 'merchantId is required' });
    }

        // Idempotency: التحقق من الطلبات المكررة خلال آخر 5 دقائق
    const idempotencyWindow = 5 * 60 * 1000; // 5 دقائق
    const existingOrder = await db.order.findUnique({
      where: { orderId },
      select: { decision: true, riskScore: true, connectedRisk: true, signalsSnapshot: true, createdAt: true }
    });
    if (existingOrder && (Date.now() - new Date(existingOrder.createdAt).getTime()) < idempotencyWindow) {
      // إعادة الرد المخزن
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

    // 0. فحص القائمة السوداء
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


    // 1. فحص السرعة (Velocity Check)
    const velocityCheck = checkVelocity({ ip: ipAddress, deviceFingerprint });
    if (velocityCheck.blocked) {
      return res.status(403).json({
        error: 'Request blocked due to suspicious activity',
        reason: velocityCheck.reason,
        decision: 'block'
      });
    }

    // 1. بناء كائن order
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

    // 2. تجهيز البيانات المساعدة
    const last7days = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    // جلب الطلبات السابقة من قاعدة البيانات
    // جلب آخر 200 طلب فقط لحساب المتوسطات (أفضل أداء)
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

    // حساب الـ velocity counts باستخدام استعلامات منفصلة (أسرع)
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

    // إضافة هذه القيم إلى computedSignals (يمكن تمريرها إلى riskScoring لاحقاً)
    // لكننا سنستخدمها مباشرة في signalsSnapshot

    // جلب النزاعات السابقة (آخر 90 يوم)
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

    // 3. بناء الرسم البياني للهوية أولاً
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

    // 4. استدعاء محرك التقييم (مع تمرير velocityCounts)
    const riskResult = await calculateRiskScore(
      order,
      formattedOrders,
      disputes,
      blacklist,
      merchantId,
      false,
      { deviceVelocityCount, ipVelocityCount, emailVelocityCount }  // velocity counts
    );

    // 5. بناء الاستجابة
    const response = {
      orderId: orderId,
      score: riskResult.score,
      decision: riskResult.decision.includes('Approve') ? 'approve' :
                riskResult.decision.includes('Review') ? 'review' : 'block',
      flags: riskResult.flags,
      connectedRisk: 0,
    };

     // استخدام connectedRisk مباشرة من نتيجة Identity Graph
  response.connectedRisk = riskResult.graphRisk || 0;
    // تسجيل المحاولة الفاشلة في طبقة السرعة
    if (response.decision === 'block') {
      recordFailedAttempt({ ip: ipAddress, deviceFingerprint });
    }

    // 6. حفظ الطلب في قاعدة البيانات
    if (orderId) {
        const computed = riskResult.computedSignals || {};
      // استخدام القيم المحسوبة مسبقاً من externalVelocity (الموجودة في النطاق)
      const deviceVelocityCountFinal = deviceVelocityCount;   // من أعلى الدالة
      const ipVelocityCountFinal = ipVelocityCount;           // من أعلى الدالة
      const emailVelocityCountFinal = emailVelocityCount;     // من أعلى الدالة
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

      // حفظ RiskEvaluation إذا كان القرار block أو review
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
// نقطة نهاية مؤقتة لوضع علامة احتيال على جهاز (لأغراض الاختبار فقط)
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
  // منع الوصول في بيئة الإنتاج
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
// نقطة نهاية للتعلم من نتائج الحظر (Feedback Loop)
// تستقبل orderId و isFraud (true = الحظر كان صحيحًا, false = الحظر كان خاطئًا)
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

    // استدعاء محرك التعلم
    // نمرر isFraud كنتيجة (true = lost, false = won)
    await processFeedback(orderId, isFraud ? 'lost' : 'won');

    res.json({ success: true, message: 'Feedback recorded successfully' });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'feedback', error: error.message }, 'Feedback API error');
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});

// نقطة نهاية مؤقتة لاختبار buildGraphFromOrder
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
  // منع الوصول في بيئة الإنتاج
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
// إضافة عنصر إلى القائمة السوداء
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
    // التحقق من صحة النوع
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
    res.json({ success: true, entry: blacklistEntry });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'blacklist-add', error: error.message }, 'Error adding blacklist entry');
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});

// حذف عنصر من القائمة السوداء
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

    // التأكد من أن العنصر ينتمي إلى نفس التاجر
    const existing = await db.blacklistEntry.findFirst({
      where: { id, merchantId },
    });
    if (!existing) {
      return res.status(404).json({ error: 'Blacklist entry not found or not owned by this merchant' });
    }

    await db.blacklistEntry.delete({ where: { id } });
    res.json({ success: true, message: 'Blacklist entry deleted' });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'blacklist-delete', error: error.message }, 'Error deleting blacklist entry');
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});
// ========== GET Blacklist (Query) ==========
// استعراض القائمة السوداء للتاجر الحالي
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

    // تصفية حسب النوع (اختياري)
    if (type) {
      const validTypes = ['EMAIL', 'IP', 'DEVICE_FINGERPRINT'];
      if (!validTypes.includes(type)) {
        return res.status(400).json({ error: `type must be one of: ${validTypes.join(', ')}` });
      }
      where.type = type;
    }

    // تصفية الصلاحية: بشكل افتراضي نعرض فقط العناصر السارية (غير منتهية أو expiresAt null)
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

    // التحقق من ملكية العنصر
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

// WooCommerce webhook endpoint
router.post('/woocommerce-webhook', async (req, res) => {
  try {
    // 1. Get raw body for signature verification
    const rawBody = req.body; // express.raw puts Buffer in req.body
    
    if (!rawBody) {
      return res.status(400).json({ error: 'Raw body missing' });
    }

    // 2. Parse raw body to JSON (نحدد parsedBody الأول)
    let parsedBody;
    try {
      parsedBody = JSON.parse(rawBody.toString());
    } catch (err) {
      logger.error({ module: 'risk', err: err.message }, 'Failed to parse webhook body');
      return res.status(400).json({ error: 'Invalid JSON payload' });
    }

    // 3. استخراج merchantId (بعدين نستخدم parsedBody)
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
      
      // سجل معلومات المقارنة (بدون المفتاح أو البيانات الكاملة)
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
        return res.status(401).json({ error: 'Invalid signature', debug: { receivedLength: signature.length, expectedLength: expected.length } });
      }
    } else if (wcSecret && !signature) {
      // Secret configured but signature missing – reject
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
        logger.info({ module: 'risk', orderId: extracted.orderId }, 'Idempotent request – returning cached result');
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

    // استخراج بصمة الجهاز من Webhook (إذا وجدت)
    let deviceFingerprint = parsedBody.device_fingerprint || null;
    if (!deviceFingerprint && parsedBody.meta_data) {
        const fpMeta = parsedBody.meta_data.find(m => m.key === '_chargeguard_device_fingerprint');
        if (fpMeta) deviceFingerprint = fpMeta.value;
    }
    riskRequest.deviceFingerprint = deviceFingerprint || `wc_${extracted.orderId}`; // fallback

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
// يُستخدم بواسطة جدار الحماية الديناميكي في المكوّن الإضافي
router.post('/check-device', apiKeyAuth, async (req, res) => {
  try {
    const { fingerprint } = req.body;
    if (!fingerprint) {
      return res.status(400).json({ error: 'fingerprint is required' });
    }

    const merchantId = req.headers['x-merchant-id'];
    if (!merchantId) {
      return res.status(400).json({ error: 'x-merchant-id header is required' });
    }

    // 1. البحث عن بصمة الجهاز في Identity Graph
    const { getConnectedRisk } = require('../lib/identityGraph');
    const mockOrder = {
      deviceFingerprint: fingerprint,
      fingerprintVersion: 'v3',
    };

    let blocked = false;
    let reason = null;

    try {
      const graphResult = await getConnectedRisk(mockOrder, merchantId);
      // إذا كان connectedRisk >= 80 نعتبره تهديداً عالياً ونمنعه
      if (graphResult.connectedRisk >= 45) {
        blocked = true;
        reason = 'Device fingerprint linked to high-risk network';
      }
    } catch (err) {
      logger.error({ module: 'risk', endpoint: 'check-device', err }, 'Graph lookup error');
      // فشل آمن: لا نمنع المستخدم إذا فشل الفحص
    }

    // 2. (اختياري) البحث في القائمة السوداء المركزية
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
    // في حالة الخطأ، نعيد blocked: false لمنع الإيجابيات الخاطئة
    res.status(500).json({ blocked: false, error: error.message });
  }
});

// ========== Enrich Endpoint ==========
// يُستخدم لإثراء الطلب ببيانات BIN من بوابات الدفع الخارجية (مثل Stripe)
router.post('/enrich', apiKeyAuth, async (req, res) => {
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

    // ─── CardHash generation (if last4+expiry+brand provided) ───
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

    // 1. البحث عن الطلب الأساسي
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

    // 2. إذا لم يوجد الطلب، نخزن pending enrichment
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

    // 3. التحقق من ملكية التاجر
    if (existingOrder.merchantId !== merchantId) {
      return res.status(403).json({ error: 'Merchant ID mismatch. Order belongs to another merchant.' });
    }



    // 5. تحديث الطلب ببيانات enrichment
    let snapshot = {};
    try {
      snapshot = JSON.parse(existingOrder.signalsSnapshot || '{}');
    } catch {}

    // نضيف أو نحدث بيانات البطاقة في snapshot
    snapshot.bin = bin;
    if (cardBrand) snapshot.cardBrand = cardBrand;
    if (cardCountry) snapshot.cardIssuerCountry = cardCountry;
    if (funding) snapshot.cardFunding = funding;
    if (issuer) snapshot.cardIssuer = issuer;
    snapshot.enrichedAt = new Date().toISOString();
    snapshot.enrichmentSource = 'stripe'; // or other gateway

    // 6. تحضير الطلب لإعادة الحساب
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

    // تحميل البيانات المساعدة
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

    // 7. إعادة حساب المخاطر
    const { calculateRiskScore } = require('../lib/riskScoring');
    const riskResult = await calculateRiskScore(
      enrichedOrder,
      formattedOrders,
      disputes,
      blacklist,
      merchantId,
      false, // لا تحفظ تقييمًا تلقائيًا حتى لا تتكرر
      null,
      cardHashRecord   // ← إضافة معامل cardHashRecord
    );

    // 8. حفظ النتيجة الجديدة
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
        cardHash: cardHashRecord?.cardHash ?? null,   // <-- السطر المضاف
        signalsSnapshot: JSON.stringify(updatedSnapshot),
      }
    });

    // 9. حفظ RiskEvaluation للحدث (upsert لتجنب تكرار orderId)
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

    // 10. معالجة أي pending enrichments (إذا وجدت لهذا الطلب) - حذفها لأنها طبقت
    await db.pendingEnrichment.deleteMany({
      where: { orderId, status: 'pending' }
    });

    // الاستجابة النهائية
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
// ========== Rate limiting (simple in-memory) ==========
const registrationAttempts = new Map(); // key: ip, value: { count, lastReset }

router.post('/tenants/register', async (req, res) => {
  // ── Turnstile verification — must pass before anything else ──────────
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
  // ── End Turnstile verification ────────────────────────────────────────

  // Rate limiting: max 5 registrations per IP per hour
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowMs = 60 * 60 * 1000; // 1 hour
  const maxAttempts = 5;

  if (!registrationAttempts.has(ip) || (now - registrationAttempts.get(ip).lastReset) > windowMs) {
    registrationAttempts.set(ip, { count: 0, lastReset: now });
  }

  const attempt = registrationAttempts.get(ip);
  attempt.count++;

  if (attempt.count > maxAttempts) {
    return res.status(429).json({ error: 'Too many registration attempts. Please try again later.' });
  }

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

    const tenant = await db.tenant.create({
      data: {
        email,
        storeUrl: storeUrl || null,
        apiKey,
        plan: 'early_access',
        isActive: true
      }
    });

    logger.info({ module: 'risk', newTenant: tenant.email }, 'New tenant registered');

    res.status(201).json({
      apiKey: tenant.apiKey,
      email: tenant.email,
      plan: tenant.plan,
      message: 'Welcome to ChargeGuard Early Access! Use this API key in your plugin settings.'
    });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'register', error: error.message }, 'Registration error');
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;