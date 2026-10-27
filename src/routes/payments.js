const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const db = require('../lib/db');
const logger = require('../lib/logger');
const { sendSubscriptionConfirmationEmail } = require('../lib/email');
const { resolveTenantByApiKey } = require('../lib/apiKeyAuth');

// ══════════════════════════════════════════════════════════════════════════════
// خريطة الخطط — المصدر الوحيد للحقيقة (Source of Truth) للأسعار
// أي تغيير في السعر يتم هنا فقط، وليس في الواجهة الأمامية
// ══════════════════════════════════════════════════════════════════════════════
const PLAN_CONFIG = {
  pro_monthly:     { amount: 19,  billingCycle: 'monthly', label: 'Pro Monthly'  },
  pro_annual:      { amount: 159, billingCycle: 'annual',  label: 'Pro Annual'   },
  agency_monthly:  { amount: 49,  billingCycle: 'monthly', label: 'Agency Monthly'},
  agency_annual:   { amount: 399, billingCycle: 'annual',  label: 'Agency Annual' },
};

const SESSION_TTL_MS = 30 * 60 * 1000; // 30 دقيقة

// ══════════════════════════════════════════════════════════════════════════════
// apiKeyAuth — now backed by the shared requireAuth middleware
// (no domainAuthMiddleware here — payment confirmation happens from an
// external PayPal-hosted page, not the merchant's own storefront domain)
// ══════════════════════════════════════════════════════════════════════════════
const { requireAuth } = require('../middleware/authenticate');

const apiKeyAuth = requireAuth({
  id: true,
  email: true,
  isActive: true,
  emailVerified: true,
  plan: true,
  subscriptionStatus: true,
  subscriptionEndDate: true,
});

// ══════════════════════════════════════════════════════════════════════════════
// POST /api/payments/create-checkout-session
//
// الهدف: التاجر يختار الخطة → نُنشئ جلسة دفع آمنة → نُعيد sessionId
// الأمان: المبلغ يُحسب هنا على الخادم، لا من المتصفح أبداً
// ══════════════════════════════════════════════════════════════════════════════
router.post('/create-checkout-session', apiKeyAuth, async (req, res) => {
  try {
    const { planId } = req.body;

    // ── 1. التحقق من صحة الخطة المطلوبة ──────────────────────────────────
    if (!planId || !PLAN_CONFIG[planId]) {
      return res.status(400).json({
        error: 'Invalid planId. Must be one of: ' + Object.keys(PLAN_CONFIG).join(', '),
      });
    }

    const plan = PLAN_CONFIG[planId];

    // ── 2. التحقق من عدم وجود جلسة نشطة لنفس التاجر ──────────────────────
    // نتجنب إنشاء عشرات الجلسات إذا ضغط التاجر الزر مرات متعددة
    const existingSession = await db.checkoutSession.findFirst({
      where: {
        tenantId: req.tenant.id,
        status: 'pending',
        expiresAt: { gt: new Date() },
        planId,
      },
    });

    if (existingSession) {
      // أعد الجلسة الموجودة بدلاً من إنشاء جديدة
      logger.info(
        { module: 'payments', tenantId: req.tenant.id, sessionId: existingSession.id },
        'Returning existing checkout session'
      );
      return res.json({
        sessionId: existingSession.id,
        planLabel: plan.label,
        amount: plan.amount,
        billingCycle: plan.billingCycle,
        expiresAt: existingSession.expiresAt,
      });
    }

    // ── 3. إنشاء جلسة دفع جديدة ───────────────────────────────────────────
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

    const session = await db.checkoutSession.create({
      data: {
        tenantId:    req.tenant.id,
        planId,
        amount:      plan.amount,
        billingCycle: plan.billingCycle,
        status:      'pending',
        expiresAt,
      },
    });

    logger.info(
      { module: 'payments', tenantId: req.tenant.id, sessionId: session.id, planId },
      'Checkout session created'
    );

    res.json({
      sessionId:    session.id,
      planLabel:    plan.label,
      amount:       plan.amount,
      billingCycle: plan.billingCycle,
      expiresAt,
    });

  } catch (err) {
    logger.error({ module: 'payments', error: err.message }, 'create-checkout-session failed');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// GET /api/payments/checkout-session/:sessionId
//
// الهدف: صفحة الدفع تجلب بيانات الجلسة لعرض المبلغ الصحيح
// الأمان: لا نُعيد tenantId أو بيانات حساسة — فقط ما يحتاجه PayPal SDK
// ══════════════════════════════════════════════════════════════════════════════
router.get('/checkout-session/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;

    const session = await db.checkoutSession.findUnique({
      where: { id: sessionId },
      select: {
        id:          true,
        planId:      true,
        amount:      true,
        billingCycle: true,
        status:      true,
        expiresAt:   true,
        tenant: {
          select: { email: true }
          // نُعيد الإيميل فقط لعرض "You're upgrading account: xxx@xxx.com"
        },
      },
    });

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    if (session.status !== 'pending') {
      return res.status(410).json({
        error: 'This checkout session has already been used or expired.',
        status: session.status,
      });
    }

    if (new Date() > session.expiresAt) {
      // حدّث الحالة في قاعدة البيانات
      await db.checkoutSession.update({
        where: { id: sessionId },
        data:  { status: 'expired' },
      });
      return res.status(410).json({ error: 'This checkout session has expired. Please start over.' });
    }

    const planLabel = PLAN_CONFIG[session.planId]?.label || session.planId;

    res.json({
      sessionId:    session.id,
      planId:       session.planId,
      planLabel,
      amount:       session.amount,
      billingCycle: session.billingCycle,
      tenantEmail:  session.tenant.email,
      expiresAt:    session.expiresAt,
    });

  } catch (err) {
    logger.error({ module: 'payments', error: err.message }, 'get-checkout-session failed');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// POST /api/payments/paypal-webhook
//
// الهدف: استقبال إشعار PayPal عند اكتمال الدفع وتحديث اشتراك التاجر
// الأمان:
//   1. التحقق من توقيع PayPal (Webhook Verification)
//   2. التحقق من Idempotency (captureId فريد)
//   3. التحقق من المبلغ (مقارنة بـ CheckoutSession)
// ══════════════════════════════════════════════════════════════════════════════
router.post('/paypal-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  // نُعيد 200 فوراً لـ PayPal لمنع إعادة المحاولة أثناء معالجتنا
  // ملاحظة: PayPal ينتظر الرد قبل أن يعتبر الـ Webhook ناجحاً
  // لذلك نُرسل 200 أولاً فقط إذا نجح التحقق من التوقيع

  let rawBody;
  try {
    rawBody = req.body; // express.raw يضع Buffer هنا
    if (!rawBody) return res.status(400).json({ error: 'Empty body' });
  } catch {
    return res.status(400).json({ error: 'Body read error' });
  }

  // ── 1. التحقق من توقيع PayPal ─────────────────────────────────────────
  // PayPal يُرسل هذه الـ headers مع كل Webhook
  const webhookId        = process.env.PAYPAL_WEBHOOK_ID;
  const transmissionId   = req.headers['paypal-transmission-id'];
  const transmissionTime = req.headers['paypal-transmission-time'];
  const certUrl          = req.headers['paypal-cert-url'];
  const authAlgo         = req.headers['paypal-auth-algo'];
  const transmissionSig  = req.headers['paypal-transmission-sig'];

  if (!webhookId || !transmissionId || !transmissionSig) {
    logger.warn({ module: 'payments' }, 'PayPal webhook missing verification headers');
    return res.status(401).json({ error: 'Missing PayPal verification headers' });
  }

  // ── التحقق الحقيقي من توقيع PayPal عبر REST API ──────────────────────
  // PayPal يوفر endpoint رسمي للـ verification — أدق وأأمن من HMAC يدوي
  // لأن PayPal يستخدم RSA مع certificate متغير، مش HMAC ثابت.
  let signatureVerified = false;

  // ── PP-RL-DROPS-LEGIT fix: retry on PayPal OAuth 429/5xx ─────────────────
  // PayPal's OAuth endpoint can return 503 under load. Without retry, the
  // webhook returns 401 immediately and PayPal retries hours later — the
  // merchant's subscription activation is delayed even though payment is done.
  // 3 attempts with 1s / 2s backoff adds up to ~15s latency in the worst case (4s timeout x3 + 1s + 2s backoff),
  // well within PayPal's 30-second webhook timeout.
  const PAYPAL_TOKEN_URL = process.env.PAYPAL_MODE === 'sandbox'
    ? 'https://api.sandbox.paypal.com/v1/oauth2/token'
    : 'https://api.paypal.com/v1/oauth2/token';

  const authString = Buffer.from(
    process.env.PAYPAL_CLIENT_ID + ':' + process.env.PAYPAL_CLIENT_SECRET
  ).toString('base64');

  let accessToken = null;
  for (let _attempt = 1; _attempt <= 3; _attempt++) {
    try {
      const tokenRes = await fetch(PAYPAL_TOKEN_URL, {
        method:  'POST',
        headers: {
          'Authorization': 'Basic ' + authString,
          'Content-Type':  'application/x-www-form-urlencoded',
        },
        body:   'grant_type=client_credentials',
        signal: AbortSignal.timeout(4000),   // fail fast per attempt
      });

      if (tokenRes.ok) {
        const tokenData = await tokenRes.json();
        accessToken = tokenData.access_token || null;
        if (accessToken) break;               // success — exit retry loop
      }

      // Retryable: 429 or any 5xx from PayPal OAuth
      if (_attempt < 3 && (tokenRes.status === 429 || tokenRes.status >= 500)) {
        logger.warn(
          { module: 'payments', attempt: _attempt, status: tokenRes.status },
          'PayPal OAuth transient error — retrying'
        );
        await new Promise(r => setTimeout(r, 1000 * _attempt));
        continue;
      }

      // Non-retryable 4xx (e.g. 401 = bad credentials) — break immediately
      logger.error(
        { module: 'payments', status: tokenRes.status },
        'PayPal OAuth non-retryable error'
      );
      break;

    } catch (fetchErr) {
      // Network error / timeout — retry if attempts remain
      if (_attempt < 3) {
        logger.warn(
          { module: 'payments', attempt: _attempt, error: fetchErr.message },
          'PayPal OAuth fetch error — retrying'
        );
        await new Promise(r => setTimeout(r, 1000 * _attempt));
        continue;
      }
      logger.error(
        { module: 'payments', error: fetchErr.message },
        'PayPal OAuth fetch failed after retries'
      );
    }
  }

  try {
    if (!accessToken) {
      logger.error({ module: 'payments' }, 'PayPal token fetch failed during webhook verification');
      return res.status(401).json({ error: 'Could not obtain PayPal access token' });
    }

    // التحقق من التوقيع
    const verifyRes = await fetch(
      process.env.PAYPAL_MODE === 'sandbox'
        ? 'https://api.sandbox.paypal.com/v1/notifications/verify-webhook-signature'
        : 'https://api.paypal.com/v1/notifications/verify-webhook-signature',
      {
        method:  'POST',
        headers: {
          'Authorization': 'Bearer ' + accessToken,
          'Content-Type':  'application/json',
        },
        body: JSON.stringify({
          auth_algo:         authAlgo         || 'SHA256withRSA',
          cert_url:          certUrl,
          transmission_id:   transmissionId,
          transmission_sig:  transmissionSig,
          transmission_time: transmissionTime,
          webhook_id:        webhookId,
          webhook_event:     JSON.parse(rawBody.toString()),
        }),
      }
    );

    const verifyData     = await verifyRes.json();
    signatureVerified    = verifyData.verification_status === 'SUCCESS';

    if (!signatureVerified) {
      logger.warn(
        { module: 'payments', verification_status: verifyData.verification_status },
        'PayPal webhook signature verification FAILED'
      );
      return res.status(401).json({ error: 'Invalid webhook signature' });
    }

    logger.info({ module: 'payments', transmissionId }, 'PayPal webhook signature verified ✅');

  } catch (verifyErr) {
    logger.error(
      { module: 'payments', error: verifyErr.message },
      'PayPal webhook verification request failed'
    );
    return res.status(500).json({ error: 'Webhook verification failed' });
  }

  // ── 2. تحليل جسم الـ Webhook ──────────────────────────────────────────
  let event;
  try {
    event = JSON.parse(rawBody.toString());
  } catch {
    return res.status(400).json({ error: 'Invalid JSON payload' });
  }

  // No early ACK: every exit path below replies explicitly (200 = done, 500 = PayPal must retry).

  // ── 3. نُعالج فقط حدث اكتمال الدفع ──────────────────────────────────
  if (event.event_type !== 'PAYMENT.CAPTURE.COMPLETED') {
    logger.info(
      { module: 'payments', eventType: event.event_type },
      'Ignoring non-capture PayPal event'
    );
    return res.status(200).json({ received: true, ignored: true });
  }

  // ── 4. استخراج بيانات الدفعة ──────────────────────────────────────────
  const capture      = event.resource;
  const captureId    = capture?.id;
  const amountPaid   = parseFloat(capture?.amount?.value || '0');
  const currency     = capture?.amount?.currency_code || 'USD';
  const EXPECTED_CURRENCY = 'USD'; // ASSUMPTION: all plans are priced in USD. Confirm where the PayPal order is created.
  const customId     = capture?.custom_id;
  // custom_id هو sessionId الذي سنُمرره عند إنشاء PayPal Order

  if (!captureId || !customId) {
    logger.error(
      { module: 'payments', captureId, customId },
      'PayPal webhook missing captureId or custom_id'
    );
    return res.status(200).json({ received: true });
  }

  try {
    // ── 5. Idempotency — هل عالجنا هذه الدفعة من قبل؟ ───────────────────
    const existingPayment = await db.payment.findUnique({
      where: { captureId },
    });

    if (existingPayment) {
      logger.info(
        { module: 'payments', captureId },
        'Duplicate PayPal webhook — already processed'
      );
      return res.status(200).json({ received: true, duplicate: true });
    }

    // ── 6. جلب جلسة الدفع للتحقق من المبلغ ──────────────────────────────
    const session = await db.checkoutSession.findUnique({
      where: { id: customId },
      include: { tenant: true },
    });

    if (!session) {
      logger.error(
        { module: 'payments', customId },
        'PayPal webhook: CheckoutSession not found'
      );
      return res.status(200).json({ received: true });
    }

    if (session.status !== 'pending') {
      // #101: a capture arrived for a session that is not pending. completed = the session was
      // already activated by another capture (possible double charge); failed = we rejected an
      // earlier capture (amount/currency). In both cases the customer has paid and nothing is
      // activated or refunded here, so this must be loud. Behaviour is unchanged (return, no writes).
      const loud = session.status === 'completed' || session.status === 'failed';
      const logFn = loud ? logger.error : logger.warn;
      logFn.call(
        logger,
        {
          module: 'payments',
          customId,
          captureId,
          status: session.status,
          currency,
          rawAmount: capture?.amount?.value,
          tenantId: session.tenantId,
          reason: session.status === 'completed'
            ? 'session_completed_possible_double_charge'
            : session.status === 'failed'
              ? 'session_failed_paid_not_activated'
              : 'session_not_pending',
        },
        'PayPal webhook: capture on a non-pending checkout session. Verify manually in PayPal'
      );
      return res.status(200).json({ received: true });
    }

    // ── 7. التحقق من المبلغ (الحماية من التلاعب) ─────────────────────────
    const expectedAmount = session.amount;
    const tolerance      = 0.01; // فارق مقبول بسبب تقريبات الفاوصل العشرية

    const amountInvalid    = !Number.isFinite(amountPaid);
    const currencyMismatch = currency !== EXPECTED_CURRENCY;

    if (amountInvalid || currencyMismatch || Math.abs(amountPaid - expectedAmount) > tolerance) {
      if (amountInvalid || currencyMismatch) {
        logger.error(
          {
            module:           'payments',
            captureId,
            reason:           amountInvalid ? 'invalid_amount' : 'currency_mismatch',
            rawAmount:        capture?.amount?.value,
            currency,
            expectedCurrency: EXPECTED_CURRENCY,
            tenantId:         session.tenantId,
          },
          'PayPal webhook rejected: invalid amount or unexpected currency. Verify manually in PayPal'
        );
      }
      logger.error(
        {
          module:   'payments',
          captureId,
          amountPaid,
          expectedAmount,
          tenantId: session.tenantId,
        },
        '🚨 AMOUNT MISMATCH — possible fraud attempt on checkout'
      );
      // لا نُفعّل الاشتراك، لكن نُسجّل المحاولة
      await db.checkoutSession.update({
        where: { id: customId },
        data:  { status: 'failed' },
      });
      return res.status(200).json({ received: true });
    }

    // ── 8. حساب تاريخ انتهاء الاشتراك ────────────────────────────────────
    const now = new Date();
    const subscriptionEndDate = session.billingCycle === 'annual'
      ? new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000)
      : new Date(now.getTime() + 30  * 24 * 60 * 60 * 1000);

    // تحديد الخطة من planId
    const planName = session.planId.startsWith('pro') ? 'pro' : 'agency';

    // ── 9. تحديث كل شيء في transaction واحدة ─────────────────────────────
    await db.$transaction(async (tx) => {
      // أ. تحديث الـ Tenant بالخطة الجديدة
      await tx.tenant.update({
        where: { id: session.tenantId },
        data: {
          plan:               planName,
          subscriptionStatus: 'active',
          subscriptionEndDate,
          billingCycle:       session.billingCycle,
          lastPaymentDate:    now,
          lastPaymentAmount:  amountPaid,
          lastCaptureId:      captureId,
        },
      });

      // ب. تسجيل الدفعة في جدول Payment
      await tx.payment.create({
        data: {
          tenantId:         session.tenantId,
          checkoutSessionId: session.id,
          captureId,
          amount:           amountPaid,
          expectedAmount,
          planId:           session.planId,
          billingCycle:     session.billingCycle,
          status:           'completed',
          paypalOrderId:    capture?.supplementary_data?.related_ids?.order_id || null,
          paypalPayerId:    event.resource?.payer?.payer_id || null,
        },
      });

      // ج. إغلاق جلسة الدفع
      await tx.checkoutSession.update({
        where: { id: customId },
        data:  { status: 'completed' },
      });
    });

    // Transaction committed: ACK now. No return, so the confirmation email below is still scheduled.
    res.status(200).json({ received: true });

    logger.info(
      {
        module:    'payments',
        tenantId:  session.tenantId,
        plan:      planName,
        captureId,
        amount:    amountPaid,
        endDate:   subscriptionEndDate,
      },
      '✅ Subscription activated successfully'
    );

    // ── 10. إرسال إيميل تأكيد للتاجر (fire-and-forget) ───────────────────
    // تأخير 2 ثانية بعد الـ transaction — نضمن أن DB commit اكتمل
    // fire-and-forget: أي خطأ في الإيميل لا يؤثر على استجابة الـ webhook
    setTimeout(() => {
      sendSubscriptionConfirmationEmail(session.tenant.email, {
        planName,
        billingCycle:        session.billingCycle,
        amount:              amountPaid,
        subscriptionEndDate,
        captureId,
      }).catch(err =>
        logger.error({ module: 'payments', captureId, err: err.message }, 'Confirmation email failed — non-critical')
      );
    }, 2000);

  } catch (err) {
    // [P0-07 fix] A P2002 unique-constraint violation here means two
    // concurrent deliveries of the same webhook both passed the
    // findUnique(captureId) check above — a genuine TOCTOU race, since
    // PayPal does redeliver a webhook if it doesn't see our 200 fast
    // enough — and one of them lost the race for the captureId (or
    // checkoutSessionId) unique constraint inside this transaction. This
    // is NOT a processing failure: the constraint did exactly what it's
    // for, and the whole transaction rolling back means this particular
    // request produced zero side effects (no double subscription
    // activation, no duplicate Payment row) — the other concurrent
    // request is the one that actually completed the work. Logging this
    // as an error would be a false alarm, and could mask a real failure
    // happening at the same time under the noise.
    let dupOfKnownCapture = false;
    if (err.code === 'P2002') {
      // #89: P2002 may come from captureId (innocent redelivery) OR from checkoutSessionId
      // (a different capture on the same session). Only the first is an innocent duplicate.
      dupOfKnownCapture = Boolean(await Promise.resolve(db.payment.findUnique({ where: { captureId } })).catch(() => null));
    }
    if (dupOfKnownCapture) {
      logger.info(
        { module: 'payments', captureId, target: err.meta?.target },
        'PayPal webhook: concurrent duplicate suppressed by unique constraint — no action needed'
      );
    } else {
      logger.error(
        { module: 'payments', error: err.message, stack: err.stack },
        'PayPal webhook processing failed' + (err.code === 'P2002' ? ' (P2002 but no Payment row for this captureId: possible second payment on the same checkout session)' : '')
      );
    }
    // Reply only if nothing was sent yet. A known duplicate is done (200);
    // any real failure returns 500 so PayPal retries the delivery.
    if (!res.headersSent) {
      if (dupOfKnownCapture) {
        return res.status(200).json({ received: true, duplicate: true });
      }
      return res.status(500).json({ error: 'Webhook processing failed' });
    }
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// GET /api/payments/subscription-status
//
// الهدف: التاجر يتحقق من حالة اشتراكه (من لوحة التحكم أو Plugin)
// ══════════════════════════════════════════════════════════════════════════════
router.get('/subscription-status', apiKeyAuth, async (req, res) => {
  try {
    const tenant = await db.tenant.findUnique({
      where: { id: req.tenant.id },
      select: {
        plan:               true,
        subscriptionStatus: true,
        subscriptionEndDate: true,
        billingCycle:       true,
        lastPaymentDate:    true,
        lastPaymentAmount:  true,
      },
    });

    if (!tenant) return res.status(404).json({ error: 'Tenant not found' });

    // حساب الأيام المتبقية
    const daysRemaining = tenant.subscriptionEndDate
      ? Math.max(0, Math.ceil((new Date(tenant.subscriptionEndDate) - new Date()) / (1000 * 60 * 60 * 24)))
      : null;

    res.json({
      plan:               tenant.plan,
      subscriptionStatus: tenant.subscriptionStatus,
      subscriptionEndDate: tenant.subscriptionEndDate,
      billingCycle:       tenant.billingCycle,
      daysRemaining,
      lastPaymentDate:    tenant.lastPaymentDate,
      lastPaymentAmount:  tenant.lastPaymentAmount,
      isActive:           tenant.subscriptionStatus === 'active' || tenant.subscriptionStatus === 'grace_period',
    });

  } catch (err) {
    logger.error({ module: 'payments', error: err.message }, 'subscription-status failed');
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;