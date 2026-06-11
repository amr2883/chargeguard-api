'use strict';

// ══════════════════════════════════════════════════════════════════════════════
// Subscription Lifecycle Scheduler
//
// المهمة: إدارة دورة حياة الاشتراكات يدوياً بذكاء
// يعمل: كل ساعة
// يتحقق من:
//   1. تناننت اشتراكهم ينتهي قريباً → إرسال تحذيرات (7/3/1 يوم)
//   2. تناننت انتهى اشتراكهم → تحويل لـ grace_period
//   3. تناننت انتهت فترة سماحهم → تحويل لـ expired وخفض الخطة
//   4. حذف جلسات الدفع المنتهية (cleanup)
// ══════════════════════════════════════════════════════════════════════════════

const { sendRenewalReminderEmail, sendGracePeriodEmail } = require('../lib/email');

// ── Constants ────────────────────────────────────────────────────────────────

const GRACE_PERIOD_DAYS = 7;
// عدد أيام فترة السماح بعد انتهاء الاشتراك

const REMINDER_COOLDOWN_HOURS = 20;
// الحد الأدنى بين إيميلين من نفس النوع للتاجر نفسه
// 20 ساعة = يضمن إيميل واحد يومياً مع هامش أمان

const REMINDER_DAYS = [7, 3, 1];
// أيام الإرسال قبل الانتهاء

const PLAN_LABELS = {
  pro:    'Pro',
  agency: 'Agency',
};

const CHECKOUT_SESSION_TTL_MINUTES = 30;
// نفس القيمة في payments.js

// ── Helper: هل مضى REMINDER_COOLDOWN_HOURS منذ آخر إرسال؟ ─────────────────
const canSendEmail = (lastSentAt) => {
  if (!lastSentAt) return true;
  const hoursSince = (Date.now() - new Date(lastSentAt).getTime()) / (1000 * 60 * 60);
  return hoursSince >= REMINDER_COOLDOWN_HOURS;
};

// ── Helper: بناء رابط التجديد ────────────────────────────────────────────────
const buildRenewUrl = (planId) => {
  const base = process.env.RENDER_EXTERNAL_URL || 'https://chargeguard-api.onrender.com';
  // التاجر يُعيد المرور بنفس تدفق الدفع
  // لا نحتاج session هنا — سيُنشأ عند الضغط على الزر في صفحة التسعير
  return `https://chargeguard.io/#pricing?renew=${planId}`;
};

// ══════════════════════════════════════════════════════════════════════════════
// Phase 1: إرسال تحذيرات التجديد للاشتراكات القريبة من الانتهاء
// ══════════════════════════════════════════════════════════════════════════════
const processRenewalReminders = async (db) => {
  const now = new Date();

  // نجلب التاجر الذين اشتراكهم ينتهي خلال 7 أيام أو أقل
  // ولا يزالون في حالة active
  const maxWindow = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

  const tenantsToRemind = await db.tenant.findMany({
    where: {
      subscriptionStatus: 'active',
      subscriptionEndDate: {
        gt:  now,      // لم ينته بعد
        lte: maxWindow, // لكنه خلال 7 أيام
      },
      plan: { in: ['pro', 'agency'] },
      isActive: true,
    },
    select: {
      id:                        true,
      email:                     true,
      storeUrl:                  true,
      plan:                      true,
      billingCycle:              true,
      subscriptionEndDate:       true,
      lastRenewalReminderSentAt: true,
    },
  });

  console.log(`[SubscriptionScheduler] 📅 Found ${tenantsToRemind.length} tenants approaching renewal`);

  for (const tenant of tenantsToRemind) {
    try {
      const endDate     = new Date(tenant.subscriptionEndDate);
      // نستخدم floor مع window ±6 ساعات لضمان عدم تفويت أي إشعار
      // مثلاً: إذا كان الوقت المتبقي 6.8 يوم → floor = 6، نتحقق هل 7 في النطاق
      // إذا كان 7.1 يوم → floor = 7، يُرسل — صحيح
      // إذا كان 2.8 يوم → floor = 2، نتحقق هل 3 في النطاق (2.8 > 2.5 → نعم)
      const hoursLeft   = (endDate - now) / (1000 * 60 * 60);
      const daysLeft    = Math.ceil(hoursLeft / 24); // للعرض في الإيميل فقط
      const shouldRemind = REMINDER_DAYS.some(d => hoursLeft <= d * 24 && hoursLeft > (d * 24) - 25);
      // window = 25 ساعة لكل نقطة (أكبر من interval الساعة بهامش أمان)

      if (!shouldRemind) continue;

      if (!canSendEmail(tenant.lastRenewalReminderSentAt)) {
        console.log(`[SubscriptionScheduler] ⏭️  Skipping reminder for ${tenant.email} — cooldown active`);
        continue;
      }

      const planLabel = PLAN_LABELS[tenant.plan] || tenant.plan;
      const planId    = `${tenant.plan}_${tenant.billingCycle || 'monthly'}`;

      await sendRenewalReminderEmail(
        { email: tenant.email, storeUrl: tenant.storeUrl },
        {
          daysRemaining: daysLeft,
          planLabel,
          renewUrl: buildRenewUrl(planId),
        }
      );

      // تحديث آخر وقت إرسال
      await db.tenant.update({
        where: { id: tenant.id },
        data:  { lastRenewalReminderSentAt: new Date() },
      });

      console.log(`[SubscriptionScheduler] ✅ Renewal reminder sent to ${tenant.email} — ${daysLeft} days left`);

    } catch (err) {
      // خطأ في تاجر واحد لا يوقف الـ loop كاملاً
      console.error(`[SubscriptionScheduler] ❌ Reminder failed for ${tenant.email}:`, err.message);
    }
  }
};

// ══════════════════════════════════════════════════════════════════════════════
// Phase 2: تحويل الاشتراكات المنتهية إلى grace_period
// ══════════════════════════════════════════════════════════════════════════════
const processExpiredToGrace = async (db) => {
  const now = new Date();

  // اشتراكات انتهت وما زالت active (لم تُعالج بعد)
  const expiredTenants = await db.tenant.findMany({
    where: {
      subscriptionStatus: 'active',
      subscriptionEndDate: { lte: now },
      plan: { in: ['pro', 'agency'] },
      isActive: true,
    },
    select: {
      id:                         true,
      email:                      true,
      storeUrl:                   true,
      plan:                       true,
      billingCycle:               true,
      subscriptionEndDate:        true,
      lastGracePeriodNoticeSentAt: true,
    },
  });

  if (expiredTenants.length > 0) {
    console.log(`[SubscriptionScheduler] ⚠️  Found ${expiredTenants.length} expired subscriptions → moving to grace_period`);
  }

  for (const tenant of expiredTenants) {
    try {
      const graceEndsAt = new Date(now.getTime() + GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000);

      // تحديث الحالة أولاً — قبل إرسال الإيميل
      // لأن إرسال الإيميل قد يفشل، لكن تغيير الحالة يجب أن ينجح دائماً
      await db.tenant.update({
        where: { id: tenant.id },
        data: {
          subscriptionStatus:  'grace_period',
          subscriptionEndDate: graceEndsAt,
          // نُمدّد subscriptionEndDate لتاريخ نهاية Grace Period
          // هكذا Phase 3 يعرف متى تنتهي فترة السماح بدون حقل إضافي
        },
      });

      console.log(`[SubscriptionScheduler] 🔄 ${tenant.email} → grace_period (ends ${graceEndsAt.toISOString()})`);

      // إرسال إيميل Grace Period (مع cooldown)
      if (canSendEmail(tenant.lastGracePeriodNoticeSentAt)) {
        const planLabel = PLAN_LABELS[tenant.plan] || tenant.plan;
        const planId    = `${tenant.plan}_${tenant.billingCycle || 'monthly'}`;

        await sendGracePeriodEmail(
          { email: tenant.email, storeUrl: tenant.storeUrl },
          {
            planLabel,
            graceEndsAt,
            renewUrl: buildRenewUrl(planId),
          }
        );

        await db.tenant.update({
          where: { id: tenant.id },
          data:  { lastGracePeriodNoticeSentAt: new Date() },
        });

        console.log(`[SubscriptionScheduler] ✅ Grace period notice sent to ${tenant.email}`);
      }

    } catch (err) {
      console.error(`[SubscriptionScheduler] ❌ Grace period processing failed for ${tenant.email}:`, err.message);
    }
  }
};

// ══════════════════════════════════════════════════════════════════════════════
// Phase 3: تحويل grace_period المنتهية إلى expired وخفض الخطة
// ══════════════════════════════════════════════════════════════════════════════
const processGraceToExpired = async (db) => {
  const now = new Date();

  // grace_period انتهى (subscriptionEndDate = نهاية Grace Period)
  const graceExpiredTenants = await db.tenant.findMany({
    where: {
      subscriptionStatus: 'grace_period',
      subscriptionEndDate: { lte: now },
      isActive: true,
    },
    select: {
      id:    true,
      email: true,
      plan:  true,
    },
  });

  if (graceExpiredTenants.length > 0) {
    console.log(`[SubscriptionScheduler] 🔻 Found ${graceExpiredTenants.length} grace periods ended → downgrading to free`);
  }

  for (const tenant of graceExpiredTenants) {
    try {
      await db.tenant.update({
        where: { id: tenant.id },
        data: {
          plan:               'starter',
          subscriptionStatus: 'expired',
          subscriptionEndDate: null,
          billingCycle:        null,
          // نحتفظ بـ lastPaymentDate و lastPaymentAmount للمراجعة
        },
      });

      console.log(`[SubscriptionScheduler] ⬇️  ${tenant.email} downgraded: ${tenant.plan} → starter (grace ended)`);

      // TODO: يمكن إضافة إيميل "Your protection has ended — renew to restore" هنا
      // لكن لا نريد تضخيم الـ scope الآن

    } catch (err) {
      console.error(`[SubscriptionScheduler] ❌ Downgrade failed for ${tenant.email}:`, err.message);
    }
  }
};

// ══════════════════════════════════════════════════════════════════════════════
// Phase 4: حذف جلسات الدفع المنتهية الصلاحية
// تنظيف دوري — نبقي قاعدة البيانات نظيفة
// ══════════════════════════════════════════════════════════════════════════════
const cleanupExpiredSessions = async (db) => {
  const now = new Date();

  // نحذف الجلسات التي:
  // 1. انتهت صلاحيتها (expiresAt < now) وحالتها pending
  // 2. أو مضى عليها أكثر من 24 ساعة بأي حالة (completed/failed/expired)
  const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  try {
    const deletedExpired = await db.checkoutSession.deleteMany({
      where: {
        OR: [
          {
            status:    'pending',
            expiresAt: { lte: now },
          },
          {
            status:    { in: ['completed', 'failed', 'expired'] },
            createdAt: { lte: oneDayAgo },
          },
        ],
      },
    });

    if (deletedExpired.count > 0) {
      console.log(`[SubscriptionScheduler] 🧹 Cleaned ${deletedExpired.count} expired checkout sessions`);
    }
  } catch (err) {
    // الـ cleanup فشل — مش مشكلة كبيرة، سيحدث في الـ run التالي
    console.error(`[SubscriptionScheduler] ❌ Session cleanup failed:`, err.message);
  }
};

// ══════════════════════════════════════════════════════════════════════════════
// الدالة الرئيسية — تُشغَّل كل ساعة
// ══════════════════════════════════════════════════════════════════════════════
const runSubscriptionCycle = async (db) => {
  const startTime = Date.now();
  console.log(`[SubscriptionScheduler] 🔄 Starting subscription cycle — ${new Date().toISOString()}`);

  try {
    // الترتيب مهم:
    // Phase 1 أولاً (تحذيرات) لأنها لا تُغيّر الحالة
    // Phase 2 قبل 3 لأن 3 يعتمد على ما فعله 2
    await processRenewalReminders(db);
    await processExpiredToGrace(db);
    await processGraceToExpired(db);
    await cleanupExpiredSessions(db);

    const duration = Date.now() - startTime;
    console.log(`[SubscriptionScheduler] ✅ Cycle completed in ${duration}ms`);

  } catch (err) {
    // خطأ غير متوقع في الـ cycle كاملة
    console.error(`[SubscriptionScheduler] 💥 Cycle failed:`, err.message, err.stack);
  }
};

// ══════════════════════════════════════════════════════════════════════════════
// startSubscriptionScheduler — يُستدعى من app.js عند بدء الخادم
// ══════════════════════════════════════════════════════════════════════════════
const startSubscriptionScheduler = (db) => {
  const INTERVAL_MS = 60 * 60 * 1000; // كل ساعة
  const INITIAL_DELAY_MS = 2 * 60 * 1000; // 2 دقيقة بعد بدء الخادم

  // تأخير أولي لمنع ضغط الـ startup
  // (الـ schedulers الأخرى تنتظر 5 دقائق — نحن ننتظر 2)
  setTimeout(() => {
    console.log(`[SubscriptionScheduler] 🚀 Started — running every ${INTERVAL_MS / 60000} minutes`);

    // شغّل مرة واحدة فوراً عند البدء لاكتشاف أي حالات مكدسة
    runSubscriptionCycle(db);

    // ثم كل ساعة
    setInterval(() => runSubscriptionCycle(db), INTERVAL_MS);

  }, INITIAL_DELAY_MS);
};

module.exports = { startSubscriptionScheduler };