'use strict';

/**
 * retention.js — ChargeGuard Data Retention Policy
 * ─────────────────────────────────────────────────
 * مسؤولية هذا الملف: حذف البيانات القديمة تلقائياً من قاعدة البيانات
 * لمنع التضخم والامتثال لمبدأ Data Minimization (GDPR Art. 5.1.e).
 *
 * يُستدعى من app.js عبر:
 *   const { runFastCleanup, runDailyRetention } = require('./lib/retention');
 *
 * مهمتان:
 *   - runFastCleanup()    → كل 10 دقائق (خفيفة، حساسة للوقت)
 *   - runDailyRetention() → كل 24 ساعة  (شاملة، بدفعات تدريجية)
 */

const { PrismaClient } = require('@prisma/client');

// ─────────────────────────────────────────────────────────────────────────────
//  إعدادات الاحتفاظ — قابلة للتعديل عبر Environment Variables
// ─────────────────────────────────────────────────────────────────────────────

const RETENTION = {
  // فترات الاحتفاظ (بالأيام) — غيّرها في .env بدون إعادة deploy
  ORDER_DAYS:               Number(process.env.RETENTION_ORDER_DAYS)                || 90,
  CARD_TEST_DAYS:           Number(process.env.RETENTION_CARD_TEST_DAYS)            || 60,
  BLOCKED_ATTEMPT_DAYS:     Number(process.env.RETENTION_BLOCKED_ATTEMPT_DAYS)      || 180,
  IDENTITY_EVENT_DAYS:      Number(process.env.RETENTION_IDENTITY_EVENT_DAYS)       || 30,
  IDENTITY_NODE_DAYS:       Number(process.env.RETENTION_IDENTITY_NODE_DAYS)        || 90,
  COMPUTED_RISK_DAYS:       Number(process.env.RETENTION_COMPUTED_RISK_DAYS)        || 90,
  CARD_HASH_DAYS:           Number(process.env.RETENTION_CARD_HASH_DAYS)            || 365,
  PENDING_ENRICHMENT_HOURS: Number(process.env.RETENTION_PENDING_ENRICHMENT_HOURS)  || 24,
  UNVERIFIED_TENANT_DAYS:   Number(process.env.RETENTION_UNVERIFIED_TENANT_DAYS)    || 30,

  // إعدادات الأداء — الحذف التدريجي لتجنب قفل الجداول
  BATCH_SIZE:     Number(process.env.CLEANUP_BATCH_SIZE)     || 500,
  BATCH_DELAY_MS: Number(process.env.CLEANUP_BATCH_DELAY_MS) || 100,
};

// ─────────────────────────────────────────────────────────────────────────────
//  دوال مساعدة
// ─────────────────────────────────────────────────────────────────────────────

/** تُعيد كائن Date قبل n يوم من الآن */
function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d;
}

/** تُعيد كائن Date قبل n ساعة من الآن */
function hoursAgo(n) {
  return new Date(Date.now() - n * 60 * 60 * 1000);
}

/**
 * batchDelete — حذف تدريجي بدفعات صغيرة
 *
 * يحذف السجلات على دفعات بحجم BATCH_SIZE مع تأخير بين كل دفعة،
 * لتجنب قفل الجداول وضمان استجابة الاستعلامات الحية.
 *
 * @param {PrismaClient} prisma   - instance نشط
 * @param {string}       model    - اسم الجدول كما في Prisma (camelCase)
 * @param {object}       where    - شرط الحذف (Prisma where clause)
 * @returns {{ batches: number, total: number }} - إحصائيات الحذف
 */
async function batchDelete(prisma, model, where) {
  let totalDeleted = 0;
  let batches      = 0;

  while (true) {
    // الخطوة 1: اجلب IDs للدفعة القادمة فقط (لا نحذف كل شيء دفعة واحدة)
    const rows = await prisma[model].findMany({
      where,
      select: { id: true },
      take: RETENTION.BATCH_SIZE,
    });

    if (rows.length === 0) break; // لا توجد سجلات أخرى → انتهينا

    const ids = rows.map((r) => r.id);

    // الخطوة 2: احذف هذه الدفعة بالتحديد
    const result = await prisma[model].deleteMany({
      where: { id: { in: ids } },
    });

    totalDeleted += result.count;
    batches      += 1;

    if (rows.length < RETENTION.BATCH_SIZE) break; // الدفعة الأخيرة

    // الخطوة 3: انتظر قبل الدفعة التالية (يُخفف الضغط على DB)
    await new Promise((resolve) => setTimeout(resolve, RETENTION.BATCH_DELAY_MS));
  }

  return { batches, total: totalDeleted };
}

// ─────────────────────────────────────────────────────────────────────────────
//  runFastCleanup — تُشغَّل كل 10 دقائق
// ─────────────────────────────────────────────────────────────────────────────
/**
 * مهمة خفيفة وسريعة تعالج البيانات الحساسة للوقت:
 *   1. Order حيث decision = 'block'    (الأمان الفوري + مساحة DB)
 *   2. BlacklistEntry منتهية الصلاحية  (تنظيف منطقي خفيف)
 *   3. PendingEnrichment فاشلة > 24h   (تجنب تراكم سجلات عالقة)
 *
 * لا تنشئ PrismaClient خاص بها — تستقبله من المستدعي (app.js)
 * لتجنب فتح وإغلاق connections غير ضرورية.
 */
async function runFastCleanup(prisma) {
  const tag = `[${new Date().toISOString()}]`;

  try {
    // 1. Order المحظورة — حذف فوري بدون batching (هي أصلاً محدودة العدد)
    const blockedOrders = await prisma.order.deleteMany({
      where: { decision: 'block' },
    });

    // 2. BlacklistEntry منتهية الصلاحية
    const expiredBlacklist = await prisma.blacklistEntry.deleteMany({
      where: {
        expiresAt: { not: null, lt: new Date() },
      },
    });

    // 3. WhitelistEntry منتهية الصلاحية
    const expiredWhitelist = await prisma.whitelistEntry.deleteMany({
      where: {
        expiresAt: { not: null, lt: new Date() },
      },
    });

    // 4. PendingEnrichment عالقة > 24 ساعة (لم تُعالج ولم تكتمل)
    const stalePending = await prisma.pendingEnrichment.deleteMany({
      where: {
        createdAt: { lt: hoursAgo(RETENTION.PENDING_ENRICHMENT_HOURS) },
        status:    { not: 'done' },
      },
    });

    // سجّل فقط إذا حُذف شيء (لا نملأ logs بأسطر فارغة)
    const total = blockedOrders.count + expiredBlacklist.count + expiredWhitelist.count + stalePending.count;
    if (total > 0) {
      console.log(
        `${tag} ✅ FastCleanup — blocked orders: ${blockedOrders.count}, ` +
        `expired blacklist: ${expiredBlacklist.count}, ` +
        `expired whitelist: ${expiredWhitelist.count}, ` +
        `stale pending: ${stalePending.count}`
      );
    }
  } catch (err) {
    console.error(`${tag} ❌ FastCleanup failed:`, err.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  runDailyRetention — تُشغَّل مرة واحدة كل 24 ساعة
// ─────────────────────────────────────────────────────────────────────────────
/**
 * مهمة شاملة تحذف البيانات القديمة من 7 جداول بالترتيب الصحيح.
 *
 * الترتيب مقصود:
 *   أولاً: الجداول بدون FK (IdentityEvent, ComputedIdentityRisk)
 *   ثانياً: الجداول التي تُحذف Cascade منها (IdentityNode → IdentityEdge)
 *   ثالثاً: الجداول المستقلة (CardTestAttempt, BlockedAttempt)
 *   أخيراً: Order (تُحذف RiskEvaluation cascade، DisputeOutcome تصبح null)
 *
 * تنشئ PrismaClient خاص بها وتُغلقه عند الانتهاء.
 */
let _dailyRunning = false; // Concurrency guard

async function runDailyRetention() {
  if (_dailyRunning) {
    console.warn(`[${new Date().toISOString()}] ⚠️  Daily retention already running — skipped`);
    return;
  }
  _dailyRunning = true;

  const startedAt = new Date();
  const tag       = `[${startedAt.toISOString()}]`;

  console.log(`${tag} 🧹 Daily retention started...`);

  const prisma  = new PrismaClient();
  const results = {};

  try {

    // دالة مساعدة داخلية لعزل خطأ كل جدول عن الآخر
    async function safeClean(label, fn) {
      try {
        results[label] = await fn();
      } catch (err) {
        console.error(`[${new Date().toISOString()}] ❌ Failed to clean ${label}:`, err.message);
        results[label] = { total: 0, batches: 0, failed: true };
      }
    }

    // ── 1. IdentityEvent > 30 يوم ─────────────────────────────────────────
    await safeClean('identityEvent', () => batchDelete(
      prisma, 'identityEvent',
      { createdAt: { lt: daysAgo(RETENTION.IDENTITY_EVENT_DAYS) } }
    ));

    // ── 2. ComputedIdentityRisk > 90 يوم (PK مركب — deleteMany مباشر) ────
    await safeClean('computedIdentityRisk', async () => {
      const r = await prisma.computedIdentityRisk.deleteMany({
        where: { computedAt: { lt: daysAgo(RETENTION.COMPUTED_RISK_DAYS) } },
      });
      return { total: r.count, batches: 1 };
    });

    // ── 3. IdentityNode غير نشطة > 90 يوم (Edges تُحذف cascade) ──────────
    await safeClean('identityNode', () => batchDelete(
      prisma, 'identityNode',
      { lastSeen: { lt: daysAgo(RETENTION.IDENTITY_NODE_DAYS) } }
    ));

    // ── 4. CardTestAttempt > 60 يوم (بصمات بطاقات — GDPR priority) ───────
    await safeClean('cardTestAttempt', () => batchDelete(
      prisma, 'cardTestAttempt',
      { createdAt: { lt: daysAgo(RETENTION.CARD_TEST_DAYS) } }
    ));

    // ── 5. BlockedAttempt > 180 يوم ───────────────────────────────────────
    await safeClean('blockedAttempt', () => batchDelete(
      prisma, 'blockedAttempt',
      { blockedAt: { lt: daysAgo(RETENTION.BLOCKED_ATTEMPT_DAYS) } }
    ));

    // ── 6. Order (approve/review) > 90 يوم ───────────────────────────────
    await safeClean('order', () => batchDelete(
      prisma, 'order',
      {
        createdAt: { lt: daysAgo(RETENTION.ORDER_DAYS) },
        decision:  { in: ['approve', 'review'] },
      }
    ));

    // ── 7. CardHash غير مُستخدمة > 365 يوم ──────────────────────────────
    await safeClean('cardHash', () => batchDelete(
      prisma, 'cardHash',
      { lastSeenAt: { lt: daysAgo(RETENTION.CARD_HASH_DAYS) } }
    ));

    // ── 8. WhitelistEntry منتهية الصلاحية (احتياطي إذا فاتت FastCleanup) ──
    await safeClean('whitelistEntry', async () => {
      const r = await prisma.whitelistEntry.deleteMany({
        where: { expiresAt: { not: null, lt: new Date() } },
      });
      return { total: r.count, batches: 1 };
    });

    // ── 9. Tenants غير مؤكدين > 30 يوم ──────────────────────────────────
    // مستخدمون سجّلوا بإيميلات وهمية أو لم يكملوا التأكيد خلال شهر كامل
    await safeClean('unverifiedTenant', () => batchDelete(
      prisma, 'tenant',
      {
        emailVerified: false,
        createdAt: { lt: daysAgo(RETENTION.UNVERIFIED_TENANT_DAYS) },
      }
    ));

    // ── طباعة الملخص النهائي (سطر واحد لكل جدول) ─────────────────────────
    const durationMs = Date.now() - startedAt.getTime();
    const endTag     = `[${new Date().toISOString()}]`;

    const totalRows = Object.values(results).reduce((sum, r) => sum + r.total, 0);

    console.log(
      `${endTag} ✅ Daily retention completed in ${durationMs}ms — ` +
      `${totalRows} rows deleted total:\n` +
      `  • IdentityEvent:        ${fmt(results.identityEvent)}\n` +
      `  • ComputedIdentityRisk: ${fmt(results.computedIdentityRisk)}\n` +
      `  • IdentityNode:         ${fmt(results.identityNode)}\n` +
      `  • CardTestAttempt:      ${fmt(results.cardTestAttempt)}\n` +
      `  • BlockedAttempt:       ${fmt(results.blockedAttempt)}\n` +
      `  • Order:                ${fmt(results.order)}\n` +
      `  • CardHash:             ${fmt(results.cardHash)}\n` +
      `  • WhitelistEntry:       ${fmt(results.whitelistEntry)}\n` +
      `  • UnverifiedTenant:     ${fmt(results.unverifiedTenant)}`
    );

  } catch (err) {
    console.error(`[${new Date().toISOString()}] ❌ Daily retention failed:`, err.message);
  } finally {
    _dailyRunning = false;          // ← أطلق القفل دائماً
    await prisma.$disconnect();
  }
}

/** دالة مساعدة لتنسيق إحصائيات الجدول في الـ log */
function fmt(result) {
  if (!result)             return '⚠️  no result (skipped)';
  if (result.failed)       return '❌ failed';
  if (result.total === 0)  return 'nothing to delete';
  return `deleted ${result.total.toLocaleString()} rows (${result.batches} batch${result.batches !== 1 ? 'es' : ''})`;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Exports
// ─────────────────────────────────────────────────────────────────────────────

module.exports = { runFastCleanup, runDailyRetention, RETENTION };