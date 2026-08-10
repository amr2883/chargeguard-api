'use strict';

/**
 * reportDataService.js — ChargeGuard Monthly Report Data Engine
 * ──────────────────────────────────────────────────────────────
 * يجمع كل البيانات اللازمة لإنشاء التقرير الشهري من مصادرها الحقيقية.
 * لا يُنشئ PDF — فقط يُحضّر البيانات.
 *
 * الاستخدام:
 *   const data = await buildMonthlyReportData(prisma, tenantId, month, year);
 */

const db = require('./db');
const { SAVINGS_PER_ATTACK } = require('./constants');
const { RETENTION } = require('./retention');
const { getAdvancedLayersSnapshotForPeriod } = require('./protectionStatus');

/**
 * @param {import('@prisma/client').PrismaClient} prisma
 * @param {string} tenantId
 * @param {number} month  — 1-12
 * @param {number} year   — مثل 2025
 * @returns {Promise<object>} — كل بيانات التقرير
 */
async function buildMonthlyReportData(prisma, tenantId, month, year, storeId = null) {

  // ── حدود الشهر ─────────────────────────────────────────────────────────
  const monthStart = new Date(Date.UTC(year, month - 1, 1));
  const monthEnd   = new Date(Date.UTC(year, month,     0, 23, 59, 59, 999));

  // ── حدود الشهر السابق (للمقارنة) ────────────────────────────────────────
  const prevMonth      = month === 1 ? 12 : month - 1;
  const prevYear       = month === 1 ? year - 1 : year;
  const prevMonthStart = new Date(Date.UTC(prevYear, prevMonth - 1, 1));
  const prevMonthEnd   = new Date(Date.UTC(prevYear, prevMonth,     0, 23, 59, 59, 999));

  // Additive per-store scope. storeId = null (default) is a no-op —
  // output identical to current behavior for every existing caller.
  const storeScope = storeId ? { storeId } : {};

  // ── جلب كل البيانات بالتوازي ────────────────────────────────────────────
  const [
    tenant,
    blockedAttempts,
    prevMonthAlerts,
    topBins,
    biggestBINAttack,
    historicalAggregate,
    totalTenants,
  ] = await Promise.all([

    // بيانات التاجر الأساسية
    prisma.tenant.findUnique({
      where:  { id: tenantId },
      select: { email: true, storeUrl: true, plan: true, createdAt: true },
    }),

    // كل المحاولات المحظورة في الشهر (للإحصائيات)
    prisma.blockedAttempt.findMany({
      where: {
        tenantId,
        ...storeScope,
        blockedAt: { gte: monthStart, lte: monthEnd },
      },
      select: {
        reason:          true,
        cardBin:         true,
        cardType:        true,
        amountAttempted: true,
        blockedAt:       true,
      },
    }),

    // إحصائيات الشهر السابق من AlertLog الأسبوعية
    prisma.alertLog.aggregate({
      where: {
        tenantId,
        ...storeScope,
        alertType: 'weekly_summary',
        sentAt:    { gte: prevMonthStart, lte: prevMonthEnd },
      },
      _sum: { attackCount: true },
    }),

    // أعلى BINs تكراراً للحصول على بلد المصدر
    prisma.blockedAttempt.groupBy({
      by:    ['cardBin'],
      where: {
        tenantId,
        ...storeScope,
        blockedAt: { gte: monthStart, lte: monthEnd },
        cardBin:   { not: null },
      },
      _count:  { cardBin: true },
      orderBy: { _count: { cardBin: 'desc' } },
      take:    10,
    }),

    // أكبر هجوم BIN Sequence في الشهر
    prisma.binSequenceAlert.findFirst({
      where: {
        tenantId,
        ...storeScope,
        detectedAt: { gte: monthStart, lte: monthEnd },
      },
      orderBy: { cardsCount: 'desc' },
      select: {
        binPrefix:    true,
        layer:        true,
        cardsCount:   true,
        riskAddition: true,
        detectedAt:   true,
      },
    }),

    // الإجمالي التاريخي منذ انضمام التاجر
    prisma.blockedAttempt.aggregate({
      where:  { tenantId, ...storeScope },
      _sum:   { amountAttempted: true },
      _count: { id: true },
    }),

    // عدد التجار النشطين (للـ Social Proof)
    prisma.tenant.count({ where: { isActive: true } }),
  ]);

  // ── حساب إحصائيات الشهر ────────────────────────────────────────────────
  const totalAttacks   = blockedAttempts.length;
  const totalProtected = blockedAttempts.reduce((sum, a) => sum + (a.amountAttempted || 0), 0);
  const totalFeesSaved = totalAttacks * SAVINGS_PER_ATTACK;

  // توزيع الأسباب
  const reasonCounts = {};
  for (const { reason } of blockedAttempts) {
    reasonCounts[reason] = (reasonCounts[reason] || 0) + 1;
  }
  const reasonBreakdown = Object.entries(reasonCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([reason, count]) => ({
      reason,
      count,
      pct: totalAttacks > 0 ? Math.round((count / totalAttacks) * 100) : 0,
    }));
  const topReason = reasonBreakdown[0]?.reason ?? null;

  // الرسم البياني الأسبوعي (4 أسابيع)
  const weeklyChart = _buildWeeklyChart(blockedAttempts, monthStart, monthEnd);

  // ── BIN → Country lookup (نفس منطق dashboard.js تماماً) ────────────────
  const topBinValues = topBins.map(b => b.cardBin).filter(Boolean);
  const binRecords   = topBinValues.length > 0
    ? await prisma.binRecord.findMany({
        where:  { bin: { in: topBinValues } },
        select: { bin: true, issuerCountry: true, brand: true },
      })
    : [];

  const binCountryMap = Object.fromEntries(binRecords.map(r => [r.bin, r]));
  const threatOrigins = topBins
    .map(b => ({
      bin:     b.cardBin,
      count:   b._count.cardBin,
      country: binCountryMap[b.cardBin]?.issuerCountry ?? null,
    }))
    .filter(o => o.country)
    .reduce((acc, o) => {
      const ex = acc.find(a => a.country === o.country);
      if (ex) ex.count += o.count;
      else acc.push({ country: o.country, count: o.count });
      return acc;
    }, [])
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const topCountry = threatOrigins[0]?.country ?? null;

  // ── Protection Layers (replaces the old fake "security score") ─────────
  // coreLayersActive: the four always-on detector groups — Blacklist/Email
  // hard-block, Velocity+Device Rotation, BIN Sequence, Identity Graph —
  // which run for every active tenant regardless of plan or quota (traced
  // through risk.js's /evaluate handler). Constant within this report's
  // scope; not a live per-tenant check.
  // advancedLayersAvailable: external intelligence (IP/Email/BIN) — gated
  // by monthly quota only, not plan. See getAdvancedLayersSnapshot()'s doc
  // comment in protectionStatus.js for why this is a snapshot, and the
  // plan to make it historically accurate later.
  const CORE_LAYERS_TOTAL = 4;
  const coreLayersActive        = CORE_LAYERS_TOTAL;
  // Period-based, not live-snapshot — see getAdvancedLayersSnapshotForPeriod()'s
  // doc comment in protectionStatus.js for why this must read totalAttacks
  // (this period's historical BlockedAttempt count) rather than the tenant's
  // live monthlyBlockedCount counter.
  const advancedLayersAvailable = getAdvancedLayersSnapshotForPeriod(tenant.plan, totalAttacks);

  // ── بيانات المقارنة الشهرية ──────────────────────────────────────────────
  const prevMonthAttacks = prevMonthAlerts._sum.attackCount ?? null;

  // ── الإجماليات التاريخية ─────────────────────────────────────────────────
  const historicalProtected = historicalAggregate._sum.amountAttempted ?? 0;
  const historicalAttacks   = historicalAggregate._count.id ?? 0;

  // ── اسم الشهر للعرض ──────────────────────────────────────────────────────
  const monthName = new Intl.DateTimeFormat('en-US', {
    month: 'long', timeZone: 'UTC',
  }).format(monthStart);

  return {
    // metadata
    tenant,
    month,
    year,
    monthName,
    monthStart,
    monthEnd,
    storeId: storeId ?? null,

    // إحصائيات الشهر
    totalAttacks,
    totalProtected,
    totalFeesSaved,
    coreLayersActive,
    advancedLayersAvailable,
    topReason,
    topCountry,
    reasonBreakdown,
    threatOrigins,
    weeklyChart,

    // المقارنة الشهرية
    prevMonthAttacks,
    monthOverMonthPct: prevMonthAttacks
      ? Math.round(((totalAttacks - prevMonthAttacks) / prevMonthAttacks) * 100)
      : null,

    // الإجماليات التاريخية
    historicalProtected,
    historicalAttacks,

    // البيانات الإضافية
    biggestBINAttack,
    totalTenants,

    // إعدادات RETENTION للـ Compliance Pack
    retentionSettings: {
      blockedAttemptDays:   RETENTION.BLOCKED_ATTEMPT_DAYS,
      orderDays:            RETENTION.ORDER_DAYS,
      identityNodeDays:     RETENTION.IDENTITY_NODE_DAYS,
      cardHashDays:         RETENTION.CARD_HASH_DAYS,
    },
  };
}

// ── دوال مساعدة داخلية ─────────────────────────────────────────────────────

function _buildWeeklyChart(attempts, monthStart, monthEnd) {
  // قسّم الشهر إلى 4 أسابيع وعدّ الهجمات في كل أسبوع
  const weeks = [0, 0, 0, 0];
  for (const { blockedAt } of attempts) {
    const dayOfMonth = new Date(blockedAt).getUTCDate();
    const weekIndex  = Math.min(Math.floor((dayOfMonth - 1) / 7), 3);
    weeks[weekIndex]++;
  }
  return weeks.map((count, i) => ({ week: `Week ${i + 1}`, count }));
}



module.exports = { buildMonthlyReportData };