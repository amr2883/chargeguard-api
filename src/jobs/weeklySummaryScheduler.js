'use strict';

/**
 * Weekly Summary Scheduler
 * ------------------------
 * Runs every hour. On Sunday between 09:00–09:59 UTC:
 *   For each active Tenant:
 *     1. Skip if weekly_summary already sent this week (anti-duplication)
 *     2. Fetch this week's BlockedAttempts (with reason breakdown)
 *     3. Fetch last week's count (for week-over-week comparison)
 *     4. Write AlertLog record (always — even for quiet weeks)
 *     5. Decide whether to send email:
 *        - 0 attacks AND last 3 weeks all quiet → no email sent
 *        - 0 attacks AND first quiet week → send "quiet" email
 *        - >0 attacks → send full weekly summary email
 *
 * Uses same patterns as attackAlertScheduler.js:
 *   - Receives prisma from app.js (no internal client creation)
 *   - Sequential tenant processing with per-tenant error isolation
 *   - AlertLog written BEFORE email send to prevent duplicates
 */

const db                          = require('../lib/db');
const { sendWeeklySummaryEmail }   = require('../lib/email');

// ── Tuneable constants ──────────────────────────────────────────────────────
const SCHEDULER_INTERVAL_MS  = 60 * 60 * 1000;  // check every hour
const STARTUP_DELAY_MS       = 60 * 60 * 1000;  // first run: 1 hour after boot
const SEND_DAY_UTC           = 0;                // 0 = Sunday
const SEND_HOUR_UTC          = 9;                // 09:00–09:59 UTC
const TENANT_DELAY_MS        = 3000;             // 3s between tenants (SMTP courtesy)
const SAVINGS_PER_ATTACK     = 0.30;             // must stay in sync with attackAlertScheduler.js
const QUIET_STREAK_THRESHOLD = 3;               // skip send after this many consecutive quiet weeks
// ───────────────────────────────────────────────────────────────────────────

// ── Week boundary helpers ───────────────────────────────────────────────────

/**
 * Returns the most recent Sunday at 00:00:00.000 UTC (i.e. start of current week).
 * @param {Date} now
 * @returns {Date}
 */
function getCurrentWeekStart(now) {
  const d = new Date(now);
  d.setUTCHours(0, 0, 0, 0);
  d.setUTCDate(d.getUTCDate() - d.getUTCDay()); // rewind to Sunday
  return d;
}

/**
 * @param {Date} currentWeekStart
 * @returns {Date}
 */
function getPrevWeekStart(currentWeekStart) {
  return new Date(currentWeekStart.getTime() - 7 * 24 * 60 * 60 * 1000);
}

// ── Core scheduler logic ────────────────────────────────────────────────────

/**
 * @param {import('@prisma/client').PrismaClient} prisma
 */
async function runWeeklySummaryCheck(prisma) {
  const now   = new Date();
  const label = `[WeeklySummary ${now.toISOString()}]`;

  // Gate 1: only run on the correct day and hour
  if (now.getUTCDay() !== SEND_DAY_UTC || now.getUTCHours() !== SEND_HOUR_UTC) {
    return;
  }

  console.log(`${label} 📅 Sunday 09:xx UTC — running weekly summary check`);

  // Compute week boundaries (stable for the entire run)
  const currentWeekStart = getCurrentWeekStart(now);
  const prevWeekStart    = getPrevWeekStart(currentWeekStart);

  let tenants;
  try {
    tenants = await prisma.tenant.findMany({
      where:  { isActive: true },
      select: { id: true, email: true, storeUrl: true },
    });
  } catch (err) {
    console.error(`${label} ❌ Failed to fetch tenants:`, err.message);
    return;
  }

  if (!tenants.length) {
    console.log(`${label} ℹ️  No active tenants found.`);
    return;
  }

  console.log(`${label} 👥 Processing ${tenants.length} tenant(s)`);

  for (const tenant of tenants) {
    try {
      await processTenant(prisma, tenant, currentWeekStart, prevWeekStart, label);
    } catch (err) {
      // One tenant failing must never abort the loop for others
      console.error(`${label} ❌ Unhandled error for tenant ${tenant.id}:`, err.message);
    }

    // Courtesy delay to avoid hammering SMTP between tenants
    if (tenants.indexOf(tenant) < tenants.length - 1) {
      await new Promise(res => setTimeout(res, TENANT_DELAY_MS));
    }
  }

  console.log(`${label} ✅ Weekly summary check complete`);
}

/**
 * Processes one tenant: checks duplication, fetches data, writes log, sends email.
 *
 * @param {import('@prisma/client').PrismaClient} prisma
 * @param {{ id: string, email: string, storeUrl: string|null }} tenant
 * @param {Date} currentWeekStart
 * @param {Date} prevWeekStart
 * @param {string} label
 */
async function processTenant(prisma, tenant, currentWeekStart, prevWeekStart, label) {

  // ── Step 1: Anti-duplication ──────────────────────────────────────────────
  const alreadySent = await prisma.alertLog.findFirst({
    where: {
      tenantId:  tenant.id,
      alertType: 'weekly_summary',
      sentAt:    { gte: currentWeekStart },
    },
    select: { id: true },
  });

  if (alreadySent) {
    console.log(`${label} ⏭️  ${tenant.email} — weekly_summary already sent this week, skipping`);
    return;
  }

  // ── Step 2: Fetch this week's BlockedAttempts (full rows for reason breakdown) ──
  const thisWeekAttempts = await prisma.blockedAttempt.findMany({
    where: {
      tenantId:  tenant.id,
      blockedAt: { gte: currentWeekStart },
    },
    select: { reason: true },
  });

  const thisWeekCount = thisWeekAttempts.length;

  // ── Step 3: Fetch last week's count (scalar only — no reason needed) ──────
  const prevWeekCount = await prisma.blockedAttempt.count({
    where: {
      tenantId:  tenant.id,
      blockedAt: { gte: prevWeekStart, lt: currentWeekStart },
    },
  });

  // ── Step 4: Compute derived metrics ──────────────────────────────────────
  const savedAmount = thisWeekCount * SAVINGS_PER_ATTACK;

  // Reason breakdown (for full email)
  const reasonCounts = {};
  for (const { reason } of thisWeekAttempts) {
    reasonCounts[reason] = (reasonCounts[reason] || 0) + 1;
  }

  // topReason: the reason string with the highest count
  const topReason = thisWeekCount > 0
    ? Object.entries(reasonCounts).sort((a, b) => b[1] - a[1])[0][0]
    : null;

  // reasonBreakdown: array sorted descending, with percentage
  const reasonBreakdown = Object.entries(reasonCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([reason, count]) => ({
      reason,
      count,
      pct: Math.round((count / thisWeekCount) * 100),
    }));

  // Week-over-week delta
  const weekOverWeekPct = prevWeekCount === 0
    ? null  // avoid divide-by-zero; render as "first active week"
    : Math.round(((thisWeekCount - prevWeekCount) / prevWeekCount) * 100);

  // ── Step 5: Check quiet streak (only matters if thisWeekCount === 0) ─────
  let quietStreak = 0;
  if (thisWeekCount === 0) {
    const recentWeeklies = await prisma.alertLog.findMany({
      where: {
        tenantId:  tenant.id,
        alertType: 'weekly_summary',
      },
      orderBy: { sentAt: 'desc' },
      take:    QUIET_STREAK_THRESHOLD,
      select:  { attackCount: true },
    });

    quietStreak = recentWeeklies.filter(r => r.attackCount === 0).length;
  }

  const shouldSendEmail = thisWeekCount > 0 || quietStreak < QUIET_STREAK_THRESHOLD;

  // ── Step 6: Fetch historical totals (for quiet email only) ───────────────
  let historicalTotal = null;
  if (thisWeekCount === 0 && shouldSendEmail) {
    const historical = await prisma.alertLog.aggregate({
      where: {
        tenantId:  tenant.id,
        alertType: 'weekly_summary',
      },
      _sum: {
        attackCount: true,
        savedAmount: true,
      },
    });
    historicalTotal = {
      attacks: (historical._sum.attackCount || 0) + thisWeekCount,
      saved:   (historical._sum.savedAmount  || 0) + savedAmount,
    };
  }

  // ── Step 7: Write AlertLog BEFORE sending (prevents duplicate on crash) ──
  await prisma.alertLog.create({
    data: {
      tenantId:    tenant.id,
      alertType:   'weekly_summary',
      attackCount: thisWeekCount,
      savedAmount,
    },
  });

  // ── Step 8: Send email (or skip) ─────────────────────────────────────────
  if (!shouldSendEmail) {
    console.log(`${label} 🤫 ${tenant.email} — ${QUIET_STREAK_THRESHOLD} consecutive quiet weeks, skipping email`);
    return;
  }

  const emailPayload = {
    tenant,
    thisWeekCount,
    savedAmount,
    prevWeekCount,
    weekOverWeekPct,
    topReason,
    reasonBreakdown,
    weekStart: currentWeekStart,
    historicalTotal, // null for active weeks
  };

  // Fire-and-forget — a failed email never throws to the outer loop
  sendWeeklySummaryEmail(emailPayload)
    .then(() => {
      const kind = thisWeekCount > 0 ? 'full' : 'quiet';
      console.log(`${label} 📬 ${kind} summary sent → ${tenant.email} (${thisWeekCount} attacks)`);
    })
    .catch(err => {
      console.error(`${label} ❌ Email failed for ${tenant.email}:`, err.message);
    });
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Registers the weekly summary scheduler.
 * Call once from app.js/server.js, pass the long-lived PrismaClient.
 *
 * @param {import('@prisma/client').PrismaClient} prisma
 */
function startWeeklySummaryScheduler(prisma) {
  setTimeout(() => {
    console.log(`[${new Date().toISOString()}] 📅 Weekly Summary Scheduler started (checks every hour, sends Sundays 09:xx UTC)`);

    runWeeklySummaryCheck(prisma);
    setInterval(() => runWeeklySummaryCheck(prisma), SCHEDULER_INTERVAL_MS);

  }, STARTUP_DELAY_MS);
}

module.exports = { startWeeklySummaryScheduler };