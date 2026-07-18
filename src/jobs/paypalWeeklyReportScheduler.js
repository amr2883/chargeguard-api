'use strict';

/**
 * PayPal Weekly Shield Report Scheduler
 * --------------------------------------
 * Runs every hour. On Sunday between 09:30–09:59 UTC:
 *   For each active Tenant:
 *     1. Skip if paypal_weekly_shield already sent this week (anti-duplication)
 *     2. Fetch this week's PayPal orders (source = 'paypal' in signalsSnapshot)
 *     3. Count blocked vs flagged vs total PayPal transactions
 *     4. Fetch last week's count (week-over-week)
 *     5. Write AlertLog record (always)
 *     6. Send email:
 *        - 0 PayPal txns at all → skip (tenant isn't using PayPal)
 *        - 0 suspicious → send "clean week" email
 *        - >0 suspicious → send full PayPal Shield report
 *
 * Runs at 09:30 UTC (30 minutes after weeklySummaryScheduler at 09:00)
 * to avoid SMTP hammering both schedulers simultaneously.
 *
 * Follows exact same patterns as weeklySummaryScheduler.js.
 */

const { sendPaypalWeeklyReportEmail } = require('../lib/email');
const { acquireLock }                 = require('../lib/distributedLock');
const { SAVINGS_PER_ATTACK }          = require('../lib/constants');

// ── Tuneable constants ──────────────────────────────────────────────────────
const SCHEDULER_INTERVAL_MS = 60 * 60 * 1000;   // check every hour
const STARTUP_DELAY_MS      = 90 * 60 * 1000;   // first run: 90 min after boot
const SEND_DAY_UTC          = 0;                 // Sunday
const SEND_HOUR_UTC         = 9;                 // 09:xx UTC
const SEND_MINUTE_MIN       = 30;                // only fire if minute >= 30
const TENANT_DELAY_MS       = 4000;              // 4s between tenants
// ───────────────────────────────────────────────────────────────────────────

// ── Week boundary helpers (same as weeklySummaryScheduler) ─────────────────

function getCurrentWeekStart(now) {
  const d = new Date(now);
  d.setUTCHours(0, 0, 0, 0);
  d.setUTCDate(d.getUTCDate() - d.getUTCDay());
  return d;
}

function getPrevWeekStart(currentWeekStart) {
  return new Date(currentWeekStart.getTime() - 7 * 24 * 60 * 60 * 1000);
}

// ── Core scheduler logic ────────────────────────────────────────────────────

async function runPaypalWeeklyReportCheck(prisma) {
  const now   = new Date();
  const label = `[PaypalWeekly ${now.toISOString()}]`;

  // Gate: Sunday 09:30–09:59 UTC only
  if (
    now.getUTCDay()     !== SEND_DAY_UTC  ||
    now.getUTCHours()   !== SEND_HOUR_UTC ||
    now.getUTCMinutes() <  SEND_MINUTE_MIN
  ) {
    return;
  }

  const lock = await acquireLock('scheduler:paypalWeekly', 120_000);
  if (!lock) {
    console.log(`${label} 🔒 lock not acquired, skipping this tick`);
    return;
  }

  console.log(`${label} 📅 Sunday 09:3x UTC — running PayPal weekly shield check`);

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
      await processPaypalTenant(prisma, tenant, currentWeekStart, prevWeekStart, label);
    } catch (err) {
      console.error(`${label} ❌ Unhandled error for tenant ${tenant.id}:`, err.message);
    }

    if (tenants.indexOf(tenant) < tenants.length - 1) {
      await new Promise(res => setTimeout(res, TENANT_DELAY_MS));
    }
  }

  console.log(`${label} ✅ PayPal weekly shield check complete`);
}

// ── Per-tenant processing ───────────────────────────────────────────────────

async function processPaypalTenant(prisma, tenant, currentWeekStart, prevWeekStart, label) {

  // ── Step 1: Anti-duplication ──────────────────────────────────────────────
  const alreadySent = await prisma.alertLog.findFirst({
    where: {
      tenantId:  tenant.id,
      alertType: 'paypal_weekly_shield',
      sentAt:    { gte: currentWeekStart },
    },
    select: { id: true },
  });

  if (alreadySent) {
    console.log(`${label} ⏭️  ${tenant.email} — paypal_weekly_shield already sent this week, skipping`);
    return;
  }

  // ── Step 2: Fetch this week's PayPal orders — filtered in the DB ──────────
  // L3 perf fix: enrichmentSource is now an indexed column (see schema.prisma
  // + routes/risk.js /enrich), so Postgres does the PayPal filtering via the
  // @@index([merchantId, enrichmentSource, createdAt]) index instead of this
  // job loading every order for the tenant and JSON.parse()-ing signalsSnapshot
  // per row. signalsSnapshot is still selected because Step 5 below still
  // needs to read country data out of it — only the *filtering* moved to SQL.
  const paypalOrders = await prisma.order.findMany({
    where: {
      merchantId:       tenant.id,   // tenant.id === merchantId in this schema
      createdAt:        { gte: currentWeekStart },
      enrichmentSource: 'paypal',
    },
    select: {
      decision:        true,
      signalsSnapshot: true,
    },
  });

  const paypalTxnCount     = paypalOrders.length;
  const paypalBlockedCount = paypalOrders.filter(o => o.decision === 'block').length;
  const paypalFlaggedCount = paypalOrders.filter(o => o.decision === 'review').length;

  // ── Step 3: Skip if tenant has zero PayPal transactions at all ────────────
  // Don't send the report to stores that aren't using PayPal integration yet
  if (paypalTxnCount === 0) {
    console.log(`${label} ⏭️  ${tenant.email} — no PayPal transactions this week, skipping`);
    return;
  }

  // ── Step 4: Last week's suspicious count (week-over-week) ─────────────────
  // L3 perf fix: was findMany + JS filter + .length; now a single indexed
  // COUNT query — no rows materialized in Node memory at all for this step.
  const prevPaypalSuspicious = await prisma.order.count({
    where: {
      merchantId:       tenant.id,
      createdAt:        { gte: prevWeekStart, lt: currentWeekStart },
      enrichmentSource: 'paypal',
      decision:         { in: ['block', 'review'] },
    },
  });

  const thisWeekSuspicious = paypalBlockedCount + paypalFlaggedCount;

  const weekOverWeekPct = prevPaypalSuspicious === 0
    ? null
    : Math.round(((thisWeekSuspicious - prevPaypalSuspicious) / prevPaypalSuspicious) * 100);

  // ── Step 5: Top card country this week ────────────────────────────────────
  const countryCounts = {};
  for (const o of paypalOrders) {
    if (o.decision !== 'block' && o.decision !== 'review') continue;
    try {
      const snap = JSON.parse(o.signalsSnapshot || '{}');
      const country = snap.cardIssuerCountry || snap.cardCountry || null;
      if (country) countryCounts[country] = (countryCounts[country] || 0) + 1;
    } catch {}
  }
  const topCardCountry = Object.keys(countryCounts).length > 0
    ? Object.entries(countryCounts).sort((a, b) => b[1] - a[1])[0][0]
    : null;

  // ── Step 6: Estimated savings ─────────────────────────────────────────────
  const savedAmount = thisWeekSuspicious * SAVINGS_PER_ATTACK;

  // ── Step 7: Historical PayPal total (from AlertLog) ───────────────────────
  const historicalAgg = await prisma.alertLog.aggregate({
    where: {
      tenantId:  tenant.id,
      alertType: 'paypal_weekly_shield',
    },
    _sum: { attackCount: true },
  });

  const historicalPaypalTotal = {
    count: (historicalAgg._sum.attackCount || 0) + thisWeekSuspicious,
  };

  // ── Step 8: Write AlertLog BEFORE sending ─────────────────────────────────
  await prisma.alertLog.create({
    data: {
      tenantId:    tenant.id,
      alertType:   'paypal_weekly_shield',
      attackCount: thisWeekSuspicious,
      savedAmount,
    },
  });

  // ── Step 9: Send email ────────────────────────────────────────────────────
  sendPaypalWeeklyReportEmail({
    tenant,
    weekStart:            currentWeekStart,
    paypalTxnCount,
    paypalBlockedCount,
    paypalFlaggedCount,
    savedAmount,
    topCardCountry,
    weekOverWeekPct,
    historicalPaypalTotal,
  })
    .then(() => {
      const kind = thisWeekSuspicious > 0 ? 'full' : 'quiet';
      console.log(`${label} 📬 PayPal ${kind} shield report sent → ${tenant.email} (${thisWeekSuspicious} suspicious)`);
    })
    .catch(err => {
      console.error(`${label} ❌ Email failed for ${tenant.email}:`, err.message);
    });
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Registers the PayPal weekly shield scheduler.
 * Call once from app.js, pass the long-lived PrismaClient.
 *
 * @param {import('@prisma/client').PrismaClient} prisma
 */
function startPaypalWeeklyReportScheduler(prisma) {
  setTimeout(() => {
    console.log(`[${new Date().toISOString()}] 🛡️  PayPal Weekly Shield Scheduler started (checks every hour, sends Sundays 09:30 UTC)`);

    runPaypalWeeklyReportCheck(prisma);
    setInterval(() => runPaypalWeeklyReportCheck(prisma), SCHEDULER_INTERVAL_MS);

  }, STARTUP_DELAY_MS);
}

module.exports = { startPaypalWeeklyReportScheduler };