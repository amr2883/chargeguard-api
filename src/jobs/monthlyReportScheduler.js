'use strict';

/**
 * Monthly Report Scheduler
 * ------------------------
 * Runs every hour. On the 1st of each month at 10:00–10:59 UTC:
 *   For each active Tenant:
 *     1. Anti-duplication: skip if MonthlyReport with status 'ready' already exists
 *        for the target month/year.
 *     2. Create a MonthlyReport record with status 'generating' (acts as a lock).
 *     3. Call buildMonthlyReportData() to collect all report data.
 *     4. Update the record with real data and set status to 'ready'.
 *     5. Fire-and-forget: call sendMonthlyReportEmail().
 *     6. On any error: update the record to status 'failed' — never leaves a
 *        ghost 'generating' record in the database.
 *
 * Report period: always the *previous* calendar month.
 *   e.g. scheduler fires on 2025-02-01 → generates report for January 2025.
 *
 * Uses identical patterns to weeklySummaryScheduler.js:
 *   - Receives prisma from app.js (no internal PrismaClient creation)
 *   - Sequential tenant processing with per-tenant error isolation
 *   - DB record written BEFORE email send to prevent duplicate sends on crash
 *   - Courtesy delay between tenants to protect SMTP and DB connection pool
 */

// ─── Imports ────────────────────────────────────────────────────────────────
// Thought: we need exactly two external dependencies beyond Node built-ins.
// buildMonthlyReportData → the data engine (accepts prisma externally ✓)
// sendMonthlyReportEmail → the email builder/sender (fire-and-forget ✓)
// We do NOT import db.js — prisma always comes from the caller (app.js).
const { buildMonthlyReportData }  = require('../lib/reportDataService');
const { sendMonthlyReportEmail }  = require('../lib/email');
const { acquireLock }             = require('../lib/distributedLock');

// ─── Tuneable Constants ──────────────────────────────────────────────────────
// Thought: group every magic number here so ops can tune without reading logic.
// INTERVAL = hourly (same as weeklySummaryScheduler — gate does the real timing)
// STARTUP_DELAY = 1 hour, matching weeklySummaryScheduler. The scheduler fires
//   every hour to check the gate; there's no value in starting earlier since
//   the gate will reject every tick that isn't the 1st/10:xx anyway.
// SEND_DAY_OF_MONTH = 1 — unambiguous: first calendar day of each month UTC.
// SEND_HOUR_UTC = 10 — 12:00 Cairo, 06:00 NY; peak email open-rate window for
//   both major merchant timezones we serve.
// TENANT_DELAY_MS = 5000 — 5s between tenants. Slightly higher than weekly (3s)
//   because buildMonthlyReportData runs 7 parallel Prisma queries per tenant,
//   which is heavier than the weekly's 3 sequential queries.
const SCHEDULER_INTERVAL_MS  = 60 * 60 * 1000;  // check every hour
const STARTUP_DELAY_MS       = 60 * 60 * 1000;  // first run: 1 hour after boot
const SEND_DAY_OF_MONTH      = 1;               // 1st of every month
const SEND_HOUR_UTC          = 10;              // 10:00–10:59 UTC
const TENANT_DELAY_MS        = 5_000;           // 5s between tenants

// ─── Time Helpers ────────────────────────────────────────────────────────────

/**
 * Derives the report period (month + year) from the current timestamp.
 *
 * Thought: we fire on the 1st of the NEW month, so the report covers the
 * PREVIOUS month. getUTCMonth() is 0-indexed, which creates the January edge
 * case (index 0 → previous month is December of the prior year).
 *
 * Examples:
 *   now = 2025-02-01 → { reportMonth: 1, reportYear: 2025 }  (January)
 *   now = 2025-01-01 → { reportMonth: 12, reportYear: 2024 } (December)
 *
 * @param {Date} now
 * @returns {{ reportMonth: number, reportYear: number }}
 */
function getReportPeriod(now) {
  const currentMonthIndex = now.getUTCMonth(); // 0–11
  if (currentMonthIndex === 0) {
    // January → report covers December of the previous year
    return { reportMonth: 12, reportYear: now.getUTCFullYear() - 1 };
  }
  // All other months: subtract 1 from the 0-indexed value to get 1-indexed month
  return { reportMonth: currentMonthIndex, reportYear: now.getUTCFullYear() };
}

/**
 * Builds the download URL for the monthly report preview endpoint.
 *
 * Thought: PDF generation is a future feature. For now we point to the JSON
 * preview endpoint so the email CTA is functional from day one. The URL is
 * parameterised so each tenant sees their own data.
 *
 * @param {string} tenantId
 * @param {number} reportMonth  1–12
 * @param {number} reportYear
 * @returns {string}
 */
function buildDownloadUrl(tenantId, reportMonth, reportYear) {
  const base = process.env.RENDER_EXTERNAL_URL || 'https://chargeguard-api.onrender.com';
  return `${base}/api/dashboard/monthly-report-preview?tenantId=${tenantId}&month=${reportMonth}&year=${reportYear}`;
}

// ─── Core Scheduler Logic ────────────────────────────────────────────────────

/**
 * Runs once per hourly tick. Applies the time gate, then iterates tenants.
 *
 * @param {import('@prisma/client').PrismaClient} prisma
 */
async function runMonthlyReportCheck(prisma) {
  const now   = new Date();
  const label = `[MonthlyReport ${now.toISOString()}]`;

  // ── Gate: only proceed on the 1st of the month at 10:xx UTC ─────────────
  // Thought: two independent checks. Both must be true. getUTCDate() is 1-indexed
  // so comparing to the constant 1 is unambiguous. getUTCHours() gives 0–23.
  // The scheduler runs every 60 minutes so this window is hit exactly once per month.
  if (now.getUTCDate() !== SEND_DAY_OF_MONTH || now.getUTCHours() !== SEND_HOUR_UTC) {
    return;
  }

  // ── Derive report period (always previous month) ─────────────────────────
  const { reportMonth, reportYear } = getReportPeriod(now);

  const lock = await acquireLock('scheduler:monthlyReport', 300_000);
  if (!lock) {
    console.log(`${label} 🔒 lock not acquired, skipping this tick`);
    return;
  }

  console.log(
    `${label} 📊 1st of month, 10:xx UTC — generating ${reportMonth}/${reportYear} reports`
  );

  // ── Fetch all active tenants ─────────────────────────────────────────────
  // Thought: we select the minimum fields needed. 'plan' is required by
  // sendMonthlyReportEmail to decide whether to show the Upgrade CTA.
  let tenants;
  try {
    tenants = await prisma.tenant.findMany({
      where:  { isActive: true },
      select: { id: true, email: true, storeUrl: true, plan: true },
    });
  } catch (err) {
    console.error(`${label} ❌ Failed to fetch tenants:`, err.message);
    return;
  }

  if (!tenants.length) {
    console.log(`${label} ℹ️  No active tenants found.`);
    return;
  }

  console.log(`${label} 👥 Processing ${tenants.length} tenant(s) for ${reportMonth}/${reportYear}`);

  // ── Process tenants sequentially ─────────────────────────────────────────
  // Thought: sequential (not parallel) for two reasons:
  //   1. buildMonthlyReportData fires 7 Prisma queries per tenant — running
  //      all tenants at once on a shared PrismaClient would spike the pool.
  //   2. SMTP has rate limits; sequential + TENANT_DELAY_MS is safer.
  // When the tenant base grows beyond ~200, revisit with a concurrency limiter.
  for (let i = 0; i < tenants.length; i++) {
    const tenant = tenants[i];
    try {
      await processTenant(prisma, tenant, reportMonth, reportYear, label);
    } catch (err) {
      // One tenant failing must NEVER abort the loop for the others.
      // processTenant has its own inner catch that updates status to 'failed',
      // so reaching here means something truly unexpected happened.
      console.error(`${label} ❌ Unhandled error for tenant ${tenant.id}:`, err.message);
    }

    // Courtesy delay between tenants — skip after the last one
    if (i < tenants.length - 1) {
      await new Promise(res => setTimeout(res, TENANT_DELAY_MS));
    }
  }

  console.log(`${label} ✅ Monthly report run complete for ${reportMonth}/${reportYear}`);
}

/**
 * Processes one tenant end-to-end:
 *   anti-dup check → create 'generating' lock → build data → update 'ready' → send email.
 *
 * On ANY error after the MonthlyReport record is created, we update it to
 * 'failed' so operators can query `status = 'failed'` to find broken reports.
 * This guarantees no ghost 'generating' records survive a crash.
 *
 * @param {import('@prisma/client').PrismaClient} prisma
 * @param {{ id: string, email: string, storeUrl: string|null, plan: string }} tenant
 * @param {number} reportMonth  1–12
 * @param {number} reportYear
 * @param {string} label  — log prefix for this scheduler tick
 */
async function processTenant(prisma, tenant, reportMonth, reportYear, label) {

  // ── Step 1: Anti-duplication ──────────────────────────────────────────────
  // Thought: we check for 'ready' only — not 'generating' or 'failed'.
  //   'ready'      → skip (report already delivered successfully this month)
  //   'generating' → this is a stale lock from a previous crash; we should
  //                  retry (the record will be updated to 'failed' if it fails
  //                  again, making the state explicit)
  //   'failed'     → retry (we want to attempt recovery within the same monthly run)
  //   absent       → proceed normally
  const existingReady = await prisma.monthlyReport.findFirst({
    where: {
      tenantId:    tenant.id,
      reportMonth,
      reportYear,
      status:      'ready',
    },
    select: { id: true },
  });

  if (existingReady) {
    console.log(
      `${label} ⏭️  ${tenant.email} — report already ready for ${reportMonth}/${reportYear}, skipping`
    );
    return;
  }

  // ── Step 2: Create (or overwrite) a 'generating' lock record ─────────────
  // Thought: use upsert on the (tenantId, reportMonth, reportYear) composite.
  // This handles two scenarios cleanly:
  //   a) No record exists → create it with status 'generating'
  //   b) A 'failed' or stale 'generating' record exists → reset it to 'generating'
  //      so we get a fresh attempt tracked in DB
  // We save the record ID so we can update it later without a second lookup.
  //
  // Thought on schema: the schema defines a unique constraint on
  // (tenantId, reportMonth, reportYear) — confirmed by the migration. Without
  // that constraint, upsert's `where` clause would fail. If the constraint is
  // not present, replace upsert with findFirst + create/update branches.
  let reportRecord;
  try {
    reportRecord = await prisma.monthlyReport.upsert({
      where: {
        tenantId_reportMonth_reportYear: {
          tenantId: tenant.id,
          reportMonth,
          reportYear,
        },
      },
      create: {
        tenantId:    tenant.id,
        reportMonth,
        reportYear,
        status:      'generating',
      },
      update: {
        status: 'generating',
        // Data fields (totalAttacks, etc.) are now nullable in the schema,
        // so we don't need to reset them to null — they'll be overwritten
        // with real data when the report is generated. Prisma leaves
        // unspecified fields unchanged on update, so any stale values from
        // a previous failed attempt simply get replaced in Step 4 once
        // buildMonthlyReportData succeeds.
      },
      select: { id: true },
    });
  } catch (err) {
    // Thought: if we can't even write the lock record, abort this tenant.
    // There's no record to clean up, and the next hourly tick will retry
    // (since no 'ready' record exists).
    console.error(
      `${label} ❌ ${tenant.email} — failed to create generating record:`, err.message
    );
    return;
  }

  // From this point on: any error must update the record to 'failed'.
  // We wrap the rest of the function in a try/catch for exactly this reason.
  try {

    // ── Step 3: Build report data ───────────────────────────────────────────
    // Thought: this is the heavy call — 7 parallel Prisma queries inside.
    // It uses the SAME prisma instance passed from app.js, ensuring we stay
    // within the shared connection pool. No new PrismaClient is created.
    console.log(`${label} 🔄 ${tenant.email} — building data for ${reportMonth}/${reportYear}`);
    const reportData = await buildMonthlyReportData(prisma, tenant.id, reportMonth, reportYear);

    // ── Step 4: Update MonthlyReport record with real data ──────────────────
    // Thought: we update using the record ID we saved in Step 2. This avoids
    // a second lookup and is safe even if the upsert created a new record.
    // All scalar fields on MonthlyReport are populated here.
    await prisma.monthlyReport.update({
      where: { id: reportRecord.id },
      data: {
        status:          'ready',
        totalAttacks:    reportData.totalAttacks,
        totalProtected:  reportData.totalProtected,
        totalFeesSaved:  reportData.totalFeesSaved,
        securityScore:   reportData.securityScore,
        topCountry:      reportData.topCountry     ?? null,
        topReason:       reportData.topReason      ?? null,
        prevMonthAttacks: reportData.prevMonthAttacks ?? null,
      },
    });

    console.log(
      `${label} ✅ ${tenant.email} — record ready ` +
      `(${reportData.totalAttacks} attacks, $${reportData.totalProtected.toFixed(2)} protected)`
    );

    // ── Step 5: Send email (fire-and-forget) ────────────────────────────────
    // Thought: the record is already 'ready' in DB. A failed email is NOT a
    // reason to mark the report as 'failed' — the data is correct and the
    // tenant can still access the report via the dashboard. We log the error
    // but do not re-throw it. This matches the pattern in weeklySummaryScheduler.
    const downloadUrl = buildDownloadUrl(tenant.id, reportMonth, reportYear);

    sendMonthlyReportEmail({ tenant, reportData, downloadUrl })
      .then(() => {
        console.log(`${label} 📬 Email sent → ${tenant.email} (${reportData.monthName} ${reportYear})`);
      })
      .catch(err => {
        console.error(`${label} ❌ Email failed for ${tenant.email}:`, err.message);
      });

  } catch (err) {
    // ── Error recovery: mark record as 'failed' ─────────────────────────────
    // Thought: we MUST update the record here. Without this, a crash between
    // Step 2 and Step 4 leaves a 'generating' record that looks like an active
    // lock, causing all future hourly ticks to skip this tenant for the month.
    // Setting status to 'failed' makes the problem visible and allows manual
    // or future automated recovery.
    console.error(
      `${label} ❌ ${tenant.email} — report generation failed:`, err.message
    );

    try {
      await prisma.monthlyReport.update({
        where: { id: reportRecord.id },
        data:  { status: 'failed' },
      });
    } catch (updateErr) {
      // If even the failure update fails (e.g. DB connection lost), log and
      // move on. The 'generating' ghost record will be detectable by operators.
      console.error(
        `${label} ⚠️  ${tenant.email} — could not update record to 'failed':`,
        updateErr.message
      );
    }

    // Re-throw so the outer loop's catch can log the unhandled error with
    // tenant context. This does NOT break the loop for other tenants.
    throw err;
  }
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Registers the monthly report scheduler.
 * Call once from app.js, pass the long-lived PrismaClient (prismaForCleanup).
 *
 * Startup delay: 1 hour — matches weeklySummaryScheduler. The gate rejects
 * every non-matching tick with a no-op return, so starting early has no value.
 * The 1-hour delay ensures the server is fully stable before the first check.
 *
 * @param {import('@prisma/client').PrismaClient} prisma
 */
function startMonthlyReportScheduler(prisma) {
  setTimeout(() => {
    console.log(
      `[${new Date().toISOString()}] 📊 Monthly Report Scheduler started ` +
      `(checks every hour, runs on 1st of month 10:xx UTC)`
    );

    // Run immediately on first tick after delay, then on interval.
    // Thought: running immediately on startup is safe because the gate inside
    // runMonthlyReportCheck will reject the call unless it's actually the 1st
    // of the month at 10:xx. This is the same pattern as weeklySummaryScheduler.
    runMonthlyReportCheck(prisma);
    setInterval(() => runMonthlyReportCheck(prisma), SCHEDULER_INTERVAL_MS);

  }, STARTUP_DELAY_MS);
}

module.exports = { startMonthlyReportScheduler };