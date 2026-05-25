'use strict';

/**
 * Attack Alert Scheduler
 * ----------------------
 * Runs every 2 minutes. For each active Tenant:
 *   1. Counts BlockedAttempts in the last ATTACK_WINDOW_MS
 *   2. If count >= ATTACK_THRESHOLD:
 *      a. Checks AlertLog — was an alert sent in the last COOLDOWN_MS?
 *      b. If no recent alert → send email + write AlertLog record
 *
 * Fully isolated from the blocked-attempt handler (src/routes/risk.js).
 * Failures are fire-and-forget; a broken email never affects other tenants.
 */

const db                      = require('./db');
const { sendAttackAlertEmail } = require('./email');

// ── Tuneable constants ──────────────────────────────────────────────────────
const SCHEDULER_INTERVAL_MS = 2  * 60 * 1000;  // run every 2 minutes
const STARTUP_DELAY_MS      = 2  * 60 * 1000;  // first run: 2 min after boot
const ATTACK_WINDOW_MS      = 10 * 60 * 1000;  // look-back window: 10 minutes
const ATTACK_THRESHOLD      = 10;               // min attacks to trigger alert
const COOLDOWN_MS           = 6  * 60 * 60 * 1000; // 6-hour cooldown per tenant
const SAVINGS_PER_ATTACK    = 0.30;             // estimated $ saved per blocked attempt
// ───────────────────────────────────────────────────────────────────────────

/**
 * Core logic — runs once per scheduler tick.
 * Uses a dedicated Prisma client passed in from app.js to avoid
 * interfering with any request-scoped clients.
 *
 * @param {import('@prisma/client').PrismaClient} prisma
 */
async function runAttackAlertCheck(prisma) {
  const label = `[AttackAlert ${new Date().toISOString()}]`;

  let tenants;
  try {
    tenants = await prisma.tenant.findMany({
      where: { isActive: true },
      select: { id: true, email: true, storeUrl: true },
    });
  } catch (err) {
    console.error(`${label} ❌ Failed to fetch tenants:`, err.message);
    return;
  }

  if (!tenants.length) return;

  const windowStart = new Date(Date.now() - ATTACK_WINDOW_MS);
  const cooldownStart = new Date(Date.now() - COOLDOWN_MS);

  // Process tenants sequentially to avoid hammering DB + SMTP on large user bases.
  // When the user base grows beyond ~100 active tenants, switch to Promise.allSettled
  // with a concurrency limiter.
  for (const tenant of tenants) {
    try {
      // 1. Count attacks in the look-back window
      const attackCount = await prisma.blockedAttempt.count({
        where: {
          tenantId:  tenant.id,
          blockedAt: { gte: windowStart },
        },
      });

      if (attackCount < ATTACK_THRESHOLD) continue;

      // 2. Cooldown check — was an alert already sent recently?
      const recentAlert = await prisma.alertLog.findFirst({
        where: {
          tenantId: tenant.id,
          sentAt:   { gte: cooldownStart },
        },
        select: { id: true },
      });

      if (recentAlert) {
        console.log(`${label} ⏭️  Skipping ${tenant.email} — alert sent within cooldown window`);
        continue;
      }

      // 3. Calculate estimated savings
      const savedAmount = attackCount * SAVINGS_PER_ATTACK;

      // 4. Write AlertLog BEFORE sending email.
      //    This prevents duplicate sends if the email call throws midway.
      await prisma.alertLog.create({
        data: {
          tenantId:    tenant.id,
          alertType:   'attack_detected',
          attackCount,
          savedAmount,
        },
      });

      // 5. Send email — fire-and-forget; never throws to the outer loop
      sendAttackAlertEmail(tenant, attackCount, savedAmount)
        .catch(err => {
          console.error(`${label} ❌ Email failed for ${tenant.email}:`, err.message);
        });

      console.log(`${label} 🚨 Alert queued for ${tenant.email} — ${attackCount} attacks detected`);

    } catch (tenantErr) {
      // One tenant failing must never abort the loop for others
      console.error(`${label} ❌ Error processing tenant ${tenant.id}:`, tenantErr.message);
    }
  }
}

/**
 * Registers the scheduler inside app.listen().
 * Call once, pass a long-lived PrismaClient.
 *
 * @param {import('@prisma/client').PrismaClient} prisma
 */
function startAttackAlertScheduler(prisma) {
  setTimeout(() => {
    console.log(`[${new Date().toISOString()}] 🚨 Attack Alert Scheduler started (every 2 min)`);

    // Run immediately on first tick, then on interval
    runAttackAlertCheck(prisma);
    setInterval(() => runAttackAlertCheck(prisma), SCHEDULER_INTERVAL_MS);

  }, STARTUP_DELAY_MS);
}

module.exports = { startAttackAlertScheduler };