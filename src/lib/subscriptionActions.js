'use strict';

const db = require('./db');
const logger = require('./logger');
const { sendDowngradeEmail } = require('./email');
const { computeStartOfNextMonth } = require('./quotaGate');
const { PLAN_LABELS_FALLBACK = {} } = {};

const PLAN_LABELS = { pro: 'Pro', agency: 'Agency', starter: 'Starter', early_access: 'Early Access' };

const normalizeBillingCycle = (billingCycle) =>
  ({ early_access_promo: 'monthly' }[billingCycle]) || billingCycle || 'monthly';

const buildRenewUrl = (plan) => `https://chargeguard.io/upgrade.html?plan=${plan}_monthly`;

// ── suspendTenant ──────────────────────────────────────────────────────────
// Idempotent: suspending an already-suspended tenant succeeds silently with
// code ALREADY_SUSPENDED rather than erroring — matches the codebase's
// existing idempotency pattern (e.g. /stores POST reactivation).
async function suspendTenant(tenantId, { note } = {}) {
  const tenant = await db.tenant.findUnique({ where: { id: tenantId }, select: { id: true, email: true, isActive: true } });
  if (!tenant) return { success: false, code: 'NOT_FOUND', message: 'Tenant not found' };
  if (!tenant.isActive) return { success: true, code: 'ALREADY_SUSPENDED', tenant, message: 'Tenant already suspended' };

  const updated = await db.tenant.update({
    where: { id: tenantId },
    data:  { isActive: false },
  });
  logger.warn({ module: 'subscriptionActions', tenantId, note }, 'Tenant manually suspended');
  return { success: true, code: 'SUSPENDED', tenant: updated, message: 'Tenant suspended — all API access now returns 401' };
}

// ── reactivateTenant ────────────────────────────────────────────────────────
async function reactivateTenant(tenantId, { note } = {}) {
  const tenant = await db.tenant.findUnique({ where: { id: tenantId }, select: { id: true, email: true, isActive: true } });
  if (!tenant) return { success: false, code: 'NOT_FOUND', message: 'Tenant not found' };
  if (tenant.isActive) return { success: true, code: 'ALREADY_ACTIVE', tenant, message: 'Tenant already active' };

  const updated = await db.tenant.update({
    where: { id: tenantId },
    data:  { isActive: true },
  });
  logger.info({ module: 'subscriptionActions', tenantId, note }, 'Tenant manually reactivated');
  return { success: true, code: 'REACTIVATED', tenant: updated, message: 'Tenant reactivated — access restored' };
}

// ── downgradeToStarter ──────────────────────────────────────────────────────
// Extracted verbatim from subscriptionScheduler.js's processGraceToExpired()
// atomic transaction — this IS that logic, not a reimplementation, so the
// cron job and this manual path can never drift (CWE-1059). Idempotent:
// downgrading an already-starter tenant is a no-op success.
async function downgradeToStarter(tenantId, { note, sendEmail = true } = {}) {
  const tenant = await db.tenant.findUnique({
    where: { id: tenantId },
    select: { id: true, email: true, storeUrl: true, plan: true, billingCycle: true, lastDowngradeNoticeSentAt: true },
  });
  if (!tenant) return { success: false, code: 'NOT_FOUND', message: 'Tenant not found' };
  if (tenant.plan === 'starter') return { success: true, code: 'ALREADY_STARTER', tenant, message: 'Tenant already on Starter' };

  const previousPlan = tenant.plan;
  const now = new Date();

  const [updatedTenant, deactivatedStores] = await db.$transaction([
    db.tenant.update({
      where: { id: tenantId },
      data: {
        plan:               'starter',
        subscriptionStatus: 'expired',
        subscriptionEndDate: null,
        billingCycle:        null,
      },
    }),
    db.store.updateMany({
      where: { tenantId, isActive: true },
      data:  { isActive: false, deactivatedAt: now },
    }),
  ]);

  logger.warn(
    { module: 'subscriptionActions', tenantId, previousPlan, storesDeactivated: deactivatedStores.count, note },
    'Tenant manually downgraded to starter'
  );

  if (sendEmail) {
    try {
      const previousPlanLabel = PLAN_LABELS[previousPlan] || previousPlan;
      await sendDowngradeEmail(
        { email: tenant.email, storeUrl: tenant.storeUrl },
        { previousPlanLabel, renewUrl: buildRenewUrl(previousPlan) }
      );
      await db.tenant.update({ where: { id: tenantId }, data: { lastDowngradeNoticeSentAt: new Date() } });
    } catch (emailErr) {
      // Same tolerance as the scheduler: email failure never rolls back
      // or blocks the already-committed downgrade.
      logger.error({ module: 'subscriptionActions', tenantId, error: emailErr.message }, 'Downgrade email failed (manual action)');
    }
  }

  return {
    success: true,
    code: 'DOWNGRADED',
    tenant: updatedTenant,
    storesDeactivated: deactivatedStores.count,
    message: `Downgraded from ${previousPlan} to starter, ${deactivatedStores.count} store(s) deactivated`,
  };
}

// ── extendGracePeriod ────────────────────────────────────────────────────────
// Only meaningful while subscriptionStatus === 'grace_period' — extending a
// non-grace-period tenant's subscriptionEndDate would silently create an
// inconsistent state the scheduler's own queries don't expect (it only reads
// subscriptionEndDate against subscriptionStatus-scoped where clauses).
async function extendGracePeriod(tenantId, { days, note } = {}) {
  if (!Number.isInteger(days) || days <= 0 || days > 90) {
    return { success: false, code: 'INVALID_DAYS', message: 'days must be an integer between 1 and 90' };
  }

  const tenant = await db.tenant.findUnique({
    where: { id: tenantId },
    select: { id: true, email: true, subscriptionStatus: true, subscriptionEndDate: true },
  });
  if (!tenant) return { success: false, code: 'NOT_FOUND', message: 'Tenant not found' };
  if (tenant.subscriptionStatus !== 'grace_period') {
    return {
      success: false,
      code: 'NOT_IN_GRACE_PERIOD',
      tenant,
      message: `Tenant is currently '${tenant.subscriptionStatus}', not grace_period — extend only applies during an active grace window`,
    };
  }

  const base = tenant.subscriptionEndDate && new Date(tenant.subscriptionEndDate) > new Date()
    ? new Date(tenant.subscriptionEndDate)
    : new Date();
  const newEndDate = new Date(base.getTime() + days * 24 * 60 * 60 * 1000);

  const updated = await db.tenant.update({
    where: { id: tenantId },
    data:  { subscriptionEndDate: newEndDate },
  });

  logger.info({ module: 'subscriptionActions', tenantId, days, newEndDate, note }, 'Grace period manually extended');
  return { success: true, code: 'EXTENDED', tenant: updated, message: `Grace period extended by ${days} day(s), now ends ${newEndDate.toISOString()}` };
}

// ── setPlan ──────────────────────────────────────────────────────────────────
// Manual override for comps/corrections/fraud response. Unlike
// downgradeToStarter, this does NOT force subscriptionStatus or deactivate
// stores — it's a raw plan override, so an admin setting someone to 'agency'
// as a comp doesn't also need to fabricate a fake subscriptionEndDate. If the
// target plan is 'starter' specifically, delegates to downgradeToStarter so
// the Store-deactivation invariant (no active Store rows on a non-Agency
// plan) is never violated by this alternate path.
const VALID_PLANS = ['starter', 'pro', 'agency'];

async function setPlan(tenantId, { plan, note } = {}) {
  if (!VALID_PLANS.includes(plan)) {
    return { success: false, code: 'INVALID_PLAN', message: `plan must be one of: ${VALID_PLANS.join(', ')}` };
  }

  if (plan === 'starter') {
    return downgradeToStarter(tenantId, { note, sendEmail: false });
  }

  const tenant = await db.tenant.findUnique({ where: { id: tenantId }, select: { id: true, plan: true } });
  if (!tenant) return { success: false, code: 'NOT_FOUND', message: 'Tenant not found' };
  if (tenant.plan === plan) return { success: true, code: 'ALREADY_SET', tenant, message: `Tenant already on ${plan}` };

  const updated = await db.tenant.update({ where: { id: tenantId }, data: { plan } });
  logger.info({ module: 'subscriptionActions', tenantId, previousPlan: tenant.plan, newPlan: plan, note }, 'Plan manually set');
  return { success: true, code: 'PLAN_SET', tenant: updated, message: `Plan set to ${plan}` };
}

// ── resetQuota ───────────────────────────────────────────────────────────
// Forces an immediate, isolated quota reset without touching `plan` — the
// lever setPlan() intentionally doesn't provide. Reuses checkQuotaGate's
// exact startOfNextMonth calculation and atomic updateMany-with-WHERE
// pattern so this manual path and the lazy-reset path can never disagree
// on "what does reset mean" or race each other into a double-zero.
// Idempotent: a tenant already sitting at 0 with a future quotaResetDate
// returns ALREADY_RESET rather than re-writing identical values.
async function resetQuota(tenantId, { note } = {}) {
  const tenant = await db.tenant.findUnique({
    where: { id: tenantId },
    select: { id: true, email: true, plan: true, monthlyBlockedCount: true, quotaResetDate: true },
  });
  if (!tenant) return { success: false, code: 'TENANT_NOT_FOUND', message: 'Tenant not found' };

  const now = new Date();
  const startOfNextMonth = computeStartOfNextMonth(now);

  const alreadyReset =
    tenant.monthlyBlockedCount === 0 &&
    tenant.quotaResetDate &&
    new Date(tenant.quotaResetDate) > now;
  if (alreadyReset) {
    return { success: true, code: 'ALREADY_RESET', tenant, message: 'Quota is already reset for the current cycle' };
  }

  // Atomic guard: only write if the tenant is NOT already sitting in the
  // exact target state at write time. This is the same shape as
  // checkQuotaGate's updateMany — a WHERE-guarded conditional update, not a
  // check-then-act — so a concurrent admin double-click, or a race against
  // checkQuotaGate's own lazy reset firing on a live request, can't
  // double-zero the counter or stomp a reset that already landed.
  const updateResult = await db.tenant.updateMany({
    where: {
      id: tenantId,
      OR: [
        { monthlyBlockedCount: { not: 0 } },
        { quotaResetDate: null },
        { quotaResetDate: { lte: now } },
      ],
    },
    data: { monthlyBlockedCount: 0, quotaResetDate: startOfNextMonth },
  });

  if (updateResult.count === 0) {
    // Lost the race to a concurrent reset (another admin click, or
    // checkQuotaGate's lazy path) — re-read and report current state
    // rather than erroring or silently double-resetting.
    const refreshed = await db.tenant.findUnique({
      where: { id: tenantId },
      select: { id: true, email: true, plan: true, monthlyBlockedCount: true, quotaResetDate: true },
    });
    logger.info({ module: 'subscriptionActions', tenantId, note }, 'Quota reset raced with a concurrent reset — no-op');
    return { success: true, code: 'ALREADY_RESET', tenant: refreshed, message: 'Quota was already reset by a concurrent operation' };
  }

  const updated = await db.tenant.findUnique({
    where: { id: tenantId },
    select: { id: true, email: true, plan: true, monthlyBlockedCount: true, quotaResetDate: true },
  });

  logger.info(
    { module: 'subscriptionActions', tenantId, plan: tenant.plan, previousCount: tenant.monthlyBlockedCount, newResetDate: startOfNextMonth, note },
    'Quota manually reset'
  );
  return {
    success: true,
    code: 'RESET',
    tenant: updated,
    message: `Quota reset to 0, next cycle starts ${startOfNextMonth.toISOString()}`,
  };
}

module.exports = { suspendTenant, reactivateTenant, downgradeToStarter, extendGracePeriod, setPlan, resetQuota };