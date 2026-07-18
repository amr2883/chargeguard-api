'use strict';

const db = require('./db');
const logger = require('./logger');
const { isAgency, FREE_PLANS } = require('./planAccess');

// Single source of truth for quota limits (CWE-1059 drift fix — previously
// duplicated verbatim in /evaluate and /woocommerce-webhook in risk.js).
const PLAN_QUOTA_LIMITS = {
  ...Object.fromEntries(FREE_PLANS.map(plan => [plan, 500])),
  pro: 5000,
};
const STARTER_FALLBACK_LIMIT = 500;

/**
 * Centralized quota-gate check. Call once, immediately after req.tenant is
 * resolved, before any route-specific business logic.
 *
 * @param {object} req - req.tenant must include { id, plan, monthlyBlockedCount, quotaResetDate }
 * @param {object} res
 * @param {string} [logContext] - endpoint name for structured logging
 * @returns {Promise<boolean>} true if quota was exceeded and a fail-open 200
 *   response was already sent (caller MUST `return` immediately); false if
 *   the caller should proceed normally.
 */
async function checkQuotaGate(req, res, logContext = 'unknown') {
  const tenantPlan = req.tenant.plan;
  if (isAgency(tenantPlan)) return false;

  const monthlyLimitForPlan = PLAN_QUOTA_LIMITS[tenantPlan] !== undefined
    ? PLAN_QUOTA_LIMITS[tenantPlan]
    : STARTER_FALLBACK_LIMIT;

  const now = new Date();
  const startOfNextMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1, 0, 0, 0, 0));

  let monthlyCount = req.tenant.monthlyBlockedCount;
  const needsReset = !req.tenant.quotaResetDate || new Date(req.tenant.quotaResetDate) <= now;

  if (needsReset) {
    // Conditional reset: only commits if quotaResetDate is still stale at
    // write time. Guards against two concurrent requests both observing a
    // stale req.tenant snapshot and both attempting the reset.
    const resetResult = await db.tenant.updateMany({
      where: {
        id: req.tenant.id,
        OR: [{ quotaResetDate: null }, { quotaResetDate: { lte: now } }],
      },
      data: { monthlyBlockedCount: 0, quotaResetDate: startOfNextMonth },
    });

    if (resetResult.count > 0) {
      monthlyCount = 0;
    } else {
      // Lost the race — re-read the authoritative value instead of assuming 0.
      const refreshed = await db.tenant.findUnique({
        where: { id: req.tenant.id },
        select: { monthlyBlockedCount: true },
      });
      monthlyCount = refreshed?.monthlyBlockedCount ?? 0;
    }
  }

  if (monthlyCount >= monthlyLimitForPlan) {
    logger.warn(
      { module: 'quotaGate', endpoint: logContext, tenantId: req.tenant.id, plan: tenantPlan, monthlyCount, monthlyLimit: monthlyLimitForPlan },
      'Monthly block-quota exceeded — failing open, order will NOT be scored'
    );
    const upgradeMessage = tenantPlan === 'pro'
      ? 'Monthly Pro protection limit (5,000 blocked attempts) reached. Orders are no longer being screened — upgrade to Agency to restore protection.'
      : 'Monthly protection limit (500 blocked attempts) reached. Orders are no longer being screened — upgrade to Pro to restore protection.';

    res.status(200).json({
      decision: 'approve',
      scored: false,
      score: null,
      flags: [{ severity: 'critical', text: upgradeMessage }],
      connectedRisk: 0,
      blocked_reason: tenantPlan === 'pro' ? 'pro_quota_exceeded' : 'quota_exceeded',
    });
    return true;
  }

  return false;
}

module.exports = { checkQuotaGate, PLAN_QUOTA_LIMITS, STARTER_FALLBACK_LIMIT };