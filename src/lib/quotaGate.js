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

// Shared by checkQuotaGate's lazy reset and subscriptionActions.resetQuota's
// admin-triggered reset — a single definition so the two paths can never
// compute a different "next cycle start" and drift apart (CWE-1059).
function computeStartOfNextMonth(now) {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1, 0, 0, 0, 0));
}

/**
 * Centralized quota-status lookup. Call once, immediately after req.tenant
 * is resolved, before any route-specific business logic.
 *
 * IMPORTANT (post-fix behavior): this function NO LONGER writes an HTTP
 * response and NO LONGER short-circuits the request. Quota only gates
 * *expensive external intel lookups* inside calculateRiskScore() — cheap,
 * always-on detectors (blacklist, velocity, BIN sequence, identity graph,
 * pattern sharing) must keep running even when the merchant's monthly
 * blocked-attempt quota is exhausted. See risk.js call sites.
 *
 * @param {object} req - req.tenant must include { id, plan, monthlyBlockedCount, quotaResetDate }
 * @param {string} [logContext] - endpoint name for structured logging
 * @returns {Promise<{exceeded: boolean, plan: string, limit: number, monthlyCount: number}>}
 */
async function checkQuotaGate(req, logContext = 'unknown') {
  const tenantPlan = req.tenant.plan;
  if (isAgency(tenantPlan)) {
    return { exceeded: false, plan: tenantPlan, limit: Infinity, monthlyCount: req.tenant.monthlyBlockedCount ?? 0 };
  }

  const monthlyLimitForPlan = PLAN_QUOTA_LIMITS[tenantPlan] !== undefined
    ? PLAN_QUOTA_LIMITS[tenantPlan]
    : STARTER_FALLBACK_LIMIT;

  const now = new Date();
  const startOfNextMonth = computeStartOfNextMonth(now);

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
    // Quota exceeded is no longer fail-open. It no longer approves the
    // order or skips detection — it only tells the caller to skip
    // *expensive external intel calls* inside calculateRiskScore().
    // Cheap, always-on detectors (blacklist/velocity/BIN-sequence/graph/
    // pattern-sharing) still run in risk.js regardless of this flag, and
    // the order can still be blocked on their output.
    logger.warn(
      { module: 'quotaGate', endpoint: logContext, tenantId: req.tenant.id, plan: tenantPlan, monthlyCount, monthlyLimit: monthlyLimitForPlan },
      'Monthly block-quota exceeded — external intel lookups will be skipped; cheap detectors remain active'
    );
    return { exceeded: true, plan: tenantPlan, limit: monthlyLimitForPlan, monthlyCount };
  }

  return { exceeded: false, plan: tenantPlan, limit: monthlyLimitForPlan, monthlyCount };
}

module.exports = { checkQuotaGate, computeStartOfNextMonth, PLAN_QUOTA_LIMITS, STARTER_FALLBACK_LIMIT };