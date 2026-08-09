'use strict';

/**
 * protectionStatus.js — Unified Protection State for the Merchant Dashboard
 * ───────────────────────────────────────────────────────────────────────
 * Single source of truth for "am I protected right now?" Consumed by
 * dashboard.js's Hero section. Never mutates state — pure read.
 *
 * Priority order (worst wins, first match returned):
 *   1. emergency_pause_global  — nothing is being checked, platform-wide
 *   2. emergency_pause_tenant  — nothing is being checked, this tenant only
 *   3. quota_exhausted         — core detection active, but external
 *                                 intelligence (IP/email/BIN) is paused
 *   4. active_attack_blocked   — elevated activity, but being handled
 *   5. healthy                 — default, everything nominal
 *
 * quota_exhausted ranks above active_attack_blocked deliberately: a
 * live BIN attack is reassuring (the system caught it and is blocking
 * it automatically), whereas an exhausted quota is a silent, ongoing
 * reduction in protection depth that the merchant would otherwise never
 * notice until it's too late.
 */

const emergencyPause = require('./emergencyPause');
const { getBINStats } = require('./binSequenceDetector');
const { isAgency } = require('./planAccess');
const { PLAN_QUOTA_LIMITS, STARTER_FALLBACK_LIMIT } = require('./quotaGate');

/**
 * Read-only mirror of checkQuotaGate()'s exceeded/limit logic — deliberately
 * does NOT touch the database or perform the lazy monthly reset. A
 * dashboard page load must never race with, or duplicate, the reset that
 * checkQuotaGate() performs on the actual traffic path (/evaluate,
 * /woocommerce-webhook). If the tenant's quotaResetDate has already
 * passed, this treats the count as reset to 0 for display purposes only —
 * the real reset still happens exactly once, on the next real request.
 *
 * @param {{plan: string, monthlyBlockedCount: number, quotaResetDate: Date|null}} tenant
 * @returns {{exceeded: boolean, limit: number, monthlyCount: number}}
 */
function getQuotaStatusReadOnly(tenant) {
  if (isAgency(tenant.plan)) {
    return { exceeded: false, limit: Infinity, monthlyCount: tenant.monthlyBlockedCount ?? 0 };
  }

  const limit = PLAN_QUOTA_LIMITS[tenant.plan] !== undefined
    ? PLAN_QUOTA_LIMITS[tenant.plan]
    : STARTER_FALLBACK_LIMIT;

  const now = new Date();
  const resetPending = !tenant.quotaResetDate || new Date(tenant.quotaResetDate) <= now;
  const monthlyCount = resetPending ? 0 : (tenant.monthlyBlockedCount ?? 0);

  return { exceeded: monthlyCount >= limit, limit, monthlyCount };
}

/**
 * Computes the single, unified protection status shown at the top of the
 * merchant dashboard. Async because getBINStats() may hit Redis.
 *
 * @param {{id: string, plan: string, monthlyBlockedCount: number, quotaResetDate: Date|null}} tenant
 * @returns {Promise<{state: string, severity: 'critical'|'warning'|'healthy', title: string, detail: string, source: string, confidence: 'confirmed', expiresAt?: Date}>}
 */
async function getProtectionStatus(tenant) {
  // 1 & 2 — Emergency Pause (highest priority — genuinely no checks running)
  const pauseStatus = emergencyPause.getStatus(tenant.id);

  if (pauseStatus.global) {
    return {
      state: 'emergency_pause_global',
      severity: 'critical',
      title: 'Protection is paused',
      detail: 'All orders are being approved automatically without fraud checks. This was activated platform-wide by ChargeGuard.',
      source: 'emergency_pause',
      confidence: 'confirmed',
      expiresAt: pauseStatus.global.expiresAt,
    };
  }

  if (pauseStatus.tenant) {
    return {
      state: 'emergency_pause_tenant',
      severity: 'critical',
      title: 'Your protection is paused',
      detail: 'All orders on your store are being approved automatically without fraud checks.',
      source: 'emergency_pause',
      confidence: 'confirmed',
      expiresAt: pauseStatus.tenant.expiresAt,
    };
  }

  // 3 — Quota exhausted (silent, ongoing degradation)
  const quota = getQuotaStatusReadOnly(tenant);
  if (quota.exceeded) {
    return {
      state: 'quota_exhausted',
      severity: 'warning',
      title: 'Running on basic protection',
      detail: `Your monthly limit (${quota.monthlyCount}/${quota.limit} blocked attempts) has been reached. Core checks — device/IP blacklist, velocity, card-testing detection — are still active. Deeper checks (IP reputation, email intelligence, BIN lookup) are paused until your plan resets.`,
      source: 'quota',
      confidence: 'confirmed',
    };
  }

  // 4 — Active BIN attack currently being auto-blocked
  const binStats = await getBINStats(tenant.id);
  if (binStats.blockedPrefixes > 0) {
    return {
      state: 'active_attack_blocked',
      severity: 'warning',
      title: 'Active attack — being blocked automatically',
      detail: `ChargeGuard is currently blocking a coordinated card-testing attempt (${binStats.blockedPrefixes} BIN prefix${binStats.blockedPrefixes !== 1 ? 'es' : ''} under active block). No action needed.`,
      source: 'bin_alert',
      confidence: 'confirmed',
    };
  }

  // 5 — Healthy default
  return {
    state: 'healthy',
    severity: 'healthy',
    title: 'Fully protected',
    detail: 'All detection layers are active and running normally.',
    source: 'default',
    confidence: 'confirmed',
  };
}

module.exports = { getProtectionStatus, getQuotaStatusReadOnly };