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

// ── Advanced Layers Snapshot (used by the Monthly Report) ─────────────────
// Point-in-time snapshot of how many "advanced" (external-intelligence)
// layers are currently available for a tenant. Deliberately reuses the
// exact same quota_exhausted condition as getProtectionStatus() above —
// single source of truth, not a second independent calculation. IP/Email/
// BIN intelligence in riskScoring.js are gated by monthly quota only
// (checkQuotaGate), identically across every plan — see limitedScoring in
// risk.js's /evaluate — never by plan directly.
//
// NOTE: this is a snapshot at call time, not a historical record for a
// whole reporting period. Once ProtectionEvent rows are being written
// (see that model's schema comment), monthly reports should switch to
// reading actual historical degradation windows from there. Swap the
// implementation inside this one function only when that happens —
// callers (reportDataService.js) do not need to change.
const ADVANCED_LAYERS_TOTAL = 3; // IP Intelligence, Email Intelligence, BIN Intelligence

function getAdvancedLayersSnapshot(tenant) {
  const quota = getQuotaStatusReadOnly(tenant);
  return quota.exceeded ? 0 : ADVANCED_LAYERS_TOTAL;
}

// ── Advanced Layers Snapshot for a historical period (Monthly Report) ─────
// getAdvancedLayersSnapshot() above reads the tenant's LIVE counter — correct
// for "what's the status right now" (dashboard Hero), wrong for "what was
// the status during month X", because quotaGate.js's reset is lazy: it only
// fires on a real request after quotaResetDate has passed. A tenant with
// even one order early in the new month resets the counter to 0 BEFORE the
// scheduler generates last month's report (scheduler runs on the 1st at
// 10:xx UTC) — reading the live counter at that point would silently show
// "fully protected" for a month that may have actually hit its quota.
//
// This variant instead uses totalAttacks — the actual BlockedAttempt count
// for that specific reporting period, which is immune to the live-counter
// reset because it's a historical query, not a live counter read. This can
// run slightly high vs. the true monthlyBlockedCount (dedup logic in
// shouldIncrementQuota(), and /blocked-attempt writes BlockedAttempt rows
// without incrementing the quota) — an acceptable, safety-conservative
// direction for a security product: worst case this under-reports advanced
// protection for a month that was actually fine, never the reverse.
//
// TODO: once ProtectionEvent rows are being written (quota_exceeded type),
// switch this to read actual start/end degradation windows for the period
// instead of this attacks-vs-limit approximation. Swap inside this function
// only — reportDataService.js's call site does not need to change.
function getAdvancedLayersSnapshotForPeriod(plan, totalAttacksInPeriod) {
  if (isAgency(plan)) return ADVANCED_LAYERS_TOTAL; // unlimited quota — never exceeded
  const limit = PLAN_QUOTA_LIMITS[plan] !== undefined ? PLAN_QUOTA_LIMITS[plan] : STARTER_FALLBACK_LIMIT;
  return totalAttacksInPeriod >= limit ? 0 : ADVANCED_LAYERS_TOTAL;
}

// ── Protection Layers Checklist (used by the Dashboard Hero) ──────────────
// Single canonical list of layer names + active/inactive state, derived
// PURELY from an already-computed protectionStatus object (see
// getProtectionStatus() above) — never re-touches emergencyPause or
// getBINStats itself, so a caller that already computed protectionStatus
// once per request never pays for a second Redis/memory round trip by
// also asking for the layers breakdown.
//
// Names are the same 4 core / 3 advanced conceptual buckets used by the
// Monthly Report (reportDataService.js's local CORE_LAYERS_TOTAL and this
// file's ADVANCED_LAYERS_TOTAL) — kept here as the one place both the
// live dashboard and (eventually) historical reporting can import from,
// so a renamed layer never drifts between the two surfaces.
const CORE_LAYERS_TOTAL = 4;
const CORE_LAYER_NAMES = [
  'Blacklist & Email Verification',
  'Velocity & Device Fingerprinting',
  'BIN Sequence Detection',
  'Identity Graph',
];
const ADVANCED_LAYER_NAMES = [
  'IP Intelligence',
  'Email Intelligence',
  'BIN Intelligence',
];

/**
 * @param {{state: string}} protectionStatus - result of getProtectionStatus()
 *   (or, in the future, an equivalent historical-state object built from
 *   ProtectionEvent rows for a past reporting period — only `.state` is
 *   read here, so either shape works without this function changing).
 * @returns {{
 *   core: {name: string, active: boolean}[],
 *   advanced: {name: string, active: boolean}[],
 *   coreActiveCount: number,
 *   advancedActiveCount: number,
 * }}
 */
function getProtectionLayers(protectionStatus) {
  const isPaused = protectionStatus.state === 'emergency_pause_global'
    || protectionStatus.state === 'emergency_pause_tenant';
  const isQuotaExhausted = protectionStatus.state === 'quota_exhausted';

  const core = CORE_LAYER_NAMES.map(name => ({ name, active: !isPaused }));
  const advanced = ADVANCED_LAYER_NAMES.map(name => ({
    name,
    active: !isPaused && !isQuotaExhausted,
  }));

  return {
    core,
    advanced,
    coreActiveCount: core.filter(l => l.active).length,
    advancedActiveCount: advanced.filter(l => l.active).length,
  };
}

module.exports = {
  getProtectionStatus,
  getQuotaStatusReadOnly,
  getAdvancedLayersSnapshot,
  getAdvancedLayersSnapshotForPeriod,
  getProtectionLayers,
  ADVANCED_LAYERS_TOTAL,
  CORE_LAYERS_TOTAL,
  CORE_LAYER_NAMES,
  ADVANCED_LAYER_NAMES,
};