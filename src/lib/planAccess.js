
'use strict';

/**
 * planAccess.js — Central Plan Hierarchy & Feature-Gating Helpers
 * ─────────────────────────────────────────────────────────────
 * Single source of truth for "which plans get which paid features."
 * Confirmed against src/routes/payments.js paypal-webhook handler:
 *   const planName = session.planId.startsWith('pro') ? 'pro' : 'agency';
 * Tenant.plan is written as the short form only ('pro' / 'agency'),
 * never as the CheckoutSession-level 'pro_monthly' / 'agency_annual' etc.
 *
 * Plan hierarchy (low → high):
 *   starter / early_access  →  free tier, detection only, no real-time alerts
 *   pro                     →  paid, real-time email + Slack/Discord alerts
 *   agency                  →  paid, everything in pro + multi-store
 */

const PRO_PLUS_PLANS = ['pro', 'agency'];
const FREE_PLANS      = ['starter', 'early_access'];

/**
 * Returns true if the given plan is entitled to Pro-tier features
 * (real-time alerts, BIN intelligence, etc.).
 *
 * @param {string} plan - tenant.plan value from the database
 * @returns {boolean}
 */
function isProOrAbove(plan) {
  return PRO_PLUS_PLANS.includes(plan);
}

/**
 * Returns true if the given plan is Agency specifically.
 *
 * @param {string} plan
 * @returns {boolean}
 */
function isAgency(plan) {
  return plan === 'agency';
}

/**
 * Returns a Prisma `where`-clause fragment for Tier-1 fraud-detection
 * queries (Order velocity/history, CardTestAttempt velocity, Blacklist,
 * Whitelist). Spread into the existing `where: { merchantId, ... }` object
 * at each call site.
 *
 * Returns {} (a no-op spread) unless the tenant has explicitly opted into
 * fraudIsolationMode === 'per_store' AND a storeId was actually resolved
 * for this request (req.storeId, set by domainAuthMiddleware). This means:
 *   - Starter/Pro tenants (no Store rows, req.storeId always undefined): {}
 *   - Agency tenants who haven't opted in (default 'pooled'): {}
 *   - Agency tenants in 'per_store' mode, request missing storeId
 *     (e.g. legacy allowedDomains fallback path): {} — fails open to
 *     pooled behavior rather than silently under-matching.
 *   - Agency tenants in 'per_store' mode with a resolved storeId: { storeId }
 *
 * Deliberately NEVER used for BIN sequence detection or the Identity
 * Graph — those remain unconditionally tenant-wide (Tier 2).
 *
 * @param {{fraudIsolationMode?: string}} tenant
 * @param {string|null|undefined} storeId - req.storeId
 * @returns {{storeId?: string}}
 */
function getStoreScope(tenant, storeId) {
  if (tenant?.fraudIsolationMode === 'per_store' && storeId) {
    return { storeId };
  }
  return {};
}

module.exports = {
  PRO_PLUS_PLANS,
  FREE_PLANS,
  isProOrAbove,
  isAgency,
  getStoreScope,
};