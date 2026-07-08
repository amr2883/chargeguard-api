
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

module.exports = {
  PRO_PLUS_PLANS,
  FREE_PLANS,
  isProOrAbove,
  isAgency,
};