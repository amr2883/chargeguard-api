'use strict';

/**
 * notify.js — ChargeGuard Notification Orchestrator
 * ──────────────────────────────────────────────────
 * Routes attack alerts to all configured channels (email + webhook).
 * Each channel is isolated — failure in one never affects another.
 *
 * Exported:
 *   - notifyTenant(tenant, attackCount, savedAmount, windowMinutes)
 */

const { sendAttackAlertEmail, sendPaypalAlertEmail } = require('./email');
const { sendWebhookAlert }    = require('./webhook');
const db                      = require('./db');
const { isProOrAbove }        = require('./planAccess');
const logger = require('./logger');

/**
 * Sends attack alert to all configured channels for a single tenant.
 * Channels run in parallel; failures are logged and never throw.
 *
 * @param {object} tenant        - Tenant object (email, webhookUrl, webhookType, id)
 * @param {number} attackCount   - Number of blocked attempts
 * @param {number} savedAmount   - Estimated savings in USD
 * @param {number} [windowMinutes=10] - Time window in minutes
 * @returns {Promise<void>}
 */
async function notifyTenant(tenant, attackCount, savedAmount, windowMinutes = 10) {
  const promises = [];

  // Email — always sent
  promises.push(
    sendAttackAlertEmail(tenant, attackCount, savedAmount, windowMinutes)
      .catch(err => logger.error({ module: 'notify', fn: 'notifyTenant', tenantEmail: tenant.email, error: err.message }, 'Email failed'))
  );

  // Webhook — only if configured
  if (tenant.webhookUrl) {
    promises.push(
      sendWebhookAlert(tenant, attackCount, savedAmount, windowMinutes)
        .catch(err => logger.error({ module: 'notify', fn: 'notifyTenant', tenantId: tenant.id, error: err.message }, 'Webhook failed'))
    );
  }

  // Run all channels in parallel — each .catch() above ensures
  // that a failure in one channel never aborts the others.
  await Promise.all(promises);
}

/**
 * Sends BIN Sequence attack alert to all configured channels.
 * Enforces 30-minute cooldown per tenant to prevent spam.
 *
 * @param {object} tenant  - Tenant object (id, email, webhookUrl)
 * @param {object} alert   - BinSequenceAlert record
 * @returns {Promise<void>}
 */
async function notifyBINSequenceAlert(tenant, alert) {
  // Plan gate — must be the FIRST check in this function, before any
  // cooldown logic or DB queries, so non-Pro tenants never trigger a
  // wasted lastAlertSentAt read/write for an alert they can't receive.
  // Defense-in-depth: risk.js's call site has no plan check of its own,
  // so this is the only gate standing between detection and dispatch.
  if (!isProOrAbove(tenant.plan)) {
    logger.info({ module: 'notify', fn: 'notifyBINSequenceAlert', tenantId: tenant.id, plan: tenant.plan }, 'BIN sequence alert suppressed - plan not Pro/Agency');
    return;
  }

   // ── Cooldown Check (30 دقيقة) ─────────────────────────────────────
  // tenantData is declared here (function scope), not inside the try block,
  // because it's read later for the webhook-merge check and the webhookTenant
  // spread. A `const` declared inside try{} is block-scoped and throws a
  // ReferenceError once referenced outside — that was silently breaking
  // webhook delivery and cooldown persistence on every non-suppressed alert.
  let tenantData = null;
  try {
    tenantData = await db.tenant.findUnique({
      where:  { id: tenant.id },
      select: { lastAlertSentAt: true, webhookUrl: true, webhookType: true },
    });

    if (tenantData?.lastAlertSentAt) {
      const elapsed   = Date.now() - new Date(tenantData.lastAlertSentAt).getTime();
      const cooldownMs = 30 * 60 * 1000;
      if (elapsed < cooldownMs) {
        const remaining = Math.ceil((cooldownMs - elapsed) / 60000);
        logger.debug({ module: 'notify', fn: 'notifyBINSequenceAlert', tenantId: tenant.id, remainingMinutes: remaining }, 'BIN alert suppressed - cooldown active');
        return;
      }
    }
  } catch (err) {
    logger.error({ module: 'notify', fn: 'notifyBINSequenceAlert', tenantId: tenant.id, error: err.message }, 'Cooldown check failed');
    // Fail open — بنكمل الإرسال لو الـ DB check فشل
  }

  const LAYER_NAMES = {
    0: 'Active Attack Wave — Blocked Prefix',
    1: 'Rapid BIN Velocity Attack',
    2: 'Sequential Card Scan — Brute Force',
    3: 'Distributed Multi-Source Attack',
  };

  const promises = [];

  // ── Email ──────────────────────────────────────────────────────────
  // TODO: استبدل بـ sendBINSequenceAlertEmail مخصص عند بناء template
  promises.push(
    sendAttackAlertEmail(
      tenant,
      alert.cardsCount,
      0,
      10,
      {
        alertType:  'bin_sequence',
        layerName:  LAYER_NAMES[alert.layer] ?? 'Unknown Attack',
        binPrefix:  alert.binPrefix + 'xx',
        layer:      alert.layer,
        riskAddition: alert.riskAddition,
      }
    ).catch(err => logger.error({ module: 'notify', fn: 'notifyBINSequenceAlert', tenantEmail: tenant.email, error: err.message }, 'BIN email failed'))
  );

  // ── Webhook ────────────────────────────────────────────────────────
  if (tenant.webhookUrl || tenantData?.webhookUrl) {
    const webhookTenant = {
      ...tenant,
      webhookUrl:  tenant.webhookUrl  || tenantData?.webhookUrl,
      webhookType: tenant.webhookType || tenantData?.webhookType,
    };
    promises.push(
      sendWebhookAlert(
        webhookTenant,
        alert.cardsCount,
        0,
        10,
        {
          alertType:  'bin_sequence',
          layerName:  LAYER_NAMES[alert.layer] ?? 'Unknown Attack',
          binPrefix:  alert.binPrefix + 'xx',
          layer:      alert.layer,
          riskAddition: alert.riskAddition,
        }
      ).catch(err => logger.error({ module: 'notify', fn: 'notifyBINSequenceAlert', tenantId: tenant.id, error: err.message }, 'BIN webhook failed'))
    );
  }

  await Promise.all(promises);

  // ── تحديث lastAlertSentAt ──────────────────────────────────────────
  await db.tenant.update({
    where: { id: tenant.id },
    data:  { lastAlertSentAt: new Date() },
  }).catch(err => logger.error({ module: 'notify', fn: 'notifyBINSequenceAlert', error: err.message }, 'Failed to update lastAlertSentAt'));
}

/**
 * Sends a PayPal suspicious transaction alert to all configured channels.
 * Uses an independent cooldown key (paypal_alert) separate from BIN alerts.
 *
 * Tiered cooldown by risk score:
 *   >= 85 → no cooldown (critical)
 *   >= 70 → 30 minutes
 *   <  70 → suppressed (digest only, future phase)
 *
 * @param {object} tenant    - Tenant object (id, email, webhookUrl, webhookType)
 * @param {object} alertData - { paypalTxnId, brand, last4, cardCountry, amount,
 *                               currency, riskScore, decision, flags, estimatedSavings }
 * @returns {Promise<void>}
 */
async function notifyPaypalAlert(tenant, alertData) {
  // Plan gate — must be the FIRST check in this function, before the
  // risk-tier check and before any cooldown DB query. Defense-in-depth:
  // risk.js's /enrich call site has no plan check of its own, so this
  // is the only gate standing between detection and dispatch.
  if (!isProOrAbove(tenant.plan)) {
    logger.info({ module: 'notify', fn: 'notifyPaypalAlert', tenantId: tenant.id, plan: tenant.plan }, 'PayPal alert suppressed - plan not Pro/Agency');
    return;
  }

  const { riskScore = 0 } = alertData;

  // ── Tier check — suppress low-risk silently ───────────────────────
  if (riskScore < 70) {
    logger.debug({ module: 'notify', fn: 'notifyPaypalAlert', tenantId: tenant.id, riskScore }, 'PayPal alert suppressed - score below threshold');
    return;
  }

  // ── Independent cooldown key: 'paypal_alert' ──────────────────────
  // Avoids collision with lastAlertSentAt used by BIN sequence alerts
  const COOLDOWN_FIELD = 'lastPaypalAlertAt';
  const cooldownMs     = riskScore >= 85 ? 0 : 30 * 60 * 1000;

  if (cooldownMs > 0) {
    try {
      const tenantData = await db.tenant.findUnique({
        where:  { id: tenant.id },
        select: { [COOLDOWN_FIELD]: true, webhookUrl: true, webhookType: true },
      });

      if (tenantData?.[COOLDOWN_FIELD]) {
        const elapsed = Date.now() - new Date(tenantData[COOLDOWN_FIELD]).getTime();
        if (elapsed < cooldownMs) {
          const remaining = Math.ceil((cooldownMs - elapsed) / 60000);
          logger.debug({ module: 'notify', fn: 'notifyPaypalAlert', tenantId: tenant.id, remainingMinutes: remaining }, 'PayPal alert suppressed - cooldown active');
          return;
        }
      }

      // Merge webhookUrl/Type if missing from caller
      if (!tenant.webhookUrl && tenantData?.webhookUrl) {
        tenant.webhookUrl  = tenantData.webhookUrl;
        tenant.webhookType = tenantData.webhookType;
      }
    } catch (err) {
      logger.error({ module: 'notify', fn: 'notifyPaypalAlert', tenantId: tenant.id, error: err.message }, 'PayPal cooldown check failed');
      // Fail open — send the alert if DB check fails
    }
  }

  const promises = [];

  // ── Email ─────────────────────────────────────────────────────────
  promises.push(
    sendPaypalAlertEmail(tenant, alertData)
      .catch(err => logger.error({ module: 'notify', fn: 'notifyPaypalAlert', tenantEmail: tenant.email, error: err.message }, 'PayPal email failed'))
  );

  // ── Webhook ───────────────────────────────────────────────────────
  if (tenant.webhookUrl) {
    promises.push(
      sendWebhookAlert(
        tenant,
        1,
        alertData.estimatedSavings || 0,
        0,
        {
          alertType:    'paypal_suspicious',
          paypalTxnId:  alertData.paypalTxnId,
          riskScore:    alertData.riskScore,
          decision:     alertData.decision,
          cardCountry:  alertData.cardCountry,
          amount:       alertData.amount,
          flags:        alertData.flags,
        }
      ).catch(err => logger.error({ module: 'notify', fn: 'notifyPaypalAlert', tenantId: tenant.id, error: err.message }, 'PayPal webhook failed'))
    );
  }

  await Promise.all(promises);

  // ── Update independent cooldown timestamp ─────────────────────────
  if (cooldownMs > 0) {
    await db.tenant.update({
      where: { id: tenant.id },
      data:  { [COOLDOWN_FIELD]: new Date() },
    }).catch(err => logger.error({ module: 'notify', fn: 'notifyPaypalAlert', cooldownField: COOLDOWN_FIELD, error: err.message }, 'Failed to update cooldown timestamp'));
  }
}

module.exports = { notifyTenant, notifyBINSequenceAlert, notifyPaypalAlert };