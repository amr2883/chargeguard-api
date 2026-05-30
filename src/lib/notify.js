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
      .catch(err => console.error(`[Notify] Email failed for ${tenant.email}:`, err.message))
  );

  // Webhook — only if configured
  if (tenant.webhookUrl) {
    promises.push(
      sendWebhookAlert(tenant, attackCount, savedAmount, windowMinutes)
        .catch(err => console.error(`[Notify] Webhook failed for ${tenant.id}:`, err.message))
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
  // ── Cooldown Check (30 دقيقة) ─────────────────────────────────────
  try {
    const tenantData = await db.tenant.findUnique({
      where:  { id: tenant.id },
      select: { lastAlertSentAt: true, webhookUrl: true, webhookType: true },
    });

    if (tenantData?.lastAlertSentAt) {
      const elapsed   = Date.now() - new Date(tenantData.lastAlertSentAt).getTime();
      const cooldownMs = 30 * 60 * 1000;
      if (elapsed < cooldownMs) {
        const remaining = Math.ceil((cooldownMs - elapsed) / 60000);
        console.log(`[Notify] BIN alert suppressed for ${tenant.id} — cooldown (${remaining}m remaining)`);
        return;
      }
    }
  } catch (err) {
    console.error(`[Notify] Cooldown check failed for ${tenant.id}:`, err.message);
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
    ).catch(err => console.error(`[Notify] BIN email failed for ${tenant.email}:`, err.message))
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
      ).catch(err => console.error(`[Notify] BIN webhook failed for ${tenant.id}:`, err.message))
    );
  }

  await Promise.all(promises);

  // ── تحديث lastAlertSentAt ──────────────────────────────────────────
  await db.tenant.update({
    where: { id: tenant.id },
    data:  { lastAlertSentAt: new Date() },
  }).catch(err => console.error(`[Notify] Failed to update lastAlertSentAt:`, err.message));
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
  const { riskScore = 0 } = alertData;

  // ── Tier check — suppress low-risk silently ───────────────────────
  if (riskScore < 70) {
    console.log(`[Notify] PayPal alert suppressed for ${tenant.id} — score ${riskScore} below threshold`);
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
          console.log(`[Notify] PayPal alert suppressed for ${tenant.id} — cooldown (${remaining}m remaining)`);
          return;
        }
      }

      // Merge webhookUrl/Type if missing from caller
      if (!tenant.webhookUrl && tenantData?.webhookUrl) {
        tenant.webhookUrl  = tenantData.webhookUrl;
        tenant.webhookType = tenantData.webhookType;
      }
    } catch (err) {
      console.error(`[Notify] PayPal cooldown check failed for ${tenant.id}:`, err.message);
      // Fail open — send the alert if DB check fails
    }
  }

  const promises = [];

  // ── Email ─────────────────────────────────────────────────────────
  promises.push(
    sendPaypalAlertEmail(tenant, alertData)
      .catch(err => console.error(`[Notify] PayPal email failed for ${tenant.email}:`, err.message))
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
      ).catch(err => console.error(`[Notify] PayPal webhook failed for ${tenant.id}:`, err.message))
    );
  }

  await Promise.all(promises);

  // ── Update independent cooldown timestamp ─────────────────────────
  if (cooldownMs > 0) {
    await db.tenant.update({
      where: { id: tenant.id },
      data:  { [COOLDOWN_FIELD]: new Date() },
    }).catch(err => console.error(`[Notify] Failed to update ${COOLDOWN_FIELD}:`, err.message));
  }
}

module.exports = { notifyTenant, notifyBINSequenceAlert, notifyPaypalAlert };