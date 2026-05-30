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

const { sendAttackAlertEmail } = require('./email');
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

module.exports = { notifyTenant, notifyBINSequenceAlert };