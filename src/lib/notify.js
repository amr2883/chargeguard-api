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

module.exports = { notifyTenant };