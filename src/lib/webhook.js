'use strict';

/**
 * webhook.js — ChargeGuard Webhook Notifications
 * ──────────────────────────────────────────────
 * Sends attack alerts to Slack, Discord, or custom webhook URLs.
 * Uses same fire-and-forget + retry pattern as email.js.
 *
 * Exported:
 *   - sendWebhookAlert(tenant, attackCount, savedAmount, windowMinutes, isTest)
 *   - validateWebhookUrl(url)
 */

const logger = require('./logger');

// ── Tuneable constants ──────────────────────────────────────────────────────
const RETRIES          = 3;
const RETRY_DELAY_MS   = 2000;  // 2s initial, doubles each retry
const RETRYABLE_CODES  = new Set([429, 500, 502, 503, 504]);
const FETCH_TIMEOUT_MS = 5000;  // 5s max for webhooks

// ── SSRF Blocklist ─────────────────────────────────────────────────────────
const SSRF_BLOCKLIST = [
  /^localhost$/i,
  /^127\.\d+\.\d+\.\d+$/,
  /^0\.0\.0\.0$/,
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /^169\.254\.\d+\.\d+$/,
  /^::1$/,
  /^fc00:/i,
  /^fd00:/i,
];

// ── URL Validation ─────────────────────────────────────────────────────────

/**
 * Validates a webhook URL for safety and format.
 * @param {string} url
 * @returns {{ valid: boolean, error?: string }}
 */
function validateWebhookUrl(url) {
  if (!url || typeof url !== 'string') {
    return { valid: false, error: 'URL is required' };
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch (_) {
    return { valid: false, error: 'Invalid URL format' };
  }

  if (parsed.protocol !== 'https:') {
    return { valid: false, error: 'Only HTTPS URLs are allowed' };
  }

  const hostname = parsed.hostname.toLowerCase();
  for (const pattern of SSRF_BLOCKLIST) {
    if (pattern.test(hostname)) {
      return { valid: false, error: 'Internal or private IPs are not allowed' };
    }
  }

  return { valid: true };
}

// ── Slack Payload Builder ──────────────────────────────────────────────────

function buildSlackPayload(tenant, attackCount, savedAmount, windowMinutes, isTest) {
  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';

  const savedFormatted = savedAmount.toLocaleString('en-US', {
    style: 'currency', currency: 'USD', minimumFractionDigits: 2,
  });

  const timeStr = new Date().toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
    timeZone: 'UTC', timeZoneName: 'short',
  });

  const prefix = isTest ? '[TEST] ' : '';

  return {
    attachments: [{
      color: '#dc2626',
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `${prefix}🚨 *ChargeGuard Alert* — Card testing attack detected on \`${storeDisplay}\``
          }
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Attacks Blocked*\n${attackCount} attempts` },
            { type: 'mrkdwn', text: `*Est. Savings*\n${savedFormatted}` },
            { type: 'mrkdwn', text: `*Window*\nLast ${windowMinutes} minutes` },
            { type: 'mrkdwn', text: `*Time*\n${timeStr}` }
          ]
        },
        {
          type: 'actions',
          elements: [{
            type: 'button',
            text: { type: 'plain_text', text: 'View Dashboard →' },
            url: 'https://chargeguard-api.onrender.com/api/dashboard/page',
            style: 'danger'
          }]
        }
      ]
    }]
  };
}

// ── Discord Payload Builder ────────────────────────────────────────────────

function buildDiscordPayload(tenant, attackCount, savedAmount, windowMinutes, isTest) {
  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';

  const savedFormatted = savedAmount.toLocaleString('en-US', {
    style: 'currency', currency: 'USD', minimumFractionDigits: 2,
  });

  const prefix = isTest ? '[TEST] ' : '';

  return {
    username: 'ChargeGuard',
    embeds: [{
      title: `${prefix}🚨 Attack Detected`,
      description: `Card testing attack on **${storeDisplay}**`,
      color: 14233344, // #D9534F decimal
      fields: [
        { name: 'Attacks Blocked', value: `${attackCount} attempts`, inline: true },
        { name: 'Est. Savings',    value: savedFormatted,             inline: true },
        { name: 'Window',          value: `${windowMinutes} minutes`,  inline: true }
      ],
      footer: { text: 'ChargeGuard Security' },
      timestamp: new Date().toISOString(),
      url: 'https://chargeguard-api.onrender.com/api/dashboard/page'
    }]
  };
}

// ── Custom Payload Builder ─────────────────────────────────────────────────

function buildCustomPayload(tenant, attackCount, savedAmount, windowMinutes, isTest) {
  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';

  return {
    event: isTest ? 'attack_detected_test' : 'attack_detected',
    timestamp: new Date().toISOString(),
    store: storeDisplay,
    data: {
      attackCount,
      savedAmount: Math.round(savedAmount * 100) / 100,
      windowMinutes,
      isTest: !!isTest
    }
  };
}

// ── Main Dispatch Function ─────────────────────────────────────────────────

/**
 * Sends a webhook notification for a detected attack.
 * Fire-and-forget — failures are logged but never throw to the caller.
 *
 * @param {object}  tenant        - Tenant object (must have webhookUrl, webhookType, id)
 * @param {number}  attackCount   - Number of blocked attempts
 * @param {number}  savedAmount   - Estimated savings in USD
 * @param {number}  [windowMinutes=10] - Time window in minutes
 * @param {boolean} [isTest=false]     - If true, sends a test notification
 * @returns {Promise<void>}
 */
async function sendWebhookAlert(tenant, attackCount, savedAmount, windowMinutes = 10, isTest = false) {
  if (!tenant.webhookUrl) return;

  const url = tenant.webhookUrl;
  const type = tenant.webhookType || 'custom';

  // Build payload based on platform type
  let payload;
  switch (type) {
    case 'slack':
      payload = buildSlackPayload(tenant, attackCount, savedAmount, windowMinutes, isTest);
      break;
    case 'discord':
      payload = buildDiscordPayload(tenant, attackCount, savedAmount, windowMinutes, isTest);
      break;
    default:
      payload = buildCustomPayload(tenant, attackCount, savedAmount, windowMinutes, isTest);
  }

  const label = `[Webhook ${tenant.id.slice(0, 8)}]`;
  let lastError;

  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    const delay = RETRY_DELAY_MS * Math.pow(2, attempt - 1); // exponential backoff

    try {
      console.log(`${label} 📡 Attempt ${attempt}/${RETRIES} — POST to ${type}`);

      const controller = new AbortController();
      const timeoutId  = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

      const response = await fetch(url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(payload),
        signal:  controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        console.log(`${label} ✅ Sent successfully — ${response.status}`);
        return;
      }

      // Non-retryable client errors
      if (response.status >= 400 && response.status < 500 && response.status !== 429) {
        console.error(`${label} ❌ Failed with ${response.status} — not retrying`);
        throw new Error(`HTTP ${response.status}: ${await response.text().catch(() => '')}`);
      }

      if (!RETRYABLE_CODES.has(response.status) || attempt === RETRIES) {
        throw new Error(`HTTP ${response.status}: ${await response.text().catch(() => '')}`);
      }

      console.warn(`${label} ⚠️ Attempt ${attempt} failed with ${response.status}`);

    } catch (err) {
      lastError = err;

      if (err.name === 'AbortError') {
        console.error(`${label} ❌ Attempt ${attempt} timed out after ${FETCH_TIMEOUT_MS}ms`);
      } else if (!RETRYABLE_CODES.has(err.response?.status) || attempt === RETRIES) {
        break;
      }
    }

    if (attempt < RETRIES) {
      console.log(`${label} ⏳ Retrying in ${delay / 1000}s...`);
      await new Promise(res => setTimeout(res, delay));
    }
  }

  console.error(`${label} ❌ All ${RETRIES} attempts failed. Last error:`, lastError?.message);
  throw lastError;
}

module.exports = { sendWebhookAlert, validateWebhookUrl };