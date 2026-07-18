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
const dns    = require('dns').promises;
const net    = require('net');

// ── Tuneable constants ──────────────────────────────────────────────────────
const RETRIES          = 3;
const RETRY_DELAY_MS   = 2000;  // 2s initial, doubles each retry
const RETRYABLE_CODES  = new Set([429, 500, 502, 503, 504]);
const FETCH_TIMEOUT_MS = 5000;  // 5s max for webhooks
const DNS_TIMEOUT_MS   = 2000;  // fail closed if resolution is slow/hanging

// ── SSRF Protection (C2 fix) ────────────────────────────────────────────────
// Mirrors the WordPress plugin's chargeguard_host_is_private_or_reserved()
// (includes/class-admin-settings.php): literal-IP fast path, A+AAAA
// resolution for hostnames, every resolved address checked against
// private/reserved ranges, IPv4-mapped IPv6 unwrapping, fail-closed on any
// resolution error or timeout. This mirroring is necessary, not redundant
// with the plugin's own check — the backend is the actual network egress
// point for the outbound webhook request, and is reachable directly via API
// key (bypassing the WordPress plugin's UI and its validation entirely), so
// it must enforce this independently rather than trust the caller.

const IPV4_PRIVATE_RESERVED_CIDRS = [
  '0.0.0.0/8',       // "this" network
  '10.0.0.0/8',       // RFC1918
  '100.64.0.0/10',    // CGNAT (RFC6598)
  '127.0.0.0/8',       // loopback
  '169.254.0.0/16',    // link-local (includes cloud metadata: 169.254.169.254)
  '172.16.0.0/12',     // RFC1918
  '192.0.0.0/24',      // IETF protocol assignments
  '192.168.0.0/16',    // RFC1918
  '198.18.0.0/15',     // benchmarking (RFC2544)
  '224.0.0.0/4',       // multicast
  '240.0.0.0/4',       // reserved
];

function ipv4ToLong(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return null;
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function ipv4InCidr(ip, cidr) {
  const [range, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const ipLong    = ipv4ToLong(ip);
  const rangeLong = ipv4ToLong(range);
  if (ipLong === null || rangeLong === null) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipLong & mask) === (rangeLong & mask);
}

function isPrivateOrReservedIPv4(ip) {
  return IPV4_PRIVATE_RESERVED_CIDRS.some((cidr) => ipv4InCidr(ip, cidr));
}

// Unwraps ::ffff:a.b.c.d (RFC4291 §2.5.5.2) to its embedded IPv4 form so it
// is checked against the same ranges as a literal IPv4 address — an
// IPv4-mapped IPv6 address IS the same network address as its IPv4 form,
// and this mapping has historically been a real SSRF/allowlist-bypass
// vector when left unhandled.
function unwrapIpv4MappedIpv6(ip) {
  const match = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  return match ? match[1] : null;
}

function isPrivateOrReservedIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true; // loopback / unspecified
  const mapped = unwrapIpv4MappedIpv6(lower);
  if (mapped) return isPrivateOrReservedIPv4(mapped);   // ::ffff:0:0/96
  if (/^f[cd][0-9a-f]{2}:/i.test(lower)) return true;    // fc00::/7 (unique local)
  if (/^fe[89ab][0-9a-f]:/i.test(lower)) return true;    // fe80::/10 (link-local)
  return false;
}

function isPrivateOrReservedIP(ip) {
  const version = net.isIP(ip);
  if (version === 4) return isPrivateOrReservedIPv4(ip);
  if (version === 6) return isPrivateOrReservedIPv6(ip);
  return true; // not a recognizable IP literal — fail closed
}

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('DNS_TIMEOUT')), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * Resolves every A and AAAA record for hostname and checks each resolved
 * address against private/reserved ranges. Fails closed (treats as
 * private/blocked) on any DNS error or timeout — an unresolvable or
 * slow-resolving hostname is never treated as safe. Checking both record
 * types matters: a hostname could have a public A record (which alone
 * would pass) alongside a private/link-local AAAA record, and if delivery
 * later prefers or falls back to IPv6, that unchecked address is reachable.
 *
 * @param {string} hostname
 * @returns {Promise<{ blocked: boolean, reason?: string }>}
 */
async function resolveAndCheckHostname(hostname) {
  let aRecords = [];
  let aaaaRecords = [];
  let aError = null;
  let aaaaError = null;

  try {
    aRecords = await withTimeout(dns.resolve4(hostname), DNS_TIMEOUT_MS);
  } catch (err) {
    aError = err;
  }
  try {
    aaaaRecords = await withTimeout(dns.resolve6(hostname), DNS_TIMEOUT_MS);
  } catch (err) {
    aaaaError = err;
  }

  // Both lookups failed (or timed out) — cannot confirm safety, fail closed.
  if (aError && aaaaError) {
    return { blocked: true, reason: 'DNS resolution failed or timed out' };
  }

  const allAddresses = [...aRecords, ...aaaaRecords];
  if (allAddresses.length === 0) {
    return { blocked: true, reason: 'Hostname did not resolve to any address' };
  }

  for (const ip of allAddresses) {
    if (isPrivateOrReservedIP(ip)) {
      return { blocked: true, reason: 'Hostname resolves to an internal or reserved address' };
    }
  }

  return { blocked: false };
}

// ── URL Validation ─────────────────────────────────────────────────────────

/**
 * Validates a webhook URL for safety and format, including DNS resolution
 * of hostnames against private/reserved IP ranges (C2 fix). Async because
 * DNS resolution is inherently async — callers must `await` this; it is no
 * longer a synchronous check.
 *
 * @param {string} url
 * @returns {Promise<{ valid: boolean, error?: string }>}
 */
async function validateWebhookUrl(url) {
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

  let hostname = parsed.hostname.toLowerCase();
  if (hostname === 'localhost') {
    return { valid: false, error: 'Internal or private IPs are not allowed' };
  }

  // Strip IPv6 literal brackets ([::1] -> ::1) before checking.
  hostname = hostname.replace(/^\[|\]$/g, '');

  const ipVersion = net.isIP(hostname);
  if (ipVersion !== 0) {
    // Hostname is itself a literal IP — check directly, no DNS involved.
    if (isPrivateOrReservedIP(hostname)) {
      return { valid: false, error: 'Internal or private IPs are not allowed' };
    }
    return { valid: true };
  }

  const result = await resolveAndCheckHostname(hostname);
  if (result.blocked) {
    return { valid: false, error: 'Internal or private IPs are not allowed' };
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

// ── PayPal Slack Payload Builder ───────────────────────────────────────────

function buildSlackPaypalPayload(tenant, ctx) {
  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';

  const txnDisplay    = ctx.paypalTxnId ? ctx.paypalTxnId.slice(-8).toUpperCase() : '—';
  const amountDisplay = ctx.amount ? `$${Number(ctx.amount).toFixed(2)}` : '—';
  const topFlag       = ctx.flags?.[0]?.text || null;
  const decisionEmoji = ctx.decision === 'block' ? '🚫' : '⚠️';
  const decisionLabel = ctx.decision === 'block' ? 'Blocked' : 'Flagged for Review';

  const fields = [
    { type: 'mrkdwn', text: `*Transaction*\n#${txnDisplay}` },
    { type: 'mrkdwn', text: `*Amount*\n${amountDisplay}` },
    { type: 'mrkdwn', text: `*Card Origin*\n${ctx.cardCountry || 'Unknown'}` },
    { type: 'mrkdwn', text: `*Risk Score*\n${ctx.riskScore}/100` },
  ];
  if (topFlag) fields.push({ type: 'mrkdwn', text: `*Primary Reason*\n${topFlag}` });

  return {
    attachments: [{
      color: ctx.decision === 'block' ? '#dc2626' : '#d97706',
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `🛡️ *ChargeGuard PayPal Shield* — Suspicious transaction intercepted on \`${storeDisplay}\``
          }
        },
        { type: 'section', fields },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `${decisionEmoji} *Decision: ${decisionLabel}* — Your store is running normally. No action required.`
          }
        },
        {
          type: 'actions',
          elements: [{
            type: 'button',
            text: { type: 'plain_text', text: 'View in Dashboard →' },
            url: 'https://chargeguard-api.onrender.com/api/dashboard/page',
            style: 'danger'
          }]
        }
      ]
    }]
  };
}

// ── PayPal Discord Payload Builder ─────────────────────────────────────────

function buildDiscordPaypalPayload(tenant, ctx) {
  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';

  const txnDisplay = ctx.paypalTxnId ? ctx.paypalTxnId.slice(-8).toUpperCase() : '—';
  const topFlag    = ctx.flags?.[0]?.text || 'Suspicious activity pattern';
  const embedColor = ctx.decision === 'block' ? 14423100 : 14263066;

  return {
    username: 'ChargeGuard',
    embeds: [{
      title: '🛡️ PayPal Shield — Transaction Intercepted',
      description: `Suspicious PayPal transaction stopped on **${storeDisplay}** before processing.`,
      color: embedColor,
      fields: [
        { name: 'Transaction',    value: `#${txnDisplay}`,                                    inline: true  },
        { name: 'Amount',         value: ctx.amount ? `$${Number(ctx.amount).toFixed(2)}` : '—', inline: true },
        { name: 'Card Origin',    value: ctx.cardCountry || 'Unknown',                        inline: true  },
        { name: 'Risk Score',     value: `${ctx.riskScore}/100`,                              inline: true  },
        { name: 'Decision',       value: ctx.decision === 'block' ? '🚫 Blocked' : '⚠️ Review', inline: true },
        { name: 'Primary Reason', value: topFlag,                                             inline: false },
      ],
      footer:    { text: '✅ Your store is running normally. No action required.' },
      timestamp: new Date().toISOString(),
      url: 'https://chargeguard-api.onrender.com/api/dashboard/page'
    }]
  };
}

// ── PayPal Custom Payload Builder ──────────────────────────────────────────

function buildCustomPaypalPayload(tenant, ctx) {
  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';

  return {
    event:     'paypal_suspicious_transaction',
    timestamp: new Date().toISOString(),
    store:     storeDisplay,
    data: {
      alertType:   'paypal_suspicious',
      paypalTxnId: ctx.paypalTxnId  || null,
      riskScore:   ctx.riskScore    || 0,
      decision:    ctx.decision     || 'review',
      cardCountry: ctx.cardCountry  || null,
      amount:      ctx.amount       || null,
      flags:       ctx.flags        || [],
    }
  };
}

// ── Main Dispatch Function ─────────────────────────────────────────────────

/**
 * Sends a webhook notification for a detected attack or PayPal alert.
 * Fire-and-forget — failures are logged but never throw to the caller.
 *
 * @param {object}          tenant         - Tenant (webhookUrl, webhookType, id)
 * @param {number}          attackCount    - Blocked attempts (standard alerts)
 * @param {number}          savedAmount    - Estimated savings USD (standard alerts)
 * @param {number}          [windowMinutes=10]
 * @param {boolean|object}  [extraContext=false] - true = test | object = PayPal context
 * @returns {Promise<void>}
 */
async function sendWebhookAlert(tenant, attackCount, savedAmount, windowMinutes = 10, extraContext = false) {
  if (!tenant.webhookUrl) return;

  const url  = tenant.webhookUrl;
  const type = tenant.webhookType || 'custom';

  // C2 fix: re-validate at delivery time, not just at save time. A webhook
  // URL saved once may be delivered to repeatedly over the tenant's entire
  // lifetime — the gap between save-time validation and any given delivery
  // can be days, which is more than enough time for DNS to be repointed at
  // a private/internal address (DNS rebinding). This re-check closes that
  // window at the point that actually matters: immediately before the
  // outbound request is made.
  const revalidation = await validateWebhookUrl(url);
  if (!revalidation.valid) {
    logger.warn(
      { tenantId: tenant.id, reason: revalidation.error },
      'WEBHOOK_URL_FAILED_DELIVERY_TIME_REVALIDATION'
    );
    return;
  }

  const isPaypal = extraContext !== null
                && typeof extraContext === 'object'
                && extraContext.alertType === 'paypal_suspicious';
  const isTest   = extraContext === true;

  let payload;
  if (isPaypal) {
    switch (type) {
      case 'slack':   payload = buildSlackPaypalPayload(tenant, extraContext);   break;
      case 'discord': payload = buildDiscordPaypalPayload(tenant, extraContext); break;
      default:        payload = buildCustomPaypalPayload(tenant, extraContext);  break;
    }
  } else {
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
        method:   'POST',
        headers:  { 'Content-Type': 'application/json' },
        body:     JSON.stringify(payload),
        signal:   controller.signal,
        redirect: 'manual', // C2 fix: never follow redirects — see justification
      });

      clearTimeout(timeoutId);

      // fetch() with redirect: 'manual' does not throw on a 3xx; it returns
      // an opaqueredirect-style response instead. Treat any redirect as a
      // hard failure rather than resolving/following it ourselves — a
      // publicly-reachable URL that 302s to an internal address is a
      // classic SSRF vector that a literal or DNS check alone cannot catch,
      // since the redirect target is only known at request time.
      if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
        console.error(`${label} ❌ Refused to follow redirect response — not retrying`);
        throw new Error('Webhook URL returned a redirect; redirects are not followed for security reasons.');
      }

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

      // M1 fix: native fetch() never attaches err.response — that's an
      // Axios convention this code incorrectly assumed. Any thrown
      // exception here is a real network-level failure (DNS, connection
      // reset, TLS) or a deliberate throw from the response-handling
      // branch above (redirect refusal, non-retryable HTTP status,
      // exhausted retryable-status attempts) — all of those are already
      // correctly gated before reaching this catch, so anything landing
      // here that isn't an AbortError should be retried like any other
      // transient failure, up to the attempt cap.
      if (err.name === 'AbortError') {
        console.error(`${label} ❌ Attempt ${attempt} timed out after ${FETCH_TIMEOUT_MS}ms`);
      } else {
        console.warn(`${label} ⚠️ Attempt ${attempt} failed: ${err.message}`);
      }

      if (attempt === RETRIES) {
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