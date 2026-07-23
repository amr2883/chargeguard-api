// src/lib/cloudflareRanges.js
//
// Single source of truth for Cloudflare's published IP ranges. Fetched
// once at process startup and refreshed daily thereafter; never fetched
// inline on a request path. Exposed to the WooCommerce plugin via the
// authenticated GET /api/risk/cloudflare-ranges endpoint (routes/risk.js),
// which the plugin's WP-Cron job polls instead of hitting cloudflare.com
// directly — see ChargeGuard_Trusted_Proxy::refresh_cf_ranges() in
// includes/class-trusted-proxy.php.

const https = require('https');
const logger = require('./logger');

const CF_IPV4_URL = 'https://www.cloudflare.com/ips-v4';
const CF_IPV6_URL = 'https://www.cloudflare.com/ips-v6';
const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000; // daily
const FETCH_TIMEOUT_MS = 10_000;

// Hardcoded fallback — used only until the first successful fetch
// completes (e.g. immediately after a fresh deploy/restart), or if every
// subsequent daily refresh fails and no previously-fetched cache exists.
// This is the ONLY hardcoded copy left in the whole system; the plugin's
// fallback_cf_ranges() remains as ITS OWN last resort for when the
// backend itself is unreachable — the two are allowed to be identical
// lists without that being "the duplication" this fix addresses, because
// neither one is a primary source anymore.
const FALLBACK_RANGES = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

// Module-level cache. Starts as the fallback so isPlausibleClientIp() and
// the new endpoint always have *something* to return, even before the
// first fetch below completes.
let cachedRanges = FALLBACK_RANGES;
let lastFetchedAt = null;
let lastFetchSucceeded = false;

function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: FETCH_TIMEOUT_MS }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`Unexpected status ${res.statusCode} from ${url}`));
        return;
      }
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve(data));
    });
    req.on('timeout', () => req.destroy(new Error(`Timeout fetching ${url}`)));
    req.on('error', reject);
  });
}

function parseRangeList(body) {
  return body
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== '' && line.includes('/'));
}

/**
 * Fetches both Cloudflare range lists and updates the module-level cache
 * on success. Never throws — failures are logged and the previous cache
 * (fetched ranges, or the hardcoded fallback if nothing has ever
 * succeeded) is left in place, mirroring the plugin's own
 * refresh_cf_ranges() "keep previous cached list on failure" behavior.
 */
async function refreshCloudflareRanges() {
  try {
    const [v4Body, v6Body] = await Promise.all([
      fetchUrl(CF_IPV4_URL),
      fetchUrl(CF_IPV6_URL),
    ]);
    const ranges = [...parseRangeList(v4Body), ...parseRangeList(v6Body)];
    if (ranges.length > 0) {
      cachedRanges = ranges;
      lastFetchedAt = new Date();
      lastFetchSucceeded = true;
      logger.info({ module: 'cloudflareRanges', count: ranges.length }, 'Cloudflare IP ranges refreshed');
    } else {
      logger.warn({ module: 'cloudflareRanges' }, 'Cloudflare IP range refresh returned zero ranges — keeping previous cache');
    }
  } catch (err) {
    logger.error({ module: 'cloudflareRanges', error: err.message }, 'Cloudflare IP range refresh failed — keeping previous cache (or hardcoded fallback)');
  }
}

/** Current cached ranges — always returns an array, never blocks. */
function getCloudflareRanges() {
  return cachedRanges;
}

/** Metadata for observability/debugging (not currently exposed via API). */
function getCloudflareRangesMeta() {
  return { lastFetchedAt, lastFetchSucceeded, count: cachedRanges.length };
}

// Kick off the first fetch immediately at process startup (fire-and-forget
// — nothing in the request path awaits this), then daily thereafter.
refreshCloudflareRanges();
const intervalHandle = setInterval(refreshCloudflareRanges, REFRESH_INTERVAL_MS);
if (typeof intervalHandle.unref === 'function') intervalHandle.unref();

module.exports = {
  getCloudflareRanges,
  getCloudflareRangesMeta,
  refreshCloudflareRanges,
};