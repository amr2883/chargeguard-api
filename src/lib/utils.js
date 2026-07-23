// src/lib/utils.js
const crypto = require('crypto');
const net = require('net');
const { getCloudflareRanges } = require('./cloudflareRanges');

// Single source of truth is now src/lib/cloudflareRanges.js, which fetches
// and caches Cloudflare's published ranges daily and is also exposed to
// the WooCommerce plugin via the authenticated GET
// /api/risk/cloudflare-ranges endpoint (see routes/risk.js) — the
// plugin's WP-Cron job polls that endpoint instead of hitting
// cloudflare.com directly (ChargeGuard_Trusted_Proxy::refresh_cf_ranges()
// in class-trusted-proxy.php). This closes the two-hardcoded-copies drift
// risk that used to exist between this file and the plugin.

const PRIVATE_RESERVED_RANGES = [
  '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
  '169.254.0.0/16', '100.64.0.0/10', '0.0.0.0/8', '192.0.0.0/24',
  '192.0.2.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
  '224.0.0.0/4', '240.0.0.0/4',
  '::1/128', 'fe80::/10', 'fc00::/7', '::/128', '64:ff9b::/96',
];

function ipToBits(ip) {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return null;
    return { bytes: Buffer.from(parts), family: 4 };
  }
  if (net.isIPv6(ip)) {
    // Expand :: shorthand into 8 hextets, then pack into a 16-byte buffer.
    const [head, tail = ''] = ip.split('::');
    const headParts = head ? head.split(':').filter(Boolean) : [];
    const tailParts = tail ? tail.split(':').filter(Boolean) : [];
    const missing = 8 - headParts.length - tailParts.length;
    if (missing < 0) return null;
    const full = [...headParts, ...Array(missing).fill('0'), ...tailParts];
    if (full.length !== 8) return null;
    const buf = Buffer.alloc(16);
    for (let i = 0; i < 8; i++) {
      const val = parseInt(full[i], 16);
      if (Number.isNaN(val)) return null;
      buf.writeUInt16BE(val, i * 2);
    }
    return { bytes: buf, family: 6 };
  }
  return null;
}

function ipInCidr(ip, cidr) {
  const [subnet, maskStr] = cidr.split('/');
  const mask = parseInt(maskStr, 10);
  const ipParsed = ipToBits(ip);
  const subnetParsed = ipToBits(subnet);
  if (!ipParsed || !subnetParsed || ipParsed.family !== subnetParsed.family) return false;

  const fullBytes = Math.floor(mask / 8);
  const remBits = mask % 8;
  const a = ipParsed.bytes;
  const b = subnetParsed.bytes;

  for (let i = 0; i < fullBytes; i++) {
    if (a[i] !== b[i]) return false;
  }
  if (remBits === 0) return true;
  const maskByte = (0xff << (8 - remBits)) & 0xff;
  return (a[fullBytes] & maskByte) === (b[fullBytes] & maskByte);
}

function ipInAnyCidr(ip, cidrs) {
  return cidrs.some((c) => ipInCidr(ip, c));
}

/**
 * Defense-in-depth check on whatever ipAddress the plugin actually sent —
 * independent of the plugin's own resolution logic (see
 * ChargeGuard_Dynamic_Firewall::get_client_ip() in the WooCommerce plugin).
 * Never trust this value blindly for identity-graph anchoring or velocity
 * without running it through here first.
 *
 * @returns {{ok: boolean, reason?: string}}
 */
function isPlausibleClientIp(ip) {
  if (!ip || typeof ip !== 'string') return { ok: false, reason: 'missing' };
  const trimmed = ip.trim();
  if (!net.isIP(trimmed)) return { ok: false, reason: 'not_an_ip' };
  if (ipInAnyCidr(trimmed, PRIVATE_RESERVED_RANGES)) return { ok: false, reason: 'private_or_reserved' };
  if (ipInAnyCidr(trimmed, getCloudflareRanges())) return { ok: false, reason: 'cloudflare_edge_ip' };
  return { ok: true };
}

function normalizeEmail(email) {
  if (!email || typeof email !== 'string') return '';
  let normalized = email.normalize('NFKC').toLowerCase().trim();
  const atIndex = normalized.lastIndexOf('@');
  if (atIndex === -1) return normalized;
  let local = normalized.slice(0, atIndex);
  const domain = normalized.slice(atIndex + 1);
  
  // إزالة الـ plus tag
  local = local.split('+')[0];
  
  // تحويل googlemail.com إلى gmail.com
  const canonicalDomain = domain === 'googlemail.com' ? 'gmail.com' : domain;
  
  // إزالة النقاط من الـ local فقط إذا كان النطاق gmail.com
  if (canonicalDomain === 'gmail.com') {
    local = local.replace(/\./g, '');
  }
  
  return local + '@' + canonicalDomain;
}

function hashValue(type, value) {
  const normalized = normalizeValue(type, value);
  if (!normalized) return null;
  const secret = process.env.IDENTITY_GRAPH_SECRET;
  if (!secret) {
    throw new Error('[utils] IDENTITY_GRAPH_SECRET environment variable is required');
  }
  return crypto.createHmac('sha256', secret).update(`${type}:${normalized}`).digest('hex');
}

function normalizeValue(type, value) {
  if (!value) return '';
  switch (type) {
    case 'EMAIL': {
      const lower = value.normalize('NFKC').toLowerCase().trim();
      const [local, domain] = lower.split('@');
      if (!domain) return lower;
      const cleanLocal = local.split('+')[0];
      const gmailDomains = ['gmail.com', 'googlemail.com'];
      const finalLocal = gmailDomains.includes(domain) ? cleanLocal.replace(/\./g, '') : cleanLocal;
      return `${finalLocal}@${domain === 'googlemail.com' ? 'gmail.com' : domain}`;
    }
    case 'IP': {
      const trimmed = value.trim();
      const plausible = isPlausibleClientIp(trimmed);
      if (!plausible.ok) {
        // Never hash an implausible value into the identity graph — a
        // private/reserved IP or an unverified Cloudflare edge IP getting
        // hashed here means either a misconfigured plugin (see the
        // WordPress-side proxy-trust redesign) or a spoofed value, and in
        // either case it would corrupt IP-based anchoring rather than
        // strengthen it. Returning '' makes hashValue() return null,
        // which callers must already handle (see risk.js) — this does
        // NOT block the order, it just excludes IP from that evaluation.
        return '';
      }
      return trimmed;
    }
    case 'DEVICE':
    case 'FINGERPRINT': return value.trim();
    case 'ADDRESS': return value.normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim();
    default: return value.trim();
  }
}

function maskValue(type, value) {
  if (!value) return null;
  switch (type) {
    case 'EMAIL': {
      const [local, domain] = value.split('@');
      if (!domain) return value;
      const masked = local.length <= 2 ? local[0] + '***' : local.slice(0, 2) + '***';
      return `${masked}@${domain}`;
    }
    case 'IP': {
      const parts = value.split('.');
      if (parts.length === 4) return `${parts[0]}.${parts[1]}.*.*`;
      return value.slice(0, 6) + '***';
    }
    case 'DEVICE':
    case 'FINGERPRINT': return value.slice(0, 8) + '***';
    case 'ADDRESS': {
      const words = value.split(' ');
      return words.slice(0, 2).join(' ') + '***';
    }
    default: return value.slice(0, 4) + '***';
  }
}

function maskDeviceId(deviceId) {
  if (!deviceId) return null;
  return deviceId.slice(0, 8) + '***';
}

module.exports = { normalizeEmail, hashValue, normalizeValue, maskValue, maskDeviceId, isPlausibleClientIp };