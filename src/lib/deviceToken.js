// ─── ChargeGuard Server-Signed Device Token ───────────────────────────────
// Issues an opaque, HMAC-signed token the WooCommerce plugin stores as an
// HttpOnly cookie (chargeguard_dt) — the client's own JavaScript can never
// read or overwrite it. This does not replace the existing raw
// chargeguard_fp client fingerprint (kept for backward compatibility and
// identity-graph continuity); it is a second, independent signal that a
// client cannot forge or trivially rotate, since a fresh valid value
// requires an authenticated, signed, rate-limited round trip to this
// backend rather than a console command.

const crypto = require('crypto');

const DEVICE_TOKEN_SECRET = process.env.DEVICE_TOKEN_SECRET;
if (!DEVICE_TOKEN_SECRET) {
  throw new Error('[deviceToken] DEVICE_TOKEN_SECRET environment variable is required');
}

const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days — matches the plugin's cookie lifetime

// Coarse IP bucketing (not exact-match binding) — tolerates legitimate IP
// drift (mobile networks, CGNAT, home ISP re-leases) between mint time and
// use time, while still catching "signed on IP A, replayed en masse from
// wildly different IP B" as a corroboration mismatch rather than a hard
// identity claim.
function ipBucket(ip) {
  if (!ip || typeof ip !== 'string') return '';
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) return parts.slice(0, 3).join('.') + '.0/24';
  }
  if (ip.includes(':')) {
    return ip.split(':').slice(0, 4).join(':'); // coarse IPv6 bucket
  }
  return ip;
}

function mintDeviceToken(ip) {
  const payload = {
    rid: crypto.randomUUID(), // server-random — the client contributes nothing to this value
    ipb: ipBucket(ip),
    iat: Date.now(),
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', DEVICE_TOKEN_SECRET).update(payloadB64).digest('base64url');
  return `${payloadB64}.${sig}`;
}

/**
 * @returns {{valid:boolean, reason?:string, rid?:string, issuedAt?:number, ipMatches?:boolean}}
 */
function verifyDeviceToken(token, ip) {
  if (!token || typeof token !== 'string' || !token.includes('.')) {
    return { valid: false, reason: 'malformed' };
  }
  const [payloadB64, sig] = token.split('.');
  if (!payloadB64 || !sig) return { valid: false, reason: 'malformed' };

  let expectedSig;
  try {
    expectedSig = crypto.createHmac('sha256', DEVICE_TOKEN_SECRET).update(payloadB64).digest('base64url');
  } catch (e) {
    return { valid: false, reason: 'sig_error' };
  }

  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return { valid: false, reason: 'bad_signature' };
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch (e) {
    return { valid: false, reason: 'bad_payload' };
  }

  if (!payload.iat || (Date.now() - payload.iat) > TOKEN_TTL_MS) {
    return { valid: false, reason: 'expired' };
  }

  const ipMatches = ip ? (ipBucket(ip) === payload.ipb) : false;

  return { valid: true, rid: payload.rid, issuedAt: payload.iat, ipMatches };
}

module.exports = { mintDeviceToken, verifyDeviceToken, ipBucket };