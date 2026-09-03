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

// ─── ChargeGuard Challenge Ticket (OTP-passed proof) ──────────────────────
// A second, independent HMAC-signed opaque token — same base64url-payload
// + HMAC-SHA256 signature shape as mintDeviceToken/verifyDeviceToken
// above, reused verbatim for a different claim: proof that this exact
// (deviceFingerprint, email) pair already passed an OTP challenge
// recently (see routes/risk.js's POST /challenge/verify), so a
// legitimate customer isn't re-challenged on every checkout attempt
// within the same day. Stored client-side as a separate HttpOnly cookie
// (chargeguard_ct in the WooCommerce plugin) — never the same cookie as
// chargeguard_dt, since the two tokens assert different claims.
//
// Deliberately a SEPARATE secret from DEVICE_TOKEN_SECRET, not reused:
// mintDeviceToken/verifyDeviceToken and mintChallengeTicket/
// verifyChallengeTicket answer different questions ("is this the same
// device across requests" vs. "did this device+email pair pass an OTP
// challenge"). Keeping the signing secrets independent means a
// compromise of one can never be used to forge the other — same
// isolation principle already applied to IdentityNode.hashedValue using
// a separate secret from BlockedAttempt/CardTestAttempt's SECRET_SALT
// (see identityGraph.js).
const CHALLENGE_TICKET_SECRET = process.env.CHALLENGE_TICKET_SECRET;
if (!CHALLENGE_TICKET_SECRET) {
  throw new Error('[deviceToken] CHALLENGE_TICKET_SECRET environment variable is required');
}

const CHALLENGE_TICKET_TTL_MS = 24 * 60 * 60 * 1000; // 24h — re-challenge daily, not on every single checkout attempt

// Binds the ticket to the specific (deviceFingerprint, email) pair that
// passed the challenge, using the same HMAC-pepper pattern as
// IdentityNode.hashedValue (identityGraph.js) rather than storing the
// pair in the clear inside the payload — a ticket minted for one pair
// must not silently validate a different pair (e.g. a rotated
// fingerprint or a different email reusing a stolen ticket cookie).
// Email is lowercased/trimmed before hashing so trivial casing/whitespace
// differences between mint time and verify time don't cause a false
// mismatch.
function challengePairHash(merchantId, deviceFingerprint, email) {
  const normalizedEmail = (email || '').toLowerCase().trim();
  return crypto.createHmac('sha256', CHALLENGE_TICKET_SECRET)
    .update(`${merchantId}|${deviceFingerprint}|${normalizedEmail}`)
    .digest('hex');
}

function mintChallengeTicket(merchantId, deviceFingerprint, email) {
  const payload = {
    ph: challengePairHash(merchantId, deviceFingerprint, email),
    iat: Date.now(),
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', CHALLENGE_TICKET_SECRET).update(payloadB64).digest('base64url');
  return `${payloadB64}.${sig}`;
}

/**
 * @returns {{valid:boolean, reason?:string}}
 */
function verifyChallengeTicket(ticket, merchantId, deviceFingerprint, email) {
  if (!ticket || typeof ticket !== 'string' || !ticket.includes('.')) {
    return { valid: false, reason: 'malformed' };
  }
  const [payloadB64, sig] = ticket.split('.');
  if (!payloadB64 || !sig) return { valid: false, reason: 'malformed' };

  let expectedSig;
  try {
    expectedSig = crypto.createHmac('sha256', CHALLENGE_TICKET_SECRET).update(payloadB64).digest('base64url');
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

  if (!payload.iat || (Date.now() - payload.iat) > CHALLENGE_TICKET_TTL_MS) {
    return { valid: false, reason: 'expired' };
  }

  if (payload.ph !== challengePairHash(merchantId, deviceFingerprint, email)) {
    return { valid: false, reason: 'pair_mismatch' };
  }

  return { valid: true };
}

module.exports = { mintDeviceToken, verifyDeviceToken, ipBucket, mintChallengeTicket, verifyChallengeTicket };