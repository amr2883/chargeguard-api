// ─── Global (Merchant-Scoped) Device Rotation Detector ────────────────────
// Complements the per-IP rotation check in risk.js: that check counts
// distinct fingerprints FROM ONE IP; this counts the rate of entirely NEW
// fingerprints appearing for a merchant, IP-independent. An attacker who
// rotates both IP and fingerprint together defeats the per-IP check (each
// IP only ever contributes 1 fingerprint, so it never reaches that
// threshold) but cannot defeat this one — every rotated fingerprint is
// still "new" to the merchant regardless of which IP it arrives from.
//
// GRADUATED + DUAL-WINDOW DESIGN (low-and-slow evasion fix):
// A single fixed threshold on a single window has a fundamental limit —
// any attacker rate slower than the threshold/window ratio evades it
// forever (see design discussion). Two independent mitigations are
// layered here instead of one:
//
//   1. GRADUATED RESPONSE on the short (10-min) window: instead of a
//      binary approve/block at 12, three tiers (soft/challenge/block) at
//      5/8/12 give the caller (risk.js) room to apply proportionate
//      friction — a soft risk-score bump (not yet wired into
//      riskScoring.js — tracked as a follow-up, not blocking), then an
//      OTP step-up challenge, before an outright hard block.
//
//   2. A SECOND, LONGER (1-hour) WINDOW closes the gap the short window
//      can't: an attacker who paces themselves just under the short
//      window's soft threshold (e.g. 4 new fingerprints/10min) still
//      accumulates ~24/hour — the long window's own challenge/block
//      thresholds catch that sustained pattern even though no single
//      10-minute slice ever looked suspicious on its own.
//
// This does NOT fully solve low-and-slow — no threshold-based counter
// can (an attacker who paces under BOTH windows' lowest thresholds, e.g.
// ~19 new fingerprints/hour, still evades all friction indefinitely) —
// but it cuts the maximum sustained fully-invisible rate by roughly 3-4x
// compared to the original single 12/10min threshold (~66/hour before,
// ~19/hour after). Closing the remainder needs a fundamentally different
// signal (the cross-merchant Identity Graph network, or a hard step-up
// like 3D Secure) — see design discussion for the full threat-model
// writeup.
//
// Threshold values below are a documented starting point, not a tuned
// result — there is no real production traffic data yet (open item
// tracked elsewhere). Revisit once real traffic volume is known.
//
// Deliberately in-memory, not DB-backed: the whole point is a counter
// that adds zero extra I/O to /evaluate, the highest-traffic endpoint in
// this codebase, on every single request (not just as an error
// fallback).
//
// KNOWN LIMITATION (same accepted tradeoff as velocityDetector.js's
// DB-error fallback store): this state is per-process. Under horizontal
// scaling, an attacker could in principle spread requests across
// instances to keep each instance's local count under threshold. If a
// Redis client is already configured elsewhere in this codebase (e.g. for
// binSequenceDetector.js), this module can be swapped to use it instead —
// same function signature, same return shape, no caller changes needed.
// Not urgent today: Render's current free-tier deployment only ever runs
// one instance.

const GLOBAL_ROTATION_SHORT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const GLOBAL_ROTATION_LONG_WINDOW_MS  = 60 * 60 * 1000; // 1 hour

// Short-window (10-min) graduated thresholds. BLOCK_THRESHOLD is
// unchanged from the original single-tier design — existing production
// behavior at 12+ is fully preserved.
const SHORT_SOFT_THRESHOLD      = 5;  // raises risk score only (not yet wired — see module comment)
const SHORT_CHALLENGE_THRESHOLD = 8;  // triggers OTP step-up challenge
const SHORT_BLOCK_THRESHOLD     = 12; // hard block — same value as before this change

// Long-window (1-hour) thresholds. Catches an attacker who deliberately
// paces themselves under the short window's SOFT threshold to avoid all
// short-window friction (see module comment for the ~24/hour math).
const LONG_CHALLENGE_THRESHOLD = 20; // triggers OTP step-up challenge
const LONG_BLOCK_THRESHOLD     = 40; // hard block — set conservatively high given no real traffic data yet, to bound false-block risk on a genuine traffic spike

// Backward-compatible aliases — kept in case anything else in this
// codebase imports the original names.
const GLOBAL_ROTATION_WINDOW_MS = GLOBAL_ROTATION_SHORT_WINDOW_MS;
const GLOBAL_ROTATION_BLOCK_THRESHOLD = SHORT_BLOCK_THRESHOLD;

// merchantId -> Map<fingerprint, expiryTimestamp>  (dedupe: "seen recently?")
// TTL now matches the LONG window (1h, not 10min) — a returning legitimate
// customer within the hour is no longer double-counted as "new"; strictly
// more permissive than before for genuine repeat visitors, and has zero
// effect on the attack pattern this module defends against (a rotated
// fingerprint is by definition never reused, so its TTL never matters to
// an attacker).
const seenFingerprints = new Map();
// merchantId -> number[] (timestamps of NEW-fingerprint events, pruned to
// the LONG window — the short-window count is derived from this same
// array by filtering the most recent 10 minutes, so only ONE array is
// maintained per merchant instead of two independent ones).
const newFingerprintTimestamps = new Map();

// Periodic sweep — bounds memory growth across merchants and fingerprints.
// Same cleanup pattern as velocityDetector.js's dbErrorFallbackStore sweep.
const SWEEP_INTERVAL_MS = 5 * 60 * 1000;
setInterval(() => {
  const now = Date.now();

  for (const [merchantId, fpMap] of seenFingerprints.entries()) {
    for (const [fp, expiry] of fpMap.entries()) {
      if (expiry <= now) fpMap.delete(fp);
    }
    if (fpMap.size === 0) seenFingerprints.delete(merchantId);
  }

  for (const [merchantId, timestamps] of newFingerprintTimestamps.entries()) {
    const fresh = timestamps.filter(t => t > now - GLOBAL_ROTATION_LONG_WINDOW_MS);
    if (fresh.length === 0) newFingerprintTimestamps.delete(merchantId);
    else newFingerprintTimestamps.set(merchantId, fresh);
  }
}, SWEEP_INTERVAL_MS).unref();

/**
 * Records this (merchantId, fingerprint) sighting and returns the current
 * graduated level plus the raw counts behind it. Never touches the DB;
 * O(1) amortized per call (the per-call filter is bounded by how many
 * events landed in the last hour for this one merchant, not global state).
 *
 * @returns {{
 *   newFingerprintCount: number,  // short-window (10-min) count — kept name for backward compatibility
 *   longWindowCount: number,      // long-window (1-hour) count
 *   isNewFingerprint: boolean,
 *   level: 'clear' | 'soft' | 'challenge' | 'block',
 *   blocked: boolean              // backward-compatible — equivalent to level === 'block'
 * }}
 */
function recordAndCheckGlobalRotation(merchantId, fingerprint) {
  if (!merchantId || !fingerprint) {
    return { newFingerprintCount: 0, longWindowCount: 0, isNewFingerprint: false, level: 'clear', blocked: false };
  }

  const now = Date.now();

  let fpMap = seenFingerprints.get(merchantId);
  if (!fpMap) {
    fpMap = new Map();
    seenFingerprints.set(merchantId, fpMap);
  }

  const existingExpiry = fpMap.get(fingerprint);
  const isNewFingerprint = !existingExpiry || existingExpiry <= now;

  // Sliding TTL — refresh on every sighting, same refresh-on-read idea as
  // emailIntelligence.js's LRU cache getFromCache(). Now bound to the LONG
  // window — see module comment above.
  fpMap.set(fingerprint, now + GLOBAL_ROTATION_LONG_WINDOW_MS);

  let timestamps = newFingerprintTimestamps.get(merchantId) || [];
  timestamps = timestamps.filter(t => t > now - GLOBAL_ROTATION_LONG_WINDOW_MS);

  if (isNewFingerprint) {
    timestamps.push(now);
  }
  newFingerprintTimestamps.set(merchantId, timestamps);

  // Long-window count is simply the full (already-pruned-to-1h) array
  // length. Short-window count is a cheap re-filter of the same array for
  // the more recent 10-minute slice — avoids maintaining two separate
  // timestamp arrays per merchant.
  const longWindowCount = timestamps.length;
  const shortWindowStart = now - GLOBAL_ROTATION_SHORT_WINDOW_MS;
  const newFingerprintCount = timestamps.reduce((count, t) => (t > shortWindowStart ? count + 1 : count), 0);

  let level = 'clear';
  if (newFingerprintCount >= SHORT_BLOCK_THRESHOLD || longWindowCount >= LONG_BLOCK_THRESHOLD) {
    level = 'block';
  } else if (newFingerprintCount >= SHORT_CHALLENGE_THRESHOLD || longWindowCount >= LONG_CHALLENGE_THRESHOLD) {
    level = 'challenge';
  } else if (newFingerprintCount >= SHORT_SOFT_THRESHOLD) {
    level = 'soft';
  }

  return {
    newFingerprintCount,
    longWindowCount,
    isNewFingerprint,
    level,
    blocked: level === 'block',
  };
}

module.exports = {
  recordAndCheckGlobalRotation,
  GLOBAL_ROTATION_SHORT_WINDOW_MS,
  GLOBAL_ROTATION_LONG_WINDOW_MS,
  SHORT_SOFT_THRESHOLD,
  SHORT_CHALLENGE_THRESHOLD,
  SHORT_BLOCK_THRESHOLD,
  LONG_CHALLENGE_THRESHOLD,
  LONG_BLOCK_THRESHOLD,
  // Backward-compatible aliases
  GLOBAL_ROTATION_WINDOW_MS,
  GLOBAL_ROTATION_BLOCK_THRESHOLD,
};