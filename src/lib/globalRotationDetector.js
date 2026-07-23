// ─── Global (Merchant-Scoped) Device Rotation Detector ────────────────────
// Complements the per-IP rotation check in risk.js: that check counts
// distinct fingerprints FROM ONE IP; this counts the rate of entirely NEW
// fingerprints appearing for a merchant, IP-independent. An attacker who
// rotates both IP and fingerprint together defeats the per-IP check (each
// IP only ever contributes 1 fingerprint, so it never reaches that
// threshold) but cannot defeat this one — every rotated fingerprint is
// still "new" to the merchant regardless of which IP it arrives from.
//
// Deliberately in-memory, not DB-backed: the whole point is a counter that
// adds zero extra I/O to /evaluate, the highest-traffic endpoint in this
// codebase, on every single request (not just as an error fallback).
//
// KNOWN LIMITATION (same accepted tradeoff as velocityDetector.js's
// DB-error fallback store): this state is per-process. Under horizontal
// scaling, an attacker could in principle spread requests across
// instances to keep each instance's local count under threshold. If a
// Redis client is already configured elsewhere in this codebase (e.g. for
// binSequenceDetector.js), this module can be swapped to use it instead —
// same function signature, same return shape, no caller changes needed.

const GLOBAL_ROTATION_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const GLOBAL_ROTATION_BLOCK_THRESHOLD = 12; // 12+ new fingerprints per merchant per window

// merchantId -> Map<fingerprint, expiryTimestamp>  (dedupe: "seen recently?")
const seenFingerprints = new Map();
// merchantId -> number[] (timestamps of NEW-fingerprint events within window)
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
    const fresh = timestamps.filter(t => t > now - GLOBAL_ROTATION_WINDOW_MS);
    if (fresh.length === 0) newFingerprintTimestamps.delete(merchantId);
    else newFingerprintTimestamps.set(merchantId, fresh);
  }
}, SWEEP_INTERVAL_MS).unref();

/**
 * Records this (merchantId, fingerprint) sighting and returns the current
 * count of distinct NEW fingerprints seen for this merchant within the
 * rotation window. Never touches the DB; O(1) amortized per call.
 *
 * @returns {{ newFingerprintCount: number, isNewFingerprint: boolean, blocked: boolean }}
 */
function recordAndCheckGlobalRotation(merchantId, fingerprint) {
  if (!merchantId || !fingerprint) {
    return { newFingerprintCount: 0, isNewFingerprint: false, blocked: false };
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
  // emailIntelligence.js's LRU cache getFromCache().
  fpMap.set(fingerprint, now + GLOBAL_ROTATION_WINDOW_MS);

  let timestamps = newFingerprintTimestamps.get(merchantId) || [];
  timestamps = timestamps.filter(t => t > now - GLOBAL_ROTATION_WINDOW_MS);

  if (isNewFingerprint) {
    timestamps.push(now);
  }
  newFingerprintTimestamps.set(merchantId, timestamps);

  const newFingerprintCount = timestamps.length;

  return {
    newFingerprintCount,
    isNewFingerprint,
    blocked: newFingerprintCount >= GLOBAL_ROTATION_BLOCK_THRESHOLD,
  };
}

module.exports = {
  recordAndCheckGlobalRotation,
  GLOBAL_ROTATION_WINDOW_MS,
  GLOBAL_ROTATION_BLOCK_THRESHOLD,
};