// src/lib/metrics.js - Rate limiting for external APIs + Prometheus integration
const prometheus = require('./prometheus');

// ========== Rate Limiting (Sliding Window) ==========
const slidingWindows = new Map(); // key: `${merchantId}:${type}` (type: ip, email, bin)
const WINDOW_MS = 60 * 1000; // 1 minute window
const MAX_REQUESTS = {
  ip: 30,     // 30 IP lookups per minute per merchant
  email: 35,  // 35 email lookups per minute per merchant
  bin: 40,    // 40 BIN lookups per minute per merchant
};
const GLOBAL_BIN_LIMIT = 10; // 10 requests per minute globally for binlist.net (free tier)
let globalBinCount = 0;
let globalBinResetTime = Date.now() + WINDOW_MS;

function cleanOldEntries() {
  const now = Date.now();
  for (const [key, window] of slidingWindows.entries()) {
    if (window.resetTime < now) slidingWindows.delete(key);
  }
}

function checkLimit(merchantId, type) {
  if (!merchantId) return true; // No merchant? allow (should not happen)
  cleanOldEntries();
  const key = `${merchantId}:${type}`;
  const now = Date.now();
  let entry = slidingWindows.get(key);
  if (!entry || entry.resetTime < now) {
    entry = { count: 0, resetTime: now + WINDOW_MS };
    slidingWindows.set(key, entry);
  }
  const limit = MAX_REQUESTS[type] || 20;
  if (entry.count >= limit) return false;
  entry.count++;
  return true;
}

function checkIPLimit(merchantId) {
  return checkLimit(merchantId, 'ip');
}
function checkEmailLimit(merchantId) {
  return checkLimit(merchantId, 'email');
}
function checkBINLimit(merchantId) {
  return checkLimit(merchantId, 'bin');
}

// Global bucket for binlist.net (shared across merchants)
const binlistGlobalBucket = {
  consume: () => {
    const now = Date.now();
    if (now >= globalBinResetTime) {
      globalBinCount = 0;
      globalBinResetTime = now + WINDOW_MS;
    }
    if (globalBinCount >= GLOBAL_BIN_LIMIT) return false;
    globalBinCount++;
    return true;
  },
  get available() { return GLOBAL_BIN_LIMIT - globalBinCount; },
};

// ========== Prometheus Recording Functions ==========
function recordIP(source, latencyMs) {
  // Record successful IP intelligence request
  prometheus.recordIPIntel(source, 'success');
  // Optionally record latency as a histogram? Not implemented here.
}

function recordEmail(source, latencyMs) {
  prometheus.recordEmailIntel(source, 'success');
}

function recordBIN(source, latencyMs) {
  prometheus.recordBINIntel(source, 'success');
}

// Note: For failures (timeout, error), we would need to call recordIPIntel(source, 'failure')
// Currently the calling code (ipIntelligence.js, etc.) only calls recordIP on success.
// To add failure tracking, modify those files accordingly. This is out of scope for now.

// ========== Global Circuit Breaker Factory (fixed-window) ==========
// Used by ipIntelligence.js and emailIntelligence.js to cap AGGREGATE
// outbound calls across ALL merchants combined — a coarse, second line
// of defense sitting above the per-merchant checkLimit() above.
//
// Mirrors binlistGlobalBucket's mechanism (counter + reset timestamp,
// fixed 1-minute window reusing WINDOW_MS) rather than a true sliding
// log, for consistency with the already-proven BIN limiter and because
// boundary precision doesn't materially change the cost-protection
// outcome at this aggregate-cap layer. Unlike binlistGlobalBucket (a
// singleton — there's only one binlist.net dependency to protect),
// this is a FACTORY: each call returns an independent closure with its
// own count/resetTime, so ipRateLimiter and emailRateLimiter never
// share state and can't false-trip on each other's traffic.
//
// @param {number} maxRequests  Max allowed calls per 1-minute window.
// @returns {{ isAllowed: () => boolean, count: () => number }}
function createSlidingWindow(maxRequests) {
  let windowCount = 0;
  let resetTime = Date.now() + WINDOW_MS;

  return {
    isAllowed: () => {
      const now = Date.now();
      if (now >= resetTime) {
        windowCount = 0;
        resetTime = now + WINDOW_MS;
      }
      if (windowCount >= maxRequests) return false;
      windowCount++;
      return true;
    },
    count: () => windowCount,
  };
}

module.exports = {
  recordIP,
  checkIPLimit,
  recordEmail,
  checkEmailLimit,
  recordBIN,
  checkBINLimit,
  binlistGlobalBucket,
  createSlidingWindow,
};