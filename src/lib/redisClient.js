'use strict';

// --- Shared Redis client (singleton) ---
// Single source of truth for the Redis connection used by every
// Redis-backed detector in this codebase (binSequenceDetector.js,
// rawVelocityDetector.js, and any future module that needs a shared,
// multi-instance-safe store). Node's module cache guarantees this file
// only runs once per process no matter how many modules require() it,
// so importing this everywhere still opens exactly one TCP connection
// to Redis — not one per detector.
//
// Every consumer imports { redisClient, usingRedis } and checks
// `usingRedis && redisClient && redisClient.status === 'ready'` before
// each Redis call, exactly as before this file existed — this module
// only centralizes *construction* of the client, not the call sites.

const logger = require('./logger');

let redisClient = null;
let usingRedis = false;

if (process.env.REDIS_URL) {
  try {
    const Redis = require('ioredis');
    redisClient = new Redis(process.env.REDIS_URL, {
      maxRetriesPerRequest: 2,
      lazyConnect: false,
      retryStrategy: (times) => Math.min(times * 200, 5000),
    });
    redisClient.on('error', (err) => {
      logger.error(
        { module: 'redisClient', err: err.message },
        'Redis connection error — dependent detectors will fall back to their in-memory stores for subsequent operations'
      );
    });
    redisClient.on('connect', () => {
      logger.info(
        { module: 'redisClient' },
        'Redis connected — shared client ready (multi-instance-safe stores enabled for all dependent detectors)'
      );
    });
    usingRedis = true;
  } catch (err) {
    logger.error(
      { module: 'redisClient', err: err.message },
      'Failed to initialize shared Redis client — all dependent detectors will fall back to in-memory stores'
    );
    redisClient = null;
    usingRedis = false;
  }
} else {
  logger.warn(
    { module: 'redisClient' },
    'REDIS_URL not set — every Redis-backed detector (BIN sequence, raw device velocity, ' +
    'and any other module importing this shared client) is using a single-process in-memory ' +
    'store. This is UNSAFE if this backend runs more than one instance: an attacker can split ' +
    'an attack burst across instances to evade detection. Set REDIS_URL before scaling horizontally.'
  );
}

// Convenience helper — equivalent to the inline check every call site
// already performs (`usingRedis && redisClient && redisClient.status
// === 'ready'`). Provided for new code; existing call sites are free to
// keep using the inline check since redisClient/usingRedis are the same
// references either way.
function isRedisReady() {
  return usingRedis && redisClient && redisClient.status === 'ready';
}

module.exports = { redisClient, usingRedis, isRedisReady };