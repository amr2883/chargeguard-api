'use strict';

/**
 * Distributed Lock Helper
 * ------------------------
 * Provides a Redis-backed "SET NX PX" lock so multiple horizontally-scaled
 * backend instances can coordinate which one runs a given scheduler tick.
 *
 * Pattern: SET key instanceId NX PX ttlMs
 *   - NX: only set if the key does NOT already exist (atomic check-and-set)
 *   - PX: auto-expire after ttlMs milliseconds
 *
 * This mirrors the Redis pattern already established in
 * src/lib/binSequenceDetector.js. No explicit release/unlock is required —
 * the TTL is the safety net: if the lock-holding instance crashes mid-job,
 * the key expires on its own and the next tick can acquire it again. This
 * intentionally trades a small "worst case wait = TTL" for never leaving a
 * permanently stuck lock that requires manual intervention.
 *
 * Fails CLOSED: if Redis is unreachable, acquireLock() returns null (lock
 * NOT acquired) rather than throwing or pretending success — schedulers
 * should treat a null return as "skip this tick, try again next time"
 * exactly like the "another instance holds the lock" case. This is
 * important: silently proceeding without a lock when Redis is down would
 * reintroduce the duplicate-send bug this helper exists to fix.
 */

const logger = require('./logger');
let Redis = null;
try {
  Redis = require('ioredis');
} catch (e) {
  // ioredis is optional — the app boots without it
}

let redisClient = null;

if (process.env.REDIS_URL && Redis) {
  redisClient = new Redis(process.env.REDIS_URL, {
    maxRetriesPerRequest: 2,
    lazyConnect: false,
    retryStrategy: (times) => Math.min(times * 200, 5000),
  });

  redisClient.on('error', (err) => {
    logger.error({ module: 'distributedLock', fn: 'redisClient.on(error)', error: err.message }, 'Redis connection error');
  });

  redisClient.on('connect', () => {
    logger.info({ module: 'distributedLock', fn: 'redisClient.on(connect)' }, 'Redis connected - distributed scheduler locking active');
  });
} else if (!Redis) {
  logger.warn({ module: 'distributedLock', fn: 'init' }, 'ioredis module not installed - distributed locking is DISABLED. Install ioredis and set REDIS_URL before scaling horizontally.');
} else {
  logger.warn({ module: 'distributedLock', fn: 'init' }, 'REDIS_URL not set - distributed locking is DISABLED. If this backend runs more than one instance, schedulers WILL send duplicate alerts/reports. Set REDIS_URL before scaling horizontally.');
}

// Unique per-process identifier, useful for log correlation ("who holds this lock").
const INSTANCE_ID = process.env.RENDER_INSTANCE_ID || `pid-${process.pid}`;

/**
 * Attempts to atomically acquire a named lock.
 *
 * @param {string} key      Lock name, e.g. 'scheduler:attackAlert'
 * @param {number} ttlMs    Lock lifetime in ms — must exceed the expected
 *                          execution time of the work it guards.
 * @returns {Promise<boolean>} true if this call acquired the lock, false otherwise
 *                              (already held elsewhere, or Redis unavailable).
 */
async function acquireLock(key, ttlMs) {
  if (!redisClient) {
    // Fail closed: no Redis configured means no safe coordination is possible.
    logger.warn({ module: 'distributedLock', fn: 'acquireLock', key }, 'No Redis client configured, skipping (fail-closed)');
    return false;
  }

  if (redisClient.status !== 'ready') {
    logger.warn({ module: 'distributedLock', fn: 'acquireLock', key, redisStatus: redisClient.status }, 'Redis not ready, skipping (fail-closed)');
    return false;
  }

  try {
    const result = await redisClient.set(key, INSTANCE_ID, 'NX', 'PX', ttlMs);
    if (result === 'OK') {
      logger.debug({ module: 'distributedLock', fn: 'acquireLock', key, instanceId: INSTANCE_ID, ttlMs }, 'Lock acquired');
      return true;
    }
    logger.debug({ module: 'distributedLock', fn: 'acquireLock', key }, 'Lock not acquired - another instance is handling this run');
    return false;
  } catch (err) {
    logger.error({ module: 'distributedLock', fn: 'acquireLock', key, error: err.message }, 'Redis SET failed, skipping (fail-closed)');
    return false;
  }
}

module.exports = { acquireLock, INSTANCE_ID };