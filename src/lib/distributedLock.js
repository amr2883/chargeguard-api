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

const Redis = require('ioredis');

let redisClient = null;

if (process.env.REDIS_URL) {
  redisClient = new Redis(process.env.REDIS_URL, {
    maxRetriesPerRequest: 2,
    lazyConnect: false,
    retryStrategy: (times) => Math.min(times * 200, 5000),
  });

  redisClient.on('error', (err) => {
    console.error(`[distributedLock] Redis connection error: ${err.message}`);
  });

  redisClient.on('connect', () => {
    console.log('[distributedLock] Redis connected — distributed scheduler locking active');
  });
} else {
  console.warn(
    '[distributedLock] REDIS_URL not set — distributed locking is DISABLED. ' +
    'If this backend runs more than one instance, schedulers WILL send duplicate ' +
    'alerts/reports. Set REDIS_URL before scaling horizontally.'
  );
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
    console.warn(`[distributedLock] ${key} — no Redis client configured, skipping (fail-closed)`);
    return false;
  }

  if (redisClient.status !== 'ready') {
    console.warn(`[distributedLock] ${key} — Redis not ready (status: ${redisClient.status}), skipping (fail-closed)`);
    return false;
  }

  try {
    const result = await redisClient.set(key, INSTANCE_ID, 'NX', 'PX', ttlMs);
    if (result === 'OK') {
      console.log(`[distributedLock] ${key} — acquired by ${INSTANCE_ID} (ttl ${ttlMs}ms)`);
      return true;
    }
    console.log(`[distributedLock] ${key} — lock not acquired, another instance is handling this run`);
    return false;
  } catch (err) {
    console.error(`[distributedLock] ${key} — Redis SET failed, skipping (fail-closed): ${err.message}`);
    return false;
  }
}

module.exports = { acquireLock, INSTANCE_ID };