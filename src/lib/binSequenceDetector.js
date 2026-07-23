// --- ChargeGuard BIN Sequence Detector ---
// يكشف هجمات Card Testing حتى لو البوت غير IP + Device + Email في كل طلب
//
// الفكرة الأساسية:
// البوت بيجيب بطاقات من نفس الـ dump → نفس الـ BIN prefix (أول 6 أرقام)
// حتى لو غير كل حاجة تانية، الـ BIN range بيفضح نمط الهجوم
//
// 3 طبقات كشف:
// Layer 1: BIN Prefix Velocity  — كتير BINs من نفس الـ prefix في وقت قصير
// Layer 2: Sequential BIN Scan  — BINs بترتيب تصاعدي/تنازلي (علامة brute-force)
// Layer 3: Cross-Entity Linking — نفس الـ BIN prefix مع entities مختلفة تماماً

'use strict';

const logger = require('./logger');

// --- Constants ---
const WINDOW_MS         = 10 * 60 * 1000;  // نافذة 10 دقائق
const BLOCK_DURATION_MS = 60 * 60 * 1000;  // حظر ساعة
const PREFIX_LENGTH     = 4;               // أول 4 أرقام من الـ BIN (bank identifier)

const THRESHOLDS = {
  // Layer 1: كمية BINs مختلفة من نفس الـ prefix في 10 دقائق
  UNIQUE_BINS_PER_PREFIX: 8,

  // Layer 2: كمية BINs بتفرق 1 أو 2 رقم بين بعض (sequential scan)
  SEQUENTIAL_BINS: 5,

  // Layer 3: نفس الـ BIN prefix مع كمية entities مختلفة (IPs أو devices)
  UNIQUE_ENTITIES_PER_PREFIX: 6,
};

// --- Store: Redis-backed (multi-instance safe) with in-memory fallback ---
// L4 fix: previously a plain in-process Map with a startup guard that
// only refused to boot under WEB_CONCURRENCY > 1 rather than actually
// enabling safe horizontal scaling. This now uses Redis as the primary
// backend when REDIS_URL is configured — a shared store every instance
// reads/writes, closing the gap where an attacker could split a
// card-testing burst across instances to stay under every threshold on
// each one individually. When REDIS_URL is absent, this falls back to
// the original in-memory Map for single-instance deployments, with a
// one-time warning logged so this fallback is never silent.
//
// key: `${tenantId}:${binPrefix}` — tenant-scoped composite key (CWE-653 fix,
// unchanged from the prior implementation).
// value: { bins: { [bin]: timestamp[] }, entities: { [entity]: timestamp }, blockedUntil }
// (plain-object shape, not Map, so it round-trips through JSON for Redis
// storage — the in-memory fallback path also uses this same shape for
// consistency between the two backends.)

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
      logger.error({ module: 'binSequenceDetector', err: err.message }, 'Redis connection error — falling back to in-memory store for subsequent operations');
    });
    redisClient.on('connect', () => {
      logger.info({ module: 'binSequenceDetector' }, 'Redis connected — using shared BIN-sequence store (multi-instance safe)');
    });
    usingRedis = true;
  } catch (err) {
    logger.error({ module: 'binSequenceDetector', err: err.message }, 'Failed to initialize Redis client — falling back to in-memory store');
    redisClient = null;
    usingRedis = false;
  }
} else {
  logger.warn(
    { module: 'binSequenceDetector' },
    'REDIS_URL not set — BIN-sequence attack detection is using a single-process in-memory store. ' +
    'This is UNSAFE if this backend runs more than one instance: an attacker can split a card-testing ' +
    'burst across instances to evade detection. Set REDIS_URL before scaling horizontally.'
  );
}

// In-memory fallback store — used when Redis is not configured, or as a
// same-request fallback if an individual Redis call fails (see
// storeGet/storeSet below). Same key scheme and cleanup semantics as the
// original single-instance implementation.
const memoryStore = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, data] of memoryStore.entries()) {
    if (data.blockedUntil && data.blockedUntil < now) {
      memoryStore.delete(key);
      continue;
    }
    for (const bin of Object.keys(data.bins)) {
      const fresh = data.bins[bin].filter(t => t > now - WINDOW_MS);
      if (fresh.length === 0) delete data.bins[bin];
      else data.bins[bin] = fresh;
    }
    if (Object.keys(data.bins).length === 0 && !data.blockedUntil) {
      memoryStore.delete(key);
    }
  }
}, 5 * 60 * 1000).unref();

// Redis TTL matches BLOCK_DURATION_MS — the longest span any entry needs
// to remain meaningful (an active block). A prefix that's merely
// accumulating BIN attempts but never triggers a block naturally stops
// being queried once traffic to it stops, so a generous single TTL is
// simpler and safer than trying to track two different expiry semantics
// (window vs. block) in Redis, and errs toward over-retaining briefly
// rather than under-retaining and missing a real attack window.
const REDIS_TTL_SECONDS = Math.ceil(BLOCK_DURATION_MS / 1000);

async function storeGet(key) {
  if (usingRedis && redisClient && redisClient.status === 'ready') {
    try {
      const raw = await redisClient.get(key);
      return raw ? JSON.parse(raw) : null;
    } catch (err) {
      logger.error({ module: 'binSequenceDetector', err: err.message, key }, 'Redis GET failed — falling back to in-memory for this call');
    }
  }
  return memoryStore.get(key) || null;
}

async function storeSet(key, data) {
  if (usingRedis && redisClient && redisClient.status === 'ready') {
    try {
      await redisClient.set(key, JSON.stringify(data), 'EX', REDIS_TTL_SECONDS);
      return;
    } catch (err) {
      logger.error({ module: 'binSequenceDetector', err: err.message, key }, 'Redis SET failed — falling back to in-memory for this call');
    }
  }
  memoryStore.set(key, data);
}
// --- Lua script: atomic record-and-evaluate for recordBINAttempt() ---
// M2 fix: replaces the non-atomic storeGet() → mutate → storeSet() pattern
// with a single EVAL call. Redis guarantees the entire script executes as
// one indivisible unit — no other client's command can interleave between
// the read and the write — eliminating the lost-update race entirely,
// with one network round-trip instead of two. Mirrors checkPrefix() and
// detectSequentialScan() below exactly, so both code paths (Redis atomic
// path, and the in-memory/EVAL-failure fallback path) evaluate thresholds
// identically.
//
// KEYS[1] = storeKey
// ARGV[1] = bin
// ARGV[2] = entity
// ARGV[3] = now (ms)
// ARGV[4] = WINDOW_MS
// ARGV[5] = BLOCK_DURATION_MS
// ARGV[6] = PREFIX_LENGTH
// ARGV[7] = THRESHOLDS.UNIQUE_BINS_PER_PREFIX
// ARGV[8] = THRESHOLDS.SEQUENTIAL_BINS
// ARGV[9] = THRESHOLDS.UNIQUE_ENTITIES_PER_PREFIX
// ARGV[10] = TTL in seconds (REDIS_TTL_SECONDS)
// ARGV[11] = prefix label (for the human-readable "reason" string)
const RECORD_BIN_ATTEMPT_SCRIPT = `
local storeKey = KEYS[1]
local bin = ARGV[1]
local entity = ARGV[2]
local now = tonumber(ARGV[3])
local windowMs = tonumber(ARGV[4])
local blockDurationMs = tonumber(ARGV[5])
local prefixLength = tonumber(ARGV[6])
local uniqueBinsThreshold = tonumber(ARGV[7])
local sequentialBinsThreshold = tonumber(ARGV[8])
local uniqueEntitiesThreshold = tonumber(ARGV[9])
local ttlSeconds = tonumber(ARGV[10])
local prefixLabel = ARGV[11]

local raw = redis.call('GET', storeKey)
local data
if raw then
  data = cjson.decode(raw)
else
  data = { bins = {}, entities = {}, blockedUntil = cjson.null }
end
if data.bins == nil then data.bins = {} end
if data.entities == nil then data.entities = {} end

local windowStart = now - windowMs

-- append new bin timestamp
if data.bins[bin] == nil then data.bins[bin] = {} end
table.insert(data.bins[bin], now)

-- record/refresh entity timestamp
data.entities[entity] = now

-- prune expired bin timestamps; drop bins left with none
local prunedBins = {}
for b, timestamps in pairs(data.bins) do
  local fresh = {}
  for _, t in ipairs(timestamps) do
    if t > windowStart then
      table.insert(fresh, t)
    end
  end
  if #fresh > 0 then
    prunedBins[b] = fresh
  end
end
data.bins = prunedBins

-- prune expired entities
local prunedEntities = {}
for e, t in pairs(data.entities) do
  if t > windowStart then
    prunedEntities[e] = t
  end
end
data.entities = prunedEntities

-- collect active bins (all remaining bins are already window-fresh)
local activeBins = {}
for b, _ in pairs(data.bins) do
  table.insert(activeBins, b)
end

local activeEntitiesCount = 0
for _ in pairs(data.entities) do
  activeEntitiesCount = activeEntitiesCount + 1
end

local triggered = false
local layer = cjson.null
local reason = cjson.null
local riskAddition = 0

-- Layer 1: BIN prefix velocity
if #activeBins >= uniqueBinsThreshold then
  triggered = true
  layer = 1
  reason = 'BIN prefix ' .. prefixLabel .. 'xx: ' .. #activeBins .. ' unique BINs tested in 10 minutes'
  riskAddition = 35
end

-- Layer 2: sequential BIN scan
if not triggered and #activeBins >= sequentialBinsThreshold then
  local suffixes = {}
  for _, b in ipairs(activeBins) do
    local suffixNum = tonumber(string.sub(b, prefixLength + 1))
    if suffixNum ~= nil then
      table.insert(suffixes, suffixNum)
    end
  end
  table.sort(suffixes)
  if #suffixes >= sequentialBinsThreshold then
    local streak = 1
    local isSequential = false
    for i = 2, #suffixes do
      local diff = suffixes[i] - suffixes[i - 1]
      if diff >= 1 and diff <= 2 then
        streak = streak + 1
        if streak >= sequentialBinsThreshold then
          isSequential = true
          break
        end
      else
        streak = 1
      end
    end
    if isSequential then
      triggered = true
      layer = 2
      reason = 'BIN prefix ' .. prefixLabel .. 'xx: sequential card scan detected'
      riskAddition = 40
    end
  end
end

-- Layer 3: cross-entity linking
if not triggered and #activeBins >= 4 and activeEntitiesCount >= uniqueEntitiesThreshold then
  triggered = true
  layer = 3
  reason = 'BIN prefix ' .. prefixLabel .. 'xx: ' .. #activeBins .. ' BINs from ' .. activeEntitiesCount .. ' different sources'
  riskAddition = 30
end

if triggered then
  data.blockedUntil = now + blockDurationMs
end

redis.call('SET', storeKey, cjson.encode(data), 'EX', ttlSeconds)

local result = {
  triggered = triggered,
  layer = layer,
  reason = reason,
  riskAddition = riskAddition,
  activeBinsCount = #activeBins,
  activeEntitiesCount = activeEntitiesCount,
  blockedUntil = data.blockedUntil or cjson.null,
}

return cjson.encode(result)
`;

// --- Helper: استخراج الـ prefix ---
function extractPrefix(bin) {
  if (!bin || typeof bin !== 'string') return null;
  const digits = bin.replace(/\D/g, '');
  if (digits.length < PREFIX_LENGTH) return null;
  return digits.slice(0, PREFIX_LENGTH);
}

// --- Helper: كشف BINs بترتيب تصاعدي/تنازلي ---
// لو 5 BINs بتفرق بينهم 1-2 رقم → brute-force scan
function detectSequentialScan(bins) {
  if (bins.length < THRESHOLDS.SEQUENTIAL_BINS) return false;

  // خد آخر 6 أرقام من كل BIN (الجزء المتغير)
  const suffixes = bins
    .map(b => parseInt(b.slice(PREFIX_LENGTH), 10))
    .filter(n => !isNaN(n))
    .sort((a, b) => a - b);

  if (suffixes.length < THRESHOLDS.SEQUENTIAL_BINS) return false;

  // دور على تسلسل بفرق ≤ 2
  let streak = 1;
  for (let i = 1; i < suffixes.length; i++) {
    const diff = suffixes[i] - suffixes[i - 1];
    if (diff >= 1 && diff <= 2) {
      streak++;
      if (streak >= THRESHOLDS.SEQUENTIAL_BINS) return true;
    } else {
      streak = 1;
    }
  }
  return false;
}

// --- تسجيل طلب جديد ---
// entity = IP أو device fingerprint (أي identifier)
// L4 fix: now async (Redis calls are async) and uses plain-object shape
// ({ bins: {}, entities: {} }) instead of nested Map, since Map does not
// survive JSON.stringify/parse for Redis storage. checkPrefix() below is
// updated to accept both shapes' iteration needs via Object.entries().
async function recordBINAttempt({ tenantId, bin, entity }) {
  const prefix = extractPrefix(bin);
  if (!prefix) return null;

  // Composite key enforces tenant isolation at the storage layer — no call
  // site can accidentally read/write another tenant's threat state.
  const storeKey = `${tenantId}:${prefix}`;
  const now = Date.now();

  // M2 fix: atomic path via Lua EVAL — read, append, prune, evaluate
  // thresholds, and write all happen inside Redis as one indivisible
  // operation, closing the concurrent lost-update race that the previous
  // storeGet()→mutate→storeSet() pattern had under high-concurrency bursts
  // (exactly the traffic pattern a real card-testing attack produces).
  if (usingRedis && redisClient && redisClient.status === 'ready') {
    try {
      const raw = await redisClient.eval(
        RECORD_BIN_ATTEMPT_SCRIPT,
        1,
        storeKey,
        bin,
        entity,
        now,
        WINDOW_MS,
        BLOCK_DURATION_MS,
        PREFIX_LENGTH,
        THRESHOLDS.UNIQUE_BINS_PER_PREFIX,
        THRESHOLDS.SEQUENTIAL_BINS,
        THRESHOLDS.UNIQUE_ENTITIES_PER_PREFIX,
        REDIS_TTL_SECONDS,
        prefix
      );
      return JSON.parse(raw);
    } catch (err) {
      logger.error(
        { module: 'binSequenceDetector', err: err.message, storeKey },
        'Redis EVAL failed for recordBINAttempt — falling back to non-atomic read-modify-write for this call'
      );
      // fall through to the non-atomic path below
    }
  }

  // Non-atomic fallback path — used when Redis is unavailable/not
  // configured, or when the EVAL call above failed for this specific
  // request. The race here is the same accepted trade-off as the
  // original single-instance in-memory design: acceptable because a
  // single in-memory process has no concurrent-instance race to begin
  // with, and an EVAL failure should degrade gracefully rather than
  // drop the detection attempt outright.
  let data = await storeGet(storeKey);
  if (!data) {
    data = { bins: {}, entities: {}, blockedUntil: null };
  }

  const existingTimestamps = data.bins[bin] || [];
  existingTimestamps.push(now);
  data.bins[bin] = existingTimestamps;
  data.entities[entity] = now;

  const { triggered } = checkPrefix(tenantId, prefix, data, now);
  if (triggered) {
    data.blockedUntil = now + BLOCK_DURATION_MS;
  }

  await storeSet(storeKey, data);
  return null; // signals the caller to fall back to its own storeGet+checkPrefix
}
// --- فحص prefix معين ---
// L4 fix: data.bins / data.entities are now plain objects (Redis-
// serializable) instead of Map — Object.entries()/Object.values() used
// in place of the former .entries() Map methods; behavior is otherwise
// unchanged.
function checkPrefix(tenantId, prefix, data, now = Date.now()) {
  const windowStart = now - WINDOW_MS;

  // BINs نشطة في الـ window
  const activeBins = [];
  for (const [bin, timestamps] of Object.entries(data.bins)) {
    if (timestamps.some(t => t > windowStart)) {
      activeBins.push(bin);
    }
  }

  // Entities نشطة في الـ window
  const activeEntities = Object.entries(data.entities)
    .filter(([, t]) => t > windowStart)
    .map(([e]) => e);

  // Layer 1: BIN velocity
  if (activeBins.length >= THRESHOLDS.UNIQUE_BINS_PER_PREFIX) {
    return {
      triggered: true,
      layer: 1,
      reason: `BIN prefix ${prefix}xx: ${activeBins.length} unique BINs tested in 10 minutes`,
      riskAddition: 35,
    };
  }

  // Layer 2: Sequential scan
  if (detectSequentialScan(activeBins)) {
    return {
      triggered: true,
      layer: 2,
      reason: `BIN prefix ${prefix}xx: sequential card scan detected`,
      riskAddition: 40,
    };
  }

  // Layer 3: Cross-entity (نفس الـ BIN prefix من entities مختلفة جداً)
  if (activeBins.length >= 4 && activeEntities.length >= THRESHOLDS.UNIQUE_ENTITIES_PER_PREFIX) {
    return {
      triggered: true,
      layer: 3,
      reason: `BIN prefix ${prefix}xx: ${activeBins.length} BINs from ${activeEntities.length} different sources`,
      riskAddition: 30,
    };
  }

  return { triggered: false, layer: null, reason: null, riskAddition: 0 };
}

// --- الدالة الرئيسية: يستخدمها الـ risk scoring ---
// بترجع { blocked, riskAddition, reason, layer }
// L4 fix: now async — all call sites (routes/risk.js's /evaluate and
// /woocommerce-webhook handlers) must `await` this. See that file's own
// updated call sites.
async function checkBINSequence({ tenantId, bin, ipAddress, deviceFingerprint }) {
  const prefix = extractPrefix(bin);
  if (!prefix) return { blocked: false, riskAddition: 0, reason: null };

  // Tenant-scoped lookup (CWE-653 fix): without this, a block triggered by
  // one tenant's card-testing attack on BIN prefix 4111xx would silently
  // block a completely unrelated tenant's legitimate 4111xx customers.
  const storeKey = `${tenantId}:${prefix}`;
  const now = Date.now();
  const data = await storeGet(storeKey);

  // لو محظور من قبل
  if (data?.blockedUntil && data.blockedUntil > now) {
    return {
      blocked: true,
      riskAddition: 50,
      reason: `BIN prefix ${prefix}xx temporarily blocked (active attack wave)`,
      layer: 0,
    };
  }

  // entity = IP أو device (أيهما متاح)
  const entity = ipAddress || deviceFingerprint || 'unknown';
  const atomicResult = await recordBINAttempt({ tenantId, bin, entity });

  // M2 fix: on the Redis/Lua path, atomicResult already reflects the exact
  // state produced by the write that just happened — no second read is
  // needed or safe to skip re-deriving from (a second storeGet() here
  // would just be re-reading the same thing the script already returned,
  // at the cost of an extra round-trip).
  if (atomicResult) {
    return {
      blocked: atomicResult.triggered,
      riskAddition: atomicResult.riskAddition || 0,
      reason: atomicResult.reason,
      layer: atomicResult.layer,
    };
  }

  // In-memory (or EVAL-failure) fallback path — re-read and evaluate,
  // identical to the original pre-fix behavior.
  const freshData = await storeGet(storeKey);
  if (!freshData) return { blocked: false, riskAddition: 0, reason: null };

  const result = checkPrefix(tenantId, prefix, freshData, now);

  return {
    blocked: result.triggered,
    riskAddition: result.riskAddition || 0,
    reason: result.reason,
    layer: result.layer,
  };
}

// --- إحصائيات للـ dashboard ---
// L4 fix: now async. When Redis is active, uses SCAN (non-blocking,
// cursor-based iteration) rather than KEYS, since KEYS blocks the whole
// Redis instance on large keyspaces — unacceptable for a call that can
// run on every dashboard page load. Falls back to iterating memoryStore
// directly when Redis is not configured/available, matching the
// original single-instance behavior exactly.
async function getBINStats(tenantId) {
  const now = Date.now();
  let activePrefixes = 0;
  let blockedPrefixes = 0;
  let totalActiveBINs = 0;
  const windowStart = now - WINDOW_MS;

  // Keys are `${tenantId}:${prefix}` — filter to only this tenant's entries
  // so dashboard stats never leak another merchant's attack telemetry
  // (CWE-653: Improper Isolation of Shared Resources / multi-tenancy fix).
  const tenantKeyPrefix = `${tenantId}:`;

  const tallyEntry = (data) => {
    const activeBins = Object.values(data.bins).filter(ts =>
      ts.some(t => t > windowStart)
    ).length;
    if (activeBins > 0) {
      activePrefixes++;
      totalActiveBINs += activeBins;
    }
    if (data.blockedUntil && data.blockedUntil > now) {
      blockedPrefixes++;
    }
  };

  if (usingRedis && redisClient && redisClient.status === 'ready') {
    try {
      let cursor = '0';
      do {
        const [nextCursor, keys] = await redisClient.scan(
          cursor, 'MATCH', `${tenantKeyPrefix}*`, 'COUNT', 200
        );
        cursor = nextCursor;
        if (keys.length > 0) {
          const values = await redisClient.mget(keys);
          for (const raw of values) {
            if (!raw) continue;
            try {
              tallyEntry(JSON.parse(raw));
            } catch (parseErr) {
              logger.error({ module: 'binSequenceDetector', err: parseErr.message }, 'Failed to parse Redis value during getBINStats scan');
            }
          }
        }
      } while (cursor !== '0');
      return { activePrefixes, blockedPrefixes, totalActiveBINs };
    } catch (err) {
      logger.error({ module: 'binSequenceDetector', err: err.message, tenantId }, 'Redis SCAN failed in getBINStats — falling back to in-memory store for this call');
      // fall through to in-memory below
    }
  }

  for (const [key, data] of memoryStore.entries()) {
    if (!key.startsWith(tenantKeyPrefix)) continue;
    tallyEntry(data);
  }

  return { activePrefixes, blockedPrefixes, totalActiveBINs };
}

module.exports = { checkBINSequence, recordBINAttempt, getBINStats, THRESHOLDS };
