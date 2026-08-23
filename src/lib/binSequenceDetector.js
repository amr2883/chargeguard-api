// --- ChargeGuard BIN Sequence Detector ---
// يكشف هجمات Card Testing حتى لو البوت غير IP + Device + Email في كل طلب
//
// الفكرة الأساسية:
// البوت بيجيب بطاقات من نفس الـ dump → نفس الـ BIN prefix (أول 4 أرقام)
// حتى لو غير كل حاجة تانية، الـ BIN range بيفضح نمط الهجوم
//
// 4 طبقات كشف:
// Layer 1: BIN Prefix Velocity  — كتير BINs من نفس الـ prefix في وقت قصير
// Layer 2: Sequential BIN Scan  — BINs بترتيب تصاعدي/تنازلي (علامة brute-force)
// Layer 3: Cross-Entity Linking — نفس الـ BIN prefix مع entities مختلفة تماماً
// Layer 4: Cross-Prefix Diversity — [إضافة جديدة] نفس الـ entity بيختبر
//          براندات/بنوك مختلفة تمامًا (BIN prefixes مختلفة) بدل تكرار
//          نفس الـ prefix — يقفل الفجوة اللي Layer 1/2/3 عمياء عنها لما
//          المهاجم بيلف على أنواع بطاقات متنوعة (Visa/Mastercard/Amex/...)

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

  // Layer 4 [NEW — bin-diverse attack fix]: كمية BIN prefixes مختلفة
  // (بنوك/براندات مختلفة تمامًا) من نفس الـ entity في 10 دقائق. عتبة
  // منخفضة عمدًا (4) — عميل حقيقي عمره ما بيختبر 4 بنوك/براندات مختلفة
  // في نفس الجلسة، فمفيش خطر false-positive حقيقي، وده بيقفل الفجوة
  // اللي Layer 1/2/3 عمياء عنها بالتصميم (بيجمّعوا بالـ prefix، مش
  // بالـ entity، فمهاجم بيلف على براندات مختلفة كان بيعدّي منهم الثلاثة).
  UNIQUE_PREFIXES_PER_ENTITY: 4,
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
    // Layer 1-3 entries: { bins: {...}, entities: {...}, blockedUntil }
    // Layer 4 entries:   { prefixes: {...}, blockedUntil } — added by
    // recordEntityPrefixAttempt's fallback path, a different shape under
    // the same memoryStore Map (key `${tenantId}:entity:${entity}`).
    // Without this branch, Object.keys(data.bins) throws on a Layer 4
    // entry (data.bins is undefined) — a synchronous exception inside a
    // setInterval callback is uncaught and crashes the whole Node
    // process, not just this cleanup tick.
    if (data.bins) {
      for (const bin of Object.keys(data.bins)) {
        const fresh = data.bins[bin].filter(t => t > now - WINDOW_MS);
        if (fresh.length === 0) delete data.bins[bin];
        else data.bins[bin] = fresh;
      }
      if (Object.keys(data.bins).length === 0 && !data.blockedUntil) {
        memoryStore.delete(key);
      }
    } else if (data.prefixes) {
      for (const prefix of Object.keys(data.prefixes)) {
        const fresh = data.prefixes[prefix].filter(t => t > now - WINDOW_MS);
        if (fresh.length === 0) delete data.prefixes[prefix];
        else data.prefixes[prefix] = fresh;
      }
      if (Object.keys(data.prefixes).length === 0 && !data.blockedUntil) {
        memoryStore.delete(key);
      }
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

// --- Lua script: atomic record-and-evaluate for Layer 4 (cross-prefix
// diversity) — نفس فلسفة RECORD_BIN_ATTEMPT_SCRIPT فوق بالحرف، لكن
// المفتاح هنا entity-scoped مش prefix-scoped: بيتتبّع كام BIN prefix
// مختلف (بنك/براند) شافهم نفس الـ entity، مش كام BIN شافهم نفس الـ prefix.
//
// KEYS[1] = entityStoreKey
// ARGV[1] = prefix
// ARGV[2] = now (ms)
// ARGV[3] = WINDOW_MS
// ARGV[4] = BLOCK_DURATION_MS
// ARGV[5] = THRESHOLDS.UNIQUE_PREFIXES_PER_ENTITY
// ARGV[6] = TTL in seconds (REDIS_TTL_SECONDS)
const RECORD_ENTITY_PREFIX_SCRIPT = `
local storeKey = KEYS[1]
local prefix = ARGV[1]
local now = tonumber(ARGV[2])
local windowMs = tonumber(ARGV[3])
local blockDurationMs = tonumber(ARGV[4])
local uniquePrefixesThreshold = tonumber(ARGV[5])
local ttlSeconds = tonumber(ARGV[6])

local raw = redis.call('GET', storeKey)
local data
if raw then
  data = cjson.decode(raw)
else
  data = { prefixes = {}, blockedUntil = cjson.null }
end
if data.prefixes == nil then data.prefixes = {} end

local windowStart = now - windowMs

if data.prefixes[prefix] == nil then data.prefixes[prefix] = {} end
table.insert(data.prefixes[prefix], now)

local prunedPrefixes = {}
for p, timestamps in pairs(data.prefixes) do
  local fresh = {}
  for _, t in ipairs(timestamps) do
    if t > windowStart then
      table.insert(fresh, t)
    end
  end
  if #fresh > 0 then
    prunedPrefixes[p] = fresh
  end
end
data.prefixes = prunedPrefixes

local activePrefixes = {}
for p, _ in pairs(data.prefixes) do
  table.insert(activePrefixes, p)
end

local triggered = false
local reason = cjson.null
local riskAddition = 0

if #activePrefixes >= uniquePrefixesThreshold then
  triggered = true
  reason = 'Entity tested ' .. #activePrefixes .. ' different card BIN prefixes (banks/brands) in 10 minutes — cross-brand card testing pattern'
  riskAddition = 45
end

if triggered then
  data.blockedUntil = now + blockDurationMs
end

redis.call('SET', storeKey, cjson.encode(data), 'EX', ttlSeconds)

local result = {
  triggered = triggered,
  reason = reason,
  riskAddition = riskAddition,
  activePrefixesCount = #activePrefixes,
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

// --- تسجيل محاولة جديدة لـ Layer 4 (تنوّع الـ prefix لنفس الـ entity) ---
// عكس recordBINAttempt فوق (اللي بيرجع null في المسار غير-الذري ويسيب
// الـ caller يعمل storeGet+checkPrefix بنفسه)، الدالة دي بترجع نتيجة
// جاهزة (triggered/reason/riskAddition) في المسارين (Redis أو fallback)
// دايمًا — عشان checkBINSequence يستهلكها مباشرة من غير خطوة قراءة تانية.
async function recordEntityPrefixAttempt({ tenantId, entity, prefix }) {
  if (!entity || !prefix) return { triggered: false, reason: null, riskAddition: 0 };

  const entityStoreKey = `${tenantId}:entity:${entity}`;
  const now = Date.now();

  if (usingRedis && redisClient && redisClient.status === 'ready') {
    try {
      const raw = await redisClient.eval(
        RECORD_ENTITY_PREFIX_SCRIPT,
        1,
        entityStoreKey,
        prefix,
        now,
        WINDOW_MS,
        BLOCK_DURATION_MS,
        THRESHOLDS.UNIQUE_PREFIXES_PER_ENTITY,
        REDIS_TTL_SECONDS
      );
      return JSON.parse(raw);
    } catch (err) {
      logger.error(
        { module: 'binSequenceDetector', err: err.message, entityStoreKey },
        'Redis EVAL failed for recordEntityPrefixAttempt — falling back to non-atomic read-modify-write for this call'
      );
      // fall through to the non-atomic path below
    }
  }

  let data = await storeGet(entityStoreKey);
  if (!data) {
    data = { prefixes: {}, blockedUntil: null };
  }
  if (!data.prefixes) data.prefixes = {};

  const existingTimestamps = data.prefixes[prefix] || [];
  existingTimestamps.push(now);
  data.prefixes[prefix] = existingTimestamps;

  const result = checkEntityPrefixes(data, now);
  if (result.triggered) {
    data.blockedUntil = now + BLOCK_DURATION_MS;
  }

  await storeSet(entityStoreKey, data);
  return result;
}

// --- فحص Layer 4 (تنوّع الـ prefix) لـ entity معين — نفس نمط checkPrefix
// تحت بالحرف، لكن بيعدّ prefixes مختلفة مش BINs مختلفة ---
function checkEntityPrefixes(data, now = Date.now()) {
  const windowStart = now - WINDOW_MS;
  const activePrefixes = [];
  for (const [prefix, timestamps] of Object.entries(data.prefixes || {})) {
    if (timestamps.some(t => t > windowStart)) {
      activePrefixes.push(prefix);
    }
  }

  if (activePrefixes.length >= THRESHOLDS.UNIQUE_PREFIXES_PER_ENTITY) {
    return {
      triggered: true,
      reason: `Entity tested ${activePrefixes.length} different card BIN prefixes (banks/brands) in 10 minutes — cross-brand card testing pattern`,
      riskAddition: 45,
    };
  }

  return { triggered: false, reason: null, riskAddition: 0 };
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

  // entity = IP أو device (أيهما متاح) — نفس التعريف الأصلي، لسه مستخدم
  // في تسجيل BIN attempts لـ Layer 1/2/3 (زي ما كان بالظبط قبل الفيكس).
  const entity = ipAddress || deviceFingerprint || 'unknown';

  // ─── Layer 4 [NEW]: Cross-Prefix Diversity ─────────────────────────────
  // diversityEntity منفصلة عمدًا عن entity فوق: بتفضّل deviceFingerprint
  // على IP (عكس entity العادية اللي بتفضّل IP). السبب: الطبقة دي عتبتها
  // ضيقة جدًا (4 بنوك مختلفة بس) عشان تمسك الهجوم بسرعة — استخدام IP
  // كمفتاح أساسي هنا كان ممكن يعمل false positive على شبكة مكتب/شبكة
  // موبايل مشتركة (عملاء حقيقيين مختلفين وراء نفس الـ IP، كل واحد ببنك
  // مختلف). device fingerprint أدق بكتير كمعرّف "نفس الجلسة/المتصفح"،
  // فهو الأنسب لطبقة بالحساسية دي. بيرجع لـ IP بس لو مفيش fingerprint
  // خالص (نفس fallback المستخدم في كل مكان تاني في المشروع).
  const diversityEntity = deviceFingerprint || ipAddress || 'unknown';
  const entityStoreKey = `${tenantId}:entity:${diversityEntity}`;
  const entityData = await storeGet(entityStoreKey);
  if (entityData?.blockedUntil && entityData.blockedUntil > now) {
    return {
      blocked: true,
      riskAddition: 50,
      reason: `Entity temporarily blocked — cross-brand card testing pattern (active attack wave)`,
      layer: 0,
    };
  }

  const entityResult = await recordEntityPrefixAttempt({ tenantId, entity: diversityEntity, prefix });
  if (entityResult && entityResult.triggered) {
    return {
      blocked: true,
      riskAddition: entityResult.riskAddition || 0,
      reason: entityResult.reason,
      layer: 4,
    };
  }
  // ─── End Layer 4 ────────────────────────────────────────────────────────

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
    // Layer 4 entries (`${tenantId}:entity:${entity}`) also match this
    // tenant-prefix filter but have a different shape ({ prefixes },
    // no `bins`) — tallyEntry() assumes the Layer 1-3 shape and throws
    // on them. getBINStats() is specifically BIN-prefix stats, so these
    // are simply out of scope here, not an error case.
    if (key.includes(':entity:')) continue;
    tallyEntry(data);
  }

  return { activePrefixes, blockedPrefixes, totalActiveBINs };
}

module.exports = { checkBINSequence, recordBINAttempt, recordEntityPrefixAttempt, getBINStats, THRESHOLDS };
