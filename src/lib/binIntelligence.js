// ─── ChargeGuard BIN Intelligence Module ───────────────────────────────────
// Zero-cost initial strategy: local DB from open-source CSV + free API fallback.
// Layers:
// 1. In-memory LRU cache
// 2. Local DB (BinRecord table)
// 3. binlist.net free API (10k/month)
// 4. Neutrino API (paid upgrade when needed)
//
// Feature flags: ENABLE_BIN_INTEL (default true), BIN_FALLBACK_API (free|neutrino)

// const db = require("../db.server.js"); // غير مطلوب حاليًا
const { recordBIN, checkBINLimit, binlistGlobalBucket } = require('./metrics');
const prometheus = require('./prometheus');
const logger = require('../lib/logger');
const { calculateCountryRiskPenalty } = require('./countryRisk');
// binlistGlobalBucket imported from metrics
// const { calculateCountryRiskPenalty } = require('./countryRisk'); // غير مطلوب حاليًا

const BIN_INTEL_ENABLED = process.env.ENABLE_BIN_INTEL !== "false";
const NEUTRINO_API_KEY = process.env.NEUTRINO_API_KEY;
const USE_FREE_API = process.env.BIN_FALLBACK_API !== "neutrino"; // default free

const MAX_BIN_CACHE = 5000;
const BIN_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// ─── True LRU Cache ──────────────────────────────────────────────────────
// JS Map يحتفظ بـ insertion order — بنستغل ده لعمل LRU حقيقي
// set/get = O(1) — delete + re-insert بيحرك الـ key لآخر الـ Map
class LRUCache {
  #cache = new Map();
  #maxSize;
  #ttlMs;

  constructor(maxSize, ttlMs) {
    this.#maxSize = maxSize;
    this.#ttlMs   = ttlMs;
  }

  get(key) {
    const entry = this.#cache.get(key);
    if (!entry) return null;
    if (entry.expiry < Date.now()) {
      this.#cache.delete(key);
      return null;
    }
    // True LRU refresh — move to end
    this.#cache.delete(key);
    this.#cache.set(key, entry);
    return entry.data;
  }

  set(key, data) {
    if (this.#cache.has(key)) {
      this.#cache.delete(key); // أزل القديم عشان تحدث الـ order
    } else if (this.#cache.size >= this.#maxSize) {
      // Evict LRU — أول entry في الـ Map = least recently used
      const lruKey = this.#cache.keys().next().value;
      this.#cache.delete(lruKey);
    }
    this.#cache.set(key, { data, expiry: Date.now() + this.#ttlMs });
  }

  has(key) {
    const entry = this.#cache.get(key);
    if (!entry) return false;
    if (entry.expiry < Date.now()) {
      this.#cache.delete(key);
      return false;
    }
    return true;
  }

  get size() { return this.#cache.size; }
}

const binCache = new LRUCache(MAX_BIN_CACHE, BIN_CACHE_TTL_MS);

// ─── Helper: Normalize BIN (6-8 digits) ─────────────────────────────────
function normalizeBin(raw) {
  if (!raw) return null;
  const cleaned = String(raw).replace(/\D/g, '');
  // keep first 8 digits if present, else all
  const bin = cleaned.slice(0, 8);
  return bin.length >= 6 ? bin : null;
}

// ─── Extract BIN from Shopify order ────────────────────────────────────
// Extract BIN from order (WooCommerce primary, Shopify fallback)
function extractBIN(order) {
  const bin = order.payment_details?.card_bin
           ?? order.payment_details?.credit_card_bin
           ?? order.payment_details?.cardBin
           ?? null;
  return normalizeBin(bin);
}

// ─── Local DB lookup with progressive prefix search ────────────────────
// بترجع { record, effectiveBin } — effectiveBin للـ lastSeenAt update
// الـ cache key منفصل عنه — دايماً bin.slice(0,6) في getBINIntelligence
async function lookupInLocalDB(bin) {
  // قاعدة البيانات المحلية غير متاحة حاليًا - نعتمد على API الخارجي
  return null;
}

// ─── Fetch from binlist.net free API ───────────────────────────────────
async function fetchFromBinlistNet(bin) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 500);
  try {
    const res = await fetch(`https://lookup.binlist.net/${bin.slice(0, 6)}`, {
      headers: { 'Accept-Version': '3' },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      prometheus.recordBINIntel('binlist_net', 'failure');
      return null;
    }
    const data = await res.json();
    if (!data.scheme && !data.type) {
      prometheus.recordBINIntel('binlist_net', 'failure');
      return null;
    }

    return {
      brand: data.scheme?.toUpperCase() ?? null,
      cardType: data.type ?? null,
      isPrepaid: data.prepaid === true,
      isCommercial: false,
      issuerName: data.bank?.name ?? null,
      issuerCountry: data.country?.alpha2?.toUpperCase() ?? null,
      cardCategory: data.prepaid ? 'prepaid' : null,
      source: 'binlist_net',
    };
  } catch {
    clearTimeout(timer);
    prometheus.recordBINIntel('binlist_net', 'failure');
    return null;
  }
}

// ─── Fetch from Neutrino API (paid) ────────────────────────────────────
// Neutrino يستخدم POST + application/x-www-form-urlencoded
// Auth: user-id header + api-key header (مش API-Key)
async function fetchFromNeutrino(bin) {
  if (!NEUTRINO_API_KEY) return null;
  const NEUTRINO_USER_ID = process.env.NEUTRINO_USER_ID;
  if (!NEUTRINO_USER_ID) {
    logger.warn({ module: 'binIntel' }, 'NEUTRINO_USER_ID not set — skipping Neutrino');
    return null;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 800);
  try {
    const body = new URLSearchParams({ 'bin-number': bin.slice(0, 6) });
    const res = await fetch('https://neutrinoapi.net/bin-lookup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'user-id':  NEUTRINO_USER_ID,
        'api-key':  NEUTRINO_API_KEY,
      },
      body,
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      prometheus.recordBINIntel('neutrino', 'failure');
      return null;
    }
    const data = await res.json();
    if (!data.valid) {
      prometheus.recordBINIntel('neutrino', 'failure');
      return null;
    }

    return {
      brand: data.card_brand?.toUpperCase() ?? null,
      cardType: data.card_type?.toUpperCase() ?? null,
      isPrepaid: data.card_type === 'PREPAID',
      isCommercial: data.is_commercial ?? false,
      issuerName: data.issuer ?? null,
      issuerCountry: data.country_code?.toUpperCase() ?? null,
      cardCategory: data.card_category ?? null,
      source: 'neutrino',
    };
  } catch {
    clearTimeout(timer);
    prometheus.recordBINIntel('neutrino', 'failure');
    return null;
  }
}

// ─── Write to cache and optionally DB (if from API) ─────────────────────
// cacheKey = effectiveBin (6-8 digits حسب ما الـ DB لاقى) — يضمن cache consistency
// binPrefix = دايماً 6 digits للـ DB — consistent مع الـ BIN standard
async function persistBinData(cacheKey, data) {
  // Update in-memory cache
  binCache.set(cacheKey, data);
  // DB persistence معطل مؤقتًا - لا توجد قاعدة بيانات محلية بعد
}

// ─── Main entry point ───────────────────────────────────────────────────
async function getBINIntelligence(binRaw, merchantId = null) {
  console.log(`[BIN] getBINIntelligence called with binRaw = ${binRaw}`);
  const start = Date.now();
  
  // وضع البيانات الوهمية للتطوير (مثل IP Intelligence)
  if (process.env.MOCK_BIN_INTEL === 'true') {
    console.log(`[BIN] MOCK_BIN_INTEL enabled — using mock data for ${binRaw}`);
    // بيانات وهمية لـ BIN نيجيري (506146)
    if (binRaw === '506146') {
      return {
        brand: 'VISA',
        cardType: 'credit',
        isPrepaid: false,
        isCommercial: false,
        issuerName: 'Test Bank Nigeria',
        issuerCountry: 'NG',
        cardCategory: 'classic',
        source: 'mock'
      };
    }
    // بيانات افتراضية لأي BIN آخر
    return {
      brand: 'VISA',
      cardType: 'credit',
      isPrepaid: false,
      isCommercial: false,
      issuerName: 'Mock Bank',
      issuerCountry: 'US',
      cardCategory: 'classic',
      source: 'mock'
    };
  }
  
  if (!BIN_INTEL_ENABLED) {
    prometheus.recordBINIntel('disabled', 'failure');
    return _skipped();
  }
  const bin = normalizeBin(binRaw);
  if (!bin) {
    prometheus.recordBINIntel('invalid', 'failure');
    return _skipped();
  }

  // 1. Cache أولاً — fast path بالـ 6-digit key
  // الـ DB دايماً بيحفظ 6 digits → الـ cache key ثابت على 6
  // يضمن إن "42424201" و"42424202" من نفس الـ issuer يشاركوا نفس الـ entry
  const cacheKey = bin.slice(0, 6);
  const cached = binCache.get(cacheKey);
  if (cached) {
    recordBIN('cache', Date.now() - start);
    return { ...cached, source: 'cache' };
  }

  // 2. Local DB lookup
  const dbResult = await lookupInLocalDB(bin);

  // 3. Local DB hit — map الـ record لـ data object
  if (dbResult) {
    const { record } = dbResult;
    const data = {
      brand:        record.brand,
      cardType:     record.cardType,
      cardCategory: record.cardCategory,
      issuerName:   record.issuerName,
      issuerCountry: record.issuerCountry,
      isPrepaid:    record.isPrepaid,
      isCommercial: record.isCommercial,
      source:       record.source,
      // riskScore مش هنا — calculateBINPenalty هي المسؤولة عن الـ risk
    };

    // اكتب في الـ cache بالـ effective key — fire-and-forget مقصود للـ cache
    // كش في الـ memory فقط — مش محتاج DB write لأن البيانات جاية من DB أصلاً
    binCache.set(cacheKey, data);

    // تحديث lastSeenAt معطل مؤقتًا
    // db.binRecord.update({
    //   where: { bin: record.bin },
    //   data: { lastSeenAt: new Date() },
    // }).catch(err => logger.error({ module: 'binIntel', err }, 'Failed to update lastSeenAt'));

    recordBIN('local_db', Date.now() - start);
    return { ...data, source: 'local_db' };
  }

  // 4. Rate-limit check — two layers بترتيب صح
  // Layer 1: Per-merchant أولاً — أرخص check، مش بيحرق global tokens
  if (!checkBINLimit(merchantId)) {
    prometheus.recordBINIntel('rate_limited', 'failure');
    return _skipped();
  }
  // Layer 2: Global bucket — بعد ما تأكدنا إن الـ merchant في الـ budget
  // يحمي binlist.net من الـ IP ban عبر كل المerchants
  if (USE_FREE_API && !binlistGlobalBucket.consume()) {
    logger.warn({
      module:    'binIntel',
      available: binlistGlobalBucket.available,
    }, 'Global binlist.net rate limit reached — skipping');
    prometheus.recordBINIntel('rate_limited', 'failure');
    return _skipped();
  }

  // 5. API fallback
  let apiData = null;
  if (USE_FREE_API) {
    apiData = await fetchFromBinlistNet(bin);
    if (apiData) apiData.source = 'binlist_net';
  } else if (NEUTRINO_API_KEY) {
    apiData = await fetchFromNeutrino(bin);
    if (apiData) apiData.source = 'neutrino';
  }

  if (apiData) {
    // riskScore مش بيتحفظ هنا — pure data فقط
    const result = { ...apiData };
    await persistBinData(cacheKey, result);
    recordBIN(apiData.source, Date.now() - start);
    return result;
  }

  console.log(`[BIN] getBINIntelligence returning _skipped()`);
  prometheus.recordBINIntel('all_failed', 'failure');
  return _skipped();
}

// ─── Penalty calculation (to be used in riskScoring.js) ─────────────────
function calculateBINPenalty(binIntel, order, isNewCustomer, ipIntel = null, merchantConfig = null) {
  if (!binIntel || binIntel.source === 'skipped') return { penalty: 0, flags: [] };

  let penalty = 0;
  const flags = [];
  const amount = order.amount || 0;

  // helper — probabilistic combination يمنع overcounting
  const addPenalty = (p) => {
    penalty = penalty + p - (penalty * p) / 100;
  };

  // Signal 1: Prepaid card
  if (binIntel.isPrepaid) {
    const base = amount > 200 ? 20 : 10;
    addPenalty(base);
    flags.push({
      severity: amount > 200 ? 'high' : 'medium',
      text: `Prepaid card detected (${binIntel.brand || 'unknown'}) — elevated fraud risk`,
    });

    if (isNewCustomer && amount >= 150) {
      addPenalty(20);
      flags.push({
        severity: 'critical',
        text: `High‑risk combo: prepaid + new customer + $${amount.toFixed(0)} order`,
      });
    }
  }

  // Signal 2: Card country vs billing country mismatch
  let billingCountry = null;
  try {
    // billingAddress ممكن يكون parsed object أو raw string — بنتعامل مع الاتنين
    const billing = typeof order.billingAddress === "string"
      ? JSON.parse(order.billingAddress)
      : order.billingAddress ?? null;
    billingCountry = billing?.country?.toUpperCase() ?? null;
  } catch { /* ignore */ }

  if (binIntel.issuerCountry && billingCountry && binIntel.issuerCountry !== billingCountry) {
    const p = amount > 100 ? 12 : 5;
    addPenalty(p);
    flags.push({
      severity: amount > 100 ? 'high' : 'medium',
      text: `Card issued in ${binIntel.issuerCountry}, billing in ${billingCountry}`,
    });
  }

  // Signal 3: Triple mismatch (card + IP + billing)
  const ipCountry = ipIntel?.country?.toUpperCase() ?? null;
  if (binIntel.issuerCountry && ipCountry && billingCountry) {
    const mismatches = [
      binIntel.issuerCountry !== ipCountry,
      binIntel.issuerCountry !== billingCountry,
      ipCountry !== billingCountry,
    ].filter(Boolean).length;
    if (mismatches >= 2) {
      addPenalty(15);
      flags.push({
        severity: 'critical',
        text: `Geographic triple mismatch — card: ${binIntel.issuerCountry}, IP: ${ipCountry}, billing: ${billingCountry}`,
      });
    }
  }

  console.log(`[BIN] issuerCountry = ${binIntel.issuerCountry}`);
  // Signal 4: Country risk
  if (amount > 50 && binIntel.issuerCountry) {
    try {
      const { calculateCountryRiskPenalty } = require('./countryRisk');
      const countryRisk = calculateCountryRiskPenalty(
        binIntel.issuerCountry,
        amount,
        merchantConfig,
      );
      if (countryRisk) {
        addPenalty(countryRisk.penalty);
        flags.push(countryRisk.flag);
      }
    } catch (err) {
      // Non-critical — continue without country risk
    }
  }

  // Cap at 40 (similar to email and IP)
  penalty = Math.min(penalty, 40);
  return { penalty, flags };
}

// ─── Helpers ────────────────────────────────────────────────────────────
// evictIfNeeded أتشالت — LRUCache class بتتعامل مع الـ eviction داخلياً

function _skipped() {
  return {
    source:       'skipped',
    brand:        null,
    cardType:     null,
    cardCategory: null,
    issuerName:   null,
    issuerCountry: null,
    isPrepaid:    false,
    isCommercial: false,
    // riskScore مش موجود هنا — calculateBINPenalty هي المسؤولة عن الـ risk
  };
}
module.exports = {
  getBINIntelligence,
  calculateBINPenalty,
  normalizeBin,
  extractBIN,
};