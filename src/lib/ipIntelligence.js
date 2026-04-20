// ─── ChargeGuard IP Intelligence Module ──────────────────────────────────
// Production-grade IP analysis with:
// - Probabilistic scoring (not binary)
// - Confidence weighting
// - Dynamic TTL cache (LRU)
// - Circuit breaker (rate protection)
// - In-flight deduplication
// - Cache invalidation on fraud
// - Signal combining (datacenter + country mismatch)
// - Full observability logging

// ─── Cache & State ────────────────────────────────────────────────────────
const { recordIP, checkIPLimit } = require('./metrics');
const prometheus = require('./prometheus');
const logger = require('../lib/logger');

// ─── Feature Flag ─────────────────────────────────────────────────────────
// لو حصل bug في production → ENABLE_IP_INTEL=false في .env يوقفه فوراً
const IP_INTEL_ENABLED = process.env.ENABLE_IP_INTEL !== "false";

// ─── IP Normalization ─────────────────────────────────────────────────────
// بيتعامل مع IPv4, IPv6, IPv4-mapped IPv6, IP مع port
function normalizeIP(ip) {
  if (!ip) return null;
  let normalized = ip.trim();

  // ── Step 1: Bracketed IPv6 with optional port ([2001:db8::1]:443 → 2001:db8::1)
  // لازم يكون أول حاجة — عشان نشيل الـ brackets والـ port مع بعض
  const bracketedMatch = normalized.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracketedMatch) {
    return bracketedMatch[1];
  }

  // ── Step 2: IPv4 with port (192.168.1.1:443 → 192.168.1.1)
  // بس لو في ":" واحدة بس — IPv6 عنده أكتر من واحدة
  if (!normalized.includes("[") && normalized.split(":").length === 2) {
    normalized = normalized.split(":")[0];
  }

  // ── Step 3: IPv4-mapped IPv6 (::ffff:192.168.1.1 → 192.168.1.1)
  if (normalized.toLowerCase().startsWith("::ffff:")) {
    const extracted = normalized.slice(7);
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(extracted)) {
      return extracted;
    }
  }

  return normalized;
}

const ipCache = new Map();       // LRU cache for IP data
const inFlight = new Map();      // In-flight deduplication

const MAX_CACHE_SIZE   = 5000;   // Max entries before LRU eviction
const TIMEOUT_MS_WITH_CACHE    = 800;  // عندنا stale fallback — نصبر أقل
const TIMEOUT_MS_WITHOUT_CACHE = 1500; // مفيش fallback — نصبر أكتر
const MAX_REQ_PER_MIN = 40;

// Sliding Window — أقوى من Fixed Window
const { createSlidingWindow } = require('./metrics');
const ipRateLimiter = createSlidingWindow(MAX_REQ_PER_MIN);

// ─── TTL Strategy ─────────────────────────────────────────────────────────
// Datacenter IPs change more frequently — shorter TTL
// Residential IPs are stable — longer TTL

function getTTL(fraudScore) {
  const h = 60 * 60 * 1000;
  if (fraudScore === null || fraudScore === undefined) return 6 * h;
  if (fraudScore >= 75) return  2 * h;
  if (fraudScore >= 25) return  6 * h;
  return                       24 * h;
}

// ─── LRU Write ────────────────────────────────────────────────────────────
// بيضمن True LRU — eviction بيحصل بعد الـ read refresh
// الـ entry اللي بنكتبه دايماً آخر الـ Map — مش هيتشال فوراً
function lruSet(cache, key, value, maxSize) {
  if (cache.has(key)) cache.delete(key); // حرك لآخر الـ Map لو موجود
  else if (cache.size >= maxSize) {
    // Evict LRU — أول entry في الـ Map = least recently used
    const lruKey = cache.keys().next().value;
    cache.delete(lruKey);
  }
  cache.set(key, value);
}

// ─── Risk Computation ─────────────────────────────────────────────────────
// Probabilistic — returns 0.0 → 1.0
// Not binary — combines multiple signals with weights

function computeIPRisk(data) {
  // Primary signal: IPQS pre-trained fraud score (0-100 → 0.0-1.0)
  // This score already incorporates proxy, VPN, Tor, bot, etc.
  if (data.fraudScore !== null && data.fraudScore !== undefined) {
    // Direct mapping: fraudScore/100 gives probability (0-1)
    return Math.min(data.fraudScore / 100, 1.0);
  }

  // Fallback: if fraudScore missing (API failure), use individual signals
  let risk = 0;
  if (data.isTor)              risk += 0.30;
  if (data.isBot)              risk += 0.25;
  if (data.isProxy || data.isVpn) risk += 0.20;
  return Math.min(risk, 1.0);
}

// ─── Confidence by Source ─────────────────────────────────────────────────
// API result is less reliable than cached (API can fluctuate)

function getConfidence(source) {
  switch (source) {
    case "cache":   return 0.90;
    case "api":     return 0.80;
    case "timeout": return 0.20;
    case "skipped": return 0.10;
    default:        return 0.50;
  }
}

// ─── Fetch with Timeout ───────────────────────────────────────────────────

async function fetchIPData(ip, timeoutMs = TIMEOUT_MS_WITHOUT_CACHE) {
  const apiKey = process.env.IPQS_API_KEY;
  
  // ✅ الوضع الوهمي الآمن للتطوير (لا يعمل إلا إذا تم تفعيله صراحة)
  if (process.env.MOCK_IP_INTEL === 'true') {
    logger.debug({ module: 'ipIntel', ipMasked: ip.slice(0, 8) + '***' }, 'MOCK_IP_INTEL enabled — using mock data');
    
    // محاكاة تأخير الشبكة بشكل بسيط
    await new Promise(resolve => setTimeout(resolve, 50));
    
    // توليد بيانات وهمية واقعية (Google DNS كمثال)
    const isGoogleDNS = ip === '8.8.8.8' || ip === '8.8.4.4';
    return {
      countryCode: 'US',
      isp: isGoogleDNS ? 'Google' : 'Mock ISP',
      org: isGoogleDNS ? 'Google' : 'Mock Org',
      hosting: false,
      fraudScore: 0,
      isProxy: false,
      isVpn: false,
      isTor: false,
      isBot: false,
      asn: null,
      mobile: false,
    };
  }

  // 🚀 منطق الإنتاج (يستخدم API الحقيقي)
  if (!apiKey || apiKey === 'your_ipqualityscore_api_key_here') {
    logger.warn({ module: 'ipIntel' }, 'IPQS_API_KEY missing or invalid — IP intelligence degraded');
    prometheus.recordIPIntel('api', 'failure');
    return null;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`https://ipqualityscore.com/api/json/ip/${apiKey}/${ip}`, {
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!res.ok) {
      prometheus.recordIPIntel('api', 'failure');
      return null;
    }
    const data = await res.json();
    if (!data?.success) {
      prometheus.recordIPIntel('api', 'failure');
      return null;
    }

    return {
      countryCode:  data.country_code   ?? null,
      isp:          data.isp            ?? null,
      org:          data.organization   ?? null,
      hosting:      data.proxy === true || data.vpn === true || data.bot_status === true,
      fraudScore:   data.fraud_score    ?? null,
      isProxy:      data.proxy          === true,
      isVpn:        data.vpn            === true,
      isTor:        data.tor            === true,
      isBot:        data.bot_status     === true,
      asn:          data.asn            ?? null,
      mobile:       data.mobile         === true,
    };

  } catch {
    clearTimeout(timer);
    prometheus.recordIPIntel('api', 'failure');
    return null;
  }
}


// ─── Private IP Detection ─────────────────────────────────────────────────
// بيمنع SSRF attacks — الـ 172.16/12 range بيتحسب صح بالـ numeric parsing
function isPrivateOrReservedIP(ip) {
  if (!ip) return true;
  if (ip === "::1" || ip === "::") return true;
  if (ip.startsWith("fe80:") || ip.startsWith("fc") || ip.startsWith("fd")) return true;
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  const [a, b] = parts.map(Number);
  if (isNaN(a) || isNaN(b)) return true;
  return (
    a === 127 ||
    a === 10 ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31)
  );
}

// ─── Main: Get IP Intelligence ────────────────────────────────────────────
// Returns full intelligence object with risk score + confidence + metadata

async function getIPIntelligence(rawIp, merchantId = null) {
  // ── Feature Flag ────────────────────────────────────────────────────────
  if (!IP_INTEL_ENABLED) {
    logger.warn({ module: 'ipIntel' }, 'DISABLED via ENABLE_IP_INTEL=false — IP intelligence inactive');
    return { riskScore: 0, confidence: 0, country: null, isp: null, isDatacenter: false, source: "skipped" };
  }

  // ── IP Normalization + Validation ────────────────────────────────────────
  const ip = normalizeIP(rawIp);
  if (!ip) {
    return { riskScore: 0, confidence: 0, country: null, isp: null, isDatacenter: false, source: "skipped" };
  }


  // SSRF protection — block private/loopback/link-local IPs
  if (isPrivateOrReservedIP(ip)) {
    return { riskScore: 0, confidence: 0, country: null, isp: null, isDatacenter: false, source: "skipped" };
  }

  

  // ── Cache Check ──────────────────────────────────────────────────────────
  const cached = ipCache.get(ip);
  if (cached) {
    if (cached.expiry > Date.now()) {
      ipCache.delete(ip);
      ipCache.set(ip, cached);
      return { ...cached.data, source: "cache", confidence: getConfidence("cache") };
    } else {
      ipCache.delete(ip); // امسح الـ expired entry فوراً
    }
  }

  // ── Per-Merchant Rate Limit (بعد cache miss بس) ───────────────────────────
  if (!checkIPLimit(merchantId)) {
    prometheus.recordIPIntel('rate_limited', 'failure');
    return { riskScore: 0, confidence: 0.10, country: null, isp: null, isDatacenter: false, source: "skipped" };
  }

  // ── Circuit Breaker (بعد cache miss بس) ──────────────────────────────────
  if (!ipRateLimiter.isAllowed()) {
    logger.warn({ module: 'ipIntel', count: ipRateLimiter.count(), limit: MAX_REQ_PER_MIN }, 'Rate limit reached — skipping');
    return { riskScore: 0.15, confidence: 0.10, country: null, isp: null, isDatacenter: false, source: "skipped" };
  }

  // ── In-flight Deduplication ───────────────────────────────────────────────
  if (inFlight.has(ip)) {
    return inFlight.get(ip);
  }

  // ── Fetch ────────────────────────────────────────────────────────────────
  const promise = (async () => {
    const start = Date.now();

    try {
      const hasStaleCache = ipCache.has(ip);
      const data = await fetchIPData(
        ip,
        hasStaleCache ? TIMEOUT_MS_WITH_CACHE : TIMEOUT_MS_WITHOUT_CACHE,
      );
      const latency = Date.now() - start;

      let result;

      if (!data) {
        // Stale-while-revalidate — لو عندنا cached data قديم نستخدمه بـ confidence أقل
        const stale = ipCache.get(ip);
        if (stale) {
          // لو الـ IP كان clean (risk < 0.2) نكون أكثر تحفظاً — ممكن اتغير
          // لو كان risky (risk >= 0.2) نثق فيه أكثر — الـ risk مش بيتغير بسرعة
          const staleConfidence = stale.data.riskScore < 0.2 ? 0.20 : 0.40;
          logger.debug({ module: 'ipIntel', ipMasked: ip.slice(0, 8) + '***', staleConfidence }, 'API timeout — using stale cache');
          // مد الـ TTL 30 دقيقة — يدي فرصة للـ API يتعافى
          // بدون ده، كل request جديد هيلاقي expired ويحاول API call تاني
          stale.expiry = Date.now() + 30 * 60 * 1000;
          lruSet(ipCache, ip, stale, MAX_CACHE_SIZE);
          result = {
            ...stale.data,
            confidence: staleConfidence,
            source:     "stale",
          };
        } else {
          result = {
            riskScore:    0,
            confidence:   getConfidence("timeout"),
            country:      null,
            isp:          null,
            isDatacenter: false,
            source:       "timeout",
          };
          prometheus.recordIPIntel('timeout', 'failure');
        }
      } else {
        const riskScore    = computeIPRisk(data);
        const isDatacenter = data.hosting === true;

      // Unknown country = weak risk signal — floor بس مش addition
        // لو الـ IP خطير أصلاً (riskScore عالي) مش هنزود عليه
        // لو الـ IP clean بس مجهول المصدر → على الأقل 0.2
        const unknownFloor = !data.countryCode ? 0.2 : 0;
        result = {
          riskScore:    Math.max(riskScore, unknownFloor),
          confidence:   getConfidence("api"),
          country:      data.countryCode ?? null,
          isp:          data.isp ?? data.org ?? null,
          isDatacenter,
          fraudScore:   data.fraudScore  ?? null,
          isProxy:      data.isProxy     ?? false,
          isVpn:        data.isVpn       ?? false,
          isTor:        data.isTor       ?? false,
          isBot:        data.isBot       ?? false,
          asn:          data.asn         ?? null,
          mobile:       data.mobile      ?? false,
          source:       "api",
        };

        // Cache with dynamic TTL — True LRU write
        lruSet(ipCache, ip, {
          data:   result,
          expiry: Date.now() + getTTL(result.fraudScore),
        }, MAX_CACHE_SIZE);
      }

      recordIP(result.source, latency);
      logger.info({
  module: 'ipIntel',
  ipMasked: ip.slice(0, 8) + '***',
  risk: result.riskScore,
  datacenter: result.isDatacenter,
  source: result.source,
  latency,
}, 'IP intelligence result');

      return result;

    } finally {
      // ضمان إن الـ inFlight يتمسح دايماً حتى لو في error
      inFlight.delete(ip);
    }
  })();

  inFlight.set(ip, promise);
  return promise;
}

// ─── Cache Invalidation ───────────────────────────────────────────────────
// بيتستدعى من markOrderAsFraud علشان نمسح الـ cache لو الـ IP اتثبت fraud
// الـ IP ممكن يكون اتغير أو يكون VPN — مش هنثق في الـ cached result تاني

function invalidateIPCache(rawIp) {
  const ip = normalizeIP(rawIp);
  if (!ip) return;
  const deleted = ipCache.delete(ip);
  if (deleted) {
    logger.info({ module: 'ipIntel', ipMasked: ip.slice(0, 8) + '***' }, 'Cache invalidated');
  }
}

// ─── Apply IP Penalty to Score ────────────────────────────────────────────
// Centralized penalty calculation — called from riskScoring.js
// Returns { penalty, flags } to add to the score
//
// Design principles:
// 1. Contextual — penalty depends on order value
// 2. Probabilistic — weighted by confidence
// 3. Signal combining — datacenter + country mismatch = boosted penalty
// 4. Capped — max -25 total to prevent double counting with graph

function calculateIPPenalty(ipIntel, orderAmount, billingCountry) {
  if (!ipIntel || ipIntel.source === "skipped" || ipIntel.source === "timeout") {
    return { penalty: 0, flags: [] };
  }
  // stale: confidence منخفضة (0.20-0.40) → effectiveRisk منخفض → penalty منخفضة أوتوماتيكلي
  // مش بنعمل early return لأن الـ confidence weighting بيتعامل معاه

  const flags = [];
  let penalty = 0;
  // penalty هنا positive number — بيتطرح من الـ score في riskScoring.js
  // Cap final: Math.min(penalty, 25) يمنع double counting مع Identity Graph

  // Effective risk = riskScore × confidence
  const effectiveRisk = ipIntel.riskScore * ipIntel.confidence;

// ── Tor Penalty ──────────────────────────────────────────────────────────
  // Tor is categorically different — anonymization with criminal-use base rate
  if (ipIntel.isTor) {
    penalty += 30;
    flags.push({
      severity: "critical",
      text: `IP identified as Tor exit node — anonymized traffic, critical fraud risk`,
    });
  }

  // ── Bot / Botnet Penalty ──────────────────────────────────────────────────
  if (ipIntel.isBot) {
    penalty += 20;
    flags.push({
      severity: "critical",
      text: `IP flagged as bot or botnet participant — automated fraud risk`,
    });
  }

  // ── Datacenter / Hosting Penalty ────────────────────────────────────────
  if (effectiveRisk > 0.5) {    // High confidence datacenter
    const basePenalty = orderAmount > 200 ? 25 : 10;
    penalty += basePenalty;
    flags.push({
      severity: orderAmount > 200 ? "high" : "medium",
      text: `IP address identified as datacenter/VPN (${ipIntel.isp || "unknown ISP"}) — high fraud risk`,
    });
  } else if (effectiveRisk > 0.25) {
    // Medium confidence — partial signal
    const basePenalty = orderAmount > 200 ? 15 : 5;
    penalty += basePenalty;
    flags.push({
      severity: "medium",
      text: `IP address associated with hosting provider (${ipIntel.isp || "unknown ISP"})`,
    });
  }

  // ── Country Mismatch Penalty ─────────────────────────────────────────────
  // Replaces the old static Egyptian IPs check
  // Soft penalty — expats and travelers are real customers
  if (ipIntel.country && billingCountry && ipIntel.country !== billingCountry) {
    const mismatchPenalty = orderAmount > 100 ? 15 : 5;
    penalty += mismatchPenalty;
    flags.push({
      severity: orderAmount > 100 ? "high" : "medium",
      text: `IP country (${ipIntel.country}) doesn't match billing country (${billingCountry})`,
    });
  }

  // ── Signal Combining Boost ───────────────────────────────────────────────
  // Datacenter + Country Mismatch together = much stronger signal
  const hasDatacenter = effectiveRisk > 0.5;
  const hasCountryMismatch = ipIntel.country && billingCountry && ipIntel.country !== billingCountry;

  if (hasDatacenter && hasCountryMismatch) {
    penalty += 10; // Interaction boost
    flags.push({
      severity: "high",
      text: `Combined signal: datacenter IP + country mismatch — strong fraud indicator`,
    });
  }

  // ── Cap Total IP Penalty ─────────────────────────────────────────────────
  // Max -25 total — prevents double counting with Identity Graph IP node
  // riskScoring.js بيعمل: score -= penalty
// Tor and bot warrant a higher cap — they are categorically more dangerous
  // than datacenter IPs alone and are not double-counted by the Identity Graph
  const penaltyCap = (ipIntel.isTor || ipIntel.isBot) ? 35 : 25;
  penalty = Math.min(penalty, penaltyCap);
  // ── IP Normalization Signal ───────────────────────────────────────────────
  // لو الـ API رجع بدون country — ده signal ضعيف في نفسه
  if (ipIntel.source === "api" && !ipIntel.country && penalty === 0) {
    penalty = 5;
    flags.push({
      severity: "medium",
      text: "IP address could not be geolocated — unverifiable origin",
    });
  }

  return { penalty, flags };
}
module.exports = {
  getIPIntelligence,
  calculateIPPenalty,
  invalidateIPCache,
  normalizeIP,
};