// ─── ChargeGuard Email Intelligence Module ───────────────────────────────
// Production-grade email analysis without external API key
//
// Layers:
// 1. DNS Domain Validation (domain existence check)
// 2. Enhanced Rules (entropy, TLD risk, pattern analysis)
//
// NOTE: HaveIBeenPwned integration removed — was checking passwords not emails.
// TODO: Re-integrate HIBP using the correct email search endpoint if needed
//       (requires paid API key: https://haveibeenpwned.com/API/v3)
//       isPwned and breachCount are intentionally always false/0 until then.
//
// Design principles:
// - Privacy-first: email never sent to external APIs in plain text
// - Probabilistic scoring (not binary)
// - Confidence weighting
// - Dynamic TTL cache (LRU — both emailCache and dnsCache)
// - Circuit breaker (rate protection)
// - Feature flag for emergency disable
// - Non-critical: failures never block order scoring

const { Resolver } = require('dns').promises;
const { recordEmail, checkEmailLimit, createSlidingWindow } = require('./metrics');
const prometheus = require('./prometheus');
const { normalizeEmail } = require('./utils');
const logger = require('../lib/logger');
// ─── Feature Flag ─────────────────────────────────────────────────────────
const EMAIL_INTEL_ENABLED = process.env.ENABLE_EMAIL_INTEL !== "false";

// Hard-block feature flag — independent of EMAIL_INTEL_ENABLED. This lets
// you disable EMAIL_INTEL_ENABLED (the full external-lookup pipeline) while
// keeping the cheap hard-block active, or vice versa, for gradual rollout /
// emergency disable without redeploying.
const EMAIL_HARD_BLOCK_ENABLED = process.env.ENABLE_EMAIL_HARD_BLOCK !== "false";

// ─── Cache & State ────────────────────────────────────────────────────────
const emailCache = new Map();    // LRU cache for email intelligence
const inFlight   = new Map();    // In-flight deduplication
const dnsCache   = new Map();    // LRU cache for DNS results (separate TTL)

const MAX_CACHE_SIZE  = 5000;
const TIMEOUT_MS      = 400;     // Slightly higher than IP (DNS can be slow)
const MAX_REQ_PER_MIN = 35;

const emailRateLimiter = createSlidingWindow(MAX_REQ_PER_MIN);

// ─── LRU Helpers ──────────────────────────────────────────────────────────
// lruSet: يضمن True LRU — eviction جوه الـ write مش في function منفصلة
// ─── LRU Write ────────────────────────────────────────────────────────────
// True LRU — eviction بيحصل جوه الـ write مش في function منفصلة
// consistent مع binIntelligence.js LRUCache implementation
function lruSet(cache, key, value, maxSize) {
  if (cache.has(key)) cache.delete(key);
  else if (cache.size >= maxSize) {
    const lruKey = cache.keys().next().value;
    cache.delete(lruKey);
  }
  cache.set(key, value);
}

// getFromCache: يجيب القيمة ويعمل LRU refresh (delete + re-insert)
// FIX: dnsCache كانت بتعمل eviction على الـ write بس مش على الـ read
//      النتيجة: FIFO بدل LRU — الـ domains الأكتر استخداماً بتتمسح
//      الحل: أي read بيعمل re-insert عشان الـ entry يفضل آخر الـ Map
function getFromCache(cache, key) {
  const entry = cache.get(key);
  if (!entry || entry.expiry <= Date.now()) {
    cache.delete(key); // شيل الـ expired entry لو موجود
    return null;
  }
  // LRU refresh — re-insert at end of Map
  cache.delete(key);
  cache.set(key, entry);
  return entry;
}

// ─── TTL Strategy ─────────────────────────────────────────────────────────
// Suspicious domains change more — shorter TTL
function getEmailTTL(risk) {
  if (risk > 0.8) return  2 * 60 * 60 * 1000;  // 2h  — high risk
  if (risk > 0.5) return  6 * 60 * 60 * 1000;  // 6h  — medium risk
  if (risk > 0.2) return 24 * 60 * 60 * 1000;  // 24h — low risk
  return                 48 * 60 * 60 * 1000;  // 48h — clean email
}

// ─── Confidence by Source ─────────────────────────────────────────────────
function getConfidence(source) {
  switch (source) {
    case "cache":   return 0.90;
    case "full":    return 0.85; // All checks passed
    case "partial": return 0.65; // Some checks failed (timeout etc)
    case "rules":   return 0.50; // Rules only, no external checks
    case "timeout": return 0.20;
    case "skipped": return 0.10;
    default:        return 0.40;
  }
}


// ─── Layer 1: DNS Domain Validation ───────────────────────────────────────
// بنشيك لو الـ domain موجود فعلاً
// domain مش موجود = email وهمي أو مؤقت
//
// FIX: شيلنا الـ AbortController — كان بيتعمل بس مش بيتربط بالـ dns.resolveMx
//      لأن Node.js dns module مش بيدعم AbortSignal
//      النتيجة: memory overhead + وهم إن الـ request بيتكنسل وهو لأ
//      الحل: Promise.race بالـ timeout بس — ده اللي بيشتغل فعلاً
//
// FIX2: إضافة clearTimeout لمنع تسرب الذاكرة
// FIX3: حذف المفتاح قبل set لضمان LRU حقيقي عند الكتابة

async function checkDomainDNS(domain) {
  const cached = getFromCache(dnsCache, domain);
  if (cached) return cached.result;

  const resolver = new Resolver();
  let timeoutId;
  try {
    const mxRecords = await Promise.race([
      resolver.resolveMx(domain),
      new Promise((_, reject) => {
        timeoutId = setTimeout(() => {
          resolver.cancel();
          reject(new Error("timeout"));
        }, TIMEOUT_MS);
      }),
    ]);
    clearTimeout(timeoutId);

    const result = {
      exists:   true,
      hasMX:    mxRecords.length > 0,
      mxCount:  mxRecords.length,
      uncertain: false,
    };

    // Cache for 24 hours — DNS doesn't change often
    lruSet(dnsCache, domain, { result, expiry: Date.now() + 24 * 60 * 60 * 1000 }, MAX_CACHE_SIZE);

    return result;

  } catch (err) {
    clearTimeout(timeoutId);

    // فرق مهم جداً:
    // ENOTFOUND/ENODATA = domain مش موجود فعلاً → penalty عالي
    // timeout/ECONNREFUSED = network issue → uncertainty بس مش penalty
    const isDefinitelyNotFound =
      err.code === "ENOTFOUND" || err.code === "ENODATA";
    const isNetworkError =
      err.message === "timeout" ||
      err.code === "ECONNREFUSED" ||
      err.code === "ETIMEOUT";

    const result = {
      exists:    isDefinitelyNotFound ? false : true, // لو network error → نفترض موجود
      hasMX:     false,
      mxCount:   0,
      uncertain: isNetworkError,
    };

    // لو domain مش موجود → cache أطول (مش هيتغير)
    // لو network error → cache أقصر (نجرب تاني بعدين)
    const ttl = isDefinitelyNotFound
      ? 24 * 60 * 60 * 1000  // 24 hours
      :  30 * 60 * 1000;     // 30 minutes فقط للـ network errors
    lruSet(dnsCache, domain, { result, expiry: Date.now() + ttl }, MAX_CACHE_SIZE);
    if (isNetworkError) {
      prometheus.recordEmailIntel('dns', 'failure');
    }
    return result;
  }
}

// ─── Layer 2: Enhanced Rules ───────────────────────────────────────────────
// Rules-based analysis — no external calls needed

// High-risk TLDs — commonly used in fraud
const HIGH_RISK_TLDS = new Set([
  "xyz", "top", "click", "link", "work", "loan", "win", "bid",
  "gq", "ml", "tk", "cf", "ga",  // Free domains often used in fraud
  "cc", "pw", "su", "casino", "download",
]);

// Known disposable email providers
let disposableDomains = new Set([
  "tempmail.com", "guerrillamail.com", "mailinator.com", "throwam.com",
  "trashmail.com", "fakeinbox.com", "yopmail.com", "sharklasers.com",
  "guerrillamailblock.com", "grr.la", "spam4.me", "trashmail.at",
  "dispostable.com", "maildrop.cc", "spamgourmet.com", "mytemp.email",
  "tempinbox.com", "throwaway.email", "discard.email", "spamherr.com",
]);

const DISPOSABLE_LIST_URL =
  "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf";

async function refreshDisposableList(retryCount = 0) {
  const MAX_RETRIES  = 4;
  const RETRY_DELAYS = [1, 2, 4, 8]; // دقايق — exponential backoff

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(DISPOSABLE_LIST_URL, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const parsed = text
      .split("\n")
      .map(line => line.trim())
      .filter(line => line.length > 0 && !line.startsWith("#"));
    if (parsed.length > 1000) {
      disposableDomains = new Set([...disposableDomains, ...parsed]);
      logger.info({ module: 'emailIntel', domainsCount: disposableDomains.size, source: 'github' }, 'Disposable list loaded');
    } else {
      logger.warn({ module: 'emailIntel', parsedLength: parsed.length }, 'GitHub list suspiciously small — keeping existing');
    }
  } catch (err) {
    clearTimeout(timer);
    logger.warn({ module: 'emailIntel', domainsCount: disposableDomains.size, err: err.message, retryCount }, 'Disposable list fetch failed');

    // Exponential backoff — بنحاول تاني لو لسه في retries
    if (retryCount < MAX_RETRIES) {
      const delayMinutes = RETRY_DELAYS[retryCount];
      const delayMs      = delayMinutes * 60 * 1000;
      logger.info({ module: 'emailIntel', retryIn: `${delayMinutes}m`, attempt: retryCount + 1 }, 'Retrying disposable list fetch');
      setTimeout(() => refreshDisposableList(retryCount + 1), delayMs);
    } else {
      // وصلنا لـ max retries — نستنى الـ 24h interval العادي
      logger.warn({ module: 'emailIntel', domainsCount: disposableDomains.size, source: 'fallback' }, 'Max retries reached — using fallback list until next scheduled refresh');
    }
  }
}

// Jitter startup — يمنع thundering herd لو في multiple workers
// كل worker بيستنى وقت عشوائي مختلف بين 0 و5 دقايق قبل أول fetch
// بعدين بيعمل refresh كل 24h + jitter صغير يمنع التزامن
const STARTUP_JITTER_MS  = Math.random() * 5 * 60 * 1000;  // 0-5 دقايق
const INTERVAL_JITTER_MS = Math.random() * 30 * 60 * 1000; // 0-30 دقيقة

// عدم تشغيل التحميل التلقائي أثناء الاختبارات
if (process.env.NODE_ENV !== 'test') {
  setTimeout(() => {
    refreshDisposableList();
    setInterval(
      refreshDisposableList,
      24 * 60 * 60 * 1000 + INTERVAL_JITTER_MS,
    );
  }, STARTUP_JITTER_MS);
}
// Known free providers (lower risk than disposable but still notable)
const FREE_PROVIDERS = new Set([
  "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com",
  "outlook.com", "live.com", "aol.com", "icloud.com",
  "protonmail.com", "pm.me", "tutanota.com",
]);

function analyzeEmailRules(email) {
  const lower = email.toLowerCase();
  const [local, domain] = lower.split("@");
  if (!domain) {
    // FIX: return safe object with default values
    return {
      riskScore: 0,
      signals: [],
      domain: '',
      tld: '',
      isFreeProvider: false,
      isDisposable: false,
    };
  }

  const signals  = [];
  let riskScore  = 0;

  // ── Disposable domain ────────────────────────────────────────────────────
  // ── Domain Risk (probabilistic combination) ──────────────────────────────
  // الـ signals دي مرتبطة ببعض — نفس الـ root cause غالباً
  // P(A or B) = P(A) + P(B) - P(A)*P(B) — يمنع overcounting
  let domainRisk = 0;

  const addDomainSignal = (signal) => {
    domainRisk = domainRisk + signal - domainRisk * signal;
  };

  if (disposableDomains.has(domain)) {
    addDomainSignal(0.80);
    signals.push({ type: "disposable_domain", weight: 0.80 });
  }

  const tld = domain.split(".").pop();
  if (HIGH_RISK_TLDS.has(tld)) {
    addDomainSignal(0.40);
    signals.push({ type: "high_risk_tld", value: tld, weight: 0.40 });
  }

  const domainWithoutTLD = domain.split(".").slice(0, -1).join(".");
  if (domainWithoutTLD.length > 20) {
    addDomainSignal(0.20);
    signals.push({ type: "long_domain", length: domainWithoutTLD.length, weight: 0.20 });
  }

  // ── Username Risk (probabilistic combination) ────────────────────────────
  // username signals مستقلة عن الـ domain signals
  let usernameRisk = 0;

  const addUsernameSignal = (signal) => {
    usernameRisk = usernameRisk + signal - usernameRisk * signal;
  };

  const entropy = local.length >= 6 ? calculateEntropy(local) : 0;
  const numbers      = (local.match(/\d/g) || []).length;
  const numericRatio = numbers / local.length;

  if (entropy > 4.0 && local.length > 8 && numericRatio > 0.3) {
    addUsernameSignal(0.30);
    signals.push({ type: "high_entropy_username", entropy: entropy.toFixed(2), weight: 0.30 });
  }

  if (numericRatio > 0.5 && local.length > 4) {
    addUsernameSignal(0.25);
    signals.push({ type: "high_numeric_ratio", ratio: numericRatio.toFixed(2), weight: 0.25 });
  }

  // ── Final Risk — combination بين domain و username ───────────────────────
  // الاتنين مستقلين عن بعض — probabilistic combination
  riskScore = domainRisk + usernameRisk - domainRisk * usernameRisk;

  // ── Free provider ────────────────────────────────────────────────────────
  const isFreeProvider = FREE_PROVIDERS.has(domain);
  if (isFreeProvider) {
    signals.push({ type: "free_provider", weight: 0 }); // Flag only, no penalty
  }

  return {
    riskScore:    Math.min(riskScore, 1.0),
    signals,
    domain,
    tld,
    isFreeProvider,
    isDisposable: disposableDomains.has(domain),
  };
}

// Shannon entropy — measures randomness of username
function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const chars = [...str];
  const len   = chars.length;
  const freq  = {};
  for (const c of chars) freq[c] = (freq[c] || 0) + 1;
  return Object.values(freq).reduce((entropy, count) => {
    const p = count / len;
    return entropy - p * Math.log2(p);
  }, 0);
}

// ─── Cheap Hard-Block Check ────────────────────────────────────────────────
// Deliberately independent of getEmailIntelligence()'s cache/rate-limit/
// circuit-breaker machinery and of the emailRateLimiter sliding window, so
// it is NEVER skipped by limitedScoring (quota exhaustion) or by the
// per-merchant rate limiter — both of which exist to protect the *scoring*
// pipeline's external-call budget, not this pipeline. This is intentionally
// only two checks, both backed by data already resident in this module:
//   1. Known disposable domain — O(1) Set lookup, zero I/O.
//   2. No MX / domain doesn't resolve — a single DNS query, already
//      wrapped by checkDomainDNS() with its own 400ms timeout and 24h LRU
//      cache, so repeat lookups for the same domain are also zero-I/O.
//
// Domain-age (<24h) hard-blocking is NOT implemented here — this codebase
// has no WHOIS/RDAP data source anywhere, and DNS resolution alone cannot
// tell you when a domain was registered. See accompanying write-up.
async function checkEmailHardBlock(email) {
  if (!EMAIL_HARD_BLOCK_ENABLED) return { blocked: false, reason: null, domain: null };
  if (!email) return { blocked: false, reason: null, domain: null };

  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) return { blocked: false, reason: null, domain: null };

  const domain = normalizedEmail.split("@")[1]?.toLowerCase();
  if (!domain) return { blocked: false, reason: null, domain: null };

  // 1. Known disposable domain — checked first since it never needs DNS.
  if (disposableDomains.has(domain)) {
    return { blocked: true, reason: 'disposable_email_domain', domain };
  }

  // 2. MX / domain existence — fail OPEN on network uncertainty (timeouts,
  // ECONNREFUSED, etc.) so a transient resolver hiccup never blocks a
  // legitimate order. Only a definitive "domain does not exist" or
  // "domain exists but accepts no mail" result blocks.
  try {
    const dnsResult = await checkDomainDNS(domain);

    if (dnsResult.uncertain) {
      return { blocked: false, reason: null, domain };
    }
    if (!dnsResult.exists) {
      return { blocked: true, reason: 'no_mx_record', domain };
    }
    if (!dnsResult.hasMX) {
      return { blocked: true, reason: 'no_mx_record', domain };
    }
  } catch (err) {
    // checkDomainDNS() already catches internally and never rejects in
    // practice, but fail open defensively in case that contract changes.
    logger.error({ module: 'emailIntel', err: err.message, domain }, 'Hard-block DNS check error — failing open');
  }

  return { blocked: false, reason: null, domain };
}

// ─── Main: Get Email Intelligence ─────────────────────────────────────────
// Returns full intelligence object with risk score + confidence + metadata

async function getEmailIntelligence(email, merchantId = null) {
  // ── Feature Flag ──────────────────────────────────────────────────────────
  if (!EMAIL_INTEL_ENABLED) {
    logger.warn({ module: 'emailIntel' }, 'DISABLED via ENABLE_EMAIL_INTEL=false');
    prometheus.recordEmailIntel('disabled', 'failure');
    return _skipped();
  }

  if (!email) return _skipped();

  // ── Gmail normalization ───────────────────────────────────────────────────
  // john.doe+test@gmail.com → johndoe@gmail.com
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) return { ..._skipped(), domainExists: false };
  const domain = normalizedEmail.split("@")[1];

  // ── Cache Check ───────────────────────────────────────────────────────────
  // FIX: استخدمنا getFromCache عشان نضمن LRU refresh صح
  const cached = getFromCache(emailCache, normalizedEmail);
  if (cached) {
    return { ...cached.data, source: "cache", confidence: getConfidence("cache") };
  }

  // ── In-flight Deduplication ───────────────────────────────────────────────
  // FIX: return the original promise directly to avoid automatic retry loops
  if (inFlight.has(normalizedEmail)) {
    return inFlight.get(normalizedEmail);
  }

  // ── Per-Merchant Rate Limit ───────────────────────────────────────────────
  // FIX: skip rate limit if merchantId is null
  if (!checkEmailLimit(merchantId)) {
    prometheus.recordEmailIntel('rate_limited', 'failure');
    const rateLimitedResult = { ..._skipped(), confidence: 0.10 };
    lruSet(emailCache, normalizedEmail, {
      data:   rateLimitedResult,
      expiry: Date.now() + 5 * 60 * 1000,
    }, MAX_CACHE_SIZE);
    return rateLimitedResult;
  }

  // ── Circuit Breaker (Sliding Window) ──────────────────────────────────────
  const useExternalAPIs = emailRateLimiter.isAllowed();
  if (!useExternalAPIs) {
    logger.warn({ module: 'emailIntel', count: emailRateLimiter.count(), limit: MAX_REQ_PER_MIN }, 'Rate limit reached — using rules only');
    prometheus.recordEmailIntel('rate_limited', 'failure');
  }

  // ── Build Promise ─────────────────────────────────────────────────────────
  const promise = (async () => {
    const start = Date.now();
    try {
      // Layer 2: Rules (always runs — no external calls)
      const rules = analyzeEmailRules(normalizedEmail);

      let dnsResult = { exists: true, hasMX: true, mxCount: 1, uncertain: false };
      let source    = "rules";

      if (useExternalAPIs) {
        const [dnsSettled] = await Promise.allSettled([checkDomainDNS(domain)]);
        dnsResult = dnsSettled.status === "fulfilled" ? dnsSettled.value : dnsResult;
        source    = dnsSettled.status === "fulfilled" ? "full" : "partial";
      }

      // ── Compute Final Risk Score ───────────────────────────────────────────
      // Dampening: لو الـ rules score عالي أصلاً، الـ DNS contribution بتقل
      // ده بيمنع overcounting لو نفس الـ root cause ولّد أكتر من signal
      // مثال: disposable domain → rules=0.8 → dns no MX → بدل +0.40 بيضيف 0.08 بس
      let dnsRisk = 0;
      if (!dnsResult.exists && !dnsResult.uncertain) {
        dnsRisk = 0.70;
      } else if (dnsResult.exists && !dnsResult.hasMX && !dnsResult.uncertain) {
        dnsRisk = 0.40;
      } else if (dnsResult.uncertain) {
        dnsRisk = 0.05;
      }

      // Dampening factor: كل ما الـ rules score أعلى، الـ DNS يضيف أقل
      const dampening = Math.max(0.1, 1 - rules.riskScore);
      const finalRisk  = Math.min(rules.riskScore + dnsRisk * dampening, 1.0);

     logger.debug({
  module: 'emailIntel',
  rulesRisk: rules.riskScore,
  dnsRisk,
  dampening,
  finalRisk,
}, 'Scoring details');

      const result = {
        riskScore:      finalRisk,
        confidence:     getConfidence(source),
        isPwned:        false,  // TODO: HIBP integration — see file header
        breachCount:    0,      // TODO: HIBP integration — see file header
        domainExists:   dnsResult.exists,
        hasMX:          dnsResult.hasMX,
        uncertain:      dnsResult.uncertain,
        isFreeProvider: rules.isFreeProvider,
        isDisposable:   rules.isDisposable,
        signals:        rules.signals,
        domain,
        source,
      };

      // ── Write to cache ───────────────────────────────────────────────────
      lruSet(emailCache, normalizedEmail, {
        data:   result,
        expiry: Date.now() + getEmailTTL(finalRisk),
      }, MAX_CACHE_SIZE);

      const latency = Date.now() - start;
      recordEmail(result.source, latency);
     logger.info({
  module: 'emailIntel',
  domain,
  risk: finalRisk,
  domainExists: dnsResult.exists,
  source,
  latency,
}, 'Email intelligence result');

      return result;

    } finally {
      inFlight.delete(normalizedEmail);
    }
  })();
  inFlight.set(normalizedEmail, promise);
  return promise;
}

// ─── Calculate Email Penalty ──────────────────────────────────────────────
// Called from riskScoring.js — returns { penalty, flags }

function calculateEmailPenalty(emailIntel, orderAmount, isNewCustomer) {
  // skipped → مفيش data خالص
  // timeout → البيانات مش موثوقة — consistent مع calculateIPPenalty
  if (!emailIntel || emailIntel.source === "skipped" || emailIntel.source === "timeout") {
    return { penalty: 0, flags: [] };
  }

  const flags          = [];
  const effectiveRisk  = emailIntel.riskScore * emailIntel.confidence;

  // ── كل penalty بتتحسب بشكل مستقل ──────────────────────────────────────
  // مش بيعتمد على الـ state المتراكم من الـ checks اللي قبله
  // النتيجة: نفس الـ penalty بغض النظر عن ترتيب الـ checks

  // ── 1. Domain Existence ───────────────────────────────────────────────
  let domainPenalty = 0;
  if (!emailIntel.domainExists && !emailIntel.uncertain) {
    domainPenalty = 40;
    flags.push({ severity: "critical", text: "email_domain_not_found" });
  } else if (!emailIntel.domainExists && emailIntel.uncertain) {
    domainPenalty = 5;
    flags.push({ severity: "medium", text: "email_domain_unverified" });
  } else if (!emailIntel.hasMX && !emailIntel.uncertain) {
    domainPenalty = 25;
    flags.push({ severity: "high", text: "email_domain_no_mx" });
  }

  // ── 2. Disposable Email ───────────────────────────────────────────────
  // الـ flag دايماً بيتضاف للـ explainability
  // الـ penalty بيتضاف بس لو مفيش domain penalty (لمنع double counting)
  let disposablePenalty = 0;
  if (emailIntel.isDisposable) {
    flags.push({ severity: "critical", text: "disposable_email_domain" });
    if (domainPenalty === 0) {
      disposablePenalty = 35;
    }
  }

  // ── 3. High Rules Risk ────────────────────────────────────────────────
  let rulesPenalty = 0;
  if (effectiveRisk > 0.5 && !emailIntel.isDisposable && emailIntel.domainExists) {
    const basePenalty = 8 + Math.round(7 * (effectiveRisk - 0.5) / 0.5);
    rulesPenalty = orderAmount > 200 ? basePenalty : Math.max(5, basePenalty - 3);
    const topSignal = emailIntel.signals?.[0];
    if (topSignal) {
      const signalText =
        topSignal.type === "high_entropy_username"
          ? "email_username_high_entropy"
          : topSignal.type === "high_risk_tld"
          ? "email_high_risk_tld"
          : topSignal.type === "high_numeric_ratio"
          ? "email_high_numeric_ratio"
          : "email_suspicious_pattern";
      flags.push({ severity: "medium", text: signalText });
    }
  }

  // ── 4. Free Provider + New Customer + High Value ──────────────────────
  // بيشتغل بس لو مفيش أي domain أو disposable penalty
  // لأن الـ signals دي أقوى وبتغطي الـ risk
  let freePenalty = 0;
  if (emailIntel.isFreeProvider && isNewCustomer && orderAmount >= 300 && domainPenalty === 0 && disposablePenalty === 0) {
    freePenalty = 10;
    flags.push({
      severity: "medium",
      text: "free_provider_high_value_new_customer",
    });
  }

  // ── Final Penalty ─────────────────────────────────────────────────────
  const totalPenalty = domainPenalty + disposablePenalty + rulesPenalty + freePenalty;

  // Dynamic cap بناءً على قيمة الأوردر
  // $0-200 → 40, $200-500 → 50, >$500 → 60
  let emailCap = 40;
  if (orderAmount > 500) {
    emailCap = 60;
  } else if (orderAmount > 200) {
    emailCap = 50;
  }

  return { penalty: Math.min(totalPenalty, emailCap), flags };
}

// ─── Cache Invalidation ───────────────────────────────────────────────────
function invalidateEmailCache(email) {
  if (!email) return;
  const normalized = normalizeEmail(email);
  if (!normalized) return;
  const deleted = emailCache.delete(normalized);
  if (deleted) {
    logger.info({ module: 'emailIntel', domain: normalized.split("@")[1] }, 'Cache invalidated');
  }
}

// ─── Internal Helpers ─────────────────────────────────────────────────────
function _skipped() {
  return {
    riskScore:    0,
    confidence:   0.10,
    isPwned:      false,
    breachCount:  0,
    domainExists: true,
    hasMX:        true,
    uncertain:    false,
    isDisposable: false,
    isFreeProvider: false,
    signals:      [],
    source:       "skipped",
  };
}
module.exports = {
  getEmailIntelligence,
  calculateEmailPenalty,
  invalidateEmailCache,
  checkEmailHardBlock,
};