// ─── ChargeGuard Pattern Sharing Module ──────────────────────────────────
// Cross-merchant behavioral pattern intelligence
//
// Design principles:
// 1. Bucketed signals — مش raw values (يمنع pattern explosion)
// 2. Canonical hashing — sorted keys (يمنع hash collisions)
// 3. Minimum support — 5+ occurrences قبل ما نثق في الـ pattern
// 4. Time decay — patterns قديمة بتفقد وزنها
// 5. merchantsSeen — network confidence
// 6. Privacy-safe — مفيش PII خالص

const crypto = require('crypto');
const db = require('./db');
const logger = require('./logger');



// ─── V2: Signal Weights ───────────────────────────────────────────────────
// كل signal له وزن مختلف بناءً على قوته كـ fraud indicator
// مش كل signals بتساوي بعض

const SIGNAL_WEIGHTS = {
  isDisposableEmail: 3.0,  // أقوى signal — intent واضح
  isDatacenterIP:    2.5,  // VPN/proxy — محاولة إخفاء الهوية
  highAmount:        1.5,  // target عالي — زود الخطر
  isNewCustomer:     1.0,  // cold start — مش عندنا history
 isNightOrder:      0.8,
  isHighVelocity:    2.5,
};

// V3 IMPROVEMENT: centralized constants for thresholds/limits
const MIN_SIGNAL_COUNT  = 2; // minimum active signals عشان الـ pattern يكون useful
const MIN_PATTERN_SUPPORT = 2; // minimum total occurrences عشان نثق في الـ pattern
const CLUSTER_MIN_SUPPORT = 5;
const CLUSTER_CREATE_MIN_SIGNALS = 3;
const FRAUD_RATE_THRESHOLD = 0.6;
const CLUSTER_SIMILARITY_THRESHOLD = 0.75;
const MAX_SIGNAL_INDEX_SIZE = 5000;
const MAX_PENALTY = 15;
const MAX_LEGIT_INFLUENCE = 50;  // Anti-replay: cap على legit records per pattern
const BAYES_ALPHA = 1;           // Prior fraud observations — يفترض innocence
const BAYES_BETA  = 2;           // Prior legit observations — حتى يثبت العكس

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

// ─── V2: Signal Interaction Bonuses ──────────────────────────────────────
// بعض combinations أخطر من مجموع أجزاءها
// captures non-linear interactions

function calculateInteractionBonus(activeSignals) {
  let bonus = 0;
  const has = (s) => activeSignals.includes(s);

  // disposable + datacenter = fraud intent واضح جداً
  if (has("isDisposableEmail") && has("isDatacenterIP")) bonus += 2.5;

  // new customer + high amount + night = classic fraud pattern
  if (has("isNewCustomer") && has("highAmount") && has("isNightOrder")) bonus += 1.5;

  // disposable + high amount = كارت مسروق
  if (has("isDisposableEmail") && has("highAmount")) bonus += 1.0;

  // high velocity + new customer = card testing cold start
  if (has("isHighVelocity") && has("isNewCustomer")) bonus += 2.0;

  // high velocity + disposable email = strongest card testing signal
  if (has("isHighVelocity") && has("isDisposableEmail")) bonus += 3.0;

  return bonus;
}

// ─── V2: Inverted Index (In-Memory) ──────────────────────────────────────
// signal → Set of patternHashes
// بيسمح بـ O(k) candidate filtering بدل O(N) full scan

const signalIndex = new Map(); // signal → Set<patternHash>
const INDEX_CLEAR_INTERVAL_MS = 30 * 60 * 1000;
let lastIndexTouch = Date.now();

function touchSignalIndex() {
  lastIndexTouch = Date.now();
}

// unref() — يمنع الـ interval من blocking الـ process exit
// لو الـ server بدأ يـshutdown، مش هينتظر الـ interval يخلص
setInterval(() => {
  if (Date.now() - lastIndexTouch >= INDEX_CLEAR_INTERVAL_MS && signalIndex.size > 0) {
    signalIndex.clear();
  }
}, INDEX_CLEAR_INTERVAL_MS).unref();

function indexPattern(patternHash, activeSignals) {
  touchSignalIndex();
  for (const signal of activeSignals) {
    if (!signalIndex.has(signal)) signalIndex.set(signal, new Set());
    const hashes = signalIndex.get(signal);
    // V3 IMPROVEMENT: bound memory with simple FIFO eviction
    if (!hashes.has(patternHash) && hashes.size >= MAX_SIGNAL_INDEX_SIZE) {
      const oldest = hashes.values().next().value;
      hashes.delete(oldest);
    }
    hashes.add(patternHash);
  }
}

function getCandidateHashes(activeSignals) {
  touchSignalIndex();
  const candidates = new Set();
  for (const signal of activeSignals) {
    const hashes = signalIndex.get(signal);
    if (hashes) hashes.forEach(h => candidates.add(h));
  }
  return candidates;
}

// ─── V2: Weighted Containment Similarity ─────────────────────────────────
// أذكى من Jaccard — يكتشف لو pattern A contained في pattern B
// similarity = weightedIntersection / min(weight(A), weight(B))

function calculateWeightedScore(signals) {
  return signals.reduce((sum, s) => sum + (SIGNAL_WEIGHTS[s] || 1.0), 0);
}

// ─── Max Possible Weighted Score ─────────────────────────────────────────
// بيتحسب مرة واحدة عند الـ module load — مش في كل request
// بيُستخدم لـ normalize الـ effectiveScore قبل الـ sigmoid
// يضمن إن الـ penalty discrimination شغالة على طول الـ score range
const ALL_SIGNALS = Object.keys(SIGNAL_WEIGHTS);
const MAX_WEIGHTED_SCORE = calculateWeightedScore(ALL_SIGNALS) + calculateInteractionBonus(ALL_SIGNALS);

function weightedContainmentSimilarity(signalsA, signalsB) {
  if (!signalsA.length || !signalsB.length) return 0;

  const setB = new Set(signalsB);
  const intersection = signalsA.filter(s => setB.has(s));

  const weightedIntersection = intersection.reduce((sum, s) => sum + (SIGNAL_WEIGHTS[s] || 1.0), 0);
  const weightA = calculateWeightedScore(signalsA);
  const weightB = calculateWeightedScore(signalsB);

  return weightedIntersection / Math.min(weightA, weightB);
}

// ─── Secret ───────────────────────────────────────────────────────────────
function getSecret() {
  const secret = process.env.PATTERN_SHARING_SECRET ?? process.env.IDENTITY_GRAPH_SECRET;
  if (!secret) {
    throw new Error("[PatternSharing] PATTERN_SHARING_SECRET env variable is required");
  }
  return secret;
}

// ─── Build Pattern from Order ─────────────────────────────────────────────
// بيحول الـ order لـ bucketed signals
// مش raw values — يمنع pattern explosion

function buildPattern(order, emailIntel, ipIntel, patternContext = {}) {
  const hour = new Date(order.createdAt || Date.now()).getHours();

  const pattern = {
    highAmount:        (order.amount || 0) > 200,
    isNewCustomer:     order.isNewCustomer === true,
    isDisposableEmail: emailIntel?.isDisposable === true,
    isDatacenterIP:    ipIntel?.isDatacenter === true,
    isNightOrder:      hour >= 2 && hour <= 5,
    isHighVelocity:    patternContext.isHighVelocity === true,
  };

  // فلتر الـ false values — بنشيل الـ signals الـ false من الـ pattern
  const activeSignals = Object.entries(pattern)
    .filter(([_, v]) => v === true)
    .map(([k]) => k);

  const weightedScore = calculateWeightedScore(activeSignals) + calculateInteractionBonus(activeSignals);
  return { pattern, activeSignals, signalCount: activeSignals.length, weightedScore };
}

// ─── Canonical Hash ───────────────────────────────────────────────────────
// Sorted keys — يمنع hash collisions من ترتيب مختلف

function hashPattern(pattern) {
  // Sort keys علشان نضمن canonical ordering
  const canonical = JSON.stringify(
    Object.keys(pattern)
      .sort()
      .reduce((acc, key) => {
        acc[key] = pattern[key];
        return acc;
      }, {})
  );

  return crypto
    .createHmac("sha256", getSecret())
    .update(canonical)
    .digest("hex");
}

// ─── Pattern Description ──────────────────────────────────────────────────
// Human-readable للـ debugging والـ explainability

function describePattern(activeSignals) {
  const labels = {
    highAmount:        "high-value order",
    isNewCustomer:     "new customer",
    isDisposableEmail: "disposable email",
    isDatacenterIP:    "datacenter IP",
    isNightOrder:      "night order (2-5 AM)",
    isHighVelocity:    "high velocity orders",
  };
  return activeSignals.map(s => labels[s] || s).join(" + ");
}

// V3 IMPROVEMENT: deterministic signals parsing with backward-compatible fallback
function parseStoredSignals(signalsRaw, patternDesc) {
  if (signalsRaw) {
    try {
      const parsed = JSON.parse(signalsRaw);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    } catch { /* fallback below */ }
  }
  // Legacy fallback — بيشتغل بس لو signals = null (patterns قديمة قبل V3)
  // لو patternDesc اتغير في version جديدة، الـ filter هيرجع [] بصمت
  // نـlog warning عشان نعرف لو في legacy patterns محتاجة migration
  if (patternDesc) {
    const legacy = Object.keys(SIGNAL_WEIGHTS).filter(s =>
      patternDesc.includes(describePattern([s]))
    );
    if (legacy.length > 0) {
      logger.warn({ module: 'patternSharing', patternDesc }, 'Legacy pattern signals parsed from description — consider migrating signals field');
      return legacy;
    }
  }
  // مفيش signals ومفيش description — pattern مش قابل للاستخدام في similarity
  return [];
}

// V3 IMPROVEMENT: unique merchant tracking prevents merchantsSeen inflation
async function registerPatternMerchant(patternHash, merchantId) {
  if (!merchantId) return false;
  try {
    await db.patternMerchant.create({
      data: { patternHash, merchantId },
    });
    return true;
  } catch (err) {
    // P2002 = Prisma unique constraint violation → merchant already registered
    // أي error تاني (connection، timeout) → نـ rethrow علشان ملتمسكش DB errors حقيقية
    if (err?.code === "P2002") return false;
    throw err;
  }
}

// M6 fix: per-tenant cap on legit-record contribution to a shared
// pattern's denominator. MAX_LEGIT_INFLUENCE alone only bounds the
// GLOBAL legitCount — it does nothing to stop one merchantId from
// single-handedly supplying all of it via synthetic orders that combine
// fraud-indicative signals while ensuring no later fraud report. This
// tracks contributions per (patternHash, merchantId) in PatternMerchant
// and refuses further legit increments from a merchant once it hits its
// own per-tenant ceiling — independent of, and tighter than, the global cap.
const MAX_LEGIT_INFLUENCE_PER_MERCHANT = 5;

async function canContributeLegit(patternHash, merchantId) {
  if (!merchantId) return true; // no merchant to attribute to — can't rate-limit by tenant
  const row = await db.patternMerchant.findUnique({
    where: { patternHash_merchantId: { patternHash, merchantId } },
    select: { legitCount: true },
  });
  return !row || row.legitCount < MAX_LEGIT_INFLUENCE_PER_MERCHANT;
}

async function incrementMerchantLegitCount(patternHash, merchantId) {
  if (!merchantId) return;
  try {
    await db.patternMerchant.update({
      where: { patternHash_merchantId: { patternHash, merchantId } },
      data: { legitCount: { increment: 1 } },
    });
  } catch (err) {
    logger.error({ module: 'patternSharing', err: err.message }, 'legitCount increment failed');
  }
}

async function updatePatternWithRetry(patternHash, isFraud, trustedWeightedScore, isNewMerchant, maxRetries = 3) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    // Exponential backoff مع jitter — يمنع thundering herd في high contention
    // attempt 0 → 0ms | attempt 1 → 20-30ms | attempt 2 → 40-60ms
    // بدون jitter → كل الـ retries بتصحى في نفس اللحظة → نفس المشكلة
    if (attempt > 0) {
      const base  = 20 * Math.pow(2, attempt - 1);
      const jitter = Math.random() * base * 0.5;
      await new Promise(r => setTimeout(r, base + jitter));
    }
    const existing = await db.fraudPattern.findUnique({
      where: { patternHash },
      select: { version: true, totalCount: true, fraudCount: true, legitCount: true, learnedAtCount: true },
    });
    if (!existing) return null;

    const version = Number(existing.version ?? 0);

    // ─── TTNL: سجّل لحظة التعلم مرة واحدة بس (immutable) ────────────
    // الـ pattern "learned" لما:
    // 1. fraudCount / totalCount >= MIN_FRAUD_RATE (بعد الـ increment)
    // 2. totalCount >= MIN_SUPPORT
    // 3. learnedAtCount مش مسجل قبل كده
    const nextFraudCount = Number(existing.fraudCount ?? 0) + (isFraud ? 1 : 0);
    const nextTotalCount = Number(existing.totalCount ?? 0) + 1;
    const nextLegitCount = Number(existing.legitCount ?? 0) + (!isFraud ? 1 : 0);
    const willBeTrusted  =
      existing.learnedAtCount == null &&
      nextTotalCount >= MIN_PATTERN_SUPPORT &&
      (nextFraudCount + nextLegitCount) > 0 &&
      nextFraudCount / nextTotalCount >= FRAUD_RATE_THRESHOLD;

    const result = await db.fraudPattern.updateMany({
      where: { patternHash, version },
      data: {
        totalCount:     { increment: 1 },
        fraudCount:     isFraud ? { increment: 1 } : undefined,
        legitCount:     !isFraud ? { increment: 1 } : undefined,
        merchantsSeen:  isNewMerchant ? { increment: 1 } : undefined,
        weightedScore:  isFraud ? { increment: trustedWeightedScore } : undefined,
        lastSeen:       new Date(),
        version:        { increment: 1 },
        // ─── Immutable: بيتكتب مرة واحدة بس ─────────────────────────
        learnedAtCount: willBeTrusted ? nextTotalCount : undefined,
      },
    });

    if (result.count === 1) {
      return db.fraudPattern.findUnique({ where: { patternHash } });
    }
  }

  // كل الـ retries فشلت — في contention حقيقي على الـ DB
  // نـ throw بدل silent fallback يعمل data corruption
  // الـ caller (recordPattern) محاط بـ try/catch → هيتمسك ويكمل
  logger.warn({ module: 'patternSharing', patternHash: patternHash.slice(0, 8) + '***', maxRetries }, 'Optimistic lock failed after all retries — skipping update');
  return null;
}

// ─── Record Pattern ───────────────────────────────────────────────────────
// بيسجل الـ pattern في الـ DB بعد كل order
// isFraud = true لو الـ order اتثبت fraud

async function recordPattern(order, emailIntel, ipIntel, isFraud = false, merchantId = null, patternContext = {}) {
  try {
    const { pattern, activeSignals, signalCount, weightedScore } = buildPattern(order, emailIntel, ipIntel, patternContext);

    // Minimum signal count — pattern بسيط جداً مش useful
    if (signalCount < MIN_SIGNAL_COUNT) return null;
    if (!isFraud && weightedScore < 2.5) return null;

    const patternHash = hashPattern(pattern);
    const patternDesc = describePattern(activeSignals);

    // ─── Merchant Trust (Confidence-adjusted) ────────────────────────
    // تاجر جديد → تأثير محدود على الـ network
    // تاجر أثبت نفسه → وزن أعلى
     // ─── Merchant Trust Lookup ────────────────────────────────────────
    // Wired to MerchantProfile.trustScore (kept current by feedbackLoop.js
    // on every dispute outcome) rather than a flat default — same
    // fetch-and-compute formula as computeMerchantTrust() in
    // identityGraph.js. Falls back to 0.3 (new/unknown merchant, or a DB
    // failure during lookup) so a lookup error can never abort
    // recordPattern() — it only ever degrades to the previous flat
    // behavior for this one call.
    let merchantTrust = 0.3; // default
    if (merchantId) {
      try {
        const merchantProfile = await db.merchantProfile.findUnique({
          where: { merchantId },
          select: { trustScore: true, reportCount: true },
        });
        if (merchantProfile) {
          const confidence = 1 - Math.exp(-(merchantProfile.reportCount || 0) / 10);
          merchantTrust = merchantProfile.trustScore * confidence;
        }
      } catch (trustErr) {
        logger.error({ module: 'patternSharing', err: trustErr.message }, 'MerchantProfile trust lookup failed — falling back to default trust');
      }
    }

    if (!isFraud && merchantTrust < 0.2) return null;

    // Effective weighted score = signal weights × merchant trust
    // Cap at 5 يمنع pattern poisoning من merchants بـ inflated trust
    const trustedWeightedScore = Math.min(weightedScore * merchantTrust, 5);
    const existing = await db.fraudPattern.findUnique({
      where: { patternHash },
    });

    if (existing) {
      // Anti-replay: global cap (unchanged) plus per-tenant cap (M6 fix)
      // — either one alone is insufficient; the global cap doesn't stop
      // one merchant from being the sole contributor, and a per-tenant
      // cap alone doesn't bound total network noise.
      if (!isFraud) {
        if (Number(existing.legitCount ?? 0) >= MAX_LEGIT_INFLUENCE) return null;
        if (!(await canContributeLegit(patternHash, merchantId))) return null;
      }

      const isNewPatternMerchant = await registerPatternMerchant(patternHash, merchantId);
      if (!isFraud) await incrementMerchantLegitCount(patternHash, merchantId);
      indexPattern(patternHash, activeSignals);
      const updated = await updatePatternWithRetry(patternHash, isFraud, trustedWeightedScore, isNewPatternMerchant);
      if (!updated) return null;

      // Update cluster stats مع merchant trust
      if (existing.clusterId) {
        await db.fraudCluster.update({
          where: { id: existing.clusterId },
          data: {
            totalCount:         { increment: 1 },
            fraudCount:         isFraud ? { increment: 1 } : undefined,
            merchantsSeen:      isNewPatternMerchant ? { increment: 1 } : undefined,
            weightedFraudScore: isFraud ? { increment: trustedWeightedScore } : undefined,
            lastSeen:           new Date(),
          },
        });
      }

      return updated;
    }

    // ── New Pattern — Try Cluster Assignment ──────────────────────────
    // نشوف لو في cluster مناسب قبل ما نعمل insert جديد
    let clusterId = null;

    try {
      const candidateHashes = getCandidateHashes(activeSignals);

      if (candidateHashes.size > 0) {
        const candidates = await db.fraudPattern.findMany({
          where: { patternHash: { in: Array.from(candidateHashes).slice(0, 50) }, clusterId: { not: null } },
          select: { patternHash: true, clusterId: true, patternDesc: true, signals: true },
          take: 20,
        });

        // نحسب similarity مع كل candidate
        let bestMatch = null;
        let bestSimilarity = 0;

        for (const candidate of candidates) {
          // V3 IMPROVEMENT: use stored signals; fallback to legacy patternDesc parsing.
          const candidateSignals = parseStoredSignals(candidate.signals, candidate.patternDesc);

          const similarity = weightedContainmentSimilarity(activeSignals, candidateSignals);

          if (similarity > bestSimilarity && similarity >= CLUSTER_SIMILARITY_THRESHOLD) {
            bestSimilarity = similarity;
            bestMatch = candidate;
          }
        }

        if (bestMatch?.clusterId) {
          clusterId = bestMatch.clusterId;
          if (process.env.NODE_ENV !== "production") {
            console.log(`[PatternSharing] Cluster assigned — similarity: ${(bestSimilarity * 100).toFixed(0)}% | cluster: ${clusterId.slice(0, 8)}***`);
          }
        }
      }

      // لو مفيش cluster مناسب → نعمل cluster جديد للـ pattern ده
      if (!clusterId && signalCount >= CLUSTER_CREATE_MIN_SIGNALS) {
        const newCluster = await db.fraudCluster.upsert({
          where: { clusterHash: patternHash },
          create: {
            clusterHash:        patternHash,
            clusterDesc:        patternDesc,
            totalCount:         1,
            fraudCount:         isFraud ? 1 : 0,
            merchantsSeen:      1,
            weightedFraudScore: isFraud ? trustedWeightedScore : 0,
          },
          update: {
            totalCount: { increment: 1 },
            fraudCount: isFraud ? { increment: 1 } : undefined,
            weightedFraudScore: isFraud ? { increment: trustedWeightedScore } : undefined,
          },
        });
        clusterId = newCluster.id;
      }
    } catch (clusterErr) {
      logger.error({ module: 'patternSharing', err: clusterErr }, 'Cluster assignment error');
    }

    // Index الـ pattern الجديد
    indexPattern(patternHash, activeSignals);

    const isNewPatternMerchant = await registerPatternMerchant(patternHash, merchantId);

    const firstFraudCount  = isFraud ? 1 : 0;
    const firstTotalCount  = 1;
    const firstLearnedAt   =
      firstTotalCount >= MIN_PATTERN_SUPPORT &&
      firstFraudCount / firstTotalCount >= FRAUD_RATE_THRESHOLD
        ? firstTotalCount
        : null;

    // ─── Atomic: cluster + pattern في transaction واحدة ──────────────
    // يمنع orphan clusters لو الـ pattern create فشل بعد الـ cluster create
    // الاتنين بيحصلوا مع بعض أو محدش فيهم
    return db.$transaction(async (tx) => {
      // لو clusterId اتعمل من فوق — نتأكد إنه لسه موجود جوه الـ transaction
      if (clusterId) {
        await tx.fraudCluster.update({
          where: { id: clusterId },
          data:  { lastSeen: new Date() },
        });
      }

      return tx.fraudPattern.upsert({
        where: { patternHash },
        create: {
          patternHash,
          patternDesc,
          signalCount,
          signals:        JSON.stringify(activeSignals),
          weightedScore:  isFraud ? trustedWeightedScore : 0,
          fraudCount:     firstFraudCount,
          legitCount:     !isFraud ? 1 : 0,
          totalCount:     firstTotalCount,
          merchantsSeen:  isNewPatternMerchant ? 1 : 0,
          lastSeen:       new Date(),
          version:        0,
          clusterId,
          learnedAtCount: firstLearnedAt,
        },
        update: {
          totalCount: { increment: 1 },
          fraudCount: isFraud ? { increment: 1 } : undefined,
          legitCount: !isFraud ? { increment: 1 } : undefined,
          lastSeen:   new Date(),
        },
      });
    });

  } catch (error) {
    logger.error({ module: 'patternSharing', err: error }, 'recordPattern error');
    return null;
  }
}

// ─── Time Decay ───────────────────────────────────────────────────────────
// Exponential decay بدل step function — يمنع الـ sudden jumps عند الـ boundaries
// half-life = 72h يعني بعد 3 أيام الـ fraud rate بتبقى 50% من قيمتها
const DECAY_HALF_LIFE_HOURS = 72;

// totalCount — كل ما زاد الـ evidence، الـ floor بيزيد
// يمنع pattern قوي يتلاشى بنفس سرعة pattern ضعيف
// floor = min(0.1 + log10(totalCount) * 0.1, 0.35)
// totalCount=5 → 0.17 | totalCount=50 → 0.27 | totalCount=200 → 0.33
function applyPatternDecay(fraudRate, lastSeen, totalCount = 1) {
  if (!lastSeen) return fraudRate;
  const ageHours = (Date.now() - new Date(lastSeen).getTime()) / (1000 * 60 * 60);
  const dynamicFloor = Math.min(0.1 + Math.log10(Math.max(totalCount, 1)) * 0.1, 0.35);
  const decayFactor  = Math.max(Math.pow(0.5, ageHours / DECAY_HALF_LIFE_HOURS), dynamicFloor);
  return fraudRate * decayFactor;
}

// ─── Check Pattern Risk ───────────────────────────────────────────────────
// Called from riskScoring.js
// Returns { penalty, flags }

async function checkPatternRisk(order, emailIntel, ipIntel, patternContext = {}) {
  try {
    const { pattern, activeSignals, signalCount, weightedScore: currentWeightedScore } = buildPattern(order, emailIntel, ipIntel, patternContext);

    // Minimum 2 signals علشان نشيك
    if (signalCount < 2) return { penalty: 0, flags: [] };

    const patternHash = hashPattern(pattern);

    const existingPattern = await db.fraudPattern.findUnique({
      where: { patternHash },
    });

    // ── V2: Check Cluster First (أقوى من pattern منفرد) ──────────────
    // الـ cluster بيجمع patterns متشابهة → minimum support أسرع
    let clusterBoost = 1.0;
    let cachedCluster = null; // نكش الـ cluster عشان منجيبوش مرتين

    if (existingPattern?.clusterId) {
      try {
        cachedCluster = await db.fraudCluster.findUnique({
          where: { id: existingPattern.clusterId },
        });
        const cluster = cachedCluster;
        if (cluster && cluster.totalCount >= CLUSTER_MIN_SUPPORT) {
          const clusterFraudRate = cluster.fraudCount / cluster.totalCount;
          if (clusterFraudRate >= FRAUD_RATE_THRESHOLD) {
            // V3 IMPROVEMENT: confidence-aware boost يقلل overfitting على small samples.
            const confidence = cluster.fraudCount / Math.sqrt(Math.max(cluster.totalCount, 1));
            const confidenceScale = clamp(confidence / 2, 0.8, 1.25);
            const baseBoost = cluster.merchantsSeen >= 3 ? 1.4 : 1.2;
            clusterBoost = baseBoost * confidenceScale;
          }
        }
      } catch { /* use pattern only */ }
    }

    // مفيش pattern أو data قليل — شيك على الـ cluster كـ fallback
    if (!existingPattern || existingPattern.totalCount < 5) {
      // V2 Fallback: لو الـ cluster عنده data كافية حتى لو الـ pattern جديد
      if (existingPattern?.clusterId) {
        try {
          const cluster = cachedCluster ?? await db.fraudCluster.findUnique({
            where: { id: existingPattern.clusterId },
          });
          if (cluster && cluster.totalCount >= CLUSTER_MIN_SUPPORT && cluster.fraudCount / cluster.totalCount >= FRAUD_RATE_THRESHOLD && cluster.merchantsSeen >= 2) {
            const clusterPenalty = Math.min(10, signalCount >= 3 ? 10 : 8);
            return {
              penalty: clusterPenalty,
              flags: [{
                severity: "medium",
                text: `Order matches behavioral cluster (${describePattern(activeSignals)}) — cluster seen ${cluster.fraudCount}/${cluster.totalCount} times across ${cluster.merchantsSeen} merchant${cluster.merchantsSeen > 1 ? "s" : ""}`,
              }],
            };
          }
        } catch { /* skip */ }
      }
      return { penalty: 0, flags: [] };
    }

    // Fraud rate — Bayesian smoothing يمنع instability عند data قليل
    // prior: alpha=1 fraud، beta=2 legit → يفترض innocence حتى يثبت العكس
    const effectiveFraudCount = Number(existingPattern.fraudCount ?? 0);
    const effectiveLegitCount  = Number(existingPattern.legitCount  ?? 0);
    const evidenceTotal = effectiveFraudCount + effectiveLegitCount;
    const rawFraudRate = evidenceTotal > 0
      ? (effectiveFraudCount + BAYES_ALPHA) / (evidenceTotal + BAYES_ALPHA + BAYES_BETA)
      : 0;

    // Time decay — dynamic floor بناءً على قوة الـ evidence
    const decayedFraudRate = applyPatternDecay(rawFraudRate, existingPattern.lastSeen, Number(existingPattern.totalCount ?? 1));

    // Network confidence boost (merchantsSeen)
    const networkBoost = existingPattern.merchantsSeen >= 3 ? 1.2
      : existingPattern.merchantsSeen >= 2 ? 1.1
      : 1.0;

    const effectiveFraudRate = Math.min(decayedFraudRate * networkBoost, 1.0);

    // Threshold — مش هنعاقب لو الـ fraud rate مش عالي
    if (effectiveFraudRate < FRAUD_RATE_THRESHOLD) return { penalty: 0, flags: [] };

     // V2: Penalty بناءً على weighted score مش signal count بس
    const effectiveScore = currentWeightedScore * clusterBoost;

    // Normalize قبل الـ sigmoid — يضمن discrimination على طول الـ score range
    // بدون normalize: score=10 و score=34 بيدوا نفس الـ penalty (sigmoid flat)
    // بعد normalize: كل زيادة في الـ score بتأثر على الـ penalty بشكل proportional
    const normalizedScore = (effectiveScore / Math.max(MAX_WEIGHTED_SCORE, 1)) * 10;
    const basePenalty = MAX_PENALTY / (1 + Math.exp(-0.8 * (normalizedScore - 5)));

    // Cap per pattern
    const penalty = Math.round(Math.min(basePenalty, MAX_PENALTY) * 10) / 10;

    const flags = [{
      severity: effectiveFraudRate > 0.8 ? "high" : "medium",
      text: `Order matches fraud pattern (${describePattern(activeSignals)}) — seen ${existingPattern.fraudCount}/${existingPattern.totalCount} times${existingPattern.merchantsSeen > 1 ? ` across ${existingPattern.merchantsSeen} merchants` : ""} (fraud rate: ${(effectiveFraudRate * 100).toFixed(1)}%)`,
    }];

   if (process.env.NODE_ENV !== "production") {
    console.log(`[PatternSharing] Pattern match | hash: ${patternHash.slice(0, 8)}*** | fraudRate: ${(effectiveFraudRate * 100).toFixed(1)}% | penalty: ${penalty}`);
  }

    return { penalty, flags };

  } catch (error) {
    logger.error({ module: 'patternSharing', err: error }, 'checkPatternRisk error');
    return { penalty: 0, flags: [] };
  }
}

// ─── Mark Pattern as Fraud ────────────────────────────────────────────────
// Called from markOrderAsFraud in identityGraph.js

// patternContext — computed signals (isHighVelocity, ...) من الـ caller
// default = {} للـ backward compatibility مع الـ callers القديمة
async function markPatternAsFraud(order, emailIntel, ipIntel, merchantId, patternContext = {}) {
  return recordPattern(order, emailIntel, ipIntel, true, merchantId, patternContext);
}
module.exports = {
  buildPattern,
  recordPattern,
  checkPatternRisk,
  markPatternAsFraud,
};