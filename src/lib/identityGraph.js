// ─── ChargeGuard Identity Graph ───────────────────────────────────────────
// Anchor-based fraud intelligence graph
//
// Design:
// - DEVICE is always the anchor node (center)
// - All other nodes (EMAIL, IP, ADDRESS, FINGERPRINT) connect TO device
// - Risk propagates at READ TIME only — never stored in nodes
// - Values stored as HMAC_SHA256 for privacy
// - Merchant-isolated by default
// - Edge trust threshold: seenCount >= 2

const crypto = require('crypto'); const { randomUUID } = crypto;
const prisma = require('./db');
const { invalidateIPCache } = require('./ipIntelligence');
const { invalidateEmailCache } = require('./emailIntelligence');
const logger = require('../lib/logger');
const { maskDeviceId } = require('../lib/utils');
// ─── Constants ────────────────────────────────────────────────────────────

// Relation weights — how strongly each connection propagates risk
const RELATION_WEIGHTS = {
  LINKED_TO:   0.95, // device ↔ fingerprint — very strong
  USED_WITH:   0.90, // device ↔ email       — strong
  SHIPPED_TO:  0.70, // device ↔ address     — medium
  LOGGED_FROM: 0.50, // device ↔ IP          — weak (shared networks)
};

// Path decay — risk weakens with graph distance
// depth 0 = the node itself, depth 1 = direct connection, depth 2 = 2 hops
const PATH_DECAY = [1.0, 0.60, 0.30];

// Edge trust threshold — ignore edges seen only once (prevents poisoning)
const MIN_EDGE_TRUST = 2;

// Time decay rate — older connections matter less
// λ = 0.005 → after 180 days, event has ~40% weight
const TIME_DECAY_LAMBDA = 0.005;

// Max traversal depth — dynamic based on risk level
const MAX_DEPTH_LOW  = 1; // low risk orders — سريع
const MAX_DEPTH_MED  = 2; // medium risk — default
const MAX_DEPTH_HIGH = 3; // high risk — عميق (SQLite safe دلوقتي)

// Rate limiting — max new nodes per device per hour
// بيحمي من graph inflation attacks
const MAX_NODES_PER_DEVICE_PER_HOUR = 10;

// Attack awareness — spike detection threshold
// لو device عمل أكتر من كده في ساعة → suspicious
const SPIKE_THRESHOLD_EDGES_PER_HOUR = 8;

// Secret for HMAC — loaded from env and cached after first call
// getSecret() بتتكال في كل hashValue call — caching بيمنع process.env lookup متكرر
let _cachedSecret = undefined;
function getSecret() {
  if (_cachedSecret !== undefined) return _cachedSecret;
  const secret = process.env.IDENTITY_GRAPH_SECRET ?? null;
  if (!secret) {
    // Critical — بدون secret الـ HMAC مش آمن
    // throw بدل fallback لأن fallback بيلغي الحماية خالص
    throw new Error("[IdentityGraph] IDENTITY_GRAPH_SECRET env variable is required");
  }
  _cachedSecret = secret;
  return _cachedSecret;
}

// ─── Value Normalization ───────────────────────────────────────────────────

function normalizeValue(type, value) {
  if (!value) return "";
  switch (type) {
    case "EMAIL": {
      const lower = value.normalize("NFKC").toLowerCase().trim();
      const [local, domain] = lower.split("@");
      if (!domain) return lower;
      const cleanLocal = local.split("+")[0];
      const gmailDomains = ["gmail.com", "googlemail.com"];
      const finalLocal = gmailDomains.includes(domain)
        ? cleanLocal.replace(/\./g, "")
        : cleanLocal;
      return `${finalLocal}@${domain}`;
    }
    case "IP":
      return value.trim();
    case "DEVICE":
    case "FINGERPRINT":
      return value.trim();
    case "ADDRESS":
      return value.normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim();
    default:
      return value.trim();
  }
}

// ─── HMAC Hashing ─────────────────────────────────────────────────────────
// Uses HMAC_SHA256 — immune to dictionary attacks unlike plain SHA256
// Standard in fintech for PII storage

function hashValue(type, value) {
  const normalized = normalizeValue(type, value);
  if (!normalized) return null;
  return crypto
    .createHmac("sha256", getSecret())
    .update(`${type}:${normalized}`)
    .digest("hex");
}

// ─── Masked Value for UI ───────────────────────────────────────────────────

function maskValue(type, value) {
  if (!value) return null;
  switch (type) {
    case "EMAIL": {
      const [local, domain] = value.split("@");
      if (!domain) return value;
      const masked = local.length <= 2
        ? local[0] + "***"
        : local.slice(0, 2) + "***";
      return `${masked}@${domain}`;
    }
    case "IP": {
      const parts = value.split(".");
      if (parts.length === 4) return `${parts[0]}.${parts[1]}.*.*`;
      return value.slice(0, 6) + "***";
    }
    case "DEVICE":
    case "FINGERPRINT":
      return value.slice(0, 8) + "***";
    case "ADDRESS": {
      const words = value.split(" ");
      return words.slice(0, 2).join(" ") + "***";
    }
    default:
      return value.slice(0, 4) + "***";
  }
}

// ─── Merchant Trust Score ─────────────────────────────────────────────────
// Confidence-adjusted trust — يمنع single merchant poisoning
// effectiveTrust = trustScore × (1 - e^(-reportCount/10))
// تاجر جديد → تأثير محدود | تاجر أثبت نفسه → وزن يزيد
// Pure function — بتاخد الـ data جاهزة من الـ caller بدون I/O
function computeMerchantTrust(merchantData) {
  if (!merchantData) return 0.3;
  const confidence = 1 - Math.exp(-merchantData.reportCount / 10);
  return merchantData.trustScore * confidence;
}

// ─── Global Node Type Weights ─────────────────────────────────────────────
// DEVICE أقوى signal — IP أضعف (shared/recyclable)
const GLOBAL_TYPE_WEIGHTS = {
  DEVICE:      0.70,
  FINGERPRINT: 0.60,
  IP:          0.30,
};

// ─── Step Decay for Global Nodes ──────────────────────────────────────────
// Predictable و easy to debug — بدل exponential
function applyStepDecay(score, lastSeenAt) {
  if (!lastSeenAt) return score;
  const ageHours = (Date.now() - new Date(lastSeenAt).getTime()) / (1000 * 60 * 60);
  if (ageHours < 24)  return score;
  if (ageHours < 72)  return score * 0.7;
  if (ageHours < 168) return score * 0.4;
  return score * 0.1;
}

// ─── Upsert Global Node ───────────────────────────────────────────────────
// Global nodes: merchantId = null — مشتركة بين كل التجار
// بس للـ DEVICE و IP و FINGERPRINT بس — مش EMAIL (privacy)

async function upsertGlobalNode(type, rawValue, merchantId) {
  if (type === "EMAIL" || type === "ADDRESS") return null;
  if (!GLOBAL_TYPE_WEIGHTS[type]) return null;

  const hashedValue = hashValue(type, rawValue);
  if (!hashedValue) return null;

  const maskedValue = maskValue(type, rawValue);
  const now = new Date();

  try {
    await prisma.identityNode.upsert({
      where: {
        merchantId_type_hashedValue: {
          merchantId: 'global',
          type,
          hashedValue,
        },
      },
      create: {
        merchantId: 'global',
        type,
        hashedValue,
        maskedValue,
        totalTransactions: 1,
        merchantsSeen: 1,
        recentMerchants: 1,
        firstSeen: now,
        lastSeen: now,
      },
      update: {
        totalTransactions: { increment: 1 },
        lastSeen: now,
        // merchantsSeen و recentMerchants لا يتم تحديثهما – مقبول لـ MVP
      },
    });
  } catch (err) {
    logger.error({ module: 'identityGraph', err }, 'upsertGlobalNode error');
  }
  return null;
}

// ─── Upsert Identity Node ──────────────────────────────────────────────────

// fingerprintTiers: { config, hardware } — بس للـ DEVICE nodes
// باقي الـ node types مش محتاجين tier fingerprints
async function upsertNode(merchantId, type, rawValue, fingerprintTiers = null) {
  if (!rawValue) return null;

  const hashedValue = hashValue(type, rawValue);
  if (!hashedValue) return null;

  const maskedValue = maskValue(type, rawValue);

  // ─── Three-Tier Fingerprint — بس للـ DEVICE nodes ─────────────────────
  // باقي الـ types (EMAIL, IP, ADDRESS, FINGERPRINT) مش عندهم tiers
  const tierFields = (type === "DEVICE" && fingerprintTiers) ? {
    fingerprintConfig:   fingerprintTiers.config   ?? undefined,
    fingerprintHardware: fingerprintTiers.hardware ?? undefined,
  } : {};

  try {
    return await prisma.identityNode.upsert({
      where: {
        merchantId_type_hashedValue: {
          merchantId: merchantId ?? null,
          type,
          hashedValue,
        },
      },
      create: {
        merchantId: merchantId ?? null,
        type,
        hashedValue,
        maskedValue,
        firstSeen: new Date(),
        lastSeen:  new Date(),
        ...tierFields,
      },
      update: {
        lastSeen: new Date(),
        ...tierFields, // بنحدث الـ tiers لو اتحسنوا (مثلاً pixel وصل بعد metafield)
      },
    });
  } catch (err) {
    logger.error({ module: 'identityGraph', err }, 'upsertNode fallback');
    return prisma.identityNode.findFirst({
      where: { merchantId: merchantId ?? null, type, hashedValue },
    });
  }
}

// ─── Upsert Identity Edge ──────────────────────────────────────────────────
// fromId must be DEVICE node
// Increments seenCount and updates lastSeenAt

async function upsertEdge(fromId, toId, relation, orderId) {
  const now = new Date();
  try {
    await prisma.identityEdge.upsert({
      where: {
        fromId_toId_relation: { fromId, toId, relation },
      },
      create: {
        fromId,
        toId,
        relation,
        seenCount: 1,
        uniqueOrders: 1,
        orderId,
        firstSeenAt: now,
        lastSeenAt: now,
        createdAt: now,
        updatedAt: now,
      },
      update: {
        seenCount: { increment: 1 },
        uniqueOrders: { increment: 1 },
        lastSeenAt: now,
        updatedAt: now,
      },
    });
    const edge = await prisma.identityEdge.findUnique({
      where: { fromId_toId_relation: { fromId, toId, relation } },
      include: { to: true },
    });
    return edge;
  } catch (err) {
    logger.error({ module: 'identityGraph', fromId, toId, relation, err }, 'upsertEdge error');
    return null;
  }
}
// ─── Build Graph from Order ────────────────────────────────────────────────
// Called on every new order
// Creates/updates nodes and edges

async function buildGraphFromOrder
(order, merchantId) {
  logger.debug(`[GRAPH] buildGraphFromOrder called. device: ${order?.deviceFingerprint || order?.deviceId}`);
  if (!order) return;

  const deviceId = order.deviceFingerprint || order.deviceId;
  if (!deviceId) {
    // No device — can't build anchor graph
    return;
  }

  try {
    const fingerprintTiers = {
      config:   order.fingerprintConfig   ?? null,
      hardware: order.fingerprintHardware ?? null,
    };

    // ─── Rate Limit Check — قبل أي upsert ───────────────────────────
    // بنجيب الـ existing node بـ findFirst بدون upsert
    // عشان نعمل الـ check قبل ما نعدل أي data
    const hashedDeviceId  = hashValue("DEVICE", deviceId);
    const oneHourAgo      = new Date(Date.now() - 60 * 60 * 1000);
    const existingDevice  = hashedDeviceId
      ? await prisma.identityNode.findFirst({
          where: { merchantId: merchantId ?? null, type: "DEVICE", hashedValue: hashedDeviceId },
          select: { id: true },
        })
      : null;

    if (existingDevice) {
      const recentEdges = await prisma.identityEdge.count({
        where: {
          fromId:      existingDevice.id,
          firstSeenAt: { gte: oneHourAgo },
        },
      });

      if (recentEdges > MAX_NODES_PER_DEVICE_PER_HOUR) {
        logger.warn({ module: 'identityGraph', deviceMasked: maskDeviceId(deviceId), recentEdges }, 'Rate limit exceeded — graph building stopped');
        return;
      } else if (recentEdges > SPIKE_THRESHOLD_EDGES_PER_HOUR) {
        logger.warn({ module: 'identityGraph', deviceMasked: maskDeviceId(deviceId), recentEdges }, 'Spike detected');
      }
    }

    // ─── Upsert anchor node (DEVICE) — بعد الـ rate limit check ─────
       const deviceNode = await upsertNode(merchantId, "DEVICE", deviceId, fingerprintTiers);
    logger.debug(`[GRAPH] buildGraphFromOrder: Failed to create deviceNode. Exiting.`);
    logger.debug(`[GRAPH] buildGraphFromOrder: deviceNode created with id=${deviceNode.id}`);
  logger.debug(`[GRAPH] buildGraphFromOrder: deviceNode found. Current fraudEvents=${deviceNode.fraudEvents}`);

    // 2. Upsert connected nodes and create edges
    const connections = [
      { type: "EMAIL",       value: order.email,           relation: "USED_WITH"   },
      { type: "IP",          value: order.ipAddress,       relation: "LOGGED_FROM" },
      { type: "FINGERPRINT", value: order.deviceFingerprint, relation: "LINKED_TO" },
      { type: "ADDRESS",     value: order.shippingAddress
          ? (() => { try { const a = JSON.parse(order.shippingAddress); return [a.city, a.zip, a.country].filter(Boolean).join(","); } catch { return null; } })()
          : null,
        relation: "SHIPPED_TO"
      },
    ];

    const validConns = connections.filter(c => c.value && c.value !== deviceId);

    const connNodes = await Promise.all(
      validConns.map(conn => upsertNode(merchantId, conn.type, conn.value))
    );

    await Promise.all(
      validConns
        .map((conn, i) => ({ conn, node: connNodes[i] }))
        .filter(({ node }) => node !== null)
        .map(({ conn, node }) => upsertEdge(deviceNode.id, node.id, conn.relation, order.id))
    );


    // ─── Build Global Nodes (Parallel) ───────────────────────────────
    // بدل sequential → Promise.all (parallel)
    await Promise.all([
      upsertGlobalNode("DEVICE",      deviceId,                    merchantId),
      upsertGlobalNode("IP",          order.ipAddress,             merchantId),
      upsertGlobalNode("FINGERPRINT", order.deviceFingerprint,     merchantId),
    ]);

    logger.debug({ module: 'identityGraph', orderId: order.id, deviceMasked: maskDeviceId(deviceId) }, 'Graph built');

  } catch (error) {
    logger.error({ module: 'identityGraph', err: error }, 'buildGraphFromOrder error');
  }
}

// ─── Time Decay Factor ─────────────────────────────────────────────────────

function timeDecay(date) {
  if (!date) return 1.0;
  const daysSince = (Date.now() - new Date(date).getTime()) / (1000 * 60 * 60 * 24);
  return Math.exp(-TIME_DECAY_LAMBDA * daysSince);
}

// ─── Compute Node Risk (from evidence counters) ────────────────────────────
// Risk is computed at runtime — NEVER stored in the node
// Returns 0-100

function computeNodeRisk(node) {
  // Bayesian prior — يحمي من overfitting على small samples
  // node عندها 1 fraud و0 orders → risk مش 100% لأن الـ sample صغير جداً
  // prior = 0.05 → يعمل smoothing طبيعي
  const PRIOR_WEIGHT = 0.05;
  // Trust farming protection — successOrders مش بيكبروا بلا حد
  // Asymmetric by design: fraudEvents مش محدودة — fraud بيفضل fraud
  // لكن clean orders بعد حد معين مش بتزيد الثقة — يمنع attacker
  // يبني 1000 clean orders عشان يخفف fraud signal واحد
  // الـ cap عند 20 = threshold تجريبي معقول لـ Shopify merchants
  // لو بيبيع بـ high volume (مئات الأوردرات/شهر) ممكن ترفعه لـ 50
  const SUCCESS_CAP = 20;
  const cappedSuccess = Math.min(node.successOrders, SUCCESS_CAP);
  const total         = node.fraudEvents + cappedSuccess + node.chargebacks + 1;

  // Weighted signal: fraud = 3x, chargeback = 2x, success = -0.5x
  const rawSignal = Math.max(0,
    (node.fraudEvents * 3 + node.chargebacks * 2 - cappedSuccess * 0.5) / total
  );

  // Bayesian blend: كل ما زادت الـ observations، الـ prior بيأثر أقل
  const confidence  = Math.min(1, total / 10);
  const smoothed    = rawSignal * confidence + PRIOR_WEIGHT * (1 - confidence);

  return Math.min(smoothed * 100, 100);
}

// ─── Traverse Graph and Calculate Connected Risk ───────────────────────────
// Walks graph up to MAX_DEPTH from device node
// Returns connected risk score 0-100

const MAX_VISITED_NODES = 50; // يمنع traversal explosion في graphs كبيرة
// Maximum edges to fetch per level in prefetch (prevents memory exhaustion)
const MAX_EDGES_PER_LEVEL = 500;

// ─── Prefetch Graph Edges ─────────────────────────────────────────────────
// بيجيب كل الـ edges اللي محتاجينها مرة واحدة من الـ DB
// بدل N+1 queries في كل recursion — query واحدة لكل depth level
async function prefetchGraphEdges(startNodeId, maxDepth, edgeMaturityCutoff) {
  const allEdges = new Map(); // nodeId → edges[]
  const visited  = new Set();
  let   frontier = [startNodeId];

  for (let depth = 0; depth < maxDepth; depth++) {
    if (frontier.length === 0) break;

    // نجيب edges لكل nodes في الـ frontier مرة واحدة
    const edges = await prisma.identityEdge.findMany({
      where: {
        fromId:       { in: frontier },
        seenCount:    { gte: MIN_EDGE_TRUST },
        uniqueOrders: { gte: 2 },
        firstSeenAt:  { lt: edgeMaturityCutoff },
      },
      include: { to: true },
      take: MAX_EDGES_PER_LEVEL,
      orderBy: { id: 'asc' },
    });

    // بنجمع الـ edges لكل node
    for (const edge of edges) {
      if (!allEdges.has(edge.fromId)) allEdges.set(edge.fromId, []);
      allEdges.get(edge.fromId).push(edge);
    }

    // إذا وصلنا إلى الحد الأقصى للحواف في هذا المستوى، نتوقف عن البحث في الأعماق الأكبر
    if (edges.length === MAX_EDGES_PER_LEVEL) {
      logger.warn({ module: 'identityGraph', deviceId: startNodeId, depth, edgesFetched: edges.length }, 'Reached edge limit per level, truncating traversal');
      break;
    }

    // الـ frontier الجديدة = كل الـ neighbor nodes اللي مش زرناها
    const nextFrontier = [];
    for (const edge of edges) {
      if (!visited.has(edge.toId)) {
        nextFrontier.push(edge.toId);
        visited.add(edge.toId);
      }
    }

    frontier.forEach(id => visited.add(id));
    frontier = nextFrontier;
  }

  return allEdges;
}
// ─── In-Memory Traversal ──────────────────────────────────────────────────
// بيعمل traversal في الذاكرة بدون أي DB calls
// كل الـ data اتجابت مرة واحدة في prefetchGraphEdges
function traverseInMemory(deviceNode, graphEdges, currentDepth = 0, visited = new Set(), contributed = new Set(), maxDepth = MAX_DEPTH_MED) {
  if (currentDepth > maxDepth) return 0;
  if (visited.has(deviceNode.id)) return 0;
  if (visited.size >= MAX_VISITED_NODES) {
    logger.warn({ module: 'identityGraph', maxVisitedNodes: MAX_VISITED_NODES }, 'Circuit breaker — traversal stopped');
    return 0;
  }

  visited.add(deviceNode.id);

  // Own risk — weighted by time decay + self cap
  const MAX_SELF_CONTRIBUTION = 50;
  const ownRisk  = computeNodeRisk(deviceNode);
  const ownDecay = timeDecay(deviceNode.lastSeen);
  let totalRisk  = Math.min(ownRisk * ownDecay * (PATH_DECAY[currentDepth] ?? 0.1), MAX_SELF_CONTRIBUTION);

  if (currentDepth >= maxDepth) return Math.min(totalRisk, 100);

  // نجيب الـ edges من الـ in-memory map — صفر DB calls
  const edges = graphEdges.get(deviceNode.id) || [];

  for (const edge of edges) {
    const neighborNode   = edge.to;
    const relationWeight = RELATION_WEIGHTS[edge.relation] ?? 0.5;
    const edgeDecay      = timeDecay(edge.lastSeenAt);
    const frequencyConf  = Math.min(1.0, Math.log1p(edge.seenCount) / Math.log1p(50));

    if (contributed.has(neighborNode.id)) continue;
    contributed.add(neighborNode.id);

    const subtreeRisk = traverseInMemory(
      neighborNode,
      graphEdges,
      currentDepth + 1,
      visited,
      contributed,
      maxDepth,
    );

    const MAX_NODE_CONTRIBUTION = 35;
    totalRisk += Math.min(
      subtreeRisk * relationWeight * edgeDecay * frequencyConf,
      MAX_NODE_CONTRIBUTION
    );
  }

  return Math.min(totalRisk, 100);
}

// ─── Traverse Graph and Calculate Connected Risk ───────────────────────────
// Entry point — prefetch ثم in-memory traversal
// بدل N+1 queries → queries محدودة (depth levels بس)


async function traverseFromDevice(deviceNode, maxDepth = MAX_DEPTH_MED) {
  const edgeMaturityCutoff = new Date(Date.now() - 12 * 60 * 60 * 1000);

  // Prefetch كل الـ edges مرة واحدة
  const graphEdges = await prefetchGraphEdges(deviceNode.id, maxDepth, edgeMaturityCutoff);

  // Traverse in-memory — صفر DB calls
  const connectedRisk = traverseInMemory(deviceNode, graphEdges, 0, new Set(), new Set(), maxDepth);

  return { connectedRisk, graphEdges };
}

// ─── Main: Get Connected Risk for Order ───────────────────────────────────
// Called from riskScoring.js
// Returns { connectedRisk, graphPath, hasConnections }

async function getConnectedRisk(order, merchantId) {
  logger.debug(`[GRAPH] getConnectedRisk called. device: ${order?.deviceFingerprint || order?.deviceId}`);
  const deviceId = order.deviceFingerprint || order.deviceId;

  if (!deviceId) {
    return { connectedRisk: 0, hasConnections: false, graphPath: [] };
  }

  try {
    const hashedDevice    = hashValue("DEVICE", deviceId);
    const hashedConfig    = order.fingerprintConfig   ?? null;
    const hashedHardware  = order.fingerprintHardware ?? null;

    // ─── Three-Tier Cascade — Single Query بدل 3 Sequential ──────────────
    // Tier 1: exact full HMAC — certainty (1.00)
    // Tier 2: config-level HMAC — very likely same device (0.85)
    // Tier 3: hardware-level HMAC — same physical hardware (0.65)
    // بيحل مشكلة Safari/Brave farbling اللي بيغير canvasHash كل session
    let deviceNode    = null;
    let matchTier     = "none";
    let matchConfidence = 0;
    // نفس منطق الـ global node: query واحدة بـ OR + priority selection
    // full HMAC > config > hardware
    const merchantOrConditions = [
      { hashedValue: hashedDevice },
      ...(hashedConfig   ? [{ fingerprintConfig: hashedConfig }]     : []),
      ...(hashedHardware ? [{ fingerprintHardware: hashedHardware }] : []),
    ];

    const merchantCandidates = await prisma.identityNode.findMany({
      where: { merchantId: merchantId ?? null, type: "DEVICE", OR: merchantOrConditions },
    });

    deviceNode =
      merchantCandidates.find(n => n.hashedValue         === hashedDevice)    ?? null;
    if (deviceNode) { matchTier = "full"; matchConfidence = 1.0; }

    if (!deviceNode && hashedConfig) {
      deviceNode = merchantCandidates.find(n => n.fingerprintConfig === hashedConfig) ?? null;
      if (deviceNode) { matchTier = "config"; matchConfidence = 0.85; }
    }

    if (!deviceNode && hashedHardware) {
      deviceNode = merchantCandidates.find(n => n.fingerprintHardware === hashedHardware) ?? null;
      if (deviceNode) { matchTier = "hardware"; matchConfidence = 0.65; }
    }

     if (!deviceNode) {
   logger.debug(`[GRAPH] getConnectedRisk: No deviceNode found. Returning 0.`);
    return { connectedRisk: 0, hasConnections: false, graphPath: [], matchTier: "none", matchConfidence: 0 };
  }
  logger.debug(`[GRAPH] getConnectedRisk: deviceNode found. matchTier=${matchTier}, matchConfidence=${matchConfidence}`);

    // ─── Self-Healing — بنحدث الـ full HMAC لو اتغير (Safari drift) ────────
    // بس لو:
    // 1. مش exact match (يعني full HMAC اتغير)
    // 2. Config match بـ confidence >= 0.85 (مش hardware فقط — خطر falsely heal)
    // 3. الـ fingerprint جاي من v3 source (server HMAC — مش legacy client hash)
    // يمنع poisoning: attacker يعمل hardware match ويغير الـ full HMAC للضحية
    if (matchTier !== "full" && matchConfidence >= 0.85 && order.fingerprintVersion === "v3" && hashedDevice) {
      try {
       await prisma.identityNode.updateMany({
          where: {
            id:          deviceNode.id,
            hashedValue: { not: hashedDevice },
          },
          data: {
            hashedValue:     hashedDevice,
            lastHealedAt:    new Date(),
          },
        });
        logger.info({ module: 'identityGraph', matchTier, matchConfidence, deviceMasked: hashedDevice.slice(0,8) + '***' }, 'Self-healed device node');
      } catch (healErr) {
        // Non-critical — لو فشل الـ healing، الـ scoring لسه شغال
        logger.error({ module: 'identityGraph', err: healErr }, 'Self-heal error');
      }
    }

    // Dynamic depth — high risk nodes get deeper traversal
    const nodeRisk = computeNodeRisk(deviceNode);
    const dynamicDepth = nodeRisk >= 60 ? MAX_DEPTH_HIGH
      : nodeRisk >= 20 ? MAX_DEPTH_MED
      : MAX_DEPTH_LOW;

    // Calculate risk — prefetch + in-memory traversal
    // graphEdges مشتركة بين الـ risk calculation والـ graphPath
    const { connectedRisk, graphEdges } = await traverseFromDevice(deviceNode, dynamicDepth);

    // Build explainable path from prefetched edges — صفر queries زيادة
    const deviceEdges = graphEdges.get(deviceNode.id) ?? [];
    const hasConnections = deviceEdges.length > 0;
    const graphPath = deviceEdges.slice(0, 20).map(e => ({
      relation: e.relation,
      nodeType: e.to.type,
      maskedValue: e.to.maskedValue,
      fraudEvents: e.to.fraudEvents,
      chargebacks: e.to.chargebacks,
      seenCount: e.seenCount,
      daysSinceLastSeen: Math.round(
        (Date.now() - new Date(e.to.lastSeen).getTime()) / (1000 * 60 * 60 * 24)
      ),
    }));

    // ─── Global Risk (Cross-Merchant) ────────────────────────────────
    // نشيك على الـ global node للـ device
    let globalContribution = 0;
    try {
     // ─── Global Node — Single Query بدل 3 Sequential ─────────────────────
      // بنجيب كل الـ candidates في query واحدة بـ OR
      // وبعدين بنختار الأفضل manually بـ priority:
      // full HMAC match > config match > hardware match
      const orConditions = [
        { hashedValue: hashedDevice },
        ...(hashedConfig   ? [{ fingerprintConfig: hashedConfig }]     : []),
        ...(hashedHardware ? [{ fingerprintHardware: hashedHardware }] : []),
      ];

      const globalCandidates = await prisma.identityNode.findMany({
        where: { merchantId: 'global', type: "DEVICE", OR: orConditions },
      });

      const globalDeviceNode =
        globalCandidates.find(n => n.hashedValue        === hashedDevice)   ??
        globalCandidates.find(n => n.fingerprintConfig  === hashedConfig)   ??
        globalCandidates.find(n => n.fingerprintHardware === hashedHardware) ??
        null;

      if (globalDeviceNode && globalDeviceNode.totalTransactions >= 3) {
        // Fraud rate — بيحسب الـ successOrders كـ negative signal
        // device عنده 100 clean order و1 fraud → fraudRate منخفض جداً
        // بدل totalTransactions بس — بنستخدم weighted denominator
        // successOrders تأثيرها أقل من fraud لأن clean orders أسهل تتجمع
        const weightedDenominator = Math.max(
          globalDeviceNode.fraudEvents +
          (globalDeviceNode.successOrders * 0.3) +
          globalDeviceNode.chargebacks +
          3,
          3
        );
        const fraudRate = globalDeviceNode.fraudEvents / weightedDenominator;

        // Confidence boost بناءً على عدد الـ transactions
        const confidenceBoost = Math.min(1, globalDeviceNode.totalTransactions / 10);

        // Raw global score
        const rawGlobalScore = fraudRate * confidenceBoost * 100;

        // Step decay
        const decayedScore = applyStepDecay(rawGlobalScore, globalDeviceNode.lastSeen);

        // Recency boost — بس لو في fraud فعلي مش بس activity
        const ageHours = (Date.now() - new Date(globalDeviceNode.lastSeen).getTime()) / (1000 * 60 * 60);
        const recencyBoost = (ageHours < 1 && fraudRate > 0.1) ? 10 : 0;

        // Trust-weighted dynamic weight — يمنع Sybil attack
        // بدل merchantsSeen * 0.2 (قابل للتلاعب)
        // بنستخدم sqrt للـ merchantsSeen عشان نقلل تأثير الأرقام الكبيرة
        // وبنضرب في merchant trust average لو متاح
        // Cap merchantsSeen — يمنع attacker يوزع fraud على كتير من التجار
        // عشان يرفع الـ dynamicWeight بشكل غير طبيعي
        // max 10 merchants في الحساب — بعد كده الـ weight مش بيزيد
        const cappedMerchants = Math.min(globalDeviceNode.merchantsSeen, 10);
        const sqrtMerchants   = Math.sqrt(cappedMerchants);
        const dynamicWeight   = Math.min(0.6, sqrtMerchants * 0.15);

        // Cross-merchant velocity — smooth scaling بدل binary 0/15
        // يمنع instability من step jumps
        // بس لو في fraud pattern فعلي مش بس velocity
        const velocityBoost = fraudRate > 0.05
          ? Math.min(15, globalDeviceNode.recentMerchants * 5)
          : 0;

        // FIX: boosts بيتضافوا بعد الضرب مش قبله
        // قبل: (decayedScore + boosts) * weight → يضعف الـ boosts
        // بعد: (decayedScore * weight) + boosts → boosts بتأثر بقيمتها الكاملة
        const baseContribution = decayedScore * dynamicWeight;
        globalContribution = Math.min(
          baseContribution + recencyBoost + velocityBoost,
          30
        );

        if (globalContribution > 5) {
          const merchantsText = globalDeviceNode.merchantsSeen > 1
            ? `across ${globalDeviceNode.merchantsSeen} merchants`
            : "in network";
          logger.info({ module: 'identityGraph', globalContribution, merchantsText }, 'Global risk');

          // ─── Soft Early Warning ───────────────────────────────────────
          // لو في fraud recent في آخر 48 ساعة — نضيف flag واضح للتاجر
          // ─── Active Early Warning (Computed Alert) ────────────────────
      // بنجيب الـ computed alert من الـ cache مش بنحسبه من أول
      try {
        const computedRisk = await prisma.computedIdentityRisk.findUnique({
          where: { nodeId_algorithmVersion: { nodeId: globalDeviceNode.id, algorithmVersion: 1 } },
        });

        if (computedRisk?.alertLevel) {
          const hoursAgo = Math.round(
            (Date.now() - new Date(computedRisk.computedAt).getTime()) / (1000 * 60 * 60)
          );

          // Alert صالح لـ 72 ساعة فقط
          if (hoursAgo <= 72) {
            if (!graphPath.some(p => p.type === "EARLY_WARNING" || p.type === "GLOBAL_WARNING")) {
              const alertBoostPreview = computedRisk.alertLevel === "danger" ? 20 : 10;
              graphPath.push({
                type:             "EARLY_WARNING",
                relation:         "NETWORK_FRAUD",
                nodeType:         "DEVICE",
                maskedValue:      "cross-merchant network signal",
                alertLevel:       computedRisk.alertLevel,
                riskScore:        computedRisk.riskScore,
                fraudWeight:      computedRisk.fraudWeight,
                cleanWeight:      computedRisk.cleanWeight,
                merchantsSeen:    globalDeviceNode.merchantsSeen,
                estimatedContrib: alertBoostPreview,
                hoursAgo,
                earlyWarning:     hoursAgo <= 48,
              });
            }

            // زيادة الـ globalContribution لو في active alert
            const alertBoost = computedRisk.alertLevel === "danger" ? 20 : 10;
            globalContribution = Math.min(globalContribution + alertBoost, 30);

            logger.warn({ module: 'identityGraph', deviceMasked: hashedDevice.slice(0,8) + '***', alertLevel: computedRisk.alertLevel, riskScore: computedRisk.riskScore, hoursAgo }, 'Early Warning');
          }
        } else if (globalDeviceNode.fraudEvents > 0) {
          const hoursAgo = Math.round(
            (Date.now() - new Date(globalDeviceNode.lastSeen).getTime()) / (1000 * 60 * 60)
          );
          if (!graphPath.some(p => p.type === "EARLY_WARNING" || p.type === "GLOBAL_WARNING")) {
            graphPath.push({
              type:        "GLOBAL_WARNING",
              relation:    "NETWORK_FRAUD",
              nodeType:    "DEVICE",
              maskedValue: "cross-merchant signal",
              fraudEvents: globalDeviceNode.fraudEvents,
              chargebacks: globalDeviceNode.chargebacks,
              merchantsSeen: globalDeviceNode.merchantsSeen,
              hoursAgo,
              earlyWarning: hoursAgo <= 48,
            });
          }
        }
      } catch (alertErr) {
        logger.error({ module: 'identityGraph', err: alertErr }, 'Alert lookup error');
      }
        }
      }
    } catch (globalErr) {
      logger.error({ module: 'identityGraph', err: globalErr }, 'Global risk error');
    }

    // ─── Confidence Multiplier — بيقلل risk propagation على fuzzy matches ──
    // exact match (1.00) → full risk
    // config match (0.85) → 85% risk — نفس الجهاز تقريباً
    // hardware match (0.65) → 65% risk — نفس الـ hardware، مش متأكدين من الـ user
    // يمنع false positive: جهازين بنفس الـ hardware يعاقبوا بعض
    const rawRisk      = Math.min(connectedRisk + globalContribution, 100);
    const adjustedRisk = Math.round(rawRisk * matchConfidence);

    if (matchTier !== "full") {
      logger.debug({ module: 'identityGraph', matchTier, matchConfidence, rawRisk, adjustedRisk }, 'Fuzzy match');
    }
  const result = {
    connectedRisk:      adjustedRisk,
    hasConnections,
    graphPath,
    globalContribution: Math.round(globalContribution),
    matchTier,
    matchConfidence,
  };
  logger.debug(`[GRAPH] getConnectedRisk result: connectedRisk=${adjustedRisk}, matchTier=${matchTier}`);
  return result;

  } catch (error) {
    logger.error({ module: 'identityGraph', err: error }, 'getConnectedRisk error');
    return { connectedRisk: 0, hasConnections: false, graphPath: [] };
  }
}

// ─── Mark Node as Fraud ────────────────────────────────────────────────────
// Called from feedback loop when dispute is lost
// Increments fraud counters on all nodes linked to this order

// patternContext — optional, بيتمرر من الـ feedback loop لو متاح
// default = {} للـ backward compatibility
async function markOrderAsFraud(order, merchantId, patternContext = {}) {
  logger.debug(`[GRAPH] markOrderAsFraud called. device: ${order?.deviceFingerprint || order?.deviceId}`);
  const deviceId = order.deviceFingerprint || order.deviceId;
  if (!deviceId) return;

  try {
    const hashedDevice = hashValue("DEVICE", deviceId);

    const deviceNode = await prisma.identityNode.findFirst({
      where: { merchantId: merchantId ?? null, type: "DEVICE", hashedValue: hashedDevice },
    });

    if (!deviceNode) {
    logger.debug(`[GRAPH] markOrderAsFraud: No deviceNode found. Exiting.`);
    return;
  }

    // ─── Batch 1: Load all data needed ───────────────────────────────
    // query واحدة بدل N queries — نجيب كل حاجة مع بعض
    const [edges, globalNode, merchantTrustData] = await Promise.all([
      prisma.identityEdge.findMany({
        where: { fromId: deviceNode.id },
        select: { to: { select: { id: true } } },
      }),
      prisma.identityNode.findFirst({
        where: { merchantId: 'global', type: "DEVICE", hashedValue: hashedDevice },
        select: { id: true },
      }),
      merchantId ? prisma.merchantProfile.findUnique({
        where: { merchantId: merchantId },
        select: { trustScore: true, reportCount: true },
      }) : Promise.resolve(null),
    ]);

    // ─── Batch 2: All node updates in one transaction ─────────────────
    const connectedNodeIds = edges.map(e => e.to.id);

   const DEVICE_MIN_FRAUD = 2;

    await prisma.$transaction(async (tx) => {
      // Device node
      await tx.identityNode.update({
        where: { id: deviceNode.id },
        data: { fraudEvents: { increment: 1 }, chargebacks: { increment: 1 } },
      });

      // Connected nodes — bulk update
      if (connectedNodeIds.length > 0) {
        await tx.identityNode.updateMany({
          where: { id: { in: connectedNodeIds } },
          data: { fraudEvents: { increment: 1 }, chargebacks: { increment: 1 } },
        });
      }

      // Global node — تحديث ذري باستخدام SQL خام
     // Global node — تحديث بسيط (بدون flaggedAtCount)
if (globalNode) {
  await tx.identityNode.update({
    where: { id: globalNode.id },
    data: {
      fraudEvents: { increment: 1 },
      chargebacks: { increment: 1 },
      totalTransactions: { increment: 1 },
      lastSeen: new Date(),
    },
  });
}

      // Merchant trust
      if (merchantId) {
       await tx.merchantProfile.update({
  where: { merchantId: merchantId },
  data: {
    reportCount: { increment: 1 },
  },
});
      }
    });

    // ─── Batch 3: Identity Event + Computed Risk ──────────────────────
    // منفصلة عن الـ transaction الأولى — لأنها تعتمد على الـ recentEvents
    try {
      const merchantTrust = computeMerchantTrust(merchantTrustData);

      const [, recentEvents] = await Promise.all([
        prisma.identityEvent.create({
          data: {
            nodeId:        deviceNode.id,
            merchantId:    merchantId ?? null,
            type:          "FRAUD_CONFIRMED",
            eventCategory: "IDENTITY",
            weight:        merchantTrust,
          },
        }),
        prisma.identityEvent.findMany({
          where: {
            nodeId:    deviceNode.id,
            createdAt: { gte: new Date(Date.now() - 72 * 60 * 60 * 1000) },
          },
          select: { type: true, weight: true },
        }),
      ]);

      const fraudWeight = recentEvents
        .filter(e => e.type === "FRAUD_CONFIRMED" || e.type === "CHARGEBACK")
        .reduce((sum, e) => sum + e.weight, 0) + merchantTrust;

      const cleanWeight = recentEvents
        .filter(e => e.type === "CLEAN_ORDER")
        .reduce((sum, e) => sum + e.weight, 0);

      const riskScore  = Math.max(0, fraudWeight - cleanWeight);
      const alertLevel = riskScore >= 2.5 ? "danger"
        : riskScore >= 1.0 ? "warning"
        : null;

      await prisma.computedIdentityRisk.upsert({
        where:  { nodeId_algorithmVersion: { nodeId: deviceNode.id, algorithmVersion: 1 } },
        create: { nodeId: deviceNode.id, algorithmVersion: 1, riskScore, alertLevel, fraudWeight, cleanWeight, eventCount: recentEvents.length + 1, computedAt: new Date() },
        update: { riskScore, alertLevel, fraudWeight, cleanWeight, eventCount: recentEvents.length + 1, computedAt: new Date() },
      });

    } catch (eventErr) {
      logger.error({ module: 'identityGraph', err: eventErr }, 'IdentityEvent record error');
    }

   


    // Invalidate IP + Email cache — لو اتثبت fraud مش هنثق في الـ cached results
    if (order.ipAddress) {
      invalidateIPCache(order.ipAddress);
    }
    if (order.email) {
      invalidateEmailCache(order.email);
    }

    logger.info({ module: 'identityGraph', deviceMasked: maskDeviceId(deviceId), connectedNodesCount: edges.length }, 'Marked fraud');

  } catch (error) {
    logger.error({ module: 'identityGraph', err: error }, 'markOrderAsFraud error');
  }
}

// ─── Mark Order as Clean ───────────────────────────────────────────────────
// Called when dispute is won — reinforces positive signals

async function markOrderAsClean(order, merchantId) {
  const deviceId = order.deviceFingerprint || order.deviceId;
  if (!deviceId) return;

  try {
    const hashedDevice = hashValue("DEVICE", deviceId);

    const deviceNode = await prisma.identityNode.findFirst({
      where: { merchantId: merchantId ?? null, type: "DEVICE", hashedValue: hashedDevice },
    });

    if (!deviceNode) {
    logger.debug(`[GRAPH] markOrderAsClean: No deviceNode found. Exiting.`);
    return;
  }

    // ─── Batch: successOrders + identityEvent في نفس الوقت ───────────
    const merchantTrustData = merchantId ? await prisma.merchantProfile.findUnique({
      where: { merchantId: merchantId },
      select: { trustScore: true, reportCount: true },
    }) : null;

    const merchantTrust = computeMerchantTrust(merchantTrustData);

    await prisma.identityNode.update({
      where: { id: deviceNode.id },
      data: { successOrders: { increment: 1 } },
    });

    // ─── Record Clean Event + Recompute ──────────────────────────────
    try {
      await  prisma.identityEvent.create({
        data: {
          nodeId:        deviceNode.id,
          merchantId:    merchantId ?? null,
          type:          "CLEAN_ORDER",
          eventCategory: "IDENTITY",
          weight:        merchantTrust,
        },
      });

      // Recompute alert — clean order قد يقلل الـ alert
      const recentEvents = await prisma.identityEvent.findMany({
        where: {
          nodeId:    deviceNode.id,
          createdAt: { gte: new Date(Date.now() - 72 * 60 * 60 * 1000) },
        },
        select: { type: true, weight: true },
      });

      const fraudWeight = recentEvents
        .filter(e => e.type === "FRAUD_CONFIRMED" || e.type === "CHARGEBACK")
        .reduce((sum, e) => sum + e.weight, 0);

      const cleanWeight = recentEvents
        .filter(e => e.type === "CLEAN_ORDER")
        .reduce((sum, e) => sum + e.weight, 0);

      const riskScore  = Math.max(0, fraudWeight - cleanWeight);
      const alertLevel = riskScore >= 2.5 ? "danger"
        : riskScore >= 1.0 ? "warning"
        : null;

      await prisma.computedIdentityRisk.upsert({
        where: { nodeId_algorithmVersion: { nodeId: deviceNode.id, algorithmVersion: 1 } },
        create: {
          nodeId:           deviceNode.id,
          algorithmVersion: 1,
          riskScore,
          alertLevel,
          fraudWeight,
          cleanWeight,
          eventCount:       recentEvents.length,
          computedAt:       new Date(),
        },
        update: {
          riskScore,
          alertLevel,
          fraudWeight,
          cleanWeight,
          eventCount: recentEvents.length,
          computedAt: new Date(),
        },
      });
    } catch (cleanEventErr) {
      logger.error({ module: 'identityGraph', err: cleanEventErr }, 'Clean event record error');
    }

    logger.info({ module: 'identityGraph', deviceMasked: maskDeviceId(deviceId) }, 'Marked clean order');

  } catch (error) {
    logger.error({ module: 'identityGraph', err: error }, 'markOrderAsClean error');
  }
}
module.exports = {
  buildGraphFromOrder,
  getConnectedRisk,
  markOrderAsFraud,
  markOrderAsClean,
  hashValue,
  maskValue,
};