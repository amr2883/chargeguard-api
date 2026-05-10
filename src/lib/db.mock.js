
// db.mock.js — يحاكي طبقة Prisma للعمل في الذاكرة
const { randomUUID } = require('crypto');

// المخازن
const identityNodes = new Map(); // key: `merchantId:type:hashedValue`
const identityEdges = new Map(); // key: `fromId:toId:relation`
const computedIdentityRisks = new Map(); // key: `nodeId:algorithmVersion`

// دوال مساعدة
function nodeKey(merchantId, type, hashedValue) {
  return `${merchantId ?? 'null'}:${type}:${hashedValue}`;
}

function edgeKey(fromId, toId, relation) {
  return `${fromId}:${toId}:${relation}`;
}

// ========== identityNode ==========
const identityNode = {
  async upsert({ where, create, update }) {
    const key = nodeKey(where.merchantId_type_hashedValue.merchantId, where.merchantId_type_hashedValue.type, where.merchantId_type_hashedValue.hashedValue);
    let node = identityNodes.get(key);
    const now = new Date();
    if (!node) {
      node = {
        id: randomUUID(),
        fraudEvents: 0,
        successOrders: 0,
        chargebacks: 0,
        totalTransactions: 0,
        merchantsSeen: 0,
        recentMerchants: 0,
        ...create,
        firstSeen: create.firstSeen || now,
        lastSeen: create.lastSeen || now,
      };
      identityNodes.set(key, node);
    } else {
      // معالجة عمليات increment
      for (const [k, v] of Object.entries(update)) {
        if (typeof v === 'object' && v !== null && 'increment' in v) {
          node[k] = (node[k] || 0) + v.increment;
        } else {
          node[k] = v;
        }
      }
      node.lastSeen = now;
    }
    return node;
  },

  async findFirst({ where }) {
    if (where?.merchantId_type_hashedValue) {
      const key = nodeKey(where.merchantId_type_hashedValue.merchantId, where.merchantId_type_hashedValue.type, where.merchantId_type_hashedValue.hashedValue);
      return identityNodes.get(key) || null;
    }
    if (where?.merchantId !== undefined && where?.type && where?.hashedValue) {
      const key = nodeKey(where.merchantId, where.type, where.hashedValue);
      return identityNodes.get(key) || null;
    }
    // بحث عام (مبسط)
    for (const node of identityNodes.values()) {
      if (where?.merchantId !== undefined && node.merchantId !== where.merchantId) continue;
      if (where?.type && node.type !== where.type) continue;
      if (where?.hashedValue && node.hashedValue !== where.hashedValue) continue;
      return node;
    }
    return null;
  },

  async findMany({ where, include, take, orderBy }) {
    const results = [];
    const merchantId = where?.merchantId;
    const type = where?.type;
    const orConditions = where?.OR;
    
    for (const node of identityNodes.values()) {
      if (merchantId !== undefined && node.merchantId !== merchantId) continue;
      if (type && node.type !== type) continue;
      if (orConditions) {
        let match = false;
        for (const cond of orConditions) {
          if (cond.hashedValue && node.hashedValue === cond.hashedValue) { match = true; break; }
          if (cond.fingerprintConfig && node.fingerprintConfig === cond.fingerprintConfig) { match = true; break; }
          if (cond.fingerprintHardware && node.fingerprintHardware === cond.fingerprintHardware) { match = true; break; }
        }
        if (!match) continue;
      }
      results.push({ ...node });
    }
    // ترتيب (بسيط)
    if (orderBy) {
      // تجاهل
    }
    return take ? results.slice(0, take) : results;
  },

  async update({ where, data }) {
    console.log('[DB MOCK] update called with where:', JSON.stringify(where), 'data:', JSON.stringify(data));
    const node = await identityNode.findFirst({ where });
    if (!node) {
      console.log('[DB MOCK] update: node NOT found');
      return null;
    }
    
    // معالجة عمليات increment الذرية
    for (const [key, value] of Object.entries(data)) {
      if (typeof value === 'object' && value !== null && 'increment' in value) {
        const current = node[key] || 0;
        node[key] = current + value.increment;
      } else {
        node[key] = value;
      }
    }
    
    console.log('[DB MOCK] update: node updated. fraudEvents=', node.fraudEvents);
    return node;
  },

  async updateMany({ where, data }) {
    console.log('[DB MOCK] updateMany called with where:', JSON.stringify(where), 'data:', JSON.stringify(data));
    let count = 0;
    for (const node of identityNodes.values()) {
      let match = true;
      if (where?.id && !where.id.in?.includes(node.id)) match = false;
      if (where?.hashedValue && where.hashedValue.not === node.hashedValue) match = false;
                if (match) {
            // ضمان وجود الخصائص الرقمية
            node.fraudEvents = node.fraudEvents || 0;
            node.chargebacks = node.chargebacks || 0;
            node.successOrders = node.successOrders || 0;
            
            for (const [key, value] of Object.entries(data)) {
              if (typeof value === 'object' && value !== null && 'increment' in value) {
                node[key] = (node[key] || 0) + value.increment;
              } else {
                node[key] = value;
              }
            }
            count++;
          }
    }
    return { count };
  },
};

// ========== identityEdge ==========
const identityEdge = {
  async findUnique({ where }) {
    const key = edgeKey(where.fromId_toId_relation.fromId, where.fromId_toId_relation.toId, where.fromId_toId_relation.relation);
    const edge = identityEdges.get(key) || null;
    if (edge && edge.toId) {
      const toNode = [...identityNodes.values()].find(n => n.id === edge.toId);
      edge.to = toNode || { type: 'UNKNOWN', maskedValue: 'unknown', fraudEvents: 0, chargebacks: 0, lastSeen: new Date() };
    }
    return edge;
  },

  async upsert({ where, create, update }) {
    const key = edgeKey(where.fromId, where.toId, where.relation);
    let edge = identityEdges.get(key);
    const now = new Date();
    if (!edge) {
      edge = {
        id: randomUUID(),
        ...create,
        firstSeenAt: create.firstSeenAt || now,
        lastSeenAt: create.lastSeenAt || now,
        createdAt: now,
        updatedAt: now,
      };
      identityEdges.set(key, edge);
    } else {
      edge.seenCount = (edge.seenCount || 0) + 1;
      edge.lastSeenAt = now;
      edge.updatedAt = now;
    }
    // إرفاق العقدة المستهدفة (to) كعلاقة
    if (edge.toId) {
      const toNode = [...identityNodes.values()].find(n => n.id === edge.toId);
      edge.to = toNode || { type: 'UNKNOWN', maskedValue: 'unknown', fraudEvents: 0, chargebacks: 0, lastSeen: now };
    }
    return edge;
  },

  async findMany({ where, include, take }) {
    const results = [];
    const fromIds = where?.fromId?.in || (where?.fromId ? [where.fromId] : []);
    const toId = where?.toId;
    const seenCount = where?.seenCount;
    const uniqueOrders = where?.uniqueOrders;
    const firstSeenAt = where?.firstSeenAt;
    
    for (const edge of identityEdges.values()) {
      if (fromIds.length && !fromIds.includes(edge.fromId)) continue;
      if (toId && edge.toId !== toId) continue;
      if (seenCount && edge.seenCount < seenCount.gte) continue;
      if (uniqueOrders && (edge.uniqueOrders || 0) < uniqueOrders.gte) continue;
      if (firstSeenAt?.lt && new Date(edge.firstSeenAt) >= new Date(firstSeenAt.lt)) continue;
      
      const edgeCopy = { ...edge };
      if (include?.to) {
        const toNode = [...identityNodes.values()].find(n => n.id === edge.toId);
        edgeCopy.to = toNode || { type: 'UNKNOWN', maskedValue: 'unknown', fraudEvents: 0, chargebacks: 0, lastSeen: new Date() };
      }
      results.push(edgeCopy);
    }
    return take ? results.slice(0, take) : results;
  },

  async count({ where }) {
    const fromId = where?.fromId;
    const firstSeenAt = where?.firstSeenAt;
    let count = 0;
    for (const edge of identityEdges.values()) {
      if (fromId && edge.fromId !== fromId) continue;
      if (firstSeenAt?.gte && new Date(edge.firstSeenAt) < new Date(firstSeenAt.gte)) continue;
      count++;
    }
    return count;
  },
};

// ========== computedIdentityRisk ==========
const computedIdentityRisk = {
  async findUnique({ where }) {
    const key = `${where.nodeId_algorithmVersion.nodeId}:${where.nodeId_algorithmVersion.algorithmVersion}`;
    return computedIdentityRisks.get(key) || null;
  },
  async upsert({ where, create, update }) {
    const key = `${where.nodeId_algorithmVersion.nodeId}:${where.nodeId_algorithmVersion.algorithmVersion}`;
    let record = computedIdentityRisks.get(key);
    if (!record) {
      record = { ...create, computedAt: new Date() };
      computedIdentityRisks.set(key, record);
    } else {
      Object.assign(record, update, { computedAt: new Date() });
    }
    return record;
  },
};

// ========== merchant (محاكاة) ==========
const merchant = {
  async findUnique({ where, select }) {
    return { trustScore: 0.5, reportCount: 10 };
  },
  async update({ where, data }) {
    return {};
  },
};

// ========== identityEvent (محاكاة) ==========
const identityEvent = {
  async create({ data }) {
    return { id: randomUUID(), ...data };
  },
  async findMany({ where, select }) {
    return [];
  },
};

// ========== واجهة db ==========
const db = {
  identityNode,
  identityEdge,
  computedIdentityRisk,
  merchant,           // <-- أضف
  identityEvent,      // <-- أضف
  $transaction: async (fn) => fn(db),
  $executeRaw: async () => {},
};

module.exports = db;
