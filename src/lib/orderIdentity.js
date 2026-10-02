// src/lib/orderIdentity.js
//
// [C4 fix] Single source of truth for looking up / writing an Order row
// by its business key (merchantId, storeId, orderId), now that storeId
// participates in uniqueness via two partial indexes (see schema.prisma's
// Order model comment, and migration
// 20260926131147_order_store_scoped_uniqueness) instead of a single
// Prisma-declared @@unique. Prisma Client no longer generates a
// `merchantId_orderId` (or three-way) compound-unique input for this
// model — every call site that used to do
//   db.order.findUnique({ where: { merchantId_orderId: { merchantId, orderId } } })
// or
//   db.order.upsert({ where: { merchantId_orderId: {...} }, create, update })
// MUST go through the two functions below instead.
//
// storeId semantics: `null` means "pooled" and is matched with an exact
// `storeId: null` filter (translates to `storeId IS NULL` in SQL) — never
// left out of the where clause — so a lookup always resolves to exactly
// one of the two partial-index partitions, never both. This mirrors
// getStoreScope()'s own storeId ?? null convention already used
// throughout routes/risk.js.

function businessKeyWhere({ merchantId, storeId, orderId }) {
  return { merchantId, orderId, storeId: storeId ?? null };
}

/**
 * Read-only lookup. Replaces:
 *   db.order.findUnique({ where: { merchantId_orderId: { merchantId, orderId } } })
 *
 * `db` may be either the top-level Prisma client or a `tx` transaction
 * client — both expose `.order.findFirst`, so this works unchanged inside
 * an existing db.$transaction(...) call site.
 */
async function findOrderByBusinessKey(db, { merchantId, storeId, orderId }) {
  return db.order.findFirst({ where: businessKeyWhere({ merchantId, storeId, orderId }) });
}

/**
 * Create-or-update. Replaces:
 *   db.order.upsert({ where: { merchantId_orderId: {...} }, create, update })
 *
 * `create` must NOT itself set merchantId/storeId/orderId — those are
 * injected here from the business key to guarantee they always match
 * exactly what was looked up. `update` is applied either to the existing
 * row found on the first read, or (on a lost race) to the row the
 * concurrent request created.
 *
 * Race handling: findFirst-then-create has a TOCTOU window between two
 * concurrent requests for the exact same key. This is intentional and
 * safe — the partial unique index is the real guard (same defense-in-
 * depth philosophy as payments.js's P0-07 fix). A P2002 here means a
 * concurrent request already won this exact key; we re-read and apply
 * `update` to that row instead of treating it as a failure. Any other
 * error is rethrown unchanged.
 */
async function upsertOrderByBusinessKey(db, { merchantId, storeId, orderId }, { create, update }) {
  const key = businessKeyWhere({ merchantId, storeId, orderId });

  const existing = await db.order.findFirst({ where: key });
  if (existing) {
    return db.order.update({ where: { id: existing.id }, data: update });
  }

  try {
    return await db.order.create({ data: { ...create, ...key } });
  } catch (err) {
    if (err.code === 'P2002') {
      const raced = await db.order.findFirst({ where: key });
      if (raced) {
        return db.order.update({ where: { id: raced.id }, data: update });
      }
    }
    throw err;
  }
}

/**
 * Best-effort lookup when the caller has no storeId context at all — used
 * by cross-store-agnostic callers: processFeedbackSimplified (payment
 * processor disputes carry no store concept), admin override-order (no
 * store selector in the admin UI), and replayPendingEnrichments (the
 * PendingEnrichment table has no storeId column). Searches BOTH partial-
 * index partitions (storeId IS NULL and storeId IS NOT NULL) instead of
 * assuming pooled — a bare storeId:null filter would silently fail to
 * find a store-scoped order, which is worse than an honest 404.
 *
 * If more than one row matches (only possible for an Agency tenant in
 * per_store mode where two different stores independently produced the
 * same orderId — the exact scenario C4 exists to allow), this is a
 * genuine ambiguity this caller cannot resolve on its own. We log a
 * warning and deterministically pick the most recently created row
 * (least-surprising default: "the current one"), rather than silently
 * guessing or crashing. `logger` is optional but should always be passed
 * in production call sites so real-world ambiguity surfaces instead of
 * vanishing into a default pick.
 */
async function findOrderByMerchantAndOrderIdBestEffort(db, { merchantId, orderId }, logger) {
  const matches = await db.order.findMany({
    where: { merchantId, orderId },
    orderBy: { createdAt: 'desc' },
  });
  if (matches.length > 1 && logger) {
    logger.warn(
      { module: 'orderIdentity', merchantId, orderId, matchCount: matches.length },
      'Ambiguous storeId-agnostic order lookup — multiple stores share this orderId under the same tenant; picked most recent'
    );
  }
  return matches[0] ?? null;
}

module.exports = {
  findOrderByBusinessKey,
  upsertOrderByBusinessKey,
  findOrderByMerchantAndOrderIdBestEffort,
  businessKeyWhere,
};