-- [C4 fix] Drop the tenant-wide-only unique index (C3). It is being
-- replaced below by two partial unique indexes that additionally scope
-- by storeId when present, closing a same-tenant/different-store
-- collision that C3 did not address (see schema.prisma's Order model
-- comment for the full rationale).
DROP INDEX "Order_merchantId_orderId_key";

-- CreateIndex (plain, non-unique — matches the new @@index([merchantId, orderId])
-- declared in schema.prisma; query-performance only, carries no uniqueness guarantee)
CREATE INDEX "Order_merchantId_orderId_idx" ON "Order"("merchantId", "orderId");

-- [C4 fix] Store-scoped orders: Agency tenants with a resolved storeId now
-- get a genuinely independent orderId per store. Two different stores
-- under the same merchantId can share an orderId without collision.
CREATE UNIQUE INDEX "Order_merchantId_storeId_orderId_key"
  ON "Order" ("merchantId", "storeId", "orderId")
  WHERE "storeId" IS NOT NULL;

-- [C4 fix] Pooled orders (storeId IS NULL): preserves the EXACT prior C3
-- guarantee unchanged for every existing row and for Starter/Pro tenants,
-- who never populate storeId at all.
CREATE UNIQUE INDEX "Order_merchantId_orderId_pooled_key"
  ON "Order" ("merchantId", "orderId")
  WHERE "storeId" IS NULL;