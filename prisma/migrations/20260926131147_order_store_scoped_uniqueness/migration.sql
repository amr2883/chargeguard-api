-- [C4 fix, part 1 of 2: EXPAND] Add store-scoped uniqueness for Order: one
-- plain index plus two partial unique indexes (below). The old tenant-wide
-- unique index "Order_merchantId_orderId_key" (C3) is kept on purpose in this
-- step: code deployed before this change upserts by (merchantId, orderId) via
-- ON CONFLICT, and dropping that index while such code is running fails with
-- Postgres error 42P10. The DROP is part 2 of 2 (CONTRACT) and lives outside
-- this folder in docs/migrations-pending/contract_drop_order_unique.sql until
-- the new code is live (measured on Prisma 5.22 and Postgres 16: once it is
-- dropped, every upsert from the previous code fails, even for a new order).
-- Deploy order: this file, then the new code (no old instance left), then part
-- 2 of 2. The pooled partial index below keeps uniqueness only for rows with
-- storeId IS NULL. See the Order model comment in schema.prisma for the rationale.

-- CreateIndex (plain, non-unique — matches the new @@index([merchantId, orderId])
-- declared in schema.prisma; query-performance only, carries no uniqueness guarantee)
CREATE INDEX "Order_merchantId_orderId_idx" ON "Order"("merchantId", "orderId");

-- [C4 fix] Store-scoped orders: Agency tenants with a resolved storeId now
-- get a genuinely independent orderId per store. Two different stores
-- under the same merchantId can share an orderId without collision.
CREATE UNIQUE INDEX "Order_merchantId_storeId_orderId_key"
  ON "Order" ("merchantId", "storeId", "orderId")
  WHERE "storeId" IS NOT NULL;

-- [C4 fix] Pooled orders (storeId IS NULL): keeps the prior C3 guarantee for
-- every row whose storeId IS NULL, including the rows of Starter/Pro tenants,
-- who never populate storeId at all.
CREATE UNIQUE INDEX "Order_merchantId_orderId_pooled_key"
  ON "Order" ("merchantId", "orderId")
  WHERE "storeId" IS NULL;