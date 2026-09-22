-- Partial unique index for IdentityNode when merchantId IS NULL.
-- Same rationale as BlacklistEntry_null_store_unique / WhitelistEntry_null_store_unique:
-- Postgres treats each NULL as distinct in a normal unique constraint, so the
-- existing @@unique([merchantId, type, hashedValue]) does NOT prevent duplicate
-- rows when merchantId is NULL (used for global/cross-merchant identity nodes
-- via upsertGlobalNode). Currently no live code path triggers this (buildGraphFromOrder
-- always passes a real merchantId - confirmed by code audit), but this closes
-- the gap defensively at zero cost since the table is empty.
--
-- WARNING: this fails if duplicate rows already exist. Check counts before deploying.
CREATE UNIQUE INDEX "IdentityNode_null_merchant_unique"
ON "IdentityNode"("type", "hashedValue")
WHERE "merchantId" IS NULL;