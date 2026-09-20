-- Postgres treats NULLs as distinct in unique indexes, so the composite unique on
-- (merchantId, storeId, type, value) does not prevent duplicates when storeId IS NULL.
-- Every row written by POST /risk/blacklist and /risk/whitelist has storeId NULL.
-- WARNING: this fails if duplicate rows already exist. Check counts before deploying.
CREATE UNIQUE INDEX "BlacklistEntry_null_store_unique"
ON "BlacklistEntry"("merchantId", "type", "value")
WHERE "storeId" IS NULL;

CREATE UNIQUE INDEX "WhitelistEntry_null_store_unique"
ON "WhitelistEntry"("merchantId", "type", "value")
WHERE "storeId" IS NULL;
