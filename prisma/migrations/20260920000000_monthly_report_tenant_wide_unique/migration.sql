-- Postgres treats NULL as distinct in unique indexes, so the composite unique on
-- (tenantId, storeId, reportMonth, reportYear) does not prevent duplicate tenant-wide
-- rows (storeId IS NULL). This partial index closes that gap.
CREATE UNIQUE INDEX "MonthlyReport_tenant_wide_unique"
ON "MonthlyReport"("tenantId", "reportMonth", "reportYear")
WHERE "storeId" IS NULL;
