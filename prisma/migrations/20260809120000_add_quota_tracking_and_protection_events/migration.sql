-- AlterTable
ALTER TABLE "MonthlyReport" ADD COLUMN     "advancedLayersAvailable" INTEGER,
ADD COLUMN     "coreLayersActive" INTEGER;

-- AlterTable
ALTER TABLE "Tenant" ADD COLUMN     "lastQuotaExceededNoticeSentAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "ProtectionEvent" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endedAt" TIMESTAMP(3),
    "metadata" JSONB,

    CONSTRAINT "ProtectionEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ProtectionEvent_tenantId_startedAt_idx" ON "ProtectionEvent"("tenantId", "startedAt");

-- CreateIndex
CREATE INDEX "ProtectionEvent_tenantId_type_startedAt_idx" ON "ProtectionEvent"("tenantId", "type", "startedAt");

-- AddForeignKey
ALTER TABLE "ProtectionEvent" ADD CONSTRAINT "ProtectionEvent_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;