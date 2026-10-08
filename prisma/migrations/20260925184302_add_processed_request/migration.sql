-- CreateTable
CREATE TABLE "ProcessedRequest" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "requestKey" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'processing',
    "responseCode" INTEGER,
    "responseBody" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "ProcessedRequest_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ProcessedRequest_createdAt_idx" ON "ProcessedRequest"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "ProcessedRequest_tenantId_requestKey_key" ON "ProcessedRequest"("tenantId", "requestKey");
