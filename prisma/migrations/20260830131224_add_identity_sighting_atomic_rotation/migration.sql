-- CreateTable
CREATE TABLE "IdentitySighting" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "storeId" TEXT,
    "scope" TEXT NOT NULL,
    "groupKey" TEXT NOT NULL,
    "memberKey" TEXT NOT NULL,
    "orderId" TEXT NOT NULL,
    "seenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IdentitySighting_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "IdentitySighting_merchantId_scope_groupKey_seenAt_idx" ON "IdentitySighting"("merchantId", "scope", "groupKey", "seenAt");

-- CreateIndex
CREATE INDEX "IdentitySighting_merchantId_storeId_scope_groupKey_seenAt_idx" ON "IdentitySighting"("merchantId", "storeId", "scope", "groupKey", "seenAt");

-- CreateIndex
CREATE INDEX "IdentitySighting_seenAt_idx" ON "IdentitySighting"("seenAt");

-- CreateIndex
CREATE UNIQUE INDEX "IdentitySighting_merchantId_scope_orderId_key" ON "IdentitySighting"("merchantId", "scope", "orderId");
