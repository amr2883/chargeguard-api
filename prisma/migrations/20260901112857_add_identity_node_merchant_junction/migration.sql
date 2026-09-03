-- CreateTable
CREATE TABLE "IdentityNodeMerchant" (
    "nodeId" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "IdentityNodeMerchant_pkey" PRIMARY KEY ("nodeId","merchantId")
);

-- CreateIndex
CREATE INDEX "IdentityNodeMerchant_nodeId_idx" ON "IdentityNodeMerchant"("nodeId");

-- AddForeignKey
ALTER TABLE "IdentityNodeMerchant" ADD CONSTRAINT "IdentityNodeMerchant_nodeId_fkey" FOREIGN KEY ("nodeId") REFERENCES "IdentityNode"("id") ON DELETE CASCADE ON UPDATE CASCADE;
