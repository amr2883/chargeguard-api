ALTER TABLE "Order" ADD COLUMN "cardBinPrefix" TEXT;
CREATE INDEX "Order_merchantId_cardBinPrefix_createdAt_idx" ON "Order"("merchantId", "cardBinPrefix", "createdAt");
CREATE INDEX "Order_merchantId_storeId_cardBinPrefix_createdAt_idx" ON "Order"("merchantId", "storeId", "cardBinPrefix", "createdAt");
