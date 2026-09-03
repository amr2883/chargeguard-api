-- DropIndex
DROP INDEX "DisputeOutcome_disputeId_key";

-- CreateIndex
CREATE UNIQUE INDEX "DisputeOutcome_merchantId_disputeId_key" ON "DisputeOutcome"("merchantId", "disputeId");

