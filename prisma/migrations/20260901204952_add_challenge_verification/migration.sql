-- CreateTable
CREATE TABLE "ChallengeVerification" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "deviceFingerprint" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "verified" BOOLEAN NOT NULL DEFAULT false,
    "verifiedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ChallengeVerification_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ChallengeVerification_merchantId_deviceFingerprint_email_ve_idx" ON "ChallengeVerification"("merchantId", "deviceFingerprint", "email", "verified");

-- CreateIndex
CREATE INDEX "ChallengeVerification_expiresAt_idx" ON "ChallengeVerification"("expiresAt");
