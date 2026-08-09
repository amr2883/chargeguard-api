-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateTable
CREATE TABLE "Tenant" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "storeUrl" TEXT,
    "apiKey" TEXT NOT NULL,
    "webhookSecret" TEXT,
    "plan" TEXT NOT NULL DEFAULT 'early_access',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Tenant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MerchantProfile" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "totalOrders" INTEGER NOT NULL DEFAULT 0,
    "totalAmount" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "avgOrderValue" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "totalDisputes" INTEGER NOT NULL DEFAULT 0,
    "wonDisputes" INTEGER NOT NULL DEFAULT 0,
    "lostDisputes" INTEGER NOT NULL DEFAULT 0,
    "merchantWeightRatio" DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    "trustScore" DOUBLE PRECISION NOT NULL DEFAULT 0.3,
    "reportCount" INTEGER NOT NULL DEFAULT 0,
    "tenantId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "MerchantProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SignalStat" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT,
    "signalType" TEXT NOT NULL,
    "signalValue" TEXT NOT NULL,
    "rawWins" INTEGER NOT NULL DEFAULT 0,
    "rawLosses" INTEGER NOT NULL DEFAULT 0,
    "totalEvents" INTEGER NOT NULL DEFAULT 0,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    "lastDecayAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SignalStat_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Order" (
    "id" TEXT NOT NULL,
    "orderId" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "amount" DOUBLE PRECISION NOT NULL,
    "currency" TEXT NOT NULL DEFAULT 'USD',
    "email" TEXT,
    "ipAddress" TEXT,
    "customerLoginId" TEXT,
    "deviceFingerprint" TEXT,
    "fingerprintVersion" TEXT,
    "fingerprintStatus" TEXT,
    "riskScore" INTEGER,
    "riskLevel" TEXT,
    "decision" TEXT,
    "connectedRisk" INTEGER DEFAULT 0,
    "cardHash" TEXT,
    "signalsSnapshot" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Order_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskEvaluation" (
    "id" TEXT NOT NULL,
    "orderId" TEXT NOT NULL,
    "staticScore" DOUBLE PRECISION NOT NULL,
    "learningScore" DOUBLE PRECISION NOT NULL,
    "finalDecision" TEXT NOT NULL,
    "topSignals" TEXT NOT NULL DEFAULT '[]',
    "positiveSignals" TEXT NOT NULL DEFAULT '[]',
    "scoringVersion" TEXT NOT NULL,
    "outcomeStatus" TEXT NOT NULL DEFAULT 'PENDING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "fraudProb" DOUBLE PRECISION,
    "expectedLoss" DOUBLE PRECISION,
    "thresholdUsed" DOUBLE PRECISION,
    "decisionBefore" TEXT,
    "decisionAfter" TEXT,

    CONSTRAINT "RiskEvaluation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DisputeOutcome" (
    "id" TEXT NOT NULL,
    "disputeId" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "orderId" TEXT,
    "result" TEXT NOT NULL,
    "signalsPresent" TEXT NOT NULL DEFAULT '[]',
    "caseScore" INTEGER,
    "resolvedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DisputeOutcome_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FraudPattern" (
    "id" TEXT NOT NULL,
    "patternHash" TEXT NOT NULL,
    "patternDesc" TEXT,
    "signalCount" INTEGER NOT NULL DEFAULT 0,
    "weightedScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "fraudCount" INTEGER NOT NULL DEFAULT 0,
    "legitCount" INTEGER NOT NULL DEFAULT 0,
    "totalCount" INTEGER NOT NULL DEFAULT 0,
    "signals" TEXT,
    "merchantsSeen" INTEGER NOT NULL DEFAULT 0,
    "version" INTEGER NOT NULL DEFAULT 0,
    "learnedAtCount" INTEGER,
    "clusterId" TEXT,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "FraudPattern_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FraudCluster" (
    "id" TEXT NOT NULL,
    "clusterHash" TEXT NOT NULL,
    "clusterDesc" TEXT,
    "totalCount" INTEGER NOT NULL DEFAULT 0,
    "fraudCount" INTEGER NOT NULL DEFAULT 0,
    "merchantsSeen" INTEGER NOT NULL DEFAULT 0,
    "weightedFraudScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "FraudCluster_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PatternMerchant" (
    "patternHash" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PatternMerchant_pkey" PRIMARY KEY ("patternHash","merchantId")
);

-- CreateTable
CREATE TABLE "IdentityNode" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT,
    "type" TEXT NOT NULL,
    "hashedValue" TEXT NOT NULL,
    "maskedValue" TEXT,
    "fingerprintConfig" TEXT,
    "fingerprintHardware" TEXT,
    "fraudEvents" INTEGER NOT NULL DEFAULT 0,
    "successOrders" INTEGER NOT NULL DEFAULT 0,
    "chargebacks" INTEGER NOT NULL DEFAULT 0,
    "totalTransactions" INTEGER NOT NULL DEFAULT 0,
    "merchantsSeen" INTEGER NOT NULL DEFAULT 0,
    "recentMerchants" INTEGER NOT NULL DEFAULT 0,
    "flaggedAtCount" INTEGER,
    "lastHealedAt" TIMESTAMP(3),
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IdentityNode_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IdentityEdge" (
    "id" TEXT NOT NULL,
    "fromId" TEXT NOT NULL,
    "toId" TEXT NOT NULL,
    "relation" TEXT NOT NULL,
    "seenCount" INTEGER NOT NULL DEFAULT 1,
    "uniqueOrders" INTEGER NOT NULL DEFAULT 1,
    "orderId" TEXT,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "IdentityEdge_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IdentityEvent" (
    "id" TEXT NOT NULL,
    "nodeId" TEXT NOT NULL,
    "merchantId" TEXT,
    "type" TEXT NOT NULL,
    "eventCategory" TEXT NOT NULL,
    "weight" DOUBLE PRECISION NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IdentityEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ComputedIdentityRisk" (
    "nodeId" TEXT NOT NULL,
    "algorithmVersion" INTEGER NOT NULL,
    "riskScore" DOUBLE PRECISION NOT NULL,
    "alertLevel" TEXT,
    "fraudWeight" DOUBLE PRECISION NOT NULL,
    "cleanWeight" DOUBLE PRECISION NOT NULL,
    "eventCount" INTEGER NOT NULL,
    "computedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ComputedIdentityRisk_pkey" PRIMARY KEY ("nodeId","algorithmVersion")
);

-- CreateTable
CREATE TABLE "BinRecord" (
    "bin" TEXT NOT NULL,
    "brand" TEXT,
    "cardType" TEXT,
    "issuerName" TEXT,
    "issuerCountry" TEXT,
    "isPrepaid" BOOLEAN NOT NULL DEFAULT false,
    "isCommercial" BOOLEAN NOT NULL DEFAULT false,
    "source" TEXT NOT NULL,
    "hitCount" INTEGER NOT NULL DEFAULT 1,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BinRecord_pkey" PRIMARY KEY ("bin")
);

-- CreateTable
CREATE TABLE "CardTestAttempt" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "binPrefix" TEXT,
    "ipHash" TEXT,
    "emailHash" TEXT,
    "deviceHash" TEXT,
    "amount" DOUBLE PRECISION NOT NULL,
    "wasBlocked" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CardTestAttempt_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CardHash" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "cardHash" TEXT NOT NULL,
    "last4" TEXT NOT NULL,
    "expMonth" INTEGER NOT NULL,
    "expYear" INTEGER NOT NULL,
    "brand" TEXT NOT NULL,
    "attemptCount" INTEGER NOT NULL DEFAULT 1,
    "blockCount" INTEGER NOT NULL DEFAULT 0,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CardHash_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PendingEnrichment" (
    "id" TEXT NOT NULL,
    "orderId" TEXT NOT NULL,
    "paymentIntentId" TEXT,
    "enrichData" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "processedAt" TIMESTAMP(3),

    CONSTRAINT "PendingEnrichment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlacklistEntry" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "reason" TEXT,
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" TEXT,

    CONSTRAINT "BlacklistEntry_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_email_key" ON "Tenant"("email");

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_apiKey_key" ON "Tenant"("apiKey");

-- CreateIndex
CREATE UNIQUE INDEX "MerchantProfile_merchantId_key" ON "MerchantProfile"("merchantId");

-- CreateIndex
CREATE INDEX "SignalStat_merchantId_idx" ON "SignalStat"("merchantId");

-- CreateIndex
CREATE UNIQUE INDEX "SignalStat_merchantId_signalType_signalValue_key" ON "SignalStat"("merchantId", "signalType", "signalValue");

-- CreateIndex
CREATE UNIQUE INDEX "Order_orderId_key" ON "Order"("orderId");

-- CreateIndex
CREATE UNIQUE INDEX "RiskEvaluation_orderId_key" ON "RiskEvaluation"("orderId");

-- CreateIndex
CREATE UNIQUE INDEX "DisputeOutcome_disputeId_key" ON "DisputeOutcome"("disputeId");

-- CreateIndex
CREATE UNIQUE INDEX "FraudPattern_patternHash_key" ON "FraudPattern"("patternHash");

-- CreateIndex
CREATE INDEX "FraudPattern_patternHash_idx" ON "FraudPattern"("patternHash");

-- CreateIndex
CREATE INDEX "FraudPattern_clusterId_idx" ON "FraudPattern"("clusterId");

-- CreateIndex
CREATE INDEX "FraudPattern_lastSeen_idx" ON "FraudPattern"("lastSeen");

-- CreateIndex
CREATE INDEX "FraudPattern_fraudCount_idx" ON "FraudPattern"("fraudCount");

-- CreateIndex
CREATE UNIQUE INDEX "FraudCluster_clusterHash_key" ON "FraudCluster"("clusterHash");

-- CreateIndex
CREATE INDEX "FraudCluster_clusterHash_idx" ON "FraudCluster"("clusterHash");

-- CreateIndex
CREATE INDEX "FraudCluster_fraudCount_idx" ON "FraudCluster"("fraudCount");

-- CreateIndex
CREATE INDEX "PatternMerchant_patternHash_idx" ON "PatternMerchant"("patternHash");

-- CreateIndex
CREATE INDEX "IdentityNode_merchantId_type_lastSeen_idx" ON "IdentityNode"("merchantId", "type", "lastSeen");

-- CreateIndex
CREATE INDEX "IdentityNode_hashedValue_idx" ON "IdentityNode"("hashedValue");

-- CreateIndex
CREATE UNIQUE INDEX "IdentityNode_merchantId_type_hashedValue_key" ON "IdentityNode"("merchantId", "type", "hashedValue");

-- CreateIndex
CREATE INDEX "IdentityEdge_fromId_idx" ON "IdentityEdge"("fromId");

-- CreateIndex
CREATE INDEX "IdentityEdge_toId_idx" ON "IdentityEdge"("toId");

-- CreateIndex
CREATE UNIQUE INDEX "IdentityEdge_fromId_toId_relation_key" ON "IdentityEdge"("fromId", "toId", "relation");

-- CreateIndex
CREATE INDEX "IdentityEvent_nodeId_createdAt_idx" ON "IdentityEvent"("nodeId", "createdAt");

-- CreateIndex
CREATE INDEX "CardTestAttempt_merchantId_createdAt_idx" ON "CardTestAttempt"("merchantId", "createdAt");

-- CreateIndex
CREATE INDEX "CardTestAttempt_deviceHash_createdAt_idx" ON "CardTestAttempt"("deviceHash", "createdAt");

-- CreateIndex
CREATE INDEX "CardTestAttempt_ipHash_createdAt_idx" ON "CardTestAttempt"("ipHash", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "CardHash_cardHash_key" ON "CardHash"("cardHash");

-- CreateIndex
CREATE INDEX "CardHash_merchantId_cardHash_idx" ON "CardHash"("merchantId", "cardHash");

-- CreateIndex
CREATE INDEX "CardHash_lastSeenAt_idx" ON "CardHash"("lastSeenAt");

-- CreateIndex
CREATE INDEX "PendingEnrichment_orderId_idx" ON "PendingEnrichment"("orderId");

-- CreateIndex
CREATE INDEX "PendingEnrichment_status_idx" ON "PendingEnrichment"("status");

-- CreateIndex
CREATE INDEX "BlacklistEntry_merchantId_type_expiresAt_idx" ON "BlacklistEntry"("merchantId", "type", "expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "BlacklistEntry_merchantId_type_value_key" ON "BlacklistEntry"("merchantId", "type", "value");

-- AddForeignKey
ALTER TABLE "MerchantProfile" ADD CONSTRAINT "MerchantProfile_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RiskEvaluation" ADD CONSTRAINT "RiskEvaluation_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "Order"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DisputeOutcome" ADD CONSTRAINT "DisputeOutcome_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "Order"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FraudPattern" ADD CONSTRAINT "FraudPattern_clusterId_fkey" FOREIGN KEY ("clusterId") REFERENCES "FraudCluster"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IdentityEdge" ADD CONSTRAINT "IdentityEdge_fromId_fkey" FOREIGN KEY ("fromId") REFERENCES "IdentityNode"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IdentityEdge" ADD CONSTRAINT "IdentityEdge_toId_fkey" FOREIGN KEY ("toId") REFERENCES "IdentityNode"("id") ON DELETE CASCADE ON UPDATE CASCADE;

