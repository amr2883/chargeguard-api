-- CreateTable
CREATE TABLE "AdminAction" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT,
    "action" TEXT NOT NULL,
    "note" TEXT,
    "success" BOOLEAN NOT NULL,
    "resultCode" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "adminUserId" TEXT,

    CONSTRAINT "AdminAction_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AdminUser" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'readonly',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" TIMESTAMP(3),

    CONSTRAINT "AdminUser_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AlertLog" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "storeId" TEXT,
    "alertType" TEXT NOT NULL DEFAULT 'attack_detected',
    "attackCount" INTEGER NOT NULL,
    "savedAmount" DOUBLE PRECISION NOT NULL,
    "sentAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AlertLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BinRecord" (
    "bin" TEXT NOT NULL,
    "brand" TEXT,
    "cardType" TEXT,
    "cardCategory" TEXT,
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
CREATE TABLE "BinSequenceAlert" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "storeId" TEXT,
    "binPrefix" TEXT NOT NULL,
    "layer" INTEGER NOT NULL,
    "reason" TEXT NOT NULL,
    "cardsCount" INTEGER NOT NULL,
    "entitiesCount" INTEGER NOT NULL,
    "riskAddition" INTEGER NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "notifiedAt" TIMESTAMP(3),
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolvedAt" TIMESTAMP(3),

    CONSTRAINT "BinSequenceAlert_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlacklistEntry" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "storeId" TEXT,
    "type" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "normalizedValue" TEXT,
    "reason" TEXT,
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" TEXT,

    CONSTRAINT "BlacklistEntry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlockedAttempt" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "storeId" TEXT,
    "blockedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "cardBin" TEXT,
    "cardType" TEXT,
    "reason" TEXT NOT NULL,
    "ipHash" TEXT,
    "amountAttempted" DOUBLE PRECISION,
    "riskScore" INTEGER,

    CONSTRAINT "BlockedAttempt_pkey" PRIMARY KEY ("id")
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
CREATE TABLE "CardTestAttempt" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "storeId" TEXT,
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
CREATE TABLE "CheckoutSession" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "planId" TEXT NOT NULL,
    "amount" DOUBLE PRECISION NOT NULL,
    "billingCycle" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CheckoutSession_pkey" PRIMARY KEY ("id")
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
CREATE TABLE "ConnectAttempt" (
    "id" SERIAL NOT NULL,
    "ipHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ConnectAttempt_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DisputeEvidence" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "orderId" TEXT NOT NULL,
    "evidenceType" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    "metadata" JSONB,
    "submittedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "submittedBy" TEXT,

    CONSTRAINT "DisputeEvidence_pkey" PRIMARY KEY ("id")
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
CREATE TABLE "EmergencyPause" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "activatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "activatedById" TEXT,
    "deactivatedAt" TIMESTAMP(3),
    "deactivatedReason" TEXT,

    CONSTRAINT "EmergencyPause_pkey" PRIMARY KEY ("id")
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
CREATE TABLE "MonthlyReport" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "storeId" TEXT,
    "reportMonth" INTEGER NOT NULL,
    "reportYear" INTEGER NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'generating',
    "totalAttacks" INTEGER,
    "totalProtected" DOUBLE PRECISION,
    "totalFeesSaved" DOUBLE PRECISION,
    "securityScore" INTEGER,
    "coreLayersActive" INTEGER,
    "advancedLayersAvailable" INTEGER,
    "topCountry" TEXT,
    "topReason" TEXT,
    "prevMonthAttacks" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "MonthlyReport_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Order" (
    "id" TEXT NOT NULL,
    "orderId" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "storeId" TEXT,
    "amount" DOUBLE PRECISION NOT NULL,
    "currency" TEXT NOT NULL DEFAULT 'USD',
    "email" TEXT,
    "normalizedEmail" TEXT,
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
    "cardBinPrefix" TEXT,
    "signalsSnapshot" TEXT,
    "enrichmentSource" TEXT,
    "feedbackProcessedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Order_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PatternMerchant" (
    "patternHash" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PatternMerchant_pkey" PRIMARY KEY ("patternHash","merchantId")
);

-- CreateTable
CREATE TABLE "Payment" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "checkoutSessionId" TEXT NOT NULL,
    "captureId" TEXT NOT NULL,
    "amount" DOUBLE PRECISION NOT NULL,
    "expectedAmount" DOUBLE PRECISION NOT NULL,
    "planId" TEXT NOT NULL,
    "billingCycle" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'completed',
    "paypalOrderId" TEXT,
    "paypalPayerId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Payment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PendingEnrichment" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT,
    "orderId" TEXT NOT NULL,
    "paymentIntentId" TEXT,
    "enrichData" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "processedAt" TIMESTAMP(3),

    CONSTRAINT "PendingEnrichment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PluginRelease" (
    "id" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "channel" TEXT NOT NULL DEFAULT 'stable',
    "s3Key" TEXT NOT NULL,
    "checksumSha256" TEXT NOT NULL,
    "changelog" TEXT,
    "minWpVersion" TEXT,
    "testedWpVersion" TEXT,
    "minPhpVersion" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PluginRelease_pkey" PRIMARY KEY ("id")
);

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

-- CreateTable
CREATE TABLE "RegistrationAttempt" (
    "id" SERIAL NOT NULL,
    "ipHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RegistrationAttempt_pkey" PRIMARY KEY ("id")
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
CREATE TABLE "SignalStat" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT,
    "signalType" TEXT NOT NULL,
    "signalValue" TEXT NOT NULL,
    "rawWins" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "rawLosses" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "totalEvents" INTEGER NOT NULL DEFAULT 0,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    "lastDecayAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SignalStat_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Store" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "storeUrl" TEXT NOT NULL,
    "normalizedDomain" TEXT NOT NULL,
    "label" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "deactivatedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "lastActivityAt" TIMESTAMP(3),

    CONSTRAINT "Store_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Tenant" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "apiKey" TEXT,
    "apiKeyHash" TEXT,
    "storeUrl" TEXT,
    "allowedDomains" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "webhookSecret" TEXT,
    "plan" TEXT NOT NULL DEFAULT 'early_access',
    "fraudIsolationMode" TEXT NOT NULL DEFAULT 'pooled',
    "subscriptionStatus" TEXT NOT NULL DEFAULT 'free',
    "subscriptionEndDate" TIMESTAMP(3),
    "billingCycle" TEXT,
    "lastPaymentDate" TIMESTAMP(3),
    "lastPaymentAmount" DOUBLE PRECISION,
    "lastCaptureId" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "monthlyBlockedCount" INTEGER NOT NULL DEFAULT 0,
    "quotaResetDate" TIMESTAMP(3),
    "emailVerified" BOOLEAN NOT NULL DEFAULT false,
    "emailVerifyToken" TEXT,
    "emailVerifyExpiresAt" TIMESTAMP(3),
    "keyRotatedAt" TIMESTAMP(3),
    "connectToken" TEXT,
    "connectTokenExpiresAt" TIMESTAMP(3),
    "connectRequestId" TEXT,
    "lastConnectVerifiedAt" TIMESTAMP(3),
    "pendingStoreUrl" TEXT,
    "pendingNormalizedDomain" TEXT,
    "previousApiKey" TEXT,
    "previousApiKeyHash" TEXT,
    "previousApiKeyExpiresAt" TIMESTAMP(3),
    "remoteConfigKey" TEXT,
    "lastAlertSentAt" TIMESTAMP(3),
    "lastPaypalAlertAt" TIMESTAMP(3),
    "lastRenewalReminderSentAt" TIMESTAMP(3),
    "lastGracePeriodNoticeSentAt" TIMESTAMP(3),
    "lastDowngradeNoticeSentAt" TIMESTAMP(3),
    "lastQuotaExceededNoticeSentAt" TIMESTAMP(3),
    "countryOverrides" JSONB DEFAULT '{}',
    "countryOverridesUpdatedAt" TIMESTAMP(3),
    "webhookUrl" TEXT,
    "webhookType" TEXT,
    "webhookResolvedIp" TEXT,
    "webhookLastStatus" TEXT,
    "webhookLastSentAt" TIMESTAMP(3),
    "webhookFailureCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Tenant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UpdateDownloadToken" (
    "jti" TEXT NOT NULL,
    "releaseId" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),

    CONSTRAINT "UpdateDownloadToken_pkey" PRIMARY KEY ("jti")
);

-- CreateTable
CREATE TABLE "WhitelistEntry" (
    "id" TEXT NOT NULL,
    "merchantId" TEXT NOT NULL,
    "storeId" TEXT,
    "type" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "normalizedValue" TEXT,
    "reason" TEXT,
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" TEXT,

    CONSTRAINT "WhitelistEntry_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AdminAction_action_createdAt_idx" ON "AdminAction"("action" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "AdminAction_adminUserId_createdAt_idx" ON "AdminAction"("adminUserId" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "AdminAction_tenantId_createdAt_idx" ON "AdminAction"("tenantId" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "AdminUser_isActive_idx" ON "AdminUser"("isActive" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "AdminUser_keyHash_key" ON "AdminUser"("keyHash" ASC);

-- CreateIndex
CREATE INDEX "AlertLog_storeId_sentAt_idx" ON "AlertLog"("storeId" ASC, "sentAt" ASC);

-- CreateIndex
CREATE INDEX "AlertLog_tenantId_sentAt_idx" ON "AlertLog"("tenantId" ASC, "sentAt" ASC);

-- CreateIndex
CREATE INDEX "BinSequenceAlert_storeId_detectedAt_idx" ON "BinSequenceAlert"("storeId" ASC, "detectedAt" ASC);

-- CreateIndex
CREATE INDEX "BinSequenceAlert_tenantId_detectedAt_idx" ON "BinSequenceAlert"("tenantId" ASC, "detectedAt" ASC);

-- CreateIndex
CREATE INDEX "BinSequenceAlert_tenantId_status_detectedAt_idx" ON "BinSequenceAlert"("tenantId" ASC, "status" ASC, "detectedAt" ASC);

-- CreateIndex
CREATE INDEX "BlacklistEntry_merchantId_storeId_type_expiresAt_idx" ON "BlacklistEntry"("merchantId" ASC, "storeId" ASC, "type" ASC, "expiresAt" ASC);

-- CreateIndex
CREATE INDEX "BlacklistEntry_merchantId_storeId_type_normalizedValue_idx" ON "BlacklistEntry"("merchantId" ASC, "storeId" ASC, "type" ASC, "normalizedValue" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "BlacklistEntry_merchantId_storeId_type_value_key" ON "BlacklistEntry"("merchantId" ASC, "storeId" ASC, "type" ASC, "value" ASC);

-- CreateIndex
CREATE INDEX "BlacklistEntry_merchantId_type_expiresAt_idx" ON "BlacklistEntry"("merchantId" ASC, "type" ASC, "expiresAt" ASC);

-- CreateIndex
CREATE INDEX "BlockedAttempt_storeId_blockedAt_idx" ON "BlockedAttempt"("storeId" ASC, "blockedAt" ASC);

-- CreateIndex
CREATE INDEX "BlockedAttempt_tenantId_blockedAt_idx" ON "BlockedAttempt"("tenantId" ASC, "blockedAt" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "CardHash_cardHash_key" ON "CardHash"("cardHash" ASC);

-- CreateIndex
CREATE INDEX "CardHash_lastSeenAt_idx" ON "CardHash"("lastSeenAt" ASC);

-- CreateIndex
CREATE INDEX "CardHash_merchantId_cardHash_idx" ON "CardHash"("merchantId" ASC, "cardHash" ASC);

-- CreateIndex
CREATE INDEX "CardTestAttempt_deviceHash_createdAt_idx" ON "CardTestAttempt"("deviceHash" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "CardTestAttempt_ipHash_createdAt_idx" ON "CardTestAttempt"("ipHash" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "CardTestAttempt_merchantId_createdAt_idx" ON "CardTestAttempt"("merchantId" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "CardTestAttempt_merchantId_storeId_createdAt_idx" ON "CardTestAttempt"("merchantId" ASC, "storeId" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "CheckoutSession_expiresAt_idx" ON "CheckoutSession"("expiresAt" ASC);

-- CreateIndex
CREATE INDEX "CheckoutSession_tenantId_status_idx" ON "CheckoutSession"("tenantId" ASC, "status" ASC);

-- CreateIndex
CREATE INDEX "ConnectAttempt_ipHash_createdAt_idx" ON "ConnectAttempt"("ipHash" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "DisputeEvidence_merchantId_orderId_idx" ON "DisputeEvidence"("merchantId" ASC, "orderId" ASC);

-- CreateIndex
CREATE INDEX "DisputeEvidence_orderId_evidenceType_idx" ON "DisputeEvidence"("orderId" ASC, "evidenceType" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "DisputeEvidence_orderId_evidenceType_key" ON "DisputeEvidence"("orderId" ASC, "evidenceType" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "DisputeOutcome_disputeId_key" ON "DisputeOutcome"("disputeId" ASC);

-- CreateIndex
CREATE INDEX "EmergencyPause_isActive_expiresAt_idx" ON "EmergencyPause"("isActive" ASC, "expiresAt" ASC);

-- CreateIndex
CREATE INDEX "EmergencyPause_tenantId_isActive_idx" ON "EmergencyPause"("tenantId" ASC, "isActive" ASC);

-- CreateIndex
CREATE INDEX "FraudCluster_clusterHash_idx" ON "FraudCluster"("clusterHash" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "FraudCluster_clusterHash_key" ON "FraudCluster"("clusterHash" ASC);

-- CreateIndex
CREATE INDEX "FraudCluster_fraudCount_idx" ON "FraudCluster"("fraudCount" ASC);

-- CreateIndex
CREATE INDEX "FraudPattern_clusterId_idx" ON "FraudPattern"("clusterId" ASC);

-- CreateIndex
CREATE INDEX "FraudPattern_fraudCount_idx" ON "FraudPattern"("fraudCount" ASC);

-- CreateIndex
CREATE INDEX "FraudPattern_lastSeen_idx" ON "FraudPattern"("lastSeen" ASC);

-- CreateIndex
CREATE INDEX "FraudPattern_patternHash_idx" ON "FraudPattern"("patternHash" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "FraudPattern_patternHash_key" ON "FraudPattern"("patternHash" ASC);

-- CreateIndex
CREATE INDEX "IdentityEdge_fromId_idx" ON "IdentityEdge"("fromId" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "IdentityEdge_fromId_toId_relation_key" ON "IdentityEdge"("fromId" ASC, "toId" ASC, "relation" ASC);

-- CreateIndex
CREATE INDEX "IdentityEdge_toId_idx" ON "IdentityEdge"("toId" ASC);

-- CreateIndex
CREATE INDEX "IdentityEvent_nodeId_createdAt_idx" ON "IdentityEvent"("nodeId" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "IdentityNode_hashedValue_idx" ON "IdentityNode"("hashedValue" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "IdentityNode_merchantId_type_hashedValue_key" ON "IdentityNode"("merchantId" ASC, "type" ASC, "hashedValue" ASC);

-- CreateIndex
CREATE INDEX "IdentityNode_merchantId_type_lastSeen_idx" ON "IdentityNode"("merchantId" ASC, "type" ASC, "lastSeen" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "MerchantProfile_merchantId_key" ON "MerchantProfile"("merchantId" ASC);

-- CreateIndex
CREATE INDEX "MonthlyReport_storeId_reportYear_reportMonth_idx" ON "MonthlyReport"("storeId" ASC, "reportYear" ASC, "reportMonth" ASC);

-- CreateIndex
CREATE INDEX "MonthlyReport_tenantId_reportYear_reportMonth_idx" ON "MonthlyReport"("tenantId" ASC, "reportYear" ASC, "reportMonth" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "MonthlyReport_tenantId_storeId_reportMonth_reportYear_key" ON "MonthlyReport"("tenantId" ASC, "storeId" ASC, "reportMonth" ASC, "reportYear" ASC);

-- CreateIndex
CREATE INDEX "Order_merchantId_cardBinPrefix_createdAt_idx" ON "Order"("merchantId" ASC, "cardBinPrefix" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "Order_merchantId_createdAt_idx" ON "Order"("merchantId" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "Order_merchantId_deviceFingerprint_createdAt_idx" ON "Order"("merchantId" ASC, "deviceFingerprint" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "Order_merchantId_email_createdAt_idx" ON "Order"("merchantId" ASC, "email" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "Order_merchantId_enrichmentSource_createdAt_idx" ON "Order"("merchantId" ASC, "enrichmentSource" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "Order_merchantId_ipAddress_createdAt_idx" ON "Order"("merchantId" ASC, "ipAddress" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "Order_merchantId_normalizedEmail_createdAt_idx" ON "Order"("merchantId" ASC, "normalizedEmail" ASC, "createdAt" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Order_merchantId_orderId_key" ON "Order"("merchantId" ASC, "orderId" ASC);

-- CreateIndex
CREATE INDEX "Order_merchantId_storeId_cardBinPrefix_createdAt_idx" ON "Order"("merchantId" ASC, "storeId" ASC, "cardBinPrefix" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "Order_merchantId_storeId_createdAt_idx" ON "Order"("merchantId" ASC, "storeId" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "Order_merchantId_storeId_deviceFingerprint_createdAt_idx" ON "Order"("merchantId" ASC, "storeId" ASC, "deviceFingerprint" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "Order_merchantId_storeId_email_createdAt_idx" ON "Order"("merchantId" ASC, "storeId" ASC, "email" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "Order_merchantId_storeId_ipAddress_createdAt_idx" ON "Order"("merchantId" ASC, "storeId" ASC, "ipAddress" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "PatternMerchant_patternHash_idx" ON "PatternMerchant"("patternHash" ASC);

-- CreateIndex
CREATE INDEX "Payment_captureId_idx" ON "Payment"("captureId" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Payment_captureId_key" ON "Payment"("captureId" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Payment_checkoutSessionId_key" ON "Payment"("checkoutSessionId" ASC);

-- CreateIndex
CREATE INDEX "Payment_tenantId_createdAt_idx" ON "Payment"("tenantId" ASC, "createdAt" ASC);

-- CreateIndex
CREATE INDEX "PendingEnrichment_merchantId_orderId_status_idx" ON "PendingEnrichment"("merchantId" ASC, "orderId" ASC, "status" ASC);

-- CreateIndex
CREATE INDEX "PendingEnrichment_orderId_idx" ON "PendingEnrichment"("orderId" ASC);

-- CreateIndex
CREATE INDEX "PendingEnrichment_status_idx" ON "PendingEnrichment"("status" ASC);

-- CreateIndex
CREATE INDEX "PluginRelease_channel_isActive_createdAt_idx" ON "PluginRelease"("channel" ASC, "isActive" ASC, "createdAt" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "PluginRelease_version_channel_key" ON "PluginRelease"("version" ASC, "channel" ASC);

-- CreateIndex
CREATE INDEX "ProtectionEvent_tenantId_startedAt_idx" ON "ProtectionEvent"("tenantId" ASC, "startedAt" ASC);

-- CreateIndex
CREATE INDEX "ProtectionEvent_tenantId_type_startedAt_idx" ON "ProtectionEvent"("tenantId" ASC, "type" ASC, "startedAt" ASC);

-- CreateIndex
CREATE INDEX "RegistrationAttempt_ipHash_createdAt_idx" ON "RegistrationAttempt"("ipHash" ASC, "createdAt" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "RiskEvaluation_orderId_key" ON "RiskEvaluation"("orderId" ASC);

-- CreateIndex
CREATE INDEX "SignalStat_merchantId_idx" ON "SignalStat"("merchantId" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "SignalStat_merchantId_signalType_signalValue_key" ON "SignalStat"("merchantId" ASC, "signalType" ASC, "signalValue" ASC);

-- CreateIndex
CREATE INDEX "Store_normalizedDomain_idx" ON "Store"("normalizedDomain" ASC);

-- CreateIndex
CREATE INDEX "Store_tenantId_isActive_idx" ON "Store"("tenantId" ASC, "isActive" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Store_tenantId_normalizedDomain_key" ON "Store"("tenantId" ASC, "normalizedDomain" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_apiKeyHash_key" ON "Tenant"("apiKeyHash" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_apiKey_key" ON "Tenant"("apiKey" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_connectRequestId_key" ON "Tenant"("connectRequestId" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_connectToken_key" ON "Tenant"("connectToken" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_emailVerifyToken_key" ON "Tenant"("emailVerifyToken" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_email_key" ON "Tenant"("email" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_lastCaptureId_key" ON "Tenant"("lastCaptureId" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_previousApiKeyHash_key" ON "Tenant"("previousApiKeyHash" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_previousApiKey_key" ON "Tenant"("previousApiKey" ASC);

-- CreateIndex
CREATE INDEX "UpdateDownloadToken_expiresAt_idx" ON "UpdateDownloadToken"("expiresAt" ASC);

-- CreateIndex
CREATE INDEX "WhitelistEntry_merchantId_storeId_type_expiresAt_idx" ON "WhitelistEntry"("merchantId" ASC, "storeId" ASC, "type" ASC, "expiresAt" ASC);

-- CreateIndex
CREATE INDEX "WhitelistEntry_merchantId_storeId_type_normalizedValue_idx" ON "WhitelistEntry"("merchantId" ASC, "storeId" ASC, "type" ASC, "normalizedValue" ASC);

-- CreateIndex
CREATE UNIQUE INDEX "WhitelistEntry_merchantId_storeId_type_value_key" ON "WhitelistEntry"("merchantId" ASC, "storeId" ASC, "type" ASC, "value" ASC);

-- CreateIndex
CREATE INDEX "WhitelistEntry_merchantId_type_expiresAt_idx" ON "WhitelistEntry"("merchantId" ASC, "type" ASC, "expiresAt" ASC);

-- AddForeignKey
ALTER TABLE "AdminAction" ADD CONSTRAINT "AdminAction_adminUserId_fkey" FOREIGN KEY ("adminUserId") REFERENCES "AdminUser"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AdminAction" ADD CONSTRAINT "AdminAction_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AlertLog" ADD CONSTRAINT "AlertLog_storeId_fkey" FOREIGN KEY ("storeId") REFERENCES "Store"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AlertLog" ADD CONSTRAINT "AlertLog_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinSequenceAlert" ADD CONSTRAINT "BinSequenceAlert_storeId_fkey" FOREIGN KEY ("storeId") REFERENCES "Store"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BinSequenceAlert" ADD CONSTRAINT "BinSequenceAlert_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BlockedAttempt" ADD CONSTRAINT "BlockedAttempt_storeId_fkey" FOREIGN KEY ("storeId") REFERENCES "Store"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BlockedAttempt" ADD CONSTRAINT "BlockedAttempt_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CheckoutSession" ADD CONSTRAINT "CheckoutSession_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DisputeEvidence" ADD CONSTRAINT "DisputeEvidence_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "Order"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DisputeOutcome" ADD CONSTRAINT "DisputeOutcome_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "Order"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EmergencyPause" ADD CONSTRAINT "EmergencyPause_activatedById_fkey" FOREIGN KEY ("activatedById") REFERENCES "AdminUser"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FraudPattern" ADD CONSTRAINT "FraudPattern_clusterId_fkey" FOREIGN KEY ("clusterId") REFERENCES "FraudCluster"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IdentityEdge" ADD CONSTRAINT "IdentityEdge_fromId_fkey" FOREIGN KEY ("fromId") REFERENCES "IdentityNode"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IdentityEdge" ADD CONSTRAINT "IdentityEdge_toId_fkey" FOREIGN KEY ("toId") REFERENCES "IdentityNode"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MerchantProfile" ADD CONSTRAINT "MerchantProfile_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MonthlyReport" ADD CONSTRAINT "MonthlyReport_storeId_fkey" FOREIGN KEY ("storeId") REFERENCES "Store"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MonthlyReport" ADD CONSTRAINT "MonthlyReport_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Payment" ADD CONSTRAINT "Payment_checkoutSessionId_fkey" FOREIGN KEY ("checkoutSessionId") REFERENCES "CheckoutSession"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Payment" ADD CONSTRAINT "Payment_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProtectionEvent" ADD CONSTRAINT "ProtectionEvent_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RiskEvaluation" ADD CONSTRAINT "RiskEvaluation_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "Order"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Store" ADD CONSTRAINT "Store_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
