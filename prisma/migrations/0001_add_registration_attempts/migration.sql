-- CreateTable
CREATE TABLE "RegistrationAttempt" (
    "id"        SERIAL PRIMARY KEY,
    "ipHash"    TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateIndex
CREATE INDEX "RegistrationAttempt_ipHash_createdAt_idx" ON "RegistrationAttempt"("ipHash", "createdAt");
