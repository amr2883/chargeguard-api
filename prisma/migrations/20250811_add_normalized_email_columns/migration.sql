-- AlterTable: BlacklistEntry — عمود جديد nullable، بدون تأثير على @@unique الحالي
ALTER TABLE "BlacklistEntry" ADD COLUMN "normalizedValue" TEXT;

-- AlterTable: WhitelistEntry — نفس المنطق
ALTER TABLE "WhitelistEntry" ADD COLUMN "normalizedValue" TEXT;

-- AlterTable: Order — عمود جديد nullable، عمود email الخام يفضل زي ما هو
ALTER TABLE "Order" ADD COLUMN "normalizedEmail" TEXT;

-- CreateIndex: للبحث السريع في مسار الـ EMAIL condition في /evaluate و /woocommerce-webhook
CREATE INDEX "BlacklistEntry_merchantId_storeId_type_normalizedValue_idx"
  ON "BlacklistEntry"("merchantId", "storeId", "type", "normalizedValue");

CREATE INDEX "WhitelistEntry_merchantId_storeId_type_normalizedValue_idx"
  ON "WhitelistEntry"("merchantId", "storeId", "type", "normalizedValue");

-- CreateIndex: لاستعلام الـ disputes (order.normalizedEmail) في الخطوة القادمة
CREATE INDEX "Order_merchantId_normalizedEmail_createdAt_idx"
  ON "Order"("merchantId", "normalizedEmail", "createdAt");