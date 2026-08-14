// src/lib/blacklistGate.js
// Single source of truth للـ BlacklistEntry matching — يستخدمه 0b's
// early gate في /evaluate، والبوابة المضافة حديثًا في
// /woocommerce-webhook، وrecordBlockedAttempt الخاص بكل مسار على حدة
// (متروك محليًا في risk.js عمدًا — راجع تعليق القرار المعماري في نقاش
// الجلسة). استُخرج هنا تحديدًا لأن نسخة موازية من نفس المنطق —
// جوه riskScoring.js's calculateRiskScore()، بتقارن حقول email/ip/deviceId
// مش موجودة أصلاً على BlacklistEntry (الـ schema الحقيقي: type/value/
// normalizedValue) — كانت dead code صامت من الأول. نسخة واحدة بتتفحص
// ضد الـ schema الحقيقي بتمنع تكرار نفس فئة الباگ ده تاني.
//
// [Discovery 2 fix] BIN أُضيفت لـ conditions تحت — كانت غايبة بالكامل من
// هذا الملف بالرغم من إن BlacklistEntry.type يدعمها رسميًا في الـ schema
// (EMAIL/IP/DEVICE_FINGERPRINT/BIN)، والـ whitelist المقابلة في
// enrichmentProcessor.js كانت بالفعل بتفحص BIN من الأول. المستخدم
// الجديد لـ BIN هنا هو enrichmentProcessor.js — المسار الوحيد اللي
// بيوصل فيه BIN حقيقي (راجع cardBinPrefix هناك). BIN بتتفحص ضد `value`
// مباشرة (زي IP/DEVICE_FINGERPRINT) مش `normalizedValue`، بمطابقة تامة
// لنمط whitelist BIN check الموجود بالفعل في enrichmentProcessor.js.
// الـ caller مسؤول عن تطبيع الـ BIN لـ 6 أرقام قبل النداء (نفس اتفاقية
// computeNormalizedValue's BIN branch تحت).
const { normalizeEmail } = require('./utils');

// [Bug #7 fix, نُقلت من risk.js] القيمة المستخدمة في المطابقة الأمنية —
// منفصلة عن `value` اللي تفضل خام للعرض/الـ audit trail. EMAIL بتستخدم
// normalizeEmail() (homoglyph/case/plus-tag aware). IP و
// DEVICE_FINGERPRINT بس trim، من غير fuzzy matching. BIN بتفضل زي ما هي
// لأن الـ caller بيكون طبّعها لـ 6 أرقام قبل ما يستدعي الدالة.
function computeNormalizedValue(type, value) {
  if (value == null) return null;
  if (type === 'EMAIL') return normalizeEmail(value);
  if (type === 'IP' || type === 'DEVICE_FINGERPRINT') return String(value).trim();
  return String(value);
}

// findBlacklistMatch — الاستعلام فقط. بترجع الصف المطابق (أو null) بدل
// boolean، عشان الـ caller يقدر يقرا .reason و.type للـ response/logging
// (زي ما 0b بتعمل بالظبط بـ blacklistCheck).
async function findBlacklistMatch(db, { merchantId, storeScope = {}, normalizedEmail, ip, deviceFingerprint, bin }) {
  const conditions = [];
  if (normalizedEmail)   conditions.push({ type: 'EMAIL', normalizedValue: normalizedEmail });
  if (ip)                conditions.push({ type: 'IP', value: ip });
  if (deviceFingerprint) conditions.push({ type: 'DEVICE_FINGERPRINT', value: deviceFingerprint });
  if (bin)               conditions.push({ type: 'BIN', value: bin });

  if (conditions.length === 0) return null;

  return db.blacklistEntry.findFirst({
    where: {
      merchantId,
      ...storeScope,
      OR: conditions,
      AND: [{ OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }] }]
    }
  });
}

module.exports = { computeNormalizedValue, findBlacklistMatch };