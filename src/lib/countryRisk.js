// ─── ChargeGuard Country Risk Intelligence ───────────────────────────────
// Tiered country risk بدل الـ binary HIGH_RISK Set
//
// ليه منفصل عن binIntelligence.js؟
// 1. Separation of concerns — BIN module مسؤول عن data fetch بس
// 2. Reusable — IP intelligence وغيره ممكن يستخدمه
// 3. Extensible — تقدر تضيف merchant overrides من DB بدون تعديل BIN module
//
// الـ tiers مبنية على:
// - Historical fraud rates من Cybersource/Stripe published data
// - Card network chargeback reports
// - Manual review بيتعمل quarterly

// ─── Risk Tiers ───────────────────────────────────────────────────────────
// كل tier عنده:
//   countries   — Set للـ O(1) lookup
//   basePenalty — الـ penalty الأساسية قبل الـ amount scaling
//   severity    — للـ flag في الـ UI
//   label       — نص واضح للـ merchant

const COUNTRY_RISK_TIERS = {
  critical: {
    countries:   new Set(['NG', 'CM', 'GH']),
    basePenalty: 15,
    severity:    'high',
    label:       'critical-risk region',
  },
  high: {
    countries:   new Set(['PK', 'BD']),
    basePenalty: 10,
    severity:    'high',
    label:       'high-risk region',
  },
  medium: {
    countries:   new Set(['VN', 'ID', 'PH']),
    basePenalty: 6,
    severity:    'medium',
    label:       'elevated-risk region',
  },
  elevated: {
    countries:   new Set(['RO', 'UA']),
    basePenalty: 3,
    severity:    'medium',
    label:       'monitored region',
  },
};

// ─── Main Lookup ──────────────────────────────────────────────────────────
// بيرجع { tier, basePenalty, severity, label } أو null لو مفيش risk
// countryCode: ISO 3166-1 alpha-2 (مثال: 'NG', 'US')
function getCountryRiskTier(countryCode) {
  if (!countryCode) return null;
  const code = countryCode.toUpperCase();
  for (const [tier, config] of Object.entries(COUNTRY_RISK_TIERS)) {
    if (config.countries.has(code)) {
      return {
        tier,
        basePenalty: config.basePenalty,
        severity:    config.severity,
        label:       config.label,
      };
    }
  }
  return null;
}

// ─── Penalty Calculator ───────────────────────────────────────────────────
// بيحسب الـ penalty الفعلية بناءً على:
//   countryCode    — ISO alpha-2
//   amount         — قيمة الأوردر
//   merchantConfig — merchant overrides من الـ DB (optional)
//
// merchantConfig shape:
//   { countryOverrides: { 'PH': 'allow', 'NG': 'escalate' } }
//
// بيرجع { penalty, flag } أو null لو مفيش risk أو اتـsuppress
function calculateCountryRiskPenalty(countryCode, amount, merchantConfig = null) {
  const riskTier = getCountryRiskTier(countryCode);
  if (!riskTier) return null;

  // ─── Merchant Override ────────────────────────────────────────────────
  // 'allow'     — suppress الـ penalty كاملاً (مثال: merchant سوقه الأساسي PH)
  // 'escalate'  — ضاعف الـ penalty (مثال: merchant شايف NG high risk جداً)
  // مفيش override — استخدم الـ default tier penalty
  const override = merchantConfig?.countryOverrides?.[countryCode?.toUpperCase()];
  if (override === 'allow') return null; // suppressed

  // ─── Amount Scaling ───────────────────────────────────────────────────
  // أوردر فوق $100 → full penalty
  // أوردر تحت $100 → نص الـ penalty
  // منطق: risk بيتضخم مع قيمة الأوردر
  const scaledPenalty = amount > 100
    ? riskTier.basePenalty
    : Math.floor(riskTier.basePenalty / 2);

  const finalPenalty = override === 'escalate'
    ? Math.min(scaledPenalty * 2, 20) // escalate مع cap عشان مش نبالغ
    : scaledPenalty;

  return {
    penalty:  finalPenalty,
    flag: {
      severity: riskTier.severity,
      text:     `Card issued in ${riskTier.label} (${countryCode.toUpperCase()})`,
    },
  };
}
module.exports = { getCountryRiskTier, calculateCountryRiskPenalty };