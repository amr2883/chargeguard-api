// ─── ChargeGuard Signal Weights ───────────────────────────────────────────
// Reads learned signal weights from DB and applies:
// 1. Lazy Exponential Decay
// 2. Bayesian Smoothing
// 3. Log-odds transformation
// 4. Confidence-based blending (global ↔ merchant)

const db = require('./db');

// [Global-tier NULL bug fix] لازم تطابق نفس القيمة بالحرف في
// feedbackLoop.js's GLOBAL_MERCHANT_ID — راجع التعليق هناك للتفصيل
// الكامل. القراءة هنا لازم تدوّر بنفس القيمة اللي الكتابة بتستخدمها.
const GLOBAL_MERCHANT_ID = '__global__';

// ─── Constants ────────────────────────────────────────────────────────────
const DECAY_LAMBDA = 0.003;   // ~58% weight after 180 days
const BAYESIAN_ALPHA = 5;     // prior wins  (neutral = 50%)
const BAYESIAN_BETA  = 5;     // prior losses

// ─── Survivorship Bias Note ───────────────────────────────────────────────
// الـ learning system بيتعلم بس من الـ orders اللي وصلوا لـ dispute outcome
// (won أو lost). الـ fraud اللي عدى بدون dispute مش بيأثر على الـ weights.
// النتيجة: الـ weights ممكن تكون optimized للـ disputed orders بس —
// مش للـ fraud universe الكامل.
//
// Mitigation:
// 1. MIN_EVENTS_FOR_CONFIDENCE: نحتاج minimum events قبل ما نثق في الـ weight
// 2. الـ Bayesian prior (alpha=5, beta=5) بيحمي من overfit على عينة صغيرة
// 3. الـ confidence field في SignalStat بيعكس حجم العينة — مش بس الـ win rate
//
// Long-term fix: integrate proxy labels (high-risk orders that weren't disputed)
// as weak negative signals to reduce survivorship bias gradually.
const MIN_EVENTS_FOR_CONFIDENCE = 10; // أقل من كده → نثق في الـ prior أكثر

// Log-odds scaling
// BASE = 1.0 means "neutral signal" (no learning yet)
// SCALE controls how much learning moves the weight
const logger = require('./logger');
const LOG_ODDS_BASE = 1.0;
const LOG_ODDS_SCALE = 0.4;

// [Polarity fix] MAX_EFFECTIVE_WEIGHT (سقف مطلق = 5.0) اتشالت. كانت متسقة
// بس مع نطاق ECI/AVS/CVV2 (base بين 1.0-4.0) — أي إشارة base أكبر
// (IP_TOR=30, EMAIL_DOMAIN_INVALID=30) كانت هترجع مقصوصة لـ 5.0 حتى في
// cold start (صفر بيانات تعلّم)، أي فيكس مستقبلي ليها كان هيتكسر تلقائيًا
// بمجرد ما getW() تتنادى عليها. السقف الجديد نسبي لكل إشارة على حدة —
// راجع getWeightsForMerchant() تحت لتفاصيل الحساب.
//
// أثره على ECI/AVS/CVV2 الشغالين حاليًا: صفر عمليًا — أقصى قيمة ممكنة من
// logOddsWeight() (~2.84× عند أقصى ثقة) لسه أقل بكتير من السقف الجديد
// (base × 3.0)، يعني نفس السلوك المُختبر في الإنتاج بالظبط.
const MAX_WEIGHT_MULTIPLIER = 3.0;
// Merchant weight ratio constants (same as in feedbackLoop.js)
const MIN_DISPUTES_FOR_MERCHANT = 10;
const MAX_MERCHANT_RATIO = 0.30;
function calculateMerchantRatio(profile) {
  if (!profile || profile.totalDisputes < MIN_DISPUTES_FOR_MERCHANT) return 0;
  const { wonDisputes, lostDisputes, totalDisputes } = profile;
  const resolvedDisputes = wonDisputes + (lostDisputes ?? 0);
  const effectiveTotal = resolvedDisputes > 0 ? resolvedDisputes : totalDisputes;
  const extra = totalDisputes - MIN_DISPUTES_FOR_MERCHANT;
  const baseRatio = Math.min(MAX_MERCHANT_RATIO, extra * 0.01);
  const winRate = effectiveTotal > 0 ? wonDisputes / effectiveTotal : 0.5;
  const winRateModifier = winRate >= 0.5 ? 1.0 : Math.max(0.3, winRate * 2);
  return parseFloat((baseRatio * winRateModifier).toFixed(4));
}

// ─── Static Baseline Weights ──────────────────────────────────────────────
// Used when no learned data exists yet (cold start)
// These mirror the original scoring points
const STATIC_WEIGHTS = {
  "ECI:5":                   { base: 4.0, description: "Full 3DS authentication" },
  "ECI:6":                   { base: 3.5, description: "Attempted 3DS authentication" },
  "ECI:7":                   { base: 0.0, description: "No 3DS" },
  "AVS:Y":                   { base: 2.0, description: "Full address match" },
  "AVS:A":                   { base: 0.8, description: "Address only match" },
  "AVS:Z":                   { base: 0.8, description: "ZIP only match" },
  "AVS:N":                   { base: 0.0, description: "No address match" },
  "CVV2:M":                  { base: 1.0, description: "CVV matched" },
  "CVV2:N":                  { base: 0.0, description: "CVV not matched" },
  "TRACKING:confirmed":      { base: 2.0, description: "Tracking confirmed" },
  "DELIVERY_PROOF:present":  { base: 3.0, description: "Proof of delivery" },
  "LOGIN:present":           { base: 2.0, description: "Customer login recorded" },
  "CTA:accepted":            { base: 2.0, description: "Click-to-accept recorded" },
  "PRE_CHARGE:sent":         { base: 2.0, description: "7-day pre-charge notice" },
  "USAGE_LOGS:present":      { base: 2.0, description: "Usage logs after cancellation" },
  "NO_CANCEL_REQUEST:confirmed": { base: 2.0, description: "No cancellation request" },
  "CE30:eligible":           { base: 3.0, description: "CE 3.0 eligible" },
  "REFUND:processed":        { base: 3.0, description: "Refund already processed" },

 // ===== إشارات WooCommerce (Card Testing) =====
  // [Polarity fix] polarity: 'negative' مضافة لكل الإشارات دي — بتحدد
  // getWeightsForMerchant() تستخدم logOddsPenaltyWeight() (lossRate) بدل
  // logOddsWeight() (winRate). راجع تعليق logOddsPenaltyWeight() فوق.
  // [Case-normalization fix] نفس علة IP_DATACENTER بالحرف — أهم إشارة
  // كارد تيستنج كلاسيكية بعد IP_TOR، كانت متجمّدة على الـ static base
  // للأبد رغم تراكم بيانات تعلّم حقيقية.
  "BIN_PREPAID:TRUE":          { base: 15, polarity: 'negative', description: "Prepaid card detected" },
  "BIN_COUNTRY:NG":            { base: 15, polarity: 'negative', description: "Card issued in Nigeria" },
  "BIN_COUNTRY:CM":            { base: 15, polarity: 'negative', description: "Card issued in Cameroon" },
  "BIN_COUNTRY:GH":            { base: 15, polarity: 'negative', description: "Card issued in Ghana" },
  "BIN_COUNTRY:PK":            { base: 10, polarity: 'negative', description: "Card issued in Pakistan" },
  "BIN_COUNTRY:BD":            { base: 10, polarity: 'negative', description: "Card issued in Bangladesh" },
  "BIN_COUNTRY:VN":            { base: 6,  polarity: 'negative', description: "Card issued in Vietnam" },
  "BIN_COUNTRY:ID":            { base: 6,  polarity: 'negative', description: "Card issued in Indonesia" },
  "BIN_COUNTRY:PH":            { base: 6,  polarity: 'negative', description: "Card issued in Philippines" },
  // [BIN_COUNTRY completeness fix] كانت ناقصة RO/UA (tier "elevated" في
  // countryRisk.js's COUNTRY_RISK_TIERS، basePenalty=3) — بدونهم، أي
  // إشارة BIN_COUNTRY:RO أو BIN_COUNTRY:UA كانت هترفض بصمت من whitelist
  // في feedbackLoop.js (راجع التعديل المقابل هناك)، رغم إنها مستخدمة
  // فعليًا في calculateCountryRiskPenalty().
  "BIN_COUNTRY:RO":            { base: 3,  polarity: 'negative', description: "Card issued in Romania" },
  "BIN_COUNTRY:UA":            { base: 3,  polarity: 'negative', description: "Card issued in Ukraine" },
  // [Stale-baseline fix] الأرقام دي اتصححت لتطابق القيم الحية الفعلية في
  // emailIntelligence.js's calculateEmailPenalty() (35/10) بدل الأرقام
  // القديمة (20/5) اللي كانت متروكة من غير تحديث من زمان — لو وصّلنا
  // getW() بالـ base القديمة، كان هيحصل قفزة سلوكية فورية وقت النشر حتى
  // بصفر بيانات تعلّم، عكس مبدأ "صفر أثر عند cold start".
  // [Case-normalization fix] كانت مرفوضة بصمت وقت الكتابة (نفس فئة IP_BOT).
  "EMAIL_DISPOSABLE:TRUE":     { base: 35, polarity: 'negative', description: "Disposable email address" },
  "EMAIL_FREE_PROVIDER:TRUE":  { base: 10, polarity: 'negative', description: "Free email provider, new customer, high value order" },
  // [Granularity fix] EMAIL_DOMAIN_INVALID القديمة كانت بتخلط 3 حقائق
  // مختلفة تمامًا (domain مش موجود بثقة=40، domain غير مؤكد بسبب DNS
  // timeout=5، domain موجود لكن بلا MX=25) تحت اسم واحد — وكمان الحالة
  // التالتة (no_mx) مكنتش بتتسجل كإشارة تعلّم خالص. اتقسّمت لـ 3 مفاتيح
  // منفصلة تطابق فروع calculateEmailPenalty() الفعلية بالظبط.
  // [Case-normalization fix] الثلاثة كانوا مرفوضين بصمت وقت الكتابة.
  "EMAIL_DOMAIN_NOT_FOUND:TRUE":  { base: 40, polarity: 'negative', description: "Email domain does not exist (confirmed, not a network timeout)" },
  "EMAIL_DOMAIN_UNVERIFIED:TRUE": { base: 5,  polarity: 'negative', description: "Email domain existence could not be verified (DNS timeout/network error)" },
  "EMAIL_DOMAIN_NO_MX:TRUE":      { base: 25, polarity: 'negative', description: "Email domain exists but has no MX records" },
  // [Case-normalization fix] IP_PROXY متروكة lowercase عمدًا — مفيش أي
  // نداء getW ليها في ipIntelligence.js خالص (راجع تعليق "مؤجّلة عمدًا"
  // هناك)، فمفيش live caller يتأثر — بس بتصحيحها كمان دلوقتي لمنع أي حد
  // يستخدمها مستقبلاً بافتراض غلط إنها شغالة زي IP_TOR.
  "IP_PROXY:TRUE":             { base: 20, polarity: 'negative', description: "IP is a proxy (currently unwired — see calculateIPPenalty comment)" },
  // [Case-normalization fix] كانت "true" lowercase بينما updateSignalStat()
  // بتخزّن كل صف بعد .toUpperCase() بلا شرط، وipIntelligence.js's نداء
  // getW("IP_TOR","true") (لسه lowercase — اتصحح في نفس الباتش تحت) —
  // المفتاح هنا كان لازم يطابقهم الاتنين بالحرف. قبل الفيكس: getWeightsForMerchant()
  // كانت بتدوّر بمفتاح lowercase جوه map مبني من صفوف DB uppercase —
  // مطابقة مستحيلة، فالتعلّم من IP_TOR (أهم إشارة كارد تيستنج كلاسيكية)
  // كان معطّل بالكامل بصمت رغم إن الكتابة في DB كانت بتنجح.
  "IP_TOR:TRUE":               { base: 30, polarity: 'negative', description: "IP is a Tor exit node" },
  // [IP_BOT wiring] الوحيدة من بين isTor/isBot اللي عندها gate نظيف
  // ومستقل في calculateIPPenalty() (زي IP_TOR بالحرف) لكن مالهاش مفتاح
  // تعلّم أصلًا قبل كده. base=20 مطابق للـ hardcoded value الحالية —
  // صفر أثر سلوكي عند cold start. لا يوجد backlog تاريخي لهذه الإشارة
  // (extractSignalsFromSnapshot() ما كانتش بتسجّلها)، فالتعلّم يبدأ من
  // نقطة الديبلوي فصاعدًا.
  // [Case-normalization fix] كانت مرفوضة بصمت وقت الكتابة (راجع
  // VALID_SIGNAL_VALUES في feedbackLoop.js) — مش حتى مشكلة قراءة زي IP_TOR،
  // كانت أعمق: صفر صف وصل DB أصلاً.
  "IP_BOT:TRUE":                { base: 20, polarity: 'negative', description: "IP flagged as bot or botnet participant" },
  // [IP_DATACENTER wiring — Phase 2] base هنا نقطة مرجعية لحساب النسبة
  // (getLearnedMultiplier)، مش قيمة عقوبة مباشرة — نفس نمط BIN_PREPAID:true
  // بالحرف (base=15 هناك بينما العقوبة الفعلية amount-scaled 20/10).
  // القيمة الفعلية للعقوبة (12/6 حسب amount) معرّفة في ipIntelligence.js.
  // بعكس IP_BOT، extractSignalsFromSnapshot() كانت بالفعل بتسجّل
  // IP_DATACENTER:true من زمان — البيانات التاريخية دي صالحة للاستخدام
  // فورًا رغم إن العقوبة المخصصة الجديدة لم تكن موجودة وقت جمعها (الـ
  // win/loss بيعكس نتيجة الأوردر الحقيقية، مستقل عن أي عقوبة اتطبّقت
  // وقتها — راجع الشرح الكامل في محادثة الفيكس).
  // [Case-normalization fix] نفس علة IP_TOR بالحرف — الكتابة كانت بتنجح
  // (مش في whitelist)، لكن القراءة عن طريق getLearnedMultiplier() كانت
  // بترجع 1.0 (no-op) للأبد لأن getStaticWeight/getW بيدوروا بمفتاح
  // lowercase مقابل بيانات DB uppercase.
  "IP_DATACENTER:TRUE":         { base: 12, polarity: 'negative', description: "IP address is a known hosting/datacenter provider (dedicated signal, independent of composite fraud score)" },
  // [Case-normalization fix — اكتشاف الجلسة] كانت "true" lowercase بينما
  // feedbackLoop.js's updateSignalStat() بتخزّن كل signalValue بعد
  // .toUpperCase() بلا شرط — getWeightsForMerchant() تحت مستحيل تلاقي
  // أي صف تاريخي مطابق (المفتاح هنا lowercase، الـ DB مخزّن فيها
  // "TRUE"). دول مش موجودين في VALID_SIGNAL_VALUES أصلًا فالكتابة نفسها
  // كانت بتنجح دايمًا — المشكلة في القراءة بس. آمن 100%: لا NEW_CUSTOMER
  // ولا HIGH_VALUE ولا GRAPH_RISK_HIGH متصلين بـ getW() في riskScoring.js
  // حاليًا (Discovery 6 — عقوبتهم كلها hardcoded)، فمفيش live caller.
  "NEW_CUSTOMER:TRUE":         { base: 10, polarity: 'negative', description: "New customer" },
  "HIGH_VALUE:TRUE":           { base: 10, polarity: 'negative', description: "High value order" },
  "GRAPH_RISK_HIGH:TRUE":      { base: 20, polarity: 'negative', description: "High identity graph risk" },
  // [Polarity fix — إشارات جديدة، learned-only] BIN_BRAND و IP_COUNTRY:
  // base=0 عمدًا — مفيش أي أساس منطقي لعقوبة ثابتة (لا يوجد سبب موضوعي
  // لافتراض إن "فيزا" أخطر من "ماستركارد"، أو إن دولة IP معيّنة خطرة
  // بمعزل عن أي بيانات فعلية). learnedCap هو الأقصى اللي ممكن تصل له
  // العقوبة لو التاريخ الفعلي أثبت الارتباط بالاحتيال — راجع
  // getWeightsForMerchant() تحت لآلية استخدام learnedCap عند base=0.
  // مفيش أي استهلاك فعلي ليهم في riskScoring.js/binIntelligence.js/
  // ipIntelligence.js لسه — هيتضاف في خطوة لاحقة منفصلة.
  "BIN_BRAND:VISA":            { base: 0, learnedCap: 12, polarity: 'negative', description: "Card brand: Visa (learned-only)" },
  "BIN_BRAND:MASTERCARD":      { base: 0, learnedCap: 12, polarity: 'negative', description: "Card brand: Mastercard (learned-only)" },
  "BIN_BRAND:AMEX":            { base: 0, learnedCap: 12, polarity: 'negative', description: "Card brand: Amex (learned-only)" },
  "BIN_BRAND:DISCOVER":        { base: 0, learnedCap: 12, polarity: 'negative', description: "Card brand: Discover (learned-only)" },
  // [IP_COUNTRY fix] كانت placeholder غلط ("*" مش قيمة signal حقيقية —
  // getWeightsForMerchant() بتلف على مفاتيح STATIC_WEIGHTS الثابتة، مش
  // قادرة تدعم قيم ديناميكية). اتحولت لمفاتيح صريحة تطابق نفس القائمة في
  // feedbackLoop.js's VALID_SIGNAL_VALUES.IP_COUNTRY بالظبط — نفس نمط
  // BIN_COUNTRY فوق. learnedCap أقل قليلاً من BIN_COUNTRY المقابلة
  // (النصف تقريبًا) لأن IP_COUNTRY بيشتغل جنب mismatch penalty الموجودة
  // بالفعل في calculateIPPenalty() — الـ cap المشترك هناك هو اللي بيمنع
  // التراكم الزيادة، مش الـ learnedCap هنا لوحده.
  "IP_COUNTRY:NG":              { base: 0, learnedCap: 8, polarity: 'negative', description: "IP connection from Nigeria (learned-only)" },
  "IP_COUNTRY:CM":              { base: 0, learnedCap: 8, polarity: 'negative', description: "IP connection from Cameroon (learned-only)" },
  "IP_COUNTRY:GH":              { base: 0, learnedCap: 8, polarity: 'negative', description: "IP connection from Ghana (learned-only)" },
  "IP_COUNTRY:PK":              { base: 0, learnedCap: 5, polarity: 'negative', description: "IP connection from Pakistan (learned-only)" },
  "IP_COUNTRY:BD":              { base: 0, learnedCap: 5, polarity: 'negative', description: "IP connection from Bangladesh (learned-only)" },
  "IP_COUNTRY:VN":              { base: 0, learnedCap: 3, polarity: 'negative', description: "IP connection from Vietnam (learned-only)" },
  "IP_COUNTRY:ID":              { base: 0, learnedCap: 3, polarity: 'negative', description: "IP connection from Indonesia (learned-only)" },
  "IP_COUNTRY:PH":              { base: 0, learnedCap: 3, polarity: 'negative', description: "IP connection from Philippines (learned-only)" },
  "IP_COUNTRY:RO":              { base: 0, learnedCap: 3, polarity: 'negative', description: "IP connection from Romania (learned-only)" },
  "IP_COUNTRY:UA":              { base: 0, learnedCap: 3, polarity: 'negative', description: "IP connection from Ukraine (learned-only)" },
  // ===== إشارات السرعة والسلوك =====
  // [Case-normalization fix + tier-fidelity fix — اكتشاف الجلسة]
  // (1) الحالة: نفس علة NEW_CUSTOMER/HIGH_VALUE فوق — بس هنا كمان
  //     موجودة في VALID_SIGNAL_VALUES، يعني كانت متأثرة بمشكلة إضافية:
  //     الكتابة نفسها كانت بترفض بصمت قبل ما توصل حتى لمشكلة القراءة
  //     هنا (راجع تعديل VALID_SIGNAL_VALUES في feedbackLoop.js).
  // (2) DEVICE_VELOCITY كانت بس مفتاحين (medium/high) بينما
  //     riskScoring.js عندها 3 تدريجات فعلية — "critical" (base=40)
  //     مفتاح جديد يطابق التدريج التالت اللي كان مفقود بالكامل.
  //     الوصف اتصحح ليعكس التطابق الصحيح: medium=count1(-15),
  //     high=count2(-25) — مش الوصف القديم الملخبط ("2 orders"/"3+ orders").
  // IP_VELOCITY:MEDIUM اتسابت بلا استخدام عمدًا (deprecated) —
  // riskScoring.js's صيغة log2 مستمرة بسيفريتي واحدة "high" بس، مفيش
  // تدريج medium حقيقي؛ متروكة بس لتوافق أي صف قديم، مفيش حدث جديد
  // هيولّدها بعد فيكس extractSignalsFromSnapshot.
  // IP_BURST مفتاح جديد بالكامل — راجع الشرح في feedbackLoop.js.
  "DEVICE_VELOCITY:MEDIUM":    { base: 15, polarity: 'negative', description: "Device velocity tier 1 — 1 order/hour from same device" },
  "DEVICE_VELOCITY:HIGH":      { base: 25, polarity: 'negative', description: "Device velocity tier 2 — 2 orders/hour from same device" },
  "DEVICE_VELOCITY:CRITICAL":  { base: 40, polarity: 'negative', description: "Device velocity tier 3 — 3+ orders/hour from same device (hard block tier)" },
  "IP_VELOCITY:HIGH":          { base: 20, polarity: 'negative', description: "IP velocity — 2+ orders from same IP within 24h (continuous log2 penalty, single severity tier)" },
  "IP_VELOCITY:MEDIUM":        { base: 10, polarity: 'negative', description: "Deprecated — no medium tier exists in riskScoring.js's IP velocity logic; retained only for historical rows, no longer written" },
  "IP_BURST:TRUE":             { base: 50, polarity: 'negative', description: "Sustained IP burst — 10+ orders from same IP within 24h (critical override, independent of IP_VELOCITY, fires alongside it)" },
  "EMAIL_VELOCITY:HIGH":       { base: 20, polarity: 'negative', description: "High email velocity — 3+ orders from same email within 6h" },
  "SHIPPING_BILLING_MISMATCH:TRUE": { base: 10, polarity: 'negative', description: "Shipping country differs from billing" },
  "BIN_ISSUER_MISMATCH:TRUE":  { base: 10, polarity: 'negative', description: "Card issuer country differs from billing" },
  "AMOUNT_ANOMALY:TRUE":       { base: 15, polarity: 'negative', description: "Order amount significantly above average" },
  // [BIN Velocity learning-loop wiring — أعلى أولوية لمشروع الكارد
  // تيستنج] base مطابق بالحرف للقيم الثابتة الحالية في riskScoring.js
  // (10/15/25) — عند cold start (getLearnedMultiplier ترجع 1.0)، صفر
  // أثر سلوكي وقت النشر. هذه أول مرة إشارة "نفس BIN بيتكرر بسرعة من
  // مصادر مختلفة" — التعريف الحرفي لهجوم الكارد تيستنج — تدخل نظام
  // التعلّم.
  "BIN_VELOCITY_10MIN:TRUE":   { base: 10, polarity: 'negative', description: "2+ orders using the same card BIN within 10 minutes" },
  "BIN_VELOCITY_1H:TRUE":      { base: 15, polarity: 'negative', description: "3+ orders using the same card BIN within 1 hour" },
  "BIN_VELOCITY_24H:TRUE":     { base: 25, polarity: 'negative', description: "5+ orders using the same card BIN within 24 hours" },
};
// ─── Apply Lazy Exponential Decay ─────────────────────────────────────────
function applyDecay(rawWins, rawLosses, lastDecayAt) {
  if (!lastDecayAt) return { wins: rawWins, losses: rawLosses };
  const daysSince = (Date.now() - new Date(lastDecayAt).getTime()) / (1000 * 60 * 60 * 24);
  const MIN_DECAY_VALUE = 0.05;

  // Asymmetric decay — losses بتتـ decay أبطأ من wins
  // DECAY_LAMBDA = 0.003 للـ wins (~58% بعد 180 يوم)
  // DECAY_LAMBDA * 0.5 للـ losses (~76% بعد 180 يوم)
  // المنطق: fraud signal قديم لسه مهم — clean signal القديم أقل أهمية
  const winFactor  = Math.exp(-DECAY_LAMBDA * daysSince);
  const lossFactor = Math.exp(-DECAY_LAMBDA * 0.5 * daysSince);

  return {
    wins:   Math.max(MIN_DECAY_VALUE, rawWins  * winFactor),
    losses: Math.max(MIN_DECAY_VALUE, rawLosses * lossFactor),
  };
}
// ─── Bayesian Win Rate ─────────────────────────────────────────────────────
// Prevents overconfidence with small samples
// With 0 data: returns 0.5 (neutral)
// With 100 wins, 0 losses: returns ~0.91 (not 1.0)
function bayesianWinRate(wins, losses) {
  return (wins + BAYESIAN_ALPHA) / (wins + losses + BAYESIAN_ALPHA + BAYESIAN_BETA);
}

// ─── Log-odds Transformation ───────────────────────────────────────────────
// Converts win rate to a weight multiplier
// winRate = 0.5 → logOdds = 0  → weight = BASE (neutral)
// winRate = 0.9 → logOdds = 2.2 → weight = BASE + SCALE*2.2 (boosted)
// winRate = 0.1 → logOdds = -2.2 → weight = BASE - SCALE*2.2 (penalized)
function logOddsWeight(winRate) {
  // Clamp to avoid log(0) or log(inf)
  const clamped = Math.max(0.01, Math.min(0.99, winRate));
  const logOdds = Math.log(clamped / (1 - clamped));
  return Math.max(0, LOG_ODDS_BASE + LOG_ODDS_SCALE * logOdds);
}

// [Polarity fix] معكوس logOddsWeight() للإشارات السلبية (polarity:
// 'negative'). الفرق الجوهري: winRate عالية لإشارة إيجابية = ثقة أعلى =
// وزن أعلى (صح). لكن نفس المنطق على إشارة سلبية زي IP_TOR هيبقى معكوس —
// لو IP_TOR فعلاً مؤشر احتيال قوي، الأوردرات اللي عليها هتخسر الـ disputes
// غالبًا (winRate منخفضة)، فلو استخدمنا logOddsWeight() زي ما هي هتقول
// "ثقة قليلة → وزن قليل → عقوبة تتقلص" في نفس اللحظة اللي المفروض
// العقوبة تكبر فيها. هذه الدالة بتاخد lossRate (= معدل خسارة الـ dispute
// = معدل تأكد الاحتيال) بدل winRate، فكل ما الإشارة تتأكد كمؤشر احتيال
// (lossRate عالية)، الوزن بيكبر بشكل صحيح.
function logOddsPenaltyWeight(lossRate) {
  const clamped = Math.max(0.01, Math.min(0.99, lossRate));
  const logOdds = Math.log(clamped / (1 - clamped));
  return Math.max(0, LOG_ODDS_BASE + LOG_ODDS_SCALE * logOdds);
}

// ─── Confidence-based Blending ─────────────────────────────────────────────
// Low confidence → trust global more
// High confidence → trust learned weight more
function blendWeights(globalWeight, learnedWeight, confidence) {
  return (1 - confidence) * globalWeight + confidence * learnedWeight;
}



// ─── Get All Weights for Merchant ─────────────────────────────────────────
// Batch loads all weights for a merchant in one call
// Returns a map: "ECI:5" → effective weight
async function getWeightsForMerchant(merchantId) {
  try {
    // 1. جلب ملف التاجر
    const profile = await db.merchantProfile.findUnique({ where: { merchantId } });
    const ratio = calculateMerchantRatio(profile);

    // 2. جلب جميع إحصائيات الإشارات (للتاجر وللعام)
    const allStats = await db.signalStat.findMany({
      where: {
        OR: [
          { merchantId: GLOBAL_MERCHANT_ID },
          { merchantId },
        ],
      },
    });

    const globalStats = new Map();
    const merchantStats = new Map();
    for (const stat of allStats) {
      const key = `${stat.signalType}:${stat.signalValue}`;
      if (stat.merchantId === GLOBAL_MERCHANT_ID) globalStats.set(key, stat);
      else merchantStats.set(key, stat);
    }

const weightMap = {};
    for (const signalKey of Object.keys(STATIC_WEIGHTS)) {
      const entry = STATIC_WEIGHTS[signalKey];
      const staticWeight = entry.base;

      // [Polarity fix] learningScale بتحدد المقياس المستخدم فعليًا في
      // حساب learnedWeight تحت. للإشارات العادية (base > 0) هي نفسها
      // staticWeight — زي ما كان بالظبط. للإشارات الـ learned-only
      // (base=0, learnedCap موجودة — زي BIN_BRAND/IP_COUNTRY) هي
      // learnedCap، بينما staticWeight نفسها تفضل 0 كنقطة انطلاق
      // الـ blending (يعني صفر عقوبة لحد ما يتجمّع تاريخ فعلي). للإشارات
      // المعطّلة عمدًا (ECI:7, AVS:N, CVV2:N — base=0 وبدون learnedCap)
      // learningScale = 0 فتتعامل زي ما كانت بالظبط: skip فوري.
      const learningScale = staticWeight > 0 ? staticWeight : (entry.learnedCap || 0);
      if (learningScale === 0) {
        weightMap[signalKey] = 0;
        continue;
      }

      const isNegative = entry.polarity === 'negative';
      const weightFn   = isNegative ? logOddsPenaltyWeight : logOddsWeight;

      // الوزن العام
      let globalWeight = staticWeight;
      const globalStat = globalStats.get(signalKey);
      if (globalStat && globalStat.totalEvents >= 3) {
        const { wins, losses } = applyDecay(globalStat.rawWins, globalStat.rawLosses, globalStat.lastDecayAt);
        // [Polarity fix] rate بتتحسب معكوسة للإشارات السلبية — lossRate
        // (معدل خسارة الـ dispute = معدل تأكد الاحتيال) بدل winRate.
        // راجع تعليق logOddsPenaltyWeight() فوق للتفصيل الكامل.
        const rate = isNegative ? bayesianWinRate(losses, wins) : bayesianWinRate(wins, losses);
        const learnedWeight = weightFn(rate) * learningScale;
        const confidence = Math.min(1, globalStat.totalEvents / MIN_EVENTS_FOR_CONFIDENCE);
        globalWeight = blendWeights(staticWeight, learnedWeight, confidence);
      }
      // وزن التاجر
      let merchantWeight = globalWeight;
      if (ratio > 0) {
        const merchantStat = merchantStats.get(signalKey);
        if (merchantStat && merchantStat.totalEvents >= 3) {
          const { wins: mWins, losses: mLosses } = applyDecay(merchantStat.rawWins, merchantStat.rawLosses, merchantStat.lastDecayAt);
          const mRate = isNegative ? bayesianWinRate(mLosses, mWins) : bayesianWinRate(mWins, mLosses);
          const mLearned = weightFn(mRate) * learningScale;
          const mConfidence = Math.min(1, merchantStat.totalEvents / MIN_EVENTS_FOR_CONFIDENCE);
          merchantWeight = blendWeights(staticWeight, mLearned, mConfidence);
        }
      }
      const finalWeight = (1 - ratio) * globalWeight + ratio * merchantWeight;
      // [Polarity fix] السقف بقى نسبي (learningScale × MAX_WEIGHT_MULTIPLIER)
      // بدل المطلق (MAX_EFFECTIVE_WEIGHT=5.0) — راجع تعليق الثابت فوق.
      const cap = learningScale * MAX_WEIGHT_MULTIPLIER;
      weightMap[signalKey] = Math.min(cap, Math.max(0, finalWeight));
    }

    return {
      weights: weightMap,
      merchantWeightRatio: ratio,
      isLearning: (profile?.totalDisputes ?? 0) >= MIN_DISPUTES_FOR_MERCHANT,
      totalDisputes: profile?.totalDisputes ?? 0,
    };
  } catch (err) {
    logger.error({ module: 'signalWeights', err }, 'Failed to load learned weights, using static fallback');
    const staticFallback = {};
    for (const key of Object.keys(STATIC_WEIGHTS)) {
      staticFallback[key] = STATIC_WEIGHTS[key].base;
    }
    return {
      weights: staticFallback,
      merchantWeightRatio: 0,
      isLearning: false,
      totalDisputes: 0,
    };
  }
}
// ─── Get Weight for Specific Signal ───────────────────────────────────────
/**
 * @deprecated استخدم getWeightsForMerchant() بدلاً منها في أي request بيحتاج أكتر من signal
 * ⚠️  SLOW PATH — 3 DB queries per call (profile + global stat + merchant stat)
 * لو اتنادت في loop على N signals = N*3 queries
 *
 * متى تستخدمها:
 * ✅ signal واحدة فقط في isolated context (مثلاً debugging أو admin tool)
 * ❌ أبداً في loop أو في calculateRiskScore
 */
async function getWeightForSignal(signalType, signalValue, merchantId) {
  const weights = await getWeightsForMerchant(merchantId);
  return weights.weights[`${signalType}:${signalValue}`] ?? 0;
}

// ─── Get Static Weight (no DB call) ───────────────────────────────────────
// Fast path — used when learning is disabled or for comparison
function getStaticWeight(signalType, signalValue) {
  return STATIC_WEIGHTS[`${signalType}:${signalValue}`]?.base ?? 0;
}

// [Amount-scaled signals wiring] لإشارات زي BIN_PREPAID و
// BIN_ISSUER_MISMATCH — العقوبة فيها مبنية على صيغة تجارية موجودة
// (amount > threshold ? high : low)، مش على قيمة واحدة نقدر نستبدلها
// مباشرة زي ما عملنا مع IP_TOR/EMAIL_DISPOSABLE. الاستبدال المباشر كان
// هيمسح منطق الـ amount-tiering بالكامل. بدل كده، بيرجّع *نسبة* تحرّك
// الصيغة الموجودة فوق/تحت حسب تاريخ التعلّم، من غير ما يمسحها:
//   multiplier = getW(type,value) / STATIC_WEIGHTS[type:value].base
// عند cold start (getW غير متاحة، أو صفر بيانات تعلّم بعد)، getW()
// بترجع نفس static base (fallback في getWeightsForMerchant())، يعني
// multiplier = 1.0 بالظبط — الصيغة الأصلية تشتغل بلا أي تغيير.
function getLearnedMultiplier(getW, signalType, signalValue) {
  if (!getW) return 1.0;
  const staticBase = getStaticWeight(signalType, signalValue);
  if (staticBase === 0) return 1.0; // مفيش baseline نقارن بيه — no-op آمن
  const learned = getW(signalType, signalValue);
  return learned / staticBase;
}

// ─── Get Weight Description ────────────────────────────────────────────────
function getSignalDescription(signalType, signalValue) {
  return STATIC_WEIGHTS[`${signalType}:${signalValue}`]?.description ?? "Unknown signal";
}

// ─── Explain Weights (for debugging + merchant UI) ────────────────────────
// Returns a detailed breakdown of why each signal has its weight
async function explainWeights(merchantId) {
  const { weights, merchantWeightRatio, isLearning, totalDisputes } = await getWeightsForMerchant(merchantId);
  const ratio = merchantWeightRatio;
  const explanation = [];

  for (const signalKey of Object.keys(STATIC_WEIGHTS)) {
    const staticW = STATIC_WEIGHTS[signalKey].base;
    const effectiveW = weights[signalKey] ?? 0;

    explanation.push({
      signal: signalKey,
      description: STATIC_WEIGHTS[signalKey].description,
      staticWeight: staticW,
      effectiveWeight: parseFloat(effectiveW.toFixed(3)),
      delta: parseFloat((effectiveW - staticW).toFixed(3)),
      direction: effectiveW > staticW ? "boosted" : effectiveW < staticW ? "penalized" : "neutral",
    });
  }

  return {
    merchantId,
    isLearning,
    merchantWeightRatio: ratio,
    totalDisputes,
    signals: explanation.sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta)),
  };
}
module.exports = {
  getWeightsForMerchant,
  getWeightForSignal,
  getStaticWeight,
  getLearnedMultiplier,
  getSignalDescription,
  explainWeights,
  DECAY_LAMBDA,
};