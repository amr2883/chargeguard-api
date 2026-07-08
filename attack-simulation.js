// attack-simulation.js
// محاكاة دقيقة لهجوم Card Testing من النوع Bulk Low-Value
// يستهدف ChargeGuard Backend مباشرةً على نقطة /risk/evaluate
// الإصدار: v1.0

// ========== املأ القيم التالية ==========
const API_BASE = 'http://localhost:3000/api';
const API_KEY = 'elZ2bcFsLYazxo9huArwDGfQ4683PTiOJEdV5tKnjIMp1vWk';          
const MERCHANT_ID = 'test-merchant-001';  // ضع معرف التاجر
// =====================================

const EVALUATE_URL = `${API_BASE}/risk/evaluate`;

// إعدادات الهجوم
const NUM_ATTEMPTS = 100;          // عدد المحاولات الإجمالية
const DELAY_MS = 80;               // التأخير بين كل طلب (80ms محاكاة للسرعة العالية)
const ATTACKER_IP = '172.30.99.55';     // IP وهمي ثابت لجميع الطلبات
const ATTACKER_DEVICE = 'brand-new-escalation-device'; // بصمة جهاز وهمية ثابتة
const AMOUNT = 0.50;               // مبلغ صغير (أقل من دولار)

// قائمة بطاقات اختبارية (BINs متنوعة)
const testCards = [
  { bin: '400000', last4: '0002' },
  { bin: '400000', last4: '0010' },
  { bin: '520082', last4: '8282' },
  { bin: '378282', last4: '2463' },
];

// دوال مساعدة
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// إرسال طلب تقييم مزيف
async function sendFakeOrder(index) {
  // إنشاء بريد إلكتروني متغير كل مرة (نمط المجرمين)
  const email = `carder${index}@gmail.com`;
  // اختيار بطاقة عشوائية من القائمة
  const card = testCards[index % testCards.length];
  // BIN متغير قليلاً لتجنب التطابق التام
  const randomBin = card.bin + Math.floor(Math.random() * 1000).toString().padStart(4, '0');

  const payload = {
    orderId: `sim-${Date.now()}-${index}`,  // فريد لكل طلب
    email: email,
    ipAddress: ATTACKER_IP,
    deviceFingerprint: ATTACKER_DEVICE,
    amount: AMOUNT,
    billingCountry: 'US',
    shippingCountry: 'US',
    bin: randomBin,
    merchantId: MERCHANT_ID,
  };

  try {
    const response = await fetch(EVALUATE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      body: JSON.stringify(payload),
    });

    const result = await response.json();

    if (response.status === 403) {
      return { blocked: true, reason: result.reason || result.error, status: response.status };
    }

    if (response.ok) {
      if (result.decision === 'block') {
        return { blocked: true, reason: result.flags?.[0]?.text || 'Blocked by decision', status: 200 };
      } else if (result.decision === 'review') {
        return { blocked: false, decision: 'review', score: result.score };
      } else {
        return { blocked: false, decision: 'approve', score: result.score };
      }
    }

    return { error: true, message: result.error || 'Unknown error', status: response.status };
  } catch (err) {
    return { error: true, message: err.message };
  }
}

// الدالة الرئيسية
(async () => {
  console.log('╔══════════════════════════════════════════╗');
  console.log('║  ChargeGuard Card Testing Simulation    ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log(`بدء الهجوم بـ ${NUM_ATTEMPTS} طلب...`);
  console.log(`IP المهاجم: ${ATTACKER_IP}`);
  console.log(`بصمة الجهاز: ${ATTACKER_DEVICE}\n`);

  let blockedCount = 0;
  let reviewCount = 0;
  let approvedCount = 0;
  let errorCount = 0;
  let firstBlockIndex = -1;

  for (let i = 0; i < NUM_ATTEMPTS; i++) {
    const res = await sendFakeOrder(i);

    if (res.error) {
      errorCount++;
      if (errorCount <= 3) console.log(`[${i + 1}] ❌ خطأ: ${res.message}`);
    } else if (res.blocked) {
      blockedCount++;
      if (blockedCount === 1) firstBlockIndex = i + 1;
      if (blockedCount <= 3) console.log(`[${i + 1}] 🛑 محظور: ${res.reason} (HTTP ${res.status})`);
    } else if (res.decision === 'review') {
      reviewCount++;
      if (reviewCount <= 3) console.log(`[${i + 1}] 🟡 قيد المراجعة (Score: ${res.score})`);
    } else {
      approvedCount++;
      if (approvedCount <= 3) console.log(`[${i + 1}] ✅ موافق عليه (Score: ${res.score})`);
    }

    await sleep(DELAY_MS);
  }

  console.log('\n📊 == ملخص الهجوم ==');
  console.log(`✅ موافق عليه: ${approvedCount}`);
  console.log(`🟡 قيد المراجعة: ${reviewCount}`);
  console.log(`🛑 محظور (Blocked): ${blockedCount}`);
  console.log(`❌ أخطاء: ${errorCount}`);

  if (firstBlockIndex > 0) {
    console.log(`\n🔒 تم اكتشاف الهجوم وحظر الجهاز/IP بعد ${firstBlockIndex} طلب.`);
    console.log('→ نظام Velocity Detection يعمل بكفاءة عالية.');
  } else if (reviewCount > 0) {
    console.log('\n⚠️ لم يتم الحظر الكامل لكن بعض الطلبات اعتبرت مشبوهة (Review).');
    console.log('→ قد تحتاج عتبات السرعة إلى تشديد بسيط.');
  } else {
    console.log('\n❌ فشل الاكتشاف: لم يتم حظر أي طلب. يجب مراجعة إعدادات العتبات (Thresholds).');
  }

  // اختبار القائمة السوداء: هل أُضيف الجهاز تلقائياً؟
  console.log('\n--- فحص القائمة السوداء (check-device) ---');
  try {
    const checkRes = await fetch(`${API_BASE}/risk/check-device`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
        'X-Merchant-Id': MERCHANT_ID,
      },
      body: JSON.stringify({ fingerprint: ATTACKER_DEVICE }),
    });
    const checkData = await checkRes.json();
    console.log('حالة البصمة بعد الهجوم:', JSON.stringify(checkData, null, 2));
  } catch (e) {
    console.log('تعذر الاتصال بـ check-device:', e.message);
  }
})();