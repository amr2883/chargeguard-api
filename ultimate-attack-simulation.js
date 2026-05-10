// ultimate-attack-simulation.js
// تنفيذ هجوم شامل يحاكي Card Testing عبر Store API
// تم التحقق من كونه المحاكاة الأكثر دقة للهجمات الموثقة

const API_URL = 'https://chargeguard-api.onrender.com/api/risk/evaluate';
const API_KEY = 'Jx5/k9M6HT5ktjdo++kP0pRy5A32UnQzBo8z6AJxYdU=';
const MERCHANT_ID = 'test-merchant-001';

// تكوين الهجوم
const NUM_ATTEMPTS = 100;
const DELAY_MS = 85;
const ATTACK_IP = '192.168.99.100'; // IP جديد ونظيف
const ATTACK_DEVICE = 'test-bot-device-001'; // جهاز جديد

// بطاقات اختبارية متنوعة
const cards = [
  { bin: '400000', last4: '0002' },
  { bin: '400000', last4: '0010' },
  { bin: '520082', last4: '8282' },
  { bin: '378282', last4: '2463' },
];

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

async function launchAttack() {
  console.log('🛡️ بدء هجوم واقعي لاختبار البطاقات ضد ChargeGuard\n');
  
  let blocked = 0, approved = 0, reviewed = 0, errors = 0;
  let firstBlock = -1;

  for (let i = 0; i < NUM_ATTEMPTS; i++) {
    const card = cards[i % cards.length];
    const randomSuffix = Math.floor(Math.random() * 1000).toString().padStart(4, '0');
    const payload = {
      orderId: `attk-${Date.now()}-${i}`,
      email: `carder${i}@gmail.com`, // تجنب بريد مؤقت لاختبار طبقات أخرى
      ipAddress: ATTACK_IP,
      deviceFingerprint: ATTACK_DEVICE,
      amount: 0.50,
      billingCountry: 'US',
      shippingCountry: 'US',
      bin: card.bin + randomSuffix,
      merchantId: MERCHANT_ID,
    };

    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
        body: JSON.stringify(payload),
      });
      const result = await response.json();

      if (response.status === 403) {
        blocked++;
        if (blocked === 1) firstBlock = i + 1;
        if (blocked <= 3) console.log(`[${i+1}] 🛑 محظور: ${result.reason || result.error}`);
      } else if (result.decision === 'block') {
        blocked++;
        if (blocked === 1) firstBlock = i + 1;
        if (blocked <= 3) console.log(`[${i+1}] 🛑 محظور: ${result.flags[0]?.text}`);
      } else if (result.decision === 'review') {
        reviewed++;
        if (reviewed <= 3) console.log(`[${i+1}] 🟡 مراجعة (Score: ${result.score})`);
      } else {
        approved++;
        if (approved <= 3) console.log(`[${i+1}] ✅ موافق (Score: ${result.score})`);
      }
    } catch (error) {
      errors++;
      if (errors <= 3) console.error(`[${i+1}] ❌ خطأ: ${error.message}`);
    }
    await sleep(DELAY_MS);
  }

  console.log(`\n📊 ملخص الهجوم (${NUM_ATTEMPTS} محاولة):`);
  console.log(`✅ موافق: ${approved}`);
  console.log(`🟡 مراجعة: ${reviewed}`);
  console.log(`🛑 محظور: ${blocked}`);
  if (firstBlock > 0) console.log(`🔒 تم الكشف عن الهجوم بعد ${firstBlock} طلب.`);
}
launchAttack();