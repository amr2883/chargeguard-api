// tests/simulate-attack.js
// محاكاة هجوم Card Testing على ChargeGuard API مباشرة

const TARGET_URL = process.argv[2] || 'http://localhost:3000';

// بيانات هجوم
const ATTACK = {
  email: 'bot@tempmail.com',
  amount: 1.99,
  ip: '198.51.100.50',
  device: 'bot-device-1',
  cardBin: '400000',
  userAgent: '',
  origin: 'Unknown'
};

// بيانات شرعي
const LEGIT = {
  email: 'real.customer@gmail.com',
  amount: 49.99,
  ip: '203.0.113.10',
  device: 'normal-device',
  cardBin: '411111',
  userAgent: 'Mozilla/5.0 Chrome/126',
  origin: 'https://shop.example.com'
};

async function sendRequest(data, label) {
  const res = await fetch(`${TARGET_URL}/api/risk/evaluate`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'User-Agent': data.userAgent,
      'Origin': data.origin
    },
    body: JSON.stringify({
      order_id: `${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      email: data.email,
      amount: data.amount,
      ip_address: data.ip,
      device_fingerprint: data.device,
      card_bin: data.cardBin
    })
  });
  const json = await res.json();
  return { decision: json.decision || 'unknown', status: res.status };
}

async function main() {
  console.log(`🎯 ChargeGuard Simulation — Target: ${TARGET_URL}\n`);

  let blocked = 0, reviewed = 0, approved = 0;

  // 30 طلب هجوم
  console.log('🔥 Sending 30 ATTACK requests...');
  for (let i = 0; i < 30; i++) {
    const r = await sendRequest(ATTACK, 'attack');
    if (r.decision === 'block') blocked++;
    else if (r.decision === 'review') reviewed++;
    else approved++;
    process.stdout.write('.');
  }

  // 5 طلبات شرعية
  console.log('\n✅ Sending 5 LEGITIMATE requests...');
  let legitBlocked = 0;
  for (let i = 0; i < 5; i++) {
    const r = await sendRequest(LEGIT, 'legit');
    if (r.decision === 'block') legitBlocked++;
    process.stdout.write('.');
  }

  console.log('\n\n📊 RESULTS:');
  console.log(`   Attack — Blocked: ${blocked}, Review: ${reviewed}, Approved: ${approved}`);
  console.log(`   Legit  — Blocked: ${legitBlocked}`);

  console.log('\n───────────────────────────────────────');
  if (approved === 0 && blocked > 0 && legitBlocked === 0) {
    console.log('✅ PASS — ChargeGuard correctly blocked malicious traffic.');
  } else {
    console.log('❌ FAIL — Something went wrong.');
    if (approved > 0) console.log(`   → ${approved} attack requests were APPROVED.`);
    if (legitBlocked > 0) console.log(`   → ${legitBlocked} legitimate requests were BLOCKED.`);
  }
}

main().catch(e => console.error('Fatal:', e));