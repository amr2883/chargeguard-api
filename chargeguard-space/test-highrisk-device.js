const http = require('http');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

const API_KEY = process.env.API_KEY;
const BASE_URL = 'http://localhost:3000/api/risk';
const MERCHANT_ID = 'test_merchant_001';
const FINGERPRINT = 'high_risk_device_03';

// دالة مساعدة لإرسال طلب HTTP
function sendRequest(endpoint, body = null) {
  const url = new URL(BASE_URL + endpoint);
  const payload = body ? JSON.stringify(body) : null;
  const options = {
    hostname: url.hostname,
    port: url.port || 3000,
    path: url.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY,
      'X-Merchant-Id': MERCHANT_ID,
    }
  };
  if (payload) options.headers['Content-Length'] = Buffer.byteLength(payload);

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

(async () => {
  let passed = true;
  
  try {
    // === استدعاء /check-device للجهاز المحقون مسبقاً ===
    console.log('=== Check if high-risk device is blocked ===\n');
    const result = await sendRequest('/check-device', {
      fingerprint: FINGERPRINT
    });
    
    console.log(`Status: ${result.status}`);
    console.log(`Response: ${JSON.stringify(result.body)}`);
    
    if (result.status !== 200) {
      console.log('[FAIL] Expected status 200');
      passed = false;
    }
    if (result.body.blocked !== true) {
      console.log(`[FAIL] Expected blocked: true, got: ${result.body.blocked}`);
      passed = false;
    } else {
      console.log('[OK] Device is blocked by Identity Graph');
    }
    if (result.body.reason && result.body.reason.includes('high-risk network')) {
      console.log('[OK] Reason mentions high-risk network');
    } else {
      console.log(`[WARN] Reason: "${result.body.reason}"`);
    }

  } catch (err) {
    console.error(`[ERROR] ${err.message}`);
    passed = false;
  }

  // التقرير النهائي
  console.log('\n================================');
  console.log(passed ? '[PASS] All tests passed' : '[FAIL] Some tests failed');
  process.exit(passed ? 0 : 1);
})();