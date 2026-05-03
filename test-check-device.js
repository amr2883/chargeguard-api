const http = require('http');
const path = require('path');

// تحميل .env يدوياً
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

const API_KEY = process.env.API_KEY;
const BASE_URL = 'http://localhost:3000/api/risk/check-device';
const MERCHANT_ID = 'test_merchant_001';

if (!API_KEY) {
  console.error('API_KEY is not set in .env file');
  process.exit(1);
}

async function testCleanDevice() {
  console.log('=== Test 1: Clean Device ===\n');

  const payload = JSON.stringify({
    fingerprint: 'clean_device_test_01'
  });

  const url = new URL(BASE_URL);
  const options = {
    hostname: url.hostname,
    port: url.port || 3000,
    path: url.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY,
      'X-Merchant-Id': MERCHANT_ID,
      'Content-Length': Buffer.byteLength(payload)
    }
  };

  const startTime = Date.now();

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        const duration = Date.now() - startTime;
        let body;
        try { body = JSON.parse(data); } catch { body = data; }

        resolve({ status: res.statusCode, body, duration });
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

(async () => {
  try {
    const result = await testCleanDevice();

    console.log(`Status: ${result.status}`);
    console.log(`Duration: ${result.duration}ms`);
    console.log(`Response: ${JSON.stringify(result.body)}`);

    // تحقق تلقائي
    let passed = true;
    if (result.status !== 200) {
      console.log('[FAIL] Expected status 200');
      passed = false;
    }
    if (result.body.blocked !== false) {
      console.log(`[FAIL] Expected blocked: false, got: ${result.body.blocked}`);
      passed = false;
    }
    if (result.body.reason !== undefined) {
      console.log(`[WARN] reason should not be present for clean device`);
    }
    if (passed) {
      console.log('\n[OK] Test passed – clean device not blocked');
    }

  } catch (err) {
    console.error(`[ERROR] ${err.message}`);
  }
})();