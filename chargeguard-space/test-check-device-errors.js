const http = require('http');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

const API_KEY = process.env.API_KEY;
const BASE_URL = 'http://localhost:3000/api/risk/check-device';
const MERCHANT_ID = 'test_merchant_001';

function sendRequest(headers = {}, body = null) {
  const url = new URL(BASE_URL);
  const payload = body ? JSON.stringify(body) : null;
  const options = {
    hostname: url.hostname, port: url.port || 3000, path: url.pathname, method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers }
  };
  if (payload) options.headers['Content-Length'] = Buffer.byteLength(payload);

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

(async () => {
  let passed = true;
  
  // === Test 4: Missing fingerprint ===
  console.log('=== Test 4: Missing fingerprint ===\n');
  const result4 = await sendRequest(
    { 'X-API-Key': API_KEY, 'X-Merchant-Id': MERCHANT_ID },
    {} // body بدون fingerprint
  );
  console.log(`Status: ${result4.status}`);
  console.log(`Response: ${JSON.stringify(result4.body)}`);
  
  if (result4.status !== 400) {
    console.log(`[FAIL] Expected status 400, got ${result4.status}`);
    passed = false;
  } else {
    console.log('[OK] Status 400 returned');
  }
  if (result4.body.error !== 'fingerprint is required') {
    console.log(`[FAIL] Expected error message "fingerprint is required"`);
    passed = false;
  } else {
    console.log('[OK] Error message correct');
  }

  // === Test 5: Missing API Key ===
  console.log('\n=== Test 5: Missing API Key ===\n');
  const result5 = await sendRequest(
    { 'X-Merchant-Id': MERCHANT_ID }, // بدون X-API-Key
    { fingerprint: 'test_fp_123' }
  );
  console.log(`Status: ${result5.status}`);
  console.log(`Response: ${JSON.stringify(result5.body)}`);
  
  if (result5.status !== 401) {
    console.log(`[FAIL] Expected status 401, got ${result5.status}`);
    passed = false;
  } else {
    console.log('[OK] Status 401 returned');
  }

  // التقرير النهائي
  console.log('\n================================');
  console.log(passed ? '[PASS] All tests passed' : '[FAIL] Some tests failed');
  process.exit(passed ? 0 : 1);
})();