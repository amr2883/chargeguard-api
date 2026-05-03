const http = require('http');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

const API_KEY = process.env.API_KEY;
const BASE_URL = 'http://localhost:3000/api/risk';
const MERCHANT_ID = 'test_merchant_001';
const FINGERPRINT = 'blocked_device_test_02';

// دالة مساعدة لإرسال طلب HTTP
function sendRequest(method, endpoint, body = null) {
  const url = new URL(BASE_URL + endpoint);
  const payload = body ? JSON.stringify(body) : null;
  const options = {
    hostname: url.hostname,
    port: url.port || 3000,
    path: url.pathname,
    method,
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
  let blacklistEntryId = null;
  let passed = true;
  
  try {
    // === 1. إضافة بصمة إلى القائمة السوداء ===
    console.log('=== 1. Add fingerprint to blacklist ===\n');
    const addResult = await sendRequest('POST', '/blacklist', {
      merchantId: MERCHANT_ID,
      type: 'DEVICE_FINGERPRINT',
      value: FINGERPRINT,
      reason: 'Testing blacklist functionality'
    });
    
    console.log(`Status: ${addResult.status}`);
    console.log(`Response: ${JSON.stringify(addResult.body)}`);
    
    if (addResult.status === 200 && addResult.body.success) {
      blacklistEntryId = addResult.body.entry?.id || null;
      console.log(`[OK] Fingerprint added to blacklist${blacklistEntryId ? ' (ID: ' + blacklistEntryId + ')' : ''}\n`);
    } else {
      console.log('[FAIL] Could not add fingerprint to blacklist\n');
      passed = false;
    }

    // === 2. استدعاء /check-device ===
    console.log('=== 2. Check if device is blocked ===\n');
    const checkResult = await sendRequest('POST', '/check-device', {
      fingerprint: FINGERPRINT
    });
    
    console.log(`Status: ${checkResult.status}`);
    console.log(`Response: ${JSON.stringify(checkResult.body)}`);
    
    if (checkResult.status !== 200) {
      console.log('[FAIL] Expected status 200\n');
      passed = false;
    }
    if (checkResult.body.blocked !== true) {
      console.log(`[FAIL] Expected blocked: true, got: ${checkResult.body.blocked}\n`);
      passed = false;
    } else {
      console.log('[OK] Device is blocked\n');
    }
    if (checkResult.body.reason !== 'Device is blacklisted') {
      console.log(`[WARN] Expected reason: "Device is blacklisted", got: "${checkResult.body.reason}"\n`);
    } else {
      console.log('[OK] Reason is correct\n');
    }

    // === 3. تنظيف: حذف السجل من القائمة السوداء ===
    if (blacklistEntryId) {
      console.log('=== 3. Cleanup: Remove blacklist entry ===\n');
      const deleteResult = await sendRequest('DELETE', '/blacklist/' + blacklistEntryId, {
        merchantId: MERCHANT_ID
      });
      console.log(`Status: ${deleteResult.status}`);
      if (deleteResult.status === 200) {
        console.log('[OK] Blacklist entry removed\n');
      } else {
        console.log(`[WARN] Could not remove blacklist entry: ${JSON.stringify(deleteResult.body)}\n`);
      }
    }

  } catch (err) {
    console.error(`[ERROR] ${err.message}`);
    passed = false;
  }

  // التقرير النهائي
  console.log('================================');
  console.log(passed ? '[PASS] All tests passed' : '[FAIL] Some tests failed');
  process.exit(passed ? 0 : 1);
})();