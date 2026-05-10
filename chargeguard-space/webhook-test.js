const crypto = require('crypto');
const http = require('http');

const SECRET = 'wc_sec_i0TegQrx2wCBAFSkJ5InysjGuHhWZqDtPlN8cvUpoMaKmOfb';
const BASE_URL = 'http://localhost:3000/api/risk/woocommerce-webhook';

async function sendRequest(orderId, cardBin) {
  const payload = {
    id: orderId,
    status: "processing",
    total: "19.99",
    customer_ip_address: "203.0.113.200",
    merchantId: "test_merchant_001",
    billing: { email: "attacker@test.com", country: "US" },
    shipping: {},
    payment_details: { card_bin: cardBin },
    deviceFingerprint: "fp_test_blocked_999"
  };

  const rawBody = JSON.stringify(payload);
  const signature = crypto.createHmac('sha256', SECRET).update(rawBody).digest('base64');

  const url = new URL(BASE_URL);
  const options = {
    hostname: url.hostname,
    port: url.port || 3000,
    path: url.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-WC-Webhook-Signature': signature,
      'Content-Length': Buffer.byteLength(rawBody)
    }
  };

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
    req.write(rawBody);
    req.end();
  });
}

(async () => {
  console.log('=== Webhook Signature Test ===\n');
  const cards = [
    { orderId: 'sig-test-1', bin: '411111' },
    { orderId: 'sig-test-2', bin: '550000' },
    { orderId: 'sig-test-3', bin: '340000' },
  ];
  for (const { orderId, bin } of cards) {
    try {
      const { status, body } = await sendRequest(orderId, bin);
      console.log(`[${orderId}] Status: ${status} | Decision: ${body.decision} | Score: ${body.score}`);
    } catch (err) {
      console.log(`[${orderId}] ERROR: ${err.message}`);
    }
    await new Promise(r => setTimeout(r, 500));
  }
})();