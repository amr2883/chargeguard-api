const crypto = require('crypto');

// السر الحقيقي
const secret = 'wc_sec_8d3a7f9e2b1c4d6a5f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0';

// نفس JSON الناجح
const rawBody = '{"id":99999,"status":"processing","total":"49.99","customer_ip_address":"203.0.113.5","merchantId":"test_merchant_001","billing":{"email":"test@example.com","country":"US"},"shipping":{},"payment_details":{"card_bin":"411111"}}';

// حساب التوقيع
const signature = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
console.log('SIGNATURE:' + signature);
