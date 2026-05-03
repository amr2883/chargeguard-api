const crypto = require('crypto');
const readline = require('readline').createInterface({ input: process.stdin, output: process.stdout });
readline.question('الصق السر الجديد لـ Webhook: ', (secret) => {
  const rawBody = '{"id":99999,"status":"processing","total":"49.99","customer_ip_address":"203.0.113.5","merchantId":"test_merchant_001","billing":{"email":"test@example.com","country":"US"},"shipping":{},"payment_details":{"card_bin":"411111"}}';
  const signature = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
  console.log('\nالتوقيع الصحيح هو:\n' + signature);
  readline.close();
});
