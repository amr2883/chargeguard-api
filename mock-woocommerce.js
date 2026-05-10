// mock-woocommerce.js – خادم وهمي يحاكي WooCommerce Store API
const express = require('express');
const app = express();
app.use(express.json());

// صفحة Checkout وهمية – تُعيد nonce
app.get('/checkout/', (req, res) => {
  const fakeNonce = 'abc123mocknonce' + Date.now();
  res.send(`
    <html>
    <body>
      <input type="hidden" id="woocommerce-process-checkout-nonce" value="${fakeNonce}">
      Welcome to checkout
    </body>
    </html>
  `);
});

// محاكي نقطة Store API
app.post('/wp-json/wc/store/v1/checkout', (req, res) => {
  const nonce = req.headers['nonce'];
  console.log(`[MOCK] Received checkout request with nonce: ${nonce}`);

  // محاكاة قبول الطلب
  res.json({
    order_id: Math.floor(Math.random() * 10000),
    status: 'pending',
    order_key: 'wc_order_' + Date.now()
  });
});

app.listen(8080, () => {
  console.log('🚀 Mock WooCommerce running on http://localhost:8080');
});