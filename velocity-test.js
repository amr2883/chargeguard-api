const crypto = require('crypto');

const secret = 'wc_sec_8d3a7f9e2b1c4d6a5f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0';
const baseUrl = 'https://Amr453-chargeguard-space.hf.space/api/risk/woocommerce-webhook';

const baseOrder = {
    status: "processing",
    total: "49.99",
    customer_ip_address: "203.0.113.80",          // IP ثابت لرؤية IP Velocity
    merchantId: "test_merchant_001",
    billing: {
        email: "gooduser@example.com",            // بريد نظيف
        country: "US"
    },
    shipping: { country: "US" },
    payment_details: {},
    deviceFingerprint: "test-device-velocity"    // جهاز ثابت لرؤية Device Velocity
};

const orders = [
    { orderId: "vel-test-1", card_bin: "424242" },
    { orderId: "vel-test-2", card_bin: "424242" },
    { orderId: "vel-test-3", card_bin: "424242" },
    { orderId: "vel-test-4", card_bin: "424242" }
];

async function sendRequest(orderId, card_bin) {
    const order = { ...baseOrder, id: orderId, payment_details: { card_bin } };
    const rawBody = JSON.stringify(order);
    const signature = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');

    const resp = await fetch(baseUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-WC-Webhook-Signature': signature
        },
        body: rawBody
    });
    return resp.json();
}

(async () => {
    console.log('=== Velocity Isolation Test ===\n');
    for (const { orderId, card_bin } of orders) {
        console.log(`Sending ${orderId}...`);
        try {
            const result = await sendRequest(orderId, card_bin);
            console.log(`  Score: ${result.score}  Decision: ${result.decision}  Cached: ${result.cached || false}`);
            if (result.flags && result.flags.length) {
                result.flags.forEach(f => console.log(`    Flag: ${f.text}`));
            }
        } catch (err) {
            console.log(`  Error: ${err.message}`);
        }
        console.log('');
    }
})();
