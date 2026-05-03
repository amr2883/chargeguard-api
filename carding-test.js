const crypto = require('crypto');

const secret = 'wc_sec_8d3a7f9e2b1c4d6a5f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0';
const baseUrl = 'https://Amr453-chargeguard-space.hf.space/api/risk/woocommerce-webhook';

// بيانات ثابتة عدا orderId و card_bin
const baseOrder = {
    status: "processing",
    total: "49.99",
    customer_ip_address: "203.0.113.5",
    merchantId: "test_merchant_001",
    billing: {
        email: "attacker@test.com",
        country: "US"
    },
    shipping: {},
    payment_details: {}  // سنملؤه لاحقاً
};

// أربع بطاقات مختلفة
const cards = [
    { orderId: "card-test-1", card_bin: "411111" },
    { orderId: "card-test-2", card_bin: "550000" },
    { orderId: "card-test-3", card_bin: "340000" },
    { orderId: "card-test-4", card_bin: "601100" }
];

async function sendRequest(orderId, card_bin) {
    const order = {
        ...baseOrder,
        id: orderId,
        payment_details: { card_bin: card_bin }
    };
    const rawBody = JSON.stringify(order);
    const signature = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');

    try {
        const response = await fetch(baseUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-WC-Webhook-Signature': signature
            },
            body: rawBody
        });
        const result = await response.json();
        return { ok: response.ok, status: response.status, result };
    } catch (err) {
        return { ok: false, error: err.message };
    }
}

(async () => {
    console.log('=== Card Testing Simulation ===\n');
    for (const { orderId, card_bin } of cards) {
        console.log(`Sending ${orderId} with card ${card_bin}...`);
        const { ok, status, result } = await sendRequest(orderId, card_bin);
        if (ok) {
            console.log(`  Status: ${status}  Decision: ${result.decision}  Score: ${result.score}`);
            if (result.flags && result.flags.length > 0) {
                result.flags.forEach(f => console.log(`    Flag: ${f.text}`));
            }
        } else {
            console.log(`  FAILED: ${result.error || JSON.stringify(result)}`);
        }
        console.log('');
    }
})();
