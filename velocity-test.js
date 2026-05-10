const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, ".env.test") });
const crypto = require("crypto");

const secret = process.env.WC_WEBHOOK_SECRET;
if (!secret) {
  console.error("خطأ: WC_WEBHOOK_SECRET غير موجود في .env.test");
  process.exit(1);
}
const baseUrl = "https://Amr453-chargeguard-space.hf.space/api/risk/woocommerce-webhook";

const baseOrder = {
    status: "processing",
    total: "49.99",
    customer_ip_address: "203.0.113.80",
    merchantId: "test_merchant_001",
    billing: {
        email: "gooduser@example.com",
        country: "US"
    },
    shipping: { country: "US" },
    payment_details: {},
    deviceFingerprint: "test-device-velocity"
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
    const signature = crypto.createHmac("sha256", secret).update(rawBody).digest("base64");

    const resp = await fetch(baseUrl, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-WC-Webhook-Signature": signature
        },
        body: rawBody
    });
    return resp.json();
}

(async () => {
    console.log("=== Velocity Isolation Test (Secure) ===\n");
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
        console.log("");
    }
})();
