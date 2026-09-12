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
    customer_ip_address: "203.0.113.5",
    merchantId: "test_merchant_001",
    billing: {
        email: "attacker@test.com",
        country: "US"
    },
    shipping: {},
    payment_details: {}
};

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
    const signature = crypto.createHmac("sha256", secret).update(rawBody).digest("base64");

    try {
        const response = await fetch(baseUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-WC-Webhook-Signature": signature
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
    console.log("=== Card Testing Simulation (Secure) ===\n");
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
        console.log("");
    }
})();
