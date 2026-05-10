const crypto = require("crypto");
const readline = require("readline").createInterface({ input: process.stdin, output: process.stdout });

console.log("أدخل السر الجديد لـ Webhook (أو اضغط Enter لاستخدام .env.test):");
readline.question("", (secret) => {
  if (!secret) {
    const path = require("path");
    require("dotenv").config({ path: path.resolve(__dirname, ".env.test") });
    secret = process.env.WC_WEBHOOK_SECRET;
    if (!secret) {
      console.error("خطأ: لم يتم توفير مفتاح");
      process.exit(1);
    }
    console.log("تم استخدام المفتاح من .env.test");
  }
  const rawBody = "{\"id\":99999,\"status\":\"processing\",\"total\":\"49.99\",\"customer_ip_address\":\"203.0.113.5\",\"merchantId\":\"test_merchant_001\",\"billing\":{\"email\":\"test@example.com\",\"country\":\"US\"},\"shipping\":{},\"payment_details\":{\"card_bin\":\"411111\"}}";
  const signature = crypto.createHmac("sha256", secret).update(rawBody).digest("base64");
  console.log("\nالتوقيع الصحيح هو:\n" + signature);
  readline.close();
});
