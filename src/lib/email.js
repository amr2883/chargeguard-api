const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);

async function sendApiKeyEmail(email, apiKey) {
  await resend.emails.send({
    from: 'ChargeGuard <onboarding@resend.dev>',
    to: email,
    subject: '🔑 Your ChargeGuard API Key',
    html: `
      <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:32px;background:#0b1121;color:#cbd5e1;border-radius:12px;">
        <div style="margin-bottom:24px;">
          <h1 style="color:#f97316;font-size:24px;margin:0;">ChargeGuard</h1>
          <p style="color:#64748b;font-size:14px;margin:4px 0 0;">Early Access</p>
        </div>

        <h2 style="color:#f1f5f9;font-size:20px;">Welcome aboard 🎉</h2>
        <p>Your API key is ready. Copy it now and keep it safe — <strong style="color:#fca5a5;">it grants full access to your store's protection.</strong></p>

        <div style="background:#020617;border:1px dashed #f97316;border-radius:8px;padding:16px 20px;margin:24px 0;word-break:break-all;font-family:monospace;font-size:14px;color:#f97316;">
          ${apiKey}
        </div>

        <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.25);border-radius:8px;padding:12px 16px;margin-bottom:24px;font-size:13px;color:#fca5a5;">
          ⚠️ Never share this key. Treat it like a password.
        </div>

        <h3 style="color:#f1f5f9;font-size:16px;">Next Steps</h3>
        <ol style="color:#cbd5e1;font-size:14px;line-height:2;">
          <li>Download the plugin from your dashboard</li>
          <li>Go to <strong>WooCommerce → Settings → ChargeGuard</strong></li>
          <li>Paste your API key and save</li>
        </ol>

        <hr style="border:none;border-top:1px solid rgba(255,255,255,0.07);margin:24px 0;">
        <p style="font-size:12px;color:#64748b;">This email was sent because you registered for ChargeGuard Early Access. If you didn't register, ignore this email.</p>
      </div>
    `
  });
}

module.exports = { sendApiKeyEmail };