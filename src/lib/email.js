const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD,
  },
});

async function sendApiKeyEmail(email, apiKey) {
  console.log('[Email] Attempting to send API key email to:', email);
  console.log('[Email] GMAIL_USER exists:', !!process.env.GMAIL_USER);

  await transporter.sendMail({
    from: `"ChargeGuard" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: '🔑 Your ChargeGuard API Key',
    html: `
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:600px;margin:0 auto;background:#ffffff;">
        
        <!-- Header -->
        <div style="background:#0b1121;padding:24px 32px;border-radius:12px 12px 0 0;">
          <table cellpadding="0" cellspacing="0" style="width:100%;">
            <tr>
              <td>
                <table cellpadding="0" cellspacing="0">
                  <tr>
                    <td style="padding-right:10px;vertical-align:middle;">
                      <div style="width:32px;height:32px;background:linear-gradient(135deg,#f97316,#ea580c);border-radius:8px;text-align:center;line-height:32px;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="white" xmlns="http://www.w3.org/2000/svg" style="vertical-align:middle;">
                          <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.4C16.5 22.15 20 17.25 20 12V6L12 2zm-1 13l-3-3 1.4-1.4L11 12.2l4.6-4.6L17 9l-6 6z"/>
                        </svg>
                      </div>
                    </td>
                    <td style="vertical-align:middle;">
                      <span style="font-size:20px;font-weight:700;color:#ffffff;letter-spacing:-0.02em;">Charge<span style="color:#f97316;">Guard</span></span>
                    </td>
                  </tr>
                </table>
              </td>
              <td style="text-align:right;vertical-align:middle;">
                <span style="font-size:11px;color:#64748b;letter-spacing:0.08em;text-transform:uppercase;">Early Access</span>
              </td>
            </tr>
          </table>
        </div>

        <!-- Body -->
        <div style="padding:32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
          <h2 style="font-size:22px;font-weight:700;color:#0f172a;margin:0 0 8px;">Welcome aboard 🎉</h2>
          <p style="font-size:15px;color:#475569;margin:0 0 24px;line-height:1.6;">Your ChargeGuard API key is ready. Save it somewhere safe — you'll need it to activate protection on your store.</p>

          <!-- API Key Box -->
          <div style="background:#f8fafc;border:1px solid #e2e8f0;border-left:4px solid #f97316;border-radius:8px;padding:20px 24px;margin-bottom:20px;">
            <p style="font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:#94a3b8;margin:0 0 8px;">Your API Key</p>
            <p style="font-family:'Courier New',Courier,monospace;font-size:13px;color:#0f172a;word-break:break-all;margin:0;line-height:1.6;">${apiKey}</p>
          </div>

          <!-- Warning -->
          <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px 16px;margin-bottom:28px;">
            <p style="font-size:13px;color:#dc2626;margin:0;">⚠️ <strong>Never share this key.</strong> It grants full access to your store's fraud protection — treat it like a password.</p>
          </div>

          <!-- Steps -->
          <h3 style="font-size:15px;font-weight:600;color:#0f172a;margin:0 0 16px;">Get protected in 3 steps</h3>
          <table cellpadding="0" cellspacing="0" style="width:100%;">
            <tr><td style="padding-bottom:12px;">
              <table cellpadding="0" cellspacing="0"><tr>
                <td style="padding-right:12px;vertical-align:top;padding-top:2px;">
                  <div style="width:22px;height:22px;background:#f97316;border-radius:50%;text-align:center;line-height:22px;font-size:12px;font-weight:700;color:white;">1</div>
                </td>
                <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;"><strong style="color:#0f172a;">Install the plugin</strong> — Download and upload via Plugins → Add New → Upload Plugin</p></td>
              </tr></table>
            </td></tr>
            <tr><td style="padding-bottom:12px;">
              <table cellpadding="0" cellspacing="0"><tr>
                <td style="padding-right:12px;vertical-align:top;padding-top:2px;">
                  <div style="width:22px;height:22px;background:#f97316;border-radius:50%;text-align:center;line-height:22px;font-size:12px;font-weight:700;color:white;">2</div>
                </td>
                <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;"><strong style="color:#0f172a;">Activate & configure</strong> — Go to WooCommerce → Settings → ChargeGuard and paste your key</p></td>
              </tr></table>
            </td></tr>
            <tr><td>
              <table cellpadding="0" cellspacing="0"><tr>
                <td style="padding-right:12px;vertical-align:top;padding-top:2px;">
                  <div style="width:22px;height:22px;background:#f97316;border-radius:50%;text-align:center;line-height:22px;font-size:12px;font-weight:700;color:white;">3</div>
                </td>
                <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;"><strong style="color:#0f172a;">You're protected</strong> — The firewall activates instantly. Bots blocked. Fees stopped.</p></td>
              </tr></table>
            </td></tr>
          </table>
        </div>

        <!-- Footer -->
        <div style="background:#f8fafc;padding:20px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
          <p style="font-size:12px;color:#94a3b8;margin:0;line-height:1.6;">You received this email because you signed up for ChargeGuard Early Access. If you didn't register, you can safely ignore this email.</p>
        </div>

      </div>
    `
  });

  console.log('[Email] ✅ Sent successfully to:', email);
}

async function sendRotatedKeyEmail(email, newApiKey) {
  console.log('[Email] Sending rotated API key to:', email);
  await transporter.sendMail({
    from: `"ChargeGuard" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: '🔑 Your ChargeGuard API Key Has Been Rotated',
    html: `
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:600px;margin:0 auto;background:#ffffff;">
        <div style="background:#0b1121;padding:24px 32px;border-radius:12px 12px 0 0;">
          <span style="font-size:20px;font-weight:700;color:#ffffff;">Charge<span style="color:#f97316;">Guard</span></span>
        </div>
        <div style="padding:32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
          <h2 style="font-size:22px;font-weight:700;color:#0f172a;margin:0 0 8px;">API Key Rotated 🔄</h2>
          <p style="font-size:15px;color:#475569;margin:0 0 24px;line-height:1.6;">Your API key has been successfully rotated. Your old key is now invalid.</p>
          <div style="background:#f8fafc;border:1px solid #e2e8f0;border-left:4px solid #f97316;border-radius:8px;padding:20px 24px;margin-bottom:20px;">
            <p style="font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:#94a3b8;margin:0 0 8px;">Your New API Key</p>
            <p style="font-family:'Courier New',Courier,monospace;font-size:13px;color:#0f172a;word-break:break-all;margin:0;line-height:1.6;">${newApiKey}</p>
          </div>
          <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px 16px;margin-bottom:28px;">
            <p style="font-size:13px;color:#dc2626;margin:0;">⚠️ <strong>Action required:</strong> Update your plugin settings immediately with this new key to maintain protection.</p>
          </div>
          <p style="font-size:13px;color:#64748b;">If you didn't request this rotation, contact support immediately.</p>
        </div>
        <div style="background:#f8fafc;padding:20px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
          <p style="font-size:12px;color:#94a3b8;margin:0;">ChargeGuard Security Team</p>
        </div>
      </div>
    `
  });
  console.log('[Email] ✅ Rotation email sent to:', email);
}

module.exports = { sendApiKeyEmail, sendRotatedKeyEmail };