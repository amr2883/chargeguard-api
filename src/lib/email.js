const nodemailer = require('nodemailer');
const MailComposer = require('nodemailer/lib/mail-composer');
const { google } = require('googleapis');

const oauth2Client = new google.auth.OAuth2(
  process.env.GMAIL_OAUTH_CLIENT_ID,
  process.env.GMAIL_OAUTH_CLIENT_SECRET,
  'https://developers.google.com/oauthplayground'
);
oauth2Client.setCredentials({
  refresh_token: process.env.GMAIL_OAUTH_REFRESH_TOKEN,
});
const gmailClient = google.gmail({ version: 'v1', auth: oauth2Client });

async function sendViaGmail({ from, to, subject, html }) {
  const mail = new MailComposer({ from, to, subject, html, encoding: 'UTF-8' });
  const rawBuffer = await new Promise((resolve, reject) => {
    mail.compile().build((err, msg) => {
      if (err) return reject(err);
      resolve(msg);
    });
  });
  const raw = rawBuffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  await gmailClient.users.messages.send({
    userId: 'me',
    requestBody: { raw },
  });
}

async function sendApiKeyEmail(email, apiKey) {
  console.log('[Email] Attempting to send API key email to:', email);

  await sendViaGmail({
    from: `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
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
  await sendViaGmail({
    from: `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
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

async function sendAttackAlertEmail(tenant, attackCount, savedAmount, windowMinutes = 10) {
  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';

  const savedFormatted = savedAmount.toLocaleString('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
  });

  const now = new Date();
  const timeStr = now.toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
    timeZone: 'UTC', timeZoneName: 'short',
  });

  const RETRIES = 3;
  const RETRY_DELAY_MS = 5000;
  const RETRYABLE_ERRORS = [429, 500, 502, 503, 504];

  let lastError;
  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    try {
      console.log(`[AttackAlert] 📡 Attempt ${attempt}/${RETRIES} — sending via Gmail API`);
      await sendViaGmail({
        from: `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
        to: tenant.email,
        subject: `🛡️ ChargeGuard blocked ${attackCount} attacks on ${storeDisplay}`,
    html: `
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:600px;margin:0 auto;background:#ffffff;">

        <!-- Header -->
        <div style="background:#0b1121;padding:24px 32px;border-radius:12px 12px 0 0;">
          <table cellpadding="0" cellspacing="0" style="width:100%;"><tr>
            <td style="vertical-align:middle;">
              <table cellpadding="0" cellspacing="0"><tr>
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
              </tr></table>
            </td>
            <td style="text-align:right;vertical-align:middle;">
              <span style="font-size:11px;color:#64748b;letter-spacing:0.08em;text-transform:uppercase;">${timeStr}</span>
            </td>
          </tr></table>
        </div>

        <!-- Victory Banner -->
        <div style="background:linear-gradient(135deg,#052e16,#14532d);padding:28px 32px;border-left:1px solid #166534;border-right:1px solid #166534;">
          <p style="font-size:13px;letter-spacing:0.1em;text-transform:uppercase;color:#4ade80;margin:0 0 8px;font-weight:600;">⚔️ Attack Neutralized</p>
          <h1 style="font-size:32px;font-weight:800;color:#ffffff;margin:0 0 4px;line-height:1.1;">
            ${attackCount} attacks blocked
          </h1>
          <p style="font-size:15px;color:#86efac;margin:0;">on <strong>${storeDisplay}</strong> in the last ${windowMinutes} minutes</p>
        </div>

        <!-- Stats Row -->
        <div style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;padding:24px 32px;">
          <table cellpadding="0" cellspacing="0" style="width:100%;">
            <tr>
              <td style="width:50%;padding-right:12px;">
                <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;padding:18px 20px;">
                  <p style="font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 6px;">Attacks Blocked</p>
                  <p style="font-size:28px;font-weight:800;color:#0f172a;margin:0;line-height:1;">${attackCount}</p>
                  <p style="font-size:12px;color:#64748b;margin:4px 0 0;">card testing attempts</p>
                </div>
              </td>
              <td style="width:50%;padding-left:12px;">
                <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;padding:18px 20px;">
                  <p style="font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 6px;">Estimated Savings</p>
                  <p style="font-size:28px;font-weight:800;color:#16a34a;margin:0;line-height:1;">${savedFormatted}</p>
                  <p style="font-size:12px;color:#64748b;margin:4px 0 0;">in dispute fees prevented</p>
                </div>
              </td>
            </tr>
          </table>
        </div>

        <!-- What happened -->
        <div style="padding:24px 32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
          <h3 style="font-size:15px;font-weight:600;color:#0f172a;margin:0 0 12px;">What just happened?</h3>
          <p style="font-size:14px;color:#475569;line-height:1.7;margin:0 0 16px;">
            A bot attempted to test stolen card numbers on your store. ChargeGuard's firewall detected the pattern and blocked all <strong>${attackCount} attempts</strong> before any transaction could go through.
          </p>
          <p style="font-size:14px;color:#475569;line-height:1.7;margin:0;">
            Your customers' checkout experience was <strong>not affected</strong>. Only the fraudulent requests were blocked.
          </p>
        </div>

        <!-- CTA -->
        <div style="padding:20px 32px 28px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;text-align:center;">
          <a href="https://chargeguard-api.onrender.com/api/dashboard/page"
             style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#ffffff;font-size:14px;font-weight:600;padding:12px 28px;border-radius:8px;text-decoration:none;letter-spacing:0.01em;">
            View Full Attack Report →
          </a>
        </div>

        <!-- Footer -->
        <div style="background:#f8fafc;padding:20px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
          <p style="font-size:12px;color:#94a3b8;margin:0;line-height:1.6;">
            You're receiving this because ChargeGuard detected an active attack on your store.
            Alerts are sent at most once every 6 hours to avoid inbox flooding.
          </p>
        </div>

      </div>
    `,
  });

  console.log(`[AttackAlert] ✅ Alert sent to ${tenant.email} — ${attackCount} attacks, ${savedFormatted} saved`);
      return;
    } catch (err) {
      lastError = err;
      const code = err?.response?.status || err?.status || err?.code || 'UNKNOWN';
      console.error(`[AttackAlert] ❌ Attempt ${attempt} failed — code: ${code}, message: ${err.message}`);
      if (!RETRYABLE_ERRORS.includes(Number(code)) || attempt === RETRIES) break;
      console.log(`[AttackAlert] ⏳ Retrying in ${RETRY_DELAY_MS / 1000}s...`);
      await new Promise(res => setTimeout(res, RETRY_DELAY_MS));
    }
  }
  throw lastError;
}

async function sendWeeklySummaryEmail({
  tenant,
  thisWeekCount,
  savedAmount,
  prevWeekCount,
  weekOverWeekPct,
  topReason,
  reasonBreakdown,
  weekStart,
  historicalTotal,
}) {
  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';

  const savedFormatted = savedAmount.toLocaleString('en-US', {
    style: 'currency', currency: 'USD', minimumFractionDigits: 2,
  });

  const weekLabel = weekStart.toLocaleString('en-US', {
    month: 'short', day: 'numeric', timeZone: 'UTC',
  });

  // ── Week-over-week badge ────────────────────────────────────────────────
  let wowBadge = '';
  if (weekOverWeekPct === null) {
    wowBadge = `<span style="font-size:12px;color:#64748b;">First active week</span>`;
  } else if (weekOverWeekPct > 0) {
    wowBadge = `<span style="font-size:12px;color:#dc2626;font-weight:600;">↑ ${weekOverWeekPct}% vs last week</span>`;
  } else if (weekOverWeekPct < 0) {
    wowBadge = `<span style="font-size:12px;color:#16a34a;font-weight:600;">↓ ${Math.abs(weekOverWeekPct)}% vs last week</span>`;
  } else {
    wowBadge = `<span style="font-size:12px;color:#64748b;">Same as last week</span>`;
  }

  // ── Contextual tip by topReason ─────────────────────────────────────────
  const TIPS = {
    velocity:     'Most attacks this week were Velocity Abuse. Consider enabling CAPTCHA on your checkout page to slow down automated attempts.',
    card_testing: 'Card Testing bots were active. Avoid free-shipping offers — they lower the cost barrier for bots running test transactions.',
    blacklist:    'ChargeGuard blocked attempts from addresses already on your blacklist. Your rules are working efficiently.',
    pattern:      'Advanced attack patterns were detected and neutralised. The adaptive protection system is running at full capacity.',
  };
  const tip = topReason && TIPS[topReason]
    ? TIPS[topReason]
    : 'Your store was quiet this week. ChargeGuard is monitoring 24/7 — the moment threats appear, they will be stopped.';

  // ── Reason breakdown bars (HTML table — no Unicode blocks) ─────────────
  const reasonLabels = {
    velocity:     'Velocity Abuse',
    card_testing: 'Card Testing',
    blacklist:    'Blacklist Match',
    pattern:      'Pattern Match',
  };

  const barsHtml = reasonBreakdown.length > 0
    ? reasonBreakdown.map(({ reason, count, pct }) => `
        <tr>
          <td style="padding-bottom:10px;">
            <table cellpadding="0" cellspacing="0" style="width:100%;">
              <tr>
                <td style="width:130px;font-size:13px;color:#334155;padding-right:10px;white-space:nowrap;">
                  ${reasonLabels[reason] || reason}
                </td>
                <td style="padding-right:10px;">
                  <div style="background:#e2e8f0;border-radius:4px;height:8px;overflow:hidden;">
                    <div style="background:#f97316;width:${pct}%;height:8px;border-radius:4px;"></div>
                  </div>
                </td>
                <td style="width:40px;font-size:12px;color:#64748b;text-align:right;white-space:nowrap;">
                  ${pct}%
                </td>
              </tr>
            </table>
          </td>
        </tr>
      `).join('')
    : '';

  // ── Shared header HTML (same as other emails) ──────────────────────────
  const headerHtml = `
    <div style="background:#0b1121;padding:24px 32px;border-radius:12px 12px 0 0;">
      <table cellpadding="0" cellspacing="0" style="width:100%;"><tr>
        <td style="vertical-align:middle;">
          <table cellpadding="0" cellspacing="0"><tr>
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
          </tr></table>
        </td>
        <td style="text-align:right;vertical-align:middle;">
          <span style="font-size:11px;color:#64748b;letter-spacing:0.08em;text-transform:uppercase;">Weekly Report — ${weekLabel}</span>
        </td>
      </tr></table>
    </div>`;

  // ── Shared footer HTML ──────────────────────────────────────────────────
  const footerHtml = `
    <div style="background:#f8fafc;padding:20px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
      <p style="font-size:12px;color:#94a3b8;margin:0;line-height:1.6;">
        You're receiving this weekly summary because your store is protected by ChargeGuard.
        Reports are sent every Sunday at 09:00 UTC.
      </p>
    </div>`;

  // ── Build HTML for active week vs quiet week ────────────────────────────
  let bodyHtml;

  if (thisWeekCount > 0) {
    // ── Full weekly summary (active week) ─────────────────────────────────
    bodyHtml = `
      <!-- Victory Banner -->
      <div style="background:linear-gradient(135deg,#052e16,#14532d);padding:28px 32px;border-left:1px solid #166534;border-right:1px solid #166534;">
        <p style="font-size:13px;letter-spacing:0.1em;text-transform:uppercase;color:#4ade80;margin:0 0 6px;font-weight:600;">🛡️ Weekly Protection Report</p>
        <h1 style="font-size:36px;font-weight:800;color:#ffffff;margin:0 0 4px;line-height:1.1;">${thisWeekCount}</h1>
        <p style="font-size:16px;color:#86efac;margin:0 0 12px;">attacks blocked on <strong>${storeDisplay}</strong> this week</p>
        ${wowBadge}
      </div>

      <!-- Savings stat -->
      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;padding:20px 32px;">
        <table cellpadding="0" cellspacing="0" style="width:100%;">
          <tr>
            <td style="width:50%;padding-right:12px;">
              <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;padding:16px 20px;">
                <p style="font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Attacks Blocked</p>
                <p style="font-size:28px;font-weight:800;color:#0f172a;margin:0;line-height:1;">${thisWeekCount}</p>
                <p style="font-size:12px;color:#64748b;margin:4px 0 0;">this week</p>
              </div>
            </td>
            <td style="width:50%;padding-left:12px;">
              <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;padding:16px 20px;">
                <p style="font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Estimated Savings</p>
                <p style="font-size:28px;font-weight:800;color:#16a34a;margin:0;line-height:1;">${savedFormatted}</p>
                <p style="font-size:12px;color:#64748b;margin:4px 0 0;">in dispute fees</p>
              </div>
            </td>
          </tr>
        </table>
      </div>

      <!-- Reason breakdown -->
      ${barsHtml ? `
      <div style="padding:24px 32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
        <h3 style="font-size:14px;font-weight:600;color:#0f172a;margin:0 0 16px;letter-spacing:0.02em;text-transform:uppercase;">Top Threats This Week</h3>
        <table cellpadding="0" cellspacing="0" style="width:100%;">${barsHtml}</table>
      </div>` : ''}

      <!-- Contextual tip -->
      <div style="padding:20px 32px;background:#f0fdf4;border:1px solid #bbf7d0;border-top:none;">
        <p style="font-size:12px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#16a34a;margin:0 0 6px;">💡 Tip of the Week</p>
        <p style="font-size:14px;color:#166534;line-height:1.7;margin:0;">${tip}</p>
      </div>

      <!-- CTA -->
      <div style="padding:20px 32px 28px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;text-align:center;">
        <a href="https://chargeguard-api.onrender.com/api/dashboard/page"
           style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#ffffff;font-size:14px;font-weight:600;padding:12px 28px;border-radius:8px;text-decoration:none;letter-spacing:0.01em;">
          View Full Dashboard →
        </a>
      </div>`;

  } else {
    // ── Quiet week email ──────────────────────────────────────────────────
    const histAttacks = historicalTotal ? historicalTotal.attacks.toLocaleString('en-US') : '—';
    const histSaved   = historicalTotal
      ? historicalTotal.saved.toLocaleString('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 2 })
      : '—';

    bodyHtml = `
      <!-- Quiet banner -->
      <div style="background:#f0fdf4;padding:28px 32px;border-left:1px solid #bbf7d0;border-right:1px solid #bbf7d0;border-top:none;text-align:center;">
        <p style="font-size:32px;margin:0 0 8px;">✅</p>
        <h1 style="font-size:22px;font-weight:700;color:#14532d;margin:0 0 8px;">Quiet week on ${storeDisplay}</h1>
        <p style="font-size:15px;color:#166534;margin:0;">No attacks detected — ChargeGuard is monitoring 24/7</p>
      </div>

      <!-- Historical totals -->
      <div style="padding:24px 32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
        <h3 style="font-size:14px;font-weight:600;color:#0f172a;margin:0 0 16px;">Your Protection Since Day One</h3>
        <table cellpadding="0" cellspacing="0" style="width:100%;">
          <tr>
            <td style="width:50%;padding-right:12px;">
              <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:16px 20px;">
                <p style="font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Total Blocked</p>
                <p style="font-size:26px;font-weight:800;color:#0f172a;margin:0;">${histAttacks}</p>
                <p style="font-size:12px;color:#64748b;margin:4px 0 0;">attacks since you joined</p>
              </div>
            </td>
            <td style="width:50%;padding-left:12px;">
              <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:16px 20px;">
                <p style="font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Total Saved</p>
                <p style="font-size:26px;font-weight:800;color:#16a34a;margin:0;">${histSaved}</p>
                <p style="font-size:12px;color:#64748b;margin:4px 0 0;">in dispute fees prevented</p>
              </div>
            </td>
          </tr>
        </table>
      </div>

      <!-- Tip -->
      <div style="padding:20px 32px 28px;background:#f8fafc;border:1px solid #e2e8f0;border-top:none;">
        <p style="font-size:12px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#64748b;margin:0 0 6px;">💡 Stay Protected</p>
        <p style="font-size:14px;color:#475569;line-height:1.7;margin:0;">${tip}</p>
      </div>`;
  }

  // ── Assemble full email ─────────────────────────────────────────────────
  const fullHtml = `
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:600px;margin:0 auto;background:#ffffff;">
      ${headerHtml}
      ${bodyHtml}
      ${footerHtml}
    </div>`;

  const subject = thisWeekCount > 0
    ? `🛡️ ChargeGuard blocked ${thisWeekCount} attacks on ${storeDisplay} this week`
    : `✅ Quiet week for ${storeDisplay} — ChargeGuard report`;

  // ── Send with retry (same pattern as sendAttackAlertEmail) ──────────────
  const RETRIES          = 3;
  const RETRY_DELAY_MS   = 5000;
  const RETRYABLE_ERRORS = [429, 500, 502, 503, 504];

  let lastError;
  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    try {
      console.log(`[WeeklySummary] 📡 Attempt ${attempt}/${RETRIES} — sending via Gmail API`);
      await sendViaGmail({
        from: `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
        to:   tenant.email,
        subject,
        html: fullHtml,
      });
      console.log(`[WeeklySummary] ✅ Sent to ${tenant.email}`);
      return;
    } catch (err) {
      lastError = err;
      const code = err?.response?.status || err?.status || err?.code || 'UNKNOWN';
      console.error(`[WeeklySummary] ❌ Attempt ${attempt} failed — code: ${code}, message: ${err.message}`);
      if (!RETRYABLE_ERRORS.includes(Number(code)) || attempt === RETRIES) break;
      console.log(`[WeeklySummary] ⏳ Retrying in ${RETRY_DELAY_MS / 1000}s...`);
      await new Promise(res => setTimeout(res, RETRY_DELAY_MS));
    }
  }
  throw lastError;
}

async function sendConfirmationEmail(email, confirmUrl) {
  console.log('[Email] Sending confirmation email to:', email);

  const RETRIES = 3;
  const RETRY_DELAY_MS = 5000;
  const RETRYABLE_ERRORS = [429, 500, 502, 503, 504];

  let lastError;
  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    try {
      console.log(`[Confirmation] 📡 Attempt ${attempt}/${RETRIES} — sending via Gmail API`);
      await sendViaGmail({
        from: `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
        to: email,
        subject: '✉️ Confirm your ChargeGuard account',
        html: `
          <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:600px;margin:0 auto;background:#ffffff;">

            <!-- Header -->
            <div style="background:#0b1121;padding:24px 32px;border-radius:12px 12px 0 0;">
              <table cellpadding="0" cellspacing="0" style="width:100%;"><tr>
                <td style="vertical-align:middle;">
                  <table cellpadding="0" cellspacing="0"><tr>
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
                  </tr></table>
                </td>
                <td style="text-align:right;vertical-align:middle;">
                  <span style="font-size:11px;color:#64748b;letter-spacing:0.08em;text-transform:uppercase;">Email Verification</span>
                </td>
              </tr></table>
            </div>

            <!-- Banner -->
            <div style="background:linear-gradient(135deg,#0f172a,#1e1b4b);padding:28px 32px;border-left:1px solid #312e81;border-right:1px solid #312e81;">
              <p style="font-size:13px;letter-spacing:0.1em;text-transform:uppercase;color:#a5b4fc;margin:0 0 8px;font-weight:600;">✉️ One step away</p>
              <h1 style="font-size:26px;font-weight:800;color:#ffffff;margin:0 0 8px;line-height:1.2;">Confirm your email address</h1>
              <p style="font-size:15px;color:#c7d2fe;margin:0;">to activate your ChargeGuard account</p>
            </div>

            <!-- Body -->
            <div style="padding:32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
              <p style="font-size:15px;color:#475569;margin:0 0 28px;line-height:1.6;">
                Thanks for signing up. Click the button below to verify your email and receive your API key.
              </p>

              <!-- CTA Button -->
              <div style="text-align:center;margin-bottom:28px;">
                <a href="${confirmUrl}"
                   style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#ffffff;font-size:15px;font-weight:700;padding:14px 36px;border-radius:8px;text-decoration:none;letter-spacing:0.01em;">
                  Verify Email Address →
                </a>
              </div>

              <!-- Expiry warning -->
              <div style="background:#fefce8;border:1px solid #fde68a;border-radius:8px;padding:12px 16px;margin-bottom:24px;">
                <p style="font-size:13px;color:#92400e;margin:0;">⏰ <strong>This link expires in 24 hours.</strong> If it expires, you can request a new one from the confirmation page.</p>
              </div>

              <!-- Fallback link -->
              <p style="font-size:12px;color:#94a3b8;margin:0;line-height:1.6;">
                If the button doesn't work, copy and paste this link into your browser:<br/>
                <span style="color:#6366f1;word-break:break-all;">${confirmUrl}</span>
              </p>
            </div>

            <!-- Footer -->
            <div style="background:#f8fafc;padding:20px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
              <p style="font-size:12px;color:#94a3b8;margin:0;line-height:1.6;">
                You received this because you registered for ChargeGuard Early Access. If you didn't sign up, you can safely ignore this email.
              </p>
            </div>

          </div>
        `
      });
      console.log(`[Confirmation] ✅ Sent successfully to: ${email}`);
      return;
    } catch (err) {
      lastError = err;
      const code = err?.response?.status || err?.status || err?.code || 'UNKNOWN';
      console.error(`[Confirmation] ❌ Attempt ${attempt} failed — code: ${code}, message: ${err.message}`);
      if (!RETRYABLE_ERRORS.includes(Number(code)) || attempt === RETRIES) break;
      console.log(`[Confirmation] ⏳ Retrying in ${RETRY_DELAY_MS / 1000}s...`);
      await new Promise(res => setTimeout(res, RETRY_DELAY_MS));
    }
  }
  throw lastError;
}

async function sendWelcomeWithKeyEmail(email, apiKey) {
  console.log('[Email] Sending welcome+key email after verification to:', email);
  await sendApiKeyEmail(email, apiKey);
}

module.exports = { sendApiKeyEmail, sendRotatedKeyEmail, sendAttackAlertEmail, sendWeeklySummaryEmail, sendConfirmationEmail, sendWelcomeWithKeyEmail };