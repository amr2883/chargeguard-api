const nodemailer = require('nodemailer');
const MailComposer = require('nodemailer/lib/mail-composer');
const { google } = require('googleapis');
const { isProOrAbove } = require('./planAccess');
const oauth2Client = new google.auth.OAuth2(
  process.env.GMAIL_OAUTH_CLIENT_ID,
  process.env.GMAIL_OAUTH_CLIENT_SECRET,
  'https://developers.google.com/oauthplayground'
);
oauth2Client.setCredentials({
  refresh_token: process.env.GMAIL_OAUTH_REFRESH_TOKEN,
});
const gmailClient = google.gmail({ version: 'v1', auth: oauth2Client });

// L5 fix: escapes HTML metacharacters in tenant-supplied values (primarily
// tenant.storeUrl / storeDisplay) before they're interpolated into HTML
// email bodies. Applied at the point of interpolation, not globally — the
// raw value stays available for non-HTML uses (e.g. email subject lines,
// which must NOT be HTML-escaped since they're plain text headers, not
// HTML). Standard OWASP output-encoding: encode for the context you're
// writing into, at the point you write into it.
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

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
  // L5 fix: escaped sibling of apiKey — same pattern as storeDisplaySafe.
  const apiKeySafe = escapeHtml(apiKey);

  const html = `
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
          <p style="font-family:'Courier New',Courier,monospace;font-size:13px;color:#0f172a;word-break:break-all;margin:0;line-height:1.6;">${apiKeySafe}</p>
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
  `;

  const RETRIES = 3;
  const RETRY_DELAY_MS = 5000;
  const RETRYABLE_ERRORS = [429, 500, 502, 503, 504];
  let lastError;

  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    try {
      console.log(`[ApiKeyEmail] 📡 Attempt ${attempt}/${RETRIES} → ${email}`);
      await sendViaGmail({
        from: `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
        to: email,
        subject: '🔑 Your ChargeGuard API Key',
        html,
      });
      console.log(`[ApiKeyEmail] ✅ Sent successfully to: ${email}`);
      return;
    } catch (err) {
      lastError = err;
      const code = err?.response?.status || err?.status || err?.code || 'UNKNOWN';
      console.error(`[ApiKeyEmail] ❌ Attempt ${attempt} failed — code: ${code}, message: ${err.message}`);
      if (!RETRYABLE_ERRORS.includes(Number(code)) || attempt === RETRIES) break;
      console.log(`[ApiKeyEmail] ⏳ Retrying in ${RETRY_DELAY_MS / 1000}s...`);
      await new Promise(res => setTimeout(res, RETRY_DELAY_MS));
    }
  }
  throw lastError;
}

async function sendRotatedKeyEmail(email, newApiKey) {
  // L5 fix: escaped sibling of newApiKey.
  const newApiKeySafe = escapeHtml(newApiKey);
  const html = `
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:600px;margin:0 auto;background:#ffffff;">
      <div style="background:#0b1121;padding:24px 32px;border-radius:12px 12px 0 0;">
        <span style="font-size:20px;font-weight:700;color:#ffffff;">Charge<span style="color:#f97316;">Guard</span></span>
      </div>
      <div style="padding:32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
        <h2 style="font-size:22px;font-weight:700;color:#0f172a;margin:0 0 8px;">API Key Rotated 🔄</h2>
        <p style="font-size:15px;color:#475569;margin:0 0 24px;line-height:1.6;">Your API key has been successfully rotated. Your old key is now invalid.</p>
        <div style="background:#f8fafc;border:1px solid #e2e8f0;border-left:4px solid #f97316;border-radius:8px;padding:20px 24px;margin-bottom:20px;">
          <p style="font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:#94a3b8;margin:0 0 8px;">Your New API Key</p>
          <p style="font-family:'Courier New',Courier,monospace;font-size:13px;color:#0f172a;word-break:break-all;margin:0;line-height:1.6;">${newApiKeySafe}</p>
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
  `;

  const RETRIES = 3;
  const RETRY_DELAY_MS = 5000;
  const RETRYABLE_ERRORS = [429, 500, 502, 503, 504];
  let lastError;

  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    try {
      console.log(`[RotatedKeyEmail] 📡 Attempt ${attempt}/${RETRIES} → ${email}`);
      await sendViaGmail({
        from: `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
        to: email,
        subject: '🔑 Your ChargeGuard API Key Has Been Rotated',
        html,
      });
      console.log(`[RotatedKeyEmail] ✅ Rotation email sent to: ${email}`);
      return;
    } catch (err) {
      lastError = err;
      const code = err?.response?.status || err?.status || err?.code || 'UNKNOWN';
      console.error(`[RotatedKeyEmail] ❌ Attempt ${attempt} failed — code: ${code}, message: ${err.message}`);
      if (!RETRYABLE_ERRORS.includes(Number(code)) || attempt === RETRIES) break;
      console.log(`[RotatedKeyEmail] ⏳ Retrying in ${RETRY_DELAY_MS / 1000}s...`);
      await new Promise(res => setTimeout(res, RETRY_DELAY_MS));
    }
  }
  throw lastError;
}

async function sendAttackAlertEmail(tenant, attackCount, savedAmount, windowMinutes = 10) {
  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';
  // L5 fix: HTML-escaped sibling of storeDisplay — used only where
  // storeDisplay is interpolated into the HTML body below. The subject
  // line further down keeps using the raw storeDisplay, since subjects
  // are plain text, not HTML.
  const storeDisplaySafe = escapeHtml(storeDisplay);

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
          <p style="font-size:15px;color:#86efac;margin:0;">on <strong>${storeDisplaySafe}</strong> in the last ${windowMinutes} minutes</p>
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
  // L5 fix: HTML-escaped sibling — see escapeHtml() definition above.
  const storeDisplaySafe = escapeHtml(storeDisplay);

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
                  ${escapeHtml(reasonLabels[reason] || reason)}
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
        <p style="font-size:16px;color:#86efac;margin:0 0 12px;">attacks blocked on <strong>${storeDisplaySafe}</strong> this week</p>
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
        <h1 style="font-size:22px;font-weight:700;color:#14532d;margin:0 0 8px;">Quiet week on ${storeDisplaySafe}</h1>
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
  // L5 fix: escaped sibling of confirmUrl, used in both href and text below.
  const confirmUrlSafe = escapeHtml(confirmUrl);

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
                <a href="${confirmUrlSafe}"
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
                <span style="color:#6366f1;word-break:break-all;">${confirmUrlSafe}</span>
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

async function sendMonthlyReportEmail({ tenant, reportData, downloadUrl }) {
  const {
    monthName, year, totalAttacks, totalProtected, totalFeesSaved,
    securityScore, reasonBreakdown, threatOrigins,
    prevMonthAttacks, monthOverMonthPct, historicalProtected,
    totalTenants, biggestBINAttack,
  } = reportData;

  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';
  // L5 fix: HTML-escaped sibling — see escapeHtml() definition above.
  const storeDisplaySafe = escapeHtml(storeDisplay);

  const fmtUSD = (n) => n.toLocaleString('en-US', {
    style: 'currency', currency: 'USD', minimumFractionDigits: 0,
  });

 // Centralized helper (planAccess.js) instead of a hand-rolled exclusion
  // check — the old check (`!== 'early_access' && !== 'free'`) incorrectly
  // evaluated 'starter' tenants as Pro, suppressing the upgrade CTA they
  // should see. isProOrAbove() is the single source of truth for plan
  // gating elsewhere in the codebase (dashboard.js, notify.js, risk.js).
  const isPro = isProOrAbove(tenant.plan);
  // ── Week-over-month badge ──────────────────────────────────────────────
  let momBadge = '';
  if (monthOverMonthPct === null) {
    momBadge = `<span style="font-size:12px;color:#64748b;">First month on record</span>`;
  } else if (monthOverMonthPct > 0) {
    momBadge = `<span style="font-size:12px;color:#dc2626;font-weight:600;">↑ ${monthOverMonthPct}% vs last month</span>`;
  } else if (monthOverMonthPct < 0) {
    momBadge = `<span style="font-size:12px;color:#16a34a;font-weight:600;">↓ ${Math.abs(monthOverMonthPct)}% vs last month</span>`;
  } else {
    momBadge = `<span style="font-size:12px;color:#64748b;">Same as last month</span>`;
  }

  // ── Reason bars (نفس pattern الـ Weekly Summary) ─────────────────────
  const reasonLabels = {
    velocity: 'Velocity Abuse', card_testing: 'Card Testing',
    blacklist: 'Blacklist Match', pattern: 'Pattern Match',
  };
  const barsHtml = reasonBreakdown.slice(0, 4).map(({ reason, pct }) => `
    <tr><td style="padding-bottom:10px;">
      <table cellpadding="0" cellspacing="0" style="width:100%;"><tr>
        <td style="width:130px;font-size:13px;color:#334155;padding-right:10px;white-space:nowrap;">
          ${escapeHtml(reasonLabels[reason] || reason)}
        </td>
        <td style="padding-right:10px;">
          <div style="background:#e2e8f0;border-radius:4px;height:8px;overflow:hidden;">
            <div style="background:#f97316;width:${pct}%;height:8px;border-radius:4px;"></div>
          </div>
        </td>
        <td style="width:40px;font-size:12px;color:#64748b;text-align:right;white-space:nowrap;">
          ${pct}%
        </td>
      </tr></table>
    </td></tr>`).join('');

  // ── Country flags ─────────────────────────────────────────────────────
  const flagEmoji = (code) => {
    if (!code || code.length !== 2) return '🌐';
    return code.toUpperCase().replace(/./g,
      c => String.fromCodePoint(c.charCodeAt(0) + 127397));
  };
  const countriesHtml = threatOrigins.slice(0, 3).map(o =>
    `<span style="margin-right:8px;">${flagEmoji(o.country)} ${escapeHtml(o.country)} (${o.count})</span>`
  ).join('');

  // ── BIN Attack Highlight ──────────────────────────────────────────────
  const binHighlight = biggestBINAttack ? `
    <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:14px 18px;margin-bottom:16px;">
      <p style="font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#c2410c;margin:0 0 6px;">
        ⚡ Biggest Attack This Month
      </p>
      <p style="font-size:14px;color:#7c2d12;margin:0;line-height:1.6;">
        A coordinated BIN sequence attack on prefix
        <strong>${escapeHtml(biggestBINAttack.binPrefix)}xx</strong> involved
        <strong>${biggestBINAttack.cardsCount} cards</strong> and was fully contained.
        Your customers noticed nothing.
      </p>
    </div>` : '';

  // ── Social Proof ──────────────────────────────────────────────────────
  const socialProof = totalTenants > 5 ? `
    <p style="font-size:13px;color:#64748b;line-height:1.6;margin:0 0 20px;">
      Your store is protected alongside
      <strong style="color:#0f172a;">${totalTenants.toLocaleString('en-US')} merchants</strong>
      in the ChargeGuard network. Threats we block for others protect you automatically.
    </p>` : '';

  // ── CTA section ───────────────────────────────────────────────────────
  const ctaSection = `
    <div style="text-align:center;margin-bottom:24px;">
      <a href="${escapeHtml(downloadUrl)}"
         style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);
                color:#fff;font-size:14px;font-weight:700;padding:13px 32px;
                border-radius:8px;text-decoration:none;letter-spacing:.01em;
                margin-bottom:12px;">
        ↓ Download Full PDF Report
      </a>
      ${!isPro ? `<br/><a href="mailto:support@chargeguard.io?subject=Upgrade to Pro"
         style="display:inline-block;margin-top:10px;font-size:12px;color:#6366f1;
                text-decoration:none;font-weight:600;">
        🔓 Upgrade to Pro — Unlock Compliance Pack & Full Archive →
      </a>` : ''}
    </div>`;

  const fullHtml = `
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:600px;margin:0 auto;background:#ffffff;">

      <!-- Header — نفس pattern الـ email.js الحالي -->
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
                <span style="font-size:20px;font-weight:700;color:#fff;letter-spacing:-.02em;">Charge<span style="color:#f97316;">Guard</span></span>
              </td>
            </tr></table>
          </td>
          <td style="text-align:right;vertical-align:middle;">
            <span style="font-size:11px;color:#64748b;letter-spacing:.08em;text-transform:uppercase;">
              ${monthName} ${year} Report
            </span>
          </td>
        </tr></table>
      </div>

      <!-- Hero — Peak Moment (Kahneman) -->
      <div style="background:linear-gradient(135deg,#052e16,#14532d);padding:32px;border-left:1px solid #166534;border-right:1px solid #166534;">
        <p style="font-size:12px;letter-spacing:.1em;text-transform:uppercase;color:#4ade80;margin:0 0 8px;font-weight:600;">
          🛡️ ${monthName} ${year} — Monthly Security Report
        </p>
        <h1 style="font-size:42px;font-weight:800;color:#ffffff;margin:0 0 4px;line-height:1;letter-spacing:-.03em;">
          ${fmtUSD(totalProtected)}
        </h1>
        <p style="font-size:15px;color:#86efac;margin:0 0 10px;">
          in fraud value blocked from <strong>${storeDisplaySafe}</strong> this month
        </p>
        ${momBadge}
      </div>

      <!-- Stats Row -->
      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;padding:20px 32px;">
        <table cellpadding="0" cellspacing="0" style="width:100%;"><tr>
          <td style="width:33%;padding-right:8px;">
            <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:16px;">
              <p style="font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Attacks Blocked</p>
              <p style="font-size:26px;font-weight:800;color:#0f172a;margin:0;line-height:1;">${totalAttacks.toLocaleString('en-US')}</p>
            </div>
          </td>
          <td style="width:33%;padding-right:8px;padding-left:4px;">
            <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:16px;">
              <p style="font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Fees Saved</p>
              <p style="font-size:26px;font-weight:800;color:#16a34a;margin:0;line-height:1;">${fmtUSD(totalFeesSaved)}</p>
            </div>
          </td>
          <td style="width:33%;padding-left:8px;">
            <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:16px;">
              <p style="font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Security Score</p>
              <p style="font-size:26px;font-weight:800;color:#3b82f6;margin:0;line-height:1;">${securityScore}<span style="font-size:14px;color:#94a3b8;">/100</span></p>
            </div>
          </td>
        </tr></table>
      </div>

      <!-- Body Content -->
      <div style="padding:24px 32px;background:#fff;border:1px solid #e2e8f0;border-top:none;">

        ${binHighlight}

        ${barsHtml ? `
        <h3 style="font-size:13px;font-weight:600;color:#0f172a;margin:0 0 14px;letter-spacing:.04em;text-transform:uppercase;">
          Attack Breakdown
        </h3>
        <table cellpadding="0" cellspacing="0" style="width:100%;margin-bottom:20px;">${barsHtml}</table>` : ''}

        ${countriesHtml ? `
        <h3 style="font-size:13px;font-weight:600;color:#0f172a;margin:0 0 10px;letter-spacing:.04em;text-transform:uppercase;">
          Top Threat Origins
        </h3>
        <div style="margin-bottom:20px;font-size:14px;color:#475569;">${countriesHtml}</div>` : ''}

        ${socialProof}

        <!-- Historical total — Endowment Effect -->
        ${historicalProtected > totalProtected ? `
        <div style="background:#f0f9ff;border:1px solid #bae6fd;border-radius:8px;padding:14px 18px;margin-bottom:20px;">
          <p style="font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#0369a1;margin:0 0 4px;">
            📊 Since You Joined ChargeGuard
          </p>
          <p style="font-size:22px;font-weight:800;color:#0c4a6e;margin:0;">
            ${fmtUSD(historicalProtected)}
            <span style="font-size:13px;font-weight:400;color:#0369a1;"> total fraud value blocked</span>
          </p>
        </div>` : ''}

        ${ctaSection}

        <!-- End Rule — الجملة الأخيرة تبقى في الذاكرة -->
        <div style="text-align:center;padding:16px 0 4px;">
          <p style="font-size:15px;font-weight:600;color:#0f172a;margin:0 0 4px;">
            ${storeDisplaySafe} was safe every day in ${monthName}. ✓
          </p>
          <p style="font-size:13px;color:#64748b;margin:0;">
            We'll be here in ${new Intl.DateTimeFormat('en-US',{month:'long'}).format(new Date(reportData.year, reportData.month, 1))} too.
          </p>
        </div>
      </div>

      <!-- Footer -->
      <div style="background:#f8fafc;padding:20px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
        <p style="font-size:12px;color:#94a3b8;margin:0;line-height:1.6;">
          You're receiving this because your store is protected by ChargeGuard.
          Monthly reports are generated on the 1st of each month.
        </p>
      </div>
    </div>`;

  // ── إرسال مع retry — نفس pattern الموجود في email.js ──────────────────
  const RETRIES = 3;
  const RETRY_DELAY_MS = 5000;
  const RETRYABLE_ERRORS = [429, 500, 502, 503, 504];
  let lastError;
  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    try {
      await sendViaGmail({
        from:    `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
        to:      tenant.email,
        subject: `📋 Your ${monthName} ${year} Security Report — ${storeDisplay}`,
        html:    fullHtml,
      });
      console.log(`[MonthlyReport] ✅ Sent to ${tenant.email} — ${monthName} ${year}`);
      return;
    } catch (err) {
      lastError = err;
      const code = err?.response?.status || err?.status || 'UNKNOWN';
      if (!RETRYABLE_ERRORS.includes(Number(code)) || attempt === RETRIES) break;
      await new Promise(res => setTimeout(res, RETRY_DELAY_MS));
    }
  }
  throw lastError;
}

async function sendPaypalWeeklyReportEmail({
  tenant,
  weekStart,
  paypalTxnCount,
  paypalBlockedCount,
  paypalFlaggedCount,
  savedAmount,
  topCardCountry,
  weekOverWeekPct,
  historicalPaypalTotal,
}) {
  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';
  // L5 fix: HTML-escaped sibling — see escapeHtml() definition above.
  const storeDisplaySafe = escapeHtml(storeDisplay);

  const savedFormatted = savedAmount.toLocaleString('en-US', {
    style: 'currency', currency: 'USD', minimumFractionDigits: 2,
  });

  const weekLabel = weekStart.toLocaleString('en-US', {
    month: 'short', day: 'numeric', timeZone: 'UTC',
  });

  // ── Week-over-week badge ───────────────────────────────────────────────
  let wowBadge = '';
  if (weekOverWeekPct === null) {
    wowBadge = `<span style="font-size:12px;color:#64748b;">First active PayPal week</span>`;
  } else if (weekOverWeekPct > 0) {
    wowBadge = `<span style="font-size:12px;color:#dc2626;font-weight:600;">↑ ${weekOverWeekPct}% vs last week</span>`;
  } else if (weekOverWeekPct < 0) {
    wowBadge = `<span style="font-size:12px;color:#16a34a;font-weight:600;">↓ ${Math.abs(weekOverWeekPct)}% vs last week</span>`;
  } else {
    wowBadge = `<span style="font-size:12px;color:#64748b;">Same as last week</span>`;
  }

  // ── Historical total block ─────────────────────────────────────────────
  const histHtml = historicalPaypalTotal && historicalPaypalTotal.count > paypalBlockedCount
    ? `<div style="background:#f0f9ff;border:1px solid #bae6fd;border-radius:8px;padding:14px 18px;margin-bottom:20px;">
         <p style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#0369a1;margin:0 0 4px;">📊 PayPal Shield — All Time</p>
         <p style="font-size:22px;font-weight:800;color:#0c4a6e;margin:0;">
           ${historicalPaypalTotal.count.toLocaleString('en-US')}
           <span style="font-size:13px;font-weight:400;color:#0369a1;"> suspicious PayPal transactions intercepted</span>
         </p>
       </div>`
    : '';

  // ── Active week vs quiet week ──────────────────────────────────────────
  let bodyHtml;

  if (paypalBlockedCount > 0 || paypalFlaggedCount > 0) {
    const totalIntercepted = paypalBlockedCount + paypalFlaggedCount;
    bodyHtml = `
      <!-- PayPal Hero Banner -->
      <div style="background:linear-gradient(135deg,#0c1a3a,#1e3a5f);padding:28px 32px;border-left:1px solid #1d4ed8;border-right:1px solid #1d4ed8;">
        <p style="font-size:12px;letter-spacing:0.1em;text-transform:uppercase;color:#93c5fd;margin:0 0 8px;font-weight:600;">🛡️ PayPal Shield — Weekly Report</p>
        <h1 style="font-size:36px;font-weight:800;color:#ffffff;margin:0 0 4px;line-height:1.1;">${totalIntercepted}</h1>
        <p style="font-size:15px;color:#bfdbfe;margin:0 0 10px;">suspicious PayPal transactions intercepted on <strong>${storeDisplaySafe}</strong></p>
        ${wowBadge}
      </div>

      <!-- Stats Row -->
      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;padding:20px 32px;">
        <table cellpadding="0" cellspacing="0" style="width:100%;">
          <tr>
            <td style="width:33%;padding-right:8px;">
              <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;padding:16px;">
                <p style="font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Blocked</p>
                <p style="font-size:26px;font-weight:800;color:#dc2626;margin:0;line-height:1;">${paypalBlockedCount}</p>
                <p style="font-size:11px;color:#64748b;margin:3px 0 0;">hard blocks</p>
              </div>
            </td>
            <td style="width:33%;padding-right:8px;padding-left:4px;">
              <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;padding:16px;">
                <p style="font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Flagged</p>
                <p style="font-size:26px;font-weight:800;color:#d97706;margin:0;line-height:1;">${paypalFlaggedCount}</p>
                <p style="font-size:11px;color:#64748b;margin:3px 0 0;">for review</p>
              </div>
            </td>
            <td style="width:33%;padding-left:8px;">
              <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;padding:16px;">
                <p style="font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Est. Savings</p>
                <p style="font-size:26px;font-weight:800;color:#16a34a;margin:0;line-height:1;">${savedFormatted}</p>
                <p style="font-size:11px;color:#64748b;margin:3px 0 0;">fees avoided</p>
              </div>
            </td>
          </tr>
        </table>
      </div>

      <!-- Top Card Origin -->
      ${topCardCountry ? `
      <div style="padding:20px 32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
        <p style="font-size:13px;font-weight:600;color:#0f172a;margin:0 0 8px;">Top Card Origin This Week</p>
        <p style="font-size:14px;color:#475569;margin:0;">Most suspicious PayPal cards this week originated from <strong style="color:#0f172a;">${escapeHtml(topCardCountry)}</strong>. ChargeGuard flagged them before any transaction was processed.</p>
      </div>` : ''}

      <!-- Historical -->
      <div style="padding:20px 32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
        ${histHtml}
      </div>

      <!-- Reassurance + Soft Pro CTA -->
      <div style="padding:16px 32px 20px;background:#f0fdf4;border:1px solid #bbf7d0;border-top:none;">
        <p style="font-size:14px;color:#166534;margin:0 0 8px;font-weight:600;">✅ PayPal is protected. Your store processed ${paypalTxnCount} PayPal transactions normally this week.</p>
        <p style="font-size:13px;color:#166534;margin:0;line-height:1.6;">ChargeGuard monitors every PayPal transaction the same way it monitors Stripe — silently, in the background.</p>
      </div>

      <!-- CTA -->
      <div style="padding:20px 32px 28px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;text-align:center;">
        <a href="https://chargeguard-api.onrender.com/api/dashboard/page"
           style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#ffffff;font-size:14px;font-weight:600;padding:12px 28px;border-radius:8px;text-decoration:none;letter-spacing:0.01em;">
          View PayPal Activity →
        </a>
      </div>`;

  } else {
    // Quiet week
    bodyHtml = `
      <!-- Quiet Banner -->
      <div style="background:#f0fdf4;padding:28px 32px;border-left:1px solid #bbf7d0;border-right:1px solid #bbf7d0;text-align:center;">
        <p style="font-size:32px;margin:0 0 8px;">🛡️</p>
        <h1 style="font-size:22px;font-weight:700;color:#14532d;margin:0 0 8px;">PayPal was clean this week</h1>
        <p style="font-size:15px;color:#166534;margin:0;">No suspicious PayPal transactions detected — monitoring is active 24/7</p>
      </div>

      <!-- Historical -->
      ${histHtml ? `<div style="padding:20px 32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">${histHtml}</div>` : ''}

      <!-- Reassurance -->
      <div style="padding:20px 32px 28px;background:#f8fafc;border:1px solid #e2e8f0;border-top:none;">
        <p style="font-size:13px;color:#475569;margin:0;line-height:1.7;">PayPal Shield scans every transaction in real time. A quiet week means the firewall is doing its job — silently blocking threats before they register.</p>
      </div>`;
  }

  const subject = (paypalBlockedCount + paypalFlaggedCount) > 0
    ? `🛡️ PayPal Shield blocked ${paypalBlockedCount + paypalFlaggedCount} suspicious transactions on ${storeDisplay}`
    : `✅ Clean PayPal week for ${storeDisplay} — Shield Report`;

  const fullHtml = `
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
            <span style="font-size:11px;color:#64748b;letter-spacing:0.08em;text-transform:uppercase;">PayPal Shield — ${weekLabel}</span>
          </td>
        </tr></table>
      </div>
      ${bodyHtml}
      <!-- Footer -->
      <div style="background:#f8fafc;padding:20px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
        <p style="font-size:12px;color:#94a3b8;margin:0;line-height:1.6;">
          You're receiving this because your store's PayPal integration is monitored by ChargeGuard.
          PayPal Shield reports are sent every Sunday at 09:30 UTC.
        </p>
      </div>
    </div>`;

  const RETRIES          = 3;
  const RETRY_DELAY_MS   = 5000;
  const RETRYABLE_ERRORS = [429, 500, 502, 503, 504];
  let lastError;

  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    try {
      console.log(`[PaypalWeekly] 📡 Attempt ${attempt}/${RETRIES} — sending via Gmail API`);
      await sendViaGmail({
        from:    `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
        to:      tenant.email,
        subject,
        html:    fullHtml,
      });
      console.log(`[PaypalWeekly] ✅ Sent to ${tenant.email}`);
      return;
    } catch (err) {
      lastError = err;
      const code = err?.response?.status || err?.status || err?.code || 'UNKNOWN';
      console.error(`[PaypalWeekly] ❌ Attempt ${attempt} failed — code: ${code}, message: ${err.message}`);
      if (!RETRYABLE_ERRORS.includes(Number(code)) || attempt === RETRIES) break;
      console.log(`[PaypalWeekly] ⏳ Retrying in ${RETRY_DELAY_MS / 1000}s...`);
      await new Promise(res => setTimeout(res, RETRY_DELAY_MS));
    }
  }
  throw lastError;
}

// ══════════════════════════════════════════════════════════════════════════════
// sendRenewalReminderEmail — تحذير "اشتراكك ينتهي خلال X أيام"
// يُرسل عند: 7 أيام، 3 أيام، 1 يوم
// ══════════════════════════════════════════════════════════════════════════════
async function sendRenewalReminderEmail(tenant, { daysRemaining, planLabel, renewUrl }) {
  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';
  // L5 fix: HTML-escaped sibling — see escapeHtml() definition above.
  const storeDisplaySafe = escapeHtml(storeDisplay);

  const urgency = daysRemaining <= 1
    ? { color: '#dc2626', bg: '#fef2f2', border: '#fecaca', badge: '🚨 Last chance', tone: 'Your protection expires tomorrow.' }
    : daysRemaining <= 3
    ? { color: '#d97706', bg: '#fffbeb', border: '#fde68a', badge: '⚠️ Expiring soon', tone: `${daysRemaining} days left on your subscription.` }
    : { color: '#0369a1', bg: '#f0f9ff', border: '#bae6fd', badge: '📅 Renewal reminder', tone: `Your subscription renews in ${daysRemaining} days.` };

  const html = `
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
            <span style="font-size:11px;color:#64748b;letter-spacing:0.08em;text-transform:uppercase;">${urgency.badge}</span>
          </td>
        </tr></table>
      </div>

      <!-- Urgency Banner -->
      <div style="background:${urgency.bg};padding:28px 32px;border-left:1px solid ${urgency.border};border-right:1px solid ${urgency.border};">
        <h1 style="font-size:24px;font-weight:800;color:${urgency.color};margin:0 0 8px;line-height:1.2;">
          ${urgency.tone}
        </h1>
        <p style="font-size:15px;color:#475569;margin:0;">
          Renew your <strong>${planLabel}</strong> plan to keep <strong>${storeDisplaySafe}</strong> protected without interruption.
        </p>
      </div>

      <!-- What happens -->
      <div style="padding:24px 32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
        <h3 style="font-size:15px;font-weight:600;color:#0f172a;margin:0 0 16px;">What happens if your subscription expires?</h3>
        <table cellpadding="0" cellspacing="0" style="width:100%;">
          <tr><td style="padding-bottom:12px;">
            <table cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:12px;vertical-align:top;padding-top:2px;width:28px;">
                <div style="width:22px;height:22px;background:#fef2f2;border:1px solid #fecaca;border-radius:50%;text-align:center;line-height:20px;font-size:12px;">❌</div>
              </td>
              <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;">Card testing protection pauses — bots can resume probing your checkout</p></td>
            </tr></table>
          </td></tr>
          <tr><td style="padding-bottom:12px;">
            <table cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:12px;vertical-align:top;padding-top:2px;width:28px;">
                <div style="width:22px;height:22px;background:#fef2f2;border:1px solid #fecaca;border-radius:50%;text-align:center;line-height:20px;font-size:12px;">❌</div>
              </td>
              <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;">BIN sequence detection and Identity Graph go offline</p></td>
            </tr></table>
          </td></tr>
          <tr><td>
            <table cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:12px;vertical-align:top;padding-top:2px;width:28px;">
                <div style="width:22px;height:22px;background:#fef2f2;border:1px solid #fecaca;border-radius:50%;text-align:center;line-height:20px;font-size:12px;">❌</div>
              </td>
              <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;">Your store reverts to the free plan (500 attacks/month limit)</p></td>
            </tr></table>
          </td></tr>
        </table>
      </div>

      <!-- CTA -->
      <div style="padding:24px 32px 28px;background:#f8fafc;border:1px solid #e2e8f0;border-top:none;text-align:center;">
        <a href="${renewUrl}"
           style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#ffffff;font-size:15px;font-weight:700;padding:14px 36px;border-radius:8px;text-decoration:none;letter-spacing:0.01em;">
          Renew ${planLabel} Now →
        </a>
        <p style="font-size:12px;color:#94a3b8;margin:16px 0 0;">
          Secure checkout via PayPal. Your data is never stored on our servers.
        </p>
      </div>

      <!-- Footer -->
      <div style="background:#f8fafc;padding:20px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
        <p style="font-size:12px;color:#94a3b8;margin:0;line-height:1.6;">
          You're receiving this because your ChargeGuard subscription is approaching its renewal date.
        </p>
      </div>
    </div>`;

  const subject = daysRemaining <= 1
    ? `🚨 ChargeGuard protection expires tomorrow — renew now`
    : `⚠️ Your ChargeGuard subscription expires in ${daysRemaining} days`;

  const RETRIES = 3;
  const RETRY_DELAY_MS = 5000;
  const RETRYABLE_ERRORS = [429, 500, 502, 503, 504];
  let lastError;

  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    try {
      console.log(`[RenewalReminder] 📡 Attempt ${attempt}/${RETRIES} → ${tenant.email}`);
      await sendViaGmail({
        from: `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
        to: tenant.email,
        subject,
        html,
      });
      console.log(`[RenewalReminder] ✅ Sent to ${tenant.email} — ${daysRemaining} days remaining`);
      return;
    } catch (err) {
      lastError = err;
      const code = err?.response?.status || err?.status || err?.code || 'UNKNOWN';
      console.error(`[RenewalReminder] ❌ Attempt ${attempt} failed — code: ${code}, message: ${err.message}`);
      if (!RETRYABLE_ERRORS.includes(Number(code)) || attempt === RETRIES) break;
      console.log(`[RenewalReminder] ⏳ Retrying in ${RETRY_DELAY_MS / 1000}s...`);
      await new Promise(res => setTimeout(res, RETRY_DELAY_MS));
    }
  }
  throw lastError;
}

// ══════════════════════════════════════════════════════════════════════════════
// sendGracePeriodEmail — إشعار "اشتراكك انتهى، لديك 7 أيام سماح"
// ══════════════════════════════════════════════════════════════════════════════
async function sendGracePeriodEmail(tenant, { planLabel, graceEndsAt, gracePeriodDays, renewUrl }) {
  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';

  const graceDateStr = graceEndsAt.toLocaleString('en-US', {
    month: 'long', day: 'numeric', year: 'numeric', timeZone: 'UTC',
  });

  const html = `
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
            <span style="font-size:11px;color:#64748b;letter-spacing:0.08em;text-transform:uppercase;">Grace Period Active</span>
          </td>
        </tr></table>
      </div>

      <!-- Banner -->
      <div style="background:linear-gradient(135deg,#451a03,#7c2d12);padding:28px 32px;border-left:1px solid #92400e;border-right:1px solid #92400e;">
        <p style="font-size:12px;letter-spacing:0.1em;text-transform:uppercase;color:#fbbf24;margin:0 0 8px;font-weight:600;">⏳ Subscription Expired</p>
        <h1 style="font-size:26px;font-weight:800;color:#ffffff;margin:0 0 8px;line-height:1.2;">
          Your store is in the grace period
        </h1>
        <p style="font-size:15px;color:#fde68a;margin:0;">
          Full protection continues until <strong>${graceDateStr}</strong>
        </p>
      </div>

      <!-- Grace Period Explanation -->
      <div style="padding:28px 32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
        <div style="background:#fefce8;border:1px solid #fde68a;border-radius:10px;padding:18px 20px;margin-bottom:24px;">
          <p style="font-size:14px;color:#92400e;margin:0;line-height:1.7;">
            <strong>Good news:</strong> We've extended your <strong>${planLabel}</strong> protection for ${gracePeriodDays} day${gracePeriodDays === 1 ? '' : 's'} at no charge.
            Your store is still fully shielded — all 53 features remain active.
            Renew before <strong>${graceDateStr}</strong> to avoid any interruption.
          </p>
        </div>

        <h3 style="font-size:15px;font-weight:600;color:#0f172a;margin:0 0 16px;">After the grace period ends:</h3>
        <table cellpadding="0" cellspacing="0" style="width:100%;">
          <tr><td style="padding-bottom:10px;">
            <table cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:12px;vertical-align:top;padding-top:2px;width:28px;">
                <div style="width:22px;height:22px;background:#fef2f2;border:1px solid #fecaca;border-radius:50%;text-align:center;line-height:20px;font-size:11px;">❌</div>
              </td>
              <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;">Protection reverts to free plan (500 attacks/month)</p></td>
            </tr></table>
          </td></tr>
          <tr><td>
            <table cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:12px;vertical-align:top;padding-top:2px;width:28px;">
                <div style="width:22px;height:22px;background:#fef2f2;border:1px solid #fecaca;border-radius:50%;text-align:center;line-height:20px;font-size:11px;">❌</div>
              </td>
              <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;">Advanced features (BIN Intelligence, Identity Graph) deactivate</p></td>
            </tr></table>
          </td></tr>
        </table>
      </div>

      <!-- CTA -->
      <div style="padding:24px 32px 28px;background:#fff7ed;border:1px solid #fed7aa;border-top:none;text-align:center;">
        <p style="font-size:14px;color:#92400e;margin:0 0 16px;font-weight:600;">
          Renew now and keep your store protected — no setup required.
        </p>
        <a href="${renewUrl}"
           style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#ffffff;font-size:15px;font-weight:700;padding:14px 36px;border-radius:8px;text-decoration:none;letter-spacing:0.01em;">
          Renew ${planLabel} — Keep Protection →
        </a>
      </div>

      <!-- Footer -->
      <div style="background:#f8fafc;padding:20px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
        <p style="font-size:12px;color:#94a3b8;margin:0;line-height:1.6;">
          You're receiving this because your ChargeGuard subscription has expired.
          Your store remains protected during the ${gracePeriodDays}-day grace period.
        </p>
      </div>
    </div>`;

  const RETRIES = 3;
  const RETRY_DELAY_MS = 5000;
  const RETRYABLE_ERRORS = [429, 500, 502, 503, 504];
  let lastError;

  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    try {
      console.log(`[GracePeriod] 📡 Attempt ${attempt}/${RETRIES} → ${tenant.email}`);
      await sendViaGmail({
        from: `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
        to: tenant.email,
        subject: `⏳ ChargeGuard grace period active — renew by ${graceDateStr}`,
        html,
      });
      console.log(`[GracePeriod] ✅ Sent to ${tenant.email}`);
      return;
    } catch (err) {
      lastError = err;
      const code = err?.response?.status || err?.status || err?.code || 'UNKNOWN';
      console.error(`[GracePeriod] ❌ Attempt ${attempt} failed — code: ${code}, message: ${err.message}`);
      if (!RETRYABLE_ERRORS.includes(Number(code)) || attempt === RETRIES) break;
      console.log(`[GracePeriod] ⏳ Retrying in ${RETRY_DELAY_MS / 1000}s...`);
      await new Promise(res => setTimeout(res, RETRY_DELAY_MS));
    }
  }
  throw lastError;
}

async function sendWelcomeWithKeyEmail(email, apiKey) {
  console.log('[Email] Sending welcome+key email after verification to:', email);
  await sendApiKeyEmail(email, apiKey);
}

async function sendPaypalAlertEmail(tenant, alertData) {
  const {
    paypalTxnId,
    brand,
    last4,
    cardCountry,
    amount,
    currency = 'USD',
    riskScore,
    decision,
    flags = [],
    estimatedSavings,
  } = alertData;

  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';
  // L5 fix: HTML-escaped sibling — see escapeHtml() definition above.
  const storeDisplaySafe = escapeHtml(storeDisplay);

  const now = new Date();
  const timeStr = now.toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
    timeZone: 'UTC', timeZoneName: 'short',
  });

  const txnDisplay    = escapeHtml(paypalTxnId ? paypalTxnId.slice(-8).toUpperCase() : '—');
  const brandClean    = brand ? brand.charAt(0).toUpperCase() + brand.slice(1) : 'Card';
  const cardDisplay   = escapeHtml(last4 ? `${brandClean} ••••${last4}` : brandClean);
  const countryDisplay = escapeHtml(cardCountry || 'Unknown');
  const amountDisplay  = amount
    ? Number(amount).toLocaleString('en-US', { style: 'currency', currency, minimumFractionDigits: 2 })
    : '—';
  const savingsDisplay = estimatedSavings
    ? estimatedSavings.toLocaleString('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 2 })
    : null;

  const decisionLabel  = decision === 'block' ? 'Blocked' : 'Flagged for Review';
  const decisionColor  = decision === 'block' ? '#dc2626' : '#d97706';
  const decisionBg     = decision === 'block' ? '#fef2f2' : '#fffbeb';
  const decisionBorder = decision === 'block' ? '#fecaca' : '#fde68a';

  const topFlag    = flags[0]?.text || null;
  // L5 fix: flag.text originates from intelligence modules (ipIntelligence.js,
  // emailIntelligence.js, binIntelligence.js, countryRisk.js), some of which
  // build their text directly from customer-supplied checkout input. Escape
  // at the point of interpolation.
  const topFlagSafe = topFlag ? escapeHtml(topFlag) : null;
  const flagsHtml  = topFlagSafe
    ? `<p style="font-size:13px;color:#475569;margin:0 0 4px;line-height:1.6;"><strong style="color:#0f172a;">Primary reason:</strong> ${topFlagSafe}</p>`
    : '';

  const savingsHtml = savingsDisplay
    ? `<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:12px 16px;margin-bottom:20px;">
         <p style="font-size:13px;color:#166534;margin:0;line-height:1.6;">💰 <strong>Estimated savings:</strong> ${savingsDisplay} in potential dispute fees avoided.</p>
       </div>`
    : '';

  const RETRIES          = 3;
  const RETRY_DELAY_MS   = 5000;
  const RETRYABLE_ERRORS = [429, 500, 502, 503, 504];

  let lastError;
  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    try {
      console.log(`[PaypalAlert] 📡 Attempt ${attempt}/${RETRIES} — sending via Gmail API`);
      await sendViaGmail({
        from:    `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
        to:      tenant.email,
        subject: `🛡️ ChargeGuard intercepted a suspicious PayPal transaction on ${storeDisplay}`,
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

  <!-- Peak Banner -->
  <div style="background:linear-gradient(135deg,#0c1a3a,#1e3a5f);padding:28px 32px;border-left:1px solid #1d4ed8;border-right:1px solid #1d4ed8;">
    <p style="font-size:12px;letter-spacing:0.1em;text-transform:uppercase;color:#93c5fd;margin:0 0 8px;font-weight:600;">🛡️ PayPal Shield — Transaction Intercepted</p>
    <h1 style="font-size:26px;font-weight:800;color:#ffffff;margin:0 0 6px;line-height:1.2;">Suspicious PayPal transaction stopped</h1>
    <p style="font-size:14px;color:#bfdbfe;margin:0;">on <strong>${storeDisplaySafe}</strong> — before it reached processing</p>
  </div>

  <!-- Transaction Card -->
  <div style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;padding:24px 32px;">
    <table cellpadding="0" cellspacing="0" style="width:100%;">
      <tr>
        <td style="width:50%;padding-right:12px;">
          <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;padding:16px 18px;">
            <p style="font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">PayPal Transaction</p>
            <p style="font-size:15px;font-weight:700;color:#0f172a;margin:0;font-family:'Courier New',monospace;">#${txnDisplay}</p>
          </div>
        </td>
        <td style="width:50%;padding-left:12px;">
          <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;padding:16px 18px;">
            <p style="font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Amount</p>
            <p style="font-size:15px;font-weight:700;color:#0f172a;margin:0;">${amountDisplay}</p>
          </div>
        </td>
      </tr>
      <tr><td colspan="2" style="padding-top:12px;">
        <table cellpadding="0" cellspacing="0" style="width:100%;"><tr>
          <td style="width:50%;padding-right:12px;">
            <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;padding:16px 18px;">
              <p style="font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Card</p>
              <p style="font-size:14px;font-weight:600;color:#0f172a;margin:0;">${cardDisplay}</p>
              <p style="font-size:12px;color:#64748b;margin:2px 0 0;">Issued in ${countryDisplay}</p>
            </div>
          </td>
          <td style="width:50%;padding-left:12px;">
            <div style="background:${decisionBg};border:1px solid ${decisionBorder};border-radius:10px;padding:16px 18px;">
              <p style="font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Decision</p>
              <p style="font-size:14px;font-weight:700;color:${decisionColor};margin:0;">${decisionLabel}</p>
              <p style="font-size:12px;color:#64748b;margin:2px 0 0;">Risk score: ${riskScore}/100</p>
            </div>
          </td>
        </tr></table>
      </td></tr>
    </table>
  </div>

  <!-- Reason + Savings -->
  <div style="padding:20px 32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
    ${flagsHtml}
    ${savingsHtml}
  </div>

  <!-- CTA -->
  <div style="padding:4px 32px 24px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;text-align:center;">
    <a href="https://chargeguard-api.onrender.com/api/dashboard/page"
       style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#ffffff;font-size:14px;font-weight:600;padding:12px 28px;border-radius:8px;text-decoration:none;letter-spacing:0.01em;">
      View in Dashboard →
    </a>
  </div>

  <!-- End Rule — الجملة الأخيرة تبقى في الذاكرة -->
  <div style="background:#f0fdf4;padding:16px 32px;border:1px solid #bbf7d0;border-top:none;text-align:center;">
    <p style="font-size:14px;font-weight:600;color:#166534;margin:0;">✅ Your store is running normally. PayPal is protected. No action required.</p>
  </div>

  <!-- Footer -->
  <div style="background:#f8fafc;padding:20px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
    <p style="font-size:12px;color:#94a3b8;margin:0;line-height:1.6;">
      You're receiving this because ChargeGuard detected suspicious PayPal activity on your store.
      Alerts are throttled to prevent inbox flooding.
    </p>
  </div>

</div>`,
      });
      console.log(`[PaypalAlert] ✅ Sent to ${tenant.email} — txn #${txnDisplay}, score ${riskScore}`);
      return;
    } catch (err) {
      lastError = err;
      const code = err?.response?.status || err?.status || err?.code || 'UNKNOWN';
      console.error(`[PaypalAlert] ❌ Attempt ${attempt} failed — code: ${code}, message: ${err.message}`);
      if (!RETRYABLE_ERRORS.includes(Number(code)) || attempt === RETRIES) break;
      console.log(`[PaypalAlert] ⏳ Retrying in ${RETRY_DELAY_MS / 1000}s...`);
      await new Promise(res => setTimeout(res, RETRY_DELAY_MS));
    }
  }
  throw lastError;
}
// ══════════════════════════════════════════════════════════════════════════════
// sendSubscriptionConfirmationEmail — تأكيد فوري بعد نجاح الدفع
// يُرسل من: paypal-webhook بعد اكتمال transaction
// ══════════════════════════════════════════════════════════════════════════════
async function sendSubscriptionConfirmationEmail(email, {
  planName,
  billingCycle,
  amount,
  subscriptionEndDate,
  captureId,
}) {
  const planLabel = planName === 'pro'
    ? (billingCycle === 'annual' ? 'Pro Annual' : 'Pro Monthly')
    : (billingCycle === 'annual' ? 'Agency Annual' : 'Agency Monthly');

  const endDateStr = subscriptionEndDate.toLocaleString('en-US', {
    month: 'long', day: 'numeric', year: 'numeric', timeZone: 'UTC',
  });

  const amountFormatted = Number(amount).toLocaleString('en-US', {
    style: 'currency', currency: 'USD', minimumFractionDigits: 2,
  });

  const captureDisplay = captureId
    ? captureId.slice(-10).toUpperCase()
    : '—';

  const dashboardUrl = process.env.RENDER_EXTERNAL_URL
    ? `${process.env.RENDER_EXTERNAL_URL}/api/dashboard/page`
    : 'https://chargeguard-api.onrender.com/api/dashboard/page';

  const html = `
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
            <span style="font-size:11px;color:#64748b;letter-spacing:0.08em;text-transform:uppercase;">Payment Confirmed</span>
          </td>
        </tr></table>
      </div>

      <!-- Hero Banner -->
      <div style="background:linear-gradient(135deg,#052e16,#14532d);padding:28px 32px;border-left:1px solid #166534;border-right:1px solid #166534;">
        <p style="font-size:13px;letter-spacing:0.1em;text-transform:uppercase;color:#4ade80;margin:0 0 8px;font-weight:600;">✅ Payment Successful</p>
        <h1 style="font-size:28px;font-weight:800;color:#ffffff;margin:0 0 6px;line-height:1.2;">
          Your ${planLabel} plan is now active
        </h1>
        <p style="font-size:15px;color:#86efac;margin:0;">
          Protection activated — your store is fully shielded
        </p>
      </div>

      <!-- Plan Details Card -->
      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;padding:24px 32px;">
        <table cellpadding="0" cellspacing="0" style="width:100%;">
          <tr>
            <td style="width:50%;padding-right:12px;">
              <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;padding:16px 18px;">
                <p style="font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Plan</p>
                <p style="font-size:17px;font-weight:700;color:#0f172a;margin:0;">${planLabel}</p>
              </div>
            </td>
            <td style="width:50%;padding-left:12px;">
              <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;padding:16px 18px;">
                <p style="font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Amount Charged</p>
                <p style="font-size:17px;font-weight:700;color:#0f172a;margin:0;">${amountFormatted}</p>
              </div>
            </td>
          </tr>
          <tr><td colspan="2" style="padding-top:12px;">
            <table cellpadding="0" cellspacing="0" style="width:100%;"><tr>
              <td style="width:50%;padding-right:12px;">
                <div style="background:#ffffff;border:1px solid #e2e8f0;border-left:3px solid #22c55e;border-radius:10px;padding:16px 18px;">
                  <p style="font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Protected Until</p>
                  <p style="font-size:14px;font-weight:700;color:#16a34a;margin:0;">${endDateStr}</p>
                </div>
              </td>
              <td style="width:50%;padding-left:12px;">
                <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;padding:16px 18px;">
                  <p style="font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin:0 0 4px;">Transaction ID</p>
                  <p style="font-size:13px;font-weight:600;color:#64748b;margin:0;font-family:'Courier New',monospace;">#${captureDisplay}</p>
                </div>
              </td>
            </tr></table>
          </td></tr>
        </table>
      </div>

      <!-- What's Active Now -->
      <div style="padding:24px 32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
        <h3 style="font-size:15px;font-weight:600;color:#0f172a;margin:0 0 16px;">What's active on your store right now</h3>
        <table cellpadding="0" cellspacing="0" style="width:100%;">
          <tr><td style="padding-bottom:10px;">
            <table cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:12px;vertical-align:top;padding-top:2px;width:28px;">
                <div style="width:22px;height:22px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:50%;text-align:center;line-height:20px;font-size:11px;">✅</div>
              </td>
              <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;"><strong style="color:#0f172a;">Real-time card testing detection</strong> — every checkout request scanned</p></td>
            </tr></table>
          </td></tr>
          <tr><td style="padding-bottom:10px;">
            <table cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:12px;vertical-align:top;padding-top:2px;width:28px;">
                <div style="width:22px;height:22px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:50%;text-align:center;line-height:20px;font-size:11px;">✅</div>
              </td>
              <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;"><strong style="color:#0f172a;">BIN sequence intelligence</strong> — coordinated attacks caught before they start</p></td>
            </tr></table>
          </td></tr>
          <tr><td>
            <table cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:12px;vertical-align:top;padding-top:2px;width:28px;">
                <div style="width:22px;height:22px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:50%;text-align:center;line-height:20px;font-size:11px;">✅</div>
              </td>
              <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;"><strong style="color:#0f172a;">Identity graph & cross-merchant signals</strong> — known fraudsters blocked network-wide</p></td>
            </tr></table>
          </td></tr>
        </table>
      </div>

      <!-- CTA -->
      <div style="padding:20px 32px 28px;background:#f8fafc;border:1px solid #e2e8f0;border-top:none;text-align:center;">
        <a href="${dashboardUrl}"
           style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#ffffff;font-size:14px;font-weight:600;padding:12px 28px;border-radius:8px;text-decoration:none;letter-spacing:0.01em;">
          Open Dashboard →
        </a>
        <p style="font-size:12px;color:#94a3b8;margin:12px 0 0;">
          Keep this email as your payment receipt.
        </p>
      </div>

      <!-- Footer -->
      <div style="background:#f8fafc;padding:20px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
        <p style="font-size:12px;color:#94a3b8;margin:0;line-height:1.6;">
          You're receiving this because you just upgraded your ChargeGuard plan.
          For billing questions, reply to this email.
        </p>
      </div>

    </div>`;

  const RETRIES = 3;
  const RETRY_DELAY_MS = 5000;
  const RETRYABLE_ERRORS = [429, 500, 502, 503, 504];
  let lastError;

  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    try {
      console.log(`[ConfirmationEmail] 📡 Attempt ${attempt}/${RETRIES} → ${email}`);
      await sendViaGmail({
        from: `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
        to: email,
        subject: `✅ Payment confirmed — ${planLabel} is now active`,
        html,
      });
      console.log(`[ConfirmationEmail] ✅ Sent to ${email} — plan: ${planLabel}, until: ${endDateStr}`);
      return;
    } catch (err) {
      lastError = err;
      const code = err?.response?.status || err?.status || err?.code || 'UNKNOWN';
      console.error(`[ConfirmationEmail] ❌ Attempt ${attempt} failed — code: ${code}, message: ${err.message}`);
      if (!RETRYABLE_ERRORS.includes(Number(code)) || attempt === RETRIES) break;
      console.log(`[ConfirmationEmail] ⏳ Retrying in ${RETRY_DELAY_MS / 1000}s...`);
      await new Promise(res => setTimeout(res, RETRY_DELAY_MS));
    }
  }
  throw lastError;
}
// ══════════════════════════════════════════════════════════════════════════════
// sendDowngradeEmail — إشعار فوري "انتهت فترة السماح، تم خفض خطتك لـ Starter"
// يُرسل من: processGraceToExpired في subscriptionScheduler.js
// ══════════════════════════════════════════════════════════════════════════════
async function sendDowngradeEmail(tenant, { previousPlanLabel, renewUrl }) {
  const storeDisplay = tenant.storeUrl
    ? tenant.storeUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')
    : 'your store';
  const storeDisplaySafe = escapeHtml(storeDisplay);

  const html = `
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
            <span style="font-size:11px;color:#64748b;letter-spacing:0.08em;text-transform:uppercase;">Plan Changed</span>
          </td>
        </tr></table>
      </div>

      <!-- Banner -->
      <div style="background:linear-gradient(135deg,#450a0a,#7f1d1d);padding:28px 32px;border-left:1px solid #991b1b;border-right:1px solid #991b1b;">
        <p style="font-size:12px;letter-spacing:0.1em;text-transform:uppercase;color:#fca5a5;margin:0 0 8px;font-weight:600;">⏰ Grace Period Ended</p>
        <h1 style="font-size:26px;font-weight:800;color:#ffffff;margin:0 0 8px;line-height:1.2;">
          Your plan has been downgraded to Starter
        </h1>
        <p style="font-size:15px;color:#fecaca;margin:0;">
          <strong>${storeDisplaySafe}</strong> is still monitored — but ${previousPlanLabel} features are now paused
        </p>
      </div>

      <!-- What changed -->
      <div style="padding:28px 32px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
        <h3 style="font-size:15px;font-weight:600;color:#0f172a;margin:0 0 16px;">What's changed on your store:</h3>
        <table cellpadding="0" cellspacing="0" style="width:100%;">
          <tr><td style="padding-bottom:10px;">
            <table cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:12px;vertical-align:top;padding-top:2px;width:28px;">
                <div style="width:22px;height:22px;background:#fef2f2;border:1px solid #fecaca;border-radius:50%;text-align:center;line-height:20px;font-size:11px;">❌</div>
              </td>
              <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;">Monthly protection limit reduced to 500 blocked attempts</p></td>
            </tr></table>
          </td></tr>
          <tr><td style="padding-bottom:10px;">
            <table cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:12px;vertical-align:top;padding-top:2px;width:28px;">
                <div style="width:22px;height:22px;background:#fef2f2;border:1px solid #fecaca;border-radius:50%;text-align:center;line-height:20px;font-size:11px;">❌</div>
              </td>
              <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;">BIN Intelligence, Threat Origins, and real-time PayPal/Slack/Discord alerts are locked</p></td>
            </tr></table>
          </td></tr>
          <tr><td>
            <table cellpadding="0" cellspacing="0"><tr>
              <td style="padding-right:12px;vertical-align:top;padding-top:2px;width:28px;">
                <div style="width:22px;height:22px;background:#fef2f2;border:1px solid #fecaca;border-radius:50%;text-align:center;line-height:20px;font-size:11px;">❌</div>
              </td>
              <td><p style="font-size:14px;color:#334155;margin:0;line-height:1.5;">Multi-store management is disabled (your existing stores are paused, not deleted)</p></td>
            </tr></table>
          </td></tr>
        </table>
      </div>

      <!-- Reassurance -->
      <div style="padding:16px 32px 4px;background:#ffffff;border:1px solid #e2e8f0;border-top:none;">
        <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:14px 18px;">
          <p style="font-size:13px;color:#166534;margin:0;line-height:1.6;">✅ Core fraud detection — card testing, velocity checks, and blacklist blocking — remains active on the Starter plan. Your store is not unprotected.</p>
        </div>
      </div>

      <!-- CTA -->
      <div style="padding:24px 32px 28px;background:#f8fafc;border:1px solid #e2e8f0;border-top:none;text-align:center;">
        <a href="${renewUrl}"
           style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#ffffff;font-size:15px;font-weight:700;padding:14px 36px;border-radius:8px;text-decoration:none;letter-spacing:0.01em;">
          Restore ${previousPlanLabel} Protection →
        </a>
      </div>

      <!-- Footer -->
      <div style="background:#f8fafc;padding:20px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
        <p style="font-size:12px;color:#94a3b8;margin:0;line-height:1.6;">
          You're receiving this because your ChargeGuard grace period ended without renewal.
        </p>
      </div>
    </div>`;

  const RETRIES = 3;
  const RETRY_DELAY_MS = 5000;
  const RETRYABLE_ERRORS = [429, 500, 502, 503, 504];
  let lastError;

  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    try {
      console.log(`[Downgrade] 📡 Attempt ${attempt}/${RETRIES} → ${tenant.email}`);
      await sendViaGmail({
        from: `"ChargeGuard" <${process.env.GMAIL_FROM}>`,
        to: tenant.email,
        subject: `Your ChargeGuard plan has been downgraded to Starter`,
        html,
      });
      console.log(`[Downgrade] ✅ Sent to ${tenant.email}`);
      return;
    } catch (err) {
      lastError = err;
      const code = err?.response?.status || err?.status || err?.code || 'UNKNOWN';
      console.error(`[Downgrade] ❌ Attempt ${attempt} failed — code: ${code}, message: ${err.message}`);
      if (!RETRYABLE_ERRORS.includes(Number(code)) || attempt === RETRIES) break;
      console.log(`[Downgrade] ⏳ Retrying in ${RETRY_DELAY_MS / 1000}s...`);
      await new Promise(res => setTimeout(res, RETRY_DELAY_MS));
    }
  }
  throw lastError;
}

module.exports = { sendApiKeyEmail, sendRotatedKeyEmail, sendAttackAlertEmail, sendWeeklySummaryEmail, sendConfirmationEmail, sendWelcomeWithKeyEmail, sendMonthlyReportEmail, sendPaypalAlertEmail, sendPaypalWeeklyReportEmail, sendRenewalReminderEmail, sendGracePeriodEmail, sendSubscriptionConfirmationEmail, sendDowngradeEmail };