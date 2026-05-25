const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const db = require('../lib/db');
const logger = require('../lib/logger');

/**
 * POST /api/auth/connect
 * التاجر يبعت الـ email بتاعه بس
 * الـ backend يرجعله كل حاجة تلقائياً
 */
router.post('/connect', async (req, res) => {
  try {
    const { email, siteUrl } = req.body;

    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'Email is required' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // ابحث عن التاجر بالـ email
    const tenant = await db.tenant.findUnique({
      where: { email: normalizedEmail },
      select: {
        id: true,
        email: true,
        apiKey: true,
        webhookSecret: true,
        isActive: true,
        emailVerified: true,
        storeUrl: true,
      }
    });

    if (!tenant) {
      return res.status(404).json({
        error: 'Email not found. Please register at chargeguard-io.netlify.app first.'
      });
    }

    if (!tenant.isActive) {
      return res.status(403).json({
        error: 'Account is inactive. Please contact support.'
      });
    }

    if (!tenant.emailVerified && process.env.EMAIL_VERIFICATION_DISABLED !== 'true') {
      return res.status(403).json({
        error: 'Email not verified. Please check your inbox and click the confirmation link before connecting your store.',
        code: 'EMAIL_NOT_VERIFIED'
      });
    }

    // لو مفيش webhookSecret — نعمله تلقائياً ونحفظه
    let webhookSecret = tenant.webhookSecret;
    if (!webhookSecret) {
      webhookSecret = crypto.randomBytes(32).toString('hex');
      await db.tenant.update({
        where: { email: normalizedEmail },
        data: { webhookSecret }
      });
    }

    // لو التاجر بعت الـ siteUrl — نحدثه
    if (siteUrl && siteUrl !== tenant.storeUrl) {
      await db.tenant.update({
        where: { email: normalizedEmail },
        data: { storeUrl: siteUrl }
      });
    }

    logger.info(`Tenant connected via email: ${normalizedEmail}`);

    return res.status(200).json({
      merchantId:    tenant.id,
      apiKey:        tenant.apiKey,
      webhookSecret: webhookSecret,
      email:         tenant.email,
    });

  } catch (err) {
    logger.error('Auth connect error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/auth/verify
 * Plugin يتحقق إن الـ API Key لا يزال صالحاً
 */
router.get('/verify', async (req, res) => {
  try {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
      return res.status(401).json({ error: 'Missing x-api-key header' });
    }

    const tenant = await db.tenant.findUnique({
      where:  { apiKey },
      select: { id: true, isActive: true, emailVerified: true },
    });

    if (!tenant || !tenant.isActive) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    if (!tenant.emailVerified && process.env.EMAIL_VERIFICATION_DISABLED !== 'true') {
      return res.status(403).json({
        error: 'Email not verified. Please check your inbox and click the confirmation link.',
        code: 'EMAIL_NOT_VERIFIED'
      });
    }

    return res.status(200).json({ valid: true });

    return res.status(200).json({ valid: true });

  } catch (err) {
    logger.error('Auth verify error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/auth/verify-email?token=xxx
 * المستخدم ينقر الرابط من إيميله — نتحقق من الـ token ونُفعّل الحساب
 */
router.get('/verify-email', async (req, res) => {
  const { token } = req.query;

  // HTML templates
  const renderPage = (title, icon, color, headline, body, extra = '') => `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8"/>
      <meta name="viewport" content="width=device-width,initial-scale=1"/>
      <title>${title} — ChargeGuard</title>
      <style>
        *{box-sizing:border-box;margin:0;padding:0}
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0b1121;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
        .card{background:#ffffff;border-radius:16px;max-width:480px;width:100%;overflow:hidden;box-shadow:0 25px 50px rgba(0,0,0,0.4)}
        .top{background:#0b1121;padding:24px 32px;display:flex;align-items:center;gap:10px}
        .logo{font-size:20px;font-weight:700;color:#fff}.logo span{color:#f97316}
        .icon-wrap{padding:32px;text-align:center}
        .icon{font-size:56px;line-height:1}
        .content{padding:0 32px 32px}
        h1{font-size:22px;font-weight:800;color:#0f172a;margin-bottom:10px;text-align:center}
        p{font-size:15px;color:#475569;line-height:1.7;text-align:center;margin-bottom:20px}
        .badge{display:inline-block;padding:4px 12px;border-radius:999px;font-size:12px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;margin-bottom:20px}
        .btn{display:block;text-align:center;padding:13px 24px;border-radius:8px;font-size:14px;font-weight:700;text-decoration:none;margin-top:8px}
        .btn-primary{background:linear-gradient(135deg,#f97316,#ea580c);color:#fff}
        .btn-secondary{background:#f1f5f9;color:#334155;margin-top:10px}
        .note{font-size:12px;color:#94a3b8;text-align:center;margin-top:20px;line-height:1.6}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="top">
          <div style="width:28px;height:28px;background:linear-gradient(135deg,#f97316,#ea580c);border-radius:6px;display:flex;align-items:center;justify-content:center">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="white"><path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.4C16.5 22.15 20 17.25 20 12V6L12 2zm-1 13l-3-3 1.4-1.4L11 12.2l4.6-4.6L17 9l-6 6z"/></svg>
          </div>
          <span class="logo">Charge<span>Guard</span></span>
        </div>
        <div class="icon-wrap"><div class="icon">${icon}</div></div>
        <div class="content">
          <div style="text-align:center">
            <span class="badge" style="background:${color.bg};color:${color.text}">${title}</span>
          </div>
          <h1>${headline}</h1>
          <p>${body}</p>
          ${extra}
        </div>
      </div>
    </body>
    </html>
  `;

  // Missing token
  if (!token) {
    return res.status(400).send(renderPage(
      'Invalid Link', '🔗', { bg: '#fee2e2', text: '#dc2626' },
      'Invalid confirmation link',
      'This link is missing a verification token. Please use the link from your email or request a new one.',
      `<a href="https://master.chargeguard-landing.pages.dev" class="btn btn-secondary">Go to ChargeGuard →</a>`
    ));
  }

  try {
    // Find tenant by token
    const tenant = await db.tenant.findUnique({
      where: { emailVerifyToken: token },
      select: {
        id: true,
        email: true,
        apiKey: true,
        emailVerified: true,
        emailVerifyExpiresAt: true,
      }
    });

    // Token not found or already used
    if (!tenant) {
      return res.status(404).send(renderPage(
        'Invalid Link', '❌', { bg: '#fee2e2', text: '#dc2626' },
        'Link already used or invalid',
        'This confirmation link has already been used or does not exist. Your account may already be active — try connecting your store.',
        `<a href="https://master.chargeguard-landing.pages.dev" class="btn btn-primary">Go to ChargeGuard →</a>`
      ));
    }

    // Already verified
    if (tenant.emailVerified) {
      return res.status(200).send(renderPage(
        'Already Verified', '✅', { bg: '#dcfce7', text: '#16a34a' },
        'Account already active',
        'Your email has already been verified. Check your inbox for your API key and start protecting your store.',
        `<a href="https://master.chargeguard-landing.pages.dev" class="btn btn-primary">Go to ChargeGuard →</a>`
      ));
    }

    // Token expired
    if (new Date() > new Date(tenant.emailVerifyExpiresAt)) {
      return res.status(410).send(renderPage(
        'Link Expired', '⏰', { bg: '#fef3c7', text: '#92400e' },
        'Confirmation link expired',
        'This link was valid for 24 hours and has now expired. Request a new confirmation email below.',
        `
        <form action="/api/auth/resend-verification" method="POST" style="margin-top:8px">
          <input type="hidden" name="email" value="${tenant.email}"/>
          <button type="submit" style="width:100%;padding:13px 24px;border-radius:8px;font-size:14px;font-weight:700;background:linear-gradient(135deg,#f97316,#ea580c);color:#fff;border:none;cursor:pointer">
            Resend Confirmation Email →
          </button>
        </form>
        <p class="note">We'll send a fresh link to ${tenant.email}</p>
        `
      ));
    }

    // ✅ SUCCESS — activate account
    await db.tenant.update({
      where: { id: tenant.id },
      data: {
        emailVerified: true,
        emailVerifyToken: null,
        emailVerifyExpiresAt: null,
      }
    });

    logger.info({ module: 'auth', tenantId: tenant.id }, 'Email verified successfully');

    // Send Welcome + API Key email (fire-and-forget)
    const { sendWelcomeWithKeyEmail } = require('../lib/email');
    sendWelcomeWithKeyEmail(tenant.email, tenant.apiKey).catch(err => {
      logger.error({ module: 'email', error: err.message }, 'Failed to send welcome email after verification');
    });

    return res.status(200).send(renderPage(
      'Email Verified', '🎉', { bg: '#dcfce7', text: '#16a34a' },
      'You\'re all set!',
      'Your email has been verified. We\'ve sent your API key to your inbox — use it to activate protection on your WooCommerce store.',
      `
      <a href="https://master.chargeguard-landing.pages.dev" class="btn btn-primary">Get Started →</a>
      <p class="note">Check your inbox for an email containing your API key.</p>
      `
    ));

  } catch (err) {
    logger.error({ module: 'auth', error: err.message }, 'Email verification error');
    return res.status(500).send(renderPage(
      'Server Error', '⚠️', { bg: '#fee2e2', text: '#dc2626' },
      'Something went wrong',
      'We encountered an error while verifying your email. Please try again or contact support.',
      `<a href="https://master.chargeguard-landing.pages.dev" class="btn btn-secondary">Go to ChargeGuard →</a>`
    ));
  }
});

/**
 * POST /api/auth/resend-verification
 * المستخدم يطلب رابط تأكيد جديد
 * Body: { email }
 */
router.post('/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'Email is required' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const tenant = await db.tenant.findUnique({
      where: { email: normalizedEmail },
      select: {
        id: true,
        email: true,
        emailVerified: true,
        emailVerifyExpiresAt: true,
      }
    });

    // Always return 200 — never reveal if email exists or not (security)
    if (!tenant) {
      return res.status(200).json({
        message: 'If this email is registered, a new confirmation link has been sent.'
      });
    }

    // Already verified
    if (tenant.emailVerified) {
      return res.status(200).json({
        message: 'This account is already verified. Check your inbox for your API key.'
      });
    }

    // Rate limit — allow resend only once per 60 seconds
    if (tenant.emailVerifyExpiresAt) {
      const issuedAt = new Date(tenant.emailVerifyExpiresAt).getTime() - (24 * 60 * 60 * 1000);
      const secondsSinceIssued = (Date.now() - issuedAt) / 1000;
      if (secondsSinceIssued < 60) {
        const waitSeconds = Math.ceil(60 - secondsSinceIssued);
        return res.status(429).json({
          error: `Please wait ${waitSeconds} second(s) before requesting another confirmation email.`,
          retryAfter: waitSeconds
        });
      }
    }

    // Generate new token
    const newToken = crypto.randomBytes(32).toString('hex');
    const newExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await db.tenant.update({
      where: { id: tenant.id },
      data: {
        emailVerifyToken: newToken,
        emailVerifyExpiresAt: newExpiresAt,
      }
    });

    const baseUrl = process.env.RENDER_EXTERNAL_URL || 'https://chargeguard-api.onrender.com';
    const confirmUrl = `${baseUrl}/api/auth/verify-email?token=${newToken}`;

    const { sendConfirmationEmail } = require('../lib/email');
    sendConfirmationEmail(tenant.email, confirmUrl).catch(err => {
      logger.error({ module: 'email', error: err.message }, 'Failed to resend confirmation email');
    });

    logger.info({ module: 'auth', tenantId: tenant.id }, 'Confirmation email resent');

    return res.status(200).json({
      message: 'If this email is registered, a new confirmation link has been sent.'
    });

  } catch (err) {
    logger.error({ module: 'auth', error: err.message }, 'Resend verification error');
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;