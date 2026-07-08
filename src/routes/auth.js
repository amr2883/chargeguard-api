const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const db = require('../lib/db');
const logger = require('../lib/logger');
const { resolveTenantByApiKey } = require('../lib/apiKeyAuth');
const { hashApiKey } = require('../lib/apiKeyHash');

// ── IP Hashing (GDPR-safe) — same construction as routes/risk.js ────────────
const hashIp = (ip) => {
  const salt = process.env.SECRET_SALT || 'default_salt_change_me';
  return crypto.createHmac('sha256', salt).update(ip).digest('hex');
};

// ── Rate limit + Turnstile middleware for /connect (OWASP API4:2023) ───────
// 3 attempts / 15 minutes per IP — tighter than /tenants/register's 5/hour
// because /connect issues a live credential on confirmation. IP-only (not
// email-keyed) to avoid creating an enumeration oracle, consistent with this
// endpoint's existing generic-200 design.
const connectRateLimit = async (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const ipHash = hashIp(ip);
  const windowMs = 15 * 60 * 1000;
  const windowStart = new Date(Date.now() - windowMs);
  const MAX_ATTEMPTS = 3;

  try {
    const [, recentCount] = await Promise.all([
      db.connectAttempt.deleteMany({
        where: { createdAt: { lt: windowStart } }
      }),
      db.connectAttempt.count({
        where: { ipHash, createdAt: { gte: windowStart } }
      })
    ]);

    if (recentCount >= MAX_ATTEMPTS) {
      const oldestAttempt = await db.connectAttempt.findFirst({
        where: { ipHash, createdAt: { gte: windowStart } },
        orderBy: { createdAt: 'asc' },
        select: { createdAt: true }
      });
      const resetAt = oldestAttempt
        ? new Date(oldestAttempt.createdAt).getTime() + windowMs
        : Date.now() + windowMs;
      const retryAfterSecs = Math.ceil((resetAt - Date.now()) / 1000);
      res.set('Retry-After', String(retryAfterSecs));
      return res.status(429).json({
        error: `Too many requests. Please try again in ${Math.ceil(retryAfterSecs / 60)} minute(s).`,
        retryAfter: retryAfterSecs
      });
    }

    await db.connectAttempt.create({ data: { ipHash } });

  } catch (rateLimitErr) {
    logger.error(
      { module: 'auth', endpoint: 'connect', error: rateLimitErr.message },
      'Rate limiter DB error — failing open'
    );
  }
  next();
};

// ── Turnstile verification for /connect ─────────────────────────────────────
const connectTurnstile = async (req, res, next) => {
  const turnstileToken = req.body.turnstileToken || '';
  if (!turnstileToken) {
    return res.status(400).json({ error: 'Security check token missing.' });
  }
  try {
    const turnstileRes = await fetch(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          secret:   process.env.TURNSTILE_SECRET_KEY,
          response: turnstileToken,
          remoteip: req.ip || req.connection.remoteAddress
        })
      }
    );
    const turnstileData = await turnstileRes.json();
    if (!turnstileData.success) {
      return res.status(403).json({ error: 'Security check failed. Please try again.' });
    }
  } catch (turnstileErr) {
    logger.error({ module: 'auth', endpoint: 'connect', error: turnstileErr.message }, 'Turnstile verification error');
    return res.status(503).json({ error: 'Security check unavailable. Please try again.' });
  }
  next();
};

/**
 * POST /api/auth/connect
 * التاجر يبعت الـ email بتاعه بس
 * الـ backend يرجعله كل حاجة تلقائياً
 */
router.post('/connect', connectRateLimit, connectTurnstile, async (req, res) => {
  const GENERIC_RESPONSE = {
    message: 'If this email is registered and verified, a secure connect link has been sent. The link expires in 15 minutes.'
  };

  try {
    const { email, siteUrl } = req.body;

    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'Email is required' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const tenant = await db.tenant.findUnique({
      where: { email: normalizedEmail },
      select: {
        id: true,
        email: true,
        isActive: true,
        emailVerified: true,
        storeUrl: true,
      }
    });

    if (!tenant || !tenant.isActive) {
      return res.status(200).json(GENERIC_RESPONSE);
    }

    if (!tenant.emailVerified && process.env.EMAIL_VERIFICATION_DISABLED !== 'true') {
      return res.status(200).json(GENERIC_RESPONSE);
    }

  if (siteUrl && siteUrl !== tenant.storeUrl) {
      const { normalizeDomain } = require('../lib/domainAuth');
      const normalizedSiteDomain = normalizeDomain(siteUrl);

      await db.tenant.update({
        where: { email: normalizedEmail },
        data: {
          storeUrl: siteUrl,
          // Re-bind the domain allowlist whenever the merchant changes their
          // store URL through /connect — otherwise a stale allowedDomains
          // entry would block legitimate traffic from the new domain while
          // the old (possibly compromised or sold) domain stayed authorized.
          ...(normalizedSiteDomain ? { allowedDomains: [normalizedSiteDomain] } : {}),
        }
      });
    }

    const connectToken = crypto.randomBytes(32).toString('hex');
    const connectTokenExpiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await db.tenant.update({
      where: { id: tenant.id },
      data: { connectToken, connectTokenExpiresAt }
    });

    const baseUrl = process.env.RENDER_EXTERNAL_URL || 'https://chargeguard-api.onrender.com';
    const confirmUrl = `${baseUrl}/api/auth/connect/confirm?token=${connectToken}`;

    const { sendConfirmationEmail } = require('../lib/email');
    sendConfirmationEmail(tenant.email, confirmUrl).catch(err => {
      logger.error({ module: 'email', error: err.message }, 'Failed to send connect confirmation email');
    });

    logger.info({ module: 'auth', tenantId: tenant.id }, 'Connect token issued');

    return res.status(200).json(GENERIC_RESPONSE);

  } catch (err) {
    logger.error('Auth connect error:', err);
    return res.status(200).json(GENERIC_RESPONSE);
  }
});

router.get('/connect/confirm', async (req, res) => {
  const { token } = req.query;

  if (!token || typeof token !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid token' });
  }

  try {
    const tenant = await db.tenant.findUnique({
      where: { connectToken: token },
      select: {
        id: true,
        email: true,
        webhookSecret: true,
        isActive: true,
        connectTokenExpiresAt: true,
      }
    });

    if (!tenant || !tenant.isActive) {
      return res.status(401).json({ error: 'Invalid or expired connect link. Please request a new one.' });
    }

    if (!tenant.connectTokenExpiresAt || new Date() > new Date(tenant.connectTokenExpiresAt)) {
      return res.status(410).json({ error: 'This connect link has expired. Please request a new one.' });
    }

      let webhookSecret = tenant.webhookSecret;
    if (!webhookSecret) {
      webhookSecret = crypto.randomBytes(32).toString('hex');
    }

    // Plaintext API keys are never persisted after their one-time delivery — only apiKeyHash is
    // stored (OWASP ASVS V6.2.1; NIST SP 800-63B §5.1.3 look-up secret storage), which makes
    // "recovering" a previously-issued key impossible by design, for any tenant. Since /connect
    // already proves inbox ownership (the only signal we'd otherwise use to gate a rotation),
    // the correct behavior — matching how GitHub, Stripe, and Twilio handle "I lost my API
    // key" — is to issue a brand-new credential here rather than attempt to return one that
    // structurally cannot exist in the database.
    //
    // NOTE — no grace period here, by design (do not "fix" this to match /rotate-key):
    // /connect/confirm is a RECOVERY flow, not a planned rotation. A merchant only reaches
    // this endpoint because their key is lost or suspected compromised. We deliberately do
    // NOT set previousApiKeyHash / previousApiKeyExpiresAt here, so the old key is killed
    // the instant the new one is issued, with no overlap window.
    //
    // Contrast with /dashboard/rotate-key: that endpoint IS a planned rotation initiated by
    // a merchant with full account access and no indication of compromise, so it sets
    // previousApiKeyHash with a 24h grace window to avoid a protection outage while the
    // WooCommerce plugin config is updated.
    //
    // Giving /connect/confirm the same grace period would mean a potentially-leaked key
    // stays valid for 24h after the owner explicitly signaled it might be compromised —
    // defeating the purpose of the recovery flow (NIST SP 800-63B §6.1: compromised/lost
    // authenticators must be invalidated immediately, not given a renewal overlap).
    const newApiKey = crypto.randomBytes(32).toString('base64');
    const newApiKeyHash = hashApiKey(newApiKey);

    await db.tenant.update({
      where: { id: tenant.id },
      data: {
        connectToken: null,
        connectTokenExpiresAt: null,
        lastConnectVerifiedAt: new Date(),
        webhookSecret,
        apiKeyHash: newApiKeyHash,
        apiKey: null,
        keyRotatedAt: new Date(),
      }
    });

    logger.info({ module: 'auth', tenantId: tenant.id }, 'Connect token verified — new API key issued');

    return res.status(200).json({
      merchantId:    tenant.id,
      apiKey:        newApiKey,
      webhookSecret: webhookSecret,
      email:         tenant.email,
      message:       'A new API key has been issued for security reasons. Update your WooCommerce plugin settings with this key.',
    });

  } catch (err) {
    logger.error('Connect confirm error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/auth/verify
 * Plugin يتحقق إن الـ API Key لا يزال صالحاً
 */
// SANCTIONED EXCEPTION to the centralized requireAuth() pattern (CWE-1059
// drift-prevention documentation — same rationale as the /connect/confirm
// no-grace-period note further down this file). Do NOT "fix" this to use
// requireAuth() without re-reading this comment in full.
//
// This is a lightweight HEALTH-CHECK endpoint: the WooCommerce plugin calls
// it to ask "is my API key still valid?" before doing anything else,
// including before it has fetched webhookSecret. Three deliberate
// deviations from the standard pattern follow from that:
//
//   a) No requireAuth() AUTH_FAIL_DELAY_MS (200ms) on failure. That delay
//      exists to blunt key-enumeration timing attacks against mutating,
//      capability-granting endpoints (CWE-208). A pure validity probe is a
//      much lower-value timing oracle — knowing a key is "valid" grants no
//      capability an attacker couldn't get more directly by trying the key
//      against a real endpoint — and this route is polled frequently, so
//      artificial latency here has a real operational cost with no
//      proportionate security benefit (cf. Kubernetes liveness/readiness
//      probes, which are intentionally excluded from the full
//      auth/authz chain the live application enforces, for the same
//      cost/benefit reason).
//   b) No domainAuthMiddleware. The plugin calls this from the merchant's
//      own server process, not a browser subject to origin enforcement —
//      there is no "origin" to bind in the way there is for browser-facing
//      mutating calls.
//   c) No verifyHmacSignature. The plugin may not have fetched
//      webhookSecret yet — requiring an HMAC signature here would be
//      circular (the secret needed to sign isn't available until after a
//      successful authenticated call).
//
// What is NOT relaxed: this handler still manually enforces tenant.isActive
// and tenant.emailVerified (mirroring requireAuth's policy exactly), and
// returns no sensitive data — only { valid: true }, never a secret. If
// those manual checks and requireAuth's checks ever diverge, that is the
// one thing to fix; the missing delay/domain/HMAC layers above are by
// design and should stay missing.
router.get('/verify', async (req, res) => {
  try {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
      return res.status(401).json({ error: 'Missing x-api-key header' });
    }

    const { tenant } = await resolveTenantByApiKey(apiKey, {
      id: true, isActive: true, emailVerified: true,
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

    // ✅ SUCCESS — activate account. The plaintext key is captured into a local variable BEFORE
    // the purge below; the same write that flips emailVerified = true also nulls the apiKey
    // column, so there is no committed state where the account is verified and the plaintext
    // key still exists in the database (CWE-532 minimization; OWASP ASVS V6.2.1). This is the
    // one and only moment the transiently-held key from /tenants/register (see routes/risk.js)
    // is read — it never touches the database again after this line.
    const plaintextKeyForWelcomeEmail = tenant.apiKey;

    // Atomic, conditional update — guards against two concurrent requests
    // for the same token both passing the emailVerified/expiry checks
    // above before either commits (CWE-362 TOCTOU). Mirrors the
    // conditional-update + re-read-on-lost-race pattern already used for
    // quota resets in risk.js's /evaluate route.
    const updateResult = await db.tenant.updateMany({
      where: {
        id: tenant.id,
        emailVerifyToken: token,
        emailVerified: false,
      },
      data: {
        emailVerified: true,
        emailVerifyToken: null,
        emailVerifyExpiresAt: null,
        apiKey: null,
      }
    });

    if (updateResult.count === 0) {
      // Lost the race — a concurrent request already verified this
      // tenant between our read and our write attempt. Do not resend the
      // welcome email or treat this as a fresh success; show the same
      // page a genuine double-click would see.
      logger.info({ module: 'auth', tenantId: tenant.id }, 'Verification lost race — already verified by concurrent request');
      return res.status(200).send(renderPage(
        'Already Verified', '✅', { bg: '#dcfce7', text: '#16a34a' },
        'Account already active',
        'Your email has already been verified. Check your inbox for your API key and start protecting your store.',
        `<a href="https://master.chargeguard-landing.pages.dev" class="btn btn-primary">Go to ChargeGuard →</a>`
      ));
    }

    logger.info({ module: 'auth', tenantId: tenant.id }, 'Email verified successfully');

    // Send Welcome + API Key email (fire-and-forget)
    const { sendWelcomeWithKeyEmail } = require('../lib/email');
    sendWelcomeWithKeyEmail(tenant.email, plaintextKeyForWelcomeEmail).catch(err => {
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