const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const db = require('../lib/db');
const logger = require('../lib/logger');
const { resolveTenantByApiKey } = require('../lib/apiKeyAuth');
const verifyHmacSignature = require('../middleware/verifyHmac');
const { requireAuth } = require('../middleware/authenticate');

const apiKeyAuth = requireAuth({ id: true, email: true, isActive: true, emailVerified: true, webhookSecret: true });

// Used only by POST /connect-with-key below — needs storeUrl/allowedDomains
// in addition to apiKeyAuth's fields, to support that route's domain-binding
// logic on a successful connect.
const connectKeyAuth = requireAuth({
  id: true,
  email: true,
  isActive: true,
  emailVerified: true,
  storeUrl: true,
  allowedDomains: true,
  webhookSecret: true,
});

// Used only by POST /connect-with-key below — needs storeUrl/allowedDomains
// in addition to apiKeyAuth's fields, to support that route's domain-binding
// logic on a successful connect.


// ── IP Hashing (GDPR-safe) — same construction as routes/risk.js ────────────
// M3 fix: fail closed, not open. A missing SECRET_SALT previously
// silently degraded to a hardcoded, publicly-known salt, making hashed
// IPs trivially reversible via rainbow table. Every other hashIp
// implementation in this codebase (routes/risk.js, velocityDetector.js)
// already fails closed on a missing salt — this brings routes/auth.js
// in line with that pattern instead of being the one silent exception.
const hashIp = (ip) => {
  const salt = process.env.SECRET_SALT;
  if (!salt) {
    throw new Error('SECRET_SALT is not configured');
  }
  return crypto.createHmac('sha256', salt).update(ip).digest('hex');
};

// ── Rate limit middleware for /connect-with-key (OWASP API4:2023) ───────
// 3 attempts / 15 minutes per IP — tighter than /tenants/register's 5/hour
// because this route is a credential-bearing "connect" action. IP-only (not
// email-keyed) to avoid creating an enumeration oracle.
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

/**
 * POST /api/auth/connect-with-key
 *
 * Primary connect path for the WooCommerce plugin's settings page.
 * The earlier emailed-confirmation-link flow was removed (#52).
 * The merchant already holds a live API key — delivered by email only
 * after verifying their address on the Landing Page (see /verify-email
 * below) — and enters it directly here alongside their account email.
 *
 * Trust model: possession of the 256-bit API key is itself the proof of
 * ownership, so no separate email round
 * trip is required — connectKeyAuth (requireAuth) is the exact same
 * centralized authentication check every other authenticated endpoint in
 * this codebase already relies on (OWASP ASVS V4.1.1). Domain binding
 * (storeUrl/allowedDomains) is only ever written once real proof of
 * possession has been established — here, that proof is authenticating
 * successfully via connectKeyAuth below.
 *
 * SANCTIONED EXCEPTION (same category as GET /verify below): no
 * verifyHmacSignature on this route. The plugin cannot compute an HMAC
 * signature before this call succeeds — it does not have webhookSecret
 * yet. Same chicken-and-egg constraint already documented above /verify.
 *
 * connectRateLimit runs per IP before authentication. It was previously
 * shared with the removed email-based /connect endpoint (#52).
 *
 * The email the merchant typed is NOT used for authentication and is
 * never compared against tenant.email — a second, lower-entropy check
 * would add no real security (the key alone is definitive) while
 * creating a new enumeration oracle, conflicting with the
 * anti-enumeration design already applied consistently elsewhere in this
 * file. The authoritative tenant.email is returned instead, so the
 * plugin always displays the real connected account regardless of what
 * was typed.
 */
router.post('/connect-with-key', connectRateLimit, connectKeyAuth, async (req, res) => {
  try {
    const tenant = req.tenant;
    const { siteUrl } = req.body || {};

    let webhookSecret = tenant.webhookSecret;
    if (!webhookSecret) {
      webhookSecret = crypto.randomBytes(32).toString('hex');
    }

    // Conditional update (H1 principle) - only touch
    // storeUrl/allowedDomains if the merchant's current site actually
    // differs from what's on file (first connect, or a site migration).
    const domainUpdate = {};
    if (siteUrl && siteUrl !== tenant.storeUrl) {
      const { normalizeDomain } = require('../lib/domainAuth');
      const normalized = normalizeDomain(siteUrl);
      domainUpdate.storeUrl = siteUrl;
      if (normalized) {
        domainUpdate.allowedDomains = [normalized];
      }
    }

    await db.tenant.update({
      where: { id: tenant.id },
      data: {
        webhookSecret,
        lastConnectVerifiedAt: new Date(),
        ...domainUpdate,
      },
    });

    logger.info({ module: 'auth', tenantId: tenant.id }, 'Store connected via direct API-key connect');

    return res.status(200).json({
      status:        'active',
      merchantId:    tenant.id,
      email:         tenant.email,
      webhookSecret,
    });
  } catch (err) {
    logger.error({ module: 'auth', error: err.message }, 'connect-with-key error');
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/auth/self-test
 *
 * Called once by the plugin immediately after connect (self_test() in
 * class-api-client.php) to confirm the signing secret it just saved
 * actually matches what the backend has on file for this tenant. The
 * handler does no work itself — apiKeyAuth + verifyHmacSignature are
 * the exact same chain used by /risk/evaluate, so reaching this
 * handler at all is the proof the plugin needs. A signature mismatch
 * never reaches this code — verifyHmacSignature responds 401 first.
 */
router.post('/self-test', apiKeyAuth, verifyHmacSignature, async (req, res) => {
  return res.status(200).json({ success: true, message: 'Signing verified' });
});

/**
 * GET /api/auth/verify
 * Plugin يتحقق إن الـ API Key لا يزال صالحاً
 */
// SANCTIONED EXCEPTION to the centralized requireAuth() pattern (CWE-1059
// drift-prevention documentation). Do NOT "fix" this to use
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

  } catch (err) {
    logger.error({ module: 'auth', error: err.message }, 'Auth verify error');
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