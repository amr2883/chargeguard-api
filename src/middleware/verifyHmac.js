const crypto = require('crypto');
const logger = require('../lib/logger');
const db = require('../lib/db');

const TIMESTAMP_TOLERANCE_SEC = 300; // 5 دقائق

async function verifyHmacSignature(req, res, next) {
  const signature  = req.headers['x-chargeguard-signature'];
  const timestamp  = req.headers['x-chargeguard-timestamp'];

// Both signature headers are mandatory on every mutating request — no
// legacy/unsigned bypass exists. A togglable security bypass is itself a
// misconfiguration risk (OWASP API8:2023): it can be silently re-enabled
// by an env-var mistake. Leaving deactivated bypass code in place is also
// CWE-561 (Dead Code) — removed entirely rather than gated off, per the
// pre-launch security audit verdict.
if (!signature || !timestamp) {
    logger.warn(
      { tenantId: req.tenant?.id, signature: !!signature, timestamp: !!timestamp, path: req.path },
      'HMAC_HEADERS_MISSING — request signature required'
    );
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // التحقق من صحة الـ Timestamp (숫자 فقط)
  const tsNum = parseInt(timestamp, 10);
  if (isNaN(tsNum) || String(tsNum) !== timestamp) {
    logger.warn({ tenantId: req.tenant?.id }, 'HMAC_INVALID_TIMESTAMP_FORMAT');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // التحقق من النافذة الزمنية
  const nowSec = Math.floor(Date.now() / 1000);
  const diff   = Math.abs(nowSec - tsNum);
  if (diff > TIMESTAMP_TOLERANCE_SEC) {
    logger.warn(
      { tenantId: req.tenant?.id, diff, tolerance: TIMESTAMP_TOLERANCE_SEC },
      'HMAC_TIMESTAMP_EXPIRED'
    );
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // التحقق من وجود الـ webhookSecret
  const secret = req.tenant?.webhookSecret;
  if (!secret) {
    logger.warn({ tenantId: req.tenant?.id }, 'HMAC_NO_SECRET_CONFIGURED');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // CRITICAL FIX (C1): the WordPress plugin's generate_hmac() sends a
  // domain-bound v2= signature — HMAC(timestamp.domain.rawBody) — but this
  // middleware previously only ever built and checked a v1= signature
  // (HMAC(timestamp.rawBody), no domain). That mismatch meant every signed
  // request from the plugin failed verification unconditionally, tripping
  // the circuit breaker and silently failing fraud protection open. Fixed
  // by branching on the version prefix actually present in the signature
  // header, so v2= (current plugin) and v1= (any not-yet-upgraded store,
  // kept only for a migration window) are each verified against the
  // signed-string format that produced them.
  //
  // Split on the FIRST "=" only — the hex digest itself never contains an
  // "=", but splitting on the first occurrence is still the correct,
  // unambiguous way to separate "v2" from the digest that follows it.
  const eqIdx        = signature.indexOf('=');
  const sigVersion   = eqIdx === -1 ? '' : signature.slice(0, eqIdx);
  const rawBody      = req.body instanceof Buffer ? req.body : Buffer.from(JSON.stringify(req.body));

  let signedStr;

  if (sigVersion === 'v2') {
    // v2 = domain-bound signature. The domain is not just informational —
    // it is verified as part of the signed string itself, so a signature
    // captured from one store's traffic cannot be replayed against a
    // different store (see justification below). Reject outright if the
    // header this depends on is missing; there is no safe fallback here.
    const storeDomain = req.headers['x-store-domain'];
    if (!storeDomain) {
      logger.warn(
        { tenantId: req.tenant?.id, path: req.path },
        'HMAC_V2_MISSING_STORE_DOMAIN_HEADER'
      );
      return res.status(401).json({ error: 'Unauthorized' });
    }
    signedStr = `${timestamp}.${storeDomain}.${rawBody.toString('utf8')}`;
  } else if (sigVersion === 'v1') {
    // Legacy, pre-domain-binding format — accepted only during the v1/v2
    // migration window for stores still running an older plugin build.
    // Flag it so it's visible in logs and to the caller; do not silently
    // treat it as equivalent to v2 going forward.
    signedStr = `${timestamp}.${rawBody.toString('utf8')}`;
    res.set('X-ChargeGuard-Signature-Deprecated', 'v1 signatures are deprecated and will be removed; upgrade the ChargeGuard plugin to enable domain-bound v2 signatures.');
    logger.warn(
      { tenantId: req.tenant?.id, path: req.path },
      'HMAC_V1_DEPRECATED_SIGNATURE_ACCEPTED'
    );
  } else {
    // No recognized version prefix — reject rather than guessing a format.
    logger.warn(
      { tenantId: req.tenant?.id, path: req.path, sigVersion },
      'HMAC_UNSUPPORTED_SIGNATURE_VERSION'
    );
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // حساب الـ expected signature — computed under whichever version's
  // signed-string format was selected above, using the same prefix the
  // client sent so the constant-time comparison below is a like-for-like
  // full-string check (prefix included).
  const expected = `${sigVersion}=` + crypto.createHmac('sha256', secret).update(signedStr).digest('hex');

  // المقارنة الآمنة
  let isValid = false;
  try {
    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expected);
    if (sigBuf.length === expBuf.length) {
      isValid = crypto.timingSafeEqual(sigBuf, expBuf);
    }
  } catch (_) {
    isValid = false;
  }

  if (!isValid) {
    logger.warn(
      { tenantId: req.tenant?.id, path: req.path },
      'HMAC_SIGNATURE_MISMATCH'
    );
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // C-V1STORE fix: v1's signed string never included domain, so req.storeId
  // (set upstream by domainAuthMiddleware from the caller-supplied
  // x-store-domain header) is not authenticated for v1 requests — it only
  // proves "this domain belongs to this tenant," not "this specific
  // signature was generated with knowledge of this specific domain." A
  // v1-signed request captured from Store A can be replayed with Store B's
  // domain header and still pass the isValid check above unchanged, then
  // inherit Store B's storeId. Only runs when domainAuthMiddleware actually
  // populated req.storeId (Agency multi-store path) — Starter/Pro and the
  // legacy own-site fallback never set it, so they're untouched.
  if (sigVersion === 'v1' && req.storeId) {
    try {
      const activeStores = await db.store.findMany({
        where: { tenantId: req.tenant.id, isActive: true },
        select: { id: true },
      });
      if (activeStores.length === 1) {
        // Structurally unambiguous — only one possible target, so pin it
        // explicitly rather than continuing to trust the header's path.
        req.storeId = activeStores[0].id;
      } else {
        // 2+ active stores: this v1 signature cannot prove which store it
        // was actually generated for. Drop the forgeable attribution rather
        // than trust it. The request still proceeds and is still scored —
        // it just isn't credited/blamed on a specific store's analytics.
        req.storeId = null;
        logger.warn(
          { tenantId: req.tenant.id, path: req.path },
          'HMAC_V1_MULTISTORE_ATTRIBUTION_DROPPED'
        );
      }
    } catch (err) {
      // Fail closed on attribution (not on the request): an error here
      // must not let an unverified header-based attribution stand.
      logger.error(
        { tenantId: req.tenant?.id, error: err.message },
        'HMAC_V1_STORE_RESOLUTION_ERROR — clearing storeId defensively'
      );
      req.storeId = null;
    }
  }

  // الـ signature صحيح — parse الـ body وتابع
  if (req.body instanceof Buffer) {
    try {
      req.body = JSON.parse(req.body.toString('utf8'));
    } catch (_) {
      return res.status(400).json({ error: 'Invalid JSON body' });
    }
  }

  next();
}

module.exports = verifyHmacSignature;