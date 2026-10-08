const crypto = require('crypto');
const logger = require('../lib/logger');
const db = require('../lib/db');
const { claimRequestOnce, completeRequest, releaseRequest } = require('../lib/replayGuard');

const TIMESTAMP_TOLERANCE_SEC = 300; // 5 دقائق

async function verifyHmacSignature(req, res, next) {
  const signature  = req.headers['x-chargeguard-signature'];
  const timestamp  = req.headers['x-chargeguard-timestamp'];
  // موجود بس في طلبات v3 (شوف build_signed_headers() في
  // class-api-client.php)؛ هيكون undefined لطلبات v1/v2 — وده طبيعي،
  // الـreplay-guard fallback تحت بيستخدم التوقيع نفسه (+ method/path) بدل
  // منه في الحالة دي. بنقراه مرة واحدة هنا عشان يُستخدم بنفس القيمة في
  // بناء الـsignedStr بتاع v3 تحت، وفي اختيار الـreplayKey لاحقًا.
  const requestId  = req.headers['x-chargeguard-request-id'];

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

  // حد أقصى قبل ما تُستخدم في أي مكان — سواء كـinput لتوقيع v3 تحت، أو
  // كـDB key في الـreplay guard لاحقًا. هيدر متحكم فيه من العميل لازم
  // يتقيّد بحد أقصى قبل ما يوصل لأي عملية تانية.
  if (requestId && !/^[A-Za-z0-9_-]{1,128}$/.test(String(requestId))) {
    const code = String(requestId).length > 128
      ? 'HMAC_REQUEST_ID_TOO_LONG'
      : 'HMAC_REQUEST_ID_INVALID';
    logger.warn(
      { tenantId: req.tenant?.id, path: req.path },
      code
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

  // Every current caller of this middleware that sends no body (all GET
  // routes, and the empty-body DELETE calls) reaches Express as an
  // empty Buffer via express.raw({ type: 'application/json' }) — see
  // app.js — because the plugin always sends Content-Type: application/json
  // even on bodyless requests (class-api-client.php). req.body should
  // therefore always be a Buffer by the time it reaches this middleware.
  // This branch is a defensive fallback only, for any future call site
  // that reaches here without going through express.raw() first (e.g. a
  // missing Content-Type header) — it fails closed with 401 rather than
  // crashing on Buffer.from(undefined)/Buffer.from(null).
  let rawBody;
  if (req.body instanceof Buffer) {
    rawBody = req.body;
  } else if (req.body === undefined || req.body === null) {
    logger.warn(
      { tenantId: req.tenant?.id, path: req.path },
      'HMAC_BODY_NOT_BUFFER — request reached verifyHmacSignature without a parsed raw body (missing Content-Type on a bodyless request?)'
    );
    rawBody = Buffer.from('');
  } else {
    rawBody = Buffer.from(JSON.stringify(req.body));
  }

  let signedStr;

  if (sigVersion === 'v3') {
    // v3 = domain-bound + request-id-bound. الـrequest id جزء من الرسالة
    // الموقّعة نفسها، مش مجرد هيدر مصاحب — يعني مهاجم معاه توقيع v3
    // ملتقط مايقدرش يغيّر X-ChargeGuard-Request-Id عشان يتهرّب من فحص
    // الـreplay guard تحت؛ أي تغيير فيه بيكسر التوقيع فورًا. طابق
    // generate_hmac() في class-api-client.php.
    const storeDomain = req.headers['x-store-domain'];
    if (!storeDomain) {
      logger.warn(
        { tenantId: req.tenant?.id, path: req.path },
        'HMAC_V3_MISSING_STORE_DOMAIN_HEADER'
      );
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (!requestId) {
      logger.warn(
        { tenantId: req.tenant?.id, path: req.path },
        'HMAC_V3_MISSING_REQUEST_ID'
      );
      return res.status(401).json({ error: 'Unauthorized' });
    }
    signedStr = `${timestamp}.${storeDomain}.${requestId}.${rawBody.toString('utf8')}`;
  } else if (sigVersion === 'v2') {
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

  // --- Replay / idempotency protection (P0-01) ---
  // "claim and cache" مش "hard reject": أول claim ناجح ينفّذ الـhandler
  // ويخزّن ردّه؛ أي تكرار بنفس المفتاح بعد كده ياخد نفس الرد المخزّن بدل
  // ما يترفض بـ401. كده retry شرعي (الرد ضاع في الشبكة بعد ما السيرفر
  // نفّذ العملية فعليًا) بيرجعله نتيجته الصح، وreplay من مهاجم مايجيبش
  // أي معلومة جديدة ولا بينفّذ أي side effect تاني. مفيش حد لسه شغال
  // (concurrent duplicate) بيترفض بـ409 بس.
  //
  // اختيار المفتاح:
  // - v3: requestId هو المفتاح مباشرة — ثابت عبر كل محاولات retry لنفس
  //   العملية المنطقية (شوف request_with_breaker() في class-api-client.php).
  // - v1/v2 (لسه مستخدمة من متاجر لسه ما حدّثتش الـplugin): مفيش
  //   requestId صريح، فبنستخدم التوقيع نفسه + method + path. التوقيع
  //   وحده مش كافي هنا: عمليات زي whitelist_delete/blacklist_delete/
  //   store_deactivate بتوقّع body فاضي والـID بتاعها في الـURL مش في
  //   الـbody الموقّع — يعني حذف عنصرين مختلفين في نفس الثانية ممكن
  //   يطلعوا بنفس التوقيع بالظبط. إضافة method+path بتفرّق بينهم لأن
  //   الـID (مصدر الاختلاف الوحيد) أصلاً موجود في الـpath.
  const replayKey = (sigVersion === 'v3' && requestId)
    ? String(requestId)
    : `${signature}:${req.method}:${req.path}`;

  let claim;
  try {
    claim = await claimRequestOnce(req.tenant.id, replayKey);
  } catch (err) {
    return res.status(503).json({ error: 'Service temporarily unavailable' });
  }

  if (!claim.claimed) {
    if (claim.cached) {
      // نفس الطلب اتخلّص قبل كده (retry شرعي أو replay) — رجّع نفس الرد
      // الأصلي من غير ما تنفّذ الـhandler ولا أي side effect تاني.
      res.status(claim.cached.code || 200);
      if (claim.cached.body != null) {
        try {
          return res.json(JSON.parse(claim.cached.body));
        } catch (_) {
          return res.send(claim.cached.body);
        }
      }
      return res.end();
    }
    // لسه شغال فعليًا (تكرار متزامن حقيقي) أو الرد الأصلي كان أكبر من
    // حد التخزين. الـPHP client مبيعملش retry على 409، فمفيش خطر loop.
    logger.warn(
      { tenantId: req.tenant?.id, path: req.path, sigVersion },
      'HMAC_REPLAY_OR_CONCURRENT_DUPLICATE'
    );
    return res.status(409).json({ error: 'Duplicate request' });
  }

  // اتحجز — ده طلب منطقي جديد. نلف res.json/res.send عشان أي رد نهائي
  // يرجّعه الـhandler يتخزن تلقائيًا تحت نفس replayKey. res.json في
  // Express بينادي res.send داخليًا، فـcapture() محميّة بـflag عشان
  // متتسجلش مرتين لنفس الرد.
  {
    const originalJson = res.json.bind(res);
    const originalSend = res.send.bind(res);
    const claimId = claim.claimId;
    let captured = false;
    const capture = (payload) => {
      if (captured) return;
      captured = true;
      // 5xx = فشل سيرفر مؤقت، مش نتيجة نهائية تستاهل الحفظ/الإرجاع لأي
      // retry لاحق — نسيب الـclaim يتحرر عشان أي retry فعلي (بنفس
      // request_id من request_with_breaker() في class-api-client.php)
      // يشغّل الـhandler من جديد فعليًا، بدل ما ياخد نفس الـ500 المخزّن
      // من غير أي فايدة. أي كود تاني (2xx أو قرار منطقي زي 401/403/409)
      // بيتخزن عادي زي قبل كده.
      if (res.statusCode >= 500) {
        releaseRequest(req.tenant.id, replayKey, claimId).catch(() => {});
      } else {
        completeRequest(req.tenant.id, replayKey, claimId, res.statusCode, payload).catch(() => {});
      }
    };
    res.json = (payload) => { capture(payload); return originalJson(payload); };
    res.send = (payload) => { capture(payload); return originalSend(payload); };
  }

  // Exposes which signed-string format this request verified against, for
  // any downstream middleware that must treat v2 (domain-bound) and v1
  // (legacy, NOT domain-bound) differently — currently only
  // autoRegisterStoreMiddleware, which must never trust
  // req.pendingStoreDomain unless this is 'v2'.
  req.hmacSignatureVersion = sigVersion;

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
    if (req.body.length === 0) {
      // Bodyless requests (GET, or DELETE with no body) sign an empty
      // string and never carried a JSON payload to begin with. Falling
      // through to JSON.parse('') here throws unconditionally
      // (SyntaxError: Unexpected end of JSON input), which would 400
      // every legitimately-signed empty-body request — e.g. this route,
      // GET /risk/whitelist, GET /risk/blacklist — even though the
      // signature check just above this already passed.
      req.body = {};
    } else {
      try {
        req.body = JSON.parse(req.body.toString('utf8'));
      } catch (_) {
        return res.status(400).json({ error: 'Invalid JSON body' });
      }
    }
  }

  next();
}

module.exports = verifyHmacSignature;