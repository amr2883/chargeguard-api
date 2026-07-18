// src/lib/domainAuth.js
'use strict';

const crypto = require('crypto');
const db     = require('./db');
const logger = require('./logger');

// ─── ثوابت بيئات التطوير ───────────────────────────────────────────────────

const DEV_EXACT = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  '0.0.0.0',
]);

// Regex للشبكات الخاصة (IPv4)
const PRIVATE_NETWORK_RE = /^(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})$/;

// ─── normalizeDomain ────────────────────────────────────────────────────────

/**
 * تُنظّف أي إدخال وتُعيد hostname نقياً بدون بروتوكول أو www أو port.
 * مثال: "https://www.MyStore.com:8080/" → "mystore.com"
 * تُعيد null إذا كان الإدخال غير صالح.
 *
 * @param  {string|undefined} raw
 * @returns {string|null}
 */
function normalizeDomain(raw) {
  if (!raw || typeof raw !== 'string') return null;

  let input = raw.trim();
  if (!input) return null;

  // إذا لم يحتوِ على بروتوكول، أضفه مؤقتاً حتى يعمل new URL()
  if (!/^https?:\/\//i.test(input)) {
    input = 'https://' + input;
  }

  let hostname;
  try {
    hostname = new URL(input).hostname;
  } catch {
    // إدخال لا يمكن تحليله — مثل نص عشوائي
    return null;
  }

  // تحويل لحروف صغيرة وإزالة www. من البداية فقط
  hostname = hostname.toLowerCase().replace(/^www\./, '');

  // إزالة أي port علق في الـ hostname (نادر لكن محتمل)
  hostname = hostname.replace(/:\d+$/, '');

  return hostname || null;
}

// ─── isDevDomain ────────────────────────────────────────────────────────────

/**
 * تُعيد true إذا كان الدومين ينتمي إلى بيئة تطوير محلية.
 *
 * @param  {string} domain  — hostname منقّح من normalizeDomain
 * @returns {boolean}
 */
function isDevDomain(domain) {
  if (!domain) return false;

  // تطابق حرفي (localhost, 127.0.0.1, ...)
  if (DEV_EXACT.has(domain)) return true;

  // امتدادات التطوير الشائعة
  if (domain.endsWith('.local'))  return true;
  if (domain.endsWith('.test'))   return true;
  if (domain.endsWith('.dev'))    return true;  // بعض المشاريع تستخدمها
  if (domain.endsWith('.localhost')) return true;

  // شبكات IPv4 الخاصة
  if (PRIVATE_NETWORK_RE.test(domain)) return true;

  return false;
}

// ─── domainAuthMiddleware ───────────────────────────────────────────────────

/**
 * Express middleware يتحقق من أن الدومين المُرسَل مع الطلب
 * موجود في قائمة allowedDomains الخاصة بالـ tenant.
 *
 * يجب تشغيله بعد apiKeyAuth حتى يكون req.tenant متاحاً.
 *
 * @type {import('express').RequestHandler}
 */
const domainAuthMiddleware = async (req, res, next) => {
  try {

    // ── ١. تجاوز الطلبات الداخلية ─────────────────────────────────────────
    const internalTokenRaw = req.headers['x-internal-token'];
    const internalTokenEnv = process.env.INTERNAL_TOKEN;

    if (internalTokenRaw && internalTokenEnv) {
      // نستخدم timingSafeEqual لمنع timing attacks
      const a = Buffer.from(internalTokenRaw);
      const b = Buffer.from(internalTokenEnv);

      if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
        logger.debug(
          { module: 'domainAuth', path: req.path },
          'Internal token matched — skipping domain check'
        );
        return next();
      }

      // Token موجود لكن خاطئ — نرفض صراحةً
      logger.warn(
        { module: 'domainAuth', ip: req.ip, path: req.path },
        'Invalid internal token provided'
      );
      return res.status(403).json({
        error: 'Invalid internal token',
        code:  'INVALID_INTERNAL_TOKEN',
      });
    }

    // ── ٢. استخراج الدومين من الـ Header ─────────────────────────────────
    const rawDomain = req.headers['x-store-domain'];
    const normalizedDomain = normalizeDomain(rawDomain);

    if (!normalizedDomain) {
      logger.warn(
        {
          module:    'domainAuth',
          tenantId:  req.tenant?.id,
          raw:       rawDomain ?? '(missing)',
          ip:        req.ip,
          path:      req.path,
        },
        'Missing or unparseable X-Store-Domain header'
      );
      return res.status(400).json({
        error: 'X-Store-Domain header is required and must be a valid domain',
        code:  'MISSING_DOMAIN',
      });
    }

    // ── ٣. السماح ببيئات التطوير (production-gated) ─────────────────────
    // CWE-693 / OWASP API8:2023 mitigation: this bypass must never be
    // reachable in production. Gated on NODE_ENV, matching the existing
    // convention used elsewhere in this codebase (app.js: /mark-fraud,
    // /test-graph). A loud warn (not debug) fires on every trigger so a
    // misconfigured NODE_ENV is immediately visible in monitoring rather
    // than silently exploitable.
    if (process.env.NODE_ENV !== 'production' && isDevDomain(normalizedDomain)) {
      logger.warn(
        {
          module:   'domainAuth',
          domain:   normalizedDomain,
          tenantId: req.tenant?.id,
          nodeEnv:  process.env.NODE_ENV,
        },
        'Dev/local domain bypass triggered — skipping allowedDomains check (non-production only)'
      );
      req.storeDomain = normalizedDomain;
      return next();
    }

    // ── ٤. التحقق من req.tenant (يجب أن يكون موجوداً من apiKeyAuth) ───────
    if (!req.tenant?.id) {
      // هذا لا يجب أن يحدث في الترتيب الصحيح للـ middleware
      logger.error(
        { module: 'domainAuth', path: req.path },
        'req.tenant missing — domainAuth must run after apiKeyAuth'
      );
      return res.status(500).json({
        error: 'Server configuration error',
        code:  'MISSING_TENANT_CONTEXT',
      });
    }

    // ── ٥. Store-aware resolution (Agency multi-store) ────────────────────
    // A tenant is "store-managed" if it has ANY Store rows, active or not —
    // that's the signal we use instead of tenant.plan, so this security path
    // never drifts out of sync with a billing field. Starter/Pro tenants
    // (zero Store rows) fall through unchanged to the legacy allowedDomains
    // check below (step ٦).
    const matchedStore = await db.store.findFirst({
      where: {
        tenantId:         req.tenant.id,
        normalizedDomain: normalizedDomain,
        isActive:         true,
      },
      select: { id: true },
    });

    if (matchedStore) {
      req.storeId     = matchedStore.id;
      req.storeDomain = normalizedDomain;
      logger.debug(
        { module: 'domainAuth', domain: normalizedDomain, tenantId: req.tenant.id, storeId: matchedStore.id },
        'Domain verified against Store table'
      );
      return next();
    }

    const tenantHasStores = await db.store.count({
      where: { tenantId: req.tenant.id, isActive: true },
    }) > 0;

    if (tenantHasStores) {
      // Store-managed tenant: primary path is the Store table. But the
      // tenant's own site (registered via /connect before they ever added
      // a client Store) lives in legacy allowedDomains, not the Store
      // table — so we consult it as a fallback for exactly this one case,
      // rather than treating "has Store rows" as "must be a Store row."
      const tenantRecordForFallback = await db.tenant.findUnique({
        where:  { id: req.tenant.id },
        select: { allowedDomains: true },
      });

      const legacyAllowedDomains = tenantRecordForFallback?.allowedDomains ?? [];

      if (legacyAllowedDomains.includes(normalizedDomain)) {
        // Agency's own site, authenticated via its original /connect
        // allowedDomains entry — not a specific managed Store, so
        // req.storeId stays undefined.
        req.storeDomain = normalizedDomain;
        logger.debug(
          { module: 'domainAuth', domain: normalizedDomain, tenantId: req.tenant.id },
          'Domain verified against legacy allowedDomains (agency own-site fallback)'
        );
        return next();
      }

      // Store-managed tenant, and this domain isn't a registered Store NOR
      // the tenant's own legacy allowedDomains entry — reject.
      logger.warn(
        { module: 'domainAuth', tenantId: req.tenant.id, requestDomain: normalizedDomain },
        'Domain mismatch — request rejected (store-managed tenant)'
      );
      return res.status(403).json({
        error: 'Domain not authorized for this API key. Add this domain as a Store first.',
        code:  'DOMAIN_MISMATCH',
      });
    }

    // ── ٦. Legacy allowedDomains check (Starter/Pro — unchanged) ──────────
    const tenantRecord = await db.tenant.findUnique({
      where:  { id: req.tenant.id },
      select: { allowedDomains: true },
    });

    const allowedDomains = tenantRecord?.allowedDomains ?? [];

    // Default-deny (OWASP ASVS V4.1.1; CWE-636 fix): an empty allowedDomains
    // array means this tenant has no authorized origin, not "skip the check."
    // With zero existing users at launch, every tenant created from this
    // point forward has allowedDomains populated at registration/connect
    // time, so this branch should only ever fire for a misconfigured or
    // tampered record — and that case must reject, not bypass.
    if (allowedDomains.length === 0) {
      logger.warn(
        { module: 'domainAuth', tenantId: req.tenant.id, requestDomain: normalizedDomain },
        'Tenant has no allowedDomains configured — rejecting (default-deny)'
      );
      return res.status(403).json({
        error: 'No authorized domain configured for this API key. Please reconnect your store.',
        code:  'NO_ALLOWED_DOMAINS',
      });
    }

    if (!allowedDomains.includes(normalizedDomain)) {
      logger.warn(
        {
          module:         'domainAuth',
          tenantId:       req.tenant.id,
          requestDomain:  normalizedDomain,
          allowedDomains,
          ip:             req.ip,
          userAgent:      req.headers['user-agent'] ?? '(none)',
          path:           req.path,
        },
        'Domain mismatch — request rejected'
      );
      return res.status(403).json({
        error: 'Domain not authorized for this API key',
        code:  'DOMAIN_MISMATCH',
      });
    }

    // ── ٧. نجح التحقق ─────────────────────────────────────────────────────
    req.storeDomain = normalizedDomain;
    logger.debug(
      { module: 'domainAuth', domain: normalizedDomain, tenantId: req.tenant.id },
      'Domain verified'
    );
    next();

} catch (err) {
    logger.error(
      { module: 'domainAuth', error: err.message, stack: err.stack },
      'Unexpected error in domainAuthMiddleware — failing closed'
    );
    // Fail closed (CWE-636 fix): this middleware is a security boundary, not
    // a convenience feature. A DB error must not silently disable domain
    // verification — that was the original defect (the missing column threw
    // on every request, and the catch block let every request through).
    return res.status(503).json({
      error: 'Unable to verify request origin. Please try again.',
      code:  'DOMAIN_CHECK_UNAVAILABLE',
    });
  }
};

// ─── Exports ────────────────────────────────────────────────────────────────

module.exports = {
  domainAuthMiddleware,
  normalizeDomain,
  isDevDomain,
};